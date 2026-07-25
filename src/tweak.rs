//! `--tweak SRC` staging. Staging only lays out bytes; [`resolve_dependencies`]
//! then rewrites dependencies, once the full set of staged files is known.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{deb, macho};

/// `rel` is relative to the `.app` bundle root.
pub struct StagedFile {
    pub rel: String,
    pub data: Vec<u8>,
    pub exec: bool,
}

/// `control` is absent if the package ships no control member.
pub struct Staged {
    pub files: Vec<StagedFile>,
    pub weak_refs: Vec<String>,
    pub label: String,
    pub control: Option<deb::Control>,
}

impl Staged {
    fn empty(label: impl Into<String>) -> Self {
        Staged {
            files: Vec::new(),
            weak_refs: Vec::new(),
            label: label.into(),
            control: None,
        }
    }

    fn merge(&mut self, other: Staged) {
        self.files.extend(other.files);
        self.weak_refs.extend(other.weak_refs);
    }
}

pub fn plan(src: &Path) -> Result<Staged> {
    let name = src
        .file_name()
        .and_then(|s| s.to_str())
        .with_context(|| format!("bad --tweak path {}", src.display()))?;
    if !src
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("deb"))
    {
        bail!("--tweak: expected a .deb package, got '{name}'");
    }
    let data = std::fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    stage_deb(name, &data)
}

fn stage_dylib(file_name: &str, mut data: Vec<u8>) -> Result<Staged> {
    if !macho::is_macho(&data) {
        bail!("{file_name} is not a Mach-O dylib");
    }
    let rpath_ref = format!("@rpath/{file_name}");
    if let Ok(fixed) = macho::set_dylib_id(&data, &rpath_ref) {
        data = fixed;
    }

    Ok(Staged {
        files: vec![StagedFile {
            rel: format!("Frameworks/{file_name}"),
            data,
            exec: true,
        }],
        weak_refs: vec![rpath_ref],
        label: file_name.to_owned(),
        control: None,
    })
}

fn stage_container(
    container_name: &str,
    dest_prefix: &str,
    files: Vec<(String, Vec<u8>)>,
    weak_link: bool,
) -> Result<Staged> {
    let principal = container_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(container_name);

    let mut out = Staged::empty(container_name);
    for (rel, mut data) in files {
        let mut exec = false;
        if macho::is_macho(&data) {
            let self_ref = format!("@rpath/{container_name}/{rel}");
            // set_dylib_id no-ops on an executable.
            if rel == principal {
                if let Ok(fixed) = macho::set_dylib_id(&data, &self_ref) {
                    data = fixed;
                }
            }
            exec = true;
            if weak_link && rel == principal {
                out.weak_refs
                    .push(format!("@rpath/{container_name}/{principal}"));
            }
        }
        out.files.push(StagedFile {
            rel: format!("{dest_prefix}{rel}"),
            data,
            exec,
        });
    }
    Ok(out)
}

/// ElleKit/libhooker symlink `DynamicLibraries` to the rootless `TweakInject`.
const TWEAK_DIRS: &[&str] = &[
    "Library/MobileSubstrate/DynamicLibraries/",
    "usr/lib/TweakInject/",
];
const FRAMEWORKS_DIR: &str = "Library/Frameworks/";
const RESOURCES_DIR: &str = "Library/Application Support/";

/// `(path, source, bytes)`, where `source` is where the bytes actually live.
fn materialise(payload: &deb::Payload) -> Vec<(String, String, Vec<u8>)> {
    let mut out = Vec::new();
    for (path, entry) in payload.iter() {
        match entry {
            deb::Entry::File(data) => out.push((path.to_owned(), path.to_owned(), data.clone())),
            deb::Entry::Symlink(target) => match payload.resolve(path) {
                deb::Resolved::File(src, data) => {
                    out.push((path.to_owned(), src.to_owned(), data.to_vec()));
                }
                deb::Resolved::Dir(items) => {
                    out.extend(items.into_iter().map(|(sub, src, data)| {
                        (format!("{path}/{sub}"), src.to_owned(), data.to_vec())
                    }))
                }
                deb::Resolved::Dangling => {
                    eprintln!("warning: .deb: skipping dangling link {path} -> {target}");
                }
            },
        }
    }
    out
}

/// `Foo.framework/Bar` gives `("Foo.framework", "Bar")`. The outermost match
/// wins, so a nested bundle stays inside its parent.
fn container_of<'a>(rest: &'a str, ext: &str) -> Option<(&'a str, &'a str)> {
    let idx = rest.find(&format!("{ext}/"))?;
    let end = idx + ext.len();
    let start = rest[..idx].rfind('/').map_or(0, |i| i + 1);
    Some((&rest[start..end], &rest[end + 1..]))
}

fn tweak_dir_file(path: &str) -> Option<&str> {
    TWEAK_DIRS
        .iter()
        .find_map(|dir| path.strip_prefix(dir))
        .filter(|name| !name.contains('/'))
}

fn report_skipped(skipped: &[String]) {
    if skipped.is_empty() {
        return;
    }
    let mut groups: BTreeMap<&str, usize> = BTreeMap::new();
    for path in skipped {
        let dir = path
            .match_indices('/')
            .nth(1)
            .map_or(path.as_str(), |(i, _)| &path[..i]);
        *groups.entry(dir).or_default() += 1;
    }
    let listed: Vec<String> = groups
        .iter()
        .take(10)
        .map(|(dir, n)| format!("{dir} ({n})"))
        .collect();
    eprintln!(
        "warning: .deb: skipped {} payload path(s) that need a jailbroken host: {}",
        skipped.len(),
        listed.join(", ")
    );
}

fn stage_deb(name: &str, deb_bytes: &[u8]) -> Result<Staged> {
    let deb::Deb { payload, control } = deb::read(deb_bytes)?;

    let mut frameworks: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
    let mut bundles: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
    let mut tweaks: Vec<(String, String, Vec<u8>)> = Vec::new();
    let mut framework_sources: HashSet<String> = HashSet::new();
    let mut skipped: Vec<String> = Vec::new();

    for (path, source, data) in materialise(&payload) {
        if let Some(name) = tweak_dir_file(&path) {
            if name.ends_with(".dylib") {
                tweaks.push((name.to_owned(), source, data));
            } else if !name.ends_with(".plist") {
                // A Substrate filter plist means nothing once weak-linked.
                skipped.push(path);
            }
            continue;
        }
        if let Some(rest) = path.strip_prefix(FRAMEWORKS_DIR) {
            match container_of(rest, ".framework") {
                Some((fw, within)) => {
                    framework_sources.insert(source);
                    frameworks
                        .entry(fw.to_owned())
                        .or_default()
                        .push((within.to_owned(), data));
                }
                None => skipped.push(path),
            }
            continue;
        }
        if let Some(rest) = path.strip_prefix(RESOURCES_DIR) {
            match container_of(rest, ".bundle") {
                Some((bundle, within)) => bundles
                    .entry(bundle.to_owned())
                    .or_default()
                    .push((within.to_owned(), data)),
                None => skipped.push(path),
            }
            continue;
        }
        // Preference bundles, themes, Activator listeners need a jailbroken host.
        if path.starts_with("Library/") {
            skipped.push(path);
        }
    }

    let mut out = Staged::empty(name);
    let framework_count = frameworks.len();
    let bundle_count = bundles.len();
    for (fw_name, files) in frameworks {
        let dest = format!("Frameworks/{fw_name}/");
        // Providers, not tweaks: whoever needs one links it.
        out.merge(stage_container(&fw_name, &dest, files, false)?);
    }
    // App root: a tweak with no jailbreak path falls back to `mainBundle`.
    for (b_name, files) in bundles {
        let dest = format!("{b_name}/");
        out.merge(stage_container(&b_name, &dest, files, false)?);
    }

    let mut staged_sources = framework_sources;
    let mut tweak_count = 0;
    for (name, source, data) in tweaks {
        // Cephei's tweak dylib links to its own framework binary; injecting
        // both would load it twice.
        if !staged_sources.insert(source) {
            continue;
        }
        // .debs carry non-Mach-O `.dylib` stubs; skip rather than abort.
        match stage_dylib(&name, data) {
            Ok(inj) => {
                out.merge(inj);
                tweak_count += 1;
            }
            Err(e) => eprintln!("warning: skipping .deb dylib {name}: {e:#}"),
        }
    }

    report_skipped(&skipped);

    if out.files.is_empty() {
        bail!(
            "--tweak: {name} had nothing usable under Library/ \
             (no tweak dylib, framework or resource bundle)"
        );
    }
    out.label = format!(
        "{name}: {tweak_count} tweak(s), {framework_count} framework(s), {bundle_count} bundle(s)"
    );
    out.control = control;
    Ok(out)
}

/// The pseudo-packages Cydia's `firmware.sh` fabricates and Sileo/Zebra follow:
/// they describe the device, so no `.deb` supplies them.
fn is_device_predicate(name: &str) -> bool {
    name == "firmware" || name.starts_with("gsc.") || name.starts_with("cy+")
}

#[derive(Debug, Default)]
pub struct DepIssues {
    /// `(package, the term nothing satisfied)`.
    pub missing: Vec<(String, String)>,
    /// `(package, the package it clashes with, the name they clash over)`.
    pub conflicts: Vec<(String, String, String)>,
}

/// Version constraints are parsed but not enforced: names only. Packages with
/// no control member sit this out.
pub fn check_dependencies(staged: &[Staged]) -> DepIssues {
    let controls: Vec<&deb::Control> = staged.iter().filter_map(|s| s.control.as_ref()).collect();
    let provided: HashSet<&str> = controls
        .iter()
        .flat_map(|c| {
            std::iter::once(c.package.as_str()).chain(c.provides.iter().map(String::as_str))
        })
        .collect();

    let mut issues = DepIssues::default();
    for c in &controls {
        for term in &c.depends {
            let satisfied = term
                .alternatives
                .iter()
                .any(|a| is_device_predicate(&a.name) || provided.contains(a.name.as_str()));
            if !satisfied {
                issues.missing.push((c.package.clone(), term.to_string()));
            }
        }
    }

    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for a in &controls {
        for name in &a.conflicts {
            // ElleKit conflicts with the `mobilesubstrate` it also provides.
            if *name == a.package || a.provides.contains(name) {
                continue;
            }
            for b in &controls {
                if b.package == a.package
                    || (b.package != *name && !b.provides.contains(name))
                    || !seen.insert(pair(&a.package, &b.package))
                {
                    continue;
                }
                issues
                    .conflicts
                    .push((a.package.clone(), b.package.clone(), name.clone()));
            }
        }
    }
    issues
}

/// A conflict is mutual, so report each pair of packages once.
fn pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
}

/// Non-absolute deps (`@rpath/…`, `@executable_path/…`) resolve already.
fn dep_tail(path: &str) -> Option<&str> {
    let rest = path.strip_prefix('/')?;
    match rest.find(".framework/") {
        Some(i) => {
            let start = rest[..i].rfind('/').map_or(0, |s| s + 1);
            Some(&rest[start..])
        }
        None => rest.rsplit('/').next().filter(|s| !s.is_empty()),
    }
}

/// Lowercased tail → the tail as actually spelled under `Frameworks/`.
fn availability(
    staged: &[Staged],
    extra: &[StagedFile],
    existing: &HashSet<String>,
) -> HashMap<String, String> {
    const DIR: &str = "Frameworks/";
    let rels = staged
        .iter()
        .flat_map(|s| s.files.iter().map(|f| f.rel.as_str()))
        .chain(extra.iter().map(|f| f.rel.as_str()))
        .chain(existing.iter().map(String::as_str));
    let mut out = HashMap::new();
    for rel in rels {
        let rel = rel.trim_start_matches('/');
        let tail = match rel.get(..DIR.len()) {
            Some(head) if head.eq_ignore_ascii_case(DIR) => &rel[DIR.len()..],
            _ => continue,
        };
        if !tail.is_empty() {
            out.insert(tail.to_lowercase(), tail.to_owned());
        }
    }
    out
}

/// System libraries are never provided in `Frameworks/`, so they need no denylist.
fn detected_rewrites(
    macho_bytes: &[u8],
    available: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for path in macho::dylib_paths(macho_bytes) {
        let Some(tail) = dep_tail(&path) else {
            continue;
        };
        if let Some(actual) = available.get(&tail.to_lowercase()) {
            out.push((path.clone(), format!("@rpath/{actual}")));
        }
    }
    out
}

/// `extra` holds staged binaries belonging to no package — the overlaid ones,
/// both rewritten and counted as providers. `existing` holds the `.app`-relative
/// paths the app already carries.
pub fn resolve_dependencies(
    staged: &mut [Staged],
    extra: &mut [StagedFile],
    existing: &HashSet<String>,
) -> Result<()> {
    let available = availability(staged, extra, existing);
    let files = staged
        .iter_mut()
        .flat_map(|pkg| pkg.files.iter_mut())
        .chain(extra.iter_mut());
    for f in files {
        if !macho::is_macho(&f.data) {
            continue;
        }
        for (old, new) in detected_rewrites(&f.data, &available) {
            f.data = macho::change_dylib_path(&f.data, &old, &new)
                .with_context(|| format!("rewriting {old} in staged {}", f.rel))?;
        }
    }
    Ok(())
}

pub fn normalise_install_name(rel: &str, data: Vec<u8>) -> Vec<u8> {
    match rel.strip_prefix("Frameworks/") {
        Some(tail) => macho::set_dylib_id(&data, &format!("@rpath/{tail}")).unwrap_or(data),
        None => data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_dependency_tails() {
        assert_eq!(
            dep_tail("/Library/Frameworks/Orion.framework/Orion"),
            Some("Orion.framework/Orion")
        );
        assert_eq!(
            dep_tail("/System/Library/Frameworks/UIKit.framework/UIKit"),
            Some("UIKit.framework/UIKit")
        );
        assert_eq!(
            dep_tail("/Library/Frameworks/Cephei.framework/Versions/A/Cephei"),
            Some("Cephei.framework/Versions/A/Cephei")
        );
        assert_eq!(
            dep_tail("/usr/lib/libsubstrate.dylib"),
            Some("libsubstrate.dylib")
        );
        assert_eq!(dep_tail("@rpath/libsubstrate.dylib"), None);
        assert_eq!(dep_tail("@executable_path/Frameworks/A.dylib"), None);
    }

    fn with_deps(deps: &[&str]) -> Option<Vec<u8>> {
        let path = "/tmp/patina-fixtures/libinject.dylib";
        let mut bin = std::path::Path::new(path)
            .exists()
            .then(|| std::fs::read(path).unwrap())?;
        for d in deps {
            bin = macho::inject_weak_dylib(&bin, d).unwrap();
        }
        Some(bin)
    }

    fn staged(rel: &str, data: Vec<u8>) -> Staged {
        Staged {
            files: vec![StagedFile {
                rel: rel.to_owned(),
                data,
                exec: true,
            }],
            weak_refs: Vec::new(),
            label: rel.to_owned(),
            control: None,
        }
    }

    fn resolve(deps: &[&str], provided: &[&str], existing: &[&str]) -> Option<Vec<String>> {
        let bin = with_deps(deps)?;
        let mut pkgs = vec![staged("Frameworks/Tweak.dylib", bin)];
        for p in provided {
            pkgs.push(staged(p, with_deps(&[]).unwrap()));
        }
        let existing = existing.iter().map(|s| (*s).to_owned()).collect();
        resolve_dependencies(&mut pkgs, &mut [], &existing).unwrap();
        Some(macho::dylib_paths(&pkgs[0].files[0].data))
    }

    #[test]
    fn rewrites_dependency_that_is_provided() {
        let dep = "/Library/Frameworks/Orion.framework/Orion";
        let Some(libs) = resolve(&[dep], &["Frameworks/Orion.framework/Orion"], &[]) else {
            return;
        };
        assert!(
            libs.iter().any(|l| l == "@rpath/Orion.framework/Orion"),
            "{libs:?}"
        );
        assert!(!libs.iter().any(|l| l == dep), "{libs:?}");
    }

    #[test]
    fn leaves_unprovided_dependency_alone() {
        let dep = "/Library/Frameworks/Orion.framework/Orion";
        let Some(libs) = resolve(&[dep], &[], &[]) else {
            return;
        };
        assert!(libs.iter().any(|l| l == dep), "{libs:?}");
    }

    #[test]
    fn leaves_system_dependencies_alone() {
        let system = [
            "/System/Library/Frameworks/UIKit.framework/UIKit",
            "/usr/lib/libobjc.A.dylib",
        ];
        let Some(libs) = resolve(
            &system,
            &["Frameworks/Orion.framework/Orion"],
            &["Frameworks/Cephei.framework/Cephei"],
        ) else {
            return;
        };
        for s in system {
            assert!(libs.iter().any(|l| l == s), "{s} was rewritten: {libs:?}");
        }
    }

    #[test]
    fn matches_provider_case_insensitively() {
        let Some(libs) = resolve(
            &["/usr/lib/libSubstrate.dylib"],
            &["Frameworks/libsubstrate.dylib"],
            &[],
        ) else {
            return;
        };
        assert!(
            libs.iter().any(|l| l == "@rpath/libsubstrate.dylib"),
            "{libs:?}"
        );
    }

    #[test]
    fn framework_already_in_the_app_counts_as_provided() {
        let Some(libs) = resolve(
            &["/Library/Frameworks/Foo.framework/Foo"],
            &[],
            &["Frameworks/Foo.framework/Foo"],
        ) else {
            return;
        };
        assert!(
            libs.iter().any(|l| l == "@rpath/Foo.framework/Foo"),
            "{libs:?}"
        );
    }

    const BHTWITTER: &str = "Package: com.bandarhl.bhtwitter\n\
        Version: 6.0.4-2\n\
        Depends: mobilesubstrate, ws.hbang.common\n\
        Conflicts: com.den.twigalaxy, xyz.cypwn.twigalaxy, xyz.cypwn.bhtwitter\n";
    const ELLEKIT: &str = "Package: ellekit\n\
        Version: 0.6.3\n\
        Conflicts: com.ex.substitute, org.coolstar.libhooker, mobilesubstrate\n\
        Provides: mobilesubstrate (= 99), org.coolstar.libhooker (= 1.6.9)\n";

    fn with_control(text: &str) -> Staged {
        let mut s = Staged::empty("pkg");
        s.control = Some(deb::parse_control(text).unwrap());
        s
    }

    fn missing_of(controls: &[&str]) -> Vec<String> {
        let staged: Vec<Staged> = controls.iter().map(|c| with_control(c)).collect();
        check_dependencies(&staged)
            .missing
            .iter()
            .map(|(pkg, dep)| format!("{pkg} needs {dep}"))
            .collect()
    }

    #[test]
    fn provides_satisfies_a_dependency() {
        assert_eq!(
            missing_of(&[BHTWITTER]),
            [
                "com.bandarhl.bhtwitter needs mobilesubstrate",
                "com.bandarhl.bhtwitter needs ws.hbang.common"
            ],
            "every unsatisfied term is reported, not just the first"
        );
        assert_eq!(
            missing_of(&[BHTWITTER, ELLEKIT]),
            ["com.bandarhl.bhtwitter needs ws.hbang.common"]
        );
        assert!(
            missing_of(&[BHTWITTER, ELLEKIT, "Package: ws.hbang.common\n"]).is_empty(),
            "supplying Cephei satisfies the run"
        );
    }

    #[test]
    fn version_constraints_are_not_enforced() {
        assert!(
            missing_of(&[
                "Package: a\nDepends: ws.hbang.common (>= 99.0)\n",
                "Package: ws.hbang.common\nVersion: 1.0\n",
            ])
            .is_empty()
        );
    }

    #[test]
    fn skips_device_predicates() {
        assert!(
            missing_of(&[
                "Package: a\nDepends: firmware (>= 15.0), cy+model.foo, gsc.720p, cy+cpu.arm64\n"
            ])
            .is_empty()
        );
        assert_eq!(
            missing_of(&[
                "Package: a\nDepends: firmware (<< 8.0) | com.rpetrich.rocketbootstrap\n"
            ]),
            Vec::<String>::new(),
            "one satisfied alternative satisfies the term"
        );
    }

    #[test]
    fn conflicts_are_reported_between_packages_in_the_run() {
        let twigalaxy = "Package: com.den.twigalaxy\n";
        let staged = [with_control(BHTWITTER), with_control(twigalaxy)];
        let issues = check_dependencies(&staged);
        assert_eq!(
            issues.conflicts,
            [(
                "com.bandarhl.bhtwitter".to_owned(),
                "com.den.twigalaxy".to_owned(),
                "com.den.twigalaxy".to_owned()
            )]
        );
    }

    #[test]
    fn a_package_does_not_conflict_with_what_it_provides() {
        let staged = [with_control(ELLEKIT), with_control(BHTWITTER)];
        assert!(check_dependencies(&staged).conflicts.is_empty());
    }

    #[test]
    fn a_mutual_conflict_is_reported_once() {
        let libhooker = "Package: org.coolstar.libhooker\n\
            Provides: mobilesubstrate\n\
            Conflicts: ellekit, mobilesubstrate\n";
        let staged = [with_control(ELLEKIT), with_control(libhooker)];
        let issues = check_dependencies(&staged);
        assert_eq!(
            issues.conflicts,
            [(
                "org.coolstar.libhooker".to_owned(),
                "ellekit".to_owned(),
                "ellekit".to_owned()
            )]
        );
    }
}

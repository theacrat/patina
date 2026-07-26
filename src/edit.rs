//! Edit orchestration: every requested operation becomes ONE [`EditPlan`],
//! committed with a single central-directory rewrite.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use plist::Value;
use zip::ZipArchive;

use crate::archive::{EditPlan, MODE_EXEC, MODE_FILE};
use crate::{codesign, icons, macho, merge, plist_ops, rename, tweak};

#[derive(Default)]
pub struct EditOptions {
    pub name: Option<String>,
    /// `(icon-name, source-png-path)` pairs.
    pub alt_icons: Vec<(String, PathBuf)>,
    pub icon: Option<PathBuf>,
    pub merge_car: Option<PathBuf>,
    /// Merged into the `.app` root, later ones winning.
    pub overlays: Vec<PathBuf>,
    pub tweaks: Vec<PathBuf>,
    pub ignore_missing_deps: bool,
    pub entitlements: Option<PathBuf>,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub min_os: Option<String>,
    pub merge_plist: Option<PathBuf>,
    pub remove_supported_devices: bool,
    pub enable_file_sharing: bool,
    pub remove_watch: bool,
    pub remove_extensions: bool,
    pub remove_encrypted_extensions: bool,
    pub thin: bool,
    pub fakesign_bundle: bool,
    pub deterministic: bool,
}

impl EditOptions {
    fn touches_metadata(&self) -> bool {
        self.bundle_id.is_some()
            || self.version.is_some()
            || self.min_os.is_some()
            || self.merge_plist.is_some()
            || self.remove_supported_devices
            || self.enable_file_sharing
    }
}

#[derive(Debug, Default)]
pub struct EditReport {
    pub app_dir: String,
    pub executable: String,
    pub renamed: bool,
    pub lproj_updated: usize,
    pub alt_icons: usize,
    pub primary_icon: bool,
    pub car_replaced: usize,
    pub car_added: Vec<String>,
    pub car_unmatched: Vec<String>,
    pub overlaid_files: usize,
    pub tweaks: Vec<String>,
    pub resigned: bool,
    pub metadata: Vec<String>,
    pub removed: Vec<String>,
    pub thinned: usize,
    pub fakesigned: Option<usize>,
}

pub enum WriteMode {
    AppendInPlace,
    Compact,
}

struct Signable {
    name: String,
    data: Vec<u8>,
    identifier: String,
    /// Only ever set for the app's main executable.
    entitlements: Option<String>,
}

/// Queueing replaces by name, so a binary is signed once, from its last bytes.
#[derive(Default)]
struct SignQueue(Vec<Signable>);

impl SignQueue {
    /// Staged tweak and overlay binaries sign under their own file name.
    fn queue_staged(&mut self, name: String, data: Vec<u8>) {
        let identifier = name.rsplit('/').next().unwrap_or(name.as_str()).to_owned();
        self.queue(name, data, identifier, None);
    }

    fn queue(
        &mut self,
        name: String,
        data: Vec<u8>,
        identifier: String,
        entitlements: Option<String>,
    ) {
        self.0.retain(|s| s.name != name);
        self.0.push(Signable {
            name,
            data,
            identifier,
            entitlements,
        });
    }

    fn unqueue(&mut self, name: &str) {
        self.0.retain(|s| s.name != name);
    }

    fn commit(self, plan: &mut EditPlan) -> Result<()> {
        for s in self.0 {
            let signed = codesign::adhoc_sign(&s.data, &s.identifier, s.entitlements.as_deref())
                .with_context(|| format!("signing {}", s.name))?;
            plan.put(s.name, signed, MODE_EXEC);
        }
        Ok(())
    }
}

pub fn edit_bytes(
    input: &[u8],
    opts: &EditOptions,
    mode: WriteMode,
) -> Result<(Vec<u8>, EditReport)> {
    let mut archive = ZipArchive::new(Cursor::new(input))?;
    let (plan, mut report) = plan_edits(&mut archive, opts)?;
    drop(archive);
    let mut out = match &mode {
        WriteMode::Compact => plan.commit_compact(input)?,
        WriteMode::AppendInPlace => plan.commit_append(input)?,
    };
    // Last: fakesign must see the fully edited bundle.
    if opts.fakesign_bundle {
        let (signed, n) = crate::fakesign::fakesign_ipa(&out, opts, &mode)?;
        out = signed;
        report.fakesigned = Some(n);
    }
    Ok((out, report))
}

pub fn edit_file_append(path: &Path, opts: &EditOptions) -> Result<EditReport> {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let (plan, mut report) = plan_edits(&mut archive, opts)?;
    drop(archive);
    plan.commit_append_in_place(path)?;
    if opts.fakesign_bundle {
        let ipa = std::fs::read(path)?;
        let (signed, n) = crate::fakesign::fakesign_ipa(&ipa, opts, &WriteMode::AppendInPlace)?;
        std::fs::write(path, signed)?;
        report.fakesigned = Some(n);
    }
    Ok(report)
}

/// A staged edit if one targets `name`, else the original entry, so edits
/// compose instead of clobbering.
fn current_bytes<R: Read + Seek>(
    staged: &HashMap<String, Vec<u8>>,
    archive: &mut ZipArchive<R>,
    name: &str,
) -> Result<Vec<u8>> {
    match staged.get(name) {
        Some(bytes) => Ok(bytes.clone()),
        None => read_entry(archive, name),
    }
}

fn read_entry<R: Read + Seek>(archive: &mut ZipArchive<R>, name: &str) -> Result<Vec<u8>> {
    let mut f = archive
        .by_name(name)
        .with_context(|| format!("archive entry not found: {name}"))?;
    let mut buf = Vec::with_capacity(f.size() as usize);
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// `(source, path-relative-to-the-overlay-root)` pairs, sorted.
pub(crate) fn overlay_files(dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    if !dir.exists() {
        bail!("--overlay path does not exist: {}", dir.display());
    }
    if !dir.is_dir() {
        bail!("--overlay expects a directory, got {}", dir.display());
    }
    let root = std::fs::canonicalize(dir)
        .with_context(|| format!("resolving overlay dir {}", dir.display()))?;
    let mut out = Vec::new();
    walk_overlay(&root, dir, "", 0, &mut out)?;
    Ok(out)
}

/// Bounds symlink-driven recursion; a link back to an ancestor never ends.
const MAX_OVERLAY_DEPTH: usize = 32;

fn walk_overlay(
    root: &Path,
    dir: &Path,
    prefix: &str,
    depth: usize,
    out: &mut Vec<(PathBuf, String)>,
) -> Result<()> {
    if depth > MAX_OVERLAY_DEPTH {
        bail!("--overlay nests deeper than {MAX_OVERLAY_DEPTH} levels at {prefix}");
    }
    let mut children: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading overlay dir {}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    children.sort();
    for child in children {
        let name = child
            .file_name()
            .and_then(|s| s.to_str())
            .with_context(|| format!("unusable overlay file name: {}", child.display()))?;
        let rel = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let meta = std::fs::symlink_metadata(&child)
            .with_context(|| format!("reading overlay file {}", child.display()))?;
        if meta.file_type().is_symlink() {
            // A link out of the tree would smuggle in unrelated files.
            match std::fs::canonicalize(&child) {
                Ok(target) if target.starts_with(root) => {
                    if target.is_dir() {
                        walk_overlay(root, &target, &rel, depth + 1, out)?;
                    } else {
                        out.push((target, rel));
                    }
                }
                _ => eprintln!(
                    "warning: overlay: skipping symlink {rel} \
                     (target is outside the overlay, or missing)"
                ),
            }
        } else if meta.is_dir() {
            walk_overlay(root, &child, &rel, depth + 1, out)?;
        } else {
            out.push((child, rel));
        }
    }
    Ok(())
}

pub fn plan_edits<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    opts: &EditOptions,
) -> Result<(EditPlan, EditReport)> {
    let names: Vec<String> = archive.file_names().map(str::to_owned).collect();
    let app_dir = find_app_dir(&names)?;
    let mut report = EditReport {
        app_dir: app_dir.clone(),
        ..Default::default()
    };

    let mut plan = EditPlan::new();
    plan.set_deterministic(opts.deterministic);
    let mut to_sign = SignQueue::default();

    // Written after the tweaks so overlays win collisions, and thinned meanwhile.
    let mut staged: HashMap<String, Vec<u8>> = HashMap::new();
    let mut overlaid: Vec<(String, u32)> = Vec::new();
    for dir in &opts.overlays {
        let files = overlay_files(dir)?;
        if files.is_empty() {
            eprintln!("warning: overlay {} has no files", dir.display());
        }
        for (src, rel) in files {
            let data = std::fs::read(&src)
                .with_context(|| format!("reading overlay file {}", src.display()))?;
            let name = format!("{app_dir}{rel}");
            if !crate::archive::is_safe_entry_name(&name) {
                bail!("unsafe overlay destination: {rel}");
            }
            let mode = if is_executable(&src) {
                MODE_EXEC
            } else {
                MODE_FILE
            };
            match overlaid.iter_mut().find(|(n, _)| *n == name) {
                Some(slot) => slot.1 = mode,
                None => overlaid.push((name.clone(), mode)),
            }
            staged.insert(name, data);
            report.overlaid_files += 1;
        }
    }

    let info_name = format!("{app_dir}Info.plist");
    let mut info = current_bytes(&staged, archive, &info_name)?;
    let executable = bundle_executable(&info)?;
    report.executable = executable.clone();
    let bundle_id = bundle_string(&info, "CFBundleIdentifier");

    if opts.remove_watch {
        let prefix = format!("{app_dir}Watch/");
        if names.iter().any(|n| n.starts_with(&prefix)) {
            plan.remove_prefix(prefix.clone());
            report.removed.push(prefix);
        }
    }
    if opts.remove_extensions {
        for dir in appex_dirs(&names, &app_dir) {
            plan.remove_prefix(dir.clone());
            report.removed.push(dir);
        }
    } else if opts.remove_encrypted_extensions {
        for dir in appex_dirs(&names, &app_dir) {
            if appex_is_encrypted(&staged, archive, &dir)? {
                plan.remove_prefix(dir.clone());
                report.removed.push(dir);
            }
        }
    }

    // Before any signing, or the signature would seal pre-thin bytes.
    if opts.thin {
        let mut targets = names.clone();
        for (n, _) in &overlaid {
            if !targets.contains(n) {
                targets.push(n.clone());
            }
        }
        for n in &targets {
            // Thinning a removal-scheduled subtree would resurrect it.
            if report.removed.iter().any(|p| n.starts_with(p)) {
                continue;
            }
            let data = current_bytes(&staged, archive, n)?;
            let Some(thinned) = macho::thin_to_arm64(&data)? else {
                continue;
            };
            staged.insert(n.clone(), thinned.clone());
            plan.put(n.clone(), thinned, MODE_EXEC);
            report.thinned += 1;
        }
    }

    let mut staged_tweaks: Vec<tweak::Staged> = Vec::new();
    for p in &opts.tweaks {
        staged_tweaks.push(tweak::plan(p)?);
    }
    check_tweak_deps(&staged_tweaks, opts)?;

    let mut overlaid_binaries: Vec<tweak::StagedFile> = Vec::new();
    for (name, _) in &overlaid {
        let data = &staged[name];
        if !macho::is_macho(data) {
            continue;
        }
        let rel = name[app_dir.len()..].to_owned();
        let data = tweak::normalise_install_name(&rel, data.clone());
        overlaid_binaries.push(tweak::StagedFile {
            rel,
            data,
            exec: true,
        });
    }

    if !staged_tweaks.is_empty() || !overlaid_binaries.is_empty() {
        let mut existing: std::collections::HashSet<String> = names
            .iter()
            .filter_map(|n| n.strip_prefix(app_dir.as_str()).map(str::to_owned))
            .collect();
        existing.extend(
            overlaid
                .iter()
                .filter_map(|(n, _)| n.strip_prefix(app_dir.as_str()).map(str::to_owned)),
        );
        tweak::resolve_dependencies(&mut staged_tweaks, &mut overlaid_binaries, &existing)?;
    }

    // A loose dylib needs weak-linking or nothing loads it; frameworks link themselves.
    let mut weak_refs: Vec<String> = Vec::new();
    for f in overlaid_binaries {
        if let Some(file) = f.rel.strip_prefix("Frameworks/")
            && !file.contains('/')
            && file.ends_with(".dylib")
        {
            weak_refs.push(format!("@rpath/{file}"));
        }
        staged.insert(format!("{app_dir}{}", f.rel), f.data);
    }

    for pkg in staged_tweaks {
        for f in pkg.files {
            let name = format!("{app_dir}{}", f.rel);
            if macho::is_macho(&f.data) {
                to_sign.queue_staged(name, f.data);
            } else if f.exec {
                plan.put(name, f.data, MODE_EXEC);
            } else {
                plan.put(name, f.data, MODE_FILE);
            }
        }
        weak_refs.extend(pkg.weak_refs);
        report.tweaks.push(pkg.label);
    }

    for (name, mode) in &overlaid {
        let data = staged[name].clone();
        if macho::is_macho(&data) {
            to_sign.queue_staged(name.clone(), data);
        } else {
            // Or the signing pass would write the tweak's binary back on top.
            to_sign.unqueue(name);
            plan.put(name.clone(), data, *mode);
        }
    }

    let mut info_dirty = false;

    if let Some(name) = &opts.name {
        info = rename::set_bundle_name(&info, name)?;
        report.renamed = true;
        info_dirty = true;
    }

    if opts.touches_metadata() {
        if let Some(id) = &opts.bundle_id {
            info = plist_ops::set_bundle_id(&info, id)?;
            report.metadata.push(format!("bundle-id={id}"));
        }
        if let Some(v) = &opts.version {
            info = plist_ops::set_version(&info, v)?;
            report.metadata.push(format!("version={v}"));
        }
        if let Some(v) = &opts.min_os {
            info = plist_ops::set_min_os(&info, v)?;
            report.metadata.push(format!("min-os={v}"));
        }
        if opts.remove_supported_devices {
            info = plist_ops::remove_key(&info, "UISupportedDevices")?;
            report.metadata.push("remove-supported-devices".into());
        }
        if opts.enable_file_sharing {
            info = plist_ops::enable_file_sharing(&info)?;
            report.metadata.push("enable-file-sharing".into());
        }
        if let Some(p) = &opts.merge_plist {
            let overlay = std::fs::read(p)
                .with_context(|| format!("reading --merge-plist file {}", p.display()))?;
            info = plist_ops::merge_plist(&info, &overlay)?;
            report.metadata.push("merge-plist".into());
        }
        info_dirty = true;
    }

    // Car replacements from every source, applied in ONE scar round-trip:
    // each merge is a full decompile+compile of the catalogue.
    let car_name = format!("{app_dir}Assets.car");
    let mut car_replacements: Vec<(String, Vec<u8>)> = Vec::new();
    let mut icon_asset = None;

    if let Some(src) = &opts.icon {
        let src_png = std::fs::read(src)
            .with_context(|| format!("reading --icon source {}", src.display()))?;
        let asset = icons::primary_icon_name(&info);
        for file in icons::primary_icon_files(&asset, &src_png)? {
            plan.put(format!("{app_dir}{}", file.filename), file.png, MODE_FILE);
        }
        info = icons::patch_primary_icon_plist(&info, &asset)?;
        info_dirty = true;
        report.primary_icon = true;

        if names.iter().any(|n| n == &car_name) || staged.contains_key(&car_name) {
            // scar matches renditions on exact dimensions, so offer every size.
            for (_, png) in icons::render_sizes(&src_png, icons::ICON_SIZES)? {
                car_replacements.push((asset.clone(), png));
            }
            icon_asset = Some(asset);
        }
    }

    if !opts.alt_icons.is_empty() {
        let mut alts = Vec::new();
        for (icon_name, src) in &opts.alt_icons {
            let src_png = std::fs::read(src)
                .with_context(|| format!("reading alt-icon source {}", src.display()))?;
            let alt = icons::generate_alt_icon(icon_name, &src_png)?;
            for file in &alt.files {
                plan.put(
                    format!("{app_dir}{}", file.filename),
                    file.png.clone(),
                    MODE_FILE,
                );
            }
            alts.push(alt);
        }
        info = icons::patch_icons_plist(&info, &alts)?;
        report.alt_icons = alts.len();
        info_dirty = true;
    }

    if info_dirty {
        plan.put(info_name, info, MODE_FILE);
    }

    if let Some(name) = &opts.name {
        let suffix = "/InfoPlist.strings";
        let mut targets = names.clone();
        for (n, _) in &overlaid {
            if !targets.contains(n) {
                targets.push(n.clone());
            }
        }
        for n in &targets {
            if n.starts_with(&app_dir) && n.ends_with(suffix) && n.contains(".lproj/") {
                let data = current_bytes(&staged, archive, n)?;
                if let Some(updated) = rename::update_infoplist_strings(&data, name) {
                    plan.put(n.clone(), updated, MODE_FILE);
                    report.lproj_updated += 1;
                }
            }
        }
    }

    if let Some(dir) = &opts.merge_car {
        if !names.iter().any(|n| n == &car_name) && !staged.contains_key(&car_name) {
            bail!("--merge-car requested but {car_name} is not in the archive");
        }
        // After the icon replacements, so these win overlapping renditions.
        car_replacements.extend(merge::dir_replacements(dir)?);
    }

    if !car_replacements.is_empty() {
        let car = current_bytes(&staged, archive, &car_name)?;
        let (merged, m) = merge::merge_car(&car, &car_replacements, opts.merge_car.is_some())?;
        if m.replaced > 0 || !m.added.is_empty() {
            plan.put(car_name, merged, MODE_FILE);
        }
        report.car_replaced = m.replaced;
        report.car_added = m.added;
        // Icon sizes the catalogue lacks are expected misses, not news.
        report.car_unmatched = m
            .unmatched
            .into_iter()
            .filter(|n| Some(n) != icon_asset.as_ref())
            .collect();
    }

    // A package of only frameworks and resources leaves the executable alone.
    if !weak_refs.is_empty() || opts.entitlements.is_some() {
        let exe_name = format!("{app_dir}{executable}");
        let mut exe = current_bytes(&staged, archive, &exe_name)?;
        // The existing LC_CODE_SIGNATURE stays put: adding one back would
        // need header cave the weak-link injection may have just consumed.
        for r in &weak_refs {
            exe = macho::inject_weak_dylib(&exe, r)?;
        }
        exe = macho::ensure_rpath(&exe, "@executable_path/Frameworks")?;

        let entitlements_xml = match &opts.entitlements {
            Some(p) => Some(
                std::fs::read_to_string(p)
                    .with_context(|| format!("reading entitlements {}", p.display()))?,
            ),
            None => None,
        };
        let identifier = opts
            .bundle_id
            .as_deref()
            .or(bundle_id.as_deref())
            .unwrap_or(&executable)
            .to_owned();
        // Replaces the overlay pass's queueing: sign the weak-linked bytes.
        to_sign.queue(exe_name, exe, identifier, entitlements_xml);
        report.resigned = true;
    }

    to_sign.commit(&mut plan)?;

    Ok((plan, report))
}

/// A tweak missing its `Depends:` stages fine then silently fails to load; an
/// unsatisfied dep is therefore an error, a conflict only a warning.
fn check_tweak_deps(staged: &[tweak::Staged], opts: &EditOptions) -> Result<()> {
    let issues = tweak::check_dependencies(staged);
    for (pkg, other, name) in &issues.conflicts {
        if name == other {
            eprintln!("warning: {pkg} conflicts with {other}");
        } else {
            eprintln!("warning: {pkg} conflicts with {other} (which provides {name})");
        }
    }
    if issues.missing.is_empty() {
        return Ok(());
    }
    let listed: Vec<String> = issues
        .missing
        .iter()
        .map(|(pkg, dep)| format!("  {pkg} needs {dep}"))
        .collect();
    let listed = listed.join("\n");
    if opts.ignore_missing_deps {
        eprintln!("warning: tweak dependencies are not satisfied:\n{listed}");
        return Ok(());
    }
    bail!(
        "tweak dependencies are not satisfied:\n{listed}\n\
         supply the missing .deb(s) with --tweak, or pass --ignore-missing-deps"
    );
}

fn appex_dirs(names: &[String], app_dir: &str) -> Vec<String> {
    let plugins = format!("{app_dir}PlugIns/");
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let Some(rest) = n.strip_prefix(&plugins) else {
            continue;
        };
        let Some(seg) = rest.split('/').next() else {
            continue;
        };
        if seg.ends_with(".appex") {
            let dir = format!("{plugins}{seg}/");
            if !out.contains(&dir) {
                out.push(dir);
            }
        }
    }
    out
}

/// FairPlay `cryptid != 0`; a missing executable counts as not encrypted.
fn appex_is_encrypted<R: Read + Seek>(
    staged: &HashMap<String, Vec<u8>>,
    archive: &mut ZipArchive<R>,
    dir: &str,
) -> Result<bool> {
    let info = current_bytes(staged, archive, &format!("{dir}Info.plist"))?;
    let Some(exe) = bundle_string(&info, "CFBundleExecutable") else {
        return Ok(false);
    };
    let Ok(macho) = current_bytes(staged, archive, &format!("{dir}{exe}")) else {
        return Ok(false);
    };
    Ok(macho::encryption_cryptid(&macho).unwrap_or(0) != 0)
}

pub(crate) fn find_app_dir(names: &[String]) -> Result<String> {
    let mut apps: Vec<String> = Vec::new();
    for n in names {
        let Some(rest) = n.strip_prefix("Payload/") else {
            continue;
        };
        let Some(seg) = rest.split('/').next() else {
            continue;
        };
        if seg.ends_with(".app") {
            let dir = format!("Payload/{seg}/");
            if !apps.contains(&dir) {
                apps.push(dir);
            }
        }
    }
    match apps.len() {
        0 => bail!("no Payload/*.app directory found — not an IPA?"),
        1 => Ok(apps.pop().unwrap()),
        _ => bail!("multiple .app bundles under Payload/: {apps:?}"),
    }
}

fn bundle_executable(info: &[u8]) -> Result<String> {
    bundle_string(info, "CFBundleExecutable").context("Info.plist has no CFBundleExecutable")
}

fn bundle_string(info: &[u8], key: &str) -> Option<String> {
    let v = Value::from_reader(Cursor::new(info)).ok()?;
    v.as_dictionary()?.get(key)?.as_string().map(str::to_owned)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    false
}

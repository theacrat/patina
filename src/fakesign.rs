//! Full-bundle ad-hoc fakesign (`--fakesign-bundle`), entirely in-memory: a
//! bundle-sealing walk over zip entries. Sealing forces an O(bundle) read.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

use anyhow::{Context, Result};
use plist::Value;
use zip::ZipArchive;

use crate::archive::{EditPlan, MODE_EXEC, MODE_FILE};
use crate::code_resources::{
    CodeResources, CodeResourcesRule, FilesFlavor, MachOSeal, needs_sha1_seals,
    normalized_resources_path,
};
use crate::codesign::{self, SealOptions, multi_digest};
use crate::edit::{EditOptions, WriteMode, find_app_dir};
use crate::macho;

/// Returns the re-spliced archive and the number of Mach-Os signed.
pub fn fakesign_ipa(ipa: &[u8], opts: &EditOptions, mode: &WriteMode) -> Result<(Vec<u8>, usize)> {
    let entries = Entries::read(ipa)?;
    let names: Vec<String> = entries.list.iter().map(|e| e.name.clone()).collect();
    let app_dir = find_app_dir(&names)?;

    // Deepest-first: a nested bundle is signed before its parent seals it.
    let bundles = discover_bundles(&entries, &app_dir);
    if !bundles.iter().any(|b| b == &app_dir) {
        eprintln!(
            "warning: {app_dir} has no discoverable Info.plist/CFBundleExecutable; \
             the app itself will not be sealed"
        );
    }

    let entitlements = match &opts.entitlements {
        Some(p) => Some(
            std::fs::read_to_string(p)
                .with_context(|| format!("reading entitlements {}", p.display()))?,
        ),
        None => None,
    };

    let mut state = State::default();
    for bundle in &bundles {
        sign_bundle(
            &entries,
            &mut state,
            bundle,
            &bundles,
            &app_dir,
            entitlements.as_deref(),
        )?;
    }

    let mut plan = EditPlan::new();
    plan.set_deterministic(opts.deterministic);
    for (name, data) in state.staged {
        if name.ends_with("/CodeResources") || name.contains("/_CodeSignature/") {
            plan.put(name, data, MODE_FILE);
        } else {
            plan.put(name, data, MODE_EXEC);
        }
    }

    let out = match mode {
        WriteMode::Compact => plan.commit_compact(ipa)?,
        WriteMode::AppendInPlace => plan.commit_append(ipa)?,
    };
    Ok((out, state.count))
}

struct Entry {
    name: String,
    is_dir: bool,
    is_symlink: bool,
    data: Vec<u8>,
}

struct Entries {
    list: Vec<Entry>,
    index: HashMap<String, usize>,
}

impl Entries {
    fn read(ipa: &[u8]) -> Result<Self> {
        let mut archive = ZipArchive::new(Cursor::new(ipa))?;
        let mut list = Vec::with_capacity(archive.len());
        let mut index = HashMap::with_capacity(archive.len());
        for i in 0..archive.len() {
            let mut f = archive.by_index(i)?;
            let name = f.name().to_owned();
            let is_dir = f.is_dir();
            let is_symlink = f.is_symlink();
            let mut data = Vec::with_capacity(f.size() as usize);
            f.read_to_end(&mut data)?;
            index.insert(name.clone(), list.len());
            list.push(Entry {
                name,
                is_dir,
                is_symlink,
                data,
            });
        }
        Ok(Self { list, index })
    }

    fn data(&self, name: &str) -> Option<&[u8]> {
        self.index.get(name).map(|&i| self.list[i].data.as_slice())
    }

    fn contains(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }
}

#[derive(Default)]
struct State {
    staged: HashMap<String, Vec<u8>>,
    signed: HashSet<String>,
    /// Bundle prefix → its signed main executable's seal info.
    main_info: HashMap<String, MachOSeal>,
    count: usize,
}

/// Bundle prefixes (trailing `/`) under `app_dir`, deepest first.
fn discover_bundles(entries: &Entries, app_dir: &str) -> Vec<String> {
    let mut set: Vec<String> = Vec::new();
    for e in &entries.list {
        let Some(prefix) = e.name.strip_suffix("Info.plist") else {
            continue;
        };
        if !prefix.starts_with(app_dir) && prefix != app_dir {
            continue;
        }
        if !prefix.is_empty() && !prefix.ends_with('/') {
            continue; // "…FooInfo.plist" — not a bundle Info.plist
        }
        if let Some(exe) = plist_string(&e.data, "CFBundleExecutable") {
            if entries.contains(&format!("{prefix}{exe}")) && !set.contains(&prefix.to_owned()) {
                set.push(prefix.to_owned());
            }
        }
    }
    set.sort_by_key(|b| std::cmp::Reverse(b.matches('/').count()));
    set
}

fn parent_bundle<'a>(bundles: &'a [String], path: &str) -> Option<&'a String> {
    bundles
        .iter()
        .filter(|b| b.as_str() != path && path.starts_with(b.as_str()))
        .max_by_key(|b| b.len())
}

fn sign_bundle(
    entries: &Entries,
    state: &mut State,
    bundle: &str,
    bundles: &[String],
    app_dir: &str,
    entitlements: Option<&str>,
) -> Result<()> {
    let info_name = format!("{bundle}Info.plist");
    let info_data = entries
        .data(&info_name)
        .with_context(|| format!("bundle {bundle} has no Info.plist"))?
        .to_vec();
    let exe_rel = plist_string(&info_data, "CFBundleExecutable")
        .with_context(|| format!("bundle {bundle} Info.plist has no CFBundleExecutable"))?;
    let main_name = format!("{bundle}{exe_rel}");
    let main_data = entries
        .data(&main_name)
        .with_context(|| format!("bundle {bundle} main executable {exe_rel} missing"))?
        .to_vec();

    let has_resources = entries
        .list
        .iter()
        .any(|e| e.name.starts_with(&format!("{bundle}Resources/")));
    let flavor = if needs_sha1_seals(&main_data) {
        FilesFlavor::Rules2WithSha1
    } else {
        FilesFlavor::Rules2
    };
    let mut rules = build_rules(has_resources, &exe_rel)?;

    // A `nested` rule seals the child by cdhash and skips its subtree.
    let mut skip: Vec<String> = Vec::new();
    for child in bundles {
        if parent_bundle(bundles, child).map(String::as_str) != Some(bundle) {
            continue;
        }
        let rel = &child[bundle.len()..];
        let rel_dir = rel.trim_end_matches('/');
        if let Some(rule) = find_rule(&rules.rules2, rel_dir) {
            if rule.nested && rel_dir.contains('.') {
                if let Some(info) = state.main_info.get(child) {
                    rules
                        .cr
                        .seal_macho(&normalized_resources_path(rel_dir), info, rule.optional);
                }
                skip.push(rel.to_owned());
            }
        }
    }

    for e in &entries.list {
        if !e.name.starts_with(bundle) || e.name == *bundle {
            continue;
        }
        let rel = e.name[bundle.len()..].to_owned();
        if rel.is_empty() || rel == exe_rel || e.is_dir {
            continue; // main exe is sealed last
        }
        if skip.iter().any(|p| rel.starts_with(p.as_str())) {
            continue;
        }
        let normalized = normalized_resources_path(&rel);

        // rules2 → the `files2` plist key.
        if let Some(rule) = find_rule(&rules.rules2, &rel) {
            if !rule.exclude {
                if e.is_symlink {
                    if !rule.omit {
                        let target = String::from_utf8_lossy(&e.data).into_owned();
                        rules.cr.seal_symlink(&normalized, target);
                    }
                } else if rule.nested && macho::is_macho(&e.data) {
                    let signed = sign_or_get(entries, state, &e.name, &file_stem(&rel))?;
                    let info = MachOSeal::parse(&signed)
                        .with_context(|| format!("seal info for {}", e.name))?;
                    rules.cr.seal_macho(&normalized, &info, rule.optional);
                } else if !rule.omit {
                    let bytes = if macho::is_macho(&e.data) {
                        sign_or_get(entries, state, &e.name, &file_stem(&rel))?
                    } else {
                        e.data.clone()
                    };
                    rules.cr.seal_regular_file(
                        flavor,
                        &normalized,
                        multi_digest(&bytes),
                        rule.optional,
                    );
                }
            }
        }

        // rules1 → the `files` plist key: regular files only, always SHA-1.
        if !e.is_symlink {
            if let Some(rule) = find_rule(&rules.rules1, &rel) {
                if !rule.exclude {
                    let bytes = current(entries, state, &e.name)?;
                    rules.cr.seal_regular_file(
                        FilesFlavor::Rules,
                        &normalized,
                        multi_digest(&bytes),
                        rule.optional,
                    );
                }
            }
        }
    }

    // The main executable carries the seal's digest, so it is signed last.
    let mut resources = Vec::new();
    rules.cr.to_writer_xml(&mut resources)?;

    let ident = plist_string(&info_data, "CFBundleIdentifier").unwrap_or_else(|| exe_rel.clone());
    let ent = if bundle == app_dir {
        entitlements
    } else {
        None
    };
    let signed_main = sign_main(&main_data, &ident, &resources, &info_data, ent)
        .with_context(|| format!("signing main executable of {bundle}"))?;
    let info = MachOSeal::parse(&signed_main)
        .with_context(|| format!("seal info for main executable of {bundle}"))?;
    state
        .staged
        .insert(format!("{bundle}_CodeSignature/CodeResources"), resources);
    state.main_info.insert(bundle.to_owned(), info);
    state.signed.insert(main_name.clone());
    state.staged.insert(main_name, signed_main);
    state.count += 1;
    Ok(())
}

fn sign_or_get(entries: &Entries, state: &mut State, name: &str, ident: &str) -> Result<Vec<u8>> {
    if state.signed.contains(name) {
        return state
            .staged
            .get(name)
            .cloned()
            .with_context(|| format!("internal: {name} signed but not staged"));
    }
    let data = entries
        .data(name)
        .with_context(|| format!("missing entry {name}"))?;
    let signed =
        codesign::adhoc_sign(data, ident, None).with_context(|| format!("signing {name}"))?;
    state.signed.insert(name.to_owned());
    state.staged.insert(name.to_owned(), signed.clone());
    state.count += 1;
    Ok(signed)
}

/// The staged (signed) bytes of `name` if any, else the original entry.
fn current(entries: &Entries, state: &State, name: &str) -> Result<Vec<u8>> {
    if let Some(b) = state.staged.get(name) {
        return Ok(b.clone());
    }
    entries
        .data(name)
        .map(|d| d.to_vec())
        .with_context(|| format!("missing entry {name}"))
}

/// Seals Info.plist + CodeResources into the CodeDirectory's special slots.
fn sign_main(
    exe: &[u8],
    ident: &str,
    resources: &[u8],
    info_plist: &[u8],
    entitlements: Option<&str>,
) -> Result<Vec<u8>> {
    // Absent an override, entitlements already in the binary are preserved.
    let inherited = codesign::embedded_entitlements(exe);
    codesign::adhoc_sign_sealing(
        exe,
        ident,
        &SealOptions {
            entitlements_xml: entitlements.or(inherited.as_deref()),
            info_plist: Some(info_plist),
            code_resources: Some(resources),
        },
    )
}

struct Rules {
    cr: CodeResources,
    rules1: Vec<CodeResourcesRule>,
    rules2: Vec<CodeResourcesRule>,
}

/// `(pattern, nested, omit, optional, weight)`.
type Spec = (&'static str, bool, bool, bool, Option<u32>);

const RES_RULES1: &[Spec] = &[
    ("^version.plist$", false, false, false, None),
    ("^Resources/", false, false, false, None),
    ("^Resources/.*\\.lproj/", false, false, true, Some(1000)),
    ("^Resources/Base\\.lproj/", false, false, false, Some(1010)),
    (
        "^Resources/.*\\.lproj/locversion.plist$",
        false,
        true,
        false,
        Some(1100),
    ),
];
const RES_RULES2: &[Spec] = &[
    ("^.*", false, false, false, None),
    ("^[^/]+$", true, false, false, Some(10)),
    (
        "^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/",
        true,
        false,
        false,
        Some(10),
    ),
    (".*\\.dSYM($|/)", false, false, false, Some(11)),
    ("^(.*/)?\\.DS_Store$", false, true, false, Some(2000)),
    ("^Info\\.plist$", false, true, false, Some(20)),
    ("^version\\.plist$", false, false, false, Some(20)),
    (
        "^embedded\\.provisionprofile$",
        false,
        false,
        false,
        Some(20),
    ),
    ("^PkgInfo$", false, true, false, Some(20)),
    ("^Resources/", false, false, false, Some(20)),
    ("^Resources/.*\\.lproj/", false, false, true, Some(1000)),
    ("^Resources/Base\\.lproj/", false, false, false, Some(1010)),
    (
        "^Resources/.*\\.lproj/locversion.plist$",
        false,
        true,
        false,
        Some(1100),
    ),
];
const NO_RES_RULES1: &[Spec] = &[
    ("^version.plist$", false, false, false, None),
    ("^.*", false, false, false, None),
    ("^.*\\.lproj/", false, false, true, Some(1000)),
    ("^Base\\.lproj/", false, false, false, Some(1010)),
    (
        "^.*\\.lproj/locversion.plist$",
        false,
        true,
        false,
        Some(1100),
    ),
];
const NO_RES_RULES2: &[Spec] = &[
    ("^.*", false, false, false, None),
    (".*\\.dSYM($|/)", false, false, false, Some(11)),
    ("^(.*/)?\\.DS_Store$", false, true, false, Some(2000)),
    ("^Info\\.plist$", false, true, false, Some(20)),
    ("^version\\.plist$", false, false, false, Some(20)),
    (
        "^embedded\\.provisionprofile$",
        false,
        false,
        false,
        Some(20),
    ),
    ("^PkgInfo$", false, true, false, Some(20)),
    ("^.*\\.lproj/", false, false, true, Some(1000)),
    ("^Base\\.lproj/", false, false, false, Some(1010)),
    (
        "^.*\\.lproj/locversion.plist$",
        false,
        true,
        false,
        Some(1100),
    ),
];

fn make_rule(spec: &Spec) -> Result<CodeResourcesRule> {
    let (pattern, nested, omit, optional, weight) = *spec;
    let mut rule = CodeResourcesRule::new(pattern)?;
    if nested {
        rule = rule.nested();
    }
    if omit {
        rule = rule.omit();
    }
    if optional {
        rule = rule.optional();
    }
    if let Some(w) = weight {
        rule = rule.weight(w);
    }
    Ok(rule)
}

fn build_rules(has_resources: bool, main_exe_rel: &str) -> Result<Rules> {
    let (specs1, specs2) = if has_resources {
        (RES_RULES1, RES_RULES2)
    } else {
        (NO_RES_RULES1, NO_RES_RULES2)
    };

    let mut cr = CodeResources::default();
    let mut rules1 = Vec::new();
    let mut rules2 = Vec::new();
    for spec in specs1 {
        let rule = make_rule(spec)?;
        cr.add_rule(&rule);
        rules1.push(rule);
    }
    for spec in specs2 {
        let rule = make_rule(spec)?;
        cr.add_rule2(&rule);
        rules2.push(rule);
    }

    let mut exclusions = vec![
        CodeResourcesRule::new("^_CodeSignature/")?.exclude(),
        CodeResourcesRule::new("^CodeResources$")?.exclude(),
        CodeResourcesRule::new("^_MASReceipt$")?.exclude(),
    ];
    // The main executable is sealed specially (it carries the resource digest).
    exclusions.push(
        CodeResourcesRule::new(format!(
            "^{}$",
            regex::escape(&normalized_resources_path(main_exe_rel))
        ))?
        .exclude(),
    );
    for rule in exclusions {
        rules1.push(rule.clone());
        rules2.push(rule);
    }

    // Exclusions first, then highest weight; `find_rule` takes the first match.
    rules1.sort();
    rules2.sort();
    Ok(Rules { cr, rules1, rules2 })
}

fn find_rule(rules: &[CodeResourcesRule], path: &str) -> Option<CodeResourcesRule> {
    let normalized = normalized_resources_path(path);
    rules.iter().find(|r| r.matches(&normalized)).cloned()
}

fn plist_string(info: &[u8], key: &str) -> Option<String> {
    Value::from_reader(Cursor::new(info))
        .ok()?
        .as_dictionary()?
        .get(key)?
        .as_string()
        .map(str::to_owned)
}

fn file_stem(rel: &str) -> String {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name.rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(name)
        .to_owned()
}

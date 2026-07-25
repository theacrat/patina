//! `_CodeSignature/CodeResources` construction. The plist is itself digested
//! into the main executable's CodeDirectory, and the emitted XML is
//! byte-compatible with Apple's `codesign`.

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::{Context, Result};
use plist::{Dictionary, Value};

use crate::codesign::{self, MultiDigest};
use crate::macho;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesFlavor {
    /// `<files>` — SHA-1 only.
    Rules,
    /// `<files2>` — SHA-256 only.
    Rules2,
    /// `<files2>` — SHA-256 plus a legacy SHA-1.
    Rules2WithSha1,
}

/// A `<rules>`/`<rules2>` entry; fields are a superset of both sections.
#[derive(Clone, Debug)]
pub struct CodeResourcesRule {
    pub pattern: String,
    pub exclude: bool,
    /// Independently signable; sealed by cdhash.
    pub nested: bool,
    pub omit: bool,
    pub optional: bool,
    pub weight: Option<u32>,
    re: regex::Regex,
}

impl CodeResourcesRule {
    pub fn new(pattern: impl Into<String>) -> Result<Self> {
        let pattern = pattern.into();
        let re = regex::Regex::new(&pattern)
            .with_context(|| format!("compiling resource rule /{pattern}/"))?;
        Ok(Self {
            pattern,
            exclude: false,
            nested: false,
            omit: false,
            optional: false,
            weight: None,
            re,
        })
    }

    #[must_use]
    pub fn exclude(mut self) -> Self {
        self.exclude = true;
        self
    }

    #[must_use]
    pub fn nested(mut self) -> Self {
        self.nested = true;
        self
    }

    #[must_use]
    pub fn omit(mut self) -> Self {
        self.omit = true;
        self
    }

    #[must_use]
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    #[must_use]
    pub fn weight(mut self, v: u32) -> Self {
        self.weight = Some(v);
        self
    }

    pub fn matches(&self, normalized_path: &str) -> bool {
        self.re.is_match(normalized_path)
    }
}

impl PartialEq for CodeResourcesRule {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
            && self.exclude == other.exclude
            && self.nested == other.nested
            && self.omit == other.omit
            && self.optional == other.optional
            && self.weight == other.weight
    }
}

impl Eq for CodeResourcesRule {}

impl PartialOrd for CodeResourcesRule {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Highest priority first: exclusions, then descending weight (default 1).
impl Ord for CodeResourcesRule {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.exclude, other.exclude) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => other.weight.unwrap_or(1).cmp(&self.weight.unwrap_or(1)),
        }
    }
}

pub fn normalized_resources_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    path.strip_prefix("Contents/").unwrap_or(&path).to_string()
}

#[derive(Clone, Debug)]
pub struct MachOSeal {
    /// SHA-256 of the CodeDirectory truncated to 20 bytes.
    pub cdhash: Vec<u8>,
    pub requirement: Option<String>,
}

impl MachOSeal {
    pub fn parse(macho: &[u8]) -> Result<Self> {
        let hashes = codesign::cdhashes(macho)?;
        // Ad-hoc: empty requirement set, so the designated requirement is the OR'd slice cdhashes.
        let requirement = hashes
            .iter()
            .map(|h| format!("cdhash H\"{}\"", hex(h)))
            .reduce(|a, b| format!("({a}) or ({b})"));
        let cdhash = hashes
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Mach-O contains no signed slices"))?;
        Ok(Self {
            cdhash,
            requirement,
        })
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Whether resources also need SHA-1 seals: the target OS predates SHA-256 seal support.
pub fn needs_sha1_seals(exe: &[u8]) -> bool {
    let Ok(slices) = macho::thin_slices(exe) else {
        return true;
    };
    if slices.is_empty() {
        return true;
    }
    slices.iter().any(|s| match target(s) {
        Some((platform, min_os)) => match platform {
            PLATFORM_MACOS => min_os < (10, 11, 4),
            PLATFORM_IOS | PLATFORM_TVOS => min_os < (11, 0, 0),
            // watchOS always seals with SHA-1; an unset platform is unknown.
            PLATFORM_WATCHOS | 0 => true,
            _ => false,
        },
        None => true,
    })
}

const PLATFORM_MACOS: u32 = 1;
const PLATFORM_IOS: u32 = 2;
const PLATFORM_TVOS: u32 = 3;
const PLATFORM_WATCHOS: u32 = 4;

type Version = (u32, u32, u32);

/// `(platform, minimum OS version)`, from `LC_BUILD_VERSION` or the legacy `LC_VERSION_MIN_*`.
fn target(thin: &[u8]) -> Option<(u32, Version)> {
    let lcs = macho::thin_load_commands(thin).ok()?;

    for (cmd, body) in &lcs {
        if *cmd == macho::LC_BUILD_VERSION && body.len() >= 24 {
            return Some((
                u32::from_le_bytes(body[8..12].try_into().ok()?),
                nibble_version(u32::from_le_bytes(body[12..16].try_into().ok()?)),
            ));
        }
    }
    for (cmd, body) in &lcs {
        let platform = match *cmd {
            macho::LC_VERSION_MIN_MACOSX => PLATFORM_MACOS,
            macho::LC_VERSION_MIN_IPHONEOS => PLATFORM_IOS,
            macho::LC_VERSION_MIN_TVOS => PLATFORM_TVOS,
            macho::LC_VERSION_MIN_WATCHOS => PLATFORM_WATCHOS,
            _ => continue,
        };
        if body.len() >= 16 {
            return Some((
                platform,
                nibble_version(u32::from_le_bytes(body[8..12].try_into().ok()?)),
            ));
        }
    }
    None
}

/// Mach-O versions are `xxxx.yy.zz` packed into nibble groups.
fn nibble_version(v: u32) -> Version {
    (v >> 16, (v >> 8) & 0xff, v & 0xff)
}

#[derive(Clone, PartialEq)]
enum FilesValue {
    Required(Vec<u8>),
    Optional(Vec<u8>),
}

impl From<&FilesValue> for Value {
    fn from(v: &FilesValue) -> Self {
        match v {
            FilesValue::Required(digest) => Value::Data(digest.clone()),
            FilesValue::Optional(digest) => {
                let mut d = Dictionary::new();
                d.insert("hash".into(), Value::Data(digest.clone()));
                d.insert("optional".into(), Value::Boolean(true));
                Value::Dictionary(d)
            }
        }
    }
}

#[derive(Clone, Default, PartialEq)]
struct Files2Value {
    cdhash: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
    hash2: Option<Vec<u8>>,
    optional: Option<bool>,
    requirement: Option<String>,
    symlink: Option<String>,
}

impl From<&Files2Value> for Value {
    fn from(v: &Files2Value) -> Self {
        // Keys are emitted in this order to match Apple's output.
        let mut d = Dictionary::new();
        if let Some(x) = &v.cdhash {
            d.insert("cdhash".into(), Value::Data(x.clone()));
        }
        if let Some(x) = &v.hash {
            d.insert("hash".into(), Value::Data(x.clone()));
        }
        if let Some(x) = &v.hash2 {
            d.insert("hash2".into(), Value::Data(x.clone()));
        }
        if let Some(x) = v.optional {
            d.insert("optional".into(), Value::Boolean(x));
        }
        if let Some(x) = &v.requirement {
            d.insert("requirement".into(), Value::String(x.clone()));
        }
        if let Some(x) = &v.symlink {
            d.insert("symlink".into(), Value::String(x.clone()));
        }
        Value::Dictionary(d)
    }
}

#[derive(Clone, PartialEq)]
struct RulesValue {
    omit: bool,
    required: bool,
    weight: Option<f64>,
}

impl From<&RulesValue> for Value {
    fn from(v: &RulesValue) -> Self {
        if v.required && !v.omit && v.weight.is_none() {
            return Value::Boolean(true);
        }
        let mut d = Dictionary::new();
        if v.omit {
            d.insert("omit".into(), Value::Boolean(true));
        }
        if !v.required {
            d.insert("optional".into(), Value::Boolean(true));
        }
        if let Some(w) = v.weight {
            d.insert("weight".into(), Value::Real(w));
        }
        Value::Dictionary(d)
    }
}

#[derive(Clone, PartialEq)]
struct Rules2Value {
    nested: Option<bool>,
    omit: Option<bool>,
    optional: Option<bool>,
    weight: Option<f64>,
}

impl From<&Rules2Value> for Value {
    fn from(v: &Rules2Value) -> Self {
        let mut d = Dictionary::new();
        if v.nested == Some(true) {
            d.insert("nested".into(), Value::Boolean(true));
        }
        if v.omit == Some(true) {
            d.insert("omit".into(), Value::Boolean(true));
        }
        if v.optional == Some(true) {
            d.insert("optional".into(), Value::Boolean(true));
        }
        if let Some(w) = v.weight {
            d.insert("weight".into(), Value::Real(w));
        }
        if d.is_empty() {
            Value::Boolean(true)
        } else {
            Value::Dictionary(d)
        }
    }
}

#[derive(Clone, Default, PartialEq)]
pub struct CodeResources {
    files: BTreeMap<String, FilesValue>,
    files2: BTreeMap<String, Files2Value>,
    rules: BTreeMap<String, RulesValue>,
    rules2: BTreeMap<String, Rules2Value>,
}

impl CodeResources {
    pub fn add_rule(&mut self, rule: &CodeResourcesRule) {
        self.rules.insert(
            rule.pattern.clone(),
            RulesValue {
                omit: rule.omit,
                required: !rule.optional,
                weight: rule.weight.map(f64::from),
            },
        );
    }

    pub fn add_rule2(&mut self, rule: &CodeResourcesRule) {
        self.rules2.insert(
            rule.pattern.clone(),
            Rules2Value {
                nested: rule.nested.then_some(true),
                omit: rule.omit.then_some(true),
                optional: rule.optional.then_some(true),
                weight: rule.weight.map(f64::from),
            },
        );
    }

    pub fn seal_regular_file(
        &mut self,
        flavor: FilesFlavor,
        path: &str,
        digests: MultiDigest,
        optional: bool,
    ) {
        match flavor {
            FilesFlavor::Rules => {
                self.files.insert(
                    path.to_owned(),
                    if optional {
                        FilesValue::Optional(digests.sha1)
                    } else {
                        FilesValue::Required(digests.sha1)
                    },
                );
            }
            FilesFlavor::Rules2 | FilesFlavor::Rules2WithSha1 => {
                self.files2.insert(
                    path.to_owned(),
                    Files2Value {
                        hash: matches!(flavor, FilesFlavor::Rules2WithSha1).then_some(digests.sha1),
                        hash2: Some(digests.sha256),
                        optional: optional.then_some(true),
                        ..Default::default()
                    },
                );
            }
        }
    }

    /// `<files>` has no symlink representation, so symlinks go in `<files2>`.
    pub fn seal_symlink(&mut self, path: &str, target: impl Into<String>) {
        self.files2.insert(
            path.to_owned(),
            Files2Value {
                symlink: Some(target.into()),
                ..Default::default()
            },
        );
    }

    /// `path` may also be a nested bundle, sealed by its main executable's cdhash.
    pub fn seal_macho(&mut self, path: &str, seal: &MachOSeal, optional: bool) {
        self.files2.insert(
            path.to_owned(),
            Files2Value {
                cdhash: Some(seal.cdhash.clone()),
                optional: optional.then_some(true),
                requirement: seal.requirement.clone(),
                ..Default::default()
            },
        );
    }

    pub fn to_writer_xml(&self, mut writer: impl Write) -> Result<()> {
        let mut data = Vec::new();
        Value::from(self).to_writer_xml(&mut data)?;
        let data = String::from_utf8(data).expect("plist XML is always valid UTF-8");

        // Apple emits `<dict/>` unspaced, leaves quotes unescaped, and ends the file with a newline.
        let data = data
            .replace("<dict />", "<dict/>")
            .replace("<true />", "<true/>")
            .replace("&quot;", "\"");

        writer.write_all(data.as_bytes())?;
        writer.write_all(b"\n")?;
        Ok(())
    }
}

impl From<&CodeResources> for Value {
    fn from(cr: &CodeResources) -> Self {
        fn section<'a, T>(map: &'a BTreeMap<String, T>) -> Value
        where
            Value: From<&'a T>,
        {
            Value::Dictionary(
                map.iter()
                    .map(|(k, v)| (k.clone(), Value::from(v)))
                    .collect(),
            )
        }

        let mut d = Dictionary::new();
        d.insert("files".into(), section(&cr.files));
        d.insert("files2".into(), section(&cr.files2));
        if !cr.rules.is_empty() {
            d.insert("rules".into(), section(&cr.rules));
        }
        if !cr.rules2.is_empty() {
            d.insert("rules2".into(), section(&cr.rules2));
        }
        Value::Dictionary(d)
    }
}

impl std::fmt::Debug for CodeResources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeResources")
            .field("files", &self.files.keys())
            .field("files2", &self.files2.keys())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codesign::multi_digest;

    use apple_codesign::cryptography::MultiDigest as AppleDigest;
    use apple_codesign::{
        CodeResources as AppleResources, CodeResourcesRule as AppleRule,
        FilesFlavor as AppleFlavor, MachFile, SignedMachOInfo,
    };

    const FIX: &str = "/tmp/patina-fixtures";
    const FIXTURES: [&str; 3] = ["main_arm64", "main_arm64_norpath", "libinject.dylib"];

    fn load(name: &str) -> Option<Vec<u8>> {
        let p = format!("{FIX}/{name}");
        if std::path::Path::new(&p).exists() {
            Some(std::fs::read(p).unwrap())
        } else {
            eprintln!("SKIP: fixture {p} not present");
            None
        }
    }

    fn apple_digest(data: &[u8]) -> AppleDigest {
        AppleDigest::from_reader(std::io::Cursor::new(data)).unwrap()
    }

    const SPECS: &[(&str, bool, bool, bool, Option<u32>)] = &[
        ("^.*", false, false, false, None),
        ("^[^/]+$", true, false, false, Some(10)),
        (".*\\.dSYM($|/)", false, false, false, Some(11)),
        ("^(.*/)?\\.DS_Store$", false, true, false, Some(2000)),
        ("^Resources/.*\\.lproj/", false, false, true, Some(1000)),
    ];

    #[test]
    fn xml_is_byte_identical_to_apple_codesign() {
        let mut ours = CodeResources::default();
        let mut theirs = AppleResources::default();

        for &(pattern, nested, omit, optional, weight) in SPECS {
            let mut a = CodeResourcesRule::new(pattern).unwrap();
            let mut b = AppleRule::new(pattern).unwrap();
            if nested {
                a = a.nested();
                b = b.nested();
            }
            if omit {
                a = a.omit();
                b = b.omit();
            }
            if optional {
                a = a.optional();
                b = b.optional();
            }
            if let Some(w) = weight {
                a = a.weight(w);
                b = b.weight(w);
            }
            ours.add_rule(&a);
            ours.add_rule2(&a);
            theirs.add_rule(b.clone());
            theirs.add_rule2(b);
        }

        let seal = MachOSeal {
            cdhash: vec![0xab; 20],
            requirement: Some("cdhash H\"deadbeef\" and \"x\"".into()),
        };
        let apple_seal = SignedMachOInfo {
            code_directory_blob: Vec::new(),
            designated_code_requirement: seal.requirement.clone(),
        };

        for (path, data, optional) in [
            ("Resources/a.txt", b"hello".as_slice(), false),
            ("Resources/en.lproj/b.strings", b"world".as_slice(), true),
        ] {
            for flavor in [
                (FilesFlavor::Rules, AppleFlavor::Rules),
                (FilesFlavor::Rules2, AppleFlavor::Rules2),
                (FilesFlavor::Rules2WithSha1, AppleFlavor::Rules2WithSha1),
            ] {
                ours.seal_regular_file(flavor.0, path, multi_digest(data), optional);
                theirs
                    .seal_regular_file(flavor.1, path, apple_digest(data), optional)
                    .unwrap();
            }
        }

        ours.seal_symlink("link", "Resources/a.txt");
        theirs.seal_symlink("link", "Resources/a.txt");

        // apple-codesign derives the cdhash from the blob, so feed it a matching one.
        let blob = b"code directory blob";
        let mut expected = codesign::sha256(blob);
        expected.truncate(20);
        let seal = MachOSeal {
            cdhash: expected,
            ..seal
        };
        let apple_seal = SignedMachOInfo {
            code_directory_blob: blob.to_vec(),
            ..apple_seal
        };
        ours.seal_macho("Frameworks/Bar.framework", &seal, true);
        theirs
            .seal_macho("Frameworks/Bar.framework", &apple_seal, true)
            .unwrap();

        let mut a = Vec::new();
        let mut b = Vec::new();
        ours.to_writer_xml(&mut a).unwrap();
        theirs.to_writer_xml(&mut b).unwrap();
        assert_eq!(
            String::from_utf8(a).unwrap(),
            String::from_utf8(b).unwrap(),
            "emitted CodeResources XML differs from apple-codesign's"
        );
    }

    #[test]
    fn mach_o_seal_matches_apple_codesign() {
        for name in FIXTURES {
            let Some(bin) = load(name) else { continue };
            let signed = codesign::adhoc_sign(&bin, "com.example.fake", None).unwrap();

            let ours = MachOSeal::parse(&signed).unwrap();
            let theirs = SignedMachOInfo::parse_data(&signed).unwrap();

            let mut expected = codesign::sha256(&theirs.code_directory_blob);
            expected.truncate(20);
            assert_eq!(ours.cdhash, expected, "{name}: cdhash mismatch");
            assert_eq!(
                ours.requirement, theirs.designated_code_requirement,
                "{name}: designated requirement mismatch"
            );
        }
    }

    #[test]
    fn sha1_seal_decision_matches_apple_codesign() {
        for name in FIXTURES {
            let Some(bin) = load(name) else { continue };
            let mach = MachFile::parse(&bin).unwrap();
            let theirs = mach.iter_macho().any(|m| match m.find_targeting() {
                Ok(Some(t)) => match t.platform.sha256_digest_support() {
                    Ok(req) => !req.matches(&t.minimum_os_version),
                    Err(_) => true,
                },
                _ => true,
            });
            assert_eq!(needs_sha1_seals(&bin), theirs, "{name}: SHA-1 decision");
        }
    }

    #[test]
    fn rules_sort_by_exclusion_then_descending_weight() {
        let mut rules = [
            CodeResourcesRule::new("^a").unwrap().weight(10),
            CodeResourcesRule::new("^b").unwrap(),
            CodeResourcesRule::new("^c").unwrap().exclude().weight(1),
            CodeResourcesRule::new("^d").unwrap().weight(2000),
        ];
        rules.sort();
        let order: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert_eq!(order, ["^c", "^d", "^a", "^b"]);
    }

    #[test]
    fn contents_prefix_is_stripped() {
        assert_eq!(
            normalized_resources_path("Contents/Resources/a"),
            "Resources/a"
        );
        assert_eq!(normalized_resources_path("Resources/a"), "Resources/a");
    }
}

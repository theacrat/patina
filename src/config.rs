//! Config bundles: a folder layout supplying an edit's files, plus an optional
//! `config.json`. A shareable zip is untrusted: names validated, size capped.
//!
//! ```text
//! config.json          non-file options
//! icon.png             primary icon
//! alt-icons/*.png      alternate icons, named after the file stem
//! tweaks/*.deb         tweak packages, one per entry
//! overlay/**           merged into the .app root
//! car/*.png            Assets.car replacements
//! merge.plist          merged into Info.plist
//! entitlements.xml     entitlements
//! ```

use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tempfile::TempDir;
use zip::ZipArchive;

use crate::archive::is_safe_entry_name;
use crate::edit::EditOptions;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub name: Option<String>,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub min_os: Option<String>,
    #[serde(default)]
    pub ignore_missing_deps: bool,
    #[serde(default)]
    pub remove_supported_devices: bool,
    #[serde(default)]
    pub enable_file_sharing: bool,
    #[serde(default)]
    pub remove_watch: bool,
    #[serde(default)]
    pub remove_extensions: bool,
    #[serde(default)]
    pub remove_encrypted_extensions: bool,
    #[serde(default)]
    pub thin: bool,
    #[serde(default)]
    pub fakesign_bundle: bool,
    #[serde(default)]
    pub deterministic: bool,
}

const CONFIG_JSON: &str = "config.json";
const ICON: &str = "icon.png";
const ALT_ICONS: &str = "alt-icons";
const TWEAKS: &str = "tweaks";
const OVERLAY: &str = "overlay";
const CAR: &str = "car";
const MERGE_PLIST: &str = "merge.plist";
const ENTITLEMENTS: &str = "entitlements.xml";

const LAYOUT: &[&str] = &[
    CONFIG_JSON,
    ICON,
    ALT_ICONS,
    TWEAKS,
    OVERLAY,
    CAR,
    MERGE_PLIST,
    ENTITLEMENTS,
];

/// A config bundle is a handful of icons and tweaks.
const MAX_EXTRACTED: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

/// A zip is extracted to a temp dir dropped with this value, so the bundle must
/// outlive every path derived from it.
#[derive(Debug)]
pub struct Bundle {
    root: PathBuf,
    _temp: Option<TempDir>,
}

impl Bundle {
    pub fn path(&self) -> &Path {
        &self.root
    }
}

pub fn load(path: &Path) -> Result<(Config, Bundle)> {
    if path.is_dir() {
        let cfg = read_config(path, path)?;
        return Ok((
            cfg,
            Bundle {
                root: path.to_owned(),
                _temp: None,
            },
        ));
    }
    load_with_limits(path, MAX_EXTRACTED, MAX_ENTRIES)
}

/// `source` only names the bundle in errors.
fn read_config(root: &Path, source: &Path) -> Result<Config> {
    if !LAYOUT.iter().any(|n| root.join(n).exists()) {
        bail!(
            "config bundle {} has nothing patina recognises at its root \
             (expected some of: {})",
            source.display(),
            LAYOUT.join(", ")
        );
    }
    let cfg_path = root.join(CONFIG_JSON);
    if cfg_path.is_file() {
        parse_config(&fs::read(&cfg_path)?)
            .with_context(|| format!("in config bundle {}", source.display()))
    } else {
        Ok(Config::default())
    }
}

fn load_with_limits(
    zip_path: &Path,
    max_bytes: u64,
    max_entries: usize,
) -> Result<(Config, Bundle)> {
    let file = fs::File::open(zip_path)
        .with_context(|| format!("opening config bundle {}", zip_path.display()))?;
    let mut zip = ZipArchive::new(BufReader::new(file))
        .with_context(|| format!("reading config bundle {} (not a zip?)", zip_path.display()))?;
    if zip.len() > max_entries {
        bail!(
            "config bundle has {} entries, over the {max_entries} cap",
            zip.len()
        );
    }

    let dir = tempfile::tempdir().context("creating a temp dir for the config bundle")?;
    let root = dir.path();
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_owned();
        if !is_safe_entry_name(&name) {
            bail!("refusing unsafe entry name in config bundle (path traversal): {name}");
        }
        let dest = root.join(&name);
        if entry.is_dir() {
            fs::create_dir_all(&dest)?;
            continue;
        }
        // Read against the remaining budget: a lying header must not drive the
        // allocation.
        let budget = max_bytes - total;
        let mut buf = Vec::new();
        let read = entry.by_ref().take(budget + 1).read_to_end(&mut buf)? as u64;
        if read > budget {
            bail!("config bundle expands past the {max_bytes}-byte cap (possible zip bomb)");
        }
        total += read;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, &buf).with_context(|| format!("extracting {name}"))?;
        // An overlay picks its zip mode from the source's exec bit.
        #[cfg(unix)]
        if entry.unix_mode().is_some_and(|m| m & 0o111 != 0) {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))?;
        }
    }

    let cfg = read_config(root, zip_path)?;
    let root = root.to_owned();
    Ok((
        cfg,
        Bundle {
            root,
            _temp: Some(dir),
        },
    ))
}

fn parse_config(bytes: &[u8]) -> Result<Config> {
    serde_json::from_slice(bytes).context("parsing config.json")
}

pub fn to_options(cfg: &Config, root: &Path) -> Result<EditOptions> {
    let mut alt_icons = Vec::new();
    for p in children(&root.join(ALT_ICONS))? {
        if !p.is_file() {
            continue;
        }
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .with_context(|| format!("unusable alt-icon name: {}", p.display()))?;
        alt_icons.push((stem.to_owned(), p.clone()));
    }

    let tweaks = children(&root.join(TWEAKS))?;
    for p in &tweaks {
        if !p.extension().is_some_and(|e| e.eq_ignore_ascii_case("deb")) {
            let name = p.file_name().unwrap_or(p.as_os_str()).to_string_lossy();
            bail!("config bundle: {TWEAKS}/{name} is not a .deb package");
        }
    }

    let overlay = root.join(OVERLAY);
    let car = root.join(CAR);
    Ok(EditOptions {
        name: cfg.name.clone(),
        alt_icons,
        icon: existing_file(root, ICON),
        merge_car: car.is_dir().then_some(car),
        overlays: overlay.is_dir().then_some(overlay).into_iter().collect(),
        tweaks,
        ignore_missing_deps: cfg.ignore_missing_deps,
        entitlements: existing_file(root, ENTITLEMENTS),
        bundle_id: cfg.bundle_id.clone(),
        version: cfg.version.clone(),
        min_os: cfg.min_os.clone(),
        merge_plist: existing_file(root, MERGE_PLIST),
        remove_supported_devices: cfg.remove_supported_devices,
        enable_file_sharing: cfg.enable_file_sharing,
        remove_watch: cfg.remove_watch,
        remove_extensions: cfg.remove_extensions,
        remove_encrypted_extensions: cfg.remove_encrypted_extensions,
        thin: cfg.thin,
        fakesign_bundle: cfg.fakesign_bundle,
        deterministic: cfg.deterministic,
    })
}

fn existing_file(root: &Path, name: &str) -> Option<PathBuf> {
    let p = root.join(name);
    p.is_file().then_some(p)
}

/// Sorted so a bundle applies in a stable order.
fn children(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    out.sort();
    Ok(out)
}

pub fn merge(base: EditOptions, cli: EditOptions) -> EditOptions {
    EditOptions {
        name: cli.name.or(base.name),
        alt_icons: concat(base.alt_icons, cli.alt_icons),
        icon: cli.icon.or(base.icon),
        merge_car: cli.merge_car.or(base.merge_car),
        overlays: concat(base.overlays, cli.overlays),
        tweaks: concat(base.tweaks, cli.tweaks),
        ignore_missing_deps: base.ignore_missing_deps || cli.ignore_missing_deps,
        entitlements: cli.entitlements.or(base.entitlements),
        bundle_id: cli.bundle_id.or(base.bundle_id),
        version: cli.version.or(base.version),
        min_os: cli.min_os.or(base.min_os),
        merge_plist: cli.merge_plist.or(base.merge_plist),
        remove_supported_devices: base.remove_supported_devices || cli.remove_supported_devices,
        enable_file_sharing: base.enable_file_sharing || cli.enable_file_sharing,
        remove_watch: base.remove_watch || cli.remove_watch,
        remove_extensions: base.remove_extensions || cli.remove_extensions,
        remove_encrypted_extensions: base.remove_encrypted_extensions
            || cli.remove_encrypted_extensions,
        thin: base.thin || cli.thin,
        fakesign_bundle: base.fakesign_bundle || cli.fakesign_bundle,
        deterministic: base.deterministic || cli.deterministic,
    }
}

fn concat<T>(mut base: Vec<T>, cli: Vec<T>) -> Vec<T> {
    base.extend(cli);
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(
                (*name).to_owned(),
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn write_pack(entries: &[(&str, &[u8])]) -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pack.zip");
        fs::write(&path, zip_bytes(entries)).unwrap();
        (dir, path)
    }

    fn write_dir(entries: &[(&str, &[u8])]) -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, data) in entries {
            let dest = dir.path().join(name);
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::write(dest, data).unwrap();
        }
        dir
    }

    #[test]
    fn a_directory_loads_like_a_zip() {
        let entries: &[(&str, &[u8])] = &[
            (CONFIG_JSON, br#"{"name": "From Dir", "thin": true}"#),
            ("icon.png", b"primary"),
            ("tweaks/hook.deb", b"debbytes"),
            ("overlay/Docs/readme.txt", b"hi"),
        ];

        let dir = write_dir(entries);
        let (cfg, bundle) = load(dir.path()).unwrap();
        let from_dir = to_options(&cfg, bundle.path()).unwrap();
        assert_eq!(bundle.path(), dir.path(), "a directory is used in place");

        let (_pack, zip) = write_pack(entries);
        let (zcfg, zbundle) = load(&zip).unwrap();
        let from_zip = to_options(&zcfg, zbundle.path()).unwrap();

        assert_eq!(from_dir.name, from_zip.name);
        assert_eq!(from_dir.name.as_deref(), Some("From Dir"));
        assert!(from_dir.thin && from_zip.thin);
        assert_eq!(from_dir.tweaks.len(), from_zip.tweaks.len());
        assert_eq!(from_dir.overlays.len(), from_zip.overlays.len());
        assert_eq!(
            fs::read(from_dir.icon.unwrap()).unwrap(),
            fs::read(from_zip.icon.unwrap()).unwrap()
        );
    }

    #[test]
    fn a_directory_with_nothing_recognisable_errors() {
        let dir = write_dir(&[("random.txt", b"x")]);
        let err = load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("nothing patina recognises"), "{err}");
    }

    #[test]
    fn round_trips_a_bundle() {
        let json = br#"{
            "name": "My App",
            "bundle_id": "com.example.app",
            "thin": true,
            "ignore_missing_deps": true
        }"#;
        let (_pack, path) = write_pack(&[
            (CONFIG_JSON, json),
            ("icon.png", b"primary"),
            ("alt-icons/Midnight.png", b"alt"),
            ("tweaks/hook.deb", b"debbytes"),
            ("overlay/Docs/readme.txt", b"hi"),
            ("car/Logo.png", b"logo"),
            ("merge.plist", b"<plist/>"),
            ("entitlements.xml", b"<plist/>"),
        ]);

        let (cfg, dir) = load(&path).unwrap();
        let opts = to_options(&cfg, dir.path()).unwrap();

        assert_eq!(opts.name.as_deref(), Some("My App"));
        assert_eq!(opts.bundle_id.as_deref(), Some("com.example.app"));
        assert!(opts.thin);
        assert!(opts.ignore_missing_deps);

        let icon = opts.icon.unwrap();
        assert!(icon.is_absolute() && icon.is_file());
        assert_eq!(fs::read(&icon).unwrap(), b"primary");

        assert_eq!(opts.alt_icons.len(), 1);
        assert_eq!(opts.alt_icons[0].0, "Midnight", "name comes from the stem");
        assert_eq!(fs::read(&opts.alt_icons[0].1).unwrap(), b"alt");

        assert_eq!(opts.tweaks.len(), 1);
        assert_eq!(fs::read(&opts.tweaks[0]).unwrap(), b"debbytes");

        assert_eq!(opts.overlays, [dir.path().join(OVERLAY)]);

        assert_eq!(opts.merge_car, Some(dir.path().join(CAR)));
        assert!(opts.merge_plist.unwrap().is_file());
        assert!(opts.entitlements.unwrap().is_file());
    }

    #[test]
    fn config_json_is_optional() {
        let (_pack, path) = write_pack(&[("icon.png", b"png")]);
        let (cfg, dir) = load(&path).unwrap();
        let opts = to_options(&cfg, dir.path()).unwrap();
        assert!(opts.name.is_none());
        assert!(opts.icon.is_some());
    }

    #[test]
    fn rejects_a_non_deb_under_tweaks() {
        for bad in ["tweaks/hook.dylib", "tweaks/Foo.framework/Foo"] {
            let (_pack, path) = write_pack(&[(CONFIG_JSON, b"{}"), (bad, b"x")]);
            let (cfg, dir) = load(&path).unwrap();
            let err = to_options(&cfg, dir.path())
                .err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_default();
            assert!(err.contains("is not a .deb package"), "{bad}: {err}");
        }
    }

    #[test]
    fn nested_overlay_paths_mirror_the_app_root() {
        let (_pack, path) = write_pack(&[
            (CONFIG_JSON, b"{}"),
            ("overlay/top.txt", b"t"),
            ("overlay/a/b/deep.txt", b"d"),
        ]);
        let (cfg, dir) = load(&path).unwrap();
        let opts = to_options(&cfg, dir.path()).unwrap();

        let files = crate::edit::overlay_files(&opts.overlays[0]).unwrap();
        let rels: Vec<&str> = files.iter().map(|(_, r)| r.as_str()).collect();
        assert_eq!(rels, ["a/b/deep.txt", "top.txt"]);
    }

    #[test]
    fn an_absent_overlay_dir_yields_no_overlays() {
        let (_pack, path) = write_pack(&[(CONFIG_JSON, b"{}"), ("icon.png", b"png")]);
        let (cfg, dir) = load(&path).unwrap();
        assert!(to_options(&cfg, dir.path()).unwrap().overlays.is_empty());
    }

    #[test]
    fn cli_overrides_config() {
        let (_pack, path) = write_pack(&[
            (
                CONFIG_JSON,
                br#"{"name": "From Config", "version": "1.0", "thin": true}"#,
            ),
            ("tweaks/a.deb", b"a"),
        ]);
        let (cfg, dir) = load(&path).unwrap();
        let base = to_options(&cfg, dir.path()).unwrap();

        let cli = EditOptions {
            name: Some("From Cli".into()),
            tweaks: vec![PathBuf::from("b.deb")],
            fakesign_bundle: true,
            ..Default::default()
        };
        let merged = merge(base, cli);

        assert_eq!(merged.name.as_deref(), Some("From Cli"));
        assert_eq!(merged.version.as_deref(), Some("1.0"));
        assert!(merged.thin, "config bool survives an absent CLI flag");
        assert!(merged.fakesign_bundle);
        assert_eq!(merged.tweaks.len(), 2, "lists concatenate");
        assert!(merged.tweaks[0].ends_with("a.deb"));
        assert_eq!(merged.tweaks[1], PathBuf::from("b.deb"));
    }

    #[test]
    fn rejects_unknown_keys() {
        let (_pack, path) = write_pack(&[(CONFIG_JSON, br#"{"bundleid": "x"}"#)]);
        let err = format!("{:#}", load(&path).unwrap_err());
        assert!(err.contains("unknown field `bundleid`"), "{err}");
    }

    #[test]
    fn rejects_traversal_in_zip_entry_names() {
        for bad in ["../evil", "overlay/../../etc/passwd", "/etc/passwd"] {
            let (_pack, path) = write_pack(&[(CONFIG_JSON, b"{}"), (bad, b"pwned")]);
            let err = load(&path).unwrap_err().to_string();
            assert!(err.contains("path traversal"), "{bad}: {err}");
        }
    }

    #[test]
    fn errors_on_an_unrecognised_bundle() {
        let (_pack, path) = write_pack(&[("random.txt", b"x")]);
        let err = load(&path).unwrap_err().to_string();
        assert!(err.contains("nothing patina recognises"), "{err}");
    }

    #[test]
    fn caps_extracted_bytes_and_entry_count() {
        let big = vec![0u8; 4096];
        let (_pack, path) = write_pack(&[(CONFIG_JSON, b"{}"), ("icon.png", &big)]);
        let err = load_with_limits(&path, 64, MAX_ENTRIES)
            .unwrap_err()
            .to_string();
        assert!(err.contains("zip bomb"), "{err}");
        assert!(load_with_limits(&path, MAX_EXTRACTED, 1).is_err());
        assert!(load_with_limits(&path, MAX_EXTRACTED, MAX_ENTRIES).is_ok());
    }
}

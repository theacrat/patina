//! Zip surgery: both write modes must pass `unzip -t` without recompressing
//! untouched entries or losing symlinks and modes.

mod common;

use std::io::{Read, Write};
use std::process::Command;

use patina::archive::EditPlan;

fn dummy_macho() -> Vec<u8> {
    common::incompressible_blob(4096)
}

fn unzip_t_ok(archive: &[u8]) {
    let dir = tempdir();
    let path = dir.join("out.ipa");
    std::fs::write(&path, archive).unwrap();
    let out = Command::new("unzip").arg("-t").arg(&path).output().unwrap();
    assert!(
        out.status.success(),
        "unzip -t failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn tempdir() -> std::path::PathBuf {
    let mut base = std::env::temp_dir();
    let uniq = format!(
        "patina-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    base.push(uniq);
    std::fs::create_dir_all(&base).unwrap();
    base
}
static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn read_entry(archive: &[u8], name: &str) -> Option<Vec<u8>> {
    patina::archive::read_entry(archive, name).unwrap()
}

fn assert_common_invariants(edited: &[u8], original: &[u8]) {
    unzip_t_ok(edited);

    assert_eq!(
        common::raw_compressed_bytes(edited, "Payload/Fake.app/blob.bin"),
        common::raw_compressed_bytes(original, "Payload/Fake.app/blob.bin"),
        "blob was recompressed"
    );

    let mut a = zip::ZipArchive::new(std::io::Cursor::new(edited.to_vec())).unwrap();
    let idx = (0..a.len())
        .find(|&i| a.name_for_index(i) == Some("Payload/Fake.app/link"))
        .expect("symlink entry missing");
    let mut f = a.by_index(idx).unwrap();
    assert!(f.is_symlink(), "link entry lost its symlink mode");
    let mut target = String::new();
    f.read_to_string(&mut target).unwrap();
    assert_eq!(target, "Fake");
    drop(f);

    let idx = (0..a.len())
        .find(|&i| a.name_for_index(i) == Some("Payload/Fake.app/Fake"))
        .unwrap();
    let mode = a.by_index(idx).unwrap().unix_mode().unwrap();
    assert_eq!(mode & 0o111, 0o111, "executable bit lost (mode {mode:o})");
}

#[test]
fn append_replaces_and_adds() {
    let (ipa, _) = common::build_ipa(&dummy_macho());
    let mut plan = EditPlan::new();
    plan.put(
        "Payload/Fake.app/Info.plist",
        common::info_plist("Renamed"),
        0o100644,
    );
    plan.put("Payload/Fake.app/added.txt", b"hello".to_vec(), 0o100644);

    let edited = plan.commit_append(&ipa).unwrap();
    assert_common_invariants(&edited, &ipa);

    let pl = read_entry(&edited, "Payload/Fake.app/Info.plist").unwrap();
    let v = plist::Value::from_reader(std::io::Cursor::new(pl)).unwrap();
    let name = v.as_dictionary().unwrap().get("CFBundleName").unwrap();
    assert_eq!(name.as_string(), Some("Renamed"));

    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/added.txt").unwrap(),
        b"hello"
    );
    let names = patina::archive::list_names(&edited).unwrap();
    let count = names
        .iter()
        .filter(|n| *n == "Payload/Fake.app/Info.plist")
        .count();
    assert_eq!(
        count, 1,
        "duplicate central-directory record for replaced entry"
    );
}

#[test]
fn compact_replaces_and_adds() {
    let (ipa, _) = common::build_ipa(&dummy_macho());
    let mut plan = EditPlan::new();
    plan.put(
        "Payload/Fake.app/Info.plist",
        common::info_plist("Renamed"),
        0o100644,
    );
    plan.put_symlink("Payload/Fake.app/newlink", "Info.plist");

    let edited = plan.commit_compact(&ipa).unwrap();
    assert_common_invariants(&edited, &ipa);

    let pl = read_entry(&edited, "Payload/Fake.app/Info.plist").unwrap();
    let v = plist::Value::from_reader(std::io::Cursor::new(pl)).unwrap();
    assert_eq!(
        v.as_dictionary()
            .unwrap()
            .get("CFBundleName")
            .unwrap()
            .as_string(),
        Some("Renamed")
    );
}

#[test]
fn append_is_smaller_edit_than_compact_on_untouched_bulk() {
    let (ipa, _) = common::build_ipa(&dummy_macho());
    let mut plan = EditPlan::new();
    plan.put("Payload/Fake.app/added.txt", b"x".to_vec(), 0o100644);
    let edited = plan.commit_append(&ipa).unwrap();

    // EOCD+16 holds the central-directory offset.
    let eocd = ipa
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .unwrap();
    let cd_offset = u32::from_le_bytes([
        ipa[eocd + 16],
        ipa[eocd + 17],
        ipa[eocd + 18],
        ipa[eocd + 19],
    ]) as usize;
    assert_eq!(
        &edited[..cd_offset],
        &ipa[..cd_offset],
        "bulk was rewritten"
    );
}

#[test]
fn deterministic_output_is_stable() {
    let (ipa, _) = common::build_ipa(&dummy_macho());
    let build = || {
        let mut plan = EditPlan::new();
        plan.set_deterministic(true);
        plan.put("Payload/Fake.app/added.txt", b"same".to_vec(), 0o100644);
        plan.commit_append(&ipa).unwrap()
    };
    assert_eq!(
        build(),
        build(),
        "deterministic output differs between runs"
    );
}

#[test]
fn round_trips_through_real_unzip() {
    let (ipa, _) = common::build_ipa(&dummy_macho());
    let mut plan = EditPlan::new();
    plan.put(
        "Payload/Fake.app/Info.plist",
        common::info_plist("ViaUnzip"),
        0o100644,
    );
    let edited = plan.commit_append(&ipa).unwrap();

    let dir = tempdir();
    let path = dir.join("out.ipa");
    std::fs::write(&path, &edited).unwrap();
    let status = Command::new("unzip")
        .arg("-o")
        .arg(&path)
        .arg("-d")
        .arg(&dir)
        .status()
        .unwrap();
    assert!(status.success());
    let extracted = std::fs::read(dir.join("Payload/Fake.app/Info.plist")).unwrap();
    let v = plist::Value::from_reader(std::io::Cursor::new(extracted)).unwrap();
    assert_eq!(
        v.as_dictionary()
            .unwrap()
            .get("CFBundleName")
            .unwrap()
            .as_string(),
        Some("ViaUnzip")
    );

    let link = dir.join("Payload/Fake.app/link");
    let meta = std::fs::symlink_metadata(&link).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "link did not extract as a symlink"
    );
}

// Keeps the `Write` import used in every config.
#[allow(dead_code)]
fn _use_write(_w: &mut dyn Write) {}

#[test]
fn malformed_eocd_errors_not_panics() {
    let (mut ipa, _) = common::build_ipa(&dummy_macho());
    let eocd = ipa
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .unwrap();
    ipa[eocd + 16..eocd + 20].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert!(
        patina::archive::list_names(&ipa).is_err(),
        "must error, not panic"
    );
    let mut plan = EditPlan::new();
    plan.put("Payload/Fake.app/x", b"y".to_vec(), 0o100644);
    assert!(plan.commit_append(&ipa).is_err());
}

#[test]
fn remove_drops_entry_in_both_modes() {
    for compact in [false, true] {
        let (ipa, _) = common::build_ipa(&dummy_macho());
        let mut plan = EditPlan::new();
        plan.remove("Payload/Fake.app/en.lproj/InfoPlist.strings");
        plan.remove_prefix("Payload/Fake.app/fr.lproj/");
        let edited = if compact {
            plan.commit_compact(&ipa).unwrap()
        } else {
            plan.commit_append(&ipa).unwrap()
        };
        assert_common_invariants(&edited, &ipa);

        let names = patina::archive::list_names(&edited).unwrap();
        assert!(
            !names
                .iter()
                .any(|n| n == "Payload/Fake.app/en.lproj/InfoPlist.strings"),
            "exact-removed entry still present ({})",
            if compact { "compact" } else { "append" }
        );
        assert!(
            !names
                .iter()
                .any(|n| n.starts_with("Payload/Fake.app/fr.lproj/")),
            "prefix-removed subtree still present"
        );
        assert!(names.iter().any(|n| n == "Payload/Fake.app/Info.plist"));
        assert!(read_entry(&edited, "Payload/Fake.app/Info.plist").is_some());
    }
}

#[test]
fn put_overrides_remove_of_same_name() {
    let (ipa, _) = common::build_ipa(&dummy_macho());
    let mut plan = EditPlan::new();
    plan.remove_prefix("Payload/Fake.app/");
    plan.put(
        "Payload/Fake.app/Info.plist",
        common::info_plist("Survivor"),
        0o100644,
    );
    let edited = plan.commit_compact(&ipa).unwrap();
    let pl = read_entry(&edited, "Payload/Fake.app/Info.plist")
        .expect("a put must win over a matching removal prefix");
    let v = plist::Value::from_reader(std::io::Cursor::new(pl)).unwrap();
    assert_eq!(
        v.as_dictionary().unwrap()["CFBundleName"].as_string(),
        Some("Survivor")
    );
}

#[test]
fn directory_survives_compact() {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.add_directory(
        "Payload/Fake.app/subdir/",
        zip::write::SimpleFileOptions::default().unix_permissions(0o040755),
    )
    .unwrap();
    w.start_file(
        "Payload/Fake.app/keep.bin",
        zip::write::SimpleFileOptions::default().unix_permissions(0o100644),
    )
    .unwrap();
    w.write_all(b"data").unwrap();
    let ipa = w.finish().unwrap().into_inner();

    let mut plan = EditPlan::new();
    plan.put("Payload/Fake.app/added.txt", b"x".to_vec(), 0o100644);
    let edited = plan.commit_compact(&ipa).unwrap();

    let mut a = zip::ZipArchive::new(std::io::Cursor::new(edited)).unwrap();
    let idx = (0..a.len())
        .find(|&i| a.name_for_index(i) == Some("Payload/Fake.app/subdir/"))
        .expect("directory entry missing");
    assert!(
        a.by_index(idx).unwrap().is_dir(),
        "directory lost its type in compact"
    );
}

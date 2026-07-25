//! CLI smoke tests against the built `patina` binary.

mod common;

use std::process::Command;

fn patina() -> Command {
    Command::new(env!("CARGO_BIN_EXE_patina"))
}

#[test]
fn edit_in_place_rename_via_cli() {
    let mach = common::fixture("main_arm64").unwrap_or_else(|| common::incompressible_blob(2048));
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();
    let path = dir.join("app.ipa");
    std::fs::write(&path, &ipa).unwrap();

    let out = patina()
        .arg("edit")
        .arg(&path)
        .arg("--name")
        .arg("Cli Renamed")
        .arg("--deterministic")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("renamed: yes"));

    let edited = std::fs::read(&path).unwrap();
    let v = plist::Value::from_reader(std::io::Cursor::new(
        patina::archive::read_entry(&edited, "Payload/Fake.app/Info.plist")
            .unwrap()
            .unwrap(),
    ))
    .unwrap();
    assert_eq!(
        v.as_dictionary().unwrap()["CFBundleName"].as_string(),
        Some("Cli Renamed")
    );
}

#[test]
fn compact_output_to_new_file_via_cli() {
    let mach = common::fixture("main_arm64").unwrap_or_else(|| common::incompressible_blob(2048));
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();
    let path = dir.join("app.ipa");
    let out_path = dir.join("out.ipa");
    std::fs::write(&path, &ipa).unwrap();

    let out = patina()
        .args(["edit"])
        .arg(&path)
        .arg("--name")
        .arg("Compacted")
        .arg("-o")
        .arg(&out_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("compact rewrite"));

    assert_eq!(
        std::fs::read(&path).unwrap(),
        ipa,
        "input mutated by -o run"
    );
    let st = Command::new("unzip")
        .arg("-t")
        .arg(&out_path)
        .status()
        .unwrap();
    assert!(st.success());
}

#[test]
fn config_bundle_drives_an_edit_and_flags_override_it() {
    let mach = common::fixture("main_arm64").unwrap_or_else(|| common::incompressible_blob(2048));
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();
    let path = dir.join("app.ipa");
    std::fs::write(&path, &ipa).unwrap();

    let pack = dir.join("pack.zip");
    {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("config.json", opts).unwrap();
        w.write_all(br#"{"name": "From Bundle", "version": "9.9", "deterministic": true}"#)
            .unwrap();
        w.start_file("overlay/Docs/readme.txt", opts).unwrap();
        w.write_all(b"from the bundle").unwrap();
        std::fs::write(&pack, w.finish().unwrap().into_inner()).unwrap();
    }

    let out = patina()
        .arg("edit")
        .arg(&path)
        .arg("--config")
        .arg(&pack)
        .arg("--name")
        .arg("From Cli")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let edited = std::fs::read(&path).unwrap();
    let v = plist::Value::from_reader(std::io::Cursor::new(
        patina::archive::read_entry(&edited, "Payload/Fake.app/Info.plist")
            .unwrap()
            .unwrap(),
    ))
    .unwrap();
    let d = v.as_dictionary().unwrap();
    assert_eq!(d["CFBundleName"].as_string(), Some("From Cli"));
    assert_eq!(d["CFBundleShortVersionString"].as_string(), Some("9.9"));
    assert_eq!(
        patina::archive::read_entry(&edited, "Payload/Fake.app/Docs/readme.txt").unwrap(),
        Some(b"from the bundle".to_vec())
    );
}

#[test]
fn overlay_flag_merges_a_folder_via_cli() {
    let mach = common::fixture("main_arm64").unwrap_or_else(|| common::incompressible_blob(2048));
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();
    let path = dir.join("app.ipa");
    std::fs::write(&path, &ipa).unwrap();

    let overlay = dir.join("overlay");
    std::fs::create_dir_all(overlay.join("Docs")).unwrap();
    std::fs::write(overlay.join("Docs/readme.txt"), b"added").unwrap();
    std::fs::write(overlay.join("blob.bin"), b"overwritten").unwrap();

    let out = patina()
        .arg("edit")
        .arg(&path)
        .arg("--overlay")
        .arg(&overlay)
        .arg("--deterministic")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("files overlaid: 2"));

    let edited = std::fs::read(&path).unwrap();
    assert_eq!(
        patina::archive::read_entry(&edited, "Payload/Fake.app/Docs/readme.txt").unwrap(),
        Some(b"added".to_vec())
    );
    assert_eq!(
        patina::archive::read_entry(&edited, "Payload/Fake.app/blob.bin").unwrap(),
        Some(b"overwritten".to_vec()),
        "an overlaid file overwrites the bundle's own"
    );
}

#[test]
fn help_and_missing_input_behaviour() {
    assert!(patina().arg("--help").output().unwrap().status.success());
    let missing = patina()
        .args(["edit", "/no/such/file.ipa"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
}

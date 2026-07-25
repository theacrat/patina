//! End-to-end `edit` pipeline over a synthetic IPA, skipped without fixtures.

mod common;

use std::io::{Cursor, Write};

use patina::edit::{EditOptions, WriteMode, edit_bytes, edit_file_append};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// Always adds a binary `Info.plist`, even for an empty entry list.
fn build_custom_ipa(entries: &[(&str, Vec<u8>, bool)]) -> Vec<u8> {
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    let plist_opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    w.start_file("Payload/Fake.app/Info.plist", plist_opts)
        .unwrap();
    w.write_all(&common::info_plist("Fake")).unwrap();
    for (name, data, stored) in entries {
        let method = if *stored {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        w.start_file(
            *name,
            SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn build_deb(files: &[(&str, &[u8])]) -> Vec<u8> {
    let entries: Vec<(&str, Option<&str>, &[u8])> =
        files.iter().map(|(p, d)| (*p, None, *d)).collect();
    build_deb_tree(&entries)
}

fn deb_file(dir: &std::path::Path, name: &str, files: &[(&str, &[u8])]) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, build_deb(files)).unwrap();
    p
}

/// `(path, symlink target, bytes)`; a target makes the entry a symlink.
fn build_deb_tree(files: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    ar_deb(&[("data.tar.gz", &tar_gz(files))])
}

fn deb_with_control(
    dir: &std::path::Path,
    name: &str,
    control: &str,
    files: &[(&str, &[u8])],
) -> std::path::PathBuf {
    let entries: Vec<(&str, Option<&str>, &[u8])> =
        files.iter().map(|(p, d)| (*p, None, *d)).collect();
    let deb = ar_deb(&[
        (
            "control.tar.gz",
            &tar_gz(&[("./control", None, control.as_bytes())]),
        ),
        ("data.tar.gz", &tar_gz(&entries)),
    ]);
    let p = dir.join(name);
    std::fs::write(&p, deb).unwrap();
    p
}

fn tar_gz(files: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    use std::io::Read;
    let mut tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar);
        for (path, link, data) in files {
            let mut h = tar::Header::new_gnu();
            match link {
                Some(target) => {
                    h.set_entry_type(tar::EntryType::Symlink);
                    h.set_size(0);
                    h.set_link_name(target).unwrap();
                }
                None => h.set_size(data.len() as u64),
            }
            h.set_path(path).unwrap();
            h.set_mode(0o755);
            h.set_cksum();
            let body: &[u8] = if link.is_some() { &[] } else { data };
            b.append(&h, body).unwrap();
        }
        b.finish().unwrap();
    }
    let mut gz = Vec::new();
    flate2::read::GzEncoder::new(Cursor::new(&tar), flate2::Compression::default())
        .read_to_end(&mut gz)
        .unwrap();
    gz
}

fn ar_deb(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut deb = Vec::new();
    {
        let mut b = ar::Builder::new(&mut deb);
        let bin = b"2.0\n";
        b.append(
            &ar::Header::new(b"debian-binary".to_vec(), bin.len() as u64),
            &bin[..],
        )
        .unwrap();
        for (name, data) in members {
            b.append(
                &ar::Header::new(name.as_bytes().to_vec(), data.len() as u64),
                *data,
            )
            .unwrap();
        }
    }
    deb
}

/// Fat container: the arm64 slice twice, the second mislabelled x86_64.
fn make_fat(arm64: &[u8]) -> Vec<u8> {
    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }
    let n = 2u32;
    let header = 8 + n as usize * 20;
    let align = 0x4000u64;
    let slices = [(0x0100_000cu32, arm64), (0x0100_0007u32, arm64)];
    let mut offsets = Vec::new();
    let mut cursor = header as u64;
    for (_, s) in &slices {
        cursor = cursor.div_ceil(align) * align;
        offsets.push(cursor);
        cursor += s.len() as u64;
    }
    let mut out = vec![0u8; cursor as usize];
    out[0..4].copy_from_slice(&be32(0xcafe_babe));
    out[4..8].copy_from_slice(&be32(n));
    for (i, (cputype, s)) in slices.iter().enumerate() {
        let base = 8 + i * 20;
        out[base..base + 4].copy_from_slice(&be32(*cputype));
        out[base + 4..base + 8].copy_from_slice(&be32(0)); // cpusubtype
        out[base + 8..base + 12].copy_from_slice(&be32(offsets[i] as u32));
        out[base + 12..base + 16].copy_from_slice(&be32(s.len() as u32));
        out[base + 16..base + 20].copy_from_slice(&be32(14)); // align 2^14
        out[offsets[i] as usize..offsets[i] as usize + s.len()].copy_from_slice(s);
    }
    out
}

fn red_png(size: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(size, size, image::Rgba([10, 130, 200, 255]));
    let mut buf = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
        .unwrap();
    buf
}

fn read_entry(archive: &[u8], name: &str) -> Vec<u8> {
    patina::archive::read_entry(archive, name)
        .unwrap()
        .unwrap_or_else(|| panic!("missing entry {name}"))
}

fn plist_of(archive: &[u8], name: &str) -> plist::Value {
    plist::Value::from_reader(Cursor::new(read_entry(archive, name))).unwrap()
}

/// `LC_CODE_SIGNATURE` count per slice; above one means a doubled signature.
fn signature_counts(data: &[u8]) -> Vec<usize> {
    use goblin::mach::load_command::CommandVariant;
    fn count(m: &goblin::mach::MachO) -> usize {
        m.load_commands
            .iter()
            .filter(|lc| matches!(lc.command, CommandVariant::CodeSignature(_)))
            .count()
    }
    match goblin::mach::Mach::parse(data).unwrap() {
        goblin::mach::Mach::Binary(m) => vec![count(&m)],
        goblin::mach::Mach::Fat(fat) => fat
            .arches()
            .unwrap()
            .iter()
            .map(|a| {
                let slice = &data[a.offset as usize..a.offset as usize + a.size as usize];
                count(&goblin::mach::MachO::parse(slice, 0).unwrap())
            })
            .collect(),
    }
}

/// `(entry name, bytes)` for every Mach-O in the archive.
fn machos(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut a = zip::ZipArchive::new(Cursor::new(archive.to_vec())).unwrap();
    let names: Vec<String> = a.file_names().map(str::to_owned).collect();
    let mut out = Vec::new();
    for n in names {
        use std::io::Read;
        let mut f = a.by_name(&n).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        if patina::macho::is_macho(&buf) {
            out.push((n, buf));
        }
    }
    out
}

#[test]
fn full_pipeline_bytes_mode() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let (ipa, _) = common::build_ipa(&mach);

    let dir = common::tempdir();
    let icon = dir.join("icon.png");
    std::fs::write(&icon, red_png(256)).unwrap();
    let deb = deb_file(
        &dir,
        "tweak.deb",
        &[(
            "Library/MobileSubstrate/DynamicLibraries/libinject.dylib",
            &dylib,
        )],
    );
    let overlay = dir.join("overlay");
    std::fs::create_dir_all(overlay.join("Docs")).unwrap();
    std::fs::write(overlay.join("Docs/extra.txt"), b"hi").unwrap();

    let opts = EditOptions {
        name: Some("Renamed".into()),
        alt_icons: vec![("Alt".into(), icon)],
        overlays: vec![overlay],
        tweaks: vec![deb],
        entitlements: None,
        deterministic: true,
        ..Default::default()
    };

    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::AppendInPlace).unwrap();

    let out = common::tempdir().join("out.ipa");
    std::fs::write(&out, &edited).unwrap();
    let st = std::process::Command::new("unzip")
        .arg("-t")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "unzip -t failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let info = plist_of(&edited, "Payload/Fake.app/Info.plist");
    let d = info.as_dictionary().unwrap();
    assert_eq!(d["CFBundleName"].as_string(), Some("Renamed"));
    assert_eq!(d["CFBundleDisplayName"].as_string(), Some("Renamed"));
    assert!(report.lproj_updated >= 1);

    for (fname, px) in [
        ("Alt60x60@2x.png", 120),
        ("Alt60x60@3x.png", 180),
        ("Alt76x76@2x.png", 152),
        ("Alt83.5x83.5@2x.png", 167),
    ] {
        let bytes = read_entry(&edited, &format!("Payload/Fake.app/{fname}"));
        let img = image::load_from_memory(&bytes).unwrap();
        assert_eq!((img.width(), img.height()), (px, px), "{fname}");
    }
    let iphone = d["CFBundleIcons"].as_dictionary().unwrap()["CFBundleAlternateIcons"]
        .as_dictionary()
        .unwrap()["Alt"]
        .as_dictionary()
        .unwrap();
    assert_eq!(
        iphone["CFBundleIconFiles"].as_array().unwrap()[0].as_string(),
        Some("Alt60x60")
    );
    assert!(d.contains_key("CFBundleIcons~ipad"));

    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/Docs/extra.txt"),
        b"hi"
    );

    let staged = read_entry(&edited, "Payload/Fake.app/Frameworks/libinject.dylib");
    assert!(
        patina::codesign::has_code_directory(&staged),
        "staged tweak dylib not signed"
    );

    let exe = read_entry(&edited, "Payload/Fake.app/Fake");
    let macho = goblin::mach::MachO::parse(&exe, 0).unwrap();
    assert!(
        macho.libs.contains(&"@rpath/libinject.dylib"),
        "weak dylib not injected: {:?}",
        macho.libs
    );
    assert!(
        macho.rpaths.contains(&"@executable_path/Frameworks"),
        "rpath missing"
    );
    assert!(
        patina::codesign::has_code_directory(&exe),
        "main executable not re-signed"
    );
    assert!(report.resigned);

    assert_eq!(
        common::raw_compressed_bytes(&edited, "Payload/Fake.app/blob.bin"),
        common::raw_compressed_bytes(&ipa, "Payload/Fake.app/blob.bin")
    );
}

#[test]
fn in_place_file_append_matches_bytes_mode_effects() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();
    let path = dir.join("app.ipa");
    std::fs::write(&path, &ipa).unwrap();

    let opts = EditOptions {
        name: Some("Renamed".into()),
        deterministic: true,
        ..Default::default()
    };
    let report = edit_file_append(&path, &opts).unwrap();
    assert!(report.renamed);

    let edited = std::fs::read(&path).unwrap();
    let st = std::process::Command::new("unzip")
        .arg("-t")
        .arg(&path)
        .output()
        .unwrap();
    assert!(st.status.success());
    let info = plist_of(&edited, "Payload/Fake.app/Info.plist");
    assert_eq!(
        info.as_dictionary().unwrap()["CFBundleName"].as_string(),
        Some("Renamed")
    );

    let eocd = ipa
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .unwrap();
    let cd_off = u32::from_le_bytes([
        ipa[eocd + 16],
        ipa[eocd + 17],
        ipa[eocd + 18],
        ipa[eocd + 19],
    ]) as usize;
    assert_eq!(
        &edited[..cd_off],
        &ipa[..cd_off],
        "in-place append rewrote the bulk"
    );
}

#[test]
fn entitlements_only_resigns() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();
    let ent = dir.join("ent.xml");
    std::fs::write(
        &ent,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>"#,
    )
    .unwrap();

    let opts = EditOptions {
        entitlements: Some(ent),
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(report.resigned);

    let exe = read_entry(&edited, "Payload/Fake.app/Fake");
    let parsed = apple_codesign::MachOBinary::parse(&exe).unwrap();
    let sig = parsed.code_signature().unwrap().unwrap();
    let ent = sig.entitlements().unwrap().expect("entitlements embedded");
    assert!(ent.as_str().contains("get-task-allow"));
}

#[test]
fn large_archive_in_place_rename_is_tail_only_and_fast() {
    let mach = common::fixture("main_arm64").unwrap_or_else(|| common::incompressible_blob(4096));
    let (mut ipa, _) = common::build_ipa(&mach);
    {
        use std::io::Write;
        let mut w = zip::ZipWriter::new_append(std::io::Cursor::new(&mut ipa)).unwrap();
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.start_file("Payload/Fake.app/huge.bin", opts).unwrap();
        w.write_all(&common::incompressible_blob(48 * 1024 * 1024))
            .unwrap();
        ipa = w.finish().unwrap().into_inner().clone();
    }

    let dir = common::tempdir();
    let path = dir.join("big.ipa");
    std::fs::write(&path, &ipa).unwrap();

    let eocd = ipa
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .unwrap();
    let cd_off = u32::from_le_bytes([
        ipa[eocd + 16],
        ipa[eocd + 17],
        ipa[eocd + 18],
        ipa[eocd + 19],
    ]) as usize;

    let opts = EditOptions {
        name: Some("Renamed".into()),
        deterministic: true,
        ..Default::default()
    };
    let start = std::time::Instant::now();
    edit_file_append(&path, &opts).unwrap();
    let elapsed = start.elapsed();
    eprintln!(
        "in-place rename on {} MiB took {:?}",
        ipa.len() / (1024 * 1024),
        elapsed
    );

    let edited = std::fs::read(&path).unwrap();
    assert_eq!(&edited[..cd_off], &ipa[..cd_off], "bulk was rewritten");
    // Generous bound: the edit touches KBs, not the 48 MiB body.
    assert!(
        elapsed.as_secs() < 3,
        "in-place rename too slow: {elapsed:?}"
    );
}

#[test]
fn overlay_of_executable_composes_with_injection() {
    let Some(_mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let (ipa, _) = common::build_ipa(&_mach);

    let dir = common::tempdir();
    let overlay = dir.join("overlay");
    std::fs::create_dir_all(&overlay).unwrap();
    std::fs::write(overlay.join("Fake"), &dylib).unwrap();
    let ent = dir.join("ent.xml");
    std::fs::write(
        &ent,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>"#,
    )
    .unwrap();

    let opts = EditOptions {
        overlays: vec![overlay],
        entitlements: Some(ent),
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(report.resigned);

    let exe = read_entry(&edited, "Payload/Fake.app/Fake");
    let m = goblin::mach::MachO::parse(&exe, 0).unwrap();
    assert_eq!(
        m.header.filetype, 0x6,
        "the overlaid file (a dylib) must be the signing base, not the archive's original executable"
    );
    assert!(
        patina::codesign::has_code_directory(&exe),
        "must be re-signed"
    );
}

/// `(relative path, bytes, executable)`.
fn overlay_dir(files: &[(&str, &[u8], bool)]) -> std::path::PathBuf {
    let dir = common::tempdir().join("overlay");
    for (rel, data, exec) in files {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
        #[cfg(unix)]
        if *exec {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn entry_mode(archive: &[u8], name: &str) -> u32 {
    let mut a = zip::ZipArchive::new(Cursor::new(archive.to_vec())).unwrap();
    a.by_name(name).unwrap().unix_mode().unwrap()
}

#[test]
fn overlay_overwrites_an_existing_file_and_adds_a_new_one() {
    let ipa = build_custom_ipa(&[(
        "Payload/Fake.app/Docs/readme.txt",
        b"original".to_vec(),
        false,
    )]);
    let overlay = overlay_dir(&[
        ("Docs/readme.txt", b"overlaid", false),
        ("Extras/deep/new.txt", b"brand new", false),
    ]);

    let opts = EditOptions {
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    assert_eq!(report.overlaid_files, 2);
    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/Docs/readme.txt"),
        b"overlaid"
    );
    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/Extras/deep/new.txt"),
        b"brand new"
    );
}

#[cfg(unix)]
#[test]
fn overlay_preserves_the_executable_bit() {
    let ipa = build_custom_ipa(&[]);
    let overlay = overlay_dir(&[
        ("bin/tool", b"#!/bin/sh\n", true),
        ("plain.txt", b"x", false),
    ]);

    let opts = EditOptions {
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    assert_eq!(
        entry_mode(&edited, "Payload/Fake.app/bin/tool") & 0o111,
        0o111
    );
    assert_eq!(entry_mode(&edited, "Payload/Fake.app/plain.txt") & 0o111, 0);
}

#[cfg(unix)]
#[test]
fn overlay_resolves_internal_symlinks_and_skips_escapes() {
    let ipa = build_custom_ipa(&[]);
    let overlay = overlay_dir(&[("real.txt", b"real", false)]);
    std::fs::create_dir(overlay.join("sub")).unwrap();
    std::fs::write(overlay.join("sub/inner.txt"), b"inner").unwrap();
    std::os::unix::fs::symlink("real.txt", overlay.join("alias.txt")).unwrap();
    std::os::unix::fs::symlink("sub", overlay.join("subalias")).unwrap();
    std::os::unix::fs::symlink("/etc", overlay.join("escape")).unwrap();
    std::os::unix::fs::symlink("nowhere.txt", overlay.join("broken.txt")).unwrap();

    let opts = EditOptions {
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    // real.txt, sub/inner.txt, alias.txt, subalias/inner.txt
    assert_eq!(report.overlaid_files, 4);
    assert_eq!(read_entry(&edited, "Payload/Fake.app/real.txt"), b"real");
    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/alias.txt"),
        b"real",
        "an alias inside the overlay is materialised as a copy"
    );
    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/subalias/inner.txt"),
        b"inner",
        "a directory alias inside the overlay is walked"
    );
    for skipped in ["Payload/Fake.app/escape", "Payload/Fake.app/broken.txt"] {
        assert_eq!(
            patina::archive::read_entry(&edited, skipped).unwrap(),
            None,
            "{skipped} must not be emitted"
        );
    }
}

#[test]
fn overlay_symlink_cycle_is_bounded() {
    let ipa = build_custom_ipa(&[]);
    let overlay = overlay_dir(&[("real.txt", b"real", false)]);
    std::os::unix::fs::symlink(".", overlay.join("loop")).unwrap();

    let opts = EditOptions {
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    // Either it bails on depth or it terminates; it must not hang or panic.
    match edit_bytes(&ipa, &opts, WriteMode::Compact) {
        Ok((edited, _)) => {
            assert_eq!(read_entry(&edited, "Payload/Fake.app/real.txt"), b"real");
        }
        Err(e) => assert!(format!("{e:#}").contains("nests deeper"), "{e:#}"),
    }
}

#[test]
fn a_bad_overlay_path_errors() {
    let ipa = build_custom_ipa(&[]);
    let dir = common::tempdir();
    let file = dir.join("not-a-dir.txt");
    std::fs::write(&file, b"x").unwrap();

    for (path, want) in [
        (dir.join("nope"), "does not exist"),
        (file, "expects a directory"),
    ] {
        let opts = EditOptions {
            overlays: vec![path],
            ..Default::default()
        };
        let err = format!(
            "{:#}",
            edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap_err()
        );
        assert!(err.contains(want), "{err}");
    }
}

#[test]
fn the_later_overlay_wins_on_a_collision() {
    let ipa = build_custom_ipa(&[]);
    let first = overlay_dir(&[
        ("Docs/readme.txt", b"first", false),
        ("only-first.txt", b"1", false),
    ]);
    let second = overlay_dir(&[("Docs/readme.txt", b"second", false)]);

    let opts = EditOptions {
        overlays: vec![first, second],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/Docs/readme.txt"),
        b"second"
    );
    assert_eq!(read_entry(&edited, "Payload/Fake.app/only-first.txt"), b"1");
}

#[test]
fn overlay_beats_a_colliding_tweak_file() {
    let Some(dylib) = common::fixture("libinject.dylib") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());
    let dir = common::tempdir();
    let deb = deb_file(
        &dir,
        "tweak.deb",
        &[
            (
                "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
                &dylib,
            ),
            ("Library/Frameworks/Hook.framework/Hook", &dylib),
            ("Library/Frameworks/Hook.framework/Info.plist", b"<plist/>"),
        ],
    );

    // The marker dependency identifies the overlaid binary past re-signing.
    let bare = patina::macho::strip_code_signature(&dylib).unwrap();
    let marked = patina::macho::inject_weak_dylib(&bare, "/nowhere/overlay-marker.dylib").unwrap();
    assert!(!patina::codesign::has_code_directory(&marked));
    let overlay = overlay_dir(&[
        ("Frameworks/Tweak.dylib", &marked, true),
        ("Frameworks/Hook.framework/Info.plist", b"overlaid", false),
    ]);

    let opts = EditOptions {
        tweaks: vec![deb],
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    assert_eq!(
        read_entry(
            &edited,
            "Payload/Fake.app/Frameworks/Hook.framework/Info.plist"
        ),
        b"overlaid",
        "the overlay must win the collision, not the .deb"
    );

    let tweak = read_entry(&edited, "Payload/Fake.app/Frameworks/Tweak.dylib");
    assert!(
        patina::macho::dylib_paths(&tweak)
            .iter()
            .any(|p| p == "/nowhere/overlay-marker.dylib"),
        "the overlaid dylib must be the one shipped"
    );
    assert!(
        patina::codesign::has_code_directory(&tweak),
        "an overlaid dylib that overrides a tweak file is still signed"
    );
    assert_ne!(tweak, marked, "patina must process it, not copy it");
}

#[test]
fn an_overlaid_dylib_is_adhoc_signed() {
    let Some(dylib) = common::fixture("libinject.dylib") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());
    let bare = patina::macho::strip_code_signature(&dylib).unwrap();
    assert!(!patina::codesign::has_code_directory(&bare));
    let overlay = overlay_dir(&[("Frameworks/Extra.dylib", &bare, true)]);

    let opts = EditOptions {
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    let staged = read_entry(&edited, "Payload/Fake.app/Frameworks/Extra.dylib");
    assert!(
        patina::codesign::has_code_directory(&staged),
        "a standalone overlaid dylib must be ad-hoc signed"
    );
    assert_ne!(staged, bare, "the source bytes were copied verbatim");
    let m = goblin::mach::MachO::parse(&staged, 0).unwrap();
    assert_eq!(
        m.name,
        Some("@rpath/Extra.dylib"),
        "install name must be normalised like a tweak's"
    );
}

#[test]
fn an_overlaid_framework_satisfies_a_tweak_dependency() {
    let Some(dylib) = common::fixture("libinject.dylib") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());
    let dep = "/Library/Frameworks/Foo.framework/Foo";
    let needs_foo = patina::macho::inject_weak_dylib(&dylib, dep).unwrap();
    let dir = common::tempdir();
    let deb = deb_file(
        &dir,
        "tweak.deb",
        &[(
            "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
            &needs_foo,
        )],
    );
    let bare = patina::macho::strip_code_signature(&dylib).unwrap();
    let overlay = overlay_dir(&[("Frameworks/Foo.framework/Foo", &bare, true)]);

    let opts = EditOptions {
        tweaks: vec![deb],
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    let staged = read_entry(&edited, "Payload/Fake.app/Frameworks/Tweak.dylib");
    let libs = patina::macho::dylib_paths(&staged);
    assert!(
        libs.iter().any(|l| l == "@rpath/Foo.framework/Foo"),
        "overlaid provider did not satisfy the dependency: {libs:?}"
    );
    assert!(!libs.iter().any(|l| l == dep), "{libs:?}");

    let foo = read_entry(&edited, "Payload/Fake.app/Frameworks/Foo.framework/Foo");
    assert!(patina::codesign::has_code_directory(&foo));
}

#[test]
fn every_staged_macho_carries_exactly_one_signature() {
    let Some(dylib) = common::fixture("libinject.dylib") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());
    let dir = common::tempdir();
    let deb = deb_file(
        &dir,
        "tweak.deb",
        &[
            (
                "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
                &dylib,
            ),
            ("Library/Frameworks/Orion.framework/Orion", &dylib),
        ],
    );
    let bare = patina::macho::strip_code_signature(&dylib).unwrap();
    let overlay = overlay_dir(&[("Frameworks/Extra.dylib", &bare, true)]);
    let ent = dir.join("ent.xml");
    std::fs::write(
        &ent,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>"#,
    )
    .unwrap();

    let opts = EditOptions {
        tweaks: vec![deb],
        overlays: vec![overlay],
        entitlements: Some(ent),
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    let found = machos(&edited);
    for want in [
        "Payload/Fake.app/Fake",
        "Payload/Fake.app/Frameworks/Tweak.dylib",
        "Payload/Fake.app/Frameworks/Orion.framework/Orion",
        "Payload/Fake.app/Frameworks/Extra.dylib",
    ] {
        assert!(found.iter().any(|(n, _)| n == want), "{want} not staged");
    }
    for (name, data) in &found {
        assert!(
            patina::codesign::has_code_directory(data),
            "{name} is unsigned"
        );
        let counts = signature_counts(data);
        assert!(
            counts.iter().all(|&c| c == 1),
            "{name} has {counts:?} LC_CODE_SIGNATURE per slice, expected one each"
        );
    }
}

#[test]
fn an_overlaid_main_executable_is_signed_once_after_injection() {
    let Some(dylib) = common::fixture("libinject.dylib") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());
    let dir = common::tempdir();
    let deb = deb_file(
        &dir,
        "tweak.deb",
        &[(
            "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
            &dylib,
        )],
    );
    let bare = patina::macho::strip_code_signature(&dylib).unwrap();
    assert!(!patina::codesign::has_code_directory(&bare));
    let overlay = overlay_dir(&[("Fake", &bare, true)]);

    let opts = EditOptions {
        tweaks: vec![deb],
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(report.resigned);

    let exe = read_entry(&edited, "Payload/Fake.app/Fake");
    let m = goblin::mach::MachO::parse(&exe, 0).unwrap();
    assert_eq!(m.header.filetype, 0x6, "the overlay must be the base");
    let libs = patina::macho::dylib_paths(&exe);
    assert!(
        libs.iter().any(|l| l == "@rpath/Tweak.dylib"),
        "the emitted executable is not the weak-linked one: {libs:?}"
    );
    assert!(patina::codesign::has_code_directory(&exe));
    assert_eq!(
        signature_counts(&exe),
        [1],
        "an overlaid main executable must be signed exactly once"
    );
}

#[test]
fn an_overlaid_info_plist_composes_with_rename() {
    let ipa = build_custom_ipa(&[]);
    let mut plist = plist::Dictionary::new();
    plist.insert("CFBundleExecutable".into(), "Fake".into());
    plist.insert("CFBundleName".into(), "Fake".into());
    plist.insert("OverlayOnlyKey".into(), "kept".into());
    let mut bytes = Vec::new();
    plist::to_writer_binary(&mut bytes, &plist::Value::Dictionary(plist)).unwrap();
    let overlay = overlay_dir(&[("Info.plist", &bytes, false)]);

    let opts = EditOptions {
        name: Some("Renamed".into()),
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    let d = plist_of(&edited, "Payload/Fake.app/Info.plist");
    let d = d.as_dictionary().unwrap();
    assert_eq!(d["CFBundleName"].as_string(), Some("Renamed"));
    assert_eq!(d["OverlayOnlyKey"].as_string(), Some("kept"));
}

#[test]
fn a_non_macho_overlay_file_is_copied_byte_identically() {
    let ipa = build_custom_ipa(&[]);
    let blob = common::incompressible_blob(4096);
    let overlay = overlay_dir(&[("Data/blob.bin", &blob, false)]);

    let opts = EditOptions {
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    assert_eq!(read_entry(&edited, "Payload/Fake.app/Data/blob.bin"), blob);
}

#[test]
fn thin_of_an_overlaid_fat_macho_is_thinned_and_signed() {
    let Some(dylib) = common::fixture("libinject.dylib") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());
    let fat = make_fat(&patina::macho::strip_code_signature(&dylib).unwrap());
    let overlay = overlay_dir(&[("Frameworks/Fat.dylib", &fat, true)]);

    let opts = EditOptions {
        overlays: vec![overlay],
        thin: true,
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(report.thinned >= 1);

    let out = read_entry(&edited, "Payload/Fake.app/Frameworks/Fat.dylib");
    assert!(
        matches!(
            goblin::mach::Mach::parse(&out).unwrap(),
            goblin::mach::Mach::Binary(_)
        ),
        "the overlaid fat dylib must collapse to thin arm64"
    );
    assert!(patina::codesign::has_code_directory(&out));
    assert_eq!(
        patina::codesign::adhoc_sign(&out, "Fat.dylib", None).unwrap(),
        out,
        "the signature must seal the post-thin bytes"
    );
}

#[test]
fn deb_framework_is_staged_as_a_provider_not_weak_linked() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();

    let deb = deb_file(
        &dir,
        "tweak.deb",
        &[
            (
                "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
                &dylib,
            ),
            ("Library/Frameworks/Hook.framework/Hook", &dylib),
            ("Library/Frameworks/Hook.framework/Info.plist", b"<plist/>"),
        ],
    );

    let opts = EditOptions {
        tweaks: vec![deb],
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(report.resigned, "the tweak weak-link must re-sign the exe");

    let hook = read_entry(&edited, "Payload/Fake.app/Frameworks/Hook.framework/Hook");
    assert!(patina::codesign::has_code_directory(&hook));
    assert_eq!(
        read_entry(
            &edited,
            "Payload/Fake.app/Frameworks/Hook.framework/Info.plist"
        ),
        b"<plist/>"
    );
    let tweak = read_entry(&edited, "Payload/Fake.app/Frameworks/Tweak.dylib");
    assert!(patina::codesign::has_code_directory(&tweak));

    let exe = read_entry(&edited, "Payload/Fake.app/Fake");
    let m = goblin::mach::MachO::parse(&exe, 0).unwrap();
    assert!(m.libs.contains(&"@rpath/Tweak.dylib"), "{:?}", m.libs);
    assert!(
        !m.libs.iter().any(|l| l.contains("Hook")),
        "a provider framework must not be weak-linked: {:?}",
        m.libs
    );
}

#[test]
fn a_non_deb_tweak_source_is_rejected() {
    let (ipa, _) = common::build_ipa(b"not-a-macho");
    let dir = common::tempdir();
    let dylib = dir.join("foo.dylib");
    std::fs::write(&dylib, b"whatever").unwrap();

    let opts = EditOptions {
        tweaks: vec![dylib],
        ..Default::default()
    };
    let err = format!(
        "{:#}",
        edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap_err()
    );
    assert!(
        err.contains("--tweak: expected a .deb package, got 'foo.dylib'"),
        "{err}"
    );
}

fn tweak_and_provider_deb() -> Option<std::path::PathBuf> {
    let dylib = common::fixture("libinject.dylib")?;
    let dep = patina::macho::inject_weak_dylib(&dylib, "/usr/lib/libsubstrate.dylib").unwrap();
    let dir = common::tempdir();
    Some(deb_file(
        &dir,
        "tweak.deb",
        &[
            ("Library/MobileSubstrate/DynamicLibraries/Tweak.dylib", &dep),
            (
                "Library/MobileSubstrate/DynamicLibraries/libsubstrate.dylib",
                &dylib,
            ),
        ],
    ))
}

#[test]
fn provided_dependency_is_rewritten() {
    let Some(deb) = tweak_and_provider_deb() else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());

    let opts = EditOptions {
        tweaks: vec![deb],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    let staged = read_entry(&edited, "Payload/Fake.app/Frameworks/Tweak.dylib");
    let m = goblin::mach::MachO::parse(&staged, 0).unwrap();
    assert!(
        m.libs.contains(&"@rpath/libsubstrate.dylib"),
        "dep not rewritten: {:?}",
        m.libs
    );
    assert!(
        !m.libs.contains(&"/usr/lib/libsubstrate.dylib"),
        "old dep path must be gone: {:?}",
        m.libs
    );
    assert!(patina::codesign::has_code_directory(&staged));
}

#[test]
fn unprovided_dependency_is_left_alone() {
    let Some(dylib) = common::fixture("libinject.dylib") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());
    let dep = patina::macho::inject_weak_dylib(&dylib, "/usr/lib/libsubstrate.dylib").unwrap();
    let dir = common::tempdir();
    let deb = deb_file(
        &dir,
        "tweak.deb",
        &[("Library/MobileSubstrate/DynamicLibraries/Tweak.dylib", &dep)],
    );

    let opts = EditOptions {
        tweaks: vec![deb],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    let staged = read_entry(&edited, "Payload/Fake.app/Frameworks/Tweak.dylib");
    let m = goblin::mach::MachO::parse(&staged, 0).unwrap();
    assert!(
        m.libs.contains(&"/usr/lib/libsubstrate.dylib"),
        "{:?}",
        m.libs
    );
}

fn deb_needing_cephei(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    let dylib = common::fixture("libinject.dylib")?;
    Some(deb_with_control(
        dir,
        name,
        "Package: com.bandarhl.bhtwitter\n\
         Version: 6.0.4-2\n\
         Depends: mobilesubstrate, ws.hbang.common\n\
         Conflicts: com.den.twigalaxy\n",
        &[(
            "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
            &dylib,
        )],
    ))
}

const ELLEKIT_CONTROL: &str = "Package: ellekit\n\
     Version: 0.6.3\n\
     Conflicts: org.coolstar.libhooker, mobilesubstrate\n\
     Provides: mobilesubstrate (= 99), org.coolstar.libhooker (= 1.6.9)\n";

#[test]
fn a_missing_tweak_dependency_is_an_error() {
    let dir = common::tempdir();
    let Some(deb) = deb_needing_cephei(&dir, "tweak.deb") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());

    let opts = EditOptions {
        tweaks: vec![deb],
        ..Default::default()
    };
    let err = format!(
        "{:#}",
        edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap_err()
    );
    assert!(
        err.contains("tweak dependencies are not satisfied"),
        "{err}"
    );
    assert!(
        err.contains("com.bandarhl.bhtwitter needs ws.hbang.common"),
        "{err}"
    );
    assert!(
        err.contains("com.bandarhl.bhtwitter needs mobilesubstrate"),
        "{err}"
    );
    assert!(err.contains("--ignore-missing-deps"), "{err}");
}

#[test]
fn ignore_missing_deps_downgrades_the_error_to_a_warning() {
    let dir = common::tempdir();
    let Some(deb) = deb_needing_cephei(&dir, "tweak.deb") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());

    let opts = EditOptions {
        tweaks: vec![deb],
        ignore_missing_deps: true,
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.tweaks.len(), 1);
    read_entry(&edited, "Payload/Fake.app/Frameworks/Tweak.dylib");
}

/// ElleKit's `Conflicts: mobilesubstrate` must not fire against its own `Provides:`.
#[test]
fn a_dependency_provided_by_another_package_satisfies_the_run() {
    let dir = common::tempdir();
    let Some(tweak) = deb_needing_cephei(&dir, "tweak.deb") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let cephei = deb_with_control(
        &dir,
        "cephei.deb",
        "Package: ws.hbang.common\nVersion: 2.0\nDepends: firmware (>= 15.0)\n",
        &[(
            "Library/Frameworks/Cephei.framework/Cephei",
            &common::fixture("libinject.dylib").unwrap(),
        )],
    );
    let ellekit = deb_with_control(
        &dir,
        "ellekit.deb",
        ELLEKIT_CONTROL,
        &[(
            "Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
            &common::fixture("libinject.dylib").unwrap(),
        )],
    );
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());

    let opts = EditOptions {
        tweaks: vec![tweak, ellekit, cephei],
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.tweaks.len(), 3);
    read_entry(&edited, "Payload/Fake.app/Frameworks/Tweak.dylib");
}

#[test]
fn fakesign_bundle_signs_and_seals() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&mach);
    let opts = EditOptions {
        fakesign_bundle: true,
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(
        report.fakesigned.unwrap() >= 1,
        "at least the main exe signed"
    );

    let out = common::tempdir().join("out.ipa");
    std::fs::write(&out, &edited).unwrap();
    let st = std::process::Command::new("unzip")
        .arg("-t")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );

    let cr = read_entry(&edited, "Payload/Fake.app/_CodeSignature/CodeResources");
    let v = plist::Value::from_reader(Cursor::new(&cr)).unwrap();
    let files2 = v.as_dictionary().unwrap()["files2"]
        .as_dictionary()
        .unwrap();
    assert!(
        files2.contains_key("blob.bin"),
        "resource not sealed: {:?}",
        files2.keys().collect::<Vec<_>>()
    );

    let exe = read_entry(&edited, "Payload/Fake.app/Fake");
    assert!(
        patina::codesign::has_code_directory(&exe),
        "main exe not signed"
    );

    assert_eq!(
        common::raw_compressed_bytes(&edited, "Payload/Fake.app/blob.bin"),
        common::raw_compressed_bytes(&ipa, "Payload/Fake.app/blob.bin")
    );
}

#[test]
fn fakesign_bundle_signs_nested_framework() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let fw_info = {
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleIdentifier".into(), "com.example.bar".into());
        d.insert("CFBundlePackageType".into(), "FMWK".into());
        d.insert("CFBundleExecutable".into(), "Bar".into());
        let mut b = Vec::new();
        plist::to_writer_binary(&mut b, &plist::Value::Dictionary(d)).unwrap();
        b
    };
    let ipa = build_custom_ipa(&[
        ("Payload/Fake.app/Fake", mach, true),
        ("Payload/Fake.app/Frameworks/Bar.framework/Bar", dylib, true),
        (
            "Payload/Fake.app/Frameworks/Bar.framework/Info.plist",
            fw_info,
            false,
        ),
    ]);

    let opts = EditOptions {
        fakesign_bundle: true,
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(
        report.fakesigned.unwrap() >= 2,
        "main exe + framework binary signed"
    );

    let nested = read_entry(
        &edited,
        "Payload/Fake.app/Frameworks/Bar.framework/_CodeSignature/CodeResources",
    );
    assert!(!nested.is_empty(), "nested framework CodeResources missing");
    let bar = read_entry(&edited, "Payload/Fake.app/Frameworks/Bar.framework/Bar");
    assert!(
        patina::codesign::has_code_directory(&bar),
        "framework binary not signed"
    );
    // Panics if the app-level seal is missing.
    let _ = read_entry(&edited, "Payload/Fake.app/_CodeSignature/CodeResources");
}

#[test]
fn metadata_writes_all_info_keys() {
    let ipa = build_custom_ipa(&[(
        "Payload/Fake.app/blob.bin",
        common::incompressible_blob(1024),
        true,
    )]);
    let dir = common::tempdir();
    let overlay = dir.join("overlay.plist");
    std::fs::write(
        &overlay,
        br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CustomKey</key><string>hi</string></dict></plist>"#,
    )
    .unwrap();

    let opts = EditOptions {
        bundle_id: Some("com.new.id".into()),
        version: Some("9.9".into()),
        min_os: Some("15.0".into()),
        merge_plist: Some(overlay),
        remove_supported_devices: true,
        enable_file_sharing: true,
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.metadata.len(), 6);

    let info = plist_of(&edited, "Payload/Fake.app/Info.plist");
    let d = info.as_dictionary().unwrap();
    assert_eq!(d["CFBundleIdentifier"].as_string(), Some("com.new.id"));
    assert_eq!(d["CFBundleShortVersionString"].as_string(), Some("9.9"));
    assert_eq!(d["CFBundleVersion"].as_string(), Some("9.9"));
    assert_eq!(d["MinimumOSVersion"].as_string(), Some("15.0"));
    assert_eq!(d["UIFileSharingEnabled"].as_boolean(), Some(true));
    assert_eq!(d["CustomKey"].as_string(), Some("hi"));
}

#[test]
fn remove_watch_and_extensions_drop_subtrees() {
    let ipa = build_custom_ipa(&[
        (
            "Payload/Fake.app/Watch/W.app/Info.plist",
            b"w".to_vec(),
            false,
        ),
        ("Payload/Fake.app/Watch/W.app/W", b"bin".to_vec(), true),
        (
            "Payload/Fake.app/PlugIns/Ext.appex/Info.plist",
            b"e".to_vec(),
            false,
        ),
        ("Payload/Fake.app/PlugIns/Keep.txt", b"k".to_vec(), false),
    ]);

    let opts = EditOptions {
        remove_watch: true,
        remove_extensions: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.removed.len(), 2);

    let names = patina::archive::list_names(&edited).unwrap();
    assert!(
        !names.iter().any(|n| n.contains("/Watch/")),
        "watch subtree remains"
    );
    assert!(
        !names.iter().any(|n| n.contains(".appex/")),
        "appex subtree remains"
    );
    assert!(
        names
            .iter()
            .any(|n| n == "Payload/Fake.app/PlugIns/Keep.txt")
    );
}

#[test]
fn remove_encrypted_extensions_spares_unencrypted() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    // The appex binary is the unencrypted fixture (cryptid 0).
    let appex_info = {
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleExecutable".into(), "Ext".into());
        let mut b = Vec::new();
        plist::to_writer_binary(&mut b, &plist::Value::Dictionary(d)).unwrap();
        b
    };
    let ipa = build_custom_ipa(&[
        (
            "Payload/Fake.app/PlugIns/Ext.appex/Info.plist",
            appex_info,
            false,
        ),
        ("Payload/Fake.app/PlugIns/Ext.appex/Ext", mach, true),
    ]);

    let opts = EditOptions {
        remove_encrypted_extensions: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(
        report.removed.is_empty(),
        "unencrypted appex must be spared"
    );
    let names = patina::archive::list_names(&edited).unwrap();
    assert!(names.iter().any(|n| n.contains("Ext.appex/")));
}

#[test]
fn thin_collapses_fat_binaries() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let fat = make_fat(&mach);
    assert!(matches!(
        goblin::mach::Mach::parse(&fat).unwrap(),
        goblin::mach::Mach::Fat(_)
    ));
    let ipa = build_custom_ipa(&[("Payload/Fake.app/Fake", fat, true)]);

    let opts = EditOptions {
        thin: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.thinned, 1);

    let exe = read_entry(&edited, "Payload/Fake.app/Fake");
    assert!(
        matches!(
            goblin::mach::Mach::parse(&exe).unwrap(),
            goblin::mach::Mach::Binary(_)
        ),
        "fat exe must collapse to a thin arm64 Mach-O"
    );
}

#[test]
fn primary_icon_declares_loose_files_when_the_app_has_none() {
    let ipa = build_custom_ipa(&[]);
    let dir = common::tempdir();
    let icon = dir.join("icon.png");
    std::fs::write(&icon, red_png(256)).unwrap();

    let opts = EditOptions {
        icon: Some(icon),
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(report.primary_icon);

    // The pair Xcode emits: one iPhone, one iPad with the idiom suffix.
    for (fname, px) in [
        ("AppIcon60x60@2x.png", 120),
        ("AppIcon76x76@2x~ipad.png", 152),
    ] {
        let img =
            image::load_from_memory(&read_entry(&edited, &format!("Payload/Fake.app/{fname}")))
                .unwrap();
        assert_eq!((img.width(), img.height()), (px, px), "{fname}");
    }

    let d = plist_of(&edited, "Payload/Fake.app/Info.plist");
    let root = d.as_dictionary().unwrap();
    let files = |key: &str| -> Vec<String> {
        root[key].as_dictionary().unwrap()["CFBundlePrimaryIcon"]
            .as_dictionary()
            .unwrap()["CFBundleIconFiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_string().unwrap().to_owned())
            .collect()
    };
    assert_eq!(files("CFBundleIcons"), ["AppIcon60x60"]);
    assert_eq!(files("CFBundleIcons~ipad"), ["AppIcon76x76"]);
}

#[test]
fn primary_icon_respects_an_apps_existing_icon_declaration() {
    let info = {
        let mut primary = plist::Dictionary::new();
        primary.insert(
            "CFBundleIconFiles".into(),
            plist::Value::Array(vec![
                "ProductionAppIcon29x29".into(),
                "ProductionAppIcon60x60".into(),
            ]),
        );
        primary.insert("CFBundleIconName".into(), "ProductionAppIcon".into());
        let mut icons = plist::Dictionary::new();
        icons.insert("CFBundlePrimaryIcon".into(), primary.into());
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleName".into(), "Fake".into());
        d.insert("CFBundleExecutable".into(), "Fake".into());
        d.insert("CFBundleIdentifier".into(), "com.example.fake".into());
        d.insert("CFBundleIconName".into(), "ProductionAppIcon".into());
        d.insert("CFBundleIcons".into(), icons.into());
        let mut b = Vec::new();
        plist::to_writer_binary(&mut b, &plist::Value::Dictionary(d)).unwrap();
        b
    };
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("Payload/Fake.app/Info.plist", SimpleFileOptions::default())
        .unwrap();
    w.write_all(&info).unwrap();
    let ipa = w.finish().unwrap().into_inner();

    let dir = common::tempdir();
    let icon = dir.join("icon.png");
    std::fs::write(&icon, red_png(256)).unwrap();
    let opts = EditOptions {
        icon: Some(icon),
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    assert!(
        patina::archive::read_entry(&edited, "Payload/Fake.app/ProductionAppIcon60x60@2x.png")
            .unwrap()
            .is_some()
    );
    assert!(
        patina::archive::read_entry(&edited, "Payload/Fake.app/AppIcon60x60@2x.png")
            .unwrap()
            .is_none(),
        "must not invent an AppIcon name the bundle does not use"
    );

    let d = plist_of(&edited, "Payload/Fake.app/Info.plist");
    let primary = d.as_dictionary().unwrap()["CFBundleIcons"]
        .as_dictionary()
        .unwrap()["CFBundlePrimaryIcon"]
        .as_dictionary()
        .unwrap();
    let files: Vec<&str> = primary["CFBundleIconFiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_string().unwrap())
        .collect();
    assert_eq!(
        files,
        ["ProductionAppIcon29x29", "ProductionAppIcon60x60"],
        "the app's own list must survive"
    );
    assert_eq!(
        primary["CFBundleIconName"].as_string(),
        Some("ProductionAppIcon"),
        "CFBundleIconName points into the catalogue and must not be touched"
    );
}

#[test]
fn thin_does_not_resurrect_removed_appex_binary() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    // 2 arches so --thin actually strips a slice; a 1-arch fat is a no-op.
    let fat = {
        let x86 = vec![0u8; 32];
        let (off0, off1) = (0x4000u32, 0x8000u32);
        let mut v = Vec::new();
        v.extend_from_slice(&0xcafebabeu32.to_be_bytes()); // FAT_MAGIC
        v.extend_from_slice(&2u32.to_be_bytes()); // nfat_arch
        v.extend_from_slice(&0x01000007u32.to_be_bytes()); // CPU_TYPE_X86_64
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&off0.to_be_bytes());
        v.extend_from_slice(&(x86.len() as u32).to_be_bytes());
        v.extend_from_slice(&14u32.to_be_bytes());
        v.extend_from_slice(&0x0100000cu32.to_be_bytes()); // CPU_TYPE_ARM64
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&off1.to_be_bytes());
        v.extend_from_slice(&(mach.len() as u32).to_be_bytes());
        v.extend_from_slice(&14u32.to_be_bytes());
        v.resize(off0 as usize, 0);
        v.extend_from_slice(&x86);
        v.resize(off1 as usize, 0);
        v.extend_from_slice(&mach);
        v
    };
    let appex_plist = {
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleExecutable".into(), "Foo".into());
        d.insert("CFBundleIdentifier".into(), "com.x.foo".into());
        let mut b = Vec::new();
        plist::to_writer_binary(&mut b, &plist::Value::Dictionary(d)).unwrap();
        b
    };

    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let o =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    w.start_file("Payload/Fake.app/Info.plist", o).unwrap();
    w.write_all(&common::info_plist("Fake")).unwrap();
    w.start_file("Payload/Fake.app/Fake", o).unwrap();
    w.write_all(&mach).unwrap();
    w.start_file("Payload/Fake.app/PlugIns/Foo.appex/Info.plist", o)
        .unwrap();
    w.write_all(&appex_plist).unwrap();
    w.start_file("Payload/Fake.app/PlugIns/Foo.appex/Foo", o)
        .unwrap();
    w.write_all(&fat).unwrap();
    let ipa = w.finish().unwrap().into_inner();

    let opts = EditOptions {
        thin: true,
        remove_extensions: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    let names = patina::archive::list_names(&edited).unwrap();
    assert!(
        !names
            .iter()
            .any(|n| n.starts_with("Payload/Fake.app/PlugIns/")),
        "removed appex must not be resurrected by --thin: {names:?}"
    );
}

/// A tweak that finds no jailbreak path falls back to `mainBundle`.
#[test]
fn deb_resource_bundles_land_at_the_app_root() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();

    let deb = dir.join("tweak.deb");
    std::fs::write(
        &deb,
        build_deb(&[
            (
                "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
                &dylib,
            ),
            (
                "Library/MobileSubstrate/DynamicLibraries/Tweak.plist",
                b"filter",
            ),
            (
                "Library/Application Support/BHT/Res.bundle/en.lproj/Localizable.strings",
                b"strings",
            ),
            (
                "Library/Application Support/BHT/Res.bundle/sound.aac",
                b"aac",
            ),
            (
                "Library/Application Support/BHT/Res.bundle/Inner.bundle/x.txt",
                b"inner",
            ),
        ]),
    )
    .unwrap();

    let opts = EditOptions {
        tweaks: vec![deb],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    assert_eq!(
        read_entry(
            &edited,
            "Payload/Fake.app/Res.bundle/en.lproj/Localizable.strings"
        ),
        b"strings"
    );
    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/Res.bundle/sound.aac"),
        b"aac"
    );
    assert_eq!(
        read_entry(&edited, "Payload/Fake.app/Res.bundle/Inner.bundle/x.txt"),
        b"inner"
    );
    let names = patina::archive::list_names(&edited).unwrap();
    assert!(
        !names.iter().any(|n| n.ends_with("Tweak.plist")),
        "Substrate filter plist should not be injected: {names:?}"
    );
}

/// ElleKit's shape: `CydiaSubstrate` is a symlink, the rest is daemon plumbing.
#[test]
fn ellekit_symlink_provides_cydiasubstrate_for_a_tweak() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let base = common::fixture("libinject.dylib").unwrap();
    // Nothing provides it, so it survives resolution and marks these bytes.
    let ellekit = patina::macho::inject_weak_dylib(&base, "/marker/libellekit.dylib").unwrap();
    let dep = "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate";
    let tweak = patina::macho::inject_weak_dylib(&base, dep).unwrap();
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();

    let ek = dir.join("ellekit.deb");
    std::fs::write(
        &ek,
        build_deb_tree(&[
            ("./var/jb/usr/lib/libellekit.dylib", None, &ellekit),
            (
                "./var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                Some("/var/jb/usr/lib/libellekit.dylib"),
                b"",
            ),
            (
                "./var/jb/usr/lib/libsubstrate.dylib",
                Some("/var/jb/usr/lib/libellekit.dylib"),
                b"",
            ),
            ("./var/jb/usr/lib/ellekit/pspawn.dylib", None, &ellekit),
            ("./var/jb/usr/libexec/ellekit/loader", None, b"loader"),
            (
                "./var/jb/etc/rc.d/ellekit-loader",
                Some("/var/jb/usr/libexec/ellekit/loader"),
                b"",
            ),
        ]),
    )
    .unwrap();
    let tw = dir.join("tweak.deb");
    std::fs::write(
        &tw,
        build_deb_tree(&[(
            "./var/jb/Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
            None,
            &tweak,
        )]),
    )
    .unwrap();

    let opts = EditOptions {
        tweaks: vec![ek, tw],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();

    let staged = read_entry(
        &edited,
        "Payload/Fake.app/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
    );
    assert!(patina::codesign::has_code_directory(&staged));
    let libs = patina::macho::dylib_paths(&staged);
    assert!(
        libs.iter().any(|l| l == "/marker/libellekit.dylib"),
        "materialised link must carry libellekit's bytes: {libs:?}"
    );

    let tweak_libs = patina::macho::dylib_paths(&read_entry(
        &edited,
        "Payload/Fake.app/Frameworks/Tweak.dylib",
    ));
    assert!(
        tweak_libs
            .iter()
            .any(|l| l == "@rpath/CydiaSubstrate.framework/CydiaSubstrate"),
        "detection must repoint the tweak at the staged framework: {tweak_libs:?}"
    );
    assert!(!tweak_libs.iter().any(|l| l == dep), "{tweak_libs:?}");

    let names = patina::archive::list_names(&edited).unwrap();
    for junk in ["pspawn", "loader", "libsubstrate"] {
        assert!(
            !names.iter().any(|n| n.contains(junk)),
            "daemon component {junk} must not be injected: {names:?}"
        );
    }
    let exe_bytes = read_entry(&edited, "Payload/Fake.app/Fake");
    let exe = goblin::mach::MachO::parse(&exe_bytes, 0).unwrap();
    assert!(exe.libs.contains(&"@rpath/Tweak.dylib"), "{:?}", exe.libs);
    assert!(
        !exe.libs
            .iter()
            .any(|l| l.contains("CydiaSubstrate") || l.contains("ellekit")),
        "a provider framework must not be weak-linked into the executable: {:?}",
        exe.libs
    );
}

/// `DynamicLibraries` links to `usr/lib/TweakInject` on rootless injectors.
#[test]
fn rootless_tweakinject_directory_counts_as_a_tweak_directory() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();

    let deb = dir.join("tweak.deb");
    std::fs::write(
        &deb,
        build_deb(&[("./var/jb/usr/lib/TweakInject/Rootless.dylib", &dylib)]),
    )
    .unwrap();

    let opts = EditOptions {
        tweaks: vec![deb],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    let exe_bytes = read_entry(&edited, "Payload/Fake.app/Fake");
    let exe = goblin::mach::MachO::parse(&exe_bytes, 0).unwrap();
    assert!(
        exe.libs.contains(&"@rpath/Rootless.dylib"),
        "{:?}",
        exe.libs
    );
}

#[test]
fn dangling_deb_symlink_is_skipped_not_fatal() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();

    let deb = dir.join("tweak.deb");
    std::fs::write(
        &deb,
        build_deb_tree(&[
            (
                "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
                None,
                &dylib,
            ),
            (
                "Library/Frameworks/Gone.framework/Gone",
                Some("/usr/lib/never-shipped.dylib"),
                b"",
            ),
        ]),
    )
    .unwrap();

    let opts = EditOptions {
        tweaks: vec![deb],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    let names = patina::archive::list_names(&edited).unwrap();
    assert!(names.iter().any(|n| n.ends_with("Frameworks/Tweak.dylib")));
    assert!(!names.iter().any(|n| n.contains("Gone")), "{names:?}");
}

/// Settings content loads in Preferences.app, which a sideloaded app never reaches.
#[test]
fn deb_settings_only_content_is_not_injected() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let (ipa, _) = common::build_ipa(&mach);
    let dir = common::tempdir();

    let deb = dir.join("tweak.deb");
    std::fs::write(
        &deb,
        build_deb(&[
            (
                "Library/MobileSubstrate/DynamicLibraries/Tweak.dylib",
                &dylib,
            ),
            ("Library/PreferenceBundles/Prefs.bundle/Info.plist", b"p"),
            ("Library/PreferenceLoader/Preferences/Tweak.plist", b"e"),
            ("Library/Themes/Tweak.theme/Icons/x.png", b"t"),
            ("usr/lib/libsomething.dylib", &dylib),
        ]),
    )
    .unwrap();

    let opts = EditOptions {
        tweaks: vec![deb],
        deterministic: true,
        ..Default::default()
    };
    let (edited, _) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    let names = patina::archive::list_names(&edited).unwrap();
    for junk in ["Prefs.bundle", "PreferenceLoader", "Themes", "libsomething"] {
        assert!(!names.iter().any(|n| n.contains(junk)), "{junk}: {names:?}");
    }
    assert!(names.iter().any(|n| n.ends_with("Frameworks/Tweak.dylib")));
}

#[test]
fn an_overlaid_dylib_is_weak_linked_but_a_framework_is_not() {
    let Some(dylib) = common::fixture("libinject.dylib") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let (ipa, _) = common::build_ipa(&common::fixture("main_arm64").unwrap());

    let overlay = overlay_dir(&[
        ("Frameworks/Extra.dylib", &dylib, true),
        ("Frameworks/Prov.framework/Prov", &dylib, true),
    ]);
    let opts = EditOptions {
        overlays: vec![overlay],
        deterministic: true,
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert!(report.resigned, "weak-linking must trigger the re-sign");

    let exe = read_entry(&edited, "Payload/Fake.app/Fake");
    let m = goblin::mach::MachO::parse(&exe, 0).unwrap();
    assert!(
        m.libs.contains(&"@rpath/Extra.dylib"),
        "loose overlaid dylib must be weak-linked: {:?}",
        m.libs
    );
    assert!(
        !m.libs.iter().any(|l| l.contains("Prov.framework")),
        "an overlaid framework must not be weak-linked: {:?}",
        m.libs
    );
    assert!(
        m.rpaths.contains(&"@executable_path/Frameworks"),
        "rpath must be ensured"
    );
    assert!(patina::codesign::has_code_directory(&exe));
}

//! Oracle test: patina's in-memory CodeResources walk must match what
//! apple-codesign's `BundleSigner` seals on disk. Skips without arm64 fixtures.

mod common;

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use apple_codesign::{BundleSigner, SigningSettings};
use patina::edit::{EditOptions, WriteMode, edit_bytes};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

fn read_entry(archive: &[u8], name: &str) -> Vec<u8> {
    patina::archive::read_entry(archive, name)
        .unwrap()
        .unwrap_or_else(|| panic!("missing entry {name}"))
}

/// `(files-keys, files2-keys, files2 hash2 by key)` from a CodeResources plist.
fn seal_summary(bytes: &[u8]) -> (Vec<String>, Vec<String>, BTreeMap<String, Vec<u8>>) {
    let v = plist::Value::from_reader(Cursor::new(bytes)).unwrap();
    let d = v.as_dictionary().unwrap();
    let keys = |section: &str| -> Vec<String> {
        d.get(section)
            .and_then(|v| v.as_dictionary())
            .map(|m| {
                let mut k: Vec<String> = m.keys().cloned().collect();
                k.sort();
                k
            })
            .unwrap_or_default()
    };
    let mut hashes = BTreeMap::new();
    if let Some(files2) = d.get("files2").and_then(|v| v.as_dictionary()) {
        for (k, val) in files2 {
            if let Some(h) =
                val.as_dictionary()
                    .and_then(|m| m.get("hash2"))
                    .and_then(|v| match v {
                        plist::Value::Data(b) => Some(b.clone()),
                        _ => None,
                    })
            {
                hashes.insert(k.clone(), h);
            }
        }
    }
    (keys("files"), keys("files2"), hashes)
}

fn extract(ipa: &[u8], dest: &Path) {
    let mut a = zip::ZipArchive::new(Cursor::new(ipa)).unwrap();
    for i in 0..a.len() {
        let mut f = a.by_index(i).unwrap();
        let rel = f.enclosed_name().unwrap();
        let out = dest.join(&rel);
        if f.is_dir() {
            std::fs::create_dir_all(&out).unwrap();
            continue;
        }
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        if f.is_symlink() {
            let mut t = String::new();
            f.read_to_string(&mut t).unwrap();
            std::os::unix::fs::symlink(&t, &out).unwrap();
            continue;
        }
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        std::fs::write(&out, &buf).unwrap();
        if let Some(mode) = f.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }
}

/// CodeResources keyed by bundle-relative directory (`""` = app root).
fn oracle_seals(ipa: &[u8], app_rel: &str) -> BTreeMap<String, Vec<u8>> {
    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    extract(ipa, src.path());
    let app_src = src.path().join(app_rel);
    let app_out = dst.path().join(app_rel);
    std::fs::create_dir_all(&app_out).unwrap();

    let mut signer = BundleSigner::new_from_path(&app_src).unwrap();
    signer.collect_nested_bundles().unwrap();
    signer
        .write_signed_bundle(&app_out, &SigningSettings::default())
        .unwrap();

    let mut out = BTreeMap::new();
    for entry in walkdir(&app_out) {
        if entry.file_name().and_then(|s| s.to_str()) == Some("CodeResources") {
            let rel = entry
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .strip_prefix(&app_out)
                .unwrap()
                .to_string_lossy()
                .to_string();
            out.insert(rel, std::fs::read(&entry).unwrap());
        }
    }
    out
}

fn walkdir(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() && !p.is_symlink() {
                stack.push(p);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    out
}

fn app_info(id: &str, exe: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut d = plist::Dictionary::new();
    d.insert("CFBundleIdentifier".into(), id.into());
    d.insert("CFBundleExecutable".into(), exe.into());
    for (k, v) in extra {
        d.insert((*k).into(), (*v).into());
    }
    let mut b = Vec::new();
    plist::to_writer_binary(&mut b, &plist::Value::Dictionary(d)).unwrap();
    b
}

fn build(entries: &[(&str, Vec<u8>, bool, Option<&str>)]) -> Vec<u8> {
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data, stored, link) in entries {
        let method = if *stored {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        let opts = SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(0o100755);
        if let Some(t) = link {
            w.add_symlink(
                (*name).to_string(),
                (*t).to_string(),
                SimpleFileOptions::default().unix_permissions(0o120777),
            )
            .unwrap();
        } else {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
    }
    w.finish().unwrap().into_inner()
}

fn mine_seals(edited: &[u8], bundle_rels: &[&str], app_dir: &str) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for rel in bundle_rels {
        let name = if rel.is_empty() {
            format!("{app_dir}_CodeSignature/CodeResources")
        } else {
            format!("{app_dir}{rel}/_CodeSignature/CodeResources")
        };
        out.insert(rel.to_string(), read_entry(edited, &name));
    }
    out
}

#[test]
fn matches_bundlesigner_flat_app() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let ipa = build(&[
        (
            "Payload/Fake.app/Info.plist",
            app_info("com.example.fake", "Fake", &[]),
            false,
            None,
        ),
        ("Payload/Fake.app/Fake", mach, true, None),
        (
            "Payload/Fake.app/blob.bin",
            common::incompressible_blob(4096),
            true,
            None,
        ),
        (
            "Payload/Fake.app/en.lproj/InfoPlist.strings",
            b"\"CFBundleName\" = \"F\";".to_vec(),
            false,
            None,
        ),
        ("Payload/Fake.app/link", Vec::new(), true, Some("Fake")),
    ]);

    let (edited, report) = edit_bytes(
        &ipa,
        &EditOptions {
            fakesign_bundle: true,
            deterministic: true,
            ..Default::default()
        },
        WriteMode::Compact,
    )
    .unwrap();
    assert!(report.fakesigned.is_some());

    let oracle = oracle_seals(&ipa, "Payload/Fake.app");
    let mine = mine_seals(&edited, &[""], "Payload/Fake.app/");

    let (o_files, o_files2, o_hashes) = seal_summary(&oracle[""]);
    let (m_files, m_files2, m_hashes) = seal_summary(&mine[""]);
    assert_eq!(m_files2, o_files2, "files2 sealed key sets differ");
    assert_eq!(m_files, o_files, "files sealed key sets differ");
    assert_eq!(
        m_hashes.get("blob.bin"),
        o_hashes.get("blob.bin"),
        "blob.bin content digest differs"
    );
    assert!(
        o_hashes.contains_key("blob.bin"),
        "oracle didn't seal blob.bin"
    );
    assert_eq!(
        String::from_utf8_lossy(&mine[""]),
        String::from_utf8_lossy(&oracle[""]),
        "CodeResources plist is not byte-identical to apple-codesign's"
    );
}

#[test]
fn matches_bundlesigner_nested_framework() {
    let Some(mach) = common::fixture("main_arm64") else {
        eprintln!("skipping: fixtures absent");
        return;
    };
    let dylib = common::fixture("libinject.dylib").unwrap();
    let ipa = build(&[
        (
            "Payload/Fake.app/Info.plist",
            app_info(
                "com.example.fake",
                "Fake",
                &[("CFBundlePackageType", "APPL")],
            ),
            false,
            None,
        ),
        ("Payload/Fake.app/Fake", mach, true, None),
        (
            "Payload/Fake.app/blob.bin",
            common::incompressible_blob(2048),
            true,
            None,
        ),
        (
            "Payload/Fake.app/Frameworks/Bar.framework/Info.plist",
            app_info("com.example.bar", "Bar", &[("CFBundlePackageType", "FMWK")]),
            false,
            None,
        ),
        (
            "Payload/Fake.app/Frameworks/Bar.framework/Bar",
            dylib,
            true,
            None,
        ),
        (
            "Payload/Fake.app/Frameworks/Bar.framework/res.txt",
            b"resource".to_vec(),
            false,
            None,
        ),
    ]);

    let (edited, _) = edit_bytes(
        &ipa,
        &EditOptions {
            fakesign_bundle: true,
            deterministic: true,
            ..Default::default()
        },
        WriteMode::Compact,
    )
    .unwrap();

    let oracle = oracle_seals(&ipa, "Payload/Fake.app");
    let mine = mine_seals(
        &edited,
        &["", "Frameworks/Bar.framework"],
        "Payload/Fake.app/",
    );

    for rel in ["", "Frameworks/Bar.framework"] {
        let (o_files, o_files2, o_hashes) = seal_summary(&oracle[rel]);
        let (m_files, m_files2, m_hashes) = seal_summary(&mine[rel]);
        assert_eq!(
            m_files2, o_files2,
            "files2 key sets differ at bundle '{rel}'"
        );
        assert_eq!(m_files, o_files, "files key sets differ at bundle '{rel}'");
        // Mach-O digests legitimately differ; compare resources only.
        // Only the nested plist is byte-comparable: in the app's own, apple-codesign
        // seals the framework's unsigned bytes into `files`, patina the signed bytes.
        if rel == "Frameworks/Bar.framework" {
            assert_eq!(
                String::from_utf8_lossy(&mine[rel]),
                String::from_utf8_lossy(&oracle[rel]),
                "nested CodeResources plist is not byte-identical"
            );
        }
        for key in o_hashes.keys() {
            if key.ends_with(".txt") || key == "blob.bin" {
                assert_eq!(
                    m_hashes.get(key),
                    o_hashes.get(key),
                    "content digest differs for {key} at bundle '{rel}'"
                );
            }
        }
    }
}

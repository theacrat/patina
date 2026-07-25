#![allow(dead_code)]
//! Shared test helpers: build a synthetic `.ipa` fixture in memory.

use std::io::{Cursor, Write};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub fn incompressible_blob(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x: u64 = 0x9e3779b97f4a7c15;
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

pub fn info_plist(name: &str) -> Vec<u8> {
    let v = plist::Value::Dictionary({
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleName".into(), name.into());
        d.insert("CFBundleDisplayName".into(), name.into());
        d.insert("CFBundleIdentifier".into(), "com.example.fake".into());
        d.insert("CFBundleExecutable".into(), "Fake".into());
        d
    });
    let mut buf = Vec::new();
    plist::to_writer_binary(&mut buf, &v).unwrap();
    buf
}

pub struct FixtureEntry {
    pub name: String,
    pub data: Vec<u8>,
    pub method: CompressionMethod,
    pub mode: u32,
    pub symlink: Option<String>,
}

pub fn build_ipa(mach_o: &[u8]) -> (Vec<u8>, Vec<FixtureEntry>) {
    let entries = vec![
        FixtureEntry {
            name: "Payload/Fake.app/Info.plist".into(),
            data: info_plist("Fake"),
            method: CompressionMethod::Deflated,
            mode: 0o100644,
            symlink: None,
        },
        FixtureEntry {
            name: "Payload/Fake.app/Fake".into(),
            data: mach_o.to_vec(),
            method: CompressionMethod::Stored,
            mode: 0o100755,
            symlink: None,
        },
        FixtureEntry {
            name: "Payload/Fake.app/en.lproj/InfoPlist.strings".into(),
            data: b"\"CFBundleDisplayName\" = \"Fake\";\n\"CFBundleName\" = \"Fake\";\n".to_vec(),
            method: CompressionMethod::Deflated,
            mode: 0o100644,
            symlink: None,
        },
        FixtureEntry {
            name: "Payload/Fake.app/fr.lproj/InfoPlist.strings".into(),
            // Deliberately lacks CFBundleDisplayName: rename must not add it.
            data: b"\"CFBundleName\" = \"Fake\";\n".to_vec(),
            method: CompressionMethod::Deflated,
            mode: 0o100644,
            symlink: None,
        },
        FixtureEntry {
            name: "Payload/Fake.app/blob.bin".into(),
            data: incompressible_blob(512 * 1024),
            method: CompressionMethod::Stored,
            mode: 0o100644,
            symlink: None,
        },
        FixtureEntry {
            name: "Payload/Fake.app/link".into(),
            data: Vec::new(),
            method: CompressionMethod::Stored,
            mode: 0o120777,
            symlink: Some("Fake".into()),
        },
    ];

    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    for e in &entries {
        let opts = SimpleFileOptions::default()
            .compression_method(e.method)
            .unix_permissions(e.mode);
        if let Some(target) = &e.symlink {
            w.add_symlink(e.name.clone(), target.clone(), opts).unwrap();
        } else {
            w.start_file(e.name.clone(), opts).unwrap();
            w.write_all(&e.data).unwrap();
        }
    }
    (w.finish().unwrap().into_inner(), entries)
}

pub fn tempdir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "patina-it-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

pub fn fixture(name: &str) -> Option<Vec<u8>> {
    let p = format!("/tmp/patina-fixtures/{name}");
    std::path::Path::new(&p)
        .exists()
        .then(|| std::fs::read(&p).unwrap())
}

pub fn raw_compressed_bytes(archive: &[u8], name: &str) -> Vec<u8> {
    use std::io::Read;
    let mut a = zip::ZipArchive::new(Cursor::new(archive.to_vec())).unwrap();
    let idx = (0..a.len())
        .find(|&i| a.name_for_index(i) == Some(name))
        .unwrap_or_else(|| panic!("entry {name} not found"));
    let mut f = a.by_index_raw(idx).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    buf
}

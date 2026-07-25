//! Pure-Rust `.deb` unpacking: an `ar` archive of `control.tar.*` and
//! `data.tar.{gz,xz,lzma,zst}`. Symlinks are kept — a tweak's public name is
//! very often a link to bytes stored elsewhere in the payload.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Cursor, Read};

use anyhow::{Context, Result, bail};

pub enum Entry {
    File(Vec<u8>),
    /// Canonical path of the link target.
    Symlink(String),
}

/// Directories carry no bytes; they are kept only so a link to an empty one
/// reads as empty, not missing.
pub struct Payload {
    entries: BTreeMap<String, Entry>,
    dirs: BTreeSet<String>,
}

pub enum Resolved<'a> {
    /// `(canonical path the bytes are stored at, bytes)`.
    File(&'a str, &'a [u8]),
    /// A directory, flattened to `(subpath, source path, bytes)`.
    Dir(Vec<(String, &'a str, &'a [u8])>),
    Dangling,
}

/// Symlinks may chain (`libhbangprefs.bundle → Cephei.bundle → …`); this bounds
/// both chain length and directory-expansion recursion, so a cycle terminates.
const MAX_LINK_DEPTH: usize = 16;

impl Payload {
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Entry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn resolve(&self, path: &str) -> Resolved<'_> {
        self.resolve_at(path, MAX_LINK_DEPTH)
    }

    fn resolve_at(&self, path: &str, fuel: usize) -> Resolved<'_> {
        if fuel == 0 {
            return Resolved::Dangling;
        }
        match self.entries.get_key_value(path) {
            Some((key, Entry::File(data))) => Resolved::File(key, data),
            Some((_, Entry::Symlink(target))) => self.resolve_at(target, fuel - 1),
            None => {
                let items = self.expand_dir(path, fuel);
                if items.is_empty() && !self.dirs.contains(path) {
                    Resolved::Dangling
                } else {
                    Resolved::Dir(items)
                }
            }
        }
    }

    fn expand_dir(&self, dir: &str, fuel: usize) -> Vec<(String, &str, &[u8])> {
        let prefix = format!("{dir}/");
        let mut out = Vec::new();
        for (key, entry) in self.entries.range(prefix.clone()..) {
            let Some(sub) = key.strip_prefix(&prefix) else {
                break;
            };
            match entry {
                Entry::File(data) => out.push((sub.to_owned(), key.as_str(), data.as_slice())),
                Entry::Symlink(_) => match self.resolve_at(key, fuel - 1) {
                    Resolved::File(src, data) => out.push((sub.to_owned(), src, data)),
                    Resolved::Dir(items) => out.extend(
                        items
                            .into_iter()
                            .map(|(s, src, data)| (format!("{sub}/{s}"), src, data)),
                    ),
                    Resolved::Dangling => {}
                },
            }
        }
        out
    }
}

/// Rootless jailbreaks graft the whole tree under one prefix: `/var/jb` on
/// Procursus/Dopamine/palera1n, `/var/LIB` in the earlier rootless drafts still
/// found on some repos.
const ROOTLESS_PREFIXES: &[&str] = &["var/jb/", "var/LIB/"];
/// roothide randomises its root as `.jbroot-<16 hex>` under this directory.
const ROOTHIDE_PARENT: &str = "var/containers/Bundle/Application/";

/// Canonical payload-relative path: leading `./`, `.`/`..` segments and any
/// rootless prefix removed. `None` when the path escapes the payload root.
pub fn canonicalise(path: &str) -> Option<String> {
    let mut segs: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop()?;
            }
            s => segs.push(s),
        }
    }
    Some(strip_root_prefix(&segs.join("/")))
}

fn strip_root_prefix(path: &str) -> String {
    for prefix in ROOTLESS_PREFIXES {
        if let Some(rest) = path.strip_prefix(prefix) {
            return rest.to_owned();
        }
        if path == prefix.trim_end_matches('/') {
            return String::new();
        }
    }
    if let Some(rest) = path.strip_prefix(ROOTHIDE_PARENT) {
        if let Some((root, tail)) = rest.split_once('/') {
            if root.starts_with(".jbroot-") {
                return tail.to_owned();
            }
        }
    }
    path.to_owned()
}

/// A symlink target is relative to the link's own directory unless absolute.
fn link_target(link: &str, target: &str) -> Option<String> {
    if target.starts_with('/') {
        return canonicalise(target);
    }
    let dir = link.rsplit_once('/').map_or("", |(d, _)| d);
    canonicalise(&format!("{dir}/{target}"))
}

/// `control` is absent only from a package with no `control.tar.*` member.
pub struct Deb {
    pub payload: Payload,
    pub control: Option<Control>,
}

pub fn read(deb: &[u8]) -> Result<Deb> {
    let (control_member, data_member) = read_members(deb)?;
    let Some((data_name, data)) = data_member else {
        bail!("no data.tar.* member in .deb (not a Debian package?)");
    };
    let control = match control_member {
        Some((name, bytes)) => control_of(&name, &bytes)?,
        None => None,
    };
    Ok(Deb {
        payload: read_tar(&decompress(&data_name, &data)?)?,
        control,
    })
}

pub fn extract_payload(deb: &[u8]) -> Result<Payload> {
    Ok(read(deb)?.payload)
}

pub fn read_control(deb: &[u8]) -> Result<Control> {
    let (control_member, _) = read_members(deb)?;
    let Some((name, bytes)) = control_member else {
        bail!("no control.tar.* member in .deb (not a Debian package?)");
    };
    control_of(&name, &bytes)?.context("control.tar has no control file")
}

fn control_of(member: &str, compressed: &[u8]) -> Result<Option<Control>> {
    let tar_bytes = decompress(member, compressed)?;
    match control_file(&tar_bytes)? {
        Some(text) => parse_control(&text).map(Some),
        None => Ok(None),
    }
}

type Member = Option<(String, Vec<u8>)>;

fn read_members(deb: &[u8]) -> Result<(Member, Member)> {
    let mut control: Member = None;
    let mut data: Member = None;
    let mut archive = ar::Archive::new(Cursor::new(deb));
    while let Some(entry) = archive.next_entry() {
        let mut entry = entry.context("reading .deb ar member")?;
        let name = String::from_utf8_lossy(entry.header().identifier())
            .trim_end_matches('/')
            .to_owned();
        let slot = if name.starts_with("control.tar") {
            &mut control
        } else if name.starts_with("data.tar") {
            &mut data
        } else {
            continue;
        };
        if slot.is_some() {
            continue;
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("reading {name} member"))?;
        *slot = Some((name, buf));
    }
    Ok((control, data))
}

fn control_file(tar_bytes: &[u8]) -> Result<Option<String>> {
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    for entry in archive.entries().context("reading control.tar")? {
        let mut entry = entry.context("reading control.tar entry")?;
        let path = entry
            .path()
            .context("bad tar path")?
            .to_string_lossy()
            .into_owned();
        if path.trim_start_matches("./") != "control" {
            continue;
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .context("reading control file")?;
        return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
    }
    Ok(None)
}

#[derive(Debug, Default)]
pub struct Control {
    pub package: String,
    pub version: Option<String>,
    /// Virtual names this package also answers to, constraints stripped.
    pub provides: Vec<String>,
    pub depends: Vec<Dependency>,
    pub conflicts: Vec<String>,
}

#[derive(Debug)]
pub struct Dependency {
    pub alternatives: Vec<Alternative>,
}

/// The version constraint is kept as written but never enforced — patina checks
/// names only.
#[derive(Debug)]
pub struct Alternative {
    pub name: String,
    pub constraint: Option<String>,
}

impl fmt::Display for Dependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.alternatives.iter().map(|a| a.name.as_str()).collect();
        f.write_str(&names.join(" | "))
    }
}

pub fn parse_control(text: &str) -> Result<Control> {
    let fields = parse_fields(text);
    let package = fields
        .get("package")
        .filter(|p| !p.is_empty())
        .context("control file has no Package: field")?;
    Ok(Control {
        package: package.clone(),
        version: fields.get("version").cloned(),
        provides: fields
            .get("provides")
            .map(|v| name_list(v))
            .unwrap_or_default(),
        depends: fields
            .get("depends")
            .map(|v| dep_list(v))
            .unwrap_or_default(),
        conflicts: fields
            .get("conflicts")
            .map(|v| name_list(v))
            .unwrap_or_default(),
    })
}

/// RFC822-ish: a line starting with whitespace continues the field above it.
fn parse_fields(text: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut last: Option<String> = None;
    for line in text.lines() {
        if line.trim().is_empty() {
            last = None;
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some(value) = last.as_ref().and_then(|k| out.get_mut(k)) {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        out.insert(key.clone(), value.trim().to_owned());
        last = Some(key);
    }
    out
}

fn name_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(|term| bare_name(term).map(|(n, _)| n))
        .collect()
}

fn dep_list(value: &str) -> Vec<Dependency> {
    value
        .split(',')
        .filter_map(|term| {
            let alternatives: Vec<Alternative> = term
                .split('|')
                .filter_map(bare_name)
                .map(|(name, constraint)| Alternative { name, constraint })
                .collect();
            (!alternatives.is_empty()).then_some(Dependency { alternatives })
        })
        .collect()
}

/// `ws.hbang.common (>= 2.0)` -> `("ws.hbang.common", Some(">= 2.0"))`. An
/// architecture qualifier (`pkg:any`) or build profile (`<…>`) is dropped.
fn bare_name(term: &str) -> Option<(String, Option<String>)> {
    let term = term.trim();
    let (head, constraint) = match term.split_once('(') {
        Some((head, rest)) => (head, rest.split_once(')').map(|(c, _)| c.trim().to_owned())),
        None => (term, None),
    };
    let name = head
        .split(['[', '<', ':'])
        .next()
        .unwrap_or_default()
        .trim();
    (!name.is_empty()).then(|| (name.to_owned(), constraint))
}

/// Decompression-bomb cap; real tweaks run KB–tens of MB.
const MAX_PAYLOAD: usize = 512 * 1024 * 1024;

/// Errors past `limit` so decompression can't allocate unboundedly.
struct CappedWriter {
    buf: Vec<u8>,
    limit: usize,
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() + data.len() > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed .deb payload exceeds cap (possible decompression bomb)",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn decompress(name: &str, compressed: &[u8]) -> Result<Vec<u8>> {
    if name.ends_with(".tar") {
        if compressed.len() > MAX_PAYLOAD {
            bail!("{name} exceeds {MAX_PAYLOAD}-byte payload cap");
        }
        return Ok(compressed.to_vec());
    }
    let mut w = CappedWriter {
        buf: Vec::new(),
        limit: MAX_PAYLOAD,
    };
    if name.ends_with(".gz") {
        std::io::copy(&mut flate2::read::GzDecoder::new(compressed), &mut w)
            .with_context(|| format!("gunzip {name}"))?;
    } else if name.ends_with(".xz") {
        lzma_rs::xz_decompress(&mut Cursor::new(compressed), &mut w)
            .with_context(|| format!("xz-decompress {name}"))?;
    } else if name.ends_with(".lzma") {
        lzma_rs::lzma_decompress(&mut Cursor::new(compressed), &mut w)
            .with_context(|| format!("lzma-decompress {name}"))?;
    } else if name.ends_with(".zst") || name.ends_with(".zstd") {
        let mut dec = ruzstd::StreamingDecoder::new(Cursor::new(compressed))
            .with_context(|| format!("reading {name} frame header"))?;
        std::io::copy(&mut dec, &mut w).with_context(|| format!("zstd-decompress {name}"))?;
    } else {
        bail!("unsupported .deb member compression: {name} (only gz/xz/lzma/zst/plain tar)");
    }
    Ok(w.buf)
}

fn read_tar(tar_bytes: &[u8]) -> Result<Payload> {
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut entries = BTreeMap::new();
    let mut dirs = BTreeSet::new();
    for entry in archive.entries().context("reading data.tar")? {
        let mut entry = entry.context("reading data.tar entry")?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_symlink() && !kind.is_hard_link() && !kind.is_dir() {
            continue;
        }
        let raw = entry
            .path()
            .context("bad tar path")?
            .to_string_lossy()
            .into_owned();
        // tar-slip: traversal/absolute paths must not reach output entry names.
        let path = match canonicalise(&raw) {
            Some(p) if p.is_empty() => continue,
            Some(p) if crate::archive::is_safe_entry_name(&p) => p,
            _ => {
                eprintln!("warning: skipping unsafe .deb payload path: {raw}");
                continue;
            }
        };
        if kind.is_dir() {
            dirs.insert(path);
            continue;
        }
        if kind.is_file() {
            let mut data = Vec::new();
            entry.read_to_end(&mut data).context("reading tar file")?;
            entries.insert(path, Entry::File(data));
            continue;
        }
        let Some(target) = entry.link_name().ok().flatten() else {
            continue;
        };
        let target = target.to_string_lossy();
        let resolved = if kind.is_hard_link() {
            canonicalise(&target)
        } else {
            link_target(&path, &target)
        };
        match resolved {
            Some(t) => {
                entries.insert(path, Entry::Symlink(t));
            }
            None => eprintln!("warning: skipping .deb link {path} -> {target} (escapes payload)"),
        }
    }
    Ok(Payload { entries, dirs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tar_of(entries: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, link, body) in entries {
            let mut header = tar::Header::new_gnu();
            match link {
                Some(target) => {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    header.set_link_name(target).unwrap();
                }
                None if path.ends_with('/') => {
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_size(0);
                }
                None => {
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(body.len() as u64);
                }
            }
            header.set_mode(0o755);
            header.set_path(path).unwrap();
            header.set_cksum();
            let payload: &[u8] = if header.entry_type().is_file() {
                body
            } else {
                &[]
            };
            builder.append(&header, payload).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn deb_of(member: &str, data: &[u8]) -> Vec<u8> {
        deb_with(&[(member, data)])
    }

    fn deb_with(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut deb = Vec::new();
        let mut builder = ar::Builder::new(&mut deb);
        let bin = b"2.0\n";
        builder
            .append(
                &ar::Header::new(b"debian-binary".to_vec(), bin.len() as u64),
                &bin[..],
            )
            .unwrap();
        for (member, data) in members {
            builder
                .append(
                    &ar::Header::new(member.as_bytes().to_vec(), data.len() as u64),
                    *data,
                )
                .unwrap();
        }
        builder.into_inner().unwrap();
        deb
    }

    fn gzipped(tar: &[u8]) -> Vec<u8> {
        let mut gz = Vec::new();
        flate2::read::GzEncoder::new(Cursor::new(tar), flate2::Compression::default())
            .read_to_end(&mut gz)
            .unwrap();
        gz
    }

    fn zstd_raw_frame(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x28, 0xb5, 0x2f, 0xfd];
        // Single_Segment, 8-byte Frame_Content_Size, no checksum, no dict.
        out.push(0xe0);
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let mut chunks = data.chunks(0x8000).peekable();
        if chunks.peek().is_none() {
            out.extend_from_slice(&[0x01, 0x00, 0x00]);
        }
        while let Some(chunk) = chunks.next() {
            let last = u32::from(chunks.peek().is_none());
            // Block_Header: size << 3 | type(0 = Raw) << 1 | last, 24-bit LE.
            let header = ((chunk.len() as u32) << 3) | last;
            out.extend_from_slice(&header.to_le_bytes()[..3]);
            out.extend_from_slice(chunk);
        }
        out
    }

    fn file(payload: &Payload, path: &str) -> Vec<u8> {
        match payload.resolve(path) {
            Resolved::File(_, data) => data.to_vec(),
            _ => panic!("{path} did not resolve to a file"),
        }
    }

    #[test]
    fn extracts_gz_payload() {
        let tar = tar_of(&[(
            "Library/MobileSubstrate/DynamicLibraries/T.dylib",
            None,
            b"hello dylib",
        )]);
        let payload = extract_payload(&deb_of("data.tar.gz", &gzipped(&tar))).unwrap();
        assert_eq!(payload.iter().count(), 1);
        assert_eq!(
            file(&payload, "Library/MobileSubstrate/DynamicLibraries/T.dylib"),
            b"hello dylib"
        );
    }

    #[test]
    fn extracts_zst_payload() {
        let tar = tar_of(&[("Library/Frameworks/A.framework/A", None, b"framework bytes")]);
        let payload = extract_payload(&deb_of("data.tar.zst", &zstd_raw_frame(&tar))).unwrap();
        assert_eq!(
            file(&payload, "Library/Frameworks/A.framework/A"),
            b"framework bytes"
        );
    }

    #[test]
    fn zstd_payload_respects_the_size_cap() {
        let mut w = CappedWriter {
            buf: Vec::new(),
            limit: 8,
        };
        let frame = zstd_raw_frame(&[7u8; 64]);
        let mut dec = ruzstd::StreamingDecoder::new(Cursor::new(&frame[..])).unwrap();
        assert!(std::io::copy(&mut dec, &mut w).is_err());
    }

    #[test]
    fn rootless_prefix_normalises_to_the_rootful_layout() {
        let rootful = tar_of(&[
            ("./usr/lib/libellekit.dylib", None, b"ELLE"),
            (
                "./Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                Some("/usr/lib/libellekit.dylib"),
                b"",
            ),
        ]);
        let rootless = tar_of(&[
            ("./var/jb/usr/lib/libellekit.dylib", None, b"ELLE"),
            (
                "./var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                Some("/var/jb/usr/lib/libellekit.dylib"),
                b"",
            ),
        ]);
        for tar in [rootful, rootless] {
            let payload = extract_payload(&deb_of("data.tar.gz", &gzipped(&tar))).unwrap();
            let paths: Vec<&str> = payload.iter().map(|(p, _)| p).collect();
            assert_eq!(
                paths,
                [
                    "Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                    "usr/lib/libellekit.dylib",
                ]
            );
            assert_eq!(
                file(
                    &payload,
                    "Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"
                ),
                b"ELLE"
            );
        }
    }

    #[test]
    fn strips_other_rootless_prefixes() {
        assert_eq!(canonicalise("./var/LIB/Library/x").unwrap(), "Library/x");
        assert_eq!(
            canonicalise("/var/containers/Bundle/Application/.jbroot-A1B2C3D4E5F60718/Library/x")
                .unwrap(),
            "Library/x"
        );
        assert_eq!(canonicalise("./Library/./a/../b").unwrap(), "Library/b");
        assert_eq!(canonicalise("../escape"), None);
    }

    #[test]
    fn follows_relative_and_chained_links() {
        let tar = tar_of(&[
            ("usr/lib/Cephei.framework/Cephei", None, b"CEPHEI"),
            (
                "Library/PreferenceBundles/Cephei.bundle",
                Some("/usr/lib/Cephei.framework"),
                b"",
            ),
            (
                "Library/PreferenceBundles/libhbangprefs.bundle",
                Some("Cephei.bundle"),
                b"",
            ),
        ]);
        let payload = extract_payload(&deb_of("data.tar.gz", &gzipped(&tar))).unwrap();
        let Resolved::Dir(items) =
            payload.resolve("Library/PreferenceBundles/libhbangprefs.bundle")
        else {
            panic!("chained link to a directory must expand");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "Cephei");
        assert_eq!(items[0].1, "usr/lib/Cephei.framework/Cephei");
        assert_eq!(items[0].2, b"CEPHEI");
    }

    #[test]
    fn link_to_an_empty_directory_is_not_dangling() {
        let tar = tar_of(&[
            ("./var/jb/usr/lib/TweakInject/", None, b""),
            (
                "./var/jb/Library/MobileSubstrate/DynamicLibraries",
                Some("/var/jb/usr/lib/TweakInject"),
                b"",
            ),
        ]);
        let payload = extract_payload(&deb_of("data.tar.gz", &gzipped(&tar))).unwrap();
        let Resolved::Dir(items) = payload.resolve("Library/MobileSubstrate/DynamicLibraries")
        else {
            panic!("an empty directory must resolve as a directory");
        };
        assert!(items.is_empty());
    }

    #[test]
    fn dangling_and_looping_links_resolve_to_dangling() {
        let tar = tar_of(&[
            ("Library/A.dylib", Some("/usr/lib/gone.dylib"), b""),
            ("Library/loop1", Some("loop2"), b""),
            ("Library/loop2", Some("loop1"), b""),
        ]);
        let payload = extract_payload(&deb_of("data.tar.gz", &gzipped(&tar))).unwrap();
        assert!(matches!(
            payload.resolve("Library/A.dylib"),
            Resolved::Dangling
        ));
        assert!(matches!(
            payload.resolve("Library/loop1"),
            Resolved::Dangling
        ));
    }

    #[test]
    fn capped_writer_stops_at_limit() {
        let mut w = CappedWriter {
            buf: Vec::new(),
            limit: 10,
        };
        assert!(w.write_all(b"0123456789").is_ok());
        assert!(w.write_all(b"x").is_err(), "must reject bytes past the cap");
        assert_eq!(w.buf.len(), 10);
    }

    #[test]
    fn errors_on_non_deb() {
        assert!(extract_payload(b"not an ar archive at all").is_err());
    }

    #[test]
    fn parses_a_control_stanza() {
        let text = "Package: ws.hbang.common\n\
                    Version: 2.0\n\
                    Depends: mobilesubstrate,\n \
                    firmware (<< 8.0) | firmware (>= 11.0) | com.rpetrich.rocketbootstrap,\n \
                    ws.hbang.common (>= 2.0)\n\
                    Provides: mobilesubstrate (= 99), org.coolstar.libhooker (= 1.6.9)\n\
                    Conflicts: com.den.twigalaxy, xyz.cypwn.twigalaxy\n\
                    Description: a tweak\n \
                    continued prose\n";
        let c = parse_control(text).unwrap();
        assert_eq!(c.package, "ws.hbang.common");
        assert_eq!(c.version.as_deref(), Some("2.0"));
        assert_eq!(c.provides, ["mobilesubstrate", "org.coolstar.libhooker"]);
        assert_eq!(c.conflicts, ["com.den.twigalaxy", "xyz.cypwn.twigalaxy"]);

        let terms: Vec<String> = c.depends.iter().map(Dependency::to_string).collect();
        assert_eq!(
            terms,
            [
                "mobilesubstrate",
                "firmware | firmware | com.rpetrich.rocketbootstrap",
                "ws.hbang.common"
            ]
        );
        assert_eq!(
            c.depends[2].alternatives[0].constraint.as_deref(),
            Some(">= 2.0"),
            "the constraint is kept, though patina never enforces it"
        );
    }

    #[test]
    fn rejects_a_control_without_a_package_field() {
        assert!(parse_control("Version: 1.0\n").is_err());
    }

    #[test]
    fn reads_a_zst_control_member() {
        let control = tar_of(&[(
            "./control",
            None,
            b"Package: ellekit\nProvides: mobilesubstrate (= 99)\n",
        )]);
        let data = tar_of(&[("usr/lib/libellekit.dylib", None, b"ELLE")]);
        let deb = deb_with(&[
            ("control.tar.zst", &zstd_raw_frame(&control)),
            ("data.tar.zst", &zstd_raw_frame(&data)),
        ]);
        let unpacked = read(&deb).unwrap();
        let control = unpacked.control.unwrap();
        assert_eq!(control.package, "ellekit");
        assert_eq!(control.provides, ["mobilesubstrate"]);
        assert_eq!(read_control(&deb).unwrap().package, "ellekit");
        assert_eq!(file(&unpacked.payload, "usr/lib/libellekit.dylib"), b"ELLE");
    }

    #[test]
    fn a_deb_without_a_control_member_has_no_control() {
        let tar = tar_of(&[("usr/lib/x.dylib", None, b"x")]);
        let unpacked = read(&deb_of("data.tar.gz", &gzipped(&tar))).unwrap();
        assert!(unpacked.control.is_none());
        assert!(read_control(&deb_of("data.tar.gz", &gzipped(&tar))).is_err());
    }
}

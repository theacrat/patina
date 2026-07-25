//! Pure-Rust ad-hoc Mach-O code signing, byte-compatible with
//! `apple-codesign`'s `MachOSigner`. Must run *after* all Mach-O edits — the
//! CodeDirectory hashes the load commands.

use anyhow::{Context, Result, bail};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

use crate::macho::{
    FAT_MAGIC, FAT_MAGIC_64, LC_CODE_SIGNATURE, LC_SEGMENT_64, MH_MAGIC_64, cstr, fat, fat_arch,
    lc, linkedit, mh, r32, r64, rb32, rb64, seg64, w32, w64,
};

const MH_EXECUTE: u32 = 0x2;

const MAGIC_REQUIREMENT_SET: u32 = 0xfade_0c01;
const MAGIC_CODE_DIRECTORY: u32 = 0xfade_0c02;
const MAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const MAGIC_ENTITLEMENTS: u32 = 0xfade_7171;
const MAGIC_ENTITLEMENTS_DER: u32 = 0xfade_7172;
const MAGIC_BLOB_WRAPPER: u32 = 0xfade_0b01;

const SLOT_CODE_DIRECTORY: u32 = 0;
const SLOT_INFO_PLIST: u32 = 1;
const SLOT_REQUIREMENT_SET: u32 = 2;
const SLOT_RESOURCE_DIR: u32 = 3;
const SLOT_ENTITLEMENTS: u32 = 5;
const SLOT_ENTITLEMENTS_DER: u32 = 7;
const SLOT_SIGNATURE: u32 = 0x10000;

const CD_VERSION_EXEC_SEG: u32 = 0x0002_0400;
const FLAG_ADHOC: u32 = 0x0002;
const DIGEST_TYPE_SHA256: u8 = 2;
const DIGEST_LEN: usize = 32;
const PAGE_SIZE: usize = 4096;

const EXEC_SEG_MAIN_BINARY: u64 = 0x0001;
const EXEC_SEG_ALLOW_UNSIGNED: u64 = 0x0010;
const EXEC_SEG_DEBUGGER: u64 = 0x0020;
const EXEC_SEG_JIT: u64 = 0x0040;
const EXEC_SEG_SKIP_LIBRARY_VALIDATION: u64 = 0x0080;
const EXEC_SEG_CAN_LOAD_CD_HASH: u64 = 0x0100;
const EXEC_SEG_CAN_EXEC_CD_HASH: u64 = 0x0200;

const SIZEOF_LINKEDIT_DATA_COMMAND: usize = 16;

pub struct MultiDigest {
    pub sha1: Vec<u8>,
    pub sha256: Vec<u8>,
}

pub fn multi_digest(data: &[u8]) -> MultiDigest {
    MultiDigest {
        sha1: sha1(data),
        sha256: sha256(data),
    }
}

pub fn sha1(data: &[u8]) -> Vec<u8> {
    Sha1::digest(data).to_vec()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

#[derive(Default)]
pub struct SealOptions<'a> {
    pub entitlements_xml: Option<&'a str>,
    pub info_plist: Option<&'a [u8]>,
    pub code_resources: Option<&'a [u8]>,
}

/// Entitlements are embedded as both XML and DER.
pub fn adhoc_sign(
    macho: &[u8],
    identifier: &str,
    entitlements_xml: Option<&str>,
) -> Result<Vec<u8>> {
    adhoc_sign_sealing(
        macho,
        identifier,
        &SealOptions {
            entitlements_xml,
            ..Default::default()
        },
    )
}

pub fn adhoc_sign_sealing(macho: &[u8], identifier: &str, seal: &SealOptions) -> Result<Vec<u8>> {
    let entitlements = match seal.entitlements_xml {
        Some(xml) => {
            let value = plist::Value::from_reader_xml(std::io::Cursor::new(xml.as_bytes()))
                .context("invalid entitlements XML")?;
            check_der_encodable(&value)?;
            Some(value)
        }
        None => None,
    };

    let slices = match kind(macho) {
        Kind::Thin => vec![macho.to_vec()],
        Kind::Fat(is64) => fat_slices(macho, is64)?,
        Kind::Other => bail!("not a recognised Mach-O (bad magic)"),
    };

    let signed = slices
        .iter()
        .map(|s| sign_thin(s, identifier, entitlements.as_ref(), seal))
        .collect::<Result<Vec<_>>>()?;

    // A single-slice universal container degrades to a thin binary, matching apple-codesign.
    if signed.len() > 1 {
        Ok(build_universal(&signed))
    } else {
        signed
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Mach-O contains no signable slices"))
    }
}

pub fn has_code_directory(macho: &[u8]) -> bool {
    first_slice(macho)
        .and_then(|s| signature_blob(&s, SLOT_CODE_DIRECTORY).map(|_| ()))
        .is_some()
}

/// SHA-256 of the CodeDirectory blob, truncated to 20 bytes (as used in CodeResources files2).
pub fn cdhash(macho: &[u8]) -> Result<Vec<u8>> {
    cdhashes(macho)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Mach-O contains no signed slices"))
}

pub fn cdhashes(macho: &[u8]) -> Result<Vec<Vec<u8>>> {
    let slices = match kind(macho) {
        Kind::Thin => vec![macho.to_vec()],
        Kind::Fat(is64) => fat_slices(macho, is64)?,
        Kind::Other => bail!("not a recognised Mach-O (bad magic)"),
    };
    slices
        .iter()
        .map(|s| {
            let cd = signature_blob(s, SLOT_CODE_DIRECTORY)
                .ok_or_else(|| anyhow::anyhow!("Mach-O has no CodeDirectory"))?;
            let mut h = sha256(&cd);
            h.truncate(20);
            Ok(h)
        })
        .collect()
}

pub fn embedded_entitlements(macho: &[u8]) -> Option<String> {
    let slice = first_slice(macho)?;
    let blob = signature_blob(&slice, SLOT_ENTITLEMENTS)?;
    String::from_utf8(blob[8..].to_vec()).ok()
}

enum Kind {
    Thin,
    Fat(bool),
    Other,
}

fn kind(buf: &[u8]) -> Kind {
    if buf.len() < 4 {
        return Kind::Other;
    }
    match rb32(buf, 0) {
        FAT_MAGIC => Kind::Fat(false),
        FAT_MAGIC_64 => Kind::Fat(true),
        _ if r32(buf, 0) == MH_MAGIC_64 => Kind::Thin,
        _ => Kind::Other,
    }
}

fn fat_slices(buf: &[u8], is64: bool) -> Result<Vec<Vec<u8>>> {
    let stride = if is64 {
        fat_arch::STRIDE64
    } else {
        fat_arch::STRIDE32
    };
    let n = rb32(buf, fat::NARCH) as usize;
    n.checked_mul(stride)
        .and_then(|x| x.checked_add(fat::ARCHS))
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| anyhow::anyhow!("truncated or malformed fat header"))?;

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let base = fat::ARCHS + i * stride;
        let (off, size) = if is64 {
            (
                rb64(buf, base + fat_arch::OFFSET) as usize,
                rb64(buf, base + fat_arch::SIZE64) as usize,
            )
        } else {
            (
                rb32(buf, base + fat_arch::OFFSET) as usize,
                rb32(buf, base + fat_arch::SIZE32) as usize,
            )
        };
        if off > buf.len() || size > buf.len() - off {
            bail!("fat arch slice out of bounds");
        }
        let slice = &buf[off..off + size];
        if matches!(kind(slice), Kind::Thin) {
            out.push(slice.to_vec());
        }
    }
    Ok(out)
}

fn first_slice(buf: &[u8]) -> Option<Vec<u8>> {
    match kind(buf) {
        Kind::Thin => Some(buf.to_vec()),
        Kind::Fat(is64) => fat_slices(buf, is64).ok()?.into_iter().next(),
        Kind::Other => None,
    }
}

/// Always a 32-bit fat header with fixed 2^14 alignment, matching `apple-codesign`.
fn build_universal(binaries: &[Vec<u8>]) -> Vec<u8> {
    const ALIGN_LOG2: u32 = 14;
    let align = 1usize << ALIGN_LOG2;

    let mut offsets = Vec::with_capacity(binaries.len());
    let mut cursor = align;
    for b in binaries {
        cursor += (align - cursor % align) % align;
        offsets.push(cursor);
        cursor += b.len();
    }

    let mut out = Vec::with_capacity(cursor);
    out.extend_from_slice(&FAT_MAGIC.to_be_bytes());
    out.extend_from_slice(&(binaries.len() as u32).to_be_bytes());
    for (b, &off) in binaries.iter().zip(&offsets) {
        out.extend_from_slice(&r32(b, 4).to_be_bytes()); // cputype
        out.extend_from_slice(&r32(b, 8).to_be_bytes()); // cpusubtype
        out.extend_from_slice(&(off as u32).to_be_bytes());
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(&ALIGN_LOG2.to_be_bytes());
    }
    out.resize(align - out.len() % align + out.len(), 0);
    for (b, &off) in binaries.iter().zip(&offsets) {
        out.resize(off, 0);
        out.extend_from_slice(b);
    }
    out
}

struct Thin<'a> {
    data: &'a [u8],
    filetype: u32,
    lcs: Vec<(usize, usize)>,
    has_sig_lc: bool,
    /// (fileoff, filesize) of `__LINKEDIT`.
    linkedit: (u64, u64),
    /// (fileoff, filesize) of `__TEXT`.
    text: (u64, u64),
    sig_off: Option<u64>,
}

fn parse(data: &[u8]) -> Result<Thin<'_>> {
    if data.len() < mh::SIZE || r32(data, 0) != MH_MAGIC_64 {
        bail!("not a 64-bit little-endian Mach-O");
    }
    let ncmds = r32(data, mh::NCMDS) as usize;
    let sizeofcmds = r32(data, mh::SIZEOFCMDS) as usize;
    if mh::SIZE + sizeofcmds > data.len() {
        bail!("load commands exceed file length");
    }

    let mut lcs = Vec::with_capacity(ncmds);
    let mut linkedit = None;
    let mut text = None;
    let mut sig_off = None;
    let mut has_sig_lc = false;

    let mut off = mh::SIZE;
    for _ in 0..ncmds {
        if off + 8 > data.len() {
            bail!("truncated load command");
        }
        let cmd = r32(data, off);
        let size = r32(data, off + lc::CMDSIZE) as usize;
        if size < 8 || off + size > data.len() {
            bail!("malformed load command (cmdsize {size})");
        }
        match cmd {
            LC_SEGMENT_64 if size >= seg64::SECTIONS => {
                let extent = (
                    r64(data, off + seg64::FILEOFF),
                    r64(data, off + seg64::FILESIZE),
                );
                match cstr(data, off + seg64::SEGNAME, seg64::SEGNAME_LEN).as_str() {
                    "__LINKEDIT" => linkedit = Some(extent),
                    "__TEXT" => text = Some(extent),
                    _ => {}
                }
            }
            LC_CODE_SIGNATURE if size >= SIZEOF_LINKEDIT_DATA_COMMAND => {
                has_sig_lc = true;
                sig_off = Some(r32(data, off + linkedit::DATAOFF) as u64);
            }
            _ => {}
        }
        lcs.push((off, size));
        off += size;
    }

    let linkedit = linkedit.ok_or_else(|| anyhow::anyhow!("Mach-O has no __LINKEDIT segment"))?;
    let text = text.ok_or_else(|| anyhow::anyhow!("Mach-O has no __TEXT segment"))?;

    Ok(Thin {
        data,
        filetype: r32(data, mh::FILETYPE),
        lcs,
        has_sig_lc,
        linkedit,
        text,
        sig_off,
    })
}

impl Thin<'_> {
    fn is_executable(&self) -> bool {
        self.filetype == MH_EXECUTE
    }

    /// Where code digests stop: the existing signature's start, else the end of `__LINKEDIT`.
    fn code_limit(&self) -> u64 {
        self.sig_off.unwrap_or(self.linkedit.0 + self.linkedit.1)
    }
}

fn sign_thin(
    data: &[u8],
    identifier: &str,
    entitlements: Option<&plist::Value>,
    seal: &SealOptions,
) -> Result<Vec<u8>> {
    let original = parse(data)?;
    let reserved = estimate_signature_size(&original, entitlements);

    // CodeDirectory digests load commands with the signature's size: splice over a zeroed placeholder.
    let intermediate = with_signature(&original, &vec![0u8; reserved])?;
    let parsed = parse(&intermediate)?;
    let sig_off = parsed
        .sig_off
        .expect("intermediate always carries a signature load command") as usize;

    let mut sig = build_superblob(&parsed, identifier, entitlements, seal)?;
    if sig.len() > reserved {
        bail!(
            "signature ({} bytes) exceeds reserved space ({reserved} bytes)",
            sig.len()
        );
    }
    sig.resize(reserved, 0);

    let mut out = intermediate;
    out[sig_off..sig_off + reserved].copy_from_slice(&sig);
    Ok(out)
}

/// Rewrites the header, load commands and `__LINKEDIT` so `sig` sits 16-byte aligned at the end.
fn with_signature(t: &Thin, sig: &[u8]) -> Result<Vec<u8>> {
    let code_limit = t.code_limit();
    let pad = ((16 - code_limit % 16) % 16) as usize;
    let sig_off = code_limit + pad as u64;

    let linkedit_start = t.linkedit.0 as usize;
    if code_limit as usize > t.data.len() || linkedit_start > code_limit as usize {
        bail!("__LINKEDIT extends beyond the file");
    }
    let linkedit_before = &t.data[linkedit_start..code_limit as usize];

    let new_filesize = (linkedit_before.len() + pad + sig.len()) as u64;
    let new_vmsize = new_filesize.div_ceil(16384) * 16384;

    let mut out = t.data[..mh::SIZE].to_vec();
    if !t.has_sig_lc {
        w32(&mut out, mh::NCMDS, r32(t.data, mh::NCMDS) + 1);
        w32(
            &mut out,
            mh::SIZEOFCMDS,
            r32(t.data, mh::SIZEOFCMDS) + SIZEOF_LINKEDIT_DATA_COMMAND as u32,
        );
    }

    for &(off, size) in &t.lcs {
        let mut c = t.data[off..off + size].to_vec();
        match r32(&c, 0) {
            LC_CODE_SIGNATURE => {
                w32(&mut c, linkedit::DATAOFF, sig_off as u32);
                w32(&mut c, linkedit::DATASIZE, sig.len() as u32);
            }
            LC_SEGMENT_64
                if size >= seg64::SECTIONS
                    && cstr(&c, seg64::SEGNAME, seg64::SEGNAME_LEN) == "__LINKEDIT" =>
            {
                w64(&mut c, seg64::FILESIZE, new_filesize);
                w64(&mut c, seg64::VMSIZE, new_vmsize);
            }
            _ => {}
        }
        out.extend_from_slice(&c);
    }

    if !t.has_sig_lc {
        let mut c = vec![0u8; SIZEOF_LINKEDIT_DATA_COMMAND];
        w32(&mut c, 0, LC_CODE_SIGNATURE);
        w32(&mut c, lc::CMDSIZE, SIZEOF_LINKEDIT_DATA_COMMAND as u32);
        w32(&mut c, linkedit::DATAOFF, sig_off as u32);
        w32(&mut c, linkedit::DATASIZE, sig.len() as u32);
        out.extend_from_slice(&c);
        if out.len() > linkedit_start {
            bail!("no room after the load commands for an LC_CODE_SIGNATURE");
        }
    }

    out.extend_from_slice(&t.data[out.len()..linkedit_start]);
    out.extend_from_slice(linkedit_before);
    out.resize(out.len() + pad, 0);
    out.extend_from_slice(sig);
    Ok(out)
}

/// Mirrors `apple-codesign`'s over-estimate; the reserved length is baked into the load commands.
fn estimate_signature_size(t: &Thin, entitlements: Option<&plist::Value>) -> usize {
    let mut size = 1024;
    size += (t.code_limit() as usize).div_ceil(PAGE_SIZE) * DIGEST_LEN;
    // The estimator always assumes an executable, so DER entitlements count even for dylibs.
    for (_, blob) in special_blobs(entitlements, true) {
        size += blob.len();
    }
    size += 4096;
    size + 1024 - size % 1024
}

fn special_blobs(entitlements: Option<&plist::Value>, is_executable: bool) -> Vec<(u32, Vec<u8>)> {
    let mut res = vec![(SLOT_REQUIREMENT_SET, blob(MAGIC_REQUIREMENT_SET, &[0; 4]))];

    if let Some(value) = entitlements {
        let mut xml = Vec::new();
        value
            .to_writer_xml(&mut xml)
            .expect("plist XML serialisation of an in-memory value cannot fail");
        res.push((SLOT_ENTITLEMENTS, blob(MAGIC_ENTITLEMENTS, &xml)));

        if is_executable {
            res.push((
                SLOT_ENTITLEMENTS_DER,
                blob(MAGIC_ENTITLEMENTS_DER, &der_encode_plist(value)),
            ));
        }
    }
    res
}

fn blob(magic: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 8);
    v.extend_from_slice(&magic.to_be_bytes());
    v.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn build_superblob(
    t: &Thin,
    identifier: &str,
    entitlements: Option<&plist::Value>,
    seal: &SealOptions,
) -> Result<Vec<u8>> {
    let mut blobs = special_blobs(entitlements, t.is_executable());

    // Info.plist and CodeResources live outside the superblob; only their digests are sealed.
    let mut specials: Vec<(u32, Vec<u8>)> = blobs.iter().map(|(s, b)| (*s, sha256(b))).collect();
    if let Some(data) = seal.info_plist {
        specials.push((SLOT_INFO_PLIST, sha256(data)));
    }
    if let Some(data) = seal.code_resources {
        specials.push((SLOT_RESOURCE_DIR, sha256(data)));
    }

    blobs.push((
        SLOT_CODE_DIRECTORY,
        code_directory(t, identifier, entitlements, &specials)?,
    ));
    blobs.push((SLOT_SIGNATURE, blob(MAGIC_BLOB_WRAPPER, &[])));
    blobs.sort_by_key(|(slot, _)| *slot);

    let mut total = 12 + 8 * blobs.len() as u32;
    let mut index = Vec::new();
    for (slot, data) in &blobs {
        index.extend_from_slice(&slot.to_be_bytes());
        index.extend_from_slice(&total.to_be_bytes());
        total += data.len() as u32;
    }

    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&MAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&(blobs.len() as u32).to_be_bytes());
    out.extend_from_slice(&index);
    for (_, data) in &blobs {
        out.extend_from_slice(data);
    }
    Ok(out)
}

fn code_directory(
    t: &Thin,
    identifier: &str,
    entitlements: Option<&plist::Value>,
    specials: &[(u32, Vec<u8>)], // (slot, digest)
) -> Result<Vec<u8>> {
    let code_limit = t.code_limit();
    let (code_limit_32, code_limit_64) = if code_limit > u32::MAX as u64 {
        (0, code_limit)
    } else {
        (code_limit as u32, 0)
    };

    let exec_seg_flags = if t.is_executable() {
        EXEC_SEG_MAIN_BINARY | entitlements.map(exec_seg_flags).unwrap_or(0)
    } else {
        0
    };

    let highest_slot = specials.iter().map(|(s, _)| *s).max().unwrap_or(0);
    let code_slots = (code_limit as usize).div_ceil(PAGE_SIZE);

    let ident_offset = 8 + 80;
    let specials_offset = ident_offset + identifier.len() + 1;
    let digest_offset = specials_offset + highest_slot as usize * DIGEST_LEN;

    let mut p = Vec::new();
    p.extend_from_slice(&CD_VERSION_EXEC_SEG.to_be_bytes());
    p.extend_from_slice(&FLAG_ADHOC.to_be_bytes());
    p.extend_from_slice(&(digest_offset as u32).to_be_bytes());
    p.extend_from_slice(&(ident_offset as u32).to_be_bytes());
    p.extend_from_slice(&highest_slot.to_be_bytes());
    p.extend_from_slice(&(code_slots as u32).to_be_bytes());
    p.extend_from_slice(&code_limit_32.to_be_bytes());
    p.push(DIGEST_LEN as u8);
    p.push(DIGEST_TYPE_SHA256);
    p.push(0); // platform
    p.push(PAGE_SIZE.trailing_zeros() as u8);
    p.extend_from_slice(&0u32.to_be_bytes()); // spare2
    p.extend_from_slice(&0u32.to_be_bytes()); // scatterOffset
    p.extend_from_slice(&0u32.to_be_bytes()); // teamOffset
    p.extend_from_slice(&0u32.to_be_bytes()); // spare3
    p.extend_from_slice(&code_limit_64.to_be_bytes());
    p.extend_from_slice(&t.text.0.to_be_bytes());
    p.extend_from_slice(&(t.text.0 + t.text.1).to_be_bytes());
    p.extend_from_slice(&exec_seg_flags.to_be_bytes());
    debug_assert_eq!(p.len(), 80);

    p.extend_from_slice(identifier.as_bytes());
    p.push(0);

    // Special slots are stored in reverse index order before the code slots; absent slots are zeroed.
    for slot in (1..=highest_slot).rev() {
        match specials.iter().find(|(s, _)| *s == slot) {
            Some((_, digest)) => p.extend_from_slice(digest),
            None => p.extend_from_slice(&[0u8; DIGEST_LEN]),
        }
    }

    let code = &t.data[..code_limit as usize];
    for chunk in code.chunks(PAGE_SIZE) {
        p.extend_from_slice(&sha256(chunk));
    }

    Ok(blob(MAGIC_CODE_DIRECTORY, &p))
}

fn exec_seg_flags(value: &plist::Value) -> u64 {
    let plist::Value::Dictionary(d) = value else {
        return 0;
    };
    let yes = |k: &str| matches!(d.get(k), Some(plist::Value::Boolean(true)));

    let mut flags = 0;
    if yes("get-task-allow") || yes("run-unsigned-code") {
        flags |= EXEC_SEG_ALLOW_UNSIGNED;
    }
    if yes("com.apple.private.cs.debugger") {
        flags |= EXEC_SEG_DEBUGGER;
    }
    if yes("dynamic-codesigning") {
        flags |= EXEC_SEG_JIT;
    }
    if yes("com.apple.private.skip-library-validation") {
        flags |= EXEC_SEG_SKIP_LIBRARY_VALIDATION;
    }
    if yes("com.apple.private.amfi.can-load-cdhash") {
        flags |= EXEC_SEG_CAN_LOAD_CD_HASH;
    }
    if yes("com.apple.private.amfi.can-execute-cdhash") {
        flags |= EXEC_SEG_CAN_EXEC_CD_HASH;
    }
    flags
}

/// Apple's DER plist: `[APPLICATION 16] { INTEGER 1, value }`, where a
/// dictionary is `[CONTEXT 16]` of `SEQUENCE { UTF8String key, value }` sorted
/// by key, and an array is a plain `SEQUENCE OF`.
fn der_encode_plist(value: &plist::Value) -> Vec<u8> {
    let mut body = der_tlv(0x02, &[1]);
    body.extend(der_value(value));
    der_tlv(0x70, &body)
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let bytes = n.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        v.push(0x80 | (bytes.len() - start) as u8);
        v.extend_from_slice(&bytes[start..]);
    }
    v.extend_from_slice(content);
    v
}

fn der_value(value: &plist::Value) -> Vec<u8> {
    match value {
        plist::Value::Dictionary(d) => {
            let mut keys: Vec<&String> = d.keys().collect();
            keys.sort();
            let mut content = Vec::new();
            for k in keys {
                let mut entry = der_tlv(0x0c, k.as_bytes());
                entry.extend(der_value(&d[k]));
                content.extend(der_tlv(0x30, &entry));
            }
            der_tlv(0xb0, &content)
        }
        plist::Value::Array(a) => {
            let content: Vec<u8> = a.iter().flat_map(der_value).collect();
            der_tlv(0x30, &content)
        }
        plist::Value::Boolean(b) => der_tlv(0x01, &[if *b { 0xff } else { 0x00 }]),
        plist::Value::Integer(i) => der_tlv(0x02, &der_int(i.as_signed().unwrap_or(0))),
        plist::Value::String(s) => der_tlv(0x0c, s.as_bytes()),
        _ => unreachable!("rejected by check_der_encodable"),
    }
}

fn check_der_encodable(value: &plist::Value) -> Result<()> {
    match value {
        plist::Value::Dictionary(d) => d.values().try_for_each(check_der_encodable),
        plist::Value::Array(a) => a.iter().try_for_each(check_der_encodable),
        plist::Value::Boolean(_) | plist::Value::String(_) => Ok(()),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(|_| ())
            .ok_or_else(|| anyhow::anyhow!("entitlements integer is out of range for DER")),
        other => bail!("entitlements value {other:?} cannot be DER encoded"),
    }
}

fn der_int(v: i64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let mut i = 0;
    while i < 7 && ((b[i] == 0 && b[i + 1] < 0x80) || (b[i] == 0xff && b[i + 1] >= 0x80)) {
        i += 1;
    }
    b[i..].to_vec()
}

/// Full blob bytes for `slot`, header included.
fn signature_blob(data: &[u8], slot: u32) -> Option<Vec<u8>> {
    let t = parse(data).ok()?;
    let start = t.sig_off? as usize;
    let sb = data.get(start..)?;
    if sb.len() < 12 || u32::from_be_bytes(sb[0..4].try_into().ok()?) != MAGIC_EMBEDDED_SIGNATURE {
        return None;
    }
    let count = u32::from_be_bytes(sb[8..12].try_into().ok()?) as usize;
    for i in 0..count {
        let e = 12 + i * 8;
        let entry = sb.get(e..e + 8)?;
        if u32::from_be_bytes(entry[0..4].try_into().ok()?) != slot {
            continue;
        }
        let off = u32::from_be_bytes(entry[4..8].try_into().ok()?) as usize;
        let header = sb.get(off..off + 8)?;
        let len = u32::from_be_bytes(header[4..8].try_into().ok()?) as usize;
        return sb.get(off..off + len).map(<[u8]>::to_vec);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use apple_codesign::{MachOSigner, SettingsScope, SigningSettings};
    use std::path::Path;
    use std::process::Command;

    const FIX: &str = "/tmp/patina-fixtures";
    const FIXTURES: [&str; 3] = ["main_arm64", "main_arm64_norpath", "libinject.dylib"];

    const ENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>get-task-allow</key><true/>
<key>application-identifier</key><string>ABCDE12345.com.example.fake</string>
<key>keychain-access-groups</key><array><string>ABCDE12345.*</string></array>
<key>com.example.count</key><integer>7</integer>
</dict></plist>"#;

    fn load(name: &str) -> Option<Vec<u8>> {
        let p = format!("{FIX}/{name}");
        if Path::new(&p).exists() {
            Some(std::fs::read(p).unwrap())
        } else {
            eprintln!("SKIP: fixture {p} not present");
            None
        }
    }

    fn oracle(bin: &[u8], identifier: &str, ent: Option<&str>) -> Vec<u8> {
        let mut settings = SigningSettings::default();
        settings.set_binary_identifier(SettingsScope::Main, identifier);
        if let Some(xml) = ent {
            settings
                .set_entitlements_xml(SettingsScope::Main, xml)
                .unwrap();
        }
        let signer = MachOSigner::new(bin).unwrap();
        let mut out = Vec::new();
        signer.write_signed_binary(&settings, &mut out).unwrap();
        out
    }

    fn assert_identical(ours: &[u8], theirs: &[u8], what: &str) {
        if ours == theirs {
            return;
        }
        let at = ours
            .iter()
            .zip(theirs)
            .position(|(a, b)| a != b)
            .unwrap_or(ours.len().min(theirs.len()));
        let lo = at.saturating_sub(32);
        let hi = (at + 32).min(ours.len().min(theirs.len()));
        panic!(
            "{what}: output differs (ours {} bytes, apple-codesign {} bytes)\n\
             first difference at 0x{at:x}\n  ours: {}\ntheirs: {}",
            ours.len(),
            theirs.len(),
            hex(&ours[lo..hi]),
            hex(&theirs[lo..hi]),
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn byte_identical_to_apple_codesign() {
        for name in FIXTURES {
            let Some(bin) = load(name) else { continue };
            for (label, ent) in [("no-entitlements", None), ("entitlements", Some(ENT))] {
                let ours = adhoc_sign(&bin, "com.example.fake", ent).unwrap();
                let theirs = oracle(&bin, "com.example.fake", ent);
                assert_identical(&ours, &theirs, &format!("{name} / {label}"));
            }
        }
    }

    #[test]
    fn byte_identical_for_fat_binaries() {
        let Some(a) = load("main_arm64") else { return };
        let Some(b) = load("main_arm64_norpath") else {
            return;
        };
        let fat = super::build_universal(&[a, b]);
        for (label, ent) in [("no-entitlements", None), ("entitlements", Some(ENT))] {
            let ours = adhoc_sign(&fat, "com.example.fake", ent).unwrap();
            let theirs = oracle(&fat, "com.example.fake", ent);
            assert_identical(&ours, &theirs, &format!("fat / {label}"));
        }
    }

    #[test]
    fn byte_identical_without_an_existing_signature() {
        for name in FIXTURES {
            let Some(bin) = load(name) else { continue };
            let stripped = crate::macho::strip_code_signature(&bin).unwrap();
            assert!(!has_code_directory(&stripped), "{name}: strip failed");

            for (label, ent) in [("no-entitlements", None), ("entitlements", Some(ENT))] {
                let ours = adhoc_sign(&stripped, "com.example.fake", ent).unwrap();
                let theirs = oracle(&stripped, "com.example.fake", ent);
                assert_identical(&ours, &theirs, &format!("{name} stripped / {label}"));
            }
            objdump_clean(&adhoc_sign(&stripped, "com.example.fake", None).unwrap());
        }
    }

    #[test]
    fn round_trip_metadata() {
        for name in FIXTURES {
            let Some(bin) = load(name) else { continue };
            let signed = adhoc_sign(&bin, "com.example.fake", Some(ENT)).unwrap();

            assert!(has_code_directory(&signed), "{name}: no CodeDirectory");

            let parsed = apple_codesign::MachOBinary::parse(&signed).unwrap();
            let sig = parsed.code_signature().unwrap().expect("signature present");
            let cd = sig.code_directory().unwrap().expect("code directory");
            let mut expected = {
                use apple_codesign::embedded_signature::Blob;
                cd.digest_with(apple_codesign::cryptography::DigestType::Sha256)
                    .unwrap()
            };
            expected.truncate(20);
            assert_eq!(
                cdhash(&signed).unwrap(),
                expected,
                "{name}: cdhash mismatch"
            );

            let ent = embedded_entitlements(&signed).expect("entitlements present");
            assert!(
                ent.contains("get-task-allow"),
                "{name}: entitlements missing key"
            );
            assert_eq!(
                ent,
                sig.entitlements().unwrap().unwrap().as_str(),
                "{name}: entitlements text mismatch"
            );

            assert!(embedded_entitlements(&bin).is_none() || !bin.is_empty());
        }
    }

    #[test]
    fn resigning_replaces_cleanly() {
        for name in FIXTURES {
            let Some(bin) = load(name) else { continue };
            let once = adhoc_sign(&bin, "com.example.fake", None).unwrap();
            let twice = adhoc_sign(&once, "com.example.fake", None).unwrap();
            assert_eq!(once, twice, "{name}: re-signing must be idempotent");

            let relabelled = adhoc_sign(&once, "com.example.other", None).unwrap();
            assert_identical(
                &relabelled,
                &oracle(&once, "com.example.other", None),
                &format!("{name} / re-signed"),
            );
        }
    }

    #[test]
    fn output_is_well_formed() {
        for name in FIXTURES {
            let Some(bin) = load(name) else { continue };
            objdump_clean(&adhoc_sign(&bin, "com.example.fake", Some(ENT)).unwrap());
        }
    }

    #[test]
    fn der_matches_apple_vectors() {
        let dict = |pairs: Vec<(&str, plist::Value)>| {
            let mut d = plist::Dictionary::new();
            for (k, v) in pairs {
                d.insert(k.to_string(), v);
            }
            plist::Value::Dictionary(d)
        };

        assert_eq!(
            der_encode_plist(&dict(vec![])),
            vec![112, 5, 2, 1, 1, 176, 0]
        );
        assert_eq!(
            der_encode_plist(&dict(vec![("key", plist::Value::Boolean(true))])),
            vec![
                112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 1, 1, 255
            ]
        );
        assert_eq!(
            der_encode_plist(&dict(vec![("key", plist::Value::Integer((-1).into()))])),
            vec![
                112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 2, 1, 255
            ]
        );
        assert_eq!(
            der_encode_plist(&dict(vec![(
                "key",
                plist::Value::Array(vec![plist::Value::Boolean(true), "foo".into()])
            )])),
            vec![
                112, 22, 2, 1, 1, 176, 17, 48, 15, 12, 3, 107, 101, 121, 48, 8, 1, 1, 255, 12, 3,
                102, 111, 111
            ]
        );
        assert_eq!(
            der_encode_plist(&dict(vec![
                ("key", plist::Value::Boolean(false)),
                ("key3", plist::Value::Integer(42.into())),
                ("key2", plist::Value::Boolean(true)),
            ])),
            vec![
                112, 37, 2, 1, 1, 176, 32, 48, 8, 12, 3, 107, 101, 121, 1, 1, 0, 48, 9, 12, 4, 107,
                101, 121, 50, 1, 1, 255, 48, 9, 12, 4, 107, 101, 121, 51, 2, 1, 42
            ]
        );
    }

    fn objdump_clean(buf: &[u8]) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "patina-cs-{}-{}.bin",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, buf).unwrap();
        let out = match Command::new("llvm-objdump")
            .args(["--macho", "--all-headers"])
            .arg(&path)
            .output()
        {
            Ok(o) => o,
            Err(_) => {
                eprintln!("SKIP objdump: llvm-objdump not found");
                let _ = std::fs::remove_file(&path);
                return;
            }
        };
        let _ = std::fs::remove_file(&path);
        let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
        assert!(out.status.success(), "objdump exit != 0: {stderr}");
        assert!(
            !stderr.contains("malformed") && !stderr.contains("truncated"),
            "objdump reported problems: {stderr}"
        );
    }
}

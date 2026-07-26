//! Mach-O load-command surgery via manual byte splicing.
//! In-place when the header cave fits, else a forced page shift.
//! Little-endian 64-bit only.

use anyhow::{Context, Result, bail};
use goblin::mach::MachO;

const PAGE: u64 = 0x4000; // arm64 = 16 KiB

const LC_REQ_DYLD: u32 = 0x8000_0000;
pub(crate) const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
pub(crate) const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
const LC_ATOM_INFO: u32 = 0x36;
const LC_NOTE: u32 = 0x31;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const ENCRYPTION_CRYPTOFF: usize = 8;
const ENCRYPTION_CRYPTID: usize = 16;
const NOTE_OFFSET: usize = 24; // note_command.offset (u64)
const LC_FUNCTION_VARIANTS: u32 = 0x37;
const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
const LC_LAZY_LOAD_DYLIB_INFO: u32 = 0x3a;
const LC_ROUTINES: u32 = 0x11;
const LC_ROUTINES_64: u32 = 0x1a;
const ROUTINES_INIT_ADDRESS: usize = 8;
const LC_TWOLEVEL_HINTS: u32 = 0x16;
const TWOLEVEL_OFFSET: usize = 8;
const LC_SYMSEG: u32 = 0x3;
const SYMSEG_OFFSET: usize = 8;
const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;
const FILESET_VMADDR: usize = 8;
const FILESET_FILEOFF: usize = 16;
const LC_THREAD: u32 = 0x4;
const LC_UNIXTHREAD: u32 = 0x5;
const THREAD_FIRST_STATE: usize = 8; // first (flavor, count) tuple
// (flavor, byte offset of the program counter within the state, its width)
const THREAD_PC: [(u32, usize, usize); 3] = [
    (6, 256, 8), // ARM_THREAD_STATE64.pc
    (4, 128, 8), // x86_THREAD_STATE64.rip
    (1, 60, 4),  // ARM_THREAD_STATE.r15
];
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_ID_DYLIB: u32 = 0xd;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;

// Payload is only strings, versions or UUIDs — no offset or address to fix up.
const OFFSET_FREE: &[u32] = &[
    LC_LOAD_DYLIB,
    LC_ID_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_RPATH,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_IPHONEOS,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
    LC_BUILD_VERSION,
    0x1b,               // LC_UUID
    0x2a,               // LC_SOURCE_VERSION
    0xe,                // LC_LOAD_DYLINKER
    0xf,                // LC_ID_DYLINKER
    0x27,               // LC_DYLD_ENVIRONMENT
    0x1f | LC_REQ_DYLD, // LC_REEXPORT_DYLIB
    0x23 | LC_REQ_DYLD, // LC_LOAD_UPWARD_DYLIB
    0x20,               // LC_LAZY_LOAD_DYLIB
    0x12,               // LC_SUB_FRAMEWORK
    0x13,               // LC_SUB_UMBRELLA
    0x14,               // LC_SUB_CLIENT
    0x15,               // LC_SUB_LIBRARY
    0x10,               // LC_PREBOUND_DYLIB
    0x2d,               // LC_LINKER_OPTION
    0x39,               // LC_TARGET_TRIPLE
    0x17,               // LC_PREBIND_CKSUM
    0x8,                // LC_IDENT
    0xa,                // LC_PREPAGE
];
pub(crate) const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub(crate) const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub(crate) const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub(crate) const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub(crate) const LC_BUILD_VERSION: u32 = 0x32;

pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_MAGIC_32: u32 = 0xfeed_face;
pub(crate) const FAT_MAGIC: u32 = 0xcafe_babe;
pub(crate) const FAT_MAGIC_64: u32 = 0xcafe_babf;

const MH_DYLIB: u32 = 0x6;

const CPU_TYPE_ARM64: u32 = 0x0100_000c; // arm64 and arm64e share this cputype

const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;

// struct field byte offsets (and strides)
pub(crate) mod mh {
    // mach_header_64
    pub const FILETYPE: usize = 12;
    pub const NCMDS: usize = 16;
    pub const SIZEOFCMDS: usize = 20;
    pub const SIZE: usize = 32; // header length == first load command
}
pub(crate) mod lc {
    // load_command header
    pub const CMDSIZE: usize = 4;
}
pub(crate) mod seg64 {
    // segment_command_64
    pub const SEGNAME: usize = 8;
    pub const SEGNAME_LEN: usize = 16;
    pub const VMADDR: usize = 24;
    pub const VMSIZE: usize = 32;
    pub const FILEOFF: usize = 40;
    pub const FILESIZE: usize = 48;
    pub const NSECTS: usize = 64;
    pub const SECTIONS: usize = 72; // first section_64
}
mod sect64 {
    // section_64
    pub const ADDR: usize = 32;
    pub const SIZE: usize = 40;
    pub const OFFSET: usize = 48;
    pub const STRIDE: usize = 80;
}
mod symtab {
    // symtab_command
    pub const SYMOFF: usize = 8;
    pub const NSYMS: usize = 12;
    pub const STROFF: usize = 16;
    pub const STRSIZE: usize = 20;
}
pub(crate) mod linkedit {
    // linkedit_data_command
    pub const DATAOFF: usize = 8;
    pub const DATASIZE: usize = 12;
}
mod main_cmd {
    // entry_point_command (LC_MAIN)
    pub const ENTRYOFF: usize = 8;
}
mod dyld_info {
    // dyld_info_command: the five *_off fields
    pub const OFFS: [usize; 5] = [8, 16, 24, 32, 40];
}
mod dysymtab {
    // dysymtab_command: the six table file-offset fields
    pub const OFFS: [usize; 6] = [32, 40, 48, 56, 64, 72];
}
mod dylib {
    // dylib_command
    pub const NAME: usize = 8; // lc_str offset field
    pub const STR: usize = 24; // string payload
}
mod rpath {
    // rpath_command
    pub const PATH: usize = 8; // lc_str offset field
    pub const STR: usize = 12; // string payload
}
mod nlist {
    // nlist_64
    pub const N_TYPE: usize = 4;
    pub const N_VALUE: usize = 8;
    pub const STRIDE: usize = 16;
}
pub(crate) mod fat {
    // fat_header
    pub const NARCH: usize = 4;
    pub const ARCHS: usize = 8; // first fat_arch
}
pub(crate) mod fat_arch {
    // fat_arch / fat_arch_64
    pub const CPUSUBTYPE: usize = 4;
    pub const OFFSET: usize = 8;
    pub const SIZE32: usize = 12;
    pub const ALIGN32: usize = 16;
    pub const STRIDE32: usize = 20;
    pub const SIZE64: usize = 16;
    pub const ALIGN64: usize = 24;
    pub const STRIDE64: usize = 32;
}

pub(crate) fn r32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
pub(crate) fn r64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
pub(crate) fn w32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn w64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
// big-endian accessors (fat headers are always big-endian)
pub(crate) fn rb32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
pub(crate) fn rb64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}
fn align_page(n: u64) -> u64 {
    n.div_ceil(PAGE) * PAGE
}

pub(crate) fn cstr(b: &[u8], start: usize, max: usize) -> String {
    let slice = &b[start..(start + max).min(b.len())];
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

/// Idempotent: no-op if any load command already references this path.
pub fn inject_weak_dylib(macho: &[u8], dylib_path: &str) -> Result<Vec<u8>> {
    apply(macho, &Op::InjectWeakDylib(dylib_path.to_string()))
}

pub fn ensure_rpath(macho: &[u8], path: &str) -> Result<Vec<u8>> {
    apply(macho, &Op::EnsureRpath(path.to_string()))
}

/// Do this before injecting: frees cave that may keep the inject in-place.
pub fn strip_code_signature(macho: &[u8]) -> Result<Vec<u8>> {
    apply(macho, &Op::StripCodeSignature)
}

/// A fat (multi-architecture) binary — the only kind [`thin_to_arm64`] rewrites.
/// Decidable from the first four bytes, so callers can skip reading the rest.
pub fn is_fat(buf: &[u8]) -> bool {
    matches!(kind(buf), Kind::Fat32 | Kind::Fat64)
}

pub fn is_macho(buf: &[u8]) -> bool {
    matches!(
        kind(buf),
        Kind::Thin64 | Kind::Thin32 | Kind::Fat32 | Kind::Fat64
    )
}

/// 64-bit slices of a thin or fat Mach-O; 32-bit slices are skipped, not an error.
pub(crate) fn thin_slices(buf: &[u8]) -> Result<Vec<&[u8]>> {
    match kind(buf) {
        Kind::Thin64 => Ok(vec![buf]),
        Kind::Thin32 => Ok(Vec::new()),
        Kind::Fat32 | Kind::Fat64 => {
            let is64 = matches!(kind(buf), Kind::Fat64);
            let nfat = rb32(buf, fat::NARCH) as usize;
            let entry = if is64 {
                fat_arch::STRIDE64
            } else {
                fat_arch::STRIDE32
            };
            nfat.checked_mul(entry)
                .and_then(|n| n.checked_add(fat::ARCHS))
                .filter(|&h| h <= buf.len())
                .ok_or_else(|| anyhow::anyhow!("truncated or malformed fat header"))?;

            let mut out = Vec::with_capacity(nfat);
            for i in 0..nfat {
                let (offset, size, _) = fat_slice_extent(buf, fat::ARCHS + i * entry, is64)?;
                let slice = &buf[offset..offset + size];
                if matches!(kind(slice), Kind::Thin64) {
                    out.push(slice);
                }
            }
            Ok(out)
        }
        Kind::Other => bail!("not a recognised Mach-O (bad magic)"),
    }
}

/// Thin 64-bit only: a fat buffer parses as garbage.
pub(crate) fn thin_load_commands(buf: &[u8]) -> Result<Vec<(u32, &[u8])>> {
    let ncmds = r32(buf, mh::NCMDS) as usize;
    if buf.len() < mh::SIZE {
        bail!("truncated Mach-O header");
    }
    let mut out = Vec::with_capacity(ncmds);
    let mut off = mh::SIZE;
    for _ in 0..ncmds {
        if off + 8 > buf.len() {
            bail!("truncated load command");
        }
        let size = r32(buf, off + lc::CMDSIZE) as usize;
        if size < 8 || off + size > buf.len() {
            bail!("malformed load command (cmdsize {size})");
        }
        out.push((r32(buf, off), &buf[off..off + size]));
        off += size;
    }
    Ok(out)
}

pub fn set_dylib_id(macho: &[u8], new_id: &str) -> Result<Vec<u8>> {
    apply(macho, &Op::SetDylibId(new_id.to_string()))
}

pub fn change_dylib_path(macho: &[u8], old: &str, new: &str) -> Result<Vec<u8>> {
    apply(
        macho,
        &Op::ChangeDylibPath(old.to_string(), new.to_string()),
    )
}

enum Op {
    InjectWeakDylib(String),
    EnsureRpath(String),
    StripCodeSignature,
    SetDylibId(String),
    ChangeDylibPath(String, String),
}

enum Kind {
    Thin64,
    Thin32,
    Fat32,
    Fat64,
    Other,
}

fn kind(buf: &[u8]) -> Kind {
    if buf.len() < 4 {
        return Kind::Other;
    }
    match rb32(buf, 0) {
        FAT_MAGIC => Kind::Fat32,
        FAT_MAGIC_64 => Kind::Fat64,
        _ => match r32(buf, 0) {
            MH_MAGIC_64 => Kind::Thin64,
            MH_MAGIC_32 => Kind::Thin32,
            _ => Kind::Other,
        },
    }
}

fn apply(buf: &[u8], op: &Op) -> Result<Vec<u8>> {
    match kind(buf) {
        Kind::Thin64 => edit_thin(buf, op),
        Kind::Thin32 => bail!("32-bit Mach-O is unsupported"),
        Kind::Fat32 | Kind::Fat64 => edit_fat(buf, op),
        Kind::Other => bail!("not a recognised Mach-O (bad magic)"),
    }
}

fn edit_fat(buf: &[u8], op: &Op) -> Result<Vec<u8>> {
    let is64 = matches!(kind(buf), Kind::Fat64);
    let nfat = rb32(buf, fat::NARCH) as usize;
    let entry = if is64 {
        fat_arch::STRIDE64
    } else {
        fat_arch::STRIDE32
    };
    nfat.checked_mul(entry)
        .and_then(|n| n.checked_add(fat::ARCHS))
        .filter(|&h| h <= buf.len())
        .ok_or_else(|| anyhow::anyhow!("truncated or malformed fat header"))?;

    let mut arches = Vec::with_capacity(nfat);
    for i in 0..nfat {
        let base = fat::ARCHS + i * entry;
        let cputype = rb32(buf, base);
        let cpusubtype = rb32(buf, base + fat_arch::CPUSUBTYPE);
        let (offset, size, align) = fat_slice_extent(buf, base, is64)?;
        let slice = &buf[offset..offset + size];
        let edited = match kind(slice) {
            Kind::Thin64 => edit_thin(slice, op)?,
            _ => slice.to_vec(),
        };
        arches.push(FatSlice {
            cputype,
            cpusubtype,
            align,
            data: edited,
        });
    }

    Ok(build_fat(is64, &arches))
}

struct FatSlice {
    cputype: u32,
    cpusubtype: u32,
    align: u32,
    data: Vec<u8>,
}

fn fat_slice_extent(buf: &[u8], base: usize, is64: bool) -> Result<(usize, usize, u32)> {
    let (offset, size, align) = if is64 {
        (
            rb64(buf, base + fat_arch::OFFSET) as usize,
            rb64(buf, base + fat_arch::SIZE64) as usize,
            rb32(buf, base + fat_arch::ALIGN64),
        )
    } else {
        (
            rb32(buf, base + fat_arch::OFFSET) as usize,
            rb32(buf, base + fat_arch::SIZE32) as usize,
            rb32(buf, base + fat_arch::ALIGN32),
        )
    };
    if offset > buf.len() || size > buf.len() - offset {
        bail!("fat arch slice out of bounds");
    }
    Ok((offset, size, align))
}

fn build_fat(is64: bool, arches: &[FatSlice]) -> Vec<u8> {
    let entry = if is64 {
        fat_arch::STRIDE64
    } else {
        fat_arch::STRIDE32
    };
    let header_size = fat::ARCHS + arches.len() * entry;

    let mut offsets = Vec::with_capacity(arches.len());
    let mut cursor = header_size as u64;
    for a in arches {
        let a_align = 1u64 << a.align;
        cursor = cursor.div_ceil(a_align) * a_align;
        offsets.push(cursor);
        cursor += a.data.len() as u64;
    }

    let mut out = vec![0u8; cursor as usize];
    out[0..4].copy_from_slice(&(if is64 { FAT_MAGIC_64 } else { FAT_MAGIC }).to_be_bytes());
    out[fat::NARCH..fat::NARCH + 4].copy_from_slice(&(arches.len() as u32).to_be_bytes());
    for (i, a) in arches.iter().enumerate() {
        let base = fat::ARCHS + i * entry;
        out[base..base + 4].copy_from_slice(&a.cputype.to_be_bytes());
        out[base + fat_arch::CPUSUBTYPE..base + fat_arch::OFFSET]
            .copy_from_slice(&a.cpusubtype.to_be_bytes());
        let off = offsets[i];
        let sz = a.data.len() as u64;
        if is64 {
            out[base + fat_arch::OFFSET..base + fat_arch::SIZE64]
                .copy_from_slice(&off.to_be_bytes());
            out[base + fat_arch::SIZE64..base + fat_arch::ALIGN64]
                .copy_from_slice(&sz.to_be_bytes());
            out[base + fat_arch::ALIGN64..base + fat_arch::ALIGN64 + 4]
                .copy_from_slice(&a.align.to_be_bytes());
        } else {
            out[base + fat_arch::OFFSET..base + fat_arch::SIZE32]
                .copy_from_slice(&(off as u32).to_be_bytes());
            out[base + fat_arch::SIZE32..base + fat_arch::ALIGN32]
                .copy_from_slice(&(sz as u32).to_be_bytes());
            out[base + fat_arch::ALIGN32..base + fat_arch::STRIDE32]
                .copy_from_slice(&a.align.to_be_bytes());
        }
        out[off as usize..off as usize + a.data.len()].copy_from_slice(&a.data);
    }
    out
}

/// `None` if already thin or fat arm64-only; errors if no arm64 slice.
pub fn thin_to_arm64(buf: &[u8]) -> Result<Option<Vec<u8>>> {
    let is64 = match kind(buf) {
        Kind::Fat64 => true,
        Kind::Fat32 => false,
        _ => return Ok(None),
    };
    let nfat = rb32(buf, fat::NARCH) as usize;
    let entry = if is64 {
        fat_arch::STRIDE64
    } else {
        fat_arch::STRIDE32
    };
    nfat.checked_mul(entry)
        .and_then(|n| n.checked_add(fat::ARCHS))
        .filter(|&h| h <= buf.len())
        .ok_or_else(|| anyhow::anyhow!("truncated or malformed fat header"))?;

    let mut kept = Vec::new();
    for i in 0..nfat {
        let base = fat::ARCHS + i * entry;
        let cputype = rb32(buf, base);
        let cpusubtype = rb32(buf, base + fat_arch::CPUSUBTYPE);
        let (offset, size, align) = fat_slice_extent(buf, base, is64)?;
        if cputype != CPU_TYPE_ARM64 {
            continue;
        }
        kept.push(FatSlice {
            cputype,
            cpusubtype,
            align,
            data: buf[offset..offset + size].to_vec(),
        });
    }

    match kept.len() {
        0 => bail!("--thin: binary has no arm64 slice to keep"),
        n if n == nfat => Ok(None),
        1 => Ok(Some(kept.pop().unwrap().data)),
        _ => Ok(Some(build_fat(is64, &kept))), // e.g. arm64 + arm64e retained
    }
}

/// Max `cryptid` across all slices; non-zero iff FairPlay-encrypted.
pub fn encryption_cryptid(buf: &[u8]) -> Result<u32> {
    match kind(buf) {
        Kind::Thin64 => thin_cryptid(buf),
        Kind::Fat32 | Kind::Fat64 => {
            let is64 = matches!(kind(buf), Kind::Fat64);
            let nfat = rb32(buf, fat::NARCH) as usize;
            let entry = if is64 {
                fat_arch::STRIDE64
            } else {
                fat_arch::STRIDE32
            };
            let mut max = 0;
            for i in 0..nfat {
                let base = fat::ARCHS + i * entry;
                if base + entry > buf.len() {
                    bail!("truncated fat header");
                }
                let (offset, size, _) = fat_slice_extent(buf, base, is64)?;
                let slice = &buf[offset..offset + size];
                if matches!(kind(slice), Kind::Thin64) {
                    max = max.max(thin_cryptid(slice)?);
                }
            }
            Ok(max)
        }
        Kind::Thin32 => Ok(0),
        Kind::Other => bail!("not a recognised Mach-O (bad magic)"),
    }
}

fn thin_cryptid(buf: &[u8]) -> Result<u32> {
    let thin = parse_thin(buf)?;
    let mut max = 0;
    for (_, c) in &thin.commands {
        let cmd = r32(c, 0);
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64)
            && c.len() >= ENCRYPTION_CRYPTID + 4
        {
            max = max.max(r32(c, ENCRYPTION_CRYPTID));
        }
    }
    Ok(max)
}

struct Thin {
    filetype: u32,
    commands: Vec<(usize, Vec<u8>)>, // (file offset, raw bytes)
    min_sect_off: u64,
    text_vmaddr: u64,
    symoff: u32,
    nsyms: u32,
}

fn parse_thin(buf: &[u8]) -> Result<Thin> {
    if buf.len() < 32 || r32(buf, 0) != MH_MAGIC_64 {
        bail!("not a 64-bit little-endian Mach-O");
    }
    let filetype = r32(buf, mh::FILETYPE);
    let ncmds = r32(buf, mh::NCMDS);
    let sizeofcmds = r32(buf, mh::SIZEOFCMDS);
    let lc_start = mh::SIZE;
    let lc_end = lc_start + sizeofcmds as usize;
    if lc_end > buf.len() {
        bail!("load commands exceed file length");
    }

    let mut commands = Vec::with_capacity(ncmds as usize);
    let mut min_sect_off = u64::MAX;
    let mut text_vmaddr = 0u64;
    let mut symoff = 0u32;
    let mut nsyms = 0u32;

    let mut off = lc_start;
    for _ in 0..ncmds {
        if off + 8 > buf.len() {
            bail!("truncated load command");
        }
        let cmd = r32(buf, off);
        let cmdsize = r32(buf, off + lc::CMDSIZE) as usize;
        if cmdsize < 8 || off + cmdsize > buf.len() {
            bail!("malformed load command (cmdsize {cmdsize})");
        }
        match cmd {
            LC_SEGMENT_64 => {
                if cmdsize < seg64::SECTIONS {
                    bail!("truncated LC_SEGMENT_64");
                }
                let segname = cstr(buf, off + seg64::SEGNAME, seg64::SEGNAME_LEN);
                if segname == "__TEXT" {
                    text_vmaddr = r64(buf, off + seg64::VMADDR);
                }
                let nsects = r32(buf, off + seg64::NSECTS);
                let mut so = off + seg64::SECTIONS;
                for _ in 0..nsects {
                    if so + sect64::STRIDE > off + cmdsize {
                        bail!("section table overruns LC_SEGMENT_64");
                    }
                    let sect_off = r32(buf, so + sect64::OFFSET) as u64;
                    let sect_size = r64(buf, so + sect64::SIZE);
                    if sect_size > 0 && sect_off > 0 {
                        min_sect_off = min_sect_off.min(sect_off);
                    }
                    so += sect64::STRIDE;
                }
            }
            LC_SYMTAB => {
                if cmdsize < symtab::STRSIZE + 4 {
                    bail!("truncated LC_SYMTAB");
                }
                symoff = r32(buf, off + symtab::SYMOFF);
                nsyms = r32(buf, off + symtab::NSYMS);
            }
            _ => {}
        }
        commands.push((off, buf[off..off + cmdsize].to_vec()));
        off += cmdsize;
    }

    if min_sect_off == u64::MAX {
        bail!("Mach-O has no sections with file content");
    }

    let _ = (ncmds, sizeofcmds);
    Ok(Thin {
        filetype,
        commands,
        min_sect_off,
        text_vmaddr,
        symoff,
        nsyms,
    })
}

fn edit_thin(buf: &[u8], op: &Op) -> Result<Vec<u8>> {
    let thin = parse_thin(buf)?;

    match op {
        Op::InjectWeakDylib(path) => {
            if dylib_referenced(buf, path)? {
                return Ok(buf.to_vec());
            }
            let mut cmds: Vec<Vec<u8>> = thin.commands.iter().map(|(_, c)| c.clone()).collect();
            cmds.push(build_dylib_lc(LC_LOAD_WEAK_DYLIB, path));
            assemble(buf, &thin, cmds)
        }
        Op::EnsureRpath(path) => {
            if rpath_present(buf, path)? {
                return Ok(buf.to_vec());
            }
            let mut cmds: Vec<Vec<u8>> = thin.commands.iter().map(|(_, c)| c.clone()).collect();
            cmds.push(build_rpath_lc(path));
            assemble(buf, &thin, cmds)
        }
        Op::StripCodeSignature => strip(buf, &thin),
        Op::SetDylibId(new) => {
            if thin.filetype != MH_DYLIB {
                bail!("set_dylib_id: Mach-O is not a dylib");
            }
            let mut changed = false;
            let mut cmds = Vec::with_capacity(thin.commands.len());
            for (_, c) in &thin.commands {
                if r32(c, 0) == LC_ID_DYLIB {
                    cmds.push(replace_lc_string(c, dylib::STR, new));
                    changed = true;
                } else {
                    cmds.push(c.clone());
                }
            }
            if !changed {
                bail!("set_dylib_id: no LC_ID_DYLIB present");
            }
            assemble(buf, &thin, cmds)
        }
        Op::ChangeDylibPath(old, new) => {
            let mut changed = false;
            let mut cmds = Vec::with_capacity(thin.commands.len());
            for (_, c) in &thin.commands {
                let cmd = r32(c, 0);
                if matches!(cmd, LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB) {
                    let name_off = r32(c, dylib::NAME) as usize;
                    if cstr(c, name_off, c.len() - name_off) == *old {
                        cmds.push(replace_lc_string(c, name_off, new));
                        changed = true;
                        continue;
                    }
                }
                cmds.push(c.clone());
            }
            if !changed {
                return Ok(buf.to_vec());
            }
            assemble(buf, &thin, cmds)
        }
    }
}

/// For a fat binary, the union across slices; unparseable slices are skipped.
pub fn dylib_paths(buf: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for slice in thin_slices(buf).unwrap_or_default() {
        let Ok(m) = MachO::parse(slice, 0) else {
            continue;
        };
        for lib in m.libs {
            // goblin seeds `libs` with "self" for the binary's own id.
            if lib != "self" && !out.iter().any(|p| p == lib) {
                out.push(lib.to_owned());
            }
        }
    }
    out
}

fn dylib_referenced(buf: &[u8], path: &str) -> Result<bool> {
    let m = MachO::parse(buf, 0).map_err(|e| anyhow::anyhow!("goblin parse: {e}"))?;
    Ok(m.libs.contains(&path))
}

fn rpath_present(buf: &[u8], path: &str) -> Result<bool> {
    let m = MachO::parse(buf, 0).map_err(|e| anyhow::anyhow!("goblin parse: {e}"))?;
    Ok(m.rpaths.contains(&path))
}

fn build_dylib_lc(cmd: u32, name: &str) -> Vec<u8> {
    let fixed = dylib::STR;
    let cmdsize = align8(fixed + name.len() + 1);
    let mut v = vec![0u8; cmdsize];
    w32(&mut v, 0, cmd);
    w32(&mut v, lc::CMDSIZE, cmdsize as u32);
    w32(&mut v, dylib::NAME, dylib::STR as u32);
    v[dylib::STR..dylib::STR + name.len()].copy_from_slice(name.as_bytes());
    v
}

fn build_rpath_lc(path: &str) -> Vec<u8> {
    let fixed = rpath::STR;
    let cmdsize = align8(fixed + path.len() + 1);
    let mut v = vec![0u8; cmdsize];
    w32(&mut v, 0, LC_RPATH);
    w32(&mut v, lc::CMDSIZE, cmdsize as u32);
    w32(&mut v, rpath::PATH, rpath::STR as u32);
    v[rpath::STR..rpath::STR + path.len()].copy_from_slice(path.as_bytes());
    v
}

fn replace_lc_string(orig: &[u8], str_off: usize, new_str: &str) -> Vec<u8> {
    let cmdsize = align8(str_off + new_str.len() + 1);
    let mut v = vec![0u8; cmdsize];
    v[..str_off].copy_from_slice(&orig[..str_off]);
    v[str_off..str_off + new_str.len()].copy_from_slice(new_str.as_bytes());
    w32(&mut v, lc::CMDSIZE, cmdsize as u32);
    v
}

fn assemble(buf: &[u8], thin: &Thin, commands: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    let new_sizeofcmds: usize = commands.iter().map(|c| c.len()).sum();
    let new_ncmds = commands.len() as u32;
    let lc_region_end = mh::SIZE as u64 + new_sizeofcmds as u64;

    if lc_region_end <= thin.min_sect_off {
        let mut out = buf.to_vec();
        w32(&mut out, mh::NCMDS, new_ncmds);
        w32(&mut out, mh::SIZEOFCMDS, new_sizeofcmds as u32);
        let mut p = mh::SIZE;
        for c in &commands {
            out[p..p + c.len()].copy_from_slice(c);
            p += c.len();
        }
        for b in out.iter_mut().take(thin.min_sect_off as usize).skip(p) {
            *b = 0;
        }
        return Ok(out);
    }

    let deficit = lc_region_end - thin.min_sect_off;
    let shift = align_page(deficit);

    let mut shifted: Vec<Vec<u8>> = commands;
    // A page insert would misalign an encrypted cryptoff range; refuse.
    for c in &shifted {
        let cmd = r32(c, 0);
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64)
            && r32(c, ENCRYPTION_CRYPTID) != 0
        {
            bail!("cannot inject into an encrypted binary (cryptid != 0); decrypt it first");
        }
    }
    for c in &mut shifted {
        shift_command(c, shift)?;
    }

    let min = thin.min_sect_off as usize;
    let front_len = min + shift as usize;
    let mut out = vec![0u8; front_len];
    out[..min].copy_from_slice(&buf[..min]);
    w32(&mut out, mh::NCMDS, new_ncmds);
    w32(&mut out, mh::SIZEOFCMDS, new_sizeofcmds as u32);
    let mut p = mh::SIZE;
    for c in &shifted {
        out[p..p + c.len()].copy_from_slice(c);
        p += c.len();
    }
    for b in out.iter_mut().take(front_len).skip(p) {
        *b = 0;
    }
    out.extend_from_slice(&buf[min..]);

    fixup_symbols(&mut out, thin, shift);
    Ok(out)
}

/// A command not rebased here nor in `OFFSET_FREE` is refused, never shifted blind: Apple keeps adding them, so unknowns must fail loud.
fn shift_command(c: &mut [u8], s: u64) -> Result<()> {
    let cmd = r32(c, 0);
    match cmd {
        LC_SEGMENT_64 => {
            let segname = cstr(c, seg64::SEGNAME, seg64::SEGNAME_LEN);
            if segname == "__PAGEZERO" {
                return Ok(());
            }
            let nsects = r32(c, seg64::NSECTS);
            if segname == "__TEXT" {
                // base fixed; grow to cover the inserted page
                w64(c, seg64::VMSIZE, r64(c, seg64::VMSIZE) + s);
                w64(c, seg64::FILESIZE, r64(c, seg64::FILESIZE) + s);
            } else {
                w64(c, seg64::VMADDR, r64(c, seg64::VMADDR) + s);
                w64(c, seg64::FILEOFF, r64(c, seg64::FILEOFF) + s);
            }
            let mut so = seg64::SECTIONS;
            for _ in 0..nsects {
                w64(c, so + sect64::ADDR, r64(c, so + sect64::ADDR) + s);
                let sect_off = r32(c, so + sect64::OFFSET);
                if sect_off != 0 {
                    w32(c, so + sect64::OFFSET, sect_off + s as u32);
                }
                so += sect64::STRIDE;
            }
        }
        LC_MAIN => w64(c, main_cmd::ENTRYOFF, r64(c, main_cmd::ENTRYOFF) + s),
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            for f in dyld_info::OFFS {
                let v = r32(c, f);
                if v != 0 {
                    w32(c, f, v + s as u32);
                }
            }
        }
        LC_SYMTAB => {
            w32(c, symtab::SYMOFF, r32(c, symtab::SYMOFF) + s as u32);
            w32(c, symtab::STROFF, r32(c, symtab::STROFF) + s as u32);
        }
        LC_DYSYMTAB => {
            for f in dysymtab::OFFS {
                let v = r32(c, f);
                if v != 0 {
                    w32(c, f, v + s as u32);
                }
            }
        }
        LC_FUNCTION_STARTS
        | LC_DATA_IN_CODE
        | LC_CODE_SIGNATURE
        | LC_SEGMENT_SPLIT_INFO
        | LC_DYLD_EXPORTS_TRIE
        | LC_DYLD_CHAINED_FIXUPS
        | LC_DYLIB_CODE_SIGN_DRS
        | LC_LINKER_OPTIMIZATION_HINT
        | LC_ATOM_INFO
        | LC_FUNCTION_VARIANTS
        | LC_FUNCTION_VARIANT_FIXUPS
        | LC_LAZY_LOAD_DYLIB_INFO => {
            let v = r32(c, linkedit::DATAOFF);
            if v != 0 {
                w32(c, linkedit::DATAOFF, v + s as u32);
            }
        }
        LC_NOTE => {
            let v = r64(c, NOTE_OFFSET);
            if v != 0 {
                w64(c, NOTE_OFFSET, v + s);
            }
        }
        // cryptid is 0 here (assemble refuses otherwise), but cryptoff tracks __TEXT.
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            let v = r32(c, ENCRYPTION_CRYPTOFF);
            if v != 0 {
                w32(c, ENCRYPTION_CRYPTOFF, v + s as u32);
            }
        }
        LC_ROUTINES_64 => {
            let v = r64(c, ROUTINES_INIT_ADDRESS);
            if v != 0 {
                w64(c, ROUTINES_INIT_ADDRESS, v + s);
            }
        }
        LC_ROUTINES => {
            let v = r32(c, ROUTINES_INIT_ADDRESS);
            if v != 0 {
                w32(c, ROUTINES_INIT_ADDRESS, v + s as u32);
            }
        }
        LC_TWOLEVEL_HINTS => {
            let v = r32(c, TWOLEVEL_OFFSET);
            if v != 0 {
                w32(c, TWOLEVEL_OFFSET, v + s as u32);
            }
        }
        LC_SYMSEG => {
            let v = r32(c, SYMSEG_OFFSET);
            if v != 0 {
                w32(c, SYMSEG_OFFSET, v + s as u32);
            }
        }
        LC_FILESET_ENTRY => {
            for f in [FILESET_VMADDR, FILESET_FILEOFF] {
                let v = r64(c, f);
                if v != 0 {
                    w64(c, f, v + s);
                }
            }
        }
        // Only each state's PC is an address; an unknown flavor's layout hides the PC, so refuse.
        LC_THREAD | LC_UNIXTHREAD => {
            let cmdsize = r32(c, lc::CMDSIZE) as usize;
            if cmdsize > c.len() {
                bail!("thread command claims {cmdsize} bytes but is {}", c.len());
            }
            let mut p = THREAD_FIRST_STATE;
            while p + 8 <= cmdsize {
                let flavor = r32(c, p);
                let state = p + 8;
                let state_len = r32(c, p + 4) as usize * 4;
                let end = state
                    .checked_add(state_len)
                    .filter(|e| *e <= cmdsize)
                    .with_context(|| format!("thread state {flavor:#x} overruns the command"))?;
                let (_, pc, width) = THREAD_PC
                    .iter()
                    .find(|(f, _, _)| *f == flavor)
                    .with_context(|| {
                        format!(
                            "unrecognised thread-state flavor {flavor:#x}: cannot locate the \
                             program counter to rebase it"
                        )
                    })?;
                if pc + width > state_len {
                    bail!("thread state {flavor:#x} too short to hold a program counter");
                }
                match width {
                    8 => {
                        let v = r64(c, state + pc);
                        if v != 0 {
                            w64(c, state + pc, v + s);
                        }
                    }
                    _ => {
                        let v = r32(c, state + pc);
                        if v != 0 {
                            w32(c, state + pc, v + s as u32);
                        }
                    }
                }
                p = end;
            }
        }
        _ if OFFSET_FREE.contains(&cmd) => {}
        _ => bail!(
            "unrecognised load command {cmd:#x}: cannot safely make room for an \
             injection in this binary, because shifting it may need offsets \
             patina does not know how to rebase"
        ),
    }
    Ok(())
}

/// Skips `__mh_execute_header`: pinned at the __TEXT base, so `n_value == text_vmaddr`.
fn fixup_symbols(out: &mut [u8], thin: &Thin, s: u64) {
    if thin.nsyms == 0 {
        return;
    }
    let base = thin.symoff as usize + s as usize;
    for i in 0..thin.nsyms as usize {
        let rec = base + i * nlist::STRIDE;
        if rec + nlist::STRIDE > out.len() {
            break;
        }
        let n_type = out[rec + nlist::N_TYPE];
        if n_type & N_STAB != 0 {
            continue;
        }
        if n_type & N_TYPE != N_SECT {
            continue;
        }
        let n_value = r64(out, rec + nlist::N_VALUE);
        if n_value != 0 && n_value != thin.text_vmaddr {
            w64(out, rec + nlist::N_VALUE, n_value + s);
        }
    }
}

fn strip(buf: &[u8], thin: &Thin) -> Result<Vec<u8>> {
    let mut sig: Option<(u32, u32)> = None; // (dataoff, datasize)
    for (_, c) in &thin.commands {
        if r32(c, 0) == LC_CODE_SIGNATURE {
            sig = Some((r32(c, linkedit::DATAOFF), r32(c, linkedit::DATASIZE)));
            break;
        }
    }
    let Some((sig_off, _sig_size)) = sig else {
        return Ok(buf.to_vec());
    };
    let sig_off = sig_off as u64;

    // The signature is always the final __LINKEDIT blob, so shrink __LINKEDIT to end where it began.
    let mut cmds = Vec::with_capacity(thin.commands.len());
    for (_, c) in &thin.commands {
        let cmd = r32(c, 0);
        if cmd == LC_CODE_SIGNATURE {
            continue;
        }
        let mut c = c.clone();
        if cmd == LC_SEGMENT_64 && cstr(&c, seg64::SEGNAME, seg64::SEGNAME_LEN) == "__LINKEDIT" {
            let fileoff = r64(&c, seg64::FILEOFF);
            let new_size = sig_off - fileoff;
            w64(&mut c, seg64::VMSIZE, new_size);
            w64(&mut c, seg64::FILESIZE, new_size);
        }
        cmds.push(c);
    }

    let mut out = assemble(buf, thin, cmds)?;
    out.truncate(sig_off as usize);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::mach::load_command::CommandVariant;
    use std::path::Path;
    use std::process::Command;

    const FIX: &str = "/tmp/patina-fixtures";

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("patina-{tag}-{}-{id}.bin", std::process::id()))
    }

    fn load(name: &str) -> Option<Vec<u8>> {
        let p = format!("{FIX}/{name}");
        if Path::new(&p).exists() {
            Some(std::fs::read(p).unwrap())
        } else {
            eprintln!("SKIP: fixture {p} not present");
            None
        }
    }

    fn linkedit_fileoff(buf: &[u8]) -> u64 {
        let t = parse_thin(buf).unwrap();
        for (_, c) in &t.commands {
            if r32(c, 0) == LC_SEGMENT_64
                && cstr(c, seg64::SEGNAME, seg64::SEGNAME_LEN) == "__LINKEDIT"
            {
                return r64(c, seg64::FILEOFF);
            }
        }
        panic!("no __LINKEDIT");
    }

    fn has_code_sig(buf: &[u8]) -> bool {
        let t = parse_thin(buf).unwrap();
        t.commands
            .iter()
            .any(|(_, c)| r32(c, 0) == LC_CODE_SIGNATURE)
    }

    fn is_weak_variant(buf: &[u8], path: &str) -> bool {
        let m = MachO::parse(buf, 0).unwrap();
        m.load_commands.iter().any(|lc| match &lc.command {
            CommandVariant::LoadWeakDylib(cmd) => {
                cstr(buf, lc.offset + cmd.dylib.name as usize, path.len() + 1) == path
            }
            _ => false,
        })
    }

    fn objdump_clean(buf: &[u8]) {
        let path = tmp_path("objdump");
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

    fn sym_addr(buf: &[u8], name: &str) -> Option<u64> {
        let path = tmp_path("syms");
        std::fs::write(&path, buf).unwrap();
        let out = Command::new("llvm-objdump")
            .args(["--macho", "--syms"])
            .arg(&path)
            .output()
            .ok()?;
        let _ = std::fs::remove_file(&path);
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.trim_end().ends_with(name) && line.split_whitespace().last() == Some(name) {
                let addr = line.split_whitespace().next()?;
                return u64::from_str_radix(addr, 16).ok();
            }
        }
        None
    }

    #[test]
    fn inject_weak_dylib_basic() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        let out = inject_weak_dylib(&orig, "@rpath/libinject.dylib").unwrap();

        let m = MachO::parse(&out, 0).unwrap();
        assert!(m.libs.contains(&"@rpath/libinject.dylib"));
        assert!(is_weak_variant(&out, "@rpath/libinject.dylib"));
        assert!(m.rpaths.contains(&"@executable_path/Frameworks"));
        objdump_clean(&out);
    }

    #[test]
    fn inject_weak_dylib_idempotent() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        let once = inject_weak_dylib(&orig, "@rpath/libinject.dylib").unwrap();
        let twice = inject_weak_dylib(&once, "@rpath/libinject.dylib").unwrap();
        assert_eq!(once, twice, "second inject must be a no-op");
    }

    #[test]
    fn strip_then_inject_in_place() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        assert!(has_code_sig(&orig), "fixture should be signed");

        let stripped = strip_code_signature(&orig).unwrap();
        assert!(!has_code_sig(&stripped), "signature must be gone");
        objdump_clean(&stripped);

        let le_before = linkedit_fileoff(&stripped);
        let injected = inject_weak_dylib(&stripped, "@rpath/libinject.dylib").unwrap();
        let le_after = linkedit_fileoff(&injected);
        assert_eq!(le_before, le_after, "expected IN-PLACE inject after strip");

        let m = MachO::parse(&injected, 0).unwrap();
        assert!(m.libs.contains(&"@rpath/libinject.dylib"));
        objdump_clean(&injected);
    }

    #[test]
    fn ensure_rpath_add_and_noop() {
        if let Some(nr) = load("main_arm64_norpath") {
            let out = ensure_rpath(&nr, "@executable_path/Frameworks").unwrap();
            let m = MachO::parse(&out, 0).unwrap();
            assert!(m.rpaths.contains(&"@executable_path/Frameworks"));
            objdump_clean(&out);
        }
        if let Some(orig) = load("main_arm64") {
            let out = ensure_rpath(&orig, "@executable_path/Frameworks").unwrap();
            assert_eq!(orig, out, "rpath already present -> identical bytes");
        }
    }

    #[test]
    fn forced_page_shift() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        let long = format!("@rpath/{}.dylib", "libveryverylonginjectionname".repeat(3));
        let out = inject_weak_dylib(&orig, &long).unwrap();

        let m = MachO::parse(&out, 0).unwrap();
        assert!(m.libs.iter().any(|l| *l == long));

        assert_eq!(
            linkedit_fileoff(&out),
            linkedit_fileoff(&orig) + PAGE,
            "linkedit must move one page"
        );
        let entry_before = lc_main_entry(&orig);
        let entry_after = lc_main_entry(&out);
        assert_eq!(
            entry_after,
            entry_before + PAGE,
            "entryoff must move one page"
        );

        objdump_clean(&out);

        if let (Some(m0), Some(m1)) = (sym_addr(&orig, "_main"), sym_addr(&out, "_main")) {
            assert_eq!(m1, m0 + PAGE, "_main n_value must advance one page");
        }
        if let (Some(h0), Some(h1)) = (
            sym_addr(&orig, "__mh_execute_header"),
            sym_addr(&out, "__mh_execute_header"),
        ) {
            assert_eq!(h1, h0, "__mh_execute_header must not move");
        }
    }

    fn lc_main_entry(buf: &[u8]) -> u64 {
        let t = parse_thin(buf).unwrap();
        for (_, c) in &t.commands {
            if r32(c, 0) == LC_MAIN {
                return r64(c, main_cmd::ENTRYOFF);
            }
        }
        panic!("no LC_MAIN");
    }

    #[test]
    fn shift_relocates_less_common_offset_commands() {
        let s = PAGE;
        for cmd in [
            LC_LINKER_OPTIMIZATION_HINT,
            LC_DYLIB_CODE_SIGN_DRS,
            LC_ATOM_INFO,
        ] {
            let mut c = vec![0u8; 16];
            w32(&mut c, 0, cmd);
            w32(&mut c, lc::CMDSIZE, 16);
            w32(&mut c, linkedit::DATAOFF, 1000);
            shift_command(&mut c, s).unwrap();
            assert_eq!(
                r32(&c, linkedit::DATAOFF) as u64,
                1000 + s,
                "cmd {cmd:#x} dataoff not shifted"
            );
        }
        let mut note = vec![0u8; 40];
        w32(&mut note, 0, LC_NOTE);
        w32(&mut note, lc::CMDSIZE, 40);
        w64(&mut note, NOTE_OFFSET, 2000);
        shift_command(&mut note, s).unwrap();
        assert_eq!(
            r64(&note, NOTE_OFFSET),
            2000 + s,
            "LC_NOTE offset not shifted"
        );
    }

    /// Guards the drift that let LC_LINKER_OPTIMIZATION_HINT go unshifted.
    #[test]
    fn every_known_load_command_is_classified() {
        // FVM commands carry a header address patina won't rebase; LC_SEGMENT is 32-bit.
        const REFUSED: &[u32] = &[
            0x1, // LC_SEGMENT
            0x6, // LC_LOADFVMLIB
            0x7, // LC_IDFVMLIB
            0x9, // LC_FVMFILE
        ];
        // Exist only in LC_REQ_DYLD-tagged form; the bare value is not a load command.
        const REQ_DYLD_ONLY: &[u32] = &[0x18, 0x1c, 0x1f, 0x23, 0x28, 0x33, 0x34, 0x35];
        // Apple loader.h, 0x1..=0x3a plus the LC_REQ_DYLD-tagged ones.
        let known: Vec<u32> = (0x1..=0x3a)
            .filter(|c| !REQ_DYLD_ONLY.contains(c))
            .chain([
                0x18 | LC_REQ_DYLD,
                0x1c | LC_REQ_DYLD,
                0x1f | LC_REQ_DYLD,
                0x22 | LC_REQ_DYLD,
                0x23 | LC_REQ_DYLD,
                0x28 | LC_REQ_DYLD,
                0x33 | LC_REQ_DYLD,
                0x34 | LC_REQ_DYLD,
                0x35 | LC_REQ_DYLD,
            ])
            .collect();

        for cmd in known {
            if cmd == LC_SEGMENT_64 {
                continue;
            }
            // Sized exactly to its tuples; trailing slack reads as a bogus tuple.
            let is_thread = matches!(cmd, LC_THREAD | LC_UNIXTHREAD);
            let size = if is_thread {
                THREAD_FIRST_STATE + 8 + 272
            } else {
                4096
            };
            let mut c = vec![0u8; size];
            w32(&mut c, 0, cmd);
            w32(&mut c, lc::CMDSIZE, size as u32);
            if is_thread {
                w32(&mut c, THREAD_FIRST_STATE, 6); // ARM_THREAD_STATE64
                w32(&mut c, THREAD_FIRST_STATE + 4, 68);
            }
            let handled = shift_command(&mut c, PAGE).is_ok();
            assert_eq!(
                handled,
                !REFUSED.contains(&cmd),
                "load command {cmd:#x} is classified wrongly: it is {}, expected {}",
                if handled { "accepted" } else { "refused" },
                if REFUSED.contains(&cmd) {
                    "refused"
                } else {
                    "accepted"
                }
            );
        }
    }

    #[test]
    fn shift_rejects_unrecognised_load_commands() {
        for cmd in [0x1u32, 0x6, 0x7, 0x9, 0x3b, 0xdead_beef] {
            let mut c = vec![0u8; 32];
            w32(&mut c, 0, cmd);
            w32(&mut c, lc::CMDSIZE, 32);
            let err = shift_command(&mut c, PAGE)
                .expect_err(&format!("cmd {cmd:#x} must be refused, not ignored"));
            assert!(
                err.to_string().contains("unrecognised load command"),
                "unexpected error for {cmd:#x}: {err}"
            );
        }
    }

    #[test]
    fn shift_leaves_offset_free_commands_untouched() {
        for &cmd in OFFSET_FREE {
            let mut c = vec![0u8; 32];
            w32(&mut c, 0, cmd);
            w32(&mut c, lc::CMDSIZE, 32);
            let before = c.clone();
            shift_command(&mut c, PAGE)
                .unwrap_or_else(|e| panic!("offset-free cmd {cmd:#x} rejected: {e}"));
            assert_eq!(c, before, "cmd {cmd:#x} must not be modified");
        }
    }

    #[test]
    fn shift_relocates_scalar_offset_commands() {
        for (cmd, field, width) in [
            (LC_ROUTINES_64, ROUTINES_INIT_ADDRESS, 8usize),
            (LC_ROUTINES, ROUTINES_INIT_ADDRESS, 4),
            (LC_TWOLEVEL_HINTS, TWOLEVEL_OFFSET, 4),
            (LC_SYMSEG, SYMSEG_OFFSET, 4),
        ] {
            let mut c = vec![0u8; 72];
            w32(&mut c, 0, cmd);
            w32(&mut c, lc::CMDSIZE, 72);
            if width == 8 {
                w64(&mut c, field, 4096);
            } else {
                w32(&mut c, field, 4096);
            }
            shift_command(&mut c, PAGE).unwrap();
            let got = if width == 8 {
                r64(&c, field)
            } else {
                r32(&c, field) as u64
            };
            assert_eq!(got, 4096 + PAGE, "cmd {cmd:#x} not rebased");
        }
    }

    #[test]
    fn shift_relocates_fileset_entry() {
        let mut c = vec![0u8; 32];
        w32(&mut c, 0, LC_FILESET_ENTRY);
        w32(&mut c, lc::CMDSIZE, 32);
        w64(&mut c, FILESET_VMADDR, 0x1_0000);
        w64(&mut c, FILESET_FILEOFF, 8192);
        shift_command(&mut c, PAGE).unwrap();
        assert_eq!(r64(&c, FILESET_VMADDR), 0x1_0000 + PAGE);
        assert_eq!(r64(&c, FILESET_FILEOFF), 8192 + PAGE);
    }

    #[test]
    fn shift_relocates_thread_program_counter() {
        // one ARM_THREAD_STATE64 tuple: flavor 6, count 68 -> 272-byte state
        let size = THREAD_FIRST_STATE + 8 + 272;
        for cmd in [LC_THREAD, LC_UNIXTHREAD] {
            let mut c = vec![0u8; size];
            w32(&mut c, 0, cmd);
            w32(&mut c, lc::CMDSIZE, size as u32);
            w32(&mut c, THREAD_FIRST_STATE, 6);
            w32(&mut c, THREAD_FIRST_STATE + 4, 68);
            let pc_at = THREAD_FIRST_STATE + 8 + 256;
            w64(&mut c, pc_at, 0x1_0000);
            w64(&mut c, THREAD_FIRST_STATE + 8, 0xdead_beef);
            shift_command(&mut c, PAGE).unwrap();
            assert_eq!(
                r64(&c, pc_at),
                0x1_0000 + PAGE,
                "cmd {cmd:#x} pc not shifted"
            );
            assert_eq!(r64(&c, THREAD_FIRST_STATE + 8), 0xdead_beef, "x0 clobbered");
        }
    }

    #[test]
    fn shift_rejects_unknown_thread_flavor() {
        let size = THREAD_FIRST_STATE + 8 + 64;
        let mut c = vec![0u8; size];
        w32(&mut c, 0, LC_UNIXTHREAD);
        w32(&mut c, lc::CMDSIZE, size as u32);
        w32(&mut c, THREAD_FIRST_STATE, 0x99); // no such flavor
        w32(&mut c, THREAD_FIRST_STATE + 4, 16);
        let err = shift_command(&mut c, PAGE).expect_err("unknown flavor must be refused");
        assert!(
            err.to_string().contains("thread-state flavor"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn shift_rejects_thread_state_overrunning_the_command() {
        let size = THREAD_FIRST_STATE + 8 + 32;
        let mut c = vec![0u8; size];
        w32(&mut c, 0, LC_UNIXTHREAD);
        w32(&mut c, lc::CMDSIZE, size as u32);
        w32(&mut c, THREAD_FIRST_STATE, 6);
        w32(&mut c, THREAD_FIRST_STATE + 4, 68); // claims 272 bytes, has 32
        assert!(
            shift_command(&mut c, PAGE).is_err(),
            "overrun must be refused"
        );
    }

    #[test]
    fn shift_relocates_recent_linkedit_commands() {
        for cmd in [
            LC_FUNCTION_VARIANTS,
            LC_FUNCTION_VARIANT_FIXUPS,
            LC_LAZY_LOAD_DYLIB_INFO,
        ] {
            let mut c = vec![0u8; 16];
            w32(&mut c, 0, cmd);
            w32(&mut c, lc::CMDSIZE, 16);
            w32(&mut c, linkedit::DATAOFF, 2048);
            shift_command(&mut c, PAGE).unwrap();
            assert_eq!(
                r32(&c, linkedit::DATAOFF) as u64,
                2048 + PAGE,
                "cmd {cmd:#x} dataoff not shifted"
            );
        }
    }

    #[test]
    fn shift_relocates_encryption_cryptoff() {
        for cmd in [LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64] {
            let mut c = vec![0u8; 24];
            w32(&mut c, 0, cmd);
            w32(&mut c, lc::CMDSIZE, 24);
            w32(&mut c, ENCRYPTION_CRYPTOFF, 16384);
            shift_command(&mut c, PAGE).unwrap();
            assert_eq!(
                r32(&c, ENCRYPTION_CRYPTOFF) as u64,
                16384 + PAGE,
                "cmd {cmd:#x} cryptoff not shifted"
            );
        }
    }

    fn strtab_span(buf: &[u8]) -> (usize, usize) {
        let ncmds = r32(buf, mh::NCMDS) as usize;
        let mut off = mh::SIZE;
        for _ in 0..ncmds {
            if r32(buf, off) == LC_SYMTAB {
                return (
                    r32(buf, off + symtab::STROFF) as usize,
                    r32(buf, off + symtab::STRSIZE) as usize,
                );
            }
            off += r32(buf, off + lc::CMDSIZE) as usize;
        }
        panic!("no LC_SYMTAB");
    }

    /// Regression: `nsyms` is the count at offset 12, not `stroff` at offset 16.
    #[test]
    fn nsyms_is_the_symbol_count_and_shift_preserves_strtab() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        let goblin_count = MachO::parse(&orig, 0).unwrap().symbols().count();
        assert_eq!(
            parse_thin(&orig).unwrap().nsyms as usize,
            goblin_count,
            "nsyms must equal the real symbol count, not stroff"
        );

        let (stroff0, strsize) = strtab_span(&orig);
        let original = orig[stroff0..stroff0 + strsize].to_vec();
        let long = format!("@rpath/{}.dylib", "libveryverylonginjectionname".repeat(3));
        let out = inject_weak_dylib(&orig, &long).unwrap();
        let (stroff1, strsize1) = strtab_span(&out);
        assert_eq!(
            stroff1,
            stroff0 + PAGE as usize,
            "strtab must move one page"
        );
        assert_eq!(
            &out[stroff1..stroff1 + strsize1],
            &original[..],
            "string table corrupted by the page shift"
        );
    }

    #[test]
    fn dylib_id_and_change_roundtrip() {
        let Some(dylib) = load("libinject.dylib") else {
            return;
        };

        let renamed = set_dylib_id(&dylib, "@rpath/renamed.dylib").unwrap();
        let m = MachO::parse(&renamed, 0).unwrap();
        assert_eq!(m.name, Some("@rpath/renamed.dylib"));
        objdump_clean(&renamed);

        let with_dep = inject_weak_dylib(&dylib, "@rpath/old.dylib").unwrap();
        let changed = change_dylib_path(&with_dep, "@rpath/old.dylib", "@rpath/new.dylib").unwrap();
        let m2 = MachO::parse(&changed, 0).unwrap();
        assert!(m2.libs.contains(&"@rpath/new.dylib"));
        assert!(!m2.libs.contains(&"@rpath/old.dylib"));
        objdump_clean(&changed);

        let noop = change_dylib_path(&dylib, "@rpath/does-not-exist", "x").unwrap();
        assert_eq!(noop, dylib);
    }

    #[test]
    fn set_dylib_id_rejects_executable() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        assert!(set_dylib_id(&orig, "x").is_err());
    }

    #[test]
    fn fat_dispatch_roundtrip() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        let fat = make_fat(&[&orig]);
        let out = inject_weak_dylib(&fat, "@rpath/libinject.dylib").unwrap();

        let mach = goblin::mach::Mach::parse(&out).unwrap();
        match mach {
            goblin::mach::Mach::Fat(fatbin) => {
                let arches = fatbin.arches().unwrap();
                assert_eq!(arches.len(), 1);
                let a = &arches[0];
                let slice = &out[a.offset as usize..(a.offset + a.size) as usize];
                let m = MachO::parse(slice, 0).unwrap();
                assert!(m.libs.contains(&"@rpath/libinject.dylib"));
            }
            _ => panic!("expected fat result"),
        }
    }

    #[test]
    fn thin_strips_non_arm64_slice() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        let fat = make_fat_typed(&[(CPU_TYPE_ARM64, &orig), (0x0100_0007, &orig)]);
        let out = thin_to_arm64(&fat).unwrap().expect("fat should be thinned");
        assert!(kind_is_thin(&out), "result must be a thin Mach-O");
        MachO::parse(&out, 0).expect("thinned slice must parse");
        objdump_clean(&out);
    }

    #[test]
    fn thin_noop_when_already_arm64_only() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        assert!(thin_to_arm64(&orig).unwrap().is_none());
        let fat = make_fat_typed(&[(CPU_TYPE_ARM64, &orig)]);
        assert!(thin_to_arm64(&fat).unwrap().is_none());
    }

    #[test]
    fn cryptid_zero_for_unencrypted_fixture() {
        let Some(orig) = load("main_arm64") else {
            return;
        };
        assert_eq!(encryption_cryptid(&orig).unwrap(), 0);
        let fat = make_fat_typed(&[(CPU_TYPE_ARM64, &orig)]);
        assert_eq!(encryption_cryptid(&fat).unwrap(), 0);
    }

    fn kind_is_thin(buf: &[u8]) -> bool {
        matches!(kind(buf), Kind::Thin64)
    }

    fn make_fat_typed(slices: &[(u32, &[u8])]) -> Vec<u8> {
        let arches: Vec<FatSlice> = slices
            .iter()
            .map(|(cputype, data)| FatSlice {
                cputype: *cputype,
                cpusubtype: 0,
                align: 14,
                data: data.to_vec(),
            })
            .collect();
        build_fat(false, &arches)
    }

    fn make_fat(slices: &[&[u8]]) -> Vec<u8> {
        let n = slices.len();
        let header = fat::ARCHS + n * fat_arch::STRIDE32;
        let align = 0x4000u64;
        let mut offsets = Vec::new();
        let mut cursor = header as u64;
        for s in slices {
            cursor = cursor.div_ceil(align) * align;
            offsets.push(cursor);
            cursor += s.len() as u64;
        }
        let mut out = vec![0u8; cursor as usize];
        out[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        out[fat::NARCH..fat::NARCH + 4].copy_from_slice(&(n as u32).to_be_bytes());
        for (i, s) in slices.iter().enumerate() {
            let base = fat::ARCHS + i * fat_arch::STRIDE32;
            out[base..base + 4].copy_from_slice(&0x0100_000cu32.to_be_bytes()); // arm64
            out[base + fat_arch::CPUSUBTYPE..base + fat_arch::OFFSET]
                .copy_from_slice(&0u32.to_be_bytes());
            out[base + fat_arch::OFFSET..base + fat_arch::SIZE32]
                .copy_from_slice(&(offsets[i] as u32).to_be_bytes());
            out[base + fat_arch::SIZE32..base + fat_arch::ALIGN32]
                .copy_from_slice(&(s.len() as u32).to_be_bytes());
            out[base + fat_arch::ALIGN32..base + fat_arch::STRIDE32]
                .copy_from_slice(&14u32.to_be_bytes()); // 2^14
            out[offsets[i] as usize..offsets[i] as usize + s.len()].copy_from_slice(s);
        }
        out
    }
}

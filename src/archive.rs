//! Zip surgery: recompression-free edits on `.ipa`/`.tipa` archives. The append
//! writer is hand-rolled because `ZipWriter::new_append` rejects duplicate
//! names, so it cannot replace an existing entry.

use std::fs::OpenOptions;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use binrw::{BinRead, BinWrite, binrw};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

fn fixed_time() -> DateTime {
    DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap()
}

const S_IFLNK: u32 = 0o120000;

pub const MODE_FILE: u32 = 0o100644;
pub const MODE_EXEC: u32 = 0o100755;
pub const MODE_SYMLINK: u32 = S_IFLNK | 0o777;
const S_IFDIR: u32 = 0o040000;
const MODE_DIR: u32 = S_IFDIR | 0o755;

struct Pending {
    name: String,
    data: Vec<u8>,
    mode: u32,
    symlink: bool,
    store: bool,
}

#[derive(Default)]
pub struct EditPlan {
    entries: Vec<Pending>,
    removed_exact: Vec<String>,
    removed_prefixes: Vec<String>,
    deterministic: bool,
}

impl EditPlan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_deterministic(&mut self, on: bool) {
        self.deterministic = on;
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.removed_exact.is_empty() && self.removed_prefixes.is_empty()
    }

    pub fn touches(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name == name)
    }

    pub fn remove(&mut self, name: impl Into<String>) {
        self.removed_exact.push(name.into());
    }

    pub fn remove_prefix(&mut self, prefix: impl Into<String>) {
        self.removed_prefixes.push(prefix.into());
    }

    /// A staged `put` overrides removal, so callers check `touches` first.
    fn is_removed(&self, name: &str) -> bool {
        self.removed_exact.iter().any(|n| n == name)
            || self
                .removed_prefixes
                .iter()
                .any(|p| name.starts_with(p.as_str()))
    }

    pub fn put(&mut self, name: impl Into<String>, data: Vec<u8>, mode: u32) {
        self.push(name.into(), data, mode, false, false);
    }

    pub fn put_stored(&mut self, name: impl Into<String>, data: Vec<u8>, mode: u32) {
        self.push(name.into(), data, mode, false, true);
    }

    pub fn put_symlink(&mut self, name: impl Into<String>, target: impl Into<String>) {
        self.push(
            name.into(),
            target.into().into_bytes(),
            MODE_SYMLINK,
            true,
            true,
        );
    }

    fn push(&mut self, name: String, data: Vec<u8>, mode: u32, symlink: bool, store: bool) {
        self.entries.retain(|e| e.name != name);
        self.entries.push(Pending {
            name,
            data,
            mode,
            symlink,
            store,
        });
    }

    fn edited_names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    fn options(&self, e: &Pending) -> SimpleFileOptions {
        let method = if e.store {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        let mut o = SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(e.mode)
            .large_file(e.data.len() as u64 > u32::MAX as u64);
        if self.deterministic {
            o = o.last_modified_time(fixed_time());
        }
        o
    }

    fn survivor_options(&self, mode: u32, mtime: Option<DateTime>) -> SimpleFileOptions {
        let mut opts = SimpleFileOptions::default().unix_permissions(mode);
        if self.deterministic {
            opts = opts.last_modified_time(fixed_time());
        } else if let Some(t) = mtime {
            opts = opts.last_modified_time(t);
        }
        opts
    }

    fn stageable_entries(&self) -> Result<Vec<&Pending>> {
        for e in &self.entries {
            if !is_safe_entry_name(&e.name) {
                bail!("refusing unsafe entry name (path traversal): {}", e.name);
            }
        }
        let mut v: Vec<&Pending> = self.entries.iter().collect();
        if self.deterministic {
            v.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Ok(v)
    }

    fn build_edits_zip(&self) -> Result<Vec<u8>> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for e in self.stageable_entries()? {
            let opts = self.options(e);
            if e.symlink {
                let target = String::from_utf8(e.data.clone())
                    .context("symlink target is not valid UTF-8")?;
                w.add_symlink(e.name.clone(), target, opts)?;
            } else {
                w.start_file(e.name.clone(), opts)?;
                w.write_all(&e.data)?;
            }
        }
        Ok(w.finish()?.into_inner())
    }

    /// Rewrites into a new archive: survivors raw-copied, edits substituted.
    pub fn commit_compact(&self, original: &[u8]) -> Result<Vec<u8>> {
        let mut src = ZipArchive::new(Cursor::new(original))?;
        let mut out = ZipWriter::new(Cursor::new(Vec::new()));

        let edited = self.edited_names();
        for i in 0..src.len() {
            let name = src.by_index_raw(i)?.name().to_owned();
            if edited.contains(&name.as_str()) {
                continue;
            }
            if self.is_removed(&name) {
                continue;
            }
            // raw_copy_file stamps S_IFREG onto the mode, so re-create symlinks
            // and directories.
            let (is_link, is_dir) = {
                let e = src.by_index(i)?;
                (e.is_symlink(), e.is_dir())
            };
            if is_dir {
                let e = src.by_index(i)?;
                let mode = e.unix_mode().unwrap_or(MODE_DIR);
                let mtime = e.last_modified();
                drop(e);
                out.add_directory(name, self.survivor_options(mode, mtime))?;
            } else if is_link {
                let mut f = src.by_index(i)?;
                let mode = f.unix_mode().unwrap_or(MODE_SYMLINK);
                let mtime = f.last_modified();
                let mut target = String::new();
                f.read_to_string(&mut target)?;
                out.add_symlink(name, target, self.survivor_options(mode, mtime))?;
            } else {
                let file = src.by_index_raw(i)?;
                out.raw_copy_file(file)?;
            }
        }
        for e in self.stageable_entries()? {
            let opts = self.options(e);
            if e.symlink {
                let target = String::from_utf8(e.data.clone())
                    .context("symlink target is not valid UTF-8")?;
                out.add_symlink(e.name.clone(), target, opts)?;
            } else {
                out.start_file(e.name.clone(), opts)?;
                out.write_all(&e.data)?;
            }
        }
        Ok(out.finish()?.into_inner())
    }

    /// In-place append: survivors stay verbatim at their existing offsets.
    pub fn commit_append(&self, original: &[u8]) -> Result<Vec<u8>> {
        let central = parse_central_directory(original)?;
        let tail = self.build_append_tail(&central, central.cd_offset)?;
        let mut out = original[..central.cd_offset as usize].to_vec();
        out.extend_from_slice(&tail);
        Ok(out)
    }

    pub fn commit_append_in_place(&self, path: &Path) -> Result<()> {
        let mut f = OpenOptions::new().read(true).write(true).open(path)?;
        let central = read_central_from_file(&mut f)?;
        let tail = self.build_append_tail(&central, central.cd_offset)?;
        f.seek(SeekFrom::Start(central.cd_offset))?;
        f.write_all(&tail)?;
        f.set_len(central.cd_offset + tail.len() as u64)?;
        Ok(())
    }

    /// `base_offset` is where the tail will live, so appended entries get
    /// correct absolute local-header offsets.
    fn build_append_tail(&self, central: &Central, base_offset: u64) -> Result<Vec<u8>> {
        let edited = self.edited_names();
        let mini_bytes = self.build_edits_zip()?;
        let mini = parse_central_directory(&mini_bytes)?;

        let mut tail = Vec::new();
        let mut new_records: Vec<Vec<u8>> = Vec::with_capacity(mini.records.len());
        for rec in &mini.records {
            let new_offset = base_offset + tail.len() as u64;
            let span = local_record_span(&mini_bytes, rec, &mini)?;
            tail.extend_from_slice(&mini_bytes[span.0..span.1]);
            new_records.push(with_local_offset(&rec.raw, new_offset)?);
        }

        let new_cd_offset = base_offset + tail.len() as u64;
        let mut count: u64 = 0;
        for rec in &central.records {
            if edited.contains(&rec.name.as_str()) || self.is_removed(&rec.name) {
                continue;
            }
            tail.extend_from_slice(&rec.raw);
            count += 1;
        }
        for cd in &new_records {
            tail.extend_from_slice(cd);
            count += 1;
        }
        let new_cd_size = base_offset + tail.len() as u64 - new_cd_offset;

        write_end_of_central_directory(
            &mut tail,
            count,
            new_cd_offset,
            new_cd_size,
            &central.comment,
        )?;
        Ok(tail)
    }
}

const OFFSET_SATURATED: u32 = 0xFFFF_FFFF;
const U16_SATURATED: u16 = 0xFFFF;
const ZIP64_EXTRA_ID: u16 = 0x0001;

#[binrw]
#[brw(little, magic = b"PK\x05\x06")]
struct Eocd {
    disk_number: u16,
    cd_start_disk: u16,
    entries_this_disk: u16,
    total_entries: u16,
    cd_size: u32,
    cd_offset: u32,
    #[br(temp)]
    #[bw(calc = comment.len() as u16)]
    comment_len: u16,
    #[br(count = comment_len)]
    comment: Vec<u8>,
}

/// Fixed portion only; the trailing extensible data sector is ignored.
#[binrw]
#[brw(little, magic = b"PK\x06\x06")]
struct Zip64Eocd {
    record_size: u64,
    version_made_by: u16,
    version_needed: u16,
    disk_number: u32,
    cd_start_disk: u32,
    entries_this_disk: u64,
    total_entries: u64,
    cd_size: u64,
    cd_offset: u64,
}

#[binrw]
#[brw(little, magic = b"PK\x06\x07")]
struct Zip64Locator {
    disk_with_zip64_eocd: u32,
    zip64_eocd_offset: u64,
    total_disks: u32,
}

/// Reads and writes byte-for-byte, so a parsed record round-trips exactly.
#[binrw]
#[brw(little, magic = b"PK\x01\x02")]
struct CentralHeader {
    version_made_by: u16,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    #[br(temp)]
    #[bw(calc = file_name.len() as u16)]
    file_name_len: u16,
    #[br(temp)]
    #[bw(calc = extra.len() as u16)]
    extra_len: u16,
    #[br(temp)]
    #[bw(calc = comment.len() as u16)]
    comment_len: u16,
    disk_start: u16,
    internal_attrs: u16,
    external_attrs: u32,
    local_header_offset: u32,
    #[br(count = file_name_len)]
    file_name: Vec<u8>,
    #[br(count = extra_len)]
    extra: Vec<u8>,
    #[br(count = comment_len)]
    comment: Vec<u8>,
}

#[binrw]
#[brw(little)]
struct ExtraField {
    id: u16,
    #[br(temp)]
    #[bw(calc = data.len() as u16)]
    size: u16,
    #[br(count = size)]
    data: Vec<u8>,
}

impl CentralHeader {
    /// The ZIP64 extra holds uncompressed size, compressed size then offset,
    /// each present only if its own 32-bit field is saturated.
    fn resolved_local_offset(&self) -> u64 {
        if self.local_header_offset != OFFSET_SATURATED {
            return self.local_header_offset as u64;
        }
        let mut cur = Cursor::new(self.extra.as_slice());
        while let Ok(field) = ExtraField::read(&mut cur) {
            if field.id != ZIP64_EXTRA_ID {
                continue;
            }
            let mut z = Cursor::new(field.data.as_slice());
            if self.uncompressed_size == OFFSET_SATURATED {
                let _ = u64::read_le(&mut z);
            }
            if self.compressed_size == OFFSET_SATURATED {
                let _ = u64::read_le(&mut z);
            }
            if let Ok(offset) = u64::read_le(&mut z) {
                return offset;
            }
        }
        self.local_header_offset as u64
    }
}

struct CentralRecord {
    name: String,
    raw: Vec<u8>,
    local_offset: u64,
}

struct Central {
    records: Vec<CentralRecord>,
    cd_offset: u64,
    comment: Vec<u8>,
}

fn eocd_is_saturated(eocd: &Eocd) -> bool {
    eocd.total_entries == U16_SATURATED
        || eocd.cd_size == OFFSET_SATURATED
        || eocd.cd_offset == OFFSET_SATURATED
}

fn read_at<T>(data: &[u8], pos: usize) -> Option<T>
where
    T: for<'a> BinRead<Args<'a> = ()> + binrw::meta::ReadEndian,
{
    if pos > data.len() {
        return None;
    }
    let mut cur = Cursor::new(data);
    cur.set_position(pos as u64);
    T::read(&mut cur).ok()
}

fn parse_central_directory(data: &[u8]) -> Result<Central> {
    let (eocd_pos, eocd) = find_eocd(data, 0).context("no end-of-central-directory record")?;
    let mut total = eocd.total_entries as u64;
    let mut cd_offset = eocd.cd_offset as u64;

    if eocd_is_saturated(&eocd)
        && let Some(loc) = read_at::<Zip64Locator>(data, eocd_pos.wrapping_sub(20))
        && let Some(z64) = read_at::<Zip64Eocd>(data, loc.zip64_eocd_offset as usize)
    {
        total = z64.total_entries;
        cd_offset = z64.cd_offset;
    }

    if cd_offset as usize > data.len() {
        bail!("central directory offset {cd_offset} out of range (corrupt archive)");
    }
    let records = parse_central_records(&data[cd_offset as usize..], total)?;
    Ok(Central {
        records,
        cd_offset,
        comment: eocd.comment,
    })
}

fn parse_central_records(data: &[u8], total: u64) -> Result<Vec<CentralRecord>> {
    let mut cur = Cursor::new(data);
    let mut records = Vec::with_capacity(total as usize);
    for _ in 0..total {
        let start = cur.position() as usize;
        let header = CentralHeader::read(&mut cur)
            .map_err(|e| anyhow::anyhow!("malformed central directory record: {e}"))?;
        let end = cur.position() as usize;
        records.push(CentralRecord {
            name: String::from_utf8_lossy(&header.file_name).into_owned(),
            raw: data[start..end].to_vec(),
            local_offset: header.resolved_local_offset(),
        });
    }
    Ok(records)
}

fn read_central_from_file(f: &mut std::fs::File) -> Result<Central> {
    let file_len = f.seek(SeekFrom::End(0))?;
    // 22-byte EOCD + up to 64KiB comment + the 20-byte ZIP64 locator ahead of it.
    let tail_len = file_len.min(22 + 0xFFFF + 20) as usize;
    let mut tail = vec![0u8; tail_len];
    f.seek(SeekFrom::Start(file_len - tail_len as u64))?;
    f.read_exact(&mut tail)?;

    let (eocd_pos, eocd) = find_eocd(&tail, file_len - tail_len as u64)
        .context("no end-of-central-directory record")?;
    let mut total = eocd.total_entries as u64;
    let mut cd_size = eocd.cd_size as u64;
    let mut cd_offset = eocd.cd_offset as u64;

    if eocd_is_saturated(&eocd)
        && let Some(loc) = read_at::<Zip64Locator>(&tail, eocd_pos.wrapping_sub(20))
    {
        let mut hdr = [0u8; 56];
        f.seek(SeekFrom::Start(loc.zip64_eocd_offset))?;
        f.read_exact(&mut hdr)?;
        if let Some(z64) = read_at::<Zip64Eocd>(&hdr, 0) {
            total = z64.total_entries;
            cd_size = z64.cd_size;
            cd_offset = z64.cd_offset;
        }
    }

    // Check before allocating: a corrupt EOCD must not drive a ~4GiB alloc.
    if cd_offset
        .checked_add(cd_size)
        .is_none_or(|end| end > file_len)
    {
        bail!("central directory out of range (corrupt or unsupported archive)");
    }

    let mut cd_bytes = vec![0u8; cd_size as usize];
    f.seek(SeekFrom::Start(cd_offset))?;
    f.read_exact(&mut cd_bytes)?;
    let records = parse_central_records(&cd_bytes, total)?;
    Ok(Central {
        records,
        cd_offset,
        comment: eocd.comment,
    })
}

/// `base` is `data`'s offset within the file, so the central-directory check
/// compares absolute offsets.
fn find_eocd(data: &[u8], base: u64) -> Option<(usize, Eocd)> {
    if data.len() < 22 {
        return None;
    }
    let min = data.len().saturating_sub(22 + 0xFFFF);
    for pos in (min..=data.len() - 22).rev() {
        if let Some(eocd) = read_at::<Eocd>(data, pos) {
            // Rejects a fake `PK\x05\x06` planted in a comment.
            let cd_before = eocd_is_saturated(&eocd)
                || eocd.cd_offset as u64 + eocd.cd_size as u64 <= base + pos as u64;
            if cd_before && pos + 22 + eocd.comment.len() == data.len() {
                return Some((pos, eocd));
            }
        }
    }
    None
}

/// A local record runs from its own offset to the next entry's, or to the
/// central directory for the last entry.
fn local_record_span(data: &[u8], rec: &CentralRecord, all: &Central) -> Result<(usize, usize)> {
    let start = rec.local_offset as usize;
    let mut end = all.cd_offset as usize;
    for other in &all.records {
        let o = other.local_offset as usize;
        if o > start && o < end {
            end = o;
        }
    }
    if start > data.len() || end > data.len() || start > end {
        bail!("local record span out of bounds");
    }
    Ok((start, end))
}

fn with_local_offset(raw: &[u8], offset: u64) -> Result<Vec<u8>> {
    if offset > 0xFFFF_FFFE {
        bail!(
            "edited entry offset {offset} exceeds 4 GiB; ZIP64 append not yet supported \
             (use --compact for archives this large)"
        );
    }
    let mut header = CentralHeader::read(&mut Cursor::new(raw))
        .map_err(|e| anyhow::anyhow!("re-reading central record: {e}"))?;
    header.local_header_offset = offset as u32;
    let mut out = Cursor::new(Vec::new());
    header
        .write(&mut out)
        .map_err(|e| anyhow::anyhow!("re-writing central record: {e}"))?;
    Ok(out.into_inner())
}

fn write_end_of_central_directory(
    out: &mut Vec<u8>,
    count: u64,
    cd_offset: u64,
    cd_size: u64,
    comment: &[u8],
) -> Result<()> {
    let need_zip64 =
        count > U16_SATURATED as u64 || cd_offset > 0xFFFF_FFFE || cd_size > 0xFFFF_FFFE;

    let mut cur = Cursor::new(std::mem::take(out));
    cur.seek(SeekFrom::End(0))?;

    if need_zip64 {
        // The ZIP64 EOCD sits immediately after the central directory.
        let z64_offset = cd_offset + cd_size;
        Zip64Eocd {
            record_size: 44,
            version_made_by: 45,
            version_needed: 45,
            disk_number: 0,
            cd_start_disk: 0,
            entries_this_disk: count,
            total_entries: count,
            cd_size,
            cd_offset,
        }
        .write(&mut cur)
        .map_err(binrw_err)?;
        Zip64Locator {
            disk_with_zip64_eocd: 0,
            zip64_eocd_offset: z64_offset,
            total_disks: 1,
        }
        .write(&mut cur)
        .map_err(binrw_err)?;
    }

    Eocd {
        disk_number: 0,
        cd_start_disk: 0,
        entries_this_disk: count.min(U16_SATURATED as u64) as u16,
        total_entries: count.min(U16_SATURATED as u64) as u16,
        cd_size: cd_size.min(OFFSET_SATURATED as u64) as u32,
        cd_offset: cd_offset.min(OFFSET_SATURATED as u64) as u32,
        comment: comment.to_vec(),
    }
    .write(&mut cur)
    .map_err(binrw_err)?;

    *out = cur.into_inner();
    Ok(())
}

fn binrw_err(e: binrw::Error) -> anyhow::Error {
    anyhow::anyhow!("zip serialisation failed: {e}")
}

pub fn read_entry(original: &[u8], name: &str) -> Result<Option<Vec<u8>>> {
    let mut src = ZipArchive::new(Cursor::new(original))?;
    match src.by_name(name) {
        Ok(mut f) => {
            let mut buf = Vec::with_capacity(f.size() as usize);
            f.read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn list_names(original: &[u8]) -> Result<Vec<String>> {
    let central = parse_central_directory(original)?;
    Ok(central.records.into_iter().map(|r| r.name).collect())
}

pub fn is_symlink_mode(mode: u32) -> bool {
    mode & 0o170000 == S_IFLNK
}

/// No absolute path, backslash, or `.`/`..`/empty component; one trailing
/// slash (a directory entry) is allowed.
pub fn is_safe_entry_name(name: &str) -> bool {
    if name.is_empty() || name.starts_with('/') || name.contains('\\') {
        return false;
    }
    let body = name.strip_suffix('/').unwrap_or(name);
    body.split('/')
        .all(|c| !c.is_empty() && c != "." && c != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_entry_names() {
        for bad in [
            "../evil", "a/../b", "/abs", "a/./b", "a\\b", "", "..", "a//b",
        ] {
            assert!(!is_safe_entry_name(bad), "{bad:?} should be unsafe");
        }
        for ok in [
            "Payload/App.app/Frameworks/x.dylib",
            "Payload/App.app/dir/",
            "a.b.c/x",
        ] {
            assert!(is_safe_entry_name(ok), "{ok:?} should be safe");
        }

        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file("Payload/App.app/Info.plist", SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"x").unwrap();
        let ipa = w.finish().unwrap().into_inner();

        let mut plan = EditPlan::new();
        plan.put(
            "Payload/App.app/Frameworks/X.framework/../../../../tmp/evil",
            b"x".to_vec(),
            0o100644,
        );
        assert!(
            plan.commit_append(&ipa).is_err(),
            "append must reject traversal"
        );
        assert!(
            plan.commit_compact(&ipa).is_err(),
            "compact must reject traversal"
        );
    }

    #[test]
    fn central_header_roundtrips_byte_for_byte() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(
            "deep/path/name.txt",
            SimpleFileOptions::default().unix_permissions(0o100644),
        )
        .unwrap();
        w.write_all(b"hello world").unwrap();
        w.add_symlink(
            "link",
            "name.txt",
            SimpleFileOptions::default().unix_permissions(0o120777),
        )
        .unwrap();
        let bytes = w.finish().unwrap().into_inner();

        let central = parse_central_directory(&bytes).unwrap();
        assert_eq!(central.records.len(), 2);
        for rec in &central.records {
            let again = with_local_offset(&rec.raw, rec.local_offset).unwrap();
            assert_eq!(again, rec.raw, "central header lost bytes on round-trip");
        }
    }
}

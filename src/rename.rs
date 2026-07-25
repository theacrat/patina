//! Rename op: set `CFBundleDisplayName` + `CFBundleName` in `Info.plist`, and
//! update those keys in `InfoPlist.strings` *only where already present*.

use std::io::Cursor;

use anyhow::{Context, Result};
use plist::Value;

const KEYS: [&str; 2] = ["CFBundleDisplayName", "CFBundleName"];

const UTF16_LE_BOM: [u8; 2] = [0xFF, 0xFE];
const UTF16_BE_BOM: [u8; 2] = [0xFE, 0xFF];
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

pub fn set_bundle_name(info_plist: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut value =
        Value::from_reader(Cursor::new(info_plist)).context("Info.plist is not a valid plist")?;
    let dict = value
        .as_dictionary_mut()
        .context("Info.plist root is not a dictionary")?;
    for key in KEYS {
        dict.insert(key.into(), Value::String(name.into()));
    }
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &value).context("failed to re-encode Info.plist")?;
    Ok(out)
}

/// `None` when nothing changed or the file cannot be parsed.
pub fn update_infoplist_strings(data: &[u8], name: &str) -> Option<Vec<u8>> {
    // Strip a leading UTF-8 BOM so `<?xml` behind one is still recognised.
    let body = data.strip_prefix(&UTF8_BOM).unwrap_or(data);
    if body.starts_with(b"bplist00") || first_nonspace_is(body, b'<') {
        return update_strings_plist(body, name);
    }
    update_strings_text(data, name)
}

fn first_nonspace_is(data: &[u8], c: u8) -> bool {
    data.iter().find(|b| !b.is_ascii_whitespace()) == Some(&c)
}

fn update_strings_plist(data: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut value = Value::from_reader(Cursor::new(data)).ok()?;
    let dict = value.as_dictionary_mut()?;
    let mut changed = false;
    for key in KEYS {
        if dict.contains_key(key) {
            dict.insert(key.into(), Value::String(name.into()));
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &value).ok()?;
    Some(out)
}

fn update_strings_text(data: &[u8], name: &str) -> Option<Vec<u8>> {
    let (mut text, encoding) = decode_text(data)?;
    let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
    let mut changed = false;
    for key in KEYS {
        // `.strings` is last-duplicate-wins, so every occurrence must change.
        // Re-mask each pass: masking preserves length, but the splice shifts bytes.
        let mut from = 0;
        while let Some((start, end)) = value_range(&mask_comments(&text), key, from) {
            text = format!("{}{}{}", &text[..start], escaped, &text[end..]);
            changed = true;
            from = start + escaped.len();
        }
    }
    if !changed {
        return None;
    }
    Some(encoding.encode(&text))
}

/// Blanks comment bytes to spaces, preserving byte positions. Quoted strings
/// and non-ASCII bytes are left intact.
fn mask_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    let mut in_str = false;
    let blank = |out: &mut [u8], i: usize| {
        if out[i] < 0x80 && !out[i].is_ascii_whitespace() {
            out[i] = b' ';
        }
    };
    while i < b.len() {
        if in_str {
            match b[i] {
                b'\\' => i += 2,
                b'"' => {
                    in_str = false;
                    i += 1;
                }
                _ => i += 1,
            }
        } else if b[i] == b'"' {
            in_str = true;
            i += 1;
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            blank(&mut out, i);
            blank(&mut out, i + 1);
            i += 2;
            while i < b.len() {
                let end = b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/';
                blank(&mut out, i);
                i += 1;
                if end {
                    blank(&mut out, i);
                    i += 1;
                    break;
                }
            }
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                blank(&mut out, i);
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

enum Encoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    fn encode(&self, s: &str) -> Vec<u8> {
        match self {
            Encoding::Utf8 => s.as_bytes().to_vec(),
            Encoding::Utf8Bom => {
                let mut v = UTF8_BOM.to_vec();
                v.extend_from_slice(s.as_bytes());
                v
            }
            Encoding::Utf16Le => {
                let mut v = UTF16_LE_BOM.to_vec();
                for u in s.encode_utf16() {
                    v.extend_from_slice(&u.to_le_bytes());
                }
                v
            }
            Encoding::Utf16Be => {
                let mut v = UTF16_BE_BOM.to_vec();
                for u in s.encode_utf16() {
                    v.extend_from_slice(&u.to_be_bytes());
                }
                v
            }
        }
    }
}

fn decode_text(data: &[u8]) -> Option<(String, Encoding)> {
    if let Some(body) = data.strip_prefix(&UTF16_LE_BOM) {
        if body.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return Some((String::from_utf16(&units).ok()?, Encoding::Utf16Le));
    }
    if let Some(body) = data.strip_prefix(&UTF16_BE_BOM) {
        if body.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return Some((String::from_utf16(&units).ok()?, Encoding::Utf16Be));
    }
    if data.starts_with(&UTF8_BOM) {
        return Some((
            String::from_utf8(data[UTF8_BOM.len()..].to_vec()).ok()?,
            Encoding::Utf8Bom,
        ));
    }
    Some((String::from_utf8(data.to_vec()).ok()?, Encoding::Utf8))
}

/// Byte range of the value content of `"key" = "value";` at or after `from`.
fn value_range(text: &str, key: &str, from: usize) -> Option<(usize, usize)> {
    let needle = format!("\"{key}\"");
    let key_pos = text.get(from..)?.find(&needle)? + from;
    let after_key = key_pos + needle.len();

    let rest = &text[after_key..];
    let eq_rel = rest.find('=')?;
    let value_region = &rest[eq_rel + 1..];
    let open_rel = value_region.find('"')?;
    if !value_region[..open_rel].trim().is_empty() {
        return None;
    }
    let value_start = after_key + eq_rel + 1 + open_rel + 1;

    let bytes = text.as_bytes();
    let mut i = value_start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => break,
            _ => i += 1,
        }
    }
    if i >= bytes.len() {
        return None;
    }
    Some((value_start, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plist_name(bytes: &[u8], key: &str) -> Option<String> {
        let v = Value::from_reader(Cursor::new(bytes)).ok()?;
        v.as_dictionary()?.get(key)?.as_string().map(str::to_owned)
    }

    #[test]
    fn sets_both_keys_in_info_plist() {
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleName".into(), "Old".into());
        d.insert("CFBundleDisplayName".into(), "Old".into());
        d.insert("CFBundleIdentifier".into(), "com.x".into());
        let mut input = Vec::new();
        plist::to_writer_binary(&mut input, &Value::Dictionary(d)).unwrap();

        let out = set_bundle_name(&input, "New").unwrap();
        assert_eq!(plist_name(&out, "CFBundleName").as_deref(), Some("New"));
        assert_eq!(
            plist_name(&out, "CFBundleDisplayName").as_deref(),
            Some("New")
        );
        assert_eq!(
            plist_name(&out, "CFBundleIdentifier").as_deref(),
            Some("com.x")
        );
    }

    #[test]
    fn info_plist_adds_display_name_if_absent() {
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleName".into(), "Old".into());
        let mut input = Vec::new();
        plist::to_writer_binary(&mut input, &Value::Dictionary(d)).unwrap();
        let out = set_bundle_name(&input, "New").unwrap();
        assert_eq!(
            plist_name(&out, "CFBundleDisplayName").as_deref(),
            Some("New")
        );
    }

    #[test]
    fn text_strings_updates_only_present_keys() {
        let input = b"/* c */\n\"CFBundleName\" = \"Old\";\n\"OtherKey\" = \"keep\";\n";
        let out = update_infoplist_strings(input, "New").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("\"CFBundleName\" = \"New\";"));
        assert!(s.contains("\"OtherKey\" = \"keep\";"));
        assert!(!s.contains("CFBundleDisplayName"));
    }

    #[test]
    fn text_strings_absent_keys_returns_none() {
        let input = b"\"SomethingElse\" = \"x\";\n";
        assert!(update_infoplist_strings(input, "New").is_none());
    }

    #[test]
    fn utf16le_roundtrips() {
        let mut input = vec![0xFF, 0xFE];
        for u in "\"CFBundleDisplayName\" = \"Old\";".encode_utf16() {
            input.extend_from_slice(&u.to_le_bytes());
        }
        let out = update_infoplist_strings(&input, "Nìce").unwrap();
        assert!(out.starts_with(&[0xFF, 0xFE]));
        let units: Vec<u16> = out[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16(&units).unwrap();
        assert!(s.contains("\"CFBundleDisplayName\" = \"Nìce\";"), "{s}");
    }

    #[test]
    fn binary_plist_strings_updates_present_key() {
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleName".into(), "Old".into());
        let mut input = Vec::new();
        plist::to_writer_binary(&mut input, &Value::Dictionary(d)).unwrap();
        let out = update_infoplist_strings(&input, "New").unwrap();
        assert_eq!(plist_name(&out, "CFBundleName").as_deref(), Some("New"));
    }

    #[test]
    fn text_strings_ignores_key_inside_comment() {
        let input =
            b"/* e.g. \"CFBundleName\" = \"IN COMMENT\"; */\n\"CFBundleName\" = \"Real\";\n";
        let out = update_infoplist_strings(input, "New").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("\"CFBundleName\" = \"New\";"),
            "real value must change: {s}"
        );
        assert!(s.contains("IN COMMENT"), "comment must be left intact: {s}");
    }

    #[test]
    fn text_strings_double_slash_in_value_is_not_a_comment() {
        let input = b"\"CFBundleName\" = \"scheme://host\";\n";
        let out = update_infoplist_strings(input, "New").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("\"CFBundleName\" = \"New\";"), "{s}");
    }

    #[test]
    fn xml_strings_with_utf8_bom_is_recognised() {
        let mut input = vec![0xEF, 0xBB, 0xBF];
        input.extend_from_slice(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleName</key><string>Old</string></dict></plist>"#,
        );
        let out = update_infoplist_strings(&input, "New").unwrap();
        let v = Value::from_reader(Cursor::new(out)).unwrap();
        assert_eq!(
            v.as_dictionary().unwrap()["CFBundleName"].as_string(),
            Some("New")
        );
    }

    #[test]
    fn text_strings_updates_all_duplicate_keys() {
        let input = b"\"CFBundleName\" = \"A\";\n\"CFBundleName\" = \"B\";\n";
        let out = update_infoplist_strings(input, "New").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(
            s.matches("= \"New\";").count(),
            2,
            "both duplicates updated: {s}"
        );
        assert!(!s.contains("\"A\"") && !s.contains("\"B\""), "{s}");
    }

    #[test]
    fn utf16_odd_length_is_rejected() {
        let mut input = UTF16_LE_BOM.to_vec();
        for u in "\"CFBundleName\" = \"X\";".encode_utf16() {
            input.extend_from_slice(&u.to_le_bytes());
        }
        input.push(0x00);
        assert!(update_infoplist_strings(&input, "New").is_none());
    }

    #[test]
    fn unparseable_returns_none() {
        let input = [0x00, 0xC0, 0xFF, 0x01, 0x02];
        assert!(update_infoplist_strings(&input, "New").is_none());
    }
}

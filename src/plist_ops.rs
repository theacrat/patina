//! `Info.plist` key writes and merges. Every function takes and returns raw
//! plist bytes (binary out) so callers can chain edits and write the entry once.

use std::io::Cursor;

use anyhow::{Context, Result};
use plist::{Dictionary, Value};

fn load(info: &[u8]) -> Result<Value> {
    Value::from_reader(Cursor::new(info)).context("Info.plist is not a valid plist")
}

fn dump(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, value).context("failed to re-encode Info.plist")?;
    Ok(out)
}

fn with_root<F>(info: &[u8], f: F) -> Result<Vec<u8>>
where
    F: FnOnce(&mut Dictionary),
{
    let mut value = load(info)?;
    let root = value
        .as_dictionary_mut()
        .context("Info.plist root is not a dictionary")?;
    f(root);
    dump(&value)
}

pub fn set_bundle_id(info: &[u8], id: &str) -> Result<Vec<u8>> {
    with_root(info, |d| {
        d.insert("CFBundleIdentifier".into(), Value::String(id.into()));
    })
}

pub fn set_version(info: &[u8], version: &str) -> Result<Vec<u8>> {
    with_root(info, |d| {
        d.insert(
            "CFBundleShortVersionString".into(),
            Value::String(version.into()),
        );
        d.insert("CFBundleVersion".into(), Value::String(version.into()));
    })
}

pub fn set_min_os(info: &[u8], version: &str) -> Result<Vec<u8>> {
    with_root(info, |d| {
        d.insert("MinimumOSVersion".into(), Value::String(version.into()));
    })
}

pub fn enable_file_sharing(info: &[u8]) -> Result<Vec<u8>> {
    with_root(info, |d| {
        d.insert("UIFileSharingEnabled".into(), Value::Boolean(true));
        d.insert(
            "LSSupportsOpeningDocumentsInPlace".into(),
            Value::Boolean(true),
        );
    })
}

pub fn remove_key(info: &[u8], key: &str) -> Result<Vec<u8>> {
    with_root(info, |d| {
        d.remove(key);
    })
}

/// Dicts merge recursively; any other overlay value replaces the base.
pub fn merge_plist(info: &[u8], overlay: &[u8]) -> Result<Vec<u8>> {
    let mut base = load(info)?;
    let overlay = load(overlay).context("--merge-plist file is not a valid plist")?;
    let base_dict = base
        .as_dictionary_mut()
        .context("Info.plist root is not a dictionary")?;
    let overlay_dict = overlay
        .as_dictionary()
        .context("--merge-plist file root is not a dictionary")?;
    merge_dict(base_dict, overlay_dict);
    dump(&base)
}

/// Past this depth overlay subtrees are inserted wholesale, bounding stack use.
const MAX_MERGE_DEPTH: usize = 64;

fn merge_dict(base: &mut Dictionary, overlay: &Dictionary) {
    merge_dict_at(base, overlay, 0);
}

fn merge_dict_at(base: &mut Dictionary, overlay: &Dictionary, depth: usize) {
    for (key, ov) in overlay {
        match (
            base.get_mut(key).and_then(Value::as_dictionary_mut),
            ov.as_dictionary(),
        ) {
            (Some(base_sub), Some(ov_sub)) if depth < MAX_MERGE_DEPTH => {
                merge_dict_at(base_sub, ov_sub, depth + 1)
            }
            _ => {
                base.insert(key.clone(), ov.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plist_of(bytes: &[u8]) -> Value {
        Value::from_reader(Cursor::new(bytes)).unwrap()
    }

    fn info(pairs: &[(&str, Value)]) -> Vec<u8> {
        let mut d = Dictionary::new();
        for (k, v) in pairs {
            d.insert((*k).into(), v.clone());
        }
        dump(&Value::Dictionary(d)).unwrap()
    }

    #[test]
    fn version_sets_both_keys() {
        let out = set_version(&info(&[]), "3.1").unwrap();
        let d = plist_of(&out);
        let d = d.as_dictionary().unwrap();
        assert_eq!(d["CFBundleShortVersionString"].as_string(), Some("3.1"));
        assert_eq!(d["CFBundleVersion"].as_string(), Some("3.1"));
    }

    #[test]
    fn bundle_id_and_min_os() {
        let out = set_bundle_id(&info(&[]), "com.x.y").unwrap();
        let out = set_min_os(&out, "14.0").unwrap();
        let v = plist_of(&out);
        let d = v.as_dictionary().unwrap();
        assert_eq!(d["CFBundleIdentifier"].as_string(), Some("com.x.y"));
        assert_eq!(d["MinimumOSVersion"].as_string(), Some("14.0"));
    }

    #[test]
    fn file_sharing_sets_both_flags_true() {
        let v = plist_of(&enable_file_sharing(&info(&[])).unwrap());
        let d = v.as_dictionary().unwrap();
        assert_eq!(d["UIFileSharingEnabled"].as_boolean(), Some(true));
        assert_eq!(
            d["LSSupportsOpeningDocumentsInPlace"].as_boolean(),
            Some(true)
        );
    }

    #[test]
    fn remove_key_deletes_and_is_idempotent() {
        let base = info(&[("UISupportedDevices", Value::Array(vec!["iPhone1,1".into()]))]);
        let out = remove_key(&base, "UISupportedDevices").unwrap();
        assert!(
            !plist_of(&out)
                .as_dictionary()
                .unwrap()
                .contains_key("UISupportedDevices")
        );
        let again = remove_key(&out, "UISupportedDevices").unwrap();
        assert!(
            !plist_of(&again)
                .as_dictionary()
                .unwrap()
                .contains_key("UISupportedDevices")
        );
    }

    #[test]
    fn merge_is_recursive_and_overrides_scalars() {
        let mut inner = Dictionary::new();
        inner.insert("keep".into(), Value::String("orig".into()));
        inner.insert("override".into(), Value::String("orig".into()));
        let base = info(&[
            ("CFBundleName", Value::String("Base".into())),
            ("Nested", Value::Dictionary(inner)),
        ]);

        let mut ov_inner = Dictionary::new();
        ov_inner.insert("override".into(), Value::String("new".into()));
        ov_inner.insert("added".into(), Value::String("new".into()));
        let mut ov = Dictionary::new();
        ov.insert("Nested".into(), Value::Dictionary(ov_inner));
        ov.insert("CFBundleName".into(), Value::String("Merged".into()));
        let overlay = dump(&Value::Dictionary(ov)).unwrap();

        let v = plist_of(&merge_plist(&base, &overlay).unwrap());
        let d = v.as_dictionary().unwrap();
        assert_eq!(d["CFBundleName"].as_string(), Some("Merged"));
        let nested = d["Nested"].as_dictionary().unwrap();
        assert_eq!(
            nested["keep"].as_string(),
            Some("orig"),
            "untouched key preserved"
        );
        assert_eq!(
            nested["override"].as_string(),
            Some("new"),
            "scalar overridden"
        );
        assert_eq!(nested["added"].as_string(), Some("new"), "new key added");
    }
}

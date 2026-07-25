//! Loose-file icon variants plus `CFBundleIcons`/`CFBundleIcons~ipad` patching.
//! iOS resolves a base name (`Alt60x60`) to on-disk `<base><@scale>.png`.

use std::io::Cursor;

use anyhow::{Context, Result};
use image::imageops::FilterType;
use plist::Value;

pub struct IconFile {
    pub filename: String,
    pub png: Vec<u8>,
    pub pixels: u32,
}

pub struct AltIcon {
    pub name: String,
    pub files: Vec<IconFile>,
    pub iphone_bases: Vec<String>,
    pub ipad_bases: Vec<String>,
}

// (base, scale suffix, pixels, is_ipad)
const VARIANTS: [(&str, &str, u32, bool); 4] = [
    ("60x60", "@2x", 120, false),
    ("60x60", "@3x", 180, false),
    ("76x76", "@2x", 152, true),
    ("83.5x83.5", "@2x", 167, true),
];

/// scar never resamples, so a replacement must be offered at every size; sizes the catalogue lacks go unmatched.
pub const ICON_SIZES: &[u32] = &[20, 29, 40, 58, 60, 76, 80, 87, 120, 152, 167, 180, 1024];

pub fn render_sizes(source_png: &[u8], sizes: &[u32]) -> Result<Vec<(u32, Vec<u8>)>> {
    let img =
        image::load_from_memory(source_png).context("icon source is not a decodable image")?;
    let mut out = Vec::with_capacity(sizes.len());
    for &px in sizes {
        let resized = img.resize_exact(px, px, FilterType::Lanczos3);
        let mut buf = Vec::new();
        resized
            .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
            .context("failed to encode icon PNG")?;
        out.push((px, buf));
    }
    Ok(out)
}

pub fn generate_alt_icon(name: &str, source_png: &[u8]) -> Result<AltIcon> {
    let img = image::load_from_memory(source_png)
        .with_context(|| format!("alt-icon '{name}': source is not a decodable image"))?;

    let (w, h) = (img.width(), img.height());
    if w != h {
        eprintln!(
            "warning: alt-icon '{name}' source is {w}x{h} (not square); it will be stretched"
        );
    } else if w < 180 {
        eprintln!("warning: alt-icon '{name}' source is {w}px; upscaling to 180px will blur");
    }

    let mut files = Vec::with_capacity(VARIANTS.len());
    let mut iphone_bases = Vec::new();
    let mut ipad_bases = Vec::new();

    for (base, scale, px, is_ipad) in VARIANTS {
        let base_name = format!("{name}{base}");
        let filename = format!("{base_name}{scale}.png");
        let resized = img.resize_exact(px, px, FilterType::Lanczos3);
        let mut png = Vec::new();
        resized
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .context("failed to encode icon PNG")?;
        files.push(IconFile {
            filename,
            png,
            pixels: px,
        });

        let bases = if is_ipad {
            &mut ipad_bases
        } else {
            &mut iphone_bases
        };
        if !bases.contains(&base_name) {
            bases.push(base_name);
        }
    }

    Ok(AltIcon {
        name: name.to_owned(),
        files,
        iphone_bases,
        ipad_bases,
    })
}

pub fn patch_icons_plist(info_plist: &[u8], alt_icons: &[AltIcon]) -> Result<Vec<u8>> {
    let mut value =
        Value::from_reader(Cursor::new(info_plist)).context("Info.plist is not a valid plist")?;
    let root = value
        .as_dictionary_mut()
        .context("Info.plist root is not a dictionary")?;

    for (icons_key, use_ipad) in [("CFBundleIcons", false), ("CFBundleIcons~ipad", true)] {
        let icons = dict_entry(root, icons_key);
        let alternates = dict_entry(icons, "CFBundleAlternateIcons");
        for alt in alt_icons {
            let bases = if use_ipad {
                &alt.ipad_bases
            } else {
                &alt.iphone_bases
            };
            let mut entry = plist::Dictionary::new();
            entry.insert(
                "CFBundleIconFiles".into(),
                Value::Array(bases.iter().map(|b| Value::String(b.clone())).collect()),
            );
            entry.insert("UIPrerenderedIcon".into(), Value::Boolean(false));
            alternates.insert(alt.name.clone(), Value::Dictionary(entry));
        }
    }

    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &value).context("failed to re-encode Info.plist")?;
    Ok(out)
}

/// The loose fallback pair Xcode emits beside the catalogue; only an app with no `Assets.car` uses them.
pub fn primary_icon_files(asset: &str, source_png: &[u8]) -> Result<Vec<IconFile>> {
    let img =
        image::load_from_memory(source_png).context("icon source is not a decodable image")?;
    let mut out = Vec::new();
    for (base, suffix, px) in [("60x60", "", 120u32), ("76x76", "~ipad", 152)] {
        let mut png = Vec::new();
        img.resize_exact(px, px, FilterType::Lanczos3)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .context("failed to encode icon PNG")?;
        out.push(IconFile {
            filename: format!("{asset}{base}@2x{suffix}.png"),
            png,
            pixels: px,
        });
    }
    Ok(out)
}

/// Only fills what the app has not declared; its own `CFBundleIconFiles` is more accurate than anything synthesised.
/// `CFBundleIconName` is never touched — it points into the catalogue.
pub fn patch_primary_icon_plist(info_plist: &[u8], asset: &str) -> Result<Vec<u8>> {
    let mut value =
        Value::from_reader(Cursor::new(info_plist)).context("Info.plist is not a valid plist")?;
    let root = value
        .as_dictionary_mut()
        .context("Info.plist root is not a dictionary")?;

    for (icons_key, base) in [("CFBundleIcons", "60x60"), ("CFBundleIcons~ipad", "76x76")] {
        let icons = dict_entry(root, icons_key);
        let primary = dict_entry(icons, "CFBundlePrimaryIcon");
        if !primary.contains_key("CFBundleIconFiles") {
            primary.insert(
                "CFBundleIconFiles".into(),
                Value::Array(vec![Value::String(format!("{asset}{base}"))]),
            );
        }
        if !primary.contains_key("UIPrerenderedIcon") {
            primary.insert("UIPrerenderedIcon".into(), Value::Boolean(false));
        }
    }

    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &value).context("failed to re-encode Info.plist")?;
    Ok(out)
}

pub fn primary_icon_name(info_plist: &[u8]) -> String {
    Value::from_reader(Cursor::new(info_plist))
        .ok()
        .and_then(|v| {
            v.as_dictionary()?
                .get("CFBundleIcons")?
                .as_dictionary()?
                .get("CFBundlePrimaryIcon")?
                .as_dictionary()?
                .get("CFBundleIconName")?
                .as_string()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "AppIcon".to_owned())
}

fn dict_entry<'a>(parent: &'a mut plist::Dictionary, key: &str) -> &'a mut plist::Dictionary {
    if parent.get(key).and_then(Value::as_dictionary).is_none() {
        parent.insert(key.into(), Value::Dictionary(plist::Dictionary::new()));
    }
    parent
        .get_mut(key)
        .and_then(Value::as_dictionary_mut)
        .expect("just inserted a dictionary")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red_png(size: u32) -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(size, size, image::Rgba([200, 30, 30, 255]));
        let mut buf = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut buf), image::ImageFormat::Png)
            .unwrap();
        buf
    }

    #[test]
    fn generates_four_correctly_sized_variants() {
        let alt = generate_alt_icon("Alt", &red_png(256)).unwrap();
        let by_name: std::collections::HashMap<_, _> =
            alt.files.iter().map(|f| (f.filename.as_str(), f)).collect();

        for (fname, expect) in [
            ("Alt60x60@2x.png", 120),
            ("Alt60x60@3x.png", 180),
            ("Alt76x76@2x.png", 152),
            ("Alt83.5x83.5@2x.png", 167),
        ] {
            let f = by_name
                .get(fname)
                .unwrap_or_else(|| panic!("missing {fname}"));
            assert_eq!(f.pixels, expect);
            let decoded = image::load_from_memory(&f.png).unwrap();
            assert_eq!(decoded.width(), expect);
            assert_eq!(decoded.height(), expect);
        }
        assert_eq!(alt.iphone_bases, vec!["Alt60x60"]);
        assert_eq!(alt.ipad_bases, vec!["Alt76x76", "Alt83.5x83.5"]);
    }

    #[test]
    fn patches_both_icon_dicts() {
        let mut d = plist::Dictionary::new();
        d.insert("CFBundleName".into(), "X".into());
        let mut input = Vec::new();
        plist::to_writer_binary(&mut input, &Value::Dictionary(d)).unwrap();

        let alt = generate_alt_icon("Alt", &red_png(200)).unwrap();
        let out = patch_icons_plist(&input, std::slice::from_ref(&alt)).unwrap();

        let v = Value::from_reader(Cursor::new(out)).unwrap();
        let root = v.as_dictionary().unwrap();

        let iphone = root["CFBundleIcons"].as_dictionary().unwrap()["CFBundleAlternateIcons"]
            .as_dictionary()
            .unwrap()["Alt"]
            .as_dictionary()
            .unwrap();
        let files: Vec<_> = iphone["CFBundleIconFiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_string().unwrap())
            .collect();
        assert_eq!(files, vec!["Alt60x60"]);
        assert_eq!(iphone["UIPrerenderedIcon"].as_boolean(), Some(false));

        let ipad = root["CFBundleIcons~ipad"].as_dictionary().unwrap()["CFBundleAlternateIcons"]
            .as_dictionary()
            .unwrap()["Alt"]
            .as_dictionary()
            .unwrap();
        let files: Vec<_> = ipad["CFBundleIconFiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_string().unwrap())
            .collect();
        assert_eq!(files, vec!["Alt76x76", "Alt83.5x83.5"]);

        assert!(
            !root["CFBundleIcons"]
                .as_dictionary()
                .unwrap()
                .contains_key("CFBundlePrimaryIcon")
        );
    }
}

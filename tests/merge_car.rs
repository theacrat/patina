//! End-to-end `--merge-car`: swap assets inside an IPA's `Assets.car` with no
//! archive-wide extraction. Catalogs are built via scar, not shipped.

mod common;

use std::collections::BTreeMap;

use patina::archive::EditPlan;
use patina::edit::{EditOptions, WriteMode, edit_bytes};
use scar::codec::{self, Pixels};
use scar::manifest::{Content, Facet, Manifest, Rendition};

fn solid(w: u32, h: u32, color: [u8; 4]) -> Pixels {
    Pixels {
        width: w,
        height: h,
        rgba: color.repeat((w * h) as usize),
    }
}

fn sample_car() -> Vec<u8> {
    let tmp = tempfile::TempDir::new().unwrap();
    let input = tmp.path().join("in");
    let packed = tmp.path().join("packed");
    let car = tmp.path().join("out.car");
    std::fs::create_dir_all(&input).unwrap();
    codec::write_png(&input.join("logo.png"), &solid(24, 24, [10, 120, 240, 255])).unwrap();
    codec::write_png(&input.join("other.png"), &solid(8, 8, [128, 128, 128, 255])).unwrap();
    scar::authoring::pack(&input, &packed, &scar::authoring::PackOptions::default()).unwrap();
    scar::compile::compile(&packed, &car).unwrap();
    std::fs::read(&car).unwrap()
}

/// `sample_car()`'s logo plus an SVG data rendition for asset `glyph`.
fn sample_car_with_svg(svg: &str) -> Vec<u8> {
    let tmp = tempfile::TempDir::new().unwrap();
    let input = tmp.path().join("in");
    let packed = tmp.path().join("packed");
    let car = tmp.path().join("out.car");
    std::fs::create_dir_all(&input).unwrap();
    codec::write_png(&input.join("logo.png"), &solid(24, 24, [10, 120, 240, 255])).unwrap();
    scar::authoring::pack(&input, &packed, &scar::authoring::PackOptions::default()).unwrap();

    std::fs::create_dir_all(packed.join("data")).unwrap();
    std::fs::write(packed.join("data/glyph.svg"), svg).unwrap();
    let manifest_path = packed.join("manifest.json");
    let mut m = Manifest::load(&manifest_path).unwrap();
    let attrs: BTreeMap<String, u16> =
        [("element".to_string(), 2), ("identifier".to_string(), 2)].into();
    m.renditions.push(Rendition {
        key: attrs.clone(),
        name: "glyph.svg".to_string(),
        layout: 1017,
        flags: 0,
        pixel_format: "SVG".to_string(),
        color_space_id: 0,
        width: 0,
        height: 0,
        scale: 100,
        modified: 0,
        slices: None,
        metrics: None,
        composition: None,
        bitmap_info: Some(1),
        extra_tlvs: BTreeMap::new(),
        content: Content::Data {
            file: "data/glyph.svg".to_string(),
            lzfse: false,
        },
    });
    m.facets.push(Facet {
        name: "glyph".to_string(),
        hotspot: None,
        attributes: attrs,
    });
    m.save(&manifest_path).unwrap();
    scar::compile::compile(&packed, &car).unwrap();
    std::fs::read(&car).unwrap()
}

/// Raw bytes of the data rendition named `<name>.svg`.
fn data_asset(car: &[u8], name: &str) -> Vec<u8> {
    let tmp = tempfile::TempDir::new().unwrap();
    let in_car = tmp.path().join("in.car");
    let work = tmp.path().join("work");
    std::fs::write(&in_car, car).unwrap();
    scar::decompile::decompile(&in_car, &work, false).unwrap();
    let m = Manifest::load(&work.join("manifest.json")).unwrap();
    let want = format!("{name}.svg");
    let r = m.renditions.iter().find(|r| r.name == want).unwrap();
    let Content::Data { file, .. } = &r.content else {
        panic!("expected data rendition")
    };
    std::fs::read(work.join(file)).unwrap()
}

fn decoded_asset(car: &[u8], name: &str) -> Vec<u8> {
    let tmp = tempfile::TempDir::new().unwrap();
    let in_car = tmp.path().join("in.car");
    let work = tmp.path().join("work");
    std::fs::write(&in_car, car).unwrap();
    scar::decompile::decompile(&in_car, &work, false).unwrap();
    let m = Manifest::load(&work.join("manifest.json")).unwrap();
    let facet = m.facets.iter().find(|f| f.name == name).unwrap();
    let ident = facet.attributes["identifier"];
    let r = m
        .renditions
        .iter()
        .find(|r| r.key.get("identifier") == Some(&ident))
        .unwrap();
    let Content::Image { file, .. } = &r.content else {
        panic!("expected image rendition")
    };
    codec::read_png(&work.join(file)).unwrap().rgba
}

fn ipa_with_car(car: &[u8]) -> Vec<u8> {
    let (base, _) = common::build_ipa(&common::incompressible_blob(2048));
    let mut plan = EditPlan::new();
    plan.put("Payload/Fake.app/Assets.car", car.to_vec(), 0o100644);
    plan.commit_append(&base).unwrap()
}

fn write_replacement_dir(pixels: &Pixels, asset: &str) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    codec::write_png(&dir.path().join(format!("{asset}.png")), pixels).unwrap();
    dir
}

#[test]
fn merge_car_replaces_named_asset_in_ipa() {
    let car = sample_car();
    let ipa = ipa_with_car(&car);

    let other_before = decoded_asset(&car, "other");
    let new_logo = solid(24, 24, [250, 30, 60, 255]);
    let dir = write_replacement_dir(&new_logo, "logo");

    let opts = EditOptions {
        merge_car: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.car_replaced, 1, "one rendition should be replaced");
    assert!(report.car_unmatched.is_empty());

    let merged_car = patina::archive::read_entry(&edited, "Payload/Fake.app/Assets.car")
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded_asset(&merged_car, "logo"),
        new_logo.rgba,
        "logo must decode to the replacement pixels"
    );
    assert_eq!(
        decoded_asset(&merged_car, "other"),
        other_before,
        "the untouched asset must be unchanged"
    );

    let out = common::tempdir().join("merged.ipa");
    std::fs::write(&out, &edited).unwrap();
    assert!(
        std::process::Command::new("unzip")
            .arg("-t")
            .arg(&out)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn merge_car_replaces_svg_asset_in_ipa() {
    let old_svg = r##"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8" fill="#123456"/></svg>"##;
    let new_svg = r##"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><circle cx="4" cy="4" r="4" fill="#654321"/></svg>"##;
    let car = sample_car_with_svg(old_svg);
    let ipa = ipa_with_car(&car);

    let logo_before = decoded_asset(&car, "logo");
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("glyph.svg"), new_svg).unwrap();

    let opts = EditOptions {
        merge_car: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.car_replaced, 1, "one rendition should be replaced");
    assert!(report.car_unmatched.is_empty());

    let merged = patina::archive::read_entry(&edited, "Payload/Fake.app/Assets.car")
        .unwrap()
        .unwrap();
    assert_eq!(data_asset(&merged, "glyph"), new_svg.as_bytes());
    assert_eq!(decoded_asset(&merged, "logo"), logo_before);
}

#[test]
fn merge_car_reports_unmatched_and_leaves_car_untouched() {
    let car = sample_car();
    let ipa = ipa_with_car(&car);
    // 10×10 cannot match `logo`'s 24×24 rendition.
    let dir = write_replacement_dir(&solid(10, 10, [1, 2, 3, 255]), "logo");

    let opts = EditOptions {
        merge_car: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.car_replaced, 0);
    assert_eq!(report.car_unmatched, vec!["logo".to_string()]);

    let before = patina::archive::read_entry(&ipa, "Payload/Fake.app/Assets.car")
        .unwrap()
        .unwrap();
    let after = patina::archive::read_entry(&edited, "Payload/Fake.app/Assets.car")
        .unwrap()
        .unwrap();
    assert_eq!(before, after, "unmatched merge must not rewrite the car");
}

#[test]
fn merge_car_composes_with_an_overlaid_car() {
    let car = sample_car();
    let (ipa, _) = common::build_ipa(&common::incompressible_blob(2048));

    let overlay = common::tempdir().join("overlay");
    std::fs::create_dir_all(&overlay).unwrap();
    std::fs::write(overlay.join("Assets.car"), &car).unwrap();

    let other_before = decoded_asset(&car, "other");
    let new_logo = solid(24, 24, [7, 200, 90, 255]);
    let dir = write_replacement_dir(&new_logo, "logo");

    let opts = EditOptions {
        overlays: vec![overlay],
        merge_car: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let (edited, report) = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap();
    assert_eq!(report.car_replaced, 1);

    let merged = patina::archive::read_entry(&edited, "Payload/Fake.app/Assets.car")
        .unwrap()
        .unwrap();
    assert_eq!(decoded_asset(&merged, "logo"), new_logo.rgba);
    assert_eq!(decoded_asset(&merged, "other"), other_before);
}

#[test]
fn merge_car_missing_car_is_an_error() {
    let (ipa, _) = common::build_ipa(&common::incompressible_blob(2048));
    let dir = write_replacement_dir(&solid(24, 24, [0, 0, 0, 255]), "logo");
    let opts = EditOptions {
        merge_car: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let err = edit_bytes(&ipa, &opts, WriteMode::Compact).unwrap_err();
    assert!(
        format!("{err:#}").contains("Assets.car"),
        "error should name the missing car"
    );
}

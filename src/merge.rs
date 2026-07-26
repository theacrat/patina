//! `Assets.car` merge glue over scar: each `<name>.png`, `<name>.svg` or
//! `<name>.pdf` replaces asset `<name>`; SVGs/PDFs naming no existing asset
//! are added as new assets. PNGs are rendered at every size their asset uses,
//! since scar itself never resamples.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::icons;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Beyond this much aspect-ratio change, a stretched replacement looks wrong
/// rather than merely resampled.
const ASPECT_WARN: f64 = 0.05;

pub struct CarMerge {
    pub replaced: usize,
    pub added: Vec<String>,
    pub unmatched: Vec<String>,
}

/// `(asset-name, bytes)` replacements from a `--merge-car` directory.
pub fn dir_replacements(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut replacements: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("reading merge-car dir {}", dir.display()))?
    {
        let path = entry?.path();
        let supported = path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
            ["png", "svg", "pdf"]
                .iter()
                .any(|s| e.eq_ignore_ascii_case(s))
        });
        if !supported {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            eprintln!(
                "warning: skipping merge-car file with a non-UTF-8 name: {}",
                path.display()
            );
            continue;
        };
        replacements.push((stem.to_owned(), std::fs::read(&path)?));
    }
    Ok(replacements)
}

/// Every PNG replacement re-rendered at each size its asset actually uses, so a
/// single supplied PNG reaches all of an asset's renditions rather than only
/// the one whose dimensions it happens to match. A supplied PNG that already
/// matches a size is passed through untouched; the largest one is the source
/// for the rest. Non-PNG replacements and names the catalogue does not size
/// (vector assets, unknown names) pass through unchanged.
fn fit_pngs_to_car(
    car_bytes: &[u8],
    replacements: &[(String, Vec<u8>)],
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut supplied: BTreeMap<&str, Vec<&Vec<u8>>> = BTreeMap::new();
    for (name, bytes) in replacements {
        if bytes.starts_with(PNG_MAGIC) {
            supplied.entry(name.as_str()).or_default().push(bytes);
        }
    }
    if supplied.is_empty() {
        return Ok(replacements.to_vec());
    }

    let names: Vec<String> = supplied.keys().map(|n| (*n).to_owned()).collect();
    let wanted = scar::merge::replacement_sizes(car_bytes, &names)
        .context("reading rendition sizes from the car")?;

    let mut out = Vec::with_capacity(replacements.len());
    let mut done: Vec<&str> = Vec::new();
    for (name, bytes) in replacements {
        if !bytes.starts_with(PNG_MAGIC) {
            out.push((name.clone(), bytes.clone()));
            continue;
        }
        // Every size for an asset is emitted at its first PNG, so ordering
        // against other assets' replacements is preserved.
        if done.contains(&name.as_str()) {
            continue;
        }
        done.push(name.as_str());

        let pngs = &supplied[name.as_str()];
        let Some(sizes) = wanted.get(name) else {
            out.extend(pngs.iter().map(|b| (name.clone(), (*b).clone())));
            continue;
        };
        out.extend(render_for_sizes(name, pngs, sizes)?);
    }
    Ok(out)
}

/// One replacement per wanted size: an exactly-matching supplied PNG if there
/// is one (the last, so later replacements still win), else the largest
/// supplied PNG stretched to fit.
fn render_for_sizes(
    name: &str,
    pngs: &[&Vec<u8>],
    sizes: &[(u32, u32)],
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut measured = Vec::with_capacity(pngs.len());
    for png in pngs {
        let size = icons::png_size(png)
            .with_context(|| format!("measuring replacement for asset '{name}'"))?;
        measured.push((size, *png));
    }
    let (source_size, source) = *measured
        .iter()
        .max_by_key(|((w, h), _)| (*w as u64) * (*h as u64))
        .expect("a name is only recorded with at least one PNG");

    let mut exact = Vec::new();
    let mut to_render = Vec::new();
    for &size in sizes {
        match measured.iter().rev().find(|(s, _)| *s == size) {
            Some((_, png)) => exact.push((name.to_owned(), (*png).clone())),
            None => to_render.push(size),
        }
    }
    warn_on_stretch(name, source_size, &to_render);

    let mut out = exact;
    for (_, png) in icons::render_exact(source, &to_render)
        .with_context(|| format!("resizing replacement for asset '{name}'"))?
    {
        out.push((name.to_owned(), png));
    }
    Ok(out)
}

fn warn_on_stretch(name: &str, (sw, sh): (u32, u32), targets: &[(u32, u32)]) {
    if sh == 0 {
        return;
    }
    let source = f64::from(sw) / f64::from(sh);
    let worst = targets
        .iter()
        .filter(|(_, h)| *h != 0)
        .map(|(w, h)| f64::from(*w) / f64::from(*h))
        .max_by(|a, b| {
            let d = |r: &f64| (r / source).ln().abs();
            d(a).total_cmp(&d(b))
        });
    if let Some(worst) = worst
        && (worst / source - 1.0).abs() > ASPECT_WARN
    {
        eprintln!(
            "warning: '{name}' is {sw}x{sh} but the catalogue wants {worst:.2}:1 \
             renditions; it will be stretched"
        );
    }
}

/// One scar round-trip applying every replacement in order (later ones win).
/// `add_missing` adds SVGs/PDFs matching no asset as new assets; PNGs never add.
pub fn merge_car(
    car_bytes: &[u8],
    replacements: &[(String, Vec<u8>)],
    add_missing: bool,
) -> Result<(Vec<u8>, CarMerge)> {
    if replacements.is_empty() {
        return Ok((
            car_bytes.to_vec(),
            CarMerge {
                replaced: 0,
                added: vec![],
                unmatched: vec![],
            },
        ));
    }
    let replacements = fit_pngs_to_car(car_bytes, replacements)?;
    let mut opts = scar::merge::MergeOptions::default();
    opts.add_missing = add_missing;
    let (out, report) = scar::merge::merge_car_report_with(car_bytes, &replacements, &opts)
        .context("scar merge_car failed")?;
    Ok((
        out,
        CarMerge {
            replaced: report.replaced,
            added: report.added,
            unmatched: report.unmatched,
        },
    ))
}

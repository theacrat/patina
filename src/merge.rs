//! `Assets.car` merge glue over scar: each `<name>.png`, `<name>.svg` or
//! `<name>.pdf` replaces asset `<name>`; SVGs/PDFs naming no existing asset
//! are added as new assets.

use std::path::Path;

use anyhow::{Context, Result};

pub struct CarMerge {
    pub replaced: usize,
    pub added: Vec<String>,
    pub unmatched: Vec<String>,
}

pub fn merge_car_dir(car_bytes: &[u8], dir: &Path) -> Result<(Vec<u8>, CarMerge)> {
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
    merge(car_bytes, &replacements, true)
}

/// Replace-only: icon re-rendering must never add assets.
pub fn merge_car_replacements(
    car_bytes: &[u8],
    replacements: &[(String, Vec<u8>)],
) -> Result<(Vec<u8>, CarMerge)> {
    merge(car_bytes, replacements, false)
}

fn merge(
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
    let mut opts = scar::merge::MergeOptions::default();
    opts.add_missing = add_missing;
    let (out, report) = scar::merge::merge_car_report_with(car_bytes, replacements, &opts)
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

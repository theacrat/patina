//! `Assets.car` merge glue over scar's `merge_car`: each `<name>.png`,
//! `<name>.svg` or `<name>.pdf` replaces asset `<name>`.

use std::path::Path;

use anyhow::{Context, Result};

pub struct CarMerge {
    pub replaced: usize,
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
    merge_car_replacements(car_bytes, &replacements)
}

pub fn merge_car_replacements(
    car_bytes: &[u8],
    replacements: &[(String, Vec<u8>)],
) -> Result<(Vec<u8>, CarMerge)> {
    if replacements.is_empty() {
        return Ok((
            car_bytes.to_vec(),
            CarMerge {
                replaced: 0,
                unmatched: vec![],
            },
        ));
    }
    let (out, report) =
        scar::merge::merge_car_report(car_bytes, replacements).context("scar merge_car failed")?;
    Ok((
        out,
        CarMerge {
            replaced: report.replaced,
            unmatched: report.unmatched,
        },
    ))
}

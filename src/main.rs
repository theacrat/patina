use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use patina::config;
use patina::edit::{EditOptions, EditReport, WriteMode, edit_bytes, edit_file_append};

#[derive(Parser)]
#[command(
    name = "patina",
    version,
    about = "Surgical, recompression-free edits on iOS .ipa archives"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Apply edits to an .ipa/.tipa in a single central-directory rewrite.
    Edit(EditArgs),
}

#[derive(Parser)]
struct EditArgs {
    /// The .ipa/.tipa to edit.
    ipa: PathBuf,

    /// Take options and assets from a config bundle folder or zip (flags win).
    #[arg(long, value_name = "DIR|ZIP")]
    config: Option<PathBuf>,

    /// Set CFBundleDisplayName + CFBundleName (and matching InfoPlist.strings).
    #[arg(long)]
    name: Option<String>,

    /// Add an alternate icon: NAME=path.png (repeatable).
    #[arg(long = "alt-icon", value_name = "NAME=PNG")]
    alt_icon: Vec<String>,

    /// Replace the primary app icon from a PNG.
    #[arg(long, value_name = "PNG")]
    icon: Option<PathBuf>,

    /// Merge replacement PNGs from a directory into the app's Assets.car.
    #[arg(long = "merge-car", value_name = "DIR")]
    merge_car: Option<PathBuf>,

    /// Merge a folder into the .app root, overwriting and adding (repeatable).
    #[arg(long, value_name = "DIR")]
    overlay: Vec<PathBuf>,

    /// Inject a tweak .deb (repeatable).
    #[arg(long = "tweak", value_name = "DEB")]
    tweak: Vec<PathBuf>,

    /// Warn instead of failing when a tweak .deb's Depends: are not supplied.
    #[arg(long)]
    ignore_missing_deps: bool,

    /// Entitlements XML applied when re-signing the main Mach-O.
    #[arg(long, value_name = "XML")]
    entitlements: Option<PathBuf>,

    /// Set CFBundleIdentifier (also the ad-hoc signing identifier).
    #[arg(long, value_name = "ID")]
    bundle_id: Option<String>,

    /// Set CFBundleShortVersionString + CFBundleVersion.
    #[arg(long, value_name = "VER")]
    version: Option<String>,

    /// Set MinimumOSVersion.
    #[arg(long, value_name = "VER")]
    min_os: Option<String>,

    /// Recursively merge a plist file into Info.plist.
    #[arg(long, value_name = "FILE")]
    merge_plist: Option<PathBuf>,

    /// Delete UISupportedDevices from Info.plist.
    #[arg(long)]
    remove_supported_devices: bool,

    /// Set UIFileSharingEnabled + LSSupportsOpeningDocumentsInPlace.
    #[arg(long)]
    enable_file_sharing: bool,

    /// Remove the Watch/ app subtree.
    #[arg(long)]
    remove_watch: bool,

    /// Remove all PlugIns/*.appex extensions.
    #[arg(long)]
    remove_extensions: bool,

    /// Remove only appex extensions whose main Mach-O is FairPlay-encrypted.
    #[arg(long)]
    remove_encrypted_extensions: bool,

    /// Strip non-arm64(e) slices from every fat Mach-O in the bundle.
    #[arg(long)]
    thin: bool,

    /// Ad-hoc fakesign the whole bundle (every Mach-O + CodeResources per level).
    #[arg(long)]
    fakesign_bundle: bool,

    /// Write to a new archive instead of editing in place (implies --compact).
    #[arg(short, long, value_name = "OUT.ipa")]
    output: Option<PathBuf>,

    /// Rewrite the whole archive (recompression-free) instead of appending.
    #[arg(long)]
    compact: bool,

    /// Emit fixed timestamps for new entries (reproducible output).
    #[arg(long)]
    deterministic: bool,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Edit(args) => run_edit(args),
    }
}

fn run_edit(args: EditArgs) -> Result<()> {
    let mut alt_icons = Vec::new();
    for spec in &args.alt_icon {
        let (name, path) = spec
            .split_once('=')
            .with_context(|| format!("--alt-icon expects NAME=path.png, got '{spec}'"))?;
        alt_icons.push((name.to_owned(), PathBuf::from(path)));
    }

    let mut opts = EditOptions {
        name: args.name,
        alt_icons,
        icon: args.icon,
        merge_car: args.merge_car,
        overlays: args.overlay,
        tweaks: args.tweak,
        ignore_missing_deps: args.ignore_missing_deps,
        entitlements: args.entitlements,
        bundle_id: args.bundle_id,
        version: args.version,
        min_os: args.min_os,
        merge_plist: args.merge_plist,
        remove_supported_devices: args.remove_supported_devices,
        enable_file_sharing: args.enable_file_sharing,
        remove_watch: args.remove_watch,
        remove_extensions: args.remove_extensions,
        remove_encrypted_extensions: args.remove_encrypted_extensions,
        thin: args.thin,
        fakesign_bundle: args.fakesign_bundle,
        deterministic: args.deterministic,
    };

    let mut bundle = None;
    if let Some(path) = &args.config {
        let (cfg, dir) = config::load(path)?;
        opts = config::merge(config::to_options(&cfg, dir.path())?, opts);
        bundle = Some(dir);
    }

    if !args.ipa.exists() {
        bail!("input archive not found: {}", args.ipa.display());
    }

    let compact = args.compact || args.output.is_some();
    let report = if compact {
        let input =
            std::fs::read(&args.ipa).with_context(|| format!("reading {}", args.ipa.display()))?;
        let (out, report) = edit_bytes(&input, &opts, WriteMode::Compact)?;
        let target = args.output.as_ref().unwrap_or(&args.ipa);
        std::fs::write(target, out).with_context(|| format!("writing {}", target.display()))?;
        report
    } else {
        edit_file_append(&args.ipa, &opts)?
    };

    // The extracted bundle must outlive every path taken from it.
    drop(bundle);

    print_report(
        &report,
        compact,
        args.output.as_deref().unwrap_or(&args.ipa),
    );
    Ok(())
}

fn print_report(r: &EditReport, compact: bool, target: &std::path::Path) {
    let mode = if compact {
        "compact rewrite"
    } else {
        "in-place append"
    };
    println!("Edited {} ({mode}) -> {}", r.app_dir, target.display());
    println!("  executable: {}", r.executable);
    if r.renamed {
        println!(
            "  renamed: yes ({} InfoPlist.strings updated)",
            r.lproj_updated
        );
    }
    if r.alt_icons > 0 {
        println!("  alt icons: {}", r.alt_icons);
    }
    if r.primary_icon {
        println!("  primary icon: replaced");
    }
    if !r.metadata.is_empty() {
        println!("  metadata: {}", r.metadata.join(", "));
    }
    if !r.removed.is_empty() {
        println!("  removed: {}", r.removed.join(", "));
    }
    if r.thinned > 0 {
        println!("  thinned to arm64: {} binaries", r.thinned);
    }
    if let Some(n) = r.fakesigned {
        println!("  fakesigned bundle: {n} Mach-Os signed + CodeResources");
    }
    if r.car_replaced > 0 || !r.car_unmatched.is_empty() {
        println!("  car merge: {} replaced", r.car_replaced);
        if !r.car_unmatched.is_empty() {
            println!("    unmatched: {}", r.car_unmatched.join(", "));
        }
    }
    if r.overlaid_files > 0 {
        println!("  files overlaid: {}", r.overlaid_files);
    }
    if !r.tweaks.is_empty() {
        println!("  tweaks: {}", r.tweaks.join(", "));
    }
    if r.resigned {
        println!("  re-signed main executable: ad-hoc");
    }
}

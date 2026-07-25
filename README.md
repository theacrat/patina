# patina

Modify iOS apps (`.ipa` files) in a fraction of a second. patina only rewrites the parts you actually change: renaming a 48 MB app takes about a millisecond.

Note: Most of this was made with LLMs, so don't expect great support, but you're free to fork it of course.

## Install

```sh
cargo build --release
```

The binary lands in `target/release/patina`. Copy it anywhere on your `PATH`.

## Quick start

```sh
# Rename an app and give it a new icon
patina edit App.ipa --name "My App" --icon icon.png

# Inject a tweak and write to a new file, leaving the original alone
patina edit App.ipa --tweak tweak.deb -o Modified.ipa
```

patina edits **in place** by default; pass `-o OUT.ipa` to keep the original.

## What you can change

Everything below can be combined in one command; `patina edit --help` has the full list.

**Appearance and identity**

| Option                     | What it does                                             |
| -------------------------- | -------------------------------------------------------- |
| `--name NAME`              | Change the app's display name                            |
| `--icon icon.png`          | Replace the app icon                                     |
| `--alt-icon NAME=icon.png` | Add an alternate icon the app can switch to (repeatable) |
| `--merge-car DIR`          | Swap individual images inside the app's asset catalogue  |
| `--bundle-id ID`           | Change the bundle identifier                             |
| `--version VER`            | Change the version number                                |

**Adding and removing**

| Option                          | What it does                                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------- |
| `--tweak tweak.deb`             | Add a tweak, as the `.deb` package it ships as (repeatable)                              |
| `--overlay DIR`                 | Merge a folder into the app, overwriting existing files and adding new ones (repeatable) |
| `--remove-watch`                | Remove the bundled Apple Watch app                                                       |
| `--remove-extensions`           | Remove all app extensions                                                                |
| `--remove-encrypted-extensions` | Remove only the encrypted extensions (these often break sideloading)                     |
| `--thin`                        | Drop non-ARM64 code to shrink the app                                                    |
| `--ignore-missing-deps`         | Carry on when a tweak's dependencies aren't supplied                                     |

An overlay wins over anything a `.deb` staged at the same path. Its Mach-Os are staged like any other — install-name normalised, thinned, rewritten to `@rpath`, ad-hoc signed — and count as dependency providers. patina's own edits (`--name`, `--icon`, `--merge-car`, re-signing) still apply on top.

Tweaks are supplied as `.deb`, the format they ship in and what theos builds. Rootless (`/var/jb/…`) and rootful are treated alike, and the Debian layout decides where things land:

| In the package                             | In the app        |
| ------------------------------------------ | ----------------- |
| `Library/MobileSubstrate/DynamicLibraries` | Loaded by the app |
| `Library/Frameworks`                       | Staged alongside  |
| `Library/Application Support/*.bundle`     | The app root      |

Symlinked aliases become real files. Anything only a jailbroken device can load — preference bundles, themes, daemons — is reported and skipped.

**Settings and compatibility**

| Option                       | What it does                                                |
| ---------------------------- | ----------------------------------------------------------- |
| `--min-os VER`               | Change the minimum iOS version                              |
| `--remove-supported-devices` | Remove the device allowlist, so it installs on more devices |
| `--enable-file-sharing`      | Expose the app's files in the Files app                     |
| `--merge-plist FILE`         | Merge extra settings into the app's `Info.plist`            |

**Signing**

| Option                | What it does                           |
| --------------------- | -------------------------------------- |
| `--entitlements FILE` | Apply entitlements when signing        |
| `--fakesign-bundle`   | Sign the entire app bundle (see below) |

**Output**

| Option            | What it does                                                   |
| ----------------- | -------------------------------------------------------------- |
| `-o OUT.ipa`      | Write to a new file instead of editing in place                |
| `--compact`       | Rebuild the archive from scratch (still without recompressing) |
| `--deterministic` | Produce byte-identical output on repeated runs                 |

A tweak with missing dependencies installs fine and then quietly does nothing, so patina checks the packages in a run against each other and fails before writing anything, naming what's missing and who needs it. A package supplies a name by being called it or declaring it in `Provides:` — how ElleKit stands in for `mobilesubstrate`. Only names are checked, not versions; dependencies describing the device, like the iOS version, are ignored; declared conflicts and `--ignore-missing-deps` are warnings only.

Tweaks often link absolute paths like `/usr/lib/libsubstrate.dylib`. patina repoints those at the app's `Frameworks/`, but only when that library is actually supplied there — staged this run or already present. Everything else, including genuine system libraries, is untouched.

## Config bundles

Instead of a long command line, pass a folder holding the settings and files — or a zip of it, which makes a set of edits easy to share.

| Option             | What it does                                              |
| ------------------ | --------------------------------------------------------- |
| `--config my-pack` | Take options and files from a config bundle folder or zip |

Files are found by where they sit, and everything is optional.

```
config.json          the settings below
icon.png             the app icon
alt-icons/*.png      alternate icons, named after the file (Midnight.png -> "Midnight")
tweaks/*.deb         tweak packages, one per file
overlay/**           files merged into the app, laid out as they are in the app
car/*.png            images to swap inside the asset catalogue
merge.plist          extra settings merged into the app's Info.plist
entitlements.xml     entitlements to sign with
```

`config.json` holds only the settings that aren't files:

```json
{
  "name": "My App",
  "bundle_id": "com.example.app",
  "version": "1.2.3",
  "min_os": "14.0",
  "remove_supported_devices": true,
  "enable_file_sharing": true,
  "remove_watch": true,
  "remove_extensions": true,
  "remove_encrypted_extensions": false,
  "ignore_missing_deps": false,
  "thin": true,
  "fakesign_bundle": true,
  "deterministic": true
}
```

The command line wins over the bundle, and repeatable options add to it rather than replace it. Unrecognised settings are an error.

## Signing and installing

patina re-signs whenever it changes the executable — enough for **AltStore** and **Sideloadly**, which re-sign with your own certificate anyway. **AppSync** relies on the app's own signature, so add `--fakesign-bundle` to sign the whole bundle; it reads every file in the app, so it's off by default.

## Development

Requires Rust 1.85+. `cargo test` runs the suite; some Mach-O tests need fixtures and skip themselves if absent (see `.github/workflows/ci.yml`).

**Pure Rust**: code signing, `.deb` unpacking and Mach-O editing are all in-tree, with no bundled `ldid`, `install_name_tool` or `otool`. Linux targets need nothing but rustup:

```sh
cargo build --release --target x86_64-unknown-linux-musl
RUSTFLAGS="-C linker=rust-lld" cargo build --release --target aarch64-unknown-linux-musl
```

Both are statically linked. macOS targets also need the macOS SDK (point `SDKROOT` at one, or use [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild)).

Asset catalogue edits are handled by [scar](https://github.com/theacrat/scar).

## Licence

patina

Copyright (C) 2026 thea

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

```
SPDX-License-Identifier: AGPL-3.0-or-later
```

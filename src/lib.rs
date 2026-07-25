//! patina — surgical, recompression-free edits on iOS `.ipa`/`.tipa` archives.
//! One `edit` batches every change into a single central-directory rewrite.

pub mod archive;
pub mod code_resources;
pub mod codesign;
pub mod config;
pub mod deb;
pub mod edit;
pub mod fakesign;
pub mod icons;
pub mod macho;
pub mod merge;
pub mod plist_ops;
pub mod rename;
pub mod tweak;

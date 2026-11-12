//! # midnight_proofs

#![cfg_attr(docsrs, feature(doc_cfg))]
// The actual lints we want to disable.
#![allow(clippy::op_ref, clippy::many_single_char_names)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[cfg(all(feature = "mmap", target_family = "wasm"))]
compile_error!("feature `mmap` requires native mmap support");
#[cfg(all(feature = "disk-spill", target_family = "wasm"))]
compile_error!("feature `disk-spill` requires native mmap and a writable filesystem");

pub mod circuit;
pub mod plonk;
pub mod poly;
pub mod transcript;

pub mod dev;
pub mod utils;

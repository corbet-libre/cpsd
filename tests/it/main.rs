//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`it::<name>::<test>`). The gates stay inside the moved files: `browser` is
//! wasm32-only, `storage` needs the native `storage` feature; `opaque_holder`,
//! `boundaries` and `stamp_vectors` run natively and in the browser. The other modules
//! are native-only, which keeps the wasm CI leg on the same suites it always ran.
mod boundaries;
mod browser;
#[path = "../common/mod.rs"]
mod common;
mod opaque_holder;
#[cfg(not(target_arch = "wasm32"))]
mod privacy_diagnostics;
#[cfg(not(target_arch = "wasm32"))]
mod proof_vectors;
#[cfg(not(target_arch = "wasm32"))]
mod root_board;
#[cfg(not(target_arch = "wasm32"))]
mod stamp_holder;
#[cfg(not(target_arch = "wasm32"))]
mod stamp_storage;
mod stamp_vectors;
mod storage;

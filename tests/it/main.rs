//! The crate's native integration tests in one binary.
//!
//! Every former `tests/<name>.rs` that the host runs is a module here, so a warm edit loop
//! links one test executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`). The targets the wasm32 CI leg drives by name (`browser`, `opaque_holder`,
//! `boundaries`, `stamp_vectors`) stay separate, as does `storage`; `tests/common` stays at its
//! path because those targets still declare `mod common;` themselves.
#[path = "../common/mod.rs"]
mod common;
mod privacy_diagnostics;
mod proof_vectors;
mod root_board;
mod stamp_holder;
mod stamp_storage;

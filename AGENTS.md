# cpsd — agent notes

Commands (repo root; work in a lane, never edit `~/agents/scratch/ws`; lane-wide checks run via `cargo xtask check/test`):
- `bash .ci/update-our-crates.sh` first: advances internal crates to newest main; the `--locked` gates below assume it
- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- `CPSD_FUZZ_CORPUS=fuzz/corpus/decode_encode cargo test --locked -- --nocapture`
- `cargo check --locked --target wasm32-unknown-unknown`

Hard invariants (enforcing check after each):
- Pseudonyms are unlinkable per community (`s * H_G1(domain || C)`), stable across renewal and key rotation; no raw gate data enters the passport. Enforced by `src/tests.rs` (`distinct_blind_requests_hide_one_secret`, `cross_community_collision`, `renewal_and_key_rotation`).
- Challenges are single-use: replayed or mistimed proofs are refused; concurrent races yield at most one success. Enforced by `src/tests.rs` (`memory_consumption_entrypoint_enforces_binding_time_and_replay`) + `tests/storage.rs` (`real_crypto_sessions_reject_replays`).
- `issue_blind_once` atomically binds the issuance tag, so one person keeps one credential across sessions, rotations and races. Enforced by `tests/storage.rs` (`conflicting_first_tags_are_atomic`, `issuance_binds_person_session`, `tag_registration_rolls_back`).
- Stamps mean one confirmation per device action: epoch-checked, ledger records each digest once, replays refused. Enforced by `src/stamp/tests.rs` (`one_stamp_approves_one_action_in_each_of_sixteen_communities`, `ledger_records_each_digest_once_until_the_cohort_ends`) + `tests/stamp_holder.rs` + `tests/stamp_storage.rs`.
- Wire format is strict: versioned `to_bytes`/`from_bytes`, v3 proofs only (v2 exchange refused), no trailing bytes or noncanonical encodings. Enforced by `tests/proof_vectors.rs` (`v3_proofs_preserve_identity_and_explicitly_reject_v2_exchange`) + `src/stamp/tests.rs` (`every_stamp_encoding_is_strict`).

Pointers: `docs/CONTRACT.md`, `docs/PROOF-V3.md`, `docs/STAMP-SECURITY.md`, `docs/DEPENDENCIES.md`; issuance in `src/session.rs`; storage in `src/storage.rs`; stamps in `src/stamp/`.
LGPL-3.0-only WITH linking-exception; no GPL/AGPL-only code; storage only through `crlt`.

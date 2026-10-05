# Route A browser acceptance — evidence map

Evidence map for the decided Route A browser build. Each required acceptance
item points to an existing test or document, or to an explicit gap. No passing
browser timing is recorded in this file.

## Current obstacle (checked in)

[Cargo.toml](../Cargo.toml#L34-L48) declares `proof_system =0.34.0` on both
targets, with the `wasmer-sys` backend natively and the `wasmer-js` backend
on wasm32, plus an exact `wasm-bindgen =0.2.104` / `js-sys =0.3.81` pin to
match Wasmer 6.1.0's bridge. The comment there states cpsd never uses
Circom/LegoGroth16 and the backend is selected only so the dependency
compiles.

[Cargo.lock](../Cargo.lock) confirms the chain: `proof_system 0.34.0` lists
`legogroth16` among its dependencies, and `legogroth16 0.18.0` depends on
`wasmer`, locked at `wasmer 6.1.0`. [DEPENDENCIES.md](./DEPENDENCIES.md#L7-L14)
records the same: `proof_system` still unconditionally includes
Circom/LegoGroth16/Wasmer although cpsd never invokes those protocols, and
calls it an open upstream reduction task.

Already direct today: `bbs_plus =0.25.0`, `bulletproofs_plus_plus =0.9.0`,
`dock_crypto_utils =0.23.0` ([Cargo.toml](../Cargo.toml#L28-L31)).

## Binding target (quoted)

> Route A: `cpsd` drops `proof_system` and composes its statements directly
> from Dock's lower crates of the same family (`bbs_plus`, `schnorr_pok`,
> `syra`, `bulletproofs_plus_plus`), no own crypto; in parallel a patch
> upstream to Dock making legogroth16 optional (return to `proof_system` once
> accepted). Fallback B (`zkryptium`, IETF BBS) only if A fails the real
> browser test. Acceptance unchanged: native and browser proofs, browser proof
> well under one second, all existing cpsd vectors and the pseudonym
> unlinkability tests.

## Evidence map

| Required item | Existing test or explicit gap |
|---|---|
| Native real proof round trip (blind issuance → present → verify, transport bytes) | [blind_issue_present_verify_and_all_transport_roundtrips](../src/tests.rs#L53-L67) |
| Browser real proof round trip (real browser Wasm) | [browser_roundtrip_and_performance](../tests/browser.rs#L17-L18) (wasm32 only; configured real-browser run in [ci.yml](../.github/workflows/ci.yml#L97-L106)) |
| Origin / request binding (signed presentation request, scope, key, kind, time) | [signed_requests_require_the_origin_pinned_scope_key_kind_and_time](../src/tests.rs#L564-L637); [proofs_bind_every_request_field_and_the_issuer_public_key](../src/tests.rs#L69-L105); [shared_epoch_proofs_bind_expiry_profile_and_all_requested_gates](../src/tests.rs#L453-L526) |
| Same secret + same community gives the same pseudonym (stability through renewal/rotation) | [renewal_and_key_rotation_preserve_pseudonyms](../src/tests.rs#L230-L254); [deterministic_identity_has_no_dependency_on_issuance_randomness](../tests/opaque_holder.rs#L10-L28) |
| Different communities give different pseudonyms (inequality regression only) | [cross_community_collision_and_bit_distribution_regression](../src/tests.rs#L256-L283); [deterministic_identity_has_no_dependency_on_issuance_randomness](../tests/opaque_holder.rs#L10-L28); [own_community_b_pseudonym_cannot_answer_community_a](../src/tests.rs#L639-L649). Inequality alone does not establish cryptographic unlinkability (see next row). |
| Cryptographic unlinkability across communities (binding obligation) | Route A acceptance requires preservation of the existing contract ([CONTRACT.md](./CONTRACT.md#L36-L37): cross-community separation relies on DDH in G1) and all vectors in this map, plus review by its implementation owner. The in-tree comment states the regression test "is not a proof of DDH" ([src/tests.rs](../src/tests.rs#L282)). |
| Existing adversary vectors (hostile holder, substituted attributes/secret, tampered bytes, malformed shapes, replay/nonce, issuance binding) | [epoch_expiry_and_gate_checks_cannot_be_bypassed_by_a_hostile_holder](../src/tests.rs#L156-L175); [hidden_signed_attributes_and_holder_secret_cannot_be_substituted](../src/tests.rs#L177-L196); [unrelated_pseudonym_secret_without_witness_equality_is_rejected](../src/tests.rs#L740-L789); [issuance_commitment_cannot_add_generators_for_issuer_owned_attributes](../src/tests.rs#L791-L846); [tampered_serialized_proofs_never_authenticate_or_panic](../src/tests.rs#L427-L451); [malformed_proof_shapes_fail_before_upstream_verification](../src/tests.rs#L322-L365); [all_ark_fields_require_decode_encode_identity](../src/tests.rs#L651-L738); storage/session replay and issuance-binding suites in [storage.rs](../tests/storage.rs) ([replays](../tests/storage.rs#L321-L338), [issuance binding](../tests/storage.rs#L542-L549), [tag races](../tests/storage.rs#L615-L633), [preflight](../tests/storage.rs#L635-L668), [rollback](../tests/storage.rs#L670-L773)); [opaque_issuance_and_refused_renewal_preserve_the_verified_identity](../tests/opaque_holder.rs#L30-L133); boundary refusals in [boundaries.rs](../tests/boundaries.rs#L9-L87) |
| Real-browser proving well under one second | Target; the instrument is [browser_roundtrip_and_performance](../tests/browser.rs#L17-L18), see timing note below. No passing value is recorded here. |
| Complete unchanged coverage | Gate documented in [COVERAGE.md](./COVERAGE.md#L1-L17): 100% of emitted production source lines and branches; native coverage does not establish browser execution ([COVERAGE.md](./COVERAGE.md#L17)). |

## Timing: what is measured versus the target

- [browser.rs](../tests/browser.rs#L61-L108) measures, per configuration
  (shared-epoch on/off × 0/1/3 gates), five `present_trusted` + `verify`
  samples with the browser `Performance` clock, logs first/median proving,
  median verifying, and byte size, and asserts median proving `< 1000.0` ms
  only for the recommended common-expiry (`shared_epoch`) profile.
- Independent hidden-expiry configurations are measured and logged but carry
  no sub-second assertion. The contract notes they "are measured but currently
  exceed one second with multiple predicates"
  ([CONTRACT.md](./CONTRACT.md#L105-L107)).
- [print_native_performance](../src/tests.rs#L367-L383) uses `Instant` on
  native only; it is not browser evidence. Build-time or Node-only runs are
  likewise not real-browser proof.

## Configured suite and gates

The repository configures the following commands; this file records no
execution or passing result:

- Native: `cargo test --locked` ([ci.yml](../.github/workflows/ci.yml#L86)).
- Real browser (Chrome via `wasm-bindgen-test-runner`,
  `WASM_BINDGEN_USE_BROWSER=1`): `cargo test --release --locked --target
  wasm32-unknown-unknown --test browser --test opaque_holder --test boundaries`
  ([ci.yml](../.github/workflows/ci.yml#L97-L106)).
- Selector limit: the configured browser command covers the `browser`,
  `opaque_holder`, and `boundaries` integration targets. A future Route A
  integration file outside that set would not run until the suite selector
  covers it; selector changes belong to the CI owners.
- Unchanged gates: `cargo fmt --check`, `cargo clippy --all-targets --
  -D warnings`, `cargo check --target wasm32-unknown-unknown`,
  advisory/license audit, and the 100% source coverage gate.

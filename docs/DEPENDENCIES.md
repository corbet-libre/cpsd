# Dependency maintenance watch

The dependency declarations follow compatible upstream ranges: `proof_system` 0.34.0,
`bbs_plus` 0.25.0, `dock_crypto_utils` 0.23.0 and `bulletproofs_plus_plus` 0.9.0.
Upstream: https://github.com/docknetwork/crypto (Apache-2.0).

`proof_system` still unconditionally includes Circom/LegoGroth16/Wasmer despite
cpsd never invoking those protocols. This is an open upstream reduction task,
not a reason to exclude those packages from advisory scanning. The native and
Wasm backends, and compatible wasm-bindgen/js-sys bridge ranges, stay covered by CI. Before
changing this family, review upstream feature isolation, release maintenance,
proof wire shapes, constant-time claims, browser timings and all adversarial
proof tests. Removing unused machinery must preserve the exact proof relations;
do not fork cryptographic primitives locally.

`csgn` main provides the required
canonical COSE request authentication. The library enables verification only;
volatile signing is test-only. Production services use csgn PersistentSigner.
`crlt` follows main with one resolved revision in the shared lock; its scoped
transactions support atomic nonce consumption and tag registration without a
direct libSQL adapter or unfinished cvld dependency.

The test-only fuzz harness uses `libfuzzer-sys` 0.4.13 under
`(MIT OR Apache-2.0) AND NCSA`; [NCSA](https://spdx.org/licenses/NCSA.html) is
the permissive University of Illinois license used by its bundled LibFuzzer.
CI audits the separately locked fuzz graph as well as the library graph.

`deny.toml` allows permissive licenses plus this project's LGPL linking
exception, with no GPL/AGPL-only allowance. CI audits the full dependency graph,
not just invoked protocols, against RustSec and registry yanks. Advisory ignores
must be narrow, individually justified and tracked here; never ignore an entire
crate or suppress the audit step to get a green build. GitHub Actions are pinned
by full commit SHA while the Rust toolchain follows stable. Dependency locks
record the tested graph; refreshes require native, browser and fuzz validation.

## Reviewed advisory exceptions (2026-10-01)

The pinned crlt uses maintained reqwest/rustls for remote transport. libSQL's
legacy remote connector is disabled. All six old transport exceptions were
removed; CI rejects their vulnerable dependency families.

Three informational Dock/arkworks exceptions remain, each tied to its reviewed
locked version by the CI source guard:

| Advisory | Dependency and exposure / follow-up |
|---|---|
| RUSTSEC-2024-0388 | derivative 2.2.0: unmaintained build-time macro; requires an upstream family migration. |
| RUSTSEC-2024-0436 | paste 1.0.15: unmaintained build-time macro; same upstream follow-up. |
| RUSTSEC-2026-0173 | proc-macro-error2 2.0.1: unmaintained Wasmer derive dependency; remove through upstream feature isolation. |

Other advisories fail cargo-deny, including new advisories in these packages.
These exceptions are not a claim that the entire graph is advisory-free.

## Browser compatibility investigation

The 2026-10-01 device integration exposed an exact-version conflict between the
old `js-sys` 0.3.81 pin and current downstream browser tests. Bridge dependencies
now use [Cargo compatible ranges](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html),
with a lock-matched runner and actual browser tests. Dock 0.34.0 and its current
upstream main still require LegoGroth16 0.18.0 with Circom and Wasmer 6; the
current Wasmer 7 release is outside that dependency's compatible range. Do not
remove browser validation or fork proof primitives to conceal an upstream
compiler failure.


## Compatibility boundary checked 2026-10-02

Current [proof_system upstream](https://github.com/docknetwork/crypto/blob/main/proof_system/Cargo.toml)
still enables LegoGroth16 Circom unconditionally. The
[LegoGroth16 dependency](https://github.com/docknetwork/crypto/blob/main/legogroth16/Cargo.toml)
requires Wasmer ^6.0.1, whose latest compatible release is 6.1.0.
The retained current-browser run d53df9d/36918570543 failed in that dependency
with current wasm-bindgen. A Wasmer 7 override, local fork, version pin or
browser-test exclusion is not a fix. Upstream feature isolation or compatible
maintenance is still required; native success must not be called browser support.

The former RUSTSEC-2025-0055 exception has been removed: RustSec classifies it
as a [tracing-subscriber vulnerability](https://rustsec.org/advisories/RUSTSEC-2025-0055.html),
not an informational maintenance notice. The patched family begins at 0.3.20;
if the current dependency graph retains 0.2.25, the audit must fail. Absence of
an installed subscriber is not permission to except a vulnerability.

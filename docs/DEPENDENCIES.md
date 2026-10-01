# Dependency maintenance watch

The security update keeps Dock's reviewed exact versions: `proof_system` 0.34.0,
`bbs_plus` 0.25.0, `dock_crypto_utils` 0.23.0 and `bulletproofs_plus_plus` 0.9.0.
Upstream: https://github.com/docknetwork/crypto (Apache-2.0).

`proof_system` still unconditionally includes Circom/LegoGroth16/Wasmer despite
cpsd never invoking those protocols. This is an open upstream reduction task,
not a reason to exclude those packages from advisory scanning. The native and
Wasm backends, and pinned wasm-bindgen/js-sys bridge, stay covered by CI. Before
changing this family, review upstream feature isolation, release maintenance,
proof wire shapes, constant-time claims, browser timings and all adversarial
proof tests. Removing unused machinery must preserve the exact proof relations;
do not fork cryptographic primitives locally.

`csgn` main at d7203f310c3c129c3f67ef4ef3e34ccf0ae8c93b provides the required
canonical COSE request authentication. The library enables verification only;
volatile signing is test-only. Production services use csgn PersistentSigner.
`crlt` remains pinned at the previously integrated revision; its scoped
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

Four unrelated Dock/arkworks exceptions remain, each tied to its reviewed
locked version by the CI source guard:

| Advisory | Dependency and exposure / follow-up |
|---|---|
| RUSTSEC-2024-0388 | derivative 2.2.0: unmaintained build-time macro; requires an upstream family migration. |
| RUSTSEC-2024-0436 | paste 1.0.15: unmaintained build-time macro; same upstream follow-up. |
| RUSTSEC-2026-0173 | proc-macro-error2 2.0.1: unmaintained Wasmer derive dependency; remove through upstream feature isolation. |
| RUSTSEC-2025-0055 | tracing-subscriber 0.2.25: ark-relations constraint tracing; cpsd installs no subscriber or request logging. Consumers must not install this old subscriber on untrusted data. |

Other advisories fail cargo-deny, including new advisories in these packages.
These exceptions are not a claim that the entire graph is advisory-free.

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

## Reviewed advisory exceptions (2026-09-30)

The first audit exposed ten existing transitive advisories. These are explicit
exceptions, **not fixed vulnerabilities**. Current published libSQL 0.9.30 and
its upstream main still use hyper 0.14 and hyper-rustls 0.25; crlt main uses the
same client. Swapping to a prerelease does not repair this chain. No crypto or
TLS implementation is locally forked. Review these exceptions on every upstream
change and before deployment; a green CI audit means the documented policy
passed, not that the resolved graph is advisory-free.

| Advisory | Dependency and exposure / follow-up |
|---|---|
| [RUSTSEC-2024-0388](https://rustsec.org/advisories/RUSTSEC-2024-0388.html) | `derivative` 2.2.0, unmaintained build-time macro in Dock/arkworks. Replace through an upstream family migration. |
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html) | `paste` 1.0.15, unmaintained build-time macro in Dock/arkworks. Same follow-up. |
| [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html) | `proc-macro-error2` 2.0.1, unmaintained Wasmer derive dependency. Remove with unused Dock protocol dependencies when upstream supports it. |
| [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134.html) | `rustls-pemfile` 2.2.0, unmaintained native-root loader wrapper over rustls-pki-types. Await libSQL transport migration. |
| [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | `h2` 0.3.27 unbounded empty frames. The reviewed libSQL connector enables only HTTP/1; crlt does not expose a custom connector. The unused HTTP/2 implementation remains compiled. CI checks the reviewed connector source. |
| [RUSTSEC-2026-0049](https://rustsec.org/advisories/RUSTSEC-2026-0049.html), [RUSTSEC-2026-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104.html) | `rustls-webpki` 0.102.8 CRL matching/parsing. The default libSQL TLS client does not configure CRLs. These exceptions do not cover callers with custom CRL use. |
| [RUSTSEC-2026-0098](https://rustsec.org/advisories/RUSTSEC-2026-0098.html), [RUSTSEC-2026-0099](https://rustsec.org/advisories/RUSTSEC-2026-0099.html) | **Open remote TLS risk:** webpki 0.102.8 mishandles URI/wildcard name constraints after a CA misissues a certificate. Fixed webpki 0.103 versions are incompatible with this libSQL dependency chain. Local-file storage is unaffected; configuring a trusted Turso endpoint does not eliminate CA misissuance risk. Upgrade through crlt/libSQL when a compatible maintained transport is available. |
| [RUSTSEC-2025-0055](https://rustsec.org/advisories/RUSTSEC-2025-0055.html) | `tracing-subscriber` 0.2.25 via ark-relations constraint tracing. cpsd installs no tracing subscriber and emits no request logs. Consumers must not enable an old logging subscriber on untrusted data. |

The CI source guard ties these assessments to exact locked versions and the
published libSQL connector implementation. Other advisories continue to fail
the audit, including new advisories for these same crates. The two TLS
name-constraint exceptions remain residual risks; they are not claimed unreachable.

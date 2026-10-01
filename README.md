# cpsd

Blind passport issuance and per-community pseudonyms for `cvld`, with a native
and `wasm32-unknown-unknown` Rust core. This is an unaudited implementation, not
a production security certification. No registry publication.

## API

1. Generate an `IssuerKey` with an immutable gate catalogue and a shared key ID.
   Publish its `IssuerPublicKey` through an authenticated key ring.
2. On the holder device, generate and retain a `HolderSecret`. Call
   `request_issue` with the issuer's fresh `IssuanceChallenge`; send only the
   `IssuanceRequest`. Keep `PendingIssuance` in the holder's encrypted vault.
3. After authenticating the person/session and checking global gates, the issuer
   calls `issuance_challenge` and `issue_blind_once` with the same
   `AuthenticatedIssuance` context and authorized attributes. The holder calls
   `PendingIssuance::finish`, which unblinds and verifies the signature.
4. Prefer `PresentationRequest::for_epoch` / `Verifier::request_for_epoch`
   with one authenticated expiry shared by the entire epoch. Issue passport
   and passed-gate expiries with that exact value. Sign `request.to_bytes()`
   with the community's `csgn::PersistentSigner`, `Kind::Credential`, and COSE
   expiry `request.now() + 1`. The wallet obtains `AuthenticatedCommunity` from
   the initiating origin's authenticated community ID and csgn key ring.
   `Passport::present(rng, expected, cose, now)` authenticates that scope before
   generating a proof.
   `verify` checks the proof against the verifier's own request and trusted key
   ring and returns a `Pseudonym`, usable as the community member ID.

Structured wire types have versioned `to_bytes`/`from_bytes` methods. The envelope is
version 2, rejecting earlier development encodings; the signed message layout
and cryptographic domain labels retain their v1 definition. Holder vault
encodings contain secrets and return zeroizing buffers. Issuer key backups
belong in the caller's secret store. Randomness uses caller-supplied
`rand` 0.8 `RngCore + CryptoRng`; browser callers must seed from the OS/browser
CSPRNG. Test seeds are never appropriate for application use.

The pure `verify` and `issue_blind` operations check cryptography and do not
consume challenges. Repeating the same valid proof against the same request
will pass them. Single-use challenge state is required at the service boundary.
Neither a holder-supplied time nor a holder-supplied key ring is authoritative.

## Dependency survey and choice

Reviewed upstream sources and crates.io's index on 2026-09-30:

| Candidate | Decision |
|---|---|
| [Dock crypto](https://github.com/docknetwork/crypto): [`bbs_plus` 0.25.0](https://crates.io/crates/bbs_plus), [`proof_system` 0.34.0](https://crates.io/crates/proof_system), `bulletproofs_plus_plus` 0.9.0, `dock_crypto_utils` 0.23.0 (Apache-2.0) | Selected. Blind BBS+ issuance, composite witness equalities, hidden range predicates, and an upstream Wasm path. These are the latest published releases found in the registry index, dated 2025-08-03; maintenance is uneven, not assumed current merely from the project name. Exact versions preserve the reviewed proof encoding. |
| [Dock pseudonyms](https://github.com/docknetwork/crypto-wasm-ts#pseudonyms) | Selected composition: a one-base Pedersen/Schnorr statement with its secret equated to the hidden BBS+ message. Upstream primitives implement all cryptography. |
| [Dock SyRA](https://github.com/docknetwork/crypto/tree/main/syra) (Apache-2.0) | Reviewed but unnecessary here: SyRA handles low-entropy credential attributes through a different issuance protocol. Our holder secret is uniformly random and high entropy. |
| [zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium) (Apache-2.0) | Useful IETF draft reference/fallback, not selected: research implementation and a different suite; it does not supply this composite range-proof/accumulator path. Its optional CL03/GMP path must not be confused with its BBS features. |
| [MATTR pairing_crypto](https://github.com/mattrglobal/pairing_crypto) (Apache-2.0) | Reviewed as another BBS implementation; lacks the selected composite predicate path. |
| [AnonCreds](https://github.com/anoncreds/anoncreds-rs) (Apache-2.0) | CL issuance/revocation is a different, heavier stack, without the chosen browser pseudonym composition. |
| [csgn](https://github.com/corbet-foss/csgn/tree/d7203f310c3c129c3f67ef4ef3e34ccf0ae8c93b) | Selected for request authentication: main already exposes strict COSE verification and persistent signing. Pin the reviewed revision; use verification-only features in the library. Direct coset + dalek would duplicate its canonicalization, key-ring and retention rules. |
| [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) | Selected for CI advisories and SPDX license checks. cargo-audit alone would not cover licenses. No crypto changes. |
| [crlt](https://github.com/corbet-foss/crlt) | Its GitHub main exposes scoped transactions, migrations and indexed queries over official libSQL; selected for native storage. |

Arkworks 0.4 is required by Dock, rather than mixed with newer incompatible
curve types. Blake2 is RustCrypto; zeroize handles owned secret buffers. These
supporting dependencies are MIT/Apache/BSD compatible. No GPL-only or AGPL-only
dependency is permitted. The package's own LGPL linking exception is unchanged. CI checks the complete
resolved license inventory against reviewed expressions; `self_cell` uses its
Apache-2.0 alternative, not its optional GPL license.

`proof_system` unconditionally pulls Circom/LegoGroth16 and Wasmer even though
cpsd never uses them. We select Wasmer's native backend on native and JavaScript
backend on Wasm. This is substantial upstream dependency overhead. Our decoder
only accepts the BBS+/Schnorr/Bulletproofs++ proof variants used here.
Wasmer 6.1.0 fails against the newer typed JavaScript function and Wasm pointer
APIs, so the Wasm bridge is pinned to its [upstream lockfile's compatible
versions](https://github.com/wasmerio/wasmer/blob/v6.1.0/Cargo.lock):
`wasm-bindgen` 0.2.104 and `js-sys`/`web-sys` 0.3.81. The test runner uses the
matching version. Review this compatibility constraint when upgrading Dock;
no Wasmer or cryptographic implementation is forked here.

## Security decisions

The signed vector is fixed by the issuer's gate catalogue: holder secret,
key ID, policy epoch, passport expiry, reserved revocation handle, then one
expiry per gate (zero means absent). No raw gate data or provider identifiers
enter the passport. The issuer is responsible for checking providers and
normalizing their results before signing.

Issuance uses a perfectly hiding Pedersen commitment to the secret. A Dock
composite proof binds knowledge of that commitment's opening to an issuer-only
tag derived from the same secret. `cglb` must bind that tag to the authenticated
person's uniqueness fingerprint on first issuance and require it on renewal;
otherwise a person could choose another secret and obtain new community IDs.
`issue_blind_once` now enforces this binding atomically through `IssuanceStore`;
only the explicitly stateless `IssuerKey::issue_blind` leaves it to its caller.
The tag is linkable at the issuer by design, never included in presentations.
A passport does not enforce one-person-one-credential on its own.

For a community C the pseudonym is `s * H_G1(domain || C)`. The exact canonical
community bytes are immutable. It is stable across renewals and key rotations.
The base is derived with Dock's hash-to-curve routine, not hash-to-scalar times
a known generator, which would allow cross-community linking. All pseudonyms
stay in G1 of the asymmetric BLS12-381 pairing; no matching G2 value for the
holder secret is exposed. Cross-community unlinkability relies on DDH in G1
and the security of the composed proofs. Collision/bit-distribution tests are
regression checks, not statistical proofs of computational unlinkability.

The recommended shared-epoch presentation combines a BBS+ signature proof and
a pseudonym opening proof. The verifier supplies its already-known common
expiry, and BBS+ selective disclosure proves that the signed passport expiry
and every requested gate expiry **equal that value exactly**. These values
come from verifier policy, never from a holder-selected disclosure. There are
no range predicates or extra setup assumptions in this profile. Only the key
ID, epoch, requested gates, common expiry and pseudonym are disclosed.

The issuer must authenticate the epoch schedule and only include a gate whose
underlying validity reaches the epoch expiry. Normalize such gate expiries to
the common expiry; never round a shorter-lived gate upward. Such a gate needs
renewal or must be omitted for that epoch. Wallets must accept the shared
schedule, not arbitrary per-person expiry requests. This trades independent
gate lifetimes for predictable browser latency without exposing individual
dates. No automatic fallback is permitted for a registered shared-epoch request.

`PresentationRequest::new` / `Verifier::request` retain an independent-expiry
profile. It additionally uses one Bulletproofs++ range proof per passport and
requested gate, equated to the signed messages. Exact expiries stay hidden,
avoiding issuer-selected dates becoming cross-community tags, but this profile
does **not** meet the browser latency target with several gates. Unrequested
gates, the signature and revocation handle stay hidden in both profiles.

The full issuer public key/catalogue, community, epoch, requested gates,
expiry profile/common expiry, verification time and fresh challenge bind the transcript. Verifiers select
trusted keys and policy themselves. All holders should share the same
issuer key/catalogue and epoch cohort: a malicious issuer can still fingerprint
people through unique keys, catalogues, denial of service or timing. Wallets
must authenticate the actual community scope and trusted issuer parameters.
`present` requires a csgn signature from the expected community's pinned ring
and exact equality with its community ID. The expected association must come
from authenticated discovery tied to the initiating origin, never from request
fields, query parameters, an untrusted redirect or a ring included in the request.
Even a valid signature from community A cannot authorize a request for B.
The existing csgn Credential envelope carries the exact versioned cpsd request;
its magic/version/kind distinguishes it from other credential payloads.
The service uses `PersistentSigner` to commit key-retention metadata before
publishing; `cpsd` needs only csgn's verification features.
The wallet-code trust assumption is explicit: the wallet origin and delivered
JavaScript/Wasm must be honest. An operator serving malicious wallet code can
read the holder secret, substitute trust anchors, or compute any pseudonym
without calling `present`. Signed requests protect an honest wallet against
malicious verifiers; they cannot protect a secret from the code holding it.
Transport, network timing, browser compromise and voluntary credential sharing
are outside this library's cryptographic guarantees. Arkworks does not promise
constant-time browser execution; local timing/side-channel attackers are outside
this implementation's guarantees.

The versioned wire format rejects trailing bytes, noncanonical encodings,
invalid/subgroup/identity keys and pseudonyms, excessive sizes, unrelated proof
variants, wrong statement counts, malformed range dimensions and response
indices. These checks are necessary because the general upstream verifier
assumes some dimensions and accepts extra statement proofs. No local signature,
curve, Fiat-Shamir, range-proof or hash primitive is implemented.

Owned secrets and vault buffers wipe on drop; Debug output excludes scalar
secrets and signatures. This is best-effort memory hygiene, not a claim that
compiler temporaries, upstream witness copies, process dumps or every allocator
copy are erased. Protect the holder vault and disable secret-bearing dumps.
The library emits no request logs or login records.

## Revocation

V1 accepts exactly the requested policy epoch and proves inclusive validity
`verification_time <= expiry < 2^40`. Timestamp zero is forbidden so a missing
gate cannot pass a range proof. The service enforces short validity and refuses
renewal while the person is suspended. Bumping the epoch invalidates a cohort;
individual early revocation is **not** implemented. The worst-case individual
suspension delay is the remaining passport lifetime (up to one shared epoch).

A hidden, signed random revocation handle reserves a future accumulator witness
binding. V2 must add a Dock `vb_accumulator` nonmembership statement with a
witness equality to that signed handle, authenticate the accumulator snapshot,
and version the wire protocol. A separately checked callback or a publicly
revealed global revocation index would not provide the required binding/privacy.
Existing v1 passports do not magically gain accumulator revocation.

## Verification

GitHub Actions runs formatting, Clippy with warnings denied, native real crypto
round trips, and the Wasm target check. Tests exercise hostile holders bypassing
client checks, transcript changes, wrong keys, renewal, malformed encodings,
expiry boundaries and pseudonym distribution. Performance tests print measured
operation durations and proof size; native timings do not establish browser
performance. Cargo is never run on the workstation.

The implemented contract is in [docs/CONTRACT.md](docs/CONTRACT.md).

## Challenge storage and service integration

Use `Verifier<S>::request_for_epoch` and `Verifier<S>::verify` for admission.
`request` remains available for independent hidden expiries. The request's
verification time is the **challenge deadline**, so a passport that expires
while its proof is being made cannot slip through. Supply the current
authoritative epoch and time at verification. Only a successful atomic consume
returns the pseudonym. Invalid proofs leave the challenge available; concurrent
valid proofs produce at most one success. Issue through `issuance_challenge`
and `issue_blind_once` for the analogous issuance replay boundary. Pass an `AuthenticatedIssuance` with the authenticated opaque global person ID
and session ID to **both** functions. The challenge digest binds both IDs and
the full issuer key. `issue_blind_once` rejects an absent/expired/mismatched
nonce before cryptography, validates the issuance proof, then atomically
registers or checks the person's issuer tag while deleting the nonce. Only
then can the blind response escape. Concurrent first issuances with different
secrets yield one winner; failed proofs or tag mismatches leave the nonce and
existing tag unchanged. New sessions and rotated issuer keys keep the same tag.
The caller authenticates sessions, assigns stable opaque person IDs, authorizes
gates and enforces suspension. Never accept authentication IDs from request
bodies or create a new person ID to bypass continuity.

`ChallengeStore` is a small fixed-community capability with a cheap `matches`
lookup before pairings and an atomic final `consume` to resolve races.
`IssuanceStore` extends it with atomic tag registration/checking and consumption.
Its `VerifiedIssuance` input has no public constructor, preventing accidental
registration of unproven request tags through the store API. `MemoryStore` shares
state across clones. Native `storage::libsql::LibsqlStore` uses the actual
`crlt` API following main with a reproducible locked revision; no direct libSQL fallback is needed.
The default `storage` feature enables it on native; Wasm excludes it. Append
`storage::libsql::SCHEMA` to the service's complete crlt migration history and
`ISSUANCE_SCHEMA` as a **new** migration for the global issuer, then
construct the adapter with its `Db`, canonical community ID and capacity.
Use `check_indexes` for community databases and `check_issuance_indexes` for the
global issuer's complete challenge and tag query plans.

One DB per community, plus a separate global issuer DB. The table has a
community key in its primary key and expiry index; queries pass through crlt's
namespace and query-plan checks. A reversible hex encoding maps arbitrary
community bytes to the namespace. Only a random nonce, request digest and
challenge expiry persist while a challenge is outstanding. The global issuer
also retains `(community_id, opaque_person_id, issuer_tag)` for continuity,
without sessions, dates or issuance history. Tags are never pruned or replaced
on renewal/key rotation. This is necessary uniqueness state, held only in the
global DB, never published to communities. No community pseudonym, proof, raw
request, issued-at/used-at date, or history table is stored.
Successful consumption deletes the row; call `prune` regularly for expired
pending rows. The service must limit challenge lifetimes, rate and capacity.
Database backups/WAL retention are operational policy, not a library guarantee.

Losing nonce state rejects all outstanding challenges. Losing or rolling back
the global person/tag registry destroys uniqueness continuity: the service must
fail closed and restore authoritative state before issuing again. Never reset
a live person's tag. MemoryStore is ephemeral and unsuitable for durable global
issuance across restarts. Pending capacity does not cap the person registry;
the authenticated global service owns registration quotas and person lifecycle. A consumed random nonce must
never deliberately be reused (there is no historical nonce ledger). Remote
write timeouts fail closed but can leave outcomes uncertain; obtain a new
challenge. Key-ring/epoch refresh must be coordinated by the service across
instances; policy changes during an in-flight call have normal snapshot
semantics. The library does not store a policy history or user revocation list.

Tests run real libSQL files, reopen databases, race independent pools, check
capacity/isolation/index plans, and run real cryptographic sessions through both
backends. `optional_real_turso_roundtrip` skips unless **both** `TURSO_URL` and
`TURSO_TOKEN` are nonempty. Only supply a disposable test DB on an authorized
runner. Credentials belong neither in the repository nor in CI.

CI also executes the release-profile Wasm test (thin LTO, one codegen unit) in headless Chrome using
[wasm-bindgen-test](https://wasm-bindgen.github.io/wasm-bindgen/wasm-bindgen-test/browsers.html).
It prints first/median proving time, median verification time and proof size for
0, 1 and 3 disclosed gates in both profiles, with five samples each. The
shared-epoch profile must have a median below one second. Independent-expiry
timing remains visible as a documented limitation: the initial release build
measured 544.5 ms for zero gates and 1088.8 ms for one gate in
[the browser run](https://github.com/corbet-foss/cpsd/actions/runs/36652266918).
The shared-epoch path changes the policy/proof workload, not the acceptance
threshold. This measures a hosted desktop browser, not mobile devices or the
maximum 64-gate case. The same real issuance/proof flow runs inside the browser
with a CSPRNG seeded from its randomness API.

Measured in [successful CI run 36653547706](https://github.com/corbet-foss/cpsd/actions/runs/36653547706)
on 2026-09-30, Chrome 153.0.8010.52, Rust 1.98.1, GitHub's `ubuntu-latest`
runner, five samples per case:

| Expiry profile | Requested gates | Median prove (ms) | Median verify (ms) | Proof bytes |
|---|---:|---:|---:|---:|
| Shared epoch | 0 | 17.8 | 20.6 | 686 |
| Shared epoch | 1 | 17.3 | 20.3 | 654 |
| Shared epoch | 3 | 16.7 | 19.6 | 590 |
| Independent hidden | 0 | 489.3 | 98.4 | 1997 |
| Independent hidden | 1 | 966.1 | 174.9 | 3276 |
| Independent hidden | 3 | 1918.2 | 329.9 | 5834 |

These are measurements, not cross-device guarantees. More revealed shared
values reduce the BBS+ response count, hence the smaller shared-epoch proofs.
That historical run passed 17 crypto unit tests, 7 executed storage/session tests, the
browser test and all required checks. The eighth storage test reported the
intentional real-Turso skip because neither credential was supplied. CI also
reviewed license expressions for all 400 locked packages.

## Security regression checks and dependency follow-up

The security regression suite covers signed scope/key/kind/time rejection,
foreign-community pseudonym substitution, a different secret with the witness
equality deliberately removed, extra issuance generators, expired and
foreign-issuer nonces, person/session swapping, conflicting first-registration
races, renewal/key rotation, and decode-encode identity for nested ark fields.
Both memory and real libSQL execute the session and continuity contract.

CI runs `cargo deny check advisories licenses`, pins every action by full SHA,
and executes a bounded, instrumented decode-encode identity fuzz target seeded
with real synthetic protocol encodings plus scalar-modulus and noncanonical
infinity inputs. Longer campaigns use `cargo +nightly fuzz run decode_encode`
on a build runner. A short CI campaign is regression evidence, not exhaustive
parser assurance. See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for the Dock
maintenance watch and dependency audit policy.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.

## Nonexporting deterministic holder

`OpaqueHolder::from_seed(&mut [u8; 32])` is the narrow passport engine embedded
by `cwlt` Wallet. `ckmg` Keys derives the dedicated, purpose-separated seed.
The dedicated holder seed is wiped after initialization. The engine retains its
holder scalar, pending issuance opening and verified passport; it exposes only
public issuance messages, signed attributes, issuer tags, pseudonyms and existing
authenticated presentations. There are no secret, RNG, passport, Clone, Debug or
serialization accessors. Wallet retains the engine and passport, and enforces
a current authorized capability before lending each operation. Vault wires that
capability; Keys does not retain the passport or perform presentations.

The identity recipe is upstream `rand_chacha::ChaCha20Rng::from_seed` at stream
and position zero, followed by the existing arkworks nonzero scalar sampler.
ChaCha20 is chosen instead of StdRng, whose algorithm is not a stable identity
contract. The 0.3 compatibility line matches arkworks 0.4's rand-core traits;
no RNG, scalar sampler, KDF or BBS+ primitive is implemented here. See the
[upstream reproducibility contract](https://docs.rs/rand_chacha/latest/rand_chacha/).
Changes to this recipe require explicit identity migration and fixed vectors.
The seed is already purpose-separated by the caller; PRF roots never enter this
API. Scalar/passport drop wiping remains in the existing zeroizing types;
upstream RNG transient stack-state wiping is not a guarantee of rand_chacha.

`begin_issuance` refuses a second outstanding attempt. `finish_issuance` consumes
its opening even on rejection and installs only a verified answer. A failed
renewal or cancellation preserves the previous verified passport. Fresh proof
randomness is supplied independently for every issuance/presentation. This port
does not export a vault checkpoint: restoring it derives identity and then
performs fresh blind issuance. Legacy scalar-exporting APIs remain for existing
callers and must not be exposed by Wallet or a frontend.

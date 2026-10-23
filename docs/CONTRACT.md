# cpsd contract, durable state v2 and exchange proofs v3

Rust facade over Dock BBS+ and composite proofs. Native and wasm32 holder and
verifier core. LGPL-3.0-only WITH LGPL-3.0-linking-exception. No own cryptographic
primitives, raw gate data, login dates, request logging or registry publication.

## Operations

- Issuer: `IssuerKey::generate`, publish `IssuerPublicKey`,
  `issue_blind(request, challenge, authorized_attributes) -> BlindPassport`.
- Holder: `HolderSecret::generate`, `request_issue -> (request, pending)`,
  `pending.finish -> Passport`, `present(rng, passport, expected_community, signed_request, now) -> Presentation`.
- Requests: `PresentationRequest::for_epoch` for the recommended common-expiry
  profile; `PresentationRequest::new` for independent hidden expiries.
- Verifier: `verify(trusted_keys, own_request, presentation) -> Pseudonym`.
- All crypto operations accept a caller CSPRNG. No network or clock is read by
  the core. Times/epochs/key rings are supplied by the authoritative service.

The passport signs a blinded holder secret, key ID, epoch, expiry, hidden
revocation handle and a fixed gate catalogue's expiries. Missing gates sign
zero. Timestamps must be in `1..2^40`, validity is inclusive, and at most 64
gates are supported. Gate results here are only authorized global proof
presence/expiry; provider checks and uniqueness belong to `cgbl`.

A presentation proves signature possession, equality of the signed secret
with the community pseudonym's exponent, current epoch, passport validity and
validity of every requested gate. The common-expiry profile requires passport
and requested gate expiries to equal the verifier's authenticated epoch expiry
exactly, and requires that expiry to cover the verification time. The issuer
only includes gates valid through that expiry; it never rounds them upward.
BBS+ reveals this already-known common value. The independent-expiry profile
instead hides individual dates using range predicates, at greater browser cost.
Both disclose key ID, epoch, requested gates and pseudonym, bound to the full
public key, community, expiry profile, time and challenge. The verifier selects
the profile and common expiry; a holder cannot downgrade a registered request.
Same secret/community gives the same pseudonym through renewal;
different communities rely on DDH in G1 for unlinkability.

Pure verification is deliberately stateless: single-use challenge consumption
is a separate mandatory service operation. An identical proof for an identical
request is still a valid mathematical proof. `issue_blind_once` enforces issuance
tag continuity and authenticated person/session binding; the stateless signing
primitive remains available only for callers implementing equivalent state.

V1 revocation is expiry plus epoch. No immediate individual revocation or
accumulator witness is implemented. The hidden signed handle is an extension
point for an authenticated accumulator statement in a future composite proof.

See the README for threat assumptions, dependency choice, caller obligations
and verification limits. Neither tests nor the dependency choice constitute an
independent security audit or an IETF BBS/W3C/EUDI conformance claim.

## Stateful boundary and storage

`Verifier<S>::request_for_epoch` (or `request` for independent expiries) creates
and registers a challenge. Verification enforces validity through its
deadline, checks the service's current epoch/time, performs an indexed nonce/binding lookup before pairings, verifies the proof and
atomically consumes the registered request digest before returning the
pseudonym. `issuance_challenge` / `issue_blind_once` provide single-use issuance.
The pure operations remain available for applications with equivalent session
state. They must never be treated as replay prevention by themselves.

The holder accepts only COSE bytes verified through the expected community's
origin-authenticated csgn key ring (`AuthenticatedCommunity`). The COSE kind is
Credential, the payload is exactly a canonical cpsd PresentationRequest, and
its exclusive expiry equals the inclusive challenge deadline plus one. In the
independent-expiry profile the deadline may lie at most
`MAX_REQUEST_AHEAD_SECONDS` (300 s, the stamp clock skew) after the wallet's
time: the deadline is also the lower bound of the hidden expiry ranges, and a
far-future deadline would make the holder's answer a range oracle for them. The
expected community must equal the signed scope. Authentication, time and scope
checks precede all proof generation. The caller supplies trusted wallet time;
service verification still enforces authoritative time and epoch.

`AuthenticatedIssuance` carries opaque authenticated person/session IDs; both
bind the challenge digest with the full issuer key under the v2 issuance-slot
domain. Old unbound pending issuance nonces therefore fail closed after upgrade.
`IssuanceStore::consume_issuance` receives an unforgeable `VerifiedIssuance`
created only after proof validation. In one transaction it checks the unexpired
nonce/binding, registers the first issuer tag or requires the existing one,
and consumes the nonce. Any mismatch rolls back; no signed answer is released
before commit. Two competing first secrets cannot both win, even with distinct
sessions/challenges. Same-secret renewal survives key rotation. Session
validation, stable person assignment, gates and blocks belong to cgbl.

`ChallengeStore` defines scoped reserve, cheap lookup, compare-and-delete and expiry pruning.
`MemoryStore` and the native `storage::libsql::LibsqlStore` implement it. Native
storage uses the crlt Git dependency; its published main API was available.
Caller-managed crlt migrations install `SCHEMA` and append `ISSUANCE_SCHEMA`
as a new migration on the global issuer database; old migration text is unchanged.
`check_indexes` checks community challenge plans; `check_issuance_indexes` also
checks the global person/tag plans. Community databases need no person registry. Capacity is bounded; nonce
collisions do not overwrite. All SQL uses community-scoped composite indexes,
including pruning. No pseudonyms, holder keys, passports, raw gates, login dates
or request logs are stored. The global issuer retains an opaque person-ID/tag
mapping with composite primary key `(community_id, person)` and no dates.
Only cpsd can construct the proof-validated tag-registration input. Tags persist
through nonce pruning/restart/key rotation and cannot be overwritten by renewal.
Database integrity, rollback prevention and authoritative restoration are service
responsibilities; lost global continuity state must stop issuance. Outstanding random nonces, request digests and
deadlines are deleted on consumption or expiry pruning. `cgbl` has a separate
global DB; community verifiers each receive their own community DB.

Tests must include real cryptographic round trips, hostile holder attempts,
nonce replay/concurrency, expiry/epoch boundaries, rotation, canonical encoding,
real libSQL storage, isolation, persistence and `EXPLAIN QUERY PLAN`. Optional
real Turso tests skip unless both environment credentials are supplied.

The browser acceptance target is enforced for the recommended common-expiry
profile. Independent hidden-expiry proofs are measured but currently exceed
one second with multiple predicates. Mobile performance remains unmeasured.
Durable state uses envelope v2; exchange proofs and authenticated presentation
requests use original v3. The signed message layout remains v1 and issuance
storage binding remains v2. Accumulator revocation remains future work.

## Trust and audit boundaries

The origin-to-community/key-ring mapping and the wallet code are trusted.
Malicious delivered JavaScript/Wasm can exfiltrate the secret or bypass this
API; signed scope checks protect an honest wallet against verifier substitution.
Arkworks is not claimed constant-time in browsers. An individual block takes
effect by expiry/epoch refresh, up to the remaining shared epoch.

All ark fields require validated decoding followed by exact canonical
re-encoding equality, including nested keys/signatures/scalars and points.
The bounded decoder retains its proof-shape checks before upstream allocation.
The `decode_encode` fuzz target checks every exported protocol decoder with an
encoding inverse. CI executes native tests, browser round trips, Wasm checks,
Clippy, formatting, dependency advisories/licenses and bounded fuzzing.

The storage dependency uses the shared current crlt revision. zeroize uses the
compatible 1.9 range, allowing security updates and one zeroize version across
facades. Native, browser, Wasm and fuzz checks use the committed lockfiles. CI
rejects duplicate Corbet packages and floating transitive Git pins.

Global issuance binds each verified issuer tag to exactly one stable authenticated
person, as well as binding each person to one tag. Without the reverse constraint,
a holder could use a second global account to renew the same community pseudonym
after a block. Both directions are checked with nonce consumption in cpsd's
single transaction; rejected duplicate claims leave the nonce reusable by the
proper independent holder. Bindings survive expiry and pruning forever.

Global SQL deployments append `ISSUANCE_UNIQUENESS_SCHEMA` after
`ISSUANCE_SCHEMA`. This new unique index fails closed on historical duplicates;
it never silently frees a holder binding. Community presentation stores require
only the original challenge schema. cgbl delegates these invariants to cpsd.

## Opaque holder port

`OpaqueHolder` owns deterministic HolderSecret plus at most one pending opening
and one verified Passport. `from_seed(&mut [u8;32])` wipes its input; the upstream
ChaCha20/nonzero-arkworks recipe defines identity. Empty -> pending -> ready;
ready may enter renewal while retaining its previous credential. A duplicate
begin refuses; cancel drops only the opening; finish consumes an opening and
updates the credential only after existing signature verification. No opening
or credential object, scalar bytes, seed, RNG, Clone, Debug or serialization
capability is exported. `present` retains the existing authenticated-community,
signed-request, lifetime, expiry, policy epoch and proof checks.

Wallet (`cwlt`) retains this object and the passport, and calls it only through
a current authorized capability. Keys (`ckmg`) derives the dedicated holder seed;
it does not retain the holder or perform presentations. Vault only wires the
Wallet capability. Public identity
reconstruction is deterministic; issuance/proof randomness is fresh and separate.
Native and browser tests execute real blind issuance, proof verification,
restoration equality, wrong-scope/expiry and failed-renewal refusal. Compile-fail
examples guard the absence of scalar/serialization/cloning accessors.

The v1 public identity vector uses the dedicated holder seed `[7; 32]` and
community bytes `community-a`. Its canonical compressed pseudonym hex is:

```text
97322b8893bb653c820feb6b9915315da5e5f7716e15ad1ac521b18643b695dcb3a24b42ae422847f63d03efb782af60
```

Native and actual browser tests assert this same fixed value before performing
fresh issuance. The test request uses the existing shared-epoch expiry profile
and the authenticated request's required exclusive COSE expiry (`now + 1`).

## Original v2 holder sealing

`from_seed_and_sealing_key` consumes and wipes the independently derived holder
seed and sealing key. The wallet context and original
`cpsd.opaque-holder.v1\0` AAD remain immutable. `seal` uses maintained
XChaCha20-Poly1305 with fresh caller-supplied randomness; `restored` returns a
separate nonexporting candidate after original identity, pending-opening and
passport-signature checks. Neither method grants durability or currentness.
Wallet must adopt the candidate only after its original matching Store receipt.
The original `from_seed` constructor remains unbound and refuses sealing.

The non-root aggregate and ciphertext containers retain original format2 kinds
10 and11, with the unchanged v2 secret/pending/passport codecs. All existing
main proof and presentation formats remain unchanged. Authenticated extended
v3/kind12 root-board state uses the original separate root-board owner codec. Its
credential and pending opening must match the same hidden holder; malformed or
foreign state refuses intact and is never stripped or resealed as a non-root holder.

Root-board descriptors, issuance contexts, proofs and joint presentation retain
their original v3 kinds and Dock protocols. Nested presentation requests use the
same exact canonical v3 framing as the ordinary owner. Root authentication reads
the original signed v3 request inside the complete authenticated root context;
no v2 exchange frame is relabeled or upgraded.
Source role authorization and atomic nonce consumption remain duties of the
original service before signature release. This library supplies no admin role.

The original root-board crypto, sealing, replay and hostile-composition tests are
ported, with explicit cross-version codec regressions. CI runs them natively
(`cargo test --locked` in `.ci/verify.sh` includes `tests/root_board.rs`). The CI
browser leg runs only the `browser`, `opaque_holder`, `boundaries` and
`stamp_vectors` test targets, so browser execution of this additive root-board
stage remains unqualified.

On 2026-10-11 the preceding v2 baseline passed native Clippy, 75 Rust tests and
six compile-fail doctests. Complete custody readiness is not claimed.


## Original lower Dock proof migration

The ordinary issuance and presentation paths now use the preserved original v3
BBS+/Schnorr/Bulletproofs++ composition directly, with no general proof-system
or Wasmer dependency. Only exchange kinds 3, 8 and 9 change to v3. Keys,
passports, pending issuance, ordinary sealed holder state and the original
root-board formats keep their exact existing encodings. Restoring state does not
upgrade an old signed request or exchange proof. The private verified root
issuance signing step and existing scoped nonce storage remain unchanged.

[PROOF-V3.md](PROOF-V3.md) defines the exact original transcripts and strict wire
shapes. Tests retain the real current holder, privacy, SQLite and root-board
scenarios and add original deterministic cross-target proof vectors and hostile
compositions made from maintained primitives. The preserved source contained
two old general-proof shape tests; these now exercise equivalent trailing-byte,
missing-range, partial-signature and oversized-range refusal in the fixed v3
codec. CI checks the formatting, compiles and runs these tests natively
(`.ci/verify.sh`). Its browser leg does not run `tests/proof_vectors.rs`, and the
`CPSD_VECTOR` hashes that file prints are not compared across targets by any
check, so browser execution of this port and actual cross-target vector equality
remain unqualified.

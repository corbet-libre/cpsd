# cpsd contract, wire format version 2

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
presence/expiry; provider checks and uniqueness belong to `cglb`.

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
its exclusive expiry equals the inclusive challenge deadline plus one. The
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
validation, stable person assignment, gates and suspension belong to cglb.

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
deadlines are deleted on consumption or expiry pruning. `cglb` has a separate
global DB; community verifiers each receive their own community DB.

Tests must include real cryptographic round trips, hostile holder attempts,
nonce replay/concurrency, expiry/epoch boundaries, rotation, canonical encoding,
real libSQL storage, isolation, persistence and `EXPLAIN QUERY PLAN`. Optional
real Turso tests skip unless both environment credentials are supplied.

The browser acceptance target is enforced for the recommended common-expiry
profile. Independent hidden-expiry proofs are measured but currently exceed
one second with multiple predicates. Mobile performance remains unmeasured.
Envelope version 2 rejects the earlier development format; the signed message
layout and cryptographic domain labels remain v1 (issuance storage binding is v2). Accumulator revocation remains future work.

## Trust and audit boundaries

The origin-to-community/key-ring mapping and the wallet code are trusted.
Malicious delivered JavaScript/Wasm can exfiltrate the secret or bypass this
API; signed scope checks protect an honest wallet against verifier substitution.
Arkworks is not claimed constant-time in browsers. Individual suspension takes
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
after suspension. Both directions are checked with nonce consumption in cpsd's
single transaction; rejected duplicate claims leave the nonce reusable by the
proper independent holder. Bindings survive expiry and pruning forever.

Global SQL deployments append `ISSUANCE_UNIQUENESS_SCHEMA` after
`ISSUANCE_SCHEMA`. This new unique index fails closed on historical duplicates;
it never silently frees a holder binding. Community presentation stores require
only the original challenge schema. cglb delegates these invariants to cpsd.

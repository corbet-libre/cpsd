# Confirmation stamp: internal security argument

Status: internal written argument, 2026-10-14, revised 2026-10-15 after the
internal security review (custody, expiry cohort, prune margin, confirmation
binding, issuance window), for stamp format v1 (envelope version 4, kinds 20
to 28). It replaces an external review, which is not
budgeted. It is a structured argument from published results and the code,
not a machine-checked proof. Nobody has independently audited the Dock crates
either (README, "Dependency survey and choice"). Product authority: the
confirmation design in the cvld gate architecture task ("One confirmation per
device", section "Stamp construction").

## 1. What the stamp is for

A device obtains one stamp after one user verification at the wallet. The
stamp approves up to sixteen pre-committed actions, one per community. Each
community checks its own action offline, under the member's existing
per-community pseudonym. The wallet never sees an action or a community.
A community never sees anything that links the member to another community.

## 2. Construction

### 2.1 Building blocks

| Block | Implementation | Assumption it rests on |
|---|---|---|
| BBS+ signature in G1 over BLS12-381 (Au, Susilo, Mu 2006; proof of knowledge of Camenisch, Drijvers, Lehmann 2016, section 4.5) | Dock `bbs_plus` 0.25 `SignatureG1`, `PoKOfSignatureG1Protocol` | q-SDH (unforgeability); proof soundness and zero knowledge in the random-oracle model |
| Blind issuance over a Pedersen commitment | `SignatureParamsG1::commit_to_messages`, `SignatureG1::new_with_committed_messages`, `unblind` | DL among the hashed generators (binding); uniform blinding (perfect hiding) |
| Multi-base Schnorr proof of the commitment's opening | `schnorr_pok` 0.23 `SchnorrCommitment` and `SchnorrResponse` | DL; special soundness; honest-verifier ZK |
| Discrete-log proofs (issuer tag, pseudonym) | `schnorr_pok::discrete_log::PokDiscreteLog` | DL |
| Fiat-Shamir | `dock_crypto_utils` Merlin transcript; one challenge per statement | random-oracle model |
| Generators, community and tag bases | Dock try-and-increment hash-to-curve from public labels | nobody knows DL relations between them |
| Pseudonym `secret * H(community)` | unchanged passport construction | DDH in G1 (XDH: G1 of the type-3 pairing) |
| Digest | BLAKE2s-256 over a length-prefixed encoding | collision and second-preimage resistance |
| Slot scalar | `hash_to_field::<Fr, Blake2b512>` of the 32-byte digest | collision resistance; bias of a 512-bit reduction is negligible |

cpsd adds no cryptographic primitive. It composes the libraries' public APIs
and checks every equality between the composed proofs explicitly.

### 2.2 Keys and message layout

A stamp issuer key is a separate BBS+ key. Its generators are hashed from
`"cpsd/stamp/v1/bbs-plus-signature-params" ‖ key-id ‖ 16`. Passport
generators are hashed from a different domain, so the two never share `g1`,
`g2`, `h_0` or any `h_i`, even under one key ID. The public key carries the
expiry cohort length `P`, which the wallet takes from its rulebook
(`StampParams`) when it creates the key. `P` is a whole number of hours that
divides one day (1, 2, 3, 4, 6, 8, 12 or 24 hours), so cohorts align with UTC
days. Nothing finer than one hour is accepted by any party. The library holds
no default; the rulebook default is one UTC calendar day (`P = 86400`).

| Index | Message | Issuer sees | Revealed in a presentation |
|---|---|---|---|
| 0 | holder secret `s` (the passport secret) | no (committed) | no |
| 1 | key-ID scalar | yes | yes |
| 2 | stamp epoch | yes | yes |
| 3 | expiry `X` (exclusive end of a cohort) | yes (computed) | yes |
| 4 to 19 | slots `d_0 … d_15` | no (committed) | exactly one |

A slot holds `hash_to_field(digest)` for each action, or a uniformly random
scalar. The device shuffles the slots with its CSPRNG.

### 2.3 Digest

`digest = BLAKE2s-256(L("cmty.stamp.v1") ‖ L(fingerprint) ‖ L(pseudonym) ‖ L(kind) ‖ L(payload digest) ‖ L(salt))`.
Here `L(x)` is the big-endian `u32` length followed by `x`. The fingerprint is
the community's pinned 32-byte fingerprint and the pseudonym is the member's
48-byte compressed pseudonym in that community. The kind is a short ASCII
label, the payload digest is the caller's 32-byte digest of the exact action,
and the salt is 32 fresh random bytes. Two independently computed known
answers are in `src/stamp/tests.rs`.

### 2.4 Custody

The holder secret `s` is the passport secret, the identity root of every
pseudonym. Only `OpaqueHolder` uses it for stamps, exactly as for passport
presentations: `begin_stamp`, `finish_stamp`, `cancel_stamp`, `stamp_covers`
and `present_stamp` take scopes, actions, keys and wallet messages, never a
secret, and return only public messages. The request function and the pending
and stamp types are crate-private.

The pending request keeps the Pedersen blinding, the sixteen slots, the stamp
key and the request time. A stamp keeps the key, epoch, `X`, slots and the
unblinded signature. Neither encoding contains `s` in any form. The opaque
holder supplies `s` when it unblinds, restores and presents. A restored stamp
must verify under the restoring holder's secret, so a stamp never moves to
another identity. Both live inside the holder and its sealed state (kind 27:
secret, passport fields, root-board field, then the stamp state). The secret
is stored once, in its own field. Without stamp state the sealed plaintext is
byte-identical to before. A holder keeps one pending request and at most eight
stamps; a new stamp first drops expired ones, then the one that expires first.
Tests: `pending_stamp_stamp_and_state_encodings_carry_no_secret_bytes`,
`stamp_state_survives_a_restart_and_never_repeats_the_secret`,
`authenticated_foreign_or_empty_stamp_state_is_refused`, the compile-fail
examples on `OpaqueHolder`, and `tests/stamp_holder.rs`.

### 2.5 Issuance

1. The wallet reserves a single-use nonce `n`. Its binding hashes the stamp
   key, the wallet member, the session and the member's passport tag.
2. The device computes `C = h_0·r + h_secret·s + Σ h_{4+i}·d_i` and the tag
   `T = s·G_tag`, which is the passport's issuer tag. It then proves knowledge
   of `(r, s, d_0 … d_15)` with `C` over exactly the bases
   `[h_0, h_secret, h_4 … h_19]`. A discrete-log proof of `T` reuses the
   blinding of `s`. Both proofs share one challenge over the issuer key, `n`,
   every base, `C`, `T` and both Schnorr commitments.
3. The device confirms with one WebAuthn user verification whose challenge
   is `BLAKE2s-256(L("cpsd/stamp/v1/user-verification") ‖ L(n) ‖ L(request))`.
   The wallet verifies this assertion and records its challenge with
   `AuthenticatedStampIssuance::with_user_verification`. cpsd does not see
   WebAuthn.
4. `issue_stamp_once` checks, in order, that the nonce is live for exactly
   this key, member, session and tag, that `T` equals the authenticated
   member's passport tag, and that the recorded challenge equals the
   request's confirmation challenge for `n` (`UnconfirmedStampRequest`
   otherwise). It then checks the proof: shared response equality, then the
   tag proof, then the opening. It signs the key ID, the epoch and
   `X = expiry_for(now) = (⌊now / P⌋ + 2)·P` blindly over `C`: the end of the
   cohort after the one containing `now`. With the default, a stamp expires
   at the end of the UTC day after issuance. Last, it consumes the nonce and
   updates the separate stamp tag registry (member to tag, tag to one member)
   in one transaction. A refusal consumes nothing.
5. The holder unblinds the signature. It checks that `X` lies on the `P`-grid
   and inside its own issuance window: `expiry_for(t₀ − δ) ≤ X ≤
   expiry_for(t₁ + δ)` and `t₁ < X`, where `t₀` is the request time, `t₁` the
   answer time and `δ = 300 s` the clock tolerance. It also checks the full
   signature over all twenty messages under its own secret.

### 2.6 Presentation and verification

`OpaqueHolder::present_stamp(scope, action, now)` takes the newest unexpired
retained stamp that carries the action, recomputes the digest with the member's own
pseudonym in `scope`, finds its slot `i` and proves the following, with
`StampRequest::with_challenge` making the action digest the challenge:

- a BBS+ proof of knowledge revealing exactly key ID, epoch, `X` and slot
  `i`, with the revealed value `hash_to_field(digest)`;
- a discrete-log proof of `P = s·H(community)`. The pseudonym proof uses the
  same blinding for `s` as the BBS+ proof, and the verifier checks that both
  responses for `s` are equal.

One Merlin transcript covers the stamp key, community ID, epoch, `X`, `i`,
the digest, the BBS+ challenge contribution (every generator and every
revealed value with its index) and the pseudonym statement. `verify_stamp` is
pure. It selects the unique key ID in the ring and requires the expected
epoch. It requires the key's cohort to be the configured `P` (the verifier's
own rulebook value), `X ≡ 0 (mod P)` and `now < X ≤ now + 2P + δ`. It refuses
an `X` off the grid or beyond `now + 2P + δ` as `WrongExpiryCohort` and an `X`
at or before `now` as `StampExpired`. It then
recomputes the digest from the verifier's own fingerprint, the action and the
presented pseudonym, and verifies both proofs. It returns the proven
pseudonym, never a caller-supplied one.

### 2.7 One use

`StampLedger` stores `(nonce = digest, binding = H(community ‖ kind),
expires = X + 1 h)` with `ChallengeStore::reserve`, which inserts only if the
key is absent. A digest already present is refused as a replay. The stamp is
invalid from `X` on; every live check compares with `X`. The margin
(`STAMP_PRUNE_MARGIN_SECONDS`) is part of the stored deadline, so any `prune`
of the shared community store, `StampLedger::prune` and `Verifier::prune`
alike, deletes a record only when `now > X + 1 h`: a node that shares the
ledger with a clock up to one hour behind, or whose clock stepped back, still
finds the record while it could accept the stamp. `release`
(compare-and-delete) exists only for an action that was not applied and
removes nothing once `X` has passed.

## 3. Threat model

| Party | Trusted for | Not trusted for |
|---|---|---|
| Wallet (stamp issuer) | user verification, rate limit, honest tag lookup, key custody | privacy: it must learn no action, community or pseudonym |
| Device wallet code (`OpaqueHolder`) | holding the secret, which never leaves it | nothing beyond its own member |
| Community verifier, peers | their own ledger | linking the member to other communities; forging other members' approvals |
| Network | nothing | anything |

Colluding wallet and communities are considered for linkability.

## 4. Properties and arguments

### 4.1 Hiding at issuance

The wallet sees `C`, `T`, the Schnorr commitments and responses, and its own
signature. `C` is a Pedersen commitment with uniform `r` over `h_0`, so it is
perfectly hiding for `s` and all slots. The Schnorr proofs are honest-verifier
zero knowledge, so in the random-oracle model their transcripts can be
simulated from `(C, T)` alone. The wallet therefore learns `T` (intended:
holder binding) and nothing about any digest, the number of real digests
(fillers are uniform scalars, like hashed digests), their order or any
community. It knows `A` and `e` of the final signature, but presentations
never reveal them (section 4.4). The salt keeps digests unguessable even for
someone who knows the action.

### 4.2 Unforgeability per slot

Suppose an adversary produces an accepted presentation for `(K, E, X, i, v)`.
Knowledge soundness of the CDL16 proof (rewinding in the random-oracle model)
extracts a valid BBS+ signature under `K` on twenty messages with `m_1 = id(K)`,
`m_2 = E`, `m_3 = X` and `m_{4+i} = v`. Blind issuance needs one more step:
in every issuance session, rewinding the Fiat-Shamir Schnorr proof of the
request extracts the opening `(r, s, d_0 … d_15)` of `C`, so the reduction
knows each message vector it had signed, and BBS+ unforgeability under q-SDH
applies to the extracted vectors. Hence the presented vector was signed in
some issuance session, and in that session the issuer accepted a proof whose
extracted opening expresses `C` over exactly
`{h_0, h_secret, h_4 … h_19}`. A commitment with a component on `h_1`, `h_2`
or `h_3` would give a non-trivial DL relation among independently hashed
generators. The signed key ID, epoch and expiry are therefore exactly the
issuer's choice, and `v` is a value the requester committed at position
`4+i`. As a result:

- slot `j`'s value cannot be shown as slot `i`. Positions are bound to
  distinct generators, and the revealed index enters both the verification
  equation and the transcript;
- a digest never committed in some session cannot be shown at all (up to
  `hash_to_field` collisions);
- the action is fixed. The verifier recomputes the digest from the action, so
  showing a different action needs a BLAKE2s second preimage;
- the presentation's pseudonym is `s·H(community)` for the signed `s`
  (shared response). A stamp issued to `s` can only approve actions as `s`'s
  pseudonym. This holds even against a compromised stamp issuer key: forging
  a signature does not give the DL of a victim's pseudonym.

Tests: `a_presentation_for_one_slot_cannot_reveal_or_forge_another` (honest
proofs moved between slots, re-labelled indices, and the honest prover fed a
wrong claim: another slot's or a foreign digest),
`tampered_challenge_scope_epoch_key_or_proof_fails`, and
`issuance_proof_binds_opening_tag_secret_key_and_nonce`. These tests show that
the implementation fails closed on wrong claims and tampered proofs. They are
not soundness tests against a cheating prover; soundness rests on the proofs
of knowledge in Dock's implementations and the argument above.

### 4.3 Holder binding

Special soundness of the joint issuance proof with one shared response gives
the same `s` in `C` and in `T = s·G_tag`. The wallet requires `T` to be the
passport tag of the member who just passed user verification. That tag was
bound to the passport secret by the passport's own issuance proof and is
registered for one person only. So a stamp's secret is that member's passport
secret, and its presentations carry that member's existing pseudonyms
(`community_base` is unchanged). The separate stamp tag registry keeps the
member-to-tag pairing immutable and unique without touching the passport
registry, whose conflict errors would otherwise fire on stamp traffic. A
wrong secret is refused by the tag comparison (`IssuerTagMismatch`). A
commitment to another secret under the member's tag is refused by the proof.
The issuer additionally requires the verified user verification to cover the
exact request and nonce, so one confirmation approves exactly this request.
Tests: `wallet_issuance_binds_member_tag_confirmation_and_single_use_nonce`,
`stamp_tag_registry_is_separate_and_immutable`,
`stamp_and_passport_prove_the_same_pseudonym`, and the libSQL contract in
`tests/stamp_storage.rs`.

### 4.4 Unlinkability

Two presentations of one stamp in communities A and B reveal the following.

| Item | A | B | Linkable? |
|---|---|---|---|
| key ID, epoch, `X` | same | same | shared by every stamp of that key and epoch issued in the same cohort, one `P`-long window aligned to UTC (one UTC day by default) |
| pseudonym | `s·H(A)` | `s·H(B)` | no, under DDH in G1 (XDH), as for passports |
| slot index | `i` | `j ≠ i` | a small likelihood ratio, growing with the number of colluders (section 5) |
| BBS+ proof (`A'`, `Ā`, `d`, commitments, responses) | fresh | fresh | no: CDL16's proof is zero knowledge; `A' = A·r1` is uniform |
| pseudonym proof | fresh | fresh | no |
| digest | recomputed by A | recomputed by B | different fingerprint and pseudonym |

Against the wallet, the proofs reveal nothing: it knows `A`, `e` and `T`, but
the randomised proof hides `A` and `e`, and linking `T` to a pseudonym is DDH.
The revealed `X` is a different matter. The wallet knows the member and the
issuance time of every stamp, because it performs the user verification and
the rate limit. A community that shares `(pseudonym, X)` with the wallet
therefore narrows the pseudonym to the members who obtained a stamp in that
issuance cohort. So the anonymity set of a presentation, also under wallet
and community collusion, is the set of stamps issued in one `P`-long window.
This is why `P` is coarse: one UTC day by default, never below one hour. The
timing of presentations is a second, independent channel; devices fan out
with independent random delays (design rule 3).

Residual risk: with very few users, the cohort may hold only one or a few
stamps. An operator who runs both the wallet and a community can then still
correlate a pseudonym with a wallet member by issuance timing, and through
the wallet link that member's communities. The risk shrinks as the number of
stamps per cohort grows; it is accepted for the alpha.

Within one community, a member's actions share the pseudonym by design (the
member ID). The test `presentations_of_one_stamp_share_only_key_epoch_and_cohort_across_communities`
checks over seeded runs that no proof element repeats across communities, as a
smoke test of a necessary condition. It also checks that a second holder's
presentation has the same observable shape.
`slot_positions_are_uniform_and_fillers_fresh` checks the slot shuffle with a
chi-square test and that fillers never repeat.

### 4.5 Replay

A presentation is non-interactive and bound by its transcript to key,
community, epoch, `X`, slot and digest. The digest in turn binds fingerprint,
pseudonym, kind, payload and salt. It cannot be replayed in another community
(base and fingerprint differ) or for another action (digest differs). Within
the community the ledger's insert-if-absent refuses the second use until the
record is pruned (`X` plus the prune margin), and verification refuses
everything from `X` on. Concurrent submissions
through independent connection pools yield exactly one success
(`concurrent_records_of_one_digest_yield_exactly_one_success`). Issuance
nonces are single use and bound to key, member, session and tag. The nonce
and the tag registry change together or not at all.

## 5. Limits and residual risks

- **No revocation.** cpsd has no per-credential revocation. A stamp lives
  from one to two cohorts after issuance (at most two days by default), and
  verifiers accept at most `2·P + δ` ahead. Bumping the stamp epoch withdraws
  every outstanding stamp. A thief with a stamp and the device's holder can
  perform only the pre-committed actions not yet recorded. A stamp blob alone
  is useless: it carries no secret.
- **Expiry as a correlator.** All stamps issued in one cohort carry the same
  `X`; the anonymity set and its residual risk are in section 4.4. A
  dishonest wallet could still pick among grid values to tag a holder. The
  holder accepts only the grid values the issuer rule gives inside its
  issuance window widened by `δ` that are still later than the answer time
  (`StampPublicKey::check_signed_expiry`): one value, or two when the request
  or answer lies within `δ` of a cohort boundary or the answer arrives in a
  later cohort, or three when the answer lies within `δ` before the end of a
  cohort and the request is about a cohort older or more. So the wallet gains
  at most about log2(3) ≈ 1.6 bits for those stamps. Values off the grid
  or outside the window are refused at unblinding, and values outside
  `now < X ≤ now + 2P + δ` by every verifier. Fan-out should finish inside one
  cohort (design rule).
- **Revealed slot index.** For one stamp, all communities see pairwise
  different indices. For unrelated stamps, indices are independent and
  uniform. For `k` colluding communities, a `k`-tuple of pairwise distinct
  indices therefore has a "same stamp" likelihood ratio of
  `16^k·(16−k)!/16!`: about 1.07 at `k = 2`, 1.5 at `k = 4`, 8.3 at `k = 8`
  and 8.8·10^5 at `k = 16`. In practice it filters candidates within one `X`
  cohort, so it compounds the cohort risk when the cohort is small. Hiding the
  index would need an OR proof over sixteen slots, which is not implemented.
- **Key-ID tagging.** A wallet could publish one key per member. Verifiers
  accept only keys in the authenticated ring, so this is visible there.
- **Epoch tagging.** Every presentation reveals the signed epoch, and the
  wallet chooses what it signs. `OpaqueHolder::finish_stamp` therefore takes
  the expected epoch from the caller and refuses any other signed epoch with
  `Error::WrongEpoch`, before it unblinds. The caller passes the epoch of the
  authenticated global publication (the signed global status, identical for
  every member and the value verifiers pass to `verify_stamp`), never a value
  from the wallet's reply. A wallet that signs another epoch gets no stamp
  installed. The residual matches key-ID tagging: a wallet that also signs and
  serves one member a per-member status is caught only by parties that compare
  it with the real publication. The expected epoch is only as trustworthy as
  the signed global status: an operator that holds both the wallet and the
  status signing key could still sign a per-member status, which the holder
  alone cannot detect; only a comparison with the communities' views could.
- **Replicas.** Two replicas that each accept a digest before they sync could
  both apply it. The design makes the same digest the same action, so action
  handlers must be idempotent per digest.
- **`release` misuse.** Releasing the record of an applied action re-enables
  a replay until `X`.
- **Clock skew and pruning.** Records outlive their stamps by one hour,
  whatever prunes the shared store (the margin is in the stored deadline,
  section 2.7). Nodes that share a ledger must keep their clocks within that
  margin of each other; a larger skew could re-accept a pruned digest.
- **Capacity.** One-use records share the community's `ChallengeStore`
  capacity with login challenges and live up to `2·P + 1 h`. Size the
  capacity for both (README); a full store refuses new login challenges with
  `StorageCapacity` until records expire.
- **Wallet duties outside cpsd.** Verifying the WebAuthn assertion (cpsd
  then refuses issuance unless its challenge covers the exact request and
  nonce), rate limiting per member and period, honest tag lookup, and timing
  separation between issuance and presentations (random fan-out delays) are
  wallet and device duties.
- **Assumptions.** q-SDH, DL, DDH in G1, the random-oracle model for every
  Fiat-Shamir transcript and hash-to-curve, BLAKE2 security, and the
  correctness of Dock's implementations (unaudited, version-pinned through
  `Cargo.lock`). Dock is not IETF BBS. The scheme here is BBS+ with `(A, e, s)`.
- **Side channels.** Proof generation runs in the device's wallet code. Dock's
  try-and-increment runs on public inputs only. Constant-time behaviour of the
  arkworks arithmetic was not reviewed.

## 6. Evidence

| Evidence | Where |
|---|---|
| Unit tests: wrong claims and tampered proofs (in-crate building blocks), cohort and window rules, no secret in blobs, slot uniformity, pseudonym equality with the passport | `src/stamp/tests.rs` |
| Custody: sealed stamp state, restart, foreign state | `src/opaque_holder/sealing/tests.rs` |
| Public custody path end to end (opaque holder, wallet, ledger) | `tests/stamp_holder.rs` |
| libSQL registry, shared-database separation, fail-closed schema, ledger across pools and reopen, concurrent replay | `tests/stamp_storage.rs` |
| Deterministic known-answer vectors (native and browser) | `tests/it/stamp_vectors.rs` |
| Passport vectors unchanged | `tests/proof_vectors.rs` (same receipts before and after) |
| Decoder fuzzing | `fuzz/fuzz_targets/decode_encode.rs` |
| Coverage | the repository gate (`docs/COVERAGE.md`), not lowered |

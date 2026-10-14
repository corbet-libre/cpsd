# Confirmation stamp: internal security argument

Status: internal written argument, 2026-10-14, for stamp format v1 (envelope
version 4, kinds 20 to 26). It replaces an external review, which is not
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
cohort length `P` (60 s to 1 day), the rulebook's stamp lifetime.

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

### 2.4 Issuance

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
   The wallet checks this assertion. cpsd does not see WebAuthn.
4. `issue_stamp_once` checks, in order, that the nonce is live for exactly
   this key, member, session and tag, and that `T` equals the authenticated
   member's passport tag. It then checks the proof: shared response equality,
   then the tag proof, then the opening. It signs the key ID, the epoch and
   `X = expiry_for(now)` blindly over `C`. Last, it consumes the nonce and
   updates the separate stamp tag registry (member to tag, tag to one member)
   in one transaction. A refusal consumes nothing.
5. The device unblinds the signature and checks that `X` lies on the
   `P`-grid. It also checks the full signature over all twenty messages.

### 2.5 Presentation and verification

`Stamp::present(scope, action)` recomputes the digest with the member's own
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
epoch. It requires `X ≡ 0 (mod P)` and `now < X ≤ now + 2P`. It then
recomputes the digest from the verifier's own fingerprint, the action and the
presented pseudonym, and verifies both proofs. It returns the proven
pseudonym, never a caller-supplied one.

### 2.6 One use

`StampLedger` stores `(nonce = digest, binding = H(community ‖ kind),
expires = X)` with `ChallengeStore::reserve`, which inserts only if the key
is absent. A digest already present is refused as a replay. A record lives
until `X`, and the stamp is invalid from `X` on, so pruning after `X` never
reopens a replay. `release` (compare-and-delete) exists only for an action
that was not applied.

## 3. Threat model

| Party | Trusted for | Not trusted for |
|---|---|---|
| Wallet (stamp issuer) | user verification, rate limit, honest tag lookup, key custody | privacy: it must learn no action, community or pseudonym |
| Device wallet code | holding the secret | nothing beyond its own member |
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
`m_2 = E`, `m_3 = X` and `m_{4+i} = v`. By BBS+ unforgeability under q-SDH,
this message vector was signed in some issuance session. In every session the
issuer accepted a proof whose extracted opening expresses `C` over exactly
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
proofs moved between slots, re-labelled indices, cheating provers that claim
another slot's or a foreign digest), `tampered_challenge_scope_epoch_key_or_proof_fails`,
and `issuance_proof_binds_opening_tag_secret_key_and_nonce`.

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
Tests: `wallet_issuance_binds_member_tag_and_single_use_nonce`,
`stamp_tag_registry_is_separate_and_immutable`, and the libSQL contract in
`tests/stamp_storage.rs`.

### 4.4 Unlinkability

Two presentations of one stamp in communities A and B reveal the following.

| Item | A | B | Linkable? |
|---|---|---|---|
| key ID, epoch, `X` | same | same | shared by every stamp of that key, epoch and half-cohort issuance window |
| pseudonym | `s·H(A)` | `s·H(B)` | no, under DDH in G1 (XDH), as for passports |
| slot index | `i` | `j ≠ i` | a 16/15 likelihood ratio per pair (see limits) |
| BBS+ proof (`A'`, `Ā`, `d`, commitments, responses) | fresh | fresh | no: CDL16's proof is zero knowledge; `A' = A·r1` is uniform |
| pseudonym proof | fresh | fresh | no |
| digest | recomputed by A | recomputed by B | different fingerprint and pseudonym |

The same holds against the wallet. It knows `A`, `e` and `T`, but the
randomised proof hides `A` and `e`, and linking `T` to a pseudonym is DDH.
Within one community, a member's actions share the pseudonym by design (the
member ID). The test `presentations_of_one_stamp_share_only_key_epoch_and_cohort_across_communities`
checks over seeded runs that no proof element repeats across communities. It
also checks that a second holder's presentation has the same observable shape.

### 4.5 Replay

A presentation is non-interactive and bound by its transcript to key,
community, epoch, `X`, slot and digest. The digest in turn binds fingerprint,
pseudonym, kind, payload and salt. It cannot be replayed in another community
(base and fingerprint differ) or for another action (digest differs). Within
the community the ledger's insert-if-absent refuses the second use until `X`,
and verification refuses everything from `X` on. Concurrent submissions
through independent connection pools yield exactly one success
(`concurrent_records_of_one_digest_yield_exactly_one_success`). Issuance
nonces are single use and bound to key, member, session and tag. The nonce
and the tag registry change together or not at all.

## 5. Limits and residual risks

- **No revocation.** cpsd has no per-credential revocation. A stamp lives at
  most until the end of the next cohort: at most `1.5·P` after issuance under
  the issuer rule, and verifiers accept at most `2·P` ahead. Bumping the stamp
  epoch withdraws every outstanding stamp. A thief with a stamp and the
  device secret can perform only the pre-committed actions not yet recorded.
- **Expiry as a correlator.** At any moment the wallet has two legal expiry
  values (this cohort or the next). A dishonest wallet could encode one bit
  per stamp. Values off the grid are refused by the holder at unblinding, and
  values outside the window by every verifier. Fan-out should finish inside
  one cohort (design rule).
- **Revealed slot index.** For one stamp, two communities always see
  different indices. For unrelated stamps the indices coincide with
  probability 1/16. Colluding communities therefore gain a likelihood ratio of
  16/15 per pair for "same stamp". Hiding the index would need an OR proof
  over sixteen slots, which is not implemented.
- **Key-ID tagging.** A wallet could publish one key per member. Verifiers
  accept only keys in the authenticated ring, so this is visible there.
- **Replicas.** Two replicas that each accept a digest before they sync could
  both apply it. The design makes the same digest the same action, so action
  handlers must be idempotent per digest.
- **`release` misuse.** Releasing the record of an applied action re-enables
  a replay until `X`.
- **Wallet duties outside cpsd.** Verifying the WebAuthn assertion over
  `confirmation_challenge`, rate limiting per member and period, honest tag
  lookup, and timing separation between issuance and presentations (random
  fan-out delays) are wallet and device duties.
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
| Unit tests with hostile provers (in-crate building blocks) | `src/stamp/tests.rs` |
| libSQL registry, shared-database separation, fail-closed schema, ledger across pools and reopen, concurrent replay | `tests/stamp_storage.rs` |
| Deterministic known-answer vectors (native and browser) | `tests/stamp_vectors.rs` |
| Passport vectors unchanged | `tests/proof_vectors.rs` (same receipts before and after) |
| Decoder fuzzing | `fuzz/fuzz_targets/decode_encode.rs` |
| Coverage | the repository gate (`docs/COVERAGE.md`), not lowered |

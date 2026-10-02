# Dock statement composition, version 3

This is an explicit protocol migration requiring independent review and actual
native/browser qualification. It is not byte-compatible with proof_system 0.34.
No v2 exchange proof is accepted as v3 by changing or inferring a version.

The v1 BBS+ signed message layout, generators, holder derivation, issuer tag and
community pseudonym remain unchanged. Existing keys, signatures, pending issuance,
passports and immutable sealed holders retain their original v2 encodings.
Only issuance requests (kind 3), authenticated presentation requests (kind 8) and
presentations (kind 9) require envelope v3. Old registered requests cannot be
downgraded: the service binds the exact canonical request and the holder accepts
only the expected community's signed v3 request.

## Maintained APIs and relations

- `bbs_plus::proof::PoKOfSignatureG1Protocol` supplies signature possession,
  selective disclosure and concrete message blindings. Its upstream equality
  examples compare `get_resp_for_message` under a shared challenge and blinding.
- `schnorr_pok::discrete_log` supplies the one-base and two-base protocols,
  all response arithmetic and verification equations.
- `bulletproofs_plus_plus::ProofArbitraryRange` supplies each original
  `now <= message < 2^40` predicate. Its public commitment conversion supplies
  both commitments to the original value. Two upstream Pedersen proofs bind
  those openings to the exact BBS+ message by equal responses, following Dock's
  `BoundCheckBpp` relation. The upper commitment's opening uses negated randomness
  as specified by that upstream conversion. Setup remains base 2, 64 bits.
- `dock_crypto_utils::transcript::MerlinTranscript` supplies Fiat–Shamir. No
  local hash-to-challenge or response/verification equation is implemented.

SyRA was reviewed and remains unnecessary for the existing random high-entropy
holder secret. Its low-entropy attribute issuance would change the original
identity and issuance contract. No second engine or fallback is selected.

## Exact transcript order

Issuance uses Merlin label `cpsd/v3/issuance`: append `issuer` (canonical original
public key), `nonce` (32 bytes), `opening` (upstream contribution using exactly
`h_0,h_secret,commitment,t`), then `tag` (upstream contribution using exactly
`tag_base,tag,t`). Obtain scalar `challenge`. Both protocols share the holder
message blinding. Verify both proofs and require opening response 2 = tag response.

Presentation uses label `cpsd/v3/presentation`: append `issuer`, `request` (whole
canonical v3 request including nonce/profile/time/community/gates), `signature`
(upstream contribution), then `pseudonym` (upstream contribution). Independent
expiry appends, in signed-message order, `range-index` (u64 big endian),
`range-proof` (complete compressed arbitrary-range proof), `range-lower` and
`range-upper` (upstream Pedersen contributions). Obtain scalar `challenge`.
Verify the signature, pseudonym and range openings under this common challenge;
require the pseudonym response to equal BBS+ message 0, and each lower/upper
value response to equal its exact signed expiry message response.

Each range proof is generated before the outer challenge. Its independent
Merlin label is `cpsd/v3/range`, with `issuer`, whole `request`, and
`message-index` (u64 big endian) appended before the upstream range protocol.
The outer transcript binds that complete proof. All range witnesses remain
hidden. The shared-epoch profile has zero range proofs and requires exact
selective disclosure of the authenticated common expiry.

## Wire and verification

An issuance proof is one length-prefixed compressed pair: full two-base opening
proof then full one-base tag proof, exactly 192 bytes. A presentation contains
length-prefixed full BBS+ proof, length-prefixed one-base pseudonym proof (80 bytes),
u16 range count, then one length-prefixed range record per expiry. Each range
record contains upstream arbitrary-range proof followed by two full two-base
opening proofs. There is no generic statement enum or optional aggregation.

Before upstream allocation, the decoder enforces full BBS+ responses only,
bounded response count, at most 65 ranges, two transformed commitments per range,
base 2, seven norm folds, and one scalar in each final norm vector. Every field
is validated and must round-trip to exactly the received bytes. Trailing bytes,
other versions, other shapes and aggregate inputs above 256 KiB fail closed.
The verifier also checks shapes on in-memory values and enforces the request's
exact number/order of ranges. Full responses replace the old omitted-response
encoding: a structurally valid but unequal response now fails verification.

`tests/proof_vectors.rs` executes deterministic issuance and both presentation
profiles on native and browser and emits hashes for exact cross-target comparison
in full acceptance. Existing identity vectors, issuance, renewal, context,
nonce/replay, malformed-wire, storage and hostile-holder tests remain mandatory.
No acceptance or compatibility claim follows from source inspection alone.

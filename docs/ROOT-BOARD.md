# Same-holder root-board credential

An admin of any community joins the platform's internal root board without
linking the two memberships. The credential is not a transferable token: it is a
second BBS+ credential over the SAME hidden holder secret as the global passport.

## Objects

| Object | Role |
|---|---|
| `RootBoardPublicKey` | Common root issuer key, root scope, policy epoch and fixed 30-day cohort (Unix-aligned, exclusive expiry). Obtained from authenticated Beacon; never per holder, never per source community. Must differ from every trusted global key. |
| `RootBoardIssuanceContext` | Verifier-owned: the source request, the common descriptor and a one-use nonce. Signed by the ROOT community ring as a csgn Credential (expiry = deadline + 1). The device separately authenticates the original source-signed request against its initiating SOURCE origin mapping and requires exact equality before proving. |
| `RootBoardIssuanceRequest` | Joint proof from the holder: global passport possession, source pseudonym, and that the blinded commitment hides the same secret. The issuer sees only the source pseudonym and the commitment, never the root pseudonym. |
| `VerifiedRootBoardIssuance` | Unforgeable result of `verify_root_board_issuance`. It is NOT a role verdict: the service must hold the current source admin lease and consume the nonce atomically before `issue_blind_root_board`. |
| `BlindRootBoardCredential` | The blind signature over the common cohort attributes only. No caller-chosen expiry or attribute. |
| `RootBoardRequest` / `RootBoardPresentation` | Joint proof of the passport and the root credential with shared blinding and challenge, plus the root pseudonym. The request is signed by the root ring (expiry = deadline + 1). No source community, source pseudonym, role or issuance tag appears. |

## Holder custody

`OpaqueHolder` keeps the pending root opening and the verified root credential
internally, beside the global passport. `begin_root_board_issuance`,
`finish_root_board_issuance`, `cancel_root_board_issuance`, `has_root_board` and
`present_root_board` are the only entry points; no secret, opening, passport or
credential is exposed. A refused source/root authorization never installs or
consumes a pending opening and keeps the previous credential. Once an authorized
attempt exists, a failed renewal answer consumes only that attempt and keeps the
previous credential. The source and root trust anchors are supplied independently;
a root signature alone cannot authorize a source pseudonym scope.

Sealing keeps the original kind 10 plaintext byte-identical when no root-board
state exists. Any root-board state selects the explicit kind 12 under the same
immutable key and context. Restore accepts each declared kind explicitly, checks
every pending and installed secret and signature, and never guesses a format.
Older readers reject kind 12.

## Transcripts

Issuance: Merlin label `cpsd/v3/root-board-issuance`, appending the global
issuer and the exact context bytes, then the passport presentation contribution
(original order) and the root opening contribution. The opening's second response
must equal the passport proof's secret response.

Presentation: label `cpsd/v3/root-board-presentation`, appending the global
issuer and the exact request bytes, then `credential=global` with the passport
contribution and `credential=root-board` with the root contribution. Both
secret responses must be equal and each proof verifies against the shared
challenge. No local response or verification equation exists.

## Not established here

The role itself (current source admin lease), nonce consumption, Beacon
authentication of the common descriptor, 30-day renewal scheduling and the
issuer-side admission policy belong to the original services. Actual native and
browser vectors, timing and an independent cryptographic review remain required.

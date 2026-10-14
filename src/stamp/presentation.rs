//! Stamp presentation (one slot, one community) and its offline verification.

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{Fr, G1Affine};
use ark_std::{
    UniformRand,
    rand::{CryptoRng, RngCore},
};
use bbs_plus::proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol};
use dock_crypto_utils::{
    signature::MessageOrBlinding,
    transcript::{MerlinTranscript, Transcript},
};
use schnorr_pok::discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol};

use super::{ActionKind, STAMP_SLOTS, Stamp, StampAction, StampDigest, StampPublicKey, StampScope};
use crate::{
    CommunityId, Error, KeyId, Pseudonym, Timestamp,
    error::{ensure, redact},
    issuer::point_bytes,
    params::{
        self, Curve, IDX_KEY_ID, IDX_SECRET, Label, STAMP_IDX_EPOCH, STAMP_IDX_EXPIRY,
        STAMP_IDX_FIRST_SLOT,
    },
    wire::{Kind, Reader, Writer},
};

/// Responses of a stamp's BBS+ proof: the hidden messages (secret and the
/// fifteen unrevealed slots) plus Dock's two randomisation witnesses.
const SIGNATURE_RESPONSES: usize = 1 + (STAMP_SLOTS - 1) + 2;
/// Exact compressed size of the pseudonym's discrete-log proof.
const PSEUDONYM_PROOF_LEN: usize = 48 + 32;

/// The statement one presentation proves. The action digest IS the challenge
/// (there is no live verifier nonce), so a peer that sees the action can check
/// the proof offline; one use per digest is enforced by [`super::StampLedger`].
pub(crate) struct StampRequest {
    community: CommunityId,
    epoch: u64,
    expires: Timestamp,
    slot: usize,
    digest: StampDigest,
}

impl StampRequest {
    /// Binds a presentation to the community, the stamp's epoch and expiry,
    /// the revealed slot index and the action digest as challenge.
    pub(crate) fn with_challenge(
        community: &CommunityId,
        epoch: u64,
        expires: Timestamp,
        slot: usize,
        digest: StampDigest,
    ) -> Self {
        Self {
            community: community.clone(),
            epoch,
            expires,
            slot,
            digest,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut label = Label::new(b"cpsd/stamp/v1/request");
        label
            .bytes(self.community.as_bytes())
            .u64(self.epoch)
            .u64(self.expires)
            .u64(self.slot as u64)
            .bytes(&self.digest.to_bytes());
        label.finish()
    }

    /// Exactly the revealed messages: key ID, epoch, expiry and one slot.
    pub(crate) fn revealed(&self, issuer: &StampPublicKey) -> BTreeMap<usize, Fr> {
        BTreeMap::from([
            (IDX_KEY_ID, params::key_id_scalar(issuer.key_id())),
            (STAMP_IDX_EPOCH, Fr::from(self.epoch)),
            (STAMP_IDX_EXPIRY, Fr::from(self.expires)),
            (STAMP_IDX_FIRST_SLOT + self.slot, self.digest.scalar()),
        ])
    }
}

fn transcript(issuer: &StampPublicKey, request: &StampRequest) -> MerlinTranscript {
    let mut transcript = MerlinTranscript::new(b"cpsd/stamp/v1/presentation");
    transcript.append_message(b"issuer", &issuer.to_bytes());
    transcript.append_message(b"request", &request.to_bytes());
    transcript
}

fn pseudonym_statement(
    transcript: &mut MerlinTranscript,
    base: &G1Affine,
    pseudonym: &G1Affine,
    t: &G1Affine,
) {
    transcript.append_message(b"pseudonym-base", &point_bytes(base));
    transcript.append_message(b"pseudonym", &point_bytes(pseudonym));
    transcript.append_message(b"pseudonym-t", &point_bytes(t));
}

/// BBS+ proof of the stamp with one revealed slot, plus the pseudonym's
/// discrete-log proof sharing the secret's response.
#[derive(Clone)]
pub(crate) struct StampProof {
    pub(crate) signature: PoKOfSignatureG1Proof<Curve>,
    pub(crate) pseudonym: PokDiscreteLog<G1Affine>,
}

/// Builds the proof for `request`, taking the revealed values from the
/// request and the signed values from the stamp. If they differ (a slot that
/// does not hold the claimed digest) the result does not verify.
pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    stamp: &Stamp,
    request: &StampRequest,
    pseudonym: &G1Affine,
) -> Result<StampProof, Error> {
    let issuer = stamp.issuer();
    let revealed = request.revealed(issuer);
    let messages = stamp.messages();
    let blinding = Fr::rand(rng);
    let signature = PoKOfSignatureG1Protocol::init(
        rng,
        &stamp.signature,
        issuer.signature_params(),
        messages.iter().enumerate().map(|(index, message)| {
            if revealed.contains_key(&index) {
                MessageOrBlinding::RevealMessage(message)
            } else if index == IDX_SECRET {
                MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
            } else {
                MessageOrBlinding::BlindMessageRandomly(message)
            }
        }),
    )
    .map_err(redact(Error::ProofGeneration))?;
    let base = params::community_base(&request.community);
    let nym = PokDiscreteLogProtocol::init(stamp.secret.0, blinding, &base);
    let mut transcript = transcript(issuer, request);
    let mut bytes = Vec::new();
    signature
        .challenge_contribution(&revealed, issuer.signature_params(), &mut bytes)
        .map_err(redact(Error::ProofGeneration))?;
    transcript.append_message(b"signature", &bytes);
    pseudonym_statement(&mut transcript, &base, pseudonym, &nym.t);
    let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
    Ok(StampProof {
        signature: signature
            .gen_proof(&challenge)
            .map_err(redact(Error::ProofGeneration))?,
        pseudonym: nym.gen_proof(&challenge),
    })
}

impl StampProof {
    fn verify(
        &self,
        issuer: &StampPublicKey,
        request: &StampRequest,
        pseudonym: &G1Affine,
    ) -> Result<(), Error> {
        let revealed = request.revealed(issuer);
        let base = params::community_base(&request.community);
        let mut transcript = transcript(issuer, request);
        let mut bytes = Vec::new();
        self.signature
            .challenge_contribution(&revealed, issuer.signature_params(), &mut bytes)
            .map_err(redact(Error::InvalidProof))?;
        transcript.append_message(b"signature", &bytes);
        pseudonym_statement(&mut transcript, &base, pseudonym, &self.pseudonym.t);
        let challenge = transcript.challenge_scalar::<Fr>(b"challenge");
        let revealed_indices: BTreeSet<usize> = revealed.keys().copied().collect();
        let secret_response = self
            .signature
            .get_resp_for_message(IDX_SECRET, &revealed_indices)
            .map_err(redact(Error::InvalidProof))?;
        if *secret_response != self.pseudonym.response
            || !self.pseudonym.verify(pseudonym, &base, &challenge)
        {
            return Err(Error::InvalidProof);
        }
        self.signature
            .verify(
                &revealed,
                &challenge,
                issuer.bbs_public_key().clone(),
                issuer.signature_params().clone(),
            )
            .map_err(redact(Error::InvalidProof))
    }
}

pub(crate) fn present<R: RngCore + CryptoRng>(
    rng: &mut R,
    stamp: &Stamp,
    scope: &StampScope,
    slot: usize,
    digest: StampDigest,
) -> Result<StampPresentation, Error> {
    let pseudonym = stamp.secret.pseudonym(scope.community());
    let request =
        StampRequest::with_challenge(scope.community(), stamp.epoch, stamp.expires, slot, digest);
    let proof = prove(rng, stamp, &request, &pseudonym.point()?)?;
    Ok(StampPresentation {
        key_id: stamp.key_id().clone(),
        epoch: stamp.epoch,
        expires: stamp.expires,
        slot,
        pseudonym,
        proof,
    })
}

/// A stamp shown in one community for one action: key ID, epoch, expiry
/// cohort, the revealed slot index, the member's pseudonym and the proof.
///
/// The slot's digest is not transmitted: the verifier recomputes it from the
/// action and the proven pseudonym. Two presentations of one stamp in
/// different communities share only the key ID, epoch and expiry.
#[derive(Clone)]
pub struct StampPresentation {
    pub(crate) key_id: KeyId,
    pub(crate) epoch: u64,
    pub(crate) expires: Timestamp,
    pub(crate) slot: usize,
    pub(crate) pseudonym: Pseudonym,
    pub(crate) proof: StampProof,
}

impl StampPresentation {
    /// Key that signed the presented stamp.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The revealed stamp epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The revealed exclusive expiry.
    pub fn expires(&self) -> Timestamp {
        self.expires
    }

    /// The revealed slot index (below [`STAMP_SLOTS`]).
    pub fn slot(&self) -> usize {
        self.slot
    }

    /// The claimed pseudonym; meaningful only after [`verify_stamp`] returned it.
    pub fn pseudonym(&self) -> &Pseudonym {
        &self.pseudonym
    }

    /// Encoding for transport with the action.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::StampPresentation);
        w.key_id(&self.key_id);
        w.u64(self.epoch);
        w.u64(self.expires);
        w.u16(self.slot as u16);
        w.fixed(&self.pseudonym.to_bytes());
        w.ark(&self.proof.signature);
        w.ark(&self.proof.pseudonym);
        w.finish_public()
    }

    /// Decodes a presentation, checking every shape before upstream decoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::StampPresentation)?;
        let key_id = r.key_id()?;
        let epoch = r.u64()?;
        let expires = r.u64()?;
        let slot = r.u16()? as usize;
        ensure(slot < STAMP_SLOTS, Error::Decode("stamp slot"))?;
        let pseudonym = Pseudonym::from_bytes(&r.fixed::<48>()?)?;
        let raw = r.bytes()?;
        crate::proof_wire::signature_shape_with(raw, SIGNATURE_RESPONSES..=SIGNATURE_RESPONSES)?;
        let signature = crate::proof_wire::decode(raw)?;
        let raw = r.bytes()?;
        ensure(
            raw.len() == PSEUDONYM_PROOF_LEN,
            Error::Decode("pseudonym proof shape"),
        )?;
        let nym = crate::proof_wire::decode(raw)?;
        r.finish()?;
        Ok(Self {
            key_id,
            epoch,
            expires,
            slot,
            pseudonym,
            proof: StampProof {
                signature,
                pseudonym: nym,
            },
        })
    }
}

impl core::fmt::Debug for StampPresentation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StampPresentation")
            .field("key_id", &self.key_id)
            .field("epoch", &self.epoch)
            .field("expires", &self.expires)
            .field("slot", &self.slot)
            .field("pseudonym", &self.pseudonym)
            .finish_non_exhaustive()
    }
}

/// A verified stamp presentation: who approved which action in which
/// community, until when. No public constructor, clone or serializer; record
/// it with [`super::StampLedger`] before applying the action.
pub struct VerifiedStamp {
    pub(crate) community: CommunityId,
    pub(crate) pseudonym: Pseudonym,
    pub(crate) digest: StampDigest,
    pub(crate) kind: ActionKind,
    pub(crate) key_id: KeyId,
    pub(crate) epoch: u64,
    pub(crate) expires: Timestamp,
}

impl VerifiedStamp {
    /// The pseudonym scope the presentation was verified for.
    pub fn community(&self) -> &CommunityId {
        &self.community
    }

    /// The proven member pseudonym. Attribute the action to this value only.
    pub fn pseudonym(&self) -> &Pseudonym {
        &self.pseudonym
    }

    /// The action digest (the one-use key).
    pub fn digest(&self) -> &StampDigest {
        &self.digest
    }

    /// The approved action kind.
    pub fn action_kind(&self) -> &ActionKind {
        &self.kind
    }

    /// The stamp key that signed it.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The stamp epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The exclusive expiry; the one-use record lives until then.
    pub fn expires(&self) -> Timestamp {
        self.expires
    }
}

impl core::fmt::Debug for VerifiedStamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedStamp")
            .field("community", &self.community)
            .field("pseudonym", &self.pseudonym)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Verifies a stamp presentation for `action` in `scope`, purely and offline.
///
/// `keys` is the authenticated stamp key ring; `epoch` the current stamp
/// epoch; `now` the verifier's time. The digest is recomputed from the
/// verifier's own fingerprint, the action and the presentation's pseudonym,
/// and the proof shows that exactly this digest is signed into the revealed
/// slot of a stamp whose hidden secret is that pseudonym's secret. The expiry
/// must lie on the key's cohort grid, after `now` and at most two cohorts
/// ahead. Returns the proven pseudonym with the action; this does NOT record
/// the one use (see [`super::StampLedger`]).
pub fn verify_stamp(
    keys: &[StampPublicKey],
    scope: &StampScope,
    epoch: u64,
    action: &StampAction,
    presentation: &StampPresentation,
    now: Timestamp,
) -> Result<VerifiedStamp, Error> {
    let mut matching = keys.iter().filter(|k| *k.key_id() == presentation.key_id);
    let issuer = matching.next().ok_or(Error::UnknownKey)?;
    ensure(matching.next().is_none(), Error::DuplicateKeyId)?;
    ensure(presentation.epoch == epoch, Error::WrongEpoch)?;
    issuer.check_expiry(presentation.expires, now)?;
    let digest = action.digest(scope.fingerprint(), &presentation.pseudonym);
    let request = StampRequest::with_challenge(
        scope.community(),
        epoch,
        presentation.expires,
        presentation.slot,
        digest,
    );
    presentation
        .proof
        .verify(issuer, &request, &presentation.pseudonym.point()?)?;
    Ok(VerifiedStamp {
        community: scope.community().clone(),
        pseudonym: presentation.pseudonym,
        digest,
        kind: action.kind().clone(),
        key_id: issuer.key_id().clone(),
        epoch,
        expires: presentation.expires,
    })
}

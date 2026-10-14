//! Blind stamp issuance: the holder's request, the issuer's blind answer and
//! the holder's unblinded stamp.

use std::collections::BTreeSet;

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_std::{
    UniformRand,
    rand::{CryptoRng, RngCore, seq::SliceRandom},
};
use bbs_plus::{setup::SignatureParamsG1, signature::SignatureG1};
use blake2::{Blake2s256, Digest};
use dock_crypto_utils::transcript::{MerlinTranscript, Transcript};
use schnorr_pok::{
    SchnorrCommitment, SchnorrResponse,
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{STAMP_SLOTS, StampAction, StampDigest, StampPresentation, StampPublicKey, StampScope};
use crate::{
    Error, HolderSecret, IssuanceChallenge, IssuerTag, KeyId, Timestamp,
    error::{ensure, redact},
    issuer::point_bytes,
    params::{self, Curve, IDX_SECRET, Label, STAMP_IDX_FIRST_SLOT},
    wire::{Kind, Reader, Writer},
};

/// Witnesses of the issuance commitment: blinding, holder secret, every slot.
pub(crate) const ISSUANCE_WITNESSES: usize = 2 + STAMP_SLOTS;
/// Position of the holder secret among the witnesses and responses.
pub(crate) const WITNESS_SECRET: usize = 1;
/// Exact compressed size of the opening's response vector: a `u64` length
/// prefix and one scalar per witness, checked before upstream decoding.
const RESPONSES_LEN: usize = 8 + ISSUANCE_WITNESSES * 32;

/// Multi-base Schnorr proof of the commitment's opening plus a discrete-log
/// proof of the issuer tag, sharing the holder secret's response.
#[derive(Clone)]
pub(crate) struct IssuanceProof {
    pub(crate) t: G1Affine,
    pub(crate) responses: SchnorrResponse<G1Affine>,
    pub(crate) tag: PokDiscreteLog<G1Affine>,
}

/// Bases of the issuance commitment, in witness order: `h_0` (blinding), the
/// secret's generator, then every slot generator. The key ID, epoch and expiry
/// generators are absent, so the commitment cannot shift issuer attributes.
pub(crate) fn bases(params: &SignatureParamsG1<Curve>) -> Vec<G1Affine> {
    let mut bases = Vec::with_capacity(ISSUANCE_WITNESSES);
    bases.push(params.h_0);
    bases.push(params.h[IDX_SECRET]);
    bases.extend_from_slice(&params.h[STAMP_IDX_FIRST_SLOT..]);
    bases
}

pub(crate) fn transcript(issuer: &StampPublicKey, nonce: &IssuanceChallenge) -> MerlinTranscript {
    let mut transcript = MerlinTranscript::new(b"cpsd/stamp/v1/issuance");
    transcript.append_message(b"issuer", &issuer.to_bytes());
    transcript.append_message(b"nonce", &nonce.to_bytes());
    transcript
}

/// The complete statement: every base, the commitment and its Schnorr
/// commitment, then the tag base, the tag and its Schnorr commitment.
pub(crate) fn statement(
    transcript: &mut MerlinTranscript,
    bases: &[G1Affine],
    commitment: &G1Affine,
    commitment_t: &G1Affine,
    tag: &G1Affine,
    tag_t: &G1Affine,
) {
    for base in bases {
        transcript.append_message(b"base", &point_bytes(base));
    }
    transcript.append_message(b"commitment", &point_bytes(commitment));
    transcript.append_message(b"commitment-t", &point_bytes(commitment_t));
    transcript.append_message(b"tag-base", &point_bytes(&params::issuer_tag_base()));
    transcript.append_message(b"tag", &point_bytes(tag));
    transcript.append_message(b"tag-t", &point_bytes(tag_t));
}

/// Starts blind stamp issuance for up to [`STAMP_SLOTS`] action digests.
///
/// Commits to `secret` and all sixteen slots for `issuer` and proves, bound to
/// the wallet's `challenge`, knowledge of the opening and that the request's
/// issuer tag (the passport tag, `secret * H("issuer tag")`) hides the same
/// secret. The digests go into random slot positions; the remaining slots are
/// random scalars. Fails with [`Error::InvalidStamp`] for no, too many or
/// repeated digests.
///
/// Send the request to the wallet; keep the [`PendingStamp`] to unblind the
/// answer. Before sending, the device confirms the request with one user
/// verification over [`StampIssuanceRequest::confirmation_challenge`].
pub fn request_stamp<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &HolderSecret,
    issuer: &StampPublicKey,
    challenge: &IssuanceChallenge,
    digests: &[StampDigest],
) -> Result<(StampIssuanceRequest, PendingStamp), Error> {
    let slots = shuffled_slots(rng, digests)?;
    request_for_slots(rng, secret, secret, issuer, challenge, &slots)
}

fn shuffled_slots<R: RngCore + CryptoRng>(
    rng: &mut R,
    digests: &[StampDigest],
) -> Result<Zeroizing<[Fr; STAMP_SLOTS]>, Error> {
    let distinct: BTreeSet<&StampDigest> = digests.iter().collect();
    ensure(
        !digests.is_empty() && digests.len() <= STAMP_SLOTS && distinct.len() == digests.len(),
        Error::InvalidStamp,
    )?;
    let mut slots = Zeroizing::new([Fr::zero(); STAMP_SLOTS]);
    for (slot, digest) in slots.iter_mut().zip(digests) {
        *slot = digest.scalar();
    }
    for slot in &mut slots[digests.len()..] {
        *slot = Fr::rand(rng);
    }
    slots.shuffle(rng);
    Ok(slots)
}

/// The request for exact slot contents. `tag_secret` differs from `secret`
/// ONLY in tests that build a hostile request whose tag hides another secret;
/// production callers go through [`request_stamp`].
pub(crate) fn request_for_slots<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &HolderSecret,
    tag_secret: &HolderSecret,
    issuer: &StampPublicKey,
    challenge: &IssuanceChallenge,
    slots: &[Fr; STAMP_SLOTS],
) -> Result<(StampIssuanceRequest, PendingStamp), Error> {
    let params = issuer.signature_params();
    // Pedersen hiding uses uniform randomness over the entire scalar field.
    let blinding = Fr::rand(rng);
    let hidden = core::iter::once((IDX_SECRET, &secret.0)).chain(
        slots
            .iter()
            .enumerate()
            .map(|(i, slot)| (STAMP_IDX_FIRST_SLOT + i, slot)),
    );
    let commitment = params
        .commit_to_messages(hidden, &blinding)
        .map_err(redact(Error::ProofGeneration))?;
    let issuer_tag = (params::issuer_tag_base() * tag_secret.0).into_affine();
    let bases = bases(params);
    let mut witnesses = Zeroizing::new(Vec::with_capacity(ISSUANCE_WITNESSES));
    witnesses.push(blinding);
    witnesses.push(secret.0);
    witnesses.extend_from_slice(slots);
    let randomness: Vec<Fr> = (0..ISSUANCE_WITNESSES).map(|_| Fr::rand(rng)).collect();
    // Equality follows Dock's shared-blinding pattern: the tag proof reuses the
    // secret's blinding, so honest responses coincide under one challenge.
    let tag = PokDiscreteLogProtocol::init(
        tag_secret.0,
        randomness[WITNESS_SECRET],
        &params::issuer_tag_base(),
    );
    let opening = SchnorrCommitment::new(&bases, randomness);
    let mut transcript = transcript(issuer, challenge);
    statement(
        &mut transcript,
        &bases,
        &commitment,
        &opening.t,
        &issuer_tag,
        &tag.t,
    );
    let challenge_scalar = transcript.challenge_scalar::<Fr>(b"challenge");
    let proof = IssuanceProof {
        t: opening.t,
        responses: opening
            .response(&witnesses, &challenge_scalar)
            .map_err(redact(Error::ProofGeneration))?,
        tag: tag.gen_proof(&challenge_scalar),
    };
    let request = StampIssuanceRequest {
        key_id: issuer.key_id().clone(),
        commitment,
        issuer_tag,
        proof,
    };
    let pending = PendingStamp {
        secret: secret.clone(),
        blinding,
        slots: *slots,
        issuer: issuer.clone(),
    };
    Ok((request, pending))
}

/// A device's request for a blind stamp: a Pedersen commitment to the holder
/// secret and all sixteen slots, the passport issuer tag, and a zero-knowledge
/// proof that the commitment opens over exactly those generators and that the
/// tag hides the committed secret, bound to the wallet's challenge.
#[derive(Clone)]
pub struct StampIssuanceRequest {
    pub(crate) key_id: KeyId,
    pub(crate) commitment: G1Affine,
    pub(crate) issuer_tag: G1Affine,
    pub(crate) proof: IssuanceProof,
}

impl StampIssuanceRequest {
    /// Stamp key the request is addressed to.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The holder's passport issuer tag. The wallet compares it with the tag it
    /// holds for the authenticated member ([`crate::AuthenticatedStampIssuance`]);
    /// it is trustworthy only after the request's proof verified.
    pub fn issuer_tag(&self) -> IssuerTag {
        IssuerTag(point_bytes(&self.issuer_tag))
    }

    /// The WebAuthn challenge of the one user verification that confirms this
    /// request: `BLAKE2s-256` over the wallet's nonce and the exact request
    /// encoding, so the confirmation covers exactly this request.
    pub fn confirmation_challenge(&self, challenge: &IssuanceChallenge) -> [u8; 32] {
        let mut label = Label::new(b"cpsd/stamp/v1/user-verification");
        label.bytes(&challenge.to_bytes()).bytes(&self.to_bytes());
        Blake2s256::digest(label.finish()).into()
    }

    /// Encoding for transport to the wallet.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::StampIssuanceRequest);
        w.key_id(&self.key_id);
        w.ark(&self.commitment);
        w.ark(&self.issuer_tag);
        w.ark(&self.proof.t);
        w.ark(&self.proof.responses);
        w.ark(&self.proof.tag);
        w.finish_public()
    }

    /// Decodes a request received from a device.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::StampIssuanceRequest)?;
        let key_id = r.key_id()?;
        let commitment = r.ark::<G1Affine>("stamp commitment")?;
        let issuer_tag = r.ark::<G1Affine>("issuer tag")?;
        let t = r.ark::<G1Affine>("stamp opening commitment")?;
        let raw = r.bytes()?;
        ensure(
            raw.len() == RESPONSES_LEN,
            Error::Decode("stamp issuance proof shape"),
        )?;
        let responses = crate::proof_wire::decode(raw)?;
        let tag = r.ark::<PokDiscreteLog<G1Affine>>("stamp tag proof")?;
        r.finish()?;
        ensure(
            !commitment.is_zero() && !issuer_tag.is_zero(),
            Error::Decode("identity element"),
        )?;
        Ok(Self {
            key_id,
            commitment,
            issuer_tag,
            proof: IssuanceProof { t, responses, tag },
        })
    }

    /// Checks the opening proof and the secret equality of commitment and tag.
    pub(crate) fn verify(
        &self,
        issuer: &StampPublicKey,
        challenge: &IssuanceChallenge,
    ) -> Result<(), Error> {
        let bases = bases(issuer.signature_params());
        let mut transcript = transcript(issuer, challenge);
        statement(
            &mut transcript,
            &bases,
            &self.commitment,
            &self.proof.t,
            &self.issuer_tag,
            &self.proof.tag.t,
        );
        let challenge_scalar = transcript.challenge_scalar::<Fr>(b"challenge");
        let shared = self
            .proof
            .responses
            .get_response(WITNESS_SECRET)
            .map_err(redact(Error::InvalidIssuanceRequest))?;
        if *shared != self.proof.tag.response
            || !self.proof.tag.verify(
                &self.issuer_tag,
                &params::issuer_tag_base(),
                &challenge_scalar,
            )
            || self
                .proof
                .responses
                .is_valid(&bases, &self.commitment, &self.proof.t, &challenge_scalar)
                .is_err()
        {
            return Err(Error::InvalidIssuanceRequest);
        }
        Ok(())
    }
}

impl core::fmt::Debug for StampIssuanceRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StampIssuanceRequest")
            .field("key_id", &self.key_id)
            .field("issuer_tag", &self.issuer_tag())
            .finish_non_exhaustive()
    }
}

/// A stamp signature as returned by the wallet, still blinded; only the
/// device holding the matching [`PendingStamp`] can unblind it.
#[derive(Clone)]
pub struct BlindStamp {
    pub(crate) key_id: KeyId,
    pub(crate) epoch: u64,
    pub(crate) expires: Timestamp,
    pub(crate) signature: SignatureG1<Curve>,
}

impl BlindStamp {
    /// Signing key.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The signed stamp epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The signed exclusive expiry (end of the cohort).
    pub fn expires(&self) -> Timestamp {
        self.expires
    }

    /// Encoding for transport to the device.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::BlindStamp);
        w.key_id(&self.key_id);
        w.u64(self.epoch);
        w.u64(self.expires);
        w.ark(&self.signature);
        w.finish_public()
    }

    /// Decodes a blind stamp received from the wallet.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::BlindStamp)?;
        let key_id = r.key_id()?;
        let epoch = r.u64()?;
        let expires = r.u64()?;
        let signature = r.ark::<SignatureG1<Curve>>("blind stamp signature")?;
        r.finish()?;
        Ok(Self {
            key_id,
            epoch,
            expires,
            signature,
        })
    }
}

impl core::fmt::Debug for BlindStamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlindStamp")
            .field("key_id", &self.key_id)
            .field("epoch", &self.epoch)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

/// Device state between [`request_stamp`] and the wallet's answer: the secret,
/// the blinding factor and the shuffled slots. Wiped on drop; storable across
/// a restart so a completed user verification is never lost.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PendingStamp {
    secret: HolderSecret,
    blinding: Fr,
    slots: [Fr; STAMP_SLOTS],
    #[zeroize(skip)]
    issuer: StampPublicKey,
}

impl PendingStamp {
    /// Unblinds the wallet's answer and checks the signature over the secret,
    /// the slots and the signed attributes, and that the expiry lies on the
    /// key's public cohort grid. Returns the stamp.
    pub fn finish(self, blind: &BlindStamp) -> Result<Stamp, Error> {
        if blind.key_id != *self.issuer.key_id() {
            return Err(Error::KeyMismatch);
        }
        let signature = blind.signature.clone().unblind(&self.blinding);
        Stamp::assemble(
            self.secret.clone(),
            self.issuer.clone(),
            blind.epoch,
            blind.expires,
            self.slots,
            signature,
        )
    }

    /// Encoding for device storage. Contains the secret; wipes itself on drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::PendingStamp);
        w.ark(&self.secret.0);
        w.ark(&self.blinding);
        for slot in &self.slots {
            w.ark(slot);
        }
        self.issuer.encode_body(&mut w);
        w.finish_secret()
    }

    /// Restores state written by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::PendingStamp)?;
        let secret = HolderSecret(r.ark::<Fr>("holder secret")?);
        let blinding = r.ark::<Fr>("blinding")?;
        let slots = read_slots(&mut r)?;
        let issuer = StampPublicKey::decode_body(&mut r)?;
        r.finish()?;
        ensure(!secret.0.is_zero(), Error::InvalidKey)?;
        Ok(Self {
            secret,
            blinding,
            slots,
            issuer,
        })
    }
}

impl core::fmt::Debug for PendingStamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingStamp")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

fn read_slots(r: &mut Reader<'_>) -> Result<[Fr; STAMP_SLOTS], Error> {
    let mut slots = [Fr::zero(); STAMP_SLOTS];
    for slot in &mut slots {
        *slot = r.ark::<Fr>("stamp slot")?;
    }
    Ok(slots)
}

/// A confirmation stamp: the unblinded BBS+ signature over the holder secret,
/// key ID, epoch, expiry cohort and sixteen slots.
///
/// Held only by the device. Shown only as a one-slot [`StampPresentation`].
/// Wiped on drop; `Debug` shows the public attributes only.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Stamp {
    pub(crate) secret: HolderSecret,
    #[zeroize(skip)]
    pub(crate) issuer: StampPublicKey,
    pub(crate) epoch: u64,
    pub(crate) expires: Timestamp,
    slots: [Fr; STAMP_SLOTS],
    pub(crate) signature: SignatureG1<Curve>,
}

impl Stamp {
    fn assemble(
        secret: HolderSecret,
        issuer: StampPublicKey,
        epoch: u64,
        expires: Timestamp,
        slots: [Fr; STAMP_SLOTS],
        signature: SignatureG1<Curve>,
    ) -> Result<Self, Error> {
        ensure(!secret.0.is_zero(), Error::InvalidKey)?;
        issuer.check_alignment(expires)?;
        let stamp = Self {
            secret,
            issuer,
            epoch,
            expires,
            slots,
            signature,
        };
        stamp
            .signature
            .verify(
                &stamp.messages(),
                stamp.issuer.bbs_public_key().clone(),
                stamp.issuer.signature_params().clone(),
            )
            .map_err(redact(Error::InvalidSignature))?;
        Ok(stamp)
    }

    pub(crate) fn messages(&self) -> Zeroizing<Vec<Fr>> {
        params::stamp_messages(
            &self.secret.0,
            self.issuer.key_id(),
            self.epoch,
            self.expires,
            &self.slots,
        )
    }

    pub(crate) fn slot_of(&self, digest: &StampDigest) -> Option<usize> {
        let scalar = digest.scalar();
        self.slots.iter().position(|slot| *slot == scalar)
    }

    /// The stamp key that signed it.
    pub fn issuer(&self) -> &StampPublicKey {
        &self.issuer
    }

    /// Signing key ID.
    pub fn key_id(&self) -> &KeyId {
        self.issuer.key_id()
    }

    /// The signed stamp epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The signed exclusive expiry (end of the cohort).
    pub fn expires(&self) -> Timestamp {
        self.expires
    }

    /// Whether the stamp carries the digest of `action` in `scope`.
    pub fn covers(&self, scope: &StampScope, action: &StampAction) -> bool {
        let member = self.secret.pseudonym(scope.community());
        self.slot_of(&action.digest(scope.fingerprint(), &member))
            .is_some()
    }

    /// Presents the stamp for one action in one community: reveals the key
    /// ID, epoch, expiry and exactly the slot holding this action's digest
    /// (computed with the member's own pseudonym in `scope`) and proves that
    /// pseudonym. Fails with [`Error::StampDigestMissing`] if the stamp does
    /// not carry the digest. The result verifies offline ([`crate::verify_stamp`]).
    pub fn present<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        scope: &StampScope,
        action: &StampAction,
    ) -> Result<StampPresentation, Error> {
        let member = self.secret.pseudonym(scope.community());
        let digest = action.digest(scope.fingerprint(), &member);
        let slot = self.slot_of(&digest).ok_or(Error::StampDigestMissing)?;
        super::presentation::present(rng, self, scope, slot, digest)
    }

    /// Encoding for device storage. Contains the secret; wipes itself on drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::Stamp);
        w.ark(&self.secret.0);
        self.issuer.encode_body(&mut w);
        w.u64(self.epoch);
        w.u64(self.expires);
        for slot in &self.slots {
            w.ark(slot);
        }
        w.ark(&self.signature);
        w.finish_secret()
    }

    /// Restores a stamp written by [`to_bytes`](Self::to_bytes) and re-checks
    /// its signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::Stamp)?;
        let secret = HolderSecret(r.ark::<Fr>("holder secret")?);
        let issuer = StampPublicKey::decode_body(&mut r)?;
        let epoch = r.u64()?;
        let expires = r.u64()?;
        let slots = read_slots(&mut r)?;
        let signature = r.ark::<SignatureG1<Curve>>("stamp signature")?;
        r.finish()?;
        Self::assemble(secret, issuer, epoch, expires, slots, signature)
    }
}

impl core::fmt::Debug for Stamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stamp")
            .field("key_id", self.issuer.key_id())
            .field("epoch", &self.epoch)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

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
    attributes::check_timestamp,
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
/// repeated digests. `now` starts the issuance window that the holder later
/// checks the signed expiry against.
///
/// Crate-private: devices go through [`crate::OpaqueHolder::begin_stamp`], so
/// no raw secret ever crosses the public API.
pub(crate) fn request_stamp<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &HolderSecret,
    issuer: &StampPublicKey,
    challenge: &IssuanceChallenge,
    digests: &[StampDigest],
    now: Timestamp,
) -> Result<(StampIssuanceRequest, PendingStamp), Error> {
    check_timestamp(now)?;
    let slots = shuffled_slots(rng, digests)?;
    request_for_slots(rng, secret, secret, issuer, challenge, &slots, now)
}

pub(crate) fn shuffled_slots<R: RngCore + CryptoRng>(
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
    now: Timestamp,
) -> Result<(StampIssuanceRequest, PendingStamp), Error> {
    let params = issuer.signature_params();
    // Pedersen hiding uses uniform randomness over the entire scalar field.
    // With the commitment it would reveal `h_secret * s`; wiped on drop.
    let blinding = Zeroizing::new(Fr::rand(rng));
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
    witnesses.push(*blinding);
    witnesses.push(secret.0);
    witnesses.extend_from_slice(slots);
    let randomness: Vec<Fr> = (0..ISSUANCE_WITNESSES).map(|_| Fr::rand(rng)).collect();
    // Equality follows Dock's shared-blinding pattern: the tag proof reuses the
    // secret's blinding, so honest responses coincide under one challenge.
    // With the public response it would yield the secret; wiped on drop (the
    // upstream protocol and commitment objects wipe their own copies).
    let shared = Zeroizing::new(randomness[WITNESS_SECRET]);
    let tag = PokDiscreteLogProtocol::init(tag_secret.0, *shared, &params::issuer_tag_base());
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
        blinding: *blinding,
        slots: *slots,
        issuer: issuer.clone(),
        request: request.to_bytes(),
        begun: now,
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
/// opaque holder that made the matching request can unblind it
/// ([`crate::OpaqueHolder::finish_stamp`]).
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

/// Device state between [`request_stamp`] and the wallet's answer: the
/// blinding factor, the shuffled slots, the stamp key, the exact public request
/// bytes, and the time the request was made.
/// The request bytes are kept so a device interrupted after sending can send the
/// SAME request again (the wallet answers it with the same stamp, without a new
/// confirmation). It never contains the holder secret: the opaque holder
/// supplies it at [`finish`](Self::finish). Wiped on drop; kept only inside
/// [`crate::OpaqueHolder`] and its sealed state.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct PendingStamp {
    blinding: Fr,
    slots: [Fr; STAMP_SLOTS],
    #[zeroize(skip)]
    issuer: StampPublicKey,
    request: Vec<u8>,
    begun: Timestamp,
}

impl PendingStamp {
    /// Unblinds the wallet's answer and checks the signature over `secret`,
    /// the slots and the signed attributes, that the signed epoch is
    /// `expected_epoch`, and that the expiry lies on the key's cohort grid
    /// inside the issuance window from the request to `now`
    /// ([`StampPublicKey::check_signed_expiry`]). Returns the stamp.
    ///
    /// The epoch is revealed by every presentation, so a wallet that signed a
    /// different epoch per member would tag the member for a colluding
    /// community. `expected_epoch` therefore comes from the authenticated
    /// global publication, never from the wallet's answer.
    pub(crate) fn finish(
        self,
        secret: &HolderSecret,
        blind: &BlindStamp,
        expected_epoch: u64,
        now: Timestamp,
    ) -> Result<Stamp, Error> {
        if blind.key_id != *self.issuer.key_id() {
            return Err(Error::KeyMismatch);
        }
        if blind.epoch != expected_epoch {
            return Err(Error::WrongEpoch);
        }
        self.issuer
            .check_signed_expiry(blind.expires, self.begun, now)?;
        let signature = blind.signature.clone().unblind(&self.blinding);
        Stamp::assemble(
            secret,
            self.issuer.clone(),
            blind.epoch,
            blind.expires,
            self.slots,
            signature,
        )
    }

    /// The stamp key the request is addressed to.
    pub(crate) fn issuer(&self) -> &StampPublicKey {
        &self.issuer
    }

    /// The exact request bytes as first sent, when this pending request carries
    /// every one of `digests` in its slots.
    pub(crate) fn request_covering(&self, digests: &[StampDigest]) -> Option<&[u8]> {
        (!digests.is_empty()
            && digests
                .iter()
                .all(|digest| self.slots.contains(&digest.scalar())))
        .then_some(self.request.as_slice())
    }

    /// Encoding for the holder's sealed state, without the holder secret.
    /// Wipes itself on drop.
    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::PendingStamp);
        w.ark(&self.blinding);
        for slot in &self.slots {
            w.ark(slot);
        }
        self.issuer.encode_body(&mut w);
        w.bytes(&self.request);
        w.u64(self.begun);
        w.finish_secret()
    }

    /// Restores state written by [`to_bytes`](Self::to_bytes).
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::PendingStamp)?;
        let blinding = r.ark::<Fr>("blinding")?;
        let slots = read_slots(&mut r)?;
        let issuer = StampPublicKey::decode_body(&mut r)?;
        let request = r.bytes()?.to_vec();
        let begun = r.u64()?;
        r.finish()?;
        check_timestamp(begun)?;
        Ok(Self {
            blinding,
            slots,
            issuer,
            request,
            begun,
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
/// It does NOT contain the holder secret: every operation takes it from the
/// opaque holder that retains this stamp ([`crate::OpaqueHolder::present_stamp`]),
/// and the encoding is useless without it. Shown only as a one-slot
/// [`StampPresentation`]. Wiped on drop; `Debug` shows the public attributes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Stamp {
    #[zeroize(skip)]
    pub(crate) issuer: StampPublicKey,
    pub(crate) epoch: u64,
    pub(crate) expires: Timestamp,
    slots: [Fr; STAMP_SLOTS],
    pub(crate) signature: SignatureG1<Curve>,
}

impl Stamp {
    fn assemble(
        secret: &HolderSecret,
        issuer: StampPublicKey,
        epoch: u64,
        expires: Timestamp,
        slots: [Fr; STAMP_SLOTS],
        signature: SignatureG1<Curve>,
    ) -> Result<Self, Error> {
        ensure(!secret.0.is_zero(), Error::InvalidKey)?;
        issuer.check_alignment(expires)?;
        let stamp = Self {
            issuer,
            epoch,
            expires,
            slots,
            signature,
        };
        stamp
            .signature
            .verify(
                &stamp.messages(secret),
                stamp.issuer.bbs_public_key().clone(),
                stamp.issuer.signature_params().clone(),
            )
            .map_err(redact(Error::InvalidSignature))?;
        Ok(stamp)
    }

    pub(crate) fn messages(&self, secret: &HolderSecret) -> Zeroizing<Vec<Fr>> {
        params::stamp_messages(
            &secret.0,
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
    pub(crate) fn issuer(&self) -> &StampPublicKey {
        &self.issuer
    }

    /// Signing key ID.
    pub(crate) fn key_id(&self) -> &KeyId {
        self.issuer.key_id()
    }

    /// Whether the stamp carries the digest of `action` in `scope` for the
    /// member whose secret is `secret`.
    pub(crate) fn covers(
        &self,
        secret: &HolderSecret,
        scope: &StampScope,
        action: &StampAction,
    ) -> bool {
        let member = secret.pseudonym(scope.community());
        self.slot_of(&action.digest(scope.fingerprint(), &member))
            .is_some()
    }

    /// Presents the stamp for one action in one community: reveals the key
    /// ID, epoch, expiry and exactly the slot holding this action's digest
    /// (computed with the member's own pseudonym in `scope`) and proves that
    /// pseudonym. Fails with [`Error::StampDigestMissing`] if the stamp does
    /// not carry the digest. The result verifies offline ([`crate::verify_stamp`]).
    pub(crate) fn present<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        secret: &HolderSecret,
        scope: &StampScope,
        action: &StampAction,
    ) -> Result<StampPresentation, Error> {
        let member = secret.pseudonym(scope.community());
        let digest = action.digest(scope.fingerprint(), &member);
        let slot = self.slot_of(&digest).ok_or(Error::StampDigestMissing)?;
        super::presentation::present(rng, secret, self, scope, slot, digest)
    }

    /// Encoding for the holder's sealed state, without the holder secret.
    /// Wipes itself on drop.
    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::Stamp);
        self.issuer.encode_body(&mut w);
        w.u64(self.epoch);
        w.u64(self.expires);
        for slot in &self.slots {
            w.ark(slot);
        }
        w.ark(&self.signature);
        w.finish_secret()
    }

    /// Restores a stamp written by [`to_bytes`](Self::to_bytes) for the holder
    /// whose secret is `secret` and re-checks its signature, so a stamp of
    /// another holder never restores.
    pub(crate) fn from_bytes(bytes: &[u8], secret: &HolderSecret) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::Stamp)?;
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

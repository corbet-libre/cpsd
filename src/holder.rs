//! Holder side: secret, issuance request, passport.

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_std::UniformRand;
use ark_std::rand::{CryptoRng, RngCore};
use bbs_plus::signature::SignatureG1;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    AuthenticatedCommunity, CommunityId, Error, IssuerPublicKey, KeyId, PassportAttributes,
    Presentation, Pseudonym, Timestamp,
    issuer::{
        BlindPassport, IssuanceChallenge, IssuanceRequest, IssuerTag, nonzero_scalar, point_bytes,
    },
    params::{self, IDX_SECRET},
    proof::IssuanceProof,
    wire::{Kind, Reader, Writer},
};

/// The holder's long-term secret: a uniformly random non-zero scalar.
///
/// It never leaves the holder's device (the vault). Every community pseudonym
/// and the issuer tag are deterministic functions of it, so it must be kept
/// across passport renewals. Wiped from memory on drop; `Debug` is redacted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HolderSecret(pub(crate) Fr);

impl HolderSecret {
    /// Draws a fresh secret.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(nonzero_scalar(rng))
    }

    /// Encoding for the holder's vault. The result wipes itself on drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::HolderSecret);
        w.ark(&self.0);
        w.finish_secret()
    }

    /// Restores a secret written by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::HolderSecret)?;
        let s = Self(r.ark::<Fr>("holder secret")?);
        r.finish()?;
        if s.0.is_zero() {
            return Err(Error::InvalidKey);
        }
        Ok(s)
    }

    /// The pseudonym of this holder in `community` (computed locally, no proof).
    pub fn pseudonym(&self, community: &CommunityId) -> Pseudonym {
        Pseudonym::from_point(scalar_mul(params::community_base(community), &self.0))
    }

    /// The issuer tag of this holder (see [`IssuerTag`]).
    pub fn issuer_tag(&self) -> IssuerTag {
        IssuerTag(point_bytes(&scalar_mul(params::issuer_tag_base(), &self.0)))
    }
}

impl core::fmt::Debug for HolderSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HolderSecret(<redacted>)")
    }
}

fn scalar_mul(base: G1Affine, s: &Fr) -> G1Affine {
    (base * s).into_affine()
}

/// Starts blind issuance: commits to `secret` for `issuer` and proves, bound
/// to the issuer's `challenge`, that the commitment and the issuer tag hide
/// the same secret.
///
/// Send the [`IssuanceRequest`] to the issuer; keep the [`PendingIssuance`]
/// (it holds the blinding factor) to unblind the answer. The request contains
/// neither the secret nor the blinding factor.
pub fn request_issue<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &HolderSecret,
    issuer: &IssuerPublicKey,
    challenge: &IssuanceChallenge,
) -> Result<(IssuanceRequest, PendingIssuance), Error> {
    // Pedersen hiding uses uniform randomness over the entire scalar field.
    // Only the long-term holder secret must exclude zero.
    let blinding = Fr::rand(rng);
    let commitment = issuer
        .signature_params()
        .commit_to_messages([(IDX_SECRET, &secret.0)], &blinding)
        .map_err(|_| Error::ProofGeneration)?;
    let issuer_tag = scalar_mul(params::issuer_tag_base(), &secret.0);
    if commitment.is_zero() || issuer_tag.is_zero() {
        return Err(Error::ProofGeneration);
    }

    let proof = IssuanceProof::new(
        rng,
        issuer,
        challenge,
        &commitment,
        &issuer_tag,
        secret.0,
        blinding,
    )?;

    let request = IssuanceRequest {
        key_id: issuer.key_id().clone(),
        commitment,
        issuer_tag,
        proof,
    };
    let pending = PendingIssuance {
        secret: secret.clone(),
        blinding,
        issuer: issuer.clone(),
    };
    Ok((request, pending))
}

/// Holder state between [`request_issue`] and the issuer's answer.
///
/// Holds the secret and the blinding factor; wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PendingIssuance {
    secret: HolderSecret,
    blinding: Fr,
    #[zeroize(skip)]
    issuer: IssuerPublicKey,
}

impl PendingIssuance {
    pub(crate) fn from_opening(
        secret: &HolderSecret,
        blinding: Fr,
        issuer: &IssuerPublicKey,
    ) -> Self {
        Self {
            secret: secret.clone(),
            blinding,
            issuer: issuer.clone(),
        }
    }

    pub(crate) fn issuer(&self) -> &IssuerPublicKey {
        &self.issuer
    }

    pub(crate) fn belongs_to(&self, secret: &HolderSecret) -> bool {
        self.secret.0 == secret.0
    }

    /// Unblinds the issuer's answer and checks the signature over the holder
    /// secret and the signed attributes. Returns the passport.
    pub fn finish(self, blind: &BlindPassport) -> Result<Passport, Error> {
        if blind.key_id != *self.issuer.key_id() {
            return Err(Error::KeyMismatch);
        }
        blind.attributes.validate(self.issuer.gates())?;
        let signature = blind.signature.clone().unblind(&self.blinding);
        Passport::assemble(
            self.secret.clone(),
            self.issuer.clone(),
            blind.attributes.clone(),
            blind.revocation,
            signature,
        )
    }

    /// Encoding for holder storage across a page reload. Contains the secret;
    /// the result wipes itself on drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::PendingIssuance);
        w.ark(&self.secret.0);
        w.ark(&self.blinding);
        self.issuer.encode_body(&mut w);
        w.finish_secret()
    }

    /// Restores state written by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::PendingIssuance)?;
        let secret = HolderSecret(r.ark::<Fr>("holder secret")?);
        let blinding = r.ark::<Fr>("blinding")?;
        let issuer = IssuerPublicKey::decode_body(&mut r)?;
        r.finish()?;
        if secret.0.is_zero() {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            secret,
            blinding,
            issuer,
        })
    }
}

impl core::fmt::Debug for PendingIssuance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingIssuance")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

/// A passport: the unblinded BBS+ signature, the signed attributes, the
/// holder secret and the issuer's public key.
///
/// Held only by the holder (the vault). Shown only as a zero-knowledge
/// [`Presentation`]. Wiped from memory on drop; `Debug` shows the attributes
/// only.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Passport {
    pub(crate) secret: HolderSecret,
    #[zeroize(skip)]
    pub(crate) issuer: IssuerPublicKey,
    #[zeroize(skip)]
    pub(crate) attributes: PassportAttributes,
    pub(crate) revocation: Fr,
    pub(crate) signature: SignatureG1<params::Curve>,
}

impl Passport {
    /// Builds a passport after checking the signature.
    fn assemble(
        secret: HolderSecret,
        issuer: IssuerPublicKey,
        attributes: PassportAttributes,
        revocation: Fr,
        signature: SignatureG1<params::Curve>,
    ) -> Result<Self, Error> {
        if secret.0.is_zero() {
            return Err(Error::InvalidKey);
        }
        let passport = Self {
            secret,
            issuer,
            attributes,
            revocation,
            signature,
        };
        passport.check_signature()?;
        Ok(passport)
    }

    pub(crate) fn messages(&self) -> Zeroizing<Vec<Fr>> {
        params::passport_messages(
            &self.secret.0,
            self.issuer.key_id(),
            self.issuer.gates(),
            &self.attributes,
            &self.revocation,
        )
    }

    fn check_signature(&self) -> Result<(), Error> {
        self.attributes.validate(self.issuer.gates())?;
        self.signature
            .verify(
                &self.messages(),
                self.issuer.bbs_public_key().clone(),
                self.issuer.signature_params().clone(),
            )
            .map_err(|_| Error::InvalidSignature)
    }

    /// The signed attributes.
    pub fn attributes(&self) -> &PassportAttributes {
        &self.attributes
    }

    /// The issuer key that signed the passport.
    pub fn issuer(&self) -> &IssuerPublicKey {
        &self.issuer
    }

    /// Signing key ID.
    pub fn key_id(&self) -> &KeyId {
        self.issuer.key_id()
    }

    /// The holder secret, for renewal requests ([`request_issue`]).
    pub fn secret(&self) -> &HolderSecret {
        &self.secret
    }

    /// The holder's pseudonym in `community` (computed locally, no proof).
    pub fn pseudonym(&self, community: &CommunityId) -> Pseudonym {
        self.secret.pseudonym(community)
    }

    /// Answer a signed request only for the wallet's authenticated expected scope.
    /// See [`crate::present`]. Unsigned requests cannot call this API.
    ///
    /// ```compile_fail
    /// # fn unsigned(p: &cpsd::Passport, r: &cpsd::PresentationRequest,
    /// # rng: &mut (impl cpsd::rand::RngCore + cpsd::rand::CryptoRng)) {
    /// p.present(rng, r);
    /// # }
    /// ```
    pub fn present<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        expected: &AuthenticatedCommunity,
        signed_request: &[u8],
        now: Timestamp,
    ) -> Result<Presentation, Error> {
        crate::presentation::present(rng, self, expected, signed_request, now)
    }

    /// Encoding for the holder's vault. Contains the secret; the result wipes
    /// itself on drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::Passport);
        w.ark(&self.secret.0);
        self.issuer.encode_body(&mut w);
        self.attributes.encode(&mut w);
        w.ark(&self.revocation);
        w.ark(&self.signature);
        w.finish_secret()
    }

    /// Restores a passport written by [`to_bytes`](Self::to_bytes) and
    /// re-checks its signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::Passport)?;
        let secret = HolderSecret(r.ark::<Fr>("holder secret")?);
        let issuer = IssuerPublicKey::decode_body(&mut r)?;
        let attributes = PassportAttributes::decode(&mut r)?;
        let revocation = r.ark::<Fr>("revocation handle")?;
        let signature = r.ark::<SignatureG1<params::Curve>>("signature")?;
        r.finish()?;
        Self::assemble(secret, issuer, attributes, revocation, signature)
    }
}

impl core::fmt::Debug for Passport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Passport")
            .field("key_id", self.issuer.key_id())
            .field("attributes", &self.attributes)
            .finish_non_exhaustive()
    }
}

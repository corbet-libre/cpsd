//! Stamp issuer keys and the expiry-cohort rule they carry.

use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_std::rand::{CryptoRng, RngCore};
use bbs_plus::{
    setup::{PublicKeyG2, SecretKey, SignatureParamsG1},
    signature::SignatureG1,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use super::{BlindStamp, StampIssuanceRequest};
use crate::{
    Error, IssuanceChallenge, KeyId, Timestamp,
    attributes::check_timestamp,
    error::ensure,
    issuer::nonzero_scalar,
    params::{self, Curve, IDX_KEY_ID, STAMP_IDX_EPOCH, STAMP_IDX_EXPIRY},
    wire::{Kind, Reader, Writer},
};

/// Shortest accepted expiry cohort (one minute).
pub const MIN_STAMP_COHORT_SECONDS: u64 = 60;

/// Longest accepted expiry cohort (one day). Stamps have no revocation; a
/// short cohort is what bounds a stolen or compromised stamp.
pub const MAX_STAMP_COHORT_SECONDS: u64 = 24 * 60 * 60;

/// Public half of a stamp issuer key: key ID, cohort length and BBS+ public
/// key, published in the wallet's stamp key ring.
///
/// The cohort length is the rulebook's stamp lifetime. Every stamp expires at
/// a multiple of it ([`expiry_for`](Self::expiry_for)), so the revealed expiry
/// is a coarse value shared by every stamp issued in the same half cohort.
/// Changing the length means rotating to a new key. The BBS+ generators are
/// re-derived from the key ID in a stamp-only domain.
#[derive(Clone)]
pub struct StampPublicKey {
    key_id: KeyId,
    cohort: u64,
    public_key: PublicKeyG2<Curve>,
    params: SignatureParamsG1<Curve>,
}

impl StampPublicKey {
    fn assemble(key_id: KeyId, cohort: u64, public_key: PublicKeyG2<Curve>) -> Result<Self, Error> {
        check_cohort(cohort)?;
        ensure(public_key.is_valid(), Error::InvalidKey)?;
        let params = params::stamp_signature_params(&key_id);
        ensure(params.is_valid(), Error::InvalidKey)?;
        Ok(Self {
            key_id,
            cohort,
            public_key,
            params,
        })
    }

    /// The key ID.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Length of one expiry cohort in seconds.
    pub fn cohort_seconds(&self) -> u64 {
        self.cohort
    }

    /// The exclusive expiry the issuer signs for a stamp issued at `now`: the
    /// end of the cohort containing `now`, or the end of the next cohort when
    /// less than half of the current one remains. Verifiers accept exactly
    /// these two values ([`verify_stamp`](crate::verify_stamp)).
    pub fn expiry_for(&self, now: Timestamp) -> Result<Timestamp, Error> {
        check_timestamp(now)?;
        let end = (now / self.cohort + 1) * self.cohort;
        let expires = if (end - now) * 2 < self.cohort {
            end + self.cohort
        } else {
            end
        };
        check_timestamp(expires)?;
        Ok(expires)
    }

    /// Verifier rule: `expires` lies on the cohort grid, is still ahead of
    /// `now` and is at most two cohorts away.
    pub(crate) fn check_expiry(&self, expires: Timestamp, now: Timestamp) -> Result<(), Error> {
        check_timestamp(now)?;
        if !expires.is_multiple_of(self.cohort) {
            return Err(Error::WrongExpiryCohort);
        }
        if expires <= now {
            return Err(Error::StampExpired);
        }
        if expires - now > 2 * self.cohort {
            return Err(Error::WrongExpiryCohort);
        }
        Ok(())
    }

    /// Holder rule at unblinding: refuse a signed expiry off the public grid,
    /// which a dishonest issuer could otherwise use to tag one holder.
    pub(crate) fn check_alignment(&self, expires: Timestamp) -> Result<(), Error> {
        check_timestamp(expires)?;
        ensure(expires.is_multiple_of(self.cohort), Error::InvalidStamp)
    }

    /// Canonical encoding for the published stamp key ring.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::StampPublicKey);
        self.encode_body(&mut w);
        w.finish_public()
    }

    /// Decodes and validates a key published with [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::StampPublicKey)?;
        let key = Self::decode_body(&mut r)?;
        r.finish()?;
        Ok(key)
    }

    pub(crate) fn encode_body(&self, w: &mut Writer) {
        w.key_id(&self.key_id);
        w.u64(self.cohort);
        w.ark(&self.public_key);
    }

    pub(crate) fn decode_body(r: &mut Reader<'_>) -> Result<Self, Error> {
        let key_id = r.key_id()?;
        let cohort = r.u64()?;
        let public_key = r.ark::<PublicKeyG2<Curve>>("stamp public key")?;
        Self::assemble(key_id, cohort, public_key)
    }

    pub(crate) fn signature_params(&self) -> &SignatureParamsG1<Curve> {
        &self.params
    }

    pub(crate) fn bbs_public_key(&self) -> &PublicKeyG2<Curve> {
        &self.public_key
    }
}

impl PartialEq for StampPublicKey {
    fn eq(&self, other: &Self) -> bool {
        // `params` is a function of the key ID.
        self.key_id == other.key_id
            && self.cohort == other.cohort
            && self.public_key == other.public_key
    }
}

impl Eq for StampPublicKey {}

impl core::fmt::Debug for StampPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StampPublicKey")
            .field("key_id", &self.key_id)
            .field("cohort_seconds", &self.cohort)
            .finish_non_exhaustive()
    }
}

fn check_cohort(cohort: u64) -> Result<(), Error> {
    ensure(
        (MIN_STAMP_COHORT_SECONDS..=MAX_STAMP_COHORT_SECONDS).contains(&cohort),
        Error::InvalidStamp,
    )
}

/// Stamp issuer key pair, held by the wallet next to (never instead of) the
/// passport issuer key.
///
/// The secret key has no getter; [`to_secret_bytes`](Self::to_secret_bytes)
/// exists only to move the key into the platform secret store. Wiped on drop.
pub struct StampIssuerKey {
    public: StampPublicKey,
    secret: SecretKey<Fr>,
}

impl StampIssuerKey {
    /// Generates a fresh key for `key_id` with the given cohort length.
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        key_id: KeyId,
        cohort_seconds: u64,
    ) -> Result<Self, Error> {
        Self::from_secret(key_id, cohort_seconds, SecretKey(nonzero_scalar(rng)))
    }

    fn from_secret(key_id: KeyId, cohort: u64, secret: SecretKey<Fr>) -> Result<Self, Error> {
        ensure(!secret.0.is_zero(), Error::InvalidKey)?;
        let params = params::stamp_signature_params(&key_id);
        let public_key = PublicKeyG2::generate_using_secret_key(&secret, &params);
        let public = StampPublicKey::assemble(key_id, cohort, public_key)?;
        Ok(Self { public, secret })
    }

    /// The public half, for the stamp key ring.
    pub fn public_key(&self) -> &StampPublicKey {
        &self.public
    }

    /// Encoding of the key pair for the platform secret store. The result
    /// wipes itself on drop.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::StampIssuerKey);
        w.key_id(&self.public.key_id);
        w.u64(self.public.cohort);
        w.ark(&self.secret.0);
        w.finish_secret()
    }

    /// Restores a key pair written by [`to_secret_bytes`](Self::to_secret_bytes);
    /// the public key is recomputed from the secret.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::StampIssuerKey)?;
        let key_id = r.key_id()?;
        let cohort = r.u64()?;
        let secret = SecretKey(r.ark::<Fr>("stamp issuer secret key")?);
        r.finish()?;
        Self::from_secret(key_id, cohort, secret)
    }

    /// Signs a stamp over the holder's blinded secret and slots.
    ///
    /// Verifies first that `request` proves knowledge of the committed secret
    /// and slots and that its issuer tag hides the same secret, bound to this
    /// key and to `challenge`. The signed attributes are the key ID, `epoch`
    /// and the cohort expiry computed from `now` ([`StampPublicKey::expiry_for`]);
    /// no caller-selected expiry exists. Services use [`issue_stamp_once`]
    /// (crate::issue_stamp_once), which also binds the wallet member, the
    /// passport tag and a single-use challenge.
    pub fn issue_blind<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        request: &StampIssuanceRequest,
        challenge: &IssuanceChallenge,
        epoch: u64,
        now: Timestamp,
    ) -> Result<BlindStamp, Error> {
        if request.key_id != self.public.key_id {
            return Err(Error::KeyMismatch);
        }
        let expires = self.public.expiry_for(now)?;
        request.verify(&self.public, challenge)?;
        let key_id = params::key_id_scalar(&self.public.key_id);
        let epoch_scalar = Fr::from(epoch);
        let expiry_scalar = Fr::from(expires);
        let known = BTreeMap::from([
            (IDX_KEY_ID, &key_id),
            (STAMP_IDX_EPOCH, &epoch_scalar),
            (STAMP_IDX_EXPIRY, &expiry_scalar),
        ]);
        let signature = SignatureG1::<Curve>::new_with_committed_messages(
            rng,
            &request.commitment,
            known,
            &self.secret,
            &self.public.params,
        )
        .map_err(crate::error::redact(Error::InvalidIssuanceRequest))?;
        Ok(BlindStamp {
            key_id: self.public.key_id.clone(),
            epoch,
            expires,
            signature,
        })
    }
}

impl core::fmt::Debug for StampIssuerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StampIssuerKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

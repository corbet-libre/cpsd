//! Issuer side: keys and blind issuance.

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_std::{
    UniformRand,
    rand::{CryptoRng, RngCore},
};
use bbs_plus::{
    setup::{PublicKeyG2, SecretKey, SignatureParamsG1},
    signature::SignatureG1,
};
use blake2::Blake2b512;
use proof_system::{
    meta_statement::{EqualWitnesses, MetaStatements},
    proof::Proof,
    proof_spec::ProofSpec,
    statement::{Statements, ped_comm::PedersenCommitment as PedersenCommitmentStmt},
    verifier::VerifierConfig,
};
use zeroize::Zeroizing;

use crate::{
    Error, GateId, KeyId, MAX_GATES, PassportAttributes,
    params::{
        self, Curve, DOMAIN_ISSUANCE, IDX_EPOCH, IDX_FIRST_GATE, IDX_KEY_ID, IDX_REVOCATION,
        IDX_SECRET, IDX_VALID_UNTIL, Label,
    },
    wire::{Kind, Reader, Writer},
};

/// Public half of an issuer key: key ID, gate catalogue and BBS+ public key.
///
/// Published in the issuer's key ring. The BBS+ message generators are not
/// stored; they are re-derived from the key ID and the catalogue, which proves
/// to every party that they carry no trapdoor.
#[derive(Clone)]
pub struct IssuerPublicKey {
    key_id: KeyId,
    gates: Vec<GateId>,
    public_key: PublicKeyG2<Curve>,
    params: SignatureParamsG1<Curve>,
}

impl IssuerPublicKey {
    fn assemble(
        key_id: KeyId,
        gates: Vec<GateId>,
        public_key: PublicKeyG2<Curve>,
    ) -> Result<Self, Error> {
        check_catalogue(&gates)?;
        crate::error::ensure(public_key.is_valid(), Error::InvalidKey)?;
        let params = params::signature_params(&key_id, &gates);
        crate::error::ensure(params.is_valid(), Error::InvalidKey)?;
        Ok(Self {
            key_id,
            gates,
            public_key,
            params,
        })
    }

    /// The key ID.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The gate catalogue; the order fixes each gate's slot in the passport.
    pub fn gates(&self) -> &[GateId] {
        &self.gates
    }

    /// Canonical encoding for the published key ring.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::IssuerPublicKey);
        self.encode_body(&mut w);
        w.finish_public()
    }

    /// Decodes and validates a key published with [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::IssuerPublicKey)?;
        let key = Self::decode_body(&mut r)?;
        r.finish()?;
        Ok(key)
    }

    pub(crate) fn encode_body(&self, w: &mut Writer) {
        w.key_id(&self.key_id);
        w.u16(self.gates.len() as u16);
        for gate in &self.gates {
            w.gate(gate);
        }
        w.ark(&self.public_key);
    }

    pub(crate) fn decode_body(r: &mut Reader<'_>) -> Result<Self, Error> {
        let key_id = r.key_id()?;
        let gates = decode_catalogue(r)?;
        let public_key = r.ark::<PublicKeyG2<Curve>>("issuer public key")?;
        Self::assemble(key_id, gates, public_key)
    }

    pub(crate) fn signature_params(&self) -> &SignatureParamsG1<Curve> {
        &self.params
    }

    pub(crate) fn bbs_public_key(&self) -> &PublicKeyG2<Curve> {
        &self.public_key
    }

    /// Slot of `gate` in the catalogue.
    pub(crate) fn gate_slot(&self, gate: &GateId) -> Result<usize, Error> {
        self.gates
            .iter()
            .position(|g| g == gate)
            .ok_or_else(|| Error::UnknownGate(gate.clone()))
    }
}

impl PartialEq for IssuerPublicKey {
    fn eq(&self, other: &Self) -> bool {
        // `params` is a function of the other fields.
        self.key_id == other.key_id
            && self.gates == other.gates
            && self.public_key == other.public_key
    }
}

impl Eq for IssuerPublicKey {}

impl core::fmt::Debug for IssuerPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuerPublicKey")
            .field("key_id", &self.key_id)
            .field("gates", &self.gates)
            .finish_non_exhaustive()
    }
}

fn check_catalogue(gates: &[GateId]) -> Result<(), Error> {
    if gates.len() > MAX_GATES {
        return Err(Error::InvalidGateCatalogue);
    }
    let unique: BTreeSet<&GateId> = gates.iter().collect();
    if unique.len() != gates.len() {
        return Err(Error::InvalidGateCatalogue);
    }
    Ok(())
}

fn decode_catalogue(r: &mut Reader<'_>) -> Result<Vec<GateId>, Error> {
    let count = r.u16()? as usize;
    if count > MAX_GATES {
        return Err(Error::InvalidGateCatalogue);
    }
    (0..count).map(|_| r.gate()).collect()
}

/// Issuer key pair (the global level, `cgbl`).
///
/// The secret key has no getter. [`to_secret_bytes`](Self::to_secret_bytes)
/// exists only to move the key into the platform secret store; the key is
/// wiped from memory on drop.
pub struct IssuerKey {
    public: IssuerPublicKey,
    secret: SecretKey<Fr>,
}

impl IssuerKey {
    /// Generates a fresh key for `key_id` with the given gate catalogue.
    ///
    /// The catalogue is fixed for the lifetime of the key: adding a gate
    /// means rotating to a new key.
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        key_id: KeyId,
        gates: Vec<GateId>,
    ) -> Result<Self, Error> {
        check_catalogue(&gates)?;
        let params = params::signature_params(&key_id, &gates);
        let secret = SecretKey(nonzero_scalar(rng));
        let public_key = PublicKeyG2::generate_using_secret_key(&secret, &params);
        let public = IssuerPublicKey::assemble(key_id, gates, public_key)?;
        Ok(Self { public, secret })
    }

    /// The public half, for the key ring.
    pub fn public_key(&self) -> &IssuerPublicKey {
        &self.public
    }

    /// Encoding of the whole key pair for the platform secret store. The
    /// result wipes itself on drop.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new(Kind::IssuerKey);
        w.key_id(&self.public.key_id);
        w.u16(self.public.gates.len() as u16);
        for gate in &self.public.gates {
            w.gate(gate);
        }
        w.ark(&self.secret.0);
        w.finish_secret()
    }

    /// Restores a key pair written by [`to_secret_bytes`](Self::to_secret_bytes);
    /// the public key is recomputed from the secret.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::IssuerKey)?;
        let key_id = r.key_id()?;
        let gates = decode_catalogue(&mut r)?;
        let secret = SecretKey(r.ark::<Fr>("issuer secret key")?);
        r.finish()?;
        if secret.0.is_zero() {
            return Err(Error::InvalidKey);
        }
        let params = params::signature_params(&key_id, &gates);
        let public_key = PublicKeyG2::generate_using_secret_key(&secret, &params);
        let public = IssuerPublicKey::assemble(key_id, gates, public_key)?;
        Ok(Self { public, secret })
    }

    /// Signs a passport over the holder's blinded secret and `attributes`.
    ///
    /// Verifies first that `request` proves knowledge of the committed secret,
    /// bound to this key and to `challenge` (which the issuer must have
    /// generated for this session and must accept only once). The issuer never
    /// learns the secret; it learns the request's [`IssuerTag`], which it
    /// should compare with the tag stored for the person before signing (see
    /// [`IssuanceRequest::issuer_tag`]).
    pub fn issue_blind<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        request: &IssuanceRequest,
        challenge: &IssuanceChallenge,
        attributes: &PassportAttributes,
    ) -> Result<BlindPassport, Error> {
        if request.key_id != self.public.key_id {
            return Err(Error::KeyMismatch);
        }
        attributes.validate(&self.public.gates)?;
        request.verify(rng, &self.public, challenge)?;

        let revocation = nonzero_scalar(rng);
        let mut known = BTreeMap::new();
        known.insert(IDX_KEY_ID, params::key_id_scalar(&self.public.key_id));
        known.insert(IDX_EPOCH, Fr::from(attributes.policy_epoch));
        known.insert(IDX_VALID_UNTIL, Fr::from(attributes.valid_until));
        known.insert(IDX_REVOCATION, revocation);
        for (i, gate) in self.public.gates.iter().enumerate() {
            let expires = attributes.gates.get(gate).copied().unwrap_or(0);
            known.insert(IDX_FIRST_GATE + i, Fr::from(expires));
        }
        debug_assert!(!known.contains_key(&IDX_SECRET));
        let signature = SignatureG1::<Curve>::new_with_committed_messages(
            rng,
            &request.commitment,
            known.iter().map(|(i, m)| (*i, m)).collect(),
            &self.secret,
            &self.public.params,
        )
        .map_err(crate::error::redact(Error::InvalidIssuanceRequest))?;

        Ok(BlindPassport {
            key_id: self.public.key_id.clone(),
            attributes: attributes.clone(),
            revocation,
            signature,
        })
    }
}

impl core::fmt::Debug for IssuerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuerKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Fresh issuer nonce for one issuance session (32 random bytes).
///
/// The issuance request's proof is bound to it; the issuer must keep it with
/// the session and accept it for one request only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IssuanceChallenge([u8; 32]);

impl IssuanceChallenge {
    /// Draws a fresh challenge.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut c = [0u8; 32];
        rng.fill_bytes(&mut c);
        Self(c)
    }

    /// Wraps challenge bytes (as transported to the holder).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The challenge bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for IssuanceChallenge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IssuanceChallenge({})", crate::wire::hex(&self.0))
    }
}

/// The holder's pseudonym towards the issuer: `secret * H("issuer tag")`.
///
/// Deterministic per holder secret and independent of every community
/// pseudonym (distinguishing them is the decisional Diffie-Hellman problem in
/// G1). The issuer stores it with the person's uniqueness fingerprint on first
/// issuance and on renewal requires the same tag, so a renewed passport keeps
/// the same secret and therefore the same community pseudonyms (no fresh
/// identities through re-issuance).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IssuerTag(pub(crate) [u8; 48]);

impl IssuerTag {
    /// Compressed G1 encoding (48 bytes), suitable as a database key.
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0
    }
}

impl core::fmt::Debug for IssuerTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IssuerTag({})", crate::wire::hex(&self.0))
    }
}

/// A holder's request for a blind signature: a Pedersen commitment to the
/// holder secret, the issuer tag, and a zero-knowledge proof that both hide
/// the same secret, bound to the issuer's challenge.
#[derive(Clone)]
pub struct IssuanceRequest {
    pub(crate) key_id: KeyId,
    pub(crate) commitment: G1Affine,
    pub(crate) issuer_tag: G1Affine,
    pub(crate) proof: Proof<Curve>,
}

impl IssuanceRequest {
    /// Key the request is addressed to.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The holder's issuer tag. Check it against the person's stored tag
    /// before calling [`IssuerKey::issue_blind`]; it is only trustworthy after
    /// `issue_blind` has verified the request (a failed verification returns
    /// an error before signing).
    pub fn issuer_tag(&self) -> IssuerTag {
        IssuerTag(point_bytes(&self.issuer_tag))
    }

    /// Encoding for transport to the issuer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::IssuanceRequest);
        w.key_id(&self.key_id);
        w.ark(&self.commitment);
        w.ark(&self.issuer_tag);
        w.proof(&self.proof);
        w.finish_public()
    }

    /// Decodes a request received from a holder.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::IssuanceRequest)?;
        let key_id = r.key_id()?;
        let commitment = r.ark::<G1Affine>("commitment")?;
        let issuer_tag = r.ark::<G1Affine>("issuer tag")?;
        let proof = r.proof(false)?;
        r.finish()?;
        if commitment.is_zero() || issuer_tag.is_zero() {
            return Err(Error::Decode("identity element"));
        }
        Ok(Self {
            key_id,
            commitment,
            issuer_tag,
            proof,
        })
    }

    fn verify<R: RngCore>(
        &self,
        rng: &mut R,
        issuer: &IssuerPublicKey,
        challenge: &IssuanceChallenge,
    ) -> Result<(), Error> {
        if self.commitment.is_zero() || self.issuer_tag.is_zero() {
            return Err(Error::InvalidIssuanceRequest);
        }
        let spec = issuance_spec(issuer, self.commitment, self.issuer_tag);
        if !crate::proof_wire::well_formed(&self.proof, spec.statements.len(), false) {
            return Err(Error::InvalidIssuanceRequest);
        }
        self.proof
            .clone()
            .verify::<R, Blake2b512>(
                rng,
                spec,
                Some(challenge.0.to_vec()),
                VerifierConfig::default(),
            )
            .map_err(crate::error::redact(Error::InvalidIssuanceRequest))
    }
}

impl core::fmt::Debug for IssuanceRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuanceRequest")
            .field("key_id", &self.key_id)
            .field("issuer_tag", &self.issuer_tag())
            .finish_non_exhaustive()
    }
}

/// Proof specification of an issuance request (same for holder and issuer):
///
/// 1. knowledge of `(blinding, secret)` with
///    `commitment = h_0 * blinding + h_secret * secret`;
/// 2. knowledge of `secret'` with `issuer_tag = T * secret'`;
/// 3. `secret == secret'`.
///
/// The context binds the proof to the issuer key; the nonce (the issuer's
/// challenge) binds it to the session.
pub(crate) fn issuance_spec(
    issuer: &IssuerPublicKey,
    commitment: G1Affine,
    issuer_tag: G1Affine,
) -> ProofSpec<Curve> {
    let params = issuer.signature_params();
    let mut statements = Statements::<Curve>::new();
    statements.add(PedersenCommitmentStmt::new_statement_from_params::<Curve>(
        vec![params.h_0, params.h[IDX_SECRET]],
        commitment,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params::<Curve>(
        vec![params::issuer_tag_base()],
        issuer_tag,
    ));
    let mut meta = MetaStatements::new();
    meta.add_witness_equality(EqualWitnesses([(0, 1), (1, 0)].into_iter().collect()));

    let mut context = Label::new(DOMAIN_ISSUANCE);
    context.bytes(&issuer.to_bytes());
    ProofSpec::new(statements, meta, vec![], Some(context.finish()))
}

/// A passport signature as returned by the issuer, still blinded.
///
/// Only the holder who made the request can unblind it
/// ([`PendingIssuance::finish`](crate::PendingIssuance::finish)).
#[derive(Clone)]
pub struct BlindPassport {
    pub(crate) key_id: KeyId,
    pub(crate) attributes: PassportAttributes,
    pub(crate) revocation: Fr,
    pub(crate) signature: SignatureG1<Curve>,
}

impl BlindPassport {
    /// Signing key.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The signed attributes.
    pub fn attributes(&self) -> &PassportAttributes {
        &self.attributes
    }

    /// The issuer-chosen revocation handle signed into the passport (hidden in
    /// every presentation). Unused in v1; the issuer should store it with the
    /// person so that accumulator revocation (v2) can revoke this passport.
    pub fn revocation_handle(&self) -> [u8; 32] {
        *scalar_bytes(&self.revocation)
    }

    /// Encoding for transport to the holder.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Kind::BlindPassport);
        w.key_id(&self.key_id);
        self.attributes.encode(&mut w);
        w.ark(&self.revocation);
        w.ark(&self.signature);
        w.finish_public()
    }

    /// Decodes a blind passport received from the issuer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::BlindPassport)?;
        let key_id = r.key_id()?;
        let attributes = PassportAttributes::decode(&mut r)?;
        let revocation = r.ark::<Fr>("revocation handle")?;
        let signature = r.ark::<SignatureG1<Curve>>("blind signature")?;
        r.finish()?;
        Ok(Self {
            key_id,
            attributes,
            revocation,
            signature,
        })
    }
}

impl core::fmt::Debug for BlindPassport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlindPassport")
            .field("key_id", &self.key_id)
            .field("attributes", &self.attributes)
            .finish_non_exhaustive()
    }
}

/// Uniformly random non-zero scalar.
pub(crate) fn nonzero_scalar<R: RngCore>(rng: &mut R) -> Fr {
    loop {
        let s = Fr::rand(rng);
        if !s.is_zero() {
            return s;
        }
    }
}

/// Compressed 48-byte encoding of a G1 point.
pub(crate) fn point_bytes(p: &G1Affine) -> [u8; 48] {
    use ark_serialize::CanonicalSerialize;
    let mut out = [0u8; 48];
    p.serialize_compressed(&mut out[..])
        .expect("G1 compresses to 48 bytes");
    out
}

/// Canonical 32-byte little-endian encoding of a scalar.
pub(crate) fn scalar_bytes(s: &Fr) -> Zeroizing<[u8; 32]> {
    use ark_serialize::CanonicalSerialize;
    let mut out = Zeroizing::new([0u8; 32]);
    s.serialize_compressed(&mut out[..])
        .expect("scalars compress to 32 bytes");
    out
}

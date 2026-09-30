//! Public parameters, message layout and domain separation.
//!
//! Every group element used by cpsd is derived by hashing a public,
//! domain-separated label to G1/G2 (docknetwork's try-and-increment
//! hash-to-curve, cofactor cleared), so nobody knows discrete-log relations
//! between them. Nothing in this module handles secrets except
//! [`passport_messages`], which assembles the signed message vector.

use std::sync::OnceLock;

use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use bbs_plus::setup::SignatureParamsG1;
use blake2::Blake2b512;
use bulletproofs_plus_plus::setup::SetupParams as BppSetupParams;
use dock_crypto_utils::hashing_utils::{affine_group_elem_from_try_and_incr, hash_to_field};
use zeroize::Zeroizing;

use crate::{CommunityId, GateId, KeyId, PassportAttributes};

/// The pairing-friendly curve (BLS12-381).
pub(crate) type Curve = Bls12_381;

// ---------------------------------------------------------------------------
// Message layout of the BBS+ passport signature (format v1).
// ---------------------------------------------------------------------------

/// Holder secret; committed (blinded) at issuance, never revealed.
pub(crate) const IDX_SECRET: usize = 0;
/// Scalar of the issuer key ID; revealed in presentations.
pub(crate) const IDX_KEY_ID: usize = 1;
/// Policy epoch; revealed in presentations.
pub(crate) const IDX_EPOCH: usize = 2;
/// End of validity; hidden, range-proven against the verifier's time.
pub(crate) const IDX_VALID_UNTIL: usize = 3;
/// Issuer-chosen random revocation handle; hidden. Reserved for accumulator
/// revocation (v2); not used by v1 presentations.
pub(crate) const IDX_REVOCATION: usize = 4;
/// First gate slot. Slot `IDX_FIRST_GATE + i` holds the expiry of catalogue
/// gate `i`, or zero if the gate was not passed; hidden, range-proven on request.
pub(crate) const IDX_FIRST_GATE: usize = 5;

/// Number of signed messages for a catalogue of `gate_count` gates.
pub(crate) fn message_count(gate_count: usize) -> usize {
    IDX_FIRST_GATE + gate_count
}

// ---------------------------------------------------------------------------
// Domain-separation labels.
// ---------------------------------------------------------------------------

const DOMAIN_SIGNATURE_PARAMS: &[u8] = b"cpsd/v1/bbs-plus-signature-params";
const DOMAIN_KEY_ID: &[u8] = b"cpsd/v1/key-id";
const DOMAIN_COMMUNITY_BASE: &[u8] = b"cpsd/v1/community-pseudonym-base";
const DOMAIN_ISSUER_TAG_BASE: &[u8] = b"cpsd/v1/issuer-tag-base";
const DOMAIN_RANGE_PROOF: &[u8] = b"cpsd/v1/bulletproofs-plus-plus-range-proof";
pub(crate) const DOMAIN_ISSUANCE: &[u8] = b"cpsd/v1/issuance";
pub(crate) const DOMAIN_PRESENTATION: &[u8] = b"cpsd/v1/presentation";

/// Unambiguous byte string builder for labels and proof contexts: every
/// variable-length field is length-prefixed.
pub(crate) struct Label(Vec<u8>);

impl Label {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut l = Self(Vec::with_capacity(256));
        l.bytes(domain);
        l
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&(b.len() as u32).to_be_bytes());
        self.0.extend_from_slice(b);
        self
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

/// BBS+ signature parameters of an issuer key: `g1`, `g2`, `h_0` and one `h_i`
/// per message, hashed from the key ID and the gate catalogue.
pub(crate) fn signature_params(key_id: &KeyId, gates: &[GateId]) -> SignatureParamsG1<Curve> {
    let mut label = Label::new(DOMAIN_SIGNATURE_PARAMS);
    label.bytes(key_id.as_str().as_bytes());
    label.u64(gates.len() as u64);
    for gate in gates {
        label.bytes(gate.as_str().as_bytes());
    }
    SignatureParamsG1::<Curve>::new::<Blake2b512>(
        &label.finish(),
        message_count(gates.len()) as u32,
    )
}

/// The key ID as a signed (and revealed) message.
pub(crate) fn key_id_scalar(key_id: &KeyId) -> Fr {
    hash_to_field::<Fr, Blake2b512>(DOMAIN_KEY_ID, key_id.as_str().as_bytes())
}

/// Hash-to-G1 of a public label; never the identity (checked).
fn base_point(input: &[u8]) -> G1Affine {
    let p = affine_group_elem_from_try_and_incr::<G1Affine, Blake2b512>(input);
    // Probability ~2^-255 for a hash output; fail loudly rather than produce a
    // pseudonym that does not depend on the secret.
    assert!(!p.is_zero(), "hash-to-curve produced the identity");
    p
}

/// Pseudonym base of a community: `pseudonym = secret * community_base(C)`.
pub(crate) fn community_base(community: &CommunityId) -> G1Affine {
    let mut label = Label::new(DOMAIN_COMMUNITY_BASE);
    label.bytes(community.as_bytes());
    base_point(&label.finish())
}

/// Base of the issuer tag `secret * issuer_tag_base()`: the holder's pseudonym
/// towards the issuer, shown at every (re-)issuance.
pub(crate) fn issuer_tag_base() -> G1Affine {
    static BASE: OnceLock<G1Affine> = OnceLock::new();
    *BASE.get_or_init(|| base_point(&Label::new(DOMAIN_ISSUER_TAG_BASE).finish()))
}

/// Bulletproofs++ setup for one arbitrary-range proof of a 64-bit value in
/// base 2 (the configuration `proof_system`'s `BoundCheckBpp` uses).
pub(crate) fn range_proof_params() -> &'static BppSetupParams<G1Affine> {
    static PARAMS: OnceLock<BppSetupParams<G1Affine>> = OnceLock::new();
    PARAMS.get_or_init(|| {
        BppSetupParams::<G1Affine>::new_for_arbitrary_range_proof::<Blake2b512>(
            &Label::new(DOMAIN_RANGE_PROOF).finish(),
            2,
            64,
            1,
        )
    })
}

/// The full signed message vector of a passport. Contains the holder secret,
/// hence wiped on drop.
pub(crate) fn passport_messages(
    secret: &Fr,
    key_id: &KeyId,
    catalogue: &[GateId],
    attributes: &PassportAttributes,
    revocation: &Fr,
) -> Zeroizing<Vec<Fr>> {
    let mut m = Zeroizing::new(vec![Fr::zero(); message_count(catalogue.len())]);
    m[IDX_SECRET] = *secret;
    m[IDX_KEY_ID] = key_id_scalar(key_id);
    m[IDX_EPOCH] = Fr::from(attributes.policy_epoch);
    m[IDX_VALID_UNTIL] = Fr::from(attributes.valid_until);
    m[IDX_REVOCATION] = *revocation;
    for (i, gate) in catalogue.iter().enumerate() {
        if let Some(expires) = attributes.gates.get(gate) {
            m[IDX_FIRST_GATE + i] = Fr::from(*expires);
        }
    }
    m
}

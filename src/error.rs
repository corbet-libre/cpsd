//! Error type.

use core::fmt;

use crate::ids::GateId;

/// Everything that can go wrong in cpsd.
///
/// Errors never contain secret material. Verification failures of
/// zero-knowledge proofs are deliberately coarse ([`Error::InvalidProof`],
/// [`Error::InvalidIssuanceRequest`]): the caller learns that a proof is
/// invalid, not which sub-relation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key, gate or community identifier is empty, too long or contains
    /// characters outside its alphabet. The payload names the identifier kind.
    InvalidIdentifier(&'static str),
    /// A timestamp is zero or not below [`TIME_LIMIT`](crate::TIME_LIMIT).
    InvalidTimestamp,
    /// The gate catalogue of an issuer key is too large or contains duplicates.
    InvalidGateCatalogue,
    /// More gates than [`MAX_GATES`](crate::MAX_GATES) were requested or issued.
    TooManyGates,
    /// The gate is not in the catalogue of the issuer key.
    UnknownGate(GateId),
    /// The object belongs to a different issuer key than the one used.
    KeyMismatch,
    /// No key with the presentation's key ID is in the verifier's key ring.
    UnknownKey,
    /// The verifier's key ring contains the same key ID twice.
    DuplicateKeyId,
    /// A public or secret key is malformed (identity element or zero scalar).
    InvalidKey,
    /// The blind-issuance request does not prove knowledge of the committed
    /// holder secret for this issuer key and challenge.
    InvalidIssuanceRequest,
    /// An opaque holder already retains an outstanding issuance opening.
    IssuancePending,
    /// No private issuance opening exists for this answer.
    NoPendingIssuance,
    /// The opaque holder has not installed a verified passport.
    PassportUnavailable,
    /// The (unblinded) passport signature does not verify.
    InvalidSignature,
    /// The passport's validity period ended before the request's time.
    PassportExpired,
    /// The passport was issued under a different policy epoch than requested.
    WrongEpoch,
    /// Signed expiries differ from the verifier's common epoch expiry.
    WrongExpiryCohort,
    /// A requested gate is not in the passport.
    GateMissing(GateId),
    /// A requested gate is in the passport but expired before the request's time.
    GateExpired(GateId),
    /// A presentation proof does not verify.
    InvalidProof,
    /// The zero-knowledge proof could not be generated.
    ProofGeneration,
    /// The storage backend failed; no database/token/input details are exposed.
    Storage,
    /// The configured outstanding-challenge capacity was reached or invalid.
    StorageCapacity,
    /// A randomly generated challenge collided; nothing was overwritten.
    ChallengeConflict,
    /// Challenge absent, already consumed, expired or bound to another request.
    InvalidChallenge,
    /// A signed presentation request failed authentication, scope or time checks.
    InvalidPresentationRequest,
    /// This authenticated person already registered a different holder secret.
    IssuerTagMismatch,
    /// This holder secret is already bound to another authenticated person.
    IssuerTagClaimed,
    /// Bytes could not be decoded; the payload names the failing part.
    Decode(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidIdentifier(kind) => write!(f, "invalid {kind}"),
            Error::InvalidTimestamp => f.write_str("timestamp out of range"),
            Error::InvalidGateCatalogue => f.write_str("invalid gate catalogue"),
            Error::TooManyGates => f.write_str("too many gates"),
            Error::UnknownGate(g) => write!(f, "gate {g} is not in the issuer's catalogue"),
            Error::KeyMismatch => f.write_str("object belongs to a different issuer key"),
            Error::UnknownKey => f.write_str("unknown issuer key"),
            Error::DuplicateKeyId => f.write_str("duplicate key ID in key ring"),
            Error::InvalidKey => f.write_str("invalid key"),
            Error::InvalidIssuanceRequest => f.write_str("invalid issuance request"),
            Error::IssuancePending => f.write_str("issuance already pending"),
            Error::NoPendingIssuance => f.write_str("no pending issuance"),
            Error::PassportUnavailable => f.write_str("passport unavailable"),
            Error::InvalidSignature => f.write_str("invalid passport signature"),
            Error::PassportExpired => f.write_str("passport expired"),
            Error::WrongEpoch => f.write_str("wrong policy epoch"),
            Error::WrongExpiryCohort => f.write_str("wrong expiry cohort"),
            Error::GateMissing(g) => write!(f, "gate {g} missing from passport"),
            Error::GateExpired(g) => write!(f, "gate {g} expired"),
            Error::InvalidProof => f.write_str("invalid proof"),
            Error::ProofGeneration => f.write_str("proof generation failed"),
            Error::Storage => f.write_str("challenge storage failed"),
            Error::StorageCapacity => f.write_str("challenge storage capacity exceeded"),
            Error::ChallengeConflict => f.write_str("challenge collision"),
            Error::InvalidChallenge => f.write_str("invalid or consumed challenge"),
            Error::InvalidPresentationRequest => {
                f.write_str("unauthenticated presentation request")
            }
            Error::IssuerTagMismatch => f.write_str("issuer tag continuity failed"),
            Error::IssuerTagClaimed => f.write_str("issuer tag already claimed"),
            Error::Decode(what) => write!(f, "cannot decode {what}"),
        }
    }
}

impl std::error::Error for Error {}

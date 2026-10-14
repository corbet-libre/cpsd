//! Action digests: what one stamp slot approves, bound to one community, one
//! member pseudonym and one action, salted so the issuer cannot guess it.

use ark_std::rand::{CryptoRng, RngCore};
use blake2::{Blake2s256, Digest};

use crate::{CommunityId, Error, Pseudonym, params::Label, wire::hex};

/// Domain of the stamp digest (confirmation design, "Stamp construction").
const DOMAIN_DIGEST: &[u8] = b"cmty.stamp.v1";

/// Maximum length in bytes of an [`ActionKind`].
pub const MAX_ACTION_KIND_LEN: usize = 64;

/// The community fingerprint the device pins for a community (32 bytes).
///
/// It names the community inside every digest, next to the pseudonym scope
/// ([`CommunityId`]) the presentation proves; both come from the device's own
/// pinned community record, never from the action's sender.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommunityFingerprint([u8; 32]);

impl CommunityFingerprint {
    /// Wraps the pinned fingerprint bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The fingerprint bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for CommunityFingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CommunityFingerprint({})", hex(&self.0))
    }
}

/// Kind of a stamped action (for example `lineage.pair` or `device.revoke`).
///
/// 1 to 64 characters from `a-z`, `0-9`, `.`, `_` and `-`, the gate alphabet.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionKind(String);

impl ActionKind {
    /// Validates and wraps an action kind.
    pub fn new(kind: impl Into<String>) -> Result<Self, Error> {
        let kind = kind.into();
        let allowed = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b);
        if kind.is_empty() || kind.len() > MAX_ACTION_KIND_LEN || !kind.bytes().all(allowed) {
            return Err(Error::InvalidIdentifier("action kind"));
        }
        Ok(Self(kind))
    }

    /// The kind as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for ActionKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ActionKind({})", self.0)
    }
}

/// Digest of the exact action payload, computed by the caller with its own
/// canonical encoding (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadDigest([u8; 32]);

impl PayloadDigest {
    /// Wraps a payload digest.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for PayloadDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PayloadDigest({})", hex(&self.0))
    }
}

/// A fresh 256-bit salt per stamped action, drawn by the device.
///
/// It travels with the action to the community and never to the wallet, so
/// the wallet cannot recompute or guess a digest from a known action. `Debug`
/// is redacted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StampSalt([u8; 32]);

impl StampSalt {
    /// Draws a fresh salt.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        Self(salt)
    }

    /// Wraps salt bytes received with an action.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The salt bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for StampSalt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StampSalt(<redacted>)")
    }
}

/// The digest one stamp slot carries:
/// `BLAKE2s-256("cmty.stamp.v1" ‖ fingerprint ‖ pseudonym ‖ kind ‖ payload ‖ salt)`,
/// every field length-prefixed (big-endian `u32`), the domain included.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StampDigest([u8; 32]);

impl StampDigest {
    /// Computes the digest from typed inputs.
    pub fn compute(
        fingerprint: &CommunityFingerprint,
        member: &Pseudonym,
        kind: &ActionKind,
        payload: &PayloadDigest,
        salt: &StampSalt,
    ) -> Self {
        let mut label = Label::new(DOMAIN_DIGEST);
        label
            .bytes(&fingerprint.0)
            .bytes(&member.to_bytes())
            .bytes(kind.as_str().as_bytes())
            .bytes(&payload.0)
            .bytes(&salt.0);
        Self(Blake2s256::digest(label.finish()).into())
    }

    /// Wraps digest bytes (as kept by the device until presentation).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn scalar(&self) -> ark_bls12_381::Fr {
        crate::params::stamp_slot_scalar(&self.0)
    }
}

impl core::fmt::Debug for StampDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StampDigest({})", hex(&self.0))
    }
}

/// One stamped action as the device and the community both hold it.
#[derive(Clone, PartialEq, Eq)]
pub struct StampAction {
    kind: ActionKind,
    payload: PayloadDigest,
    salt: StampSalt,
}

impl StampAction {
    /// Bundles the action's kind, payload digest and salt.
    pub fn new(kind: ActionKind, payload: PayloadDigest, salt: StampSalt) -> Self {
        Self {
            kind,
            payload,
            salt,
        }
    }

    /// The action kind.
    pub fn kind(&self) -> &ActionKind {
        &self.kind
    }

    /// The payload digest.
    pub fn payload(&self) -> &PayloadDigest {
        &self.payload
    }

    /// The salt.
    pub fn salt(&self) -> &StampSalt {
        &self.salt
    }

    /// The digest of this action by `member` in the community `fingerprint`.
    pub fn digest(&self, fingerprint: &CommunityFingerprint, member: &Pseudonym) -> StampDigest {
        StampDigest::compute(fingerprint, member, &self.kind, &self.payload, &self.salt)
    }
}

impl core::fmt::Debug for StampAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StampAction")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// A community as the stamp sees it: the pseudonym scope and the pinned
/// fingerprint. Devices take both from their pinned community record; a
/// verifier uses its own configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct StampScope {
    community: CommunityId,
    fingerprint: CommunityFingerprint,
}

impl StampScope {
    /// Pairs a community's pseudonym scope with its pinned fingerprint.
    pub fn new(community: CommunityId, fingerprint: CommunityFingerprint) -> Self {
        Self {
            community,
            fingerprint,
        }
    }

    /// The pseudonym scope.
    pub fn community(&self) -> &CommunityId {
        &self.community
    }

    /// The pinned fingerprint.
    pub fn fingerprint(&self) -> &CommunityFingerprint {
        &self.fingerprint
    }
}

impl core::fmt::Debug for StampScope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StampScope")
            .field("community", &self.community)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

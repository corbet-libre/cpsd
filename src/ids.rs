//! Validated identifiers: issuer keys, gates and communities.

use core::fmt;

use crate::Error;

/// Maximum length in bytes of a [`KeyId`] or [`GateId`].
pub const MAX_ID_LEN: usize = 64;

/// Maximum length in bytes of a [`CommunityId`].
pub const MAX_COMMUNITY_ID_LEN: usize = 255;

/// Identifier of an issuer key, published with the key ring.
///
/// 1 to 64 printable ASCII characters without spaces. It is signed into every
/// passport and disclosed in every presentation (it tells the verifier which
/// public key to use), so all holders of one key share it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Validates and wraps a key identifier.
    pub fn new(id: impl Into<String>) -> Result<Self, Error> {
        let id = id.into();
        if id.is_empty() || id.len() > MAX_ID_LEN || !id.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::InvalidIdentifier("key id"));
        }
        Ok(Self(id))
    }

    /// The identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifier of a global gate (for example `phone` or `government-id`).
///
/// 1 to 64 characters from `a-z`, `0-9`, `.`, `_` and `-`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GateId(String);

impl GateId {
    /// Validates and wraps a gate identifier.
    pub fn new(id: impl Into<String>) -> Result<Self, Error> {
        let id = id.into();
        let allowed = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b);
        if id.is_empty() || id.len() > MAX_ID_LEN || !id.bytes().all(allowed) {
            return Err(Error::InvalidIdentifier("gate id"));
        }
        Ok(Self(id))
    }

    /// The identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GateId({})", self.0)
    }
}

impl fmt::Display for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifier of a community: the pseudonym scope.
///
/// Opaque bytes, 1 to 255 of them. The pseudonym is a function of the exact
/// bytes, so callers must use one canonical form per community (for example
/// its immutable UUID), never a display name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommunityId(Vec<u8>);

impl CommunityId {
    /// Validates and wraps a community identifier.
    pub fn new(id: impl AsRef<[u8]>) -> Result<Self, Error> {
        let id = id.as_ref();
        if id.is_empty() || id.len() > MAX_COMMUNITY_ID_LEN {
            return Err(Error::InvalidIdentifier("community id"));
        }
        Ok(Self(id.to_vec()))
    }

    /// The identifier bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CommunityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(&self.0) {
            Ok(s) => write!(f, "CommunityId({s:?})"),
            Err(_) => write!(f, "CommunityId({})", crate::wire::hex(&self.0)),
        }
    }
}

//! The opaque holder's stamp state: at most one pending request and a bounded
//! set of stamps. Encoded only inside the sealed holder, and never with the
//! holder secret: the holder supplies it when it restores, finishes or presents.

use super::{BlindStamp, PendingStamp, Stamp, StampAction, StampScope};
use crate::{
    Error, HolderSecret, Timestamp,
    error::ensure,
    wire::{Kind, Reader, Writer},
};
use zeroize::Zeroizing;

/// Most stamps one holder retains. A new stamp first drops expired ones, then
/// the one that expires first.
pub(crate) const MAX_HELD_STAMPS: usize = 8;

pub(crate) struct StampState {
    pub(crate) pending: Option<PendingStamp>,
    pub(crate) stamps: Vec<Stamp>,
}

impl Default for StampState {
    fn default() -> Self {
        Self {
            pending: None,
            // Allocated once at its bound, so stamps never move through an
            // unwiped reallocation.
            stamps: Vec::with_capacity(MAX_HELD_STAMPS),
        }
    }
}

impl StampState {
    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_none() && self.stamps.is_empty()
    }

    /// Consumes the pending request (even on refusal) and retains the stamp.
    pub(crate) fn finish(
        &mut self,
        secret: &HolderSecret,
        blind: &BlindStamp,
        now: Timestamp,
    ) -> Result<(), Error> {
        let pending = self.pending.take().ok_or(Error::NoPendingIssuance)?;
        let stamp = pending.finish(secret, blind, now)?;
        self.stamps.retain(|held| now < held.expires);
        if self.stamps.len() >= MAX_HELD_STAMPS {
            // Non-empty here, so the first-expiring index always exists.
            let first = (0..self.stamps.len())
                .min_by_key(|&i| self.stamps[i].expires)
                .unwrap_or_default();
            self.stamps.remove(first);
        }
        self.stamps.push(stamp);
        Ok(())
    }

    /// The newest unexpired stamp that carries `action` in `scope`.
    pub(crate) fn covering(
        &self,
        secret: &HolderSecret,
        scope: &StampScope,
        action: &StampAction,
        now: Timestamp,
    ) -> Result<&Stamp, Error> {
        let mut expired = false;
        for stamp in self.stamps.iter().rev() {
            if stamp.covers(secret, scope, action) {
                if now < stamp.expires {
                    return Ok(stamp);
                }
                expired = true;
            }
        }
        Err(if expired {
            Error::StampExpired
        } else {
            Error::StampDigestMissing
        })
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let pending = self
            .pending
            .as_ref()
            .map(PendingStamp::to_bytes)
            .unwrap_or_default();
        let stamps: Vec<Zeroizing<Vec<u8>>> = self.stamps.iter().map(Stamp::to_bytes).collect();
        let length = 6 + 4 + pending.len() + 2 + stamps.iter().map(|s| 4 + s.len()).sum::<usize>();
        let mut w = Writer::with_capacity(Kind::StampState, length);
        w.bytes(&pending);
        w.u16(stamps.len() as u16);
        for stamp in &stamps {
            w.bytes(stamp);
        }
        w.finish_secret()
    }

    /// Restores the state for the holder whose secret is `secret`: every stamp
    /// must verify under it. An empty state is not a valid encoding.
    pub(crate) fn from_bytes(bytes: &[u8], secret: &HolderSecret) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::StampState)?;
        let pending = r.bytes()?;
        let pending = (!pending.is_empty())
            .then(|| PendingStamp::from_bytes(pending))
            .transpose()?;
        let count = usize::from(r.u16()?);
        ensure(count <= MAX_HELD_STAMPS, Error::InvalidSealedHolder)?;
        let mut state = Self {
            pending,
            ..Self::default()
        };
        for _ in 0..count {
            state.stamps.push(Stamp::from_bytes(r.bytes()?, secret)?);
        }
        r.finish()?;
        ensure(!state.is_empty(), Error::InvalidSealedHolder)?;
        Ok(state)
    }
}

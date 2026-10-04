//! Private extension under the original immutable holder seal, never exported.

use super::{BlindRootBoardCredential, RootBoardPublicKey};
use crate::{
    Error, HolderSecret, Passport, PendingIssuance,
    wire::{Kind, Reader, Writer},
};
use zeroize::Zeroizing;

pub(crate) struct RootBoardPending {
    pub(crate) descriptor: RootBoardPublicKey,
    pub(crate) opening: PendingIssuance,
}

pub(crate) struct RootBoardCredential {
    pub(crate) descriptor: RootBoardPublicKey,
    pub(crate) passport: Passport,
}

#[derive(Default)]
pub(crate) struct RootBoardState {
    pub(crate) pending: Option<RootBoardPending>,
    pub(crate) credential: Option<RootBoardCredential>,
}

impl RootBoardState {
    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_none() && self.credential.is_none()
    }

    pub(crate) fn finish(&mut self, blind: &BlindRootBoardCredential) -> Result<(), Error> {
        // Failed answers consume their own attempt; a previous credential stays.
        let pending = self.pending.take().ok_or(Error::NoPendingIssuance)?;
        if pending.descriptor != blind.descriptor
            || blind.blind.attributes() != &pending.descriptor.attributes()
        {
            return Err(Error::InvalidRootBoard);
        }
        let passport = pending.opening.finish(&blind.blind)?;
        self.credential = Some(RootBoardCredential {
            descriptor: pending.descriptor,
            passport,
        });
        Ok(())
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let pending_descriptor = self
            .pending
            .as_ref()
            .map(|p| p.descriptor.to_bytes())
            .unwrap_or_default();
        let opening = self
            .pending
            .as_ref()
            .map(|p| p.opening.to_bytes())
            .unwrap_or_default();
        let credential_descriptor = self
            .credential
            .as_ref()
            .map(|p| p.descriptor.to_bytes())
            .unwrap_or_default();
        let passport = self
            .credential
            .as_ref()
            .map(|p| p.passport.to_bytes())
            .unwrap_or_default();
        let length = 6
            + 16
            + pending_descriptor.len()
            + opening.len()
            + credential_descriptor.len()
            + passport.len();
        let mut w = Writer::with_capacity(Kind::RootBoardState, length);
        w.bytes(&pending_descriptor);
        w.bytes(&opening);
        w.bytes(&credential_descriptor);
        w.bytes(&passport);
        w.finish_secret()
    }

    pub(crate) fn from_bytes(bytes: &[u8], secret: &HolderSecret) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, Kind::RootBoardState)?;
        let pending_descriptor = r.bytes()?;
        let opening = r.bytes()?;
        let credential_descriptor = r.bytes()?;
        let passport = r.bytes()?;
        r.finish()?;
        let pending = if pending_descriptor.is_empty() && opening.is_empty() {
            None
        } else {
            let descriptor = RootBoardPublicKey::from_bytes(pending_descriptor)?;
            let opening = PendingIssuance::from_bytes(opening)?;
            if opening.issuer() != descriptor.issuer() || !opening.belongs_to(secret) {
                return Err(Error::InvalidSealedHolder);
            }
            Some(RootBoardPending {
                descriptor,
                opening,
            })
        };
        let credential = if credential_descriptor.is_empty() && passport.is_empty() {
            None
        } else {
            let descriptor = RootBoardPublicKey::from_bytes(credential_descriptor)?;
            // Original decoder verifies the actual signature, never a verdict.
            let passport = Passport::from_bytes(passport)?;
            if passport.issuer() != descriptor.issuer()
                || passport.attributes() != &descriptor.attributes()
                || passport.secret.0 != secret.0
            {
                return Err(Error::InvalidSealedHolder);
            }
            Some(RootBoardCredential {
                descriptor,
                passport,
            })
        };
        let state = Self {
            pending,
            credential,
        };
        if state.is_empty() {
            return Err(Error::InvalidSealedHolder);
        }
        Ok(state)
    }
}

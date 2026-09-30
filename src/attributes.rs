//! The disclosed-to-issuer content of a passport.

use std::collections::BTreeMap;

use crate::{
    Error, GateId,
    wire::{Reader, Writer},
};

/// Seconds since the Unix epoch.
pub type Timestamp = u64;

/// Exclusive upper bound for every [`Timestamp`] (2^40 s, about year 36812).
///
/// Range proofs show `now <= t < TIME_LIMIT` for hidden timestamps `t`.
pub const TIME_LIMIT: Timestamp = 1 << 40;

/// Maximum number of gates in an issuer's catalogue, a passport or a request.
pub const MAX_GATES: usize = 64;

/// The attributes the issuer signs next to the blinded holder secret.
///
/// The issuer sees them. The recommended shared-epoch profile sets passport
/// and passed-gate expiries to one authenticated, common epoch expiry. Only
/// include gates whose underlying validity reaches that expiry; never round
/// a gate's expiry upward. The verifier already knows the common value.
/// Independent-expiry presentations instead hide dates with range proofs.
///
/// A timestamp `t` counts as unexpired at time `now` if and only if
/// `now <= t`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassportAttributes {
    /// Passed global gates and the end of each gate's validity.
    pub gates: BTreeMap<GateId, Timestamp>,
    /// End of the passport's validity.
    pub valid_until: Timestamp,
    /// Policy epoch the passport was issued under; bumping the epoch
    /// invalidates every older passport at once.
    pub policy_epoch: u64,
}

impl PassportAttributes {
    /// Attributes without gates.
    pub fn new(valid_until: Timestamp, policy_epoch: u64) -> Self {
        Self {
            gates: BTreeMap::new(),
            valid_until,
            policy_epoch,
        }
    }

    /// Adds (or replaces) a passed gate with its expiry.
    pub fn with_gate(mut self, gate: GateId, expires: Timestamp) -> Self {
        self.gates.insert(gate, expires);
        self
    }

    /// Checks timestamps and that every gate is in `catalogue`.
    pub(crate) fn validate(&self, catalogue: &[GateId]) -> Result<(), Error> {
        check_timestamp(self.valid_until)?;
        if self.gates.len() > MAX_GATES {
            return Err(Error::TooManyGates);
        }
        for (gate, expires) in &self.gates {
            if !catalogue.contains(gate) {
                return Err(Error::UnknownGate(gate.clone()));
            }
            check_timestamp(*expires)?;
        }
        Ok(())
    }

    pub(crate) fn encode(&self, w: &mut Writer) {
        w.u64(self.policy_epoch);
        w.u64(self.valid_until);
        w.u16(self.gates.len() as u16);
        for (gate, expires) in &self.gates {
            w.gate(gate);
            w.u64(*expires);
        }
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let policy_epoch = r.u64()?;
        let valid_until = r.u64()?;
        let count = r.u16()? as usize;
        if count > MAX_GATES {
            return Err(Error::TooManyGates);
        }
        let mut gates = BTreeMap::new();
        let mut previous: Option<GateId> = None;
        for _ in 0..count {
            let gate = r.gate()?;
            // Canonical form: strictly ascending, hence no duplicates.
            if previous.as_ref().is_some_and(|p| *p >= gate) {
                return Err(Error::Decode("gate order"));
            }
            previous = Some(gate.clone());
            gates.insert(gate, r.u64()?);
        }
        Ok(Self {
            gates,
            valid_until,
            policy_epoch,
        })
    }
}

/// A timestamp must be in `1..TIME_LIMIT`. Zero is excluded because an absent
/// gate is encoded as zero.
pub(crate) fn check_timestamp(t: Timestamp) -> Result<(), Error> {
    if t == 0 || t >= TIME_LIMIT {
        Err(Error::InvalidTimestamp)
    } else {
        Ok(())
    }
}

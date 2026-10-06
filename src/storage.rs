//! Single-use challenges and global issuer-tag continuity. No request history.

use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
};

use crate::{CommunityId, Error, Timestamp, attributes::check_timestamp};

/// An outstanding challenge. Binding is a digest, not a stored request/proof.
#[derive(Clone, PartialEq, Eq)]
pub struct ChallengeRecord {
    /// Random 256-bit nonce, independent of every holder.
    pub nonce: [u8; 32],
    /// Domain-separated digest of the authoritative request.
    pub binding: [u8; 32],
    /// Inclusive challenge deadline, not a login/issuance date.
    pub expires: Timestamp,
}

impl core::fmt::Debug for ChallengeRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChallengeRecord(<redacted>)")
    }
}

/// Storage capability for exactly one community (or the separate global issuer).
///
/// `reserve` must never overwrite, `consume` must atomically compare and delete.
/// Lost state must fail closed. No tombstones, pseudonyms or history are retained.
/// Implementations must bound capacity and remove expired outstanding records.
pub trait ChallengeStore: Send + Sync {
    /// Immutable community scope selected by the service.
    fn community(&self) -> &CommunityId;
    /// Insert only if the nonce is absent. Return false on collision.
    fn reserve(&self, record: ChallengeRecord) -> impl Future<Output = Result<bool, Error>> + Send;
    /// Cheap lookup before cryptography; never substitutes for atomic consumption.
    fn matches(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: Timestamp,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
    /// Atomically delete a matching unexpired record, returning true once only.
    fn consume(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: Timestamp,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
    /// Delete outstanding records with deadlines strictly before `now`.
    fn prune(&self, now: Timestamp) -> impl Future<Output = Result<u64, Error>> + Send;
}

/// Proof-validated issuance authorization, constructible only by cpsd.
/// Store implementations must use all fields for an atomic compare-and-consume.
pub struct VerifiedIssuance {
    pub(crate) nonce: [u8; 32],
    pub(crate) binding: [u8; 32],
    pub(crate) now: Timestamp,
    pub(crate) person: [u8; 32],
    pub(crate) tag: crate::IssuerTag,
}

impl VerifiedIssuance {
    /// Nonce, binding, current time, stable opaque person ID, and proven issuer tag.
    pub fn fields(&self) -> ([u8; 32], [u8; 32], Timestamp, [u8; 32], crate::IssuerTag) {
        (self.nonce, self.binding, self.now, self.person, self.tag)
    }
}

/// Global issuer store. Register the first proven tag or compare with the existing
/// tag, and consume the matching unexpired nonce in ONE transaction. A mismatch
/// or failure must change neither record. Tags survive pruning and key rotation. A tag may belong to only one person,
/// preventing another account from renewing a suspended holder's pseudonyms.
/// Never reset this state while the associated global person remains registered.
pub trait IssuanceStore: ChallengeStore {
    /// Atomic tag continuity and challenge consumption; false means invalid nonce.
    fn consume_issuance(
        &self,
        issuance: VerifiedIssuance,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
}

#[derive(Default)]
struct MemoryState {
    records: BTreeMap<[u8; 32], ChallengeRecord>,
    tags: BTreeMap<[u8; 32], crate::IssuerTag>,
    tag_owners: BTreeMap<[u8; 48], [u8; 32]>,
}

/// In-memory implementation, also useful for a single-process ephemeral service.
/// Clones share state. Restart loses pending challenges, so old proofs fail closed.
#[derive(Clone)]
pub struct MemoryStore {
    community: CommunityId,
    capacity: usize,
    state: Arc<Mutex<MemoryState>>,
}

impl MemoryStore {
    /// Construct a fixed scope with a positive maximum pending count.
    pub fn new(community: CommunityId, capacity: usize) -> Result<Self, Error> {
        if capacity == 0 {
            return Err(Error::StorageCapacity);
        }
        Ok(Self {
            community,
            capacity,
            state: Arc::default(),
        })
    }
}

impl ChallengeStore for MemoryStore {
    fn community(&self) -> &CommunityId {
        &self.community
    }
    async fn reserve(&self, record: ChallengeRecord) -> Result<bool, Error> {
        check_timestamp(record.expires)?;
        let mut state = self
            .state
            .lock()
            .map_err(crate::error::redact(Error::Storage))?;
        let records = &mut state.records;
        if records.contains_key(&record.nonce) {
            return Ok(false);
        }
        if records.len() >= self.capacity {
            return Err(Error::StorageCapacity);
        }
        records.insert(record.nonce, record);
        Ok(true)
    }
    async fn matches(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: Timestamp,
    ) -> Result<bool, Error> {
        check_timestamp(now)?;
        let state = self
            .state
            .lock()
            .map_err(crate::error::redact(Error::Storage))?;
        Ok(state
            .records
            .get(&nonce)
            .is_some_and(|r| r.binding == binding && now <= r.expires))
    }
    async fn consume(
        &self,
        nonce: [u8; 32],
        binding: [u8; 32],
        now: Timestamp,
    ) -> Result<bool, Error> {
        check_timestamp(now)?;
        let mut state = self
            .state
            .lock()
            .map_err(crate::error::redact(Error::Storage))?;
        let records = &mut state.records;
        if records
            .get(&nonce)
            .is_some_and(|r| r.binding == binding && now <= r.expires)
        {
            records.remove(&nonce);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    async fn prune(&self, now: Timestamp) -> Result<u64, Error> {
        check_timestamp(now)?;
        let mut state = self
            .state
            .lock()
            .map_err(crate::error::redact(Error::Storage))?;
        let records = &mut state.records;
        let before = records.len();
        records.retain(|_, record| record.expires >= now);
        Ok((before - records.len()) as u64)
    }
}

impl IssuanceStore for MemoryStore {
    async fn consume_issuance(&self, issuance: VerifiedIssuance) -> Result<bool, Error> {
        let (nonce, binding, now, person, tag) = issuance.fields();
        check_timestamp(now)?;
        let mut state = self
            .state
            .lock()
            .map_err(crate::error::redact(Error::Storage))?;
        if !state
            .records
            .get(&nonce)
            .is_some_and(|r| r.binding == binding && now <= r.expires)
        {
            return Ok(false);
        }
        if state.tags.get(&person).is_some_and(|old| *old != tag) {
            return Err(Error::IssuerTagMismatch);
        }
        if state
            .tag_owners
            .get(&tag.to_bytes())
            .is_some_and(|old| *old != person)
        {
            return Err(Error::IssuerTagClaimed);
        }
        state.tag_owners.insert(tag.to_bytes(), person);
        state.tags.entry(person).or_insert(tag);
        state.records.remove(&nonce);
        Ok(true)
    }
}

/// Native libSQL implementation through `crlt`.
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
pub mod libsql {
    use super::*;
    use crlt::{Db, params};

    /// Append this DDL to the service's complete `crlt` migration history.
    /// Every table and index starts with the community key.
    pub const SCHEMA: &str = "
        CREATE TABLE cpsd_challenges (
            community_id TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK (length(nonce) = 32),
            binding BLOB NOT NULL CHECK (length(binding) = 32),
            expires INTEGER NOT NULL CHECK (expires > 0 AND expires < 1099511627776),
            PRIMARY KEY (community_id, nonce)
        ) WITHOUT ROWID;
        CREATE INDEX cpsd_challenges_expiry ON cpsd_challenges (community_id, expires);
    ";
    /// Append as a NEW migration after SCHEMA, never modify deployed history.
    pub const ISSUANCE_SCHEMA: &str = "
        CREATE TABLE cpsd_issuer_tags (
            community_id TEXT NOT NULL,
            person BLOB NOT NULL CHECK (length(person) = 32),
            tag BLOB NOT NULL CHECK (length(tag) = 48),
            PRIMARY KEY (community_id, person)
        ) WITHOUT ROWID;
    ";
    /// Append after ISSUANCE_SCHEMA. Existing duplicate tags require explicit
    /// operator reconciliation; migration fails rather than releasing a binding.
    pub const ISSUANCE_UNIQUENESS_SCHEMA: &str =
        "CREATE UNIQUE INDEX cpsd_issuer_tags_owner ON cpsd_issuer_tags(community_id, tag);";
    const TAG_OWNER: &str = "SELECT person FROM cpsd_issuer_tags WHERE tag = ?1";
    const MATCH: &str =
        "SELECT nonce FROM cpsd_challenges WHERE nonce = ?1 AND binding = ?2 AND expires >= ?3";
    const TAG: &str = "SELECT tag FROM cpsd_issuer_tags WHERE person = ?1";
    const REGISTER_TAG: &str = "INSERT INTO cpsd_issuer_tags (person, tag) VALUES (?1, ?2)";
    const LOOKUP: &str = "SELECT nonce FROM cpsd_challenges WHERE nonce = ?1";
    const COUNT: &str = "SELECT COUNT(*) FROM cpsd_challenges";
    const INSERT: &str =
        "INSERT INTO cpsd_challenges (nonce, binding, expires) VALUES (?1, ?2, ?3)";
    const CONSUME: &str =
        "DELETE FROM cpsd_challenges WHERE nonce = ?1 AND binding = ?2 AND expires >= ?3";
    const PRUNE: &str = "DELETE FROM cpsd_challenges WHERE expires < ?1";

    /// A fixed community capability using the official libSQL client via crlt.
    /// The caller owns database connections, migrations, credentials and routing.
    #[derive(Clone)]
    pub struct LibsqlStore {
        community: CommunityId,
        db: crlt::Community,
        capacity: usize,
    }

    impl LibsqlStore {
        /// Bind a database to the exact community bytes using reversible hex.
        /// Deploy one physical database per community; `cgbl` uses its own DB.
        pub fn new(db: &Db, community: CommunityId, capacity: usize) -> Result<Self, Error> {
            if capacity == 0 {
                return Err(Error::StorageCapacity);
            }
            let scoped = db
                .community(format!("cpsd/{}", crate::wire::hex(community.as_bytes())))
                .map_err(crate::error::redact(Error::Storage))?;
            Ok(Self {
                community,
                db: scoped,
                capacity,
            })
        }

        /// Check challenge query plans with real `EXPLAIN QUERY PLAN`.
        /// Community verifier databases need only SCHEMA.
        pub async fn check_indexes(&self) -> Result<(), Error> {
            let nonce = crlt::Value::Blob(vec![0u8; 32]);
            for (sql, args) in [
                (LOOKUP, vec![nonce.clone()]),
                (COUNT, vec![]),
                (
                    MATCH,
                    vec![nonce.clone(), nonce.clone(), crlt::Value::Integer(1)],
                ),
                (
                    INSERT,
                    vec![nonce.clone(), nonce.clone(), crlt::Value::Integer(1)],
                ),
                (CONSUME, vec![nonce.clone(), nonce, crlt::Value::Integer(1)]),
                (PRUNE, vec![crlt::Value::Integer(1)]),
            ] {
                self.db
                    .explain(sql, args)
                    .await
                    .and_then(|plan| plan.assert_indexed())
                    .map_err(crate::error::redact(Error::Storage))?;
            }
            Ok(())
        }
        /// Check global issuance query plans, including the challenge queries.
        /// Requires SCHEMA and ISSUANCE_SCHEMA in the global issuer database.
        pub async fn check_issuance_indexes(&self) -> Result<(), Error> {
            self.check_indexes().await?;
            let person = crlt::Value::Blob(vec![0; 32]);
            for (sql, args) in [
                (TAG, vec![person.clone()]),
                (TAG_OWNER, vec![crlt::Value::Blob(vec![0; 48])]),
                (REGISTER_TAG, vec![person, crlt::Value::Blob(vec![0; 48])]),
            ] {
                self.db
                    .explain(sql, args)
                    .await
                    .and_then(|plan| plan.assert_indexed())
                    .map_err(crate::error::redact(Error::Storage))?;
            }
            Ok(())
        }
    }

    impl ChallengeStore for LibsqlStore {
        fn community(&self) -> &CommunityId {
            &self.community
        }
        async fn reserve(&self, record: ChallengeRecord) -> Result<bool, Error> {
            check_timestamp(record.expires)?;
            let result = async {
                let mut tx = self.db.tx().await?;
                if !tx
                    .query(LOOKUP, params![record.nonce.to_vec()])
                    .await?
                    .is_empty()
                {
                    tx.rollback().await?;
                    return Ok(false);
                }
                let rows = tx.query(COUNT, ()).await?;
                let count = rows[0].get_i64(0)?;
                if !u64::try_from(count).is_ok_and(|count| count < self.capacity as u64) {
                    tx.rollback().await?;
                    return Err(crlt::Error::RowLimit);
                }
                tx.execute(
                    INSERT,
                    params![
                        record.nonce.to_vec(),
                        record.binding.to_vec(),
                        record.expires as i64
                    ],
                )
                .await?;
                tx.commit().await?;
                Ok::<_, crlt::Error>(true)
            }
            .await;
            result.map_err(|e| {
                if matches!(e, crlt::Error::RowLimit) {
                    Error::StorageCapacity
                } else {
                    Error::Storage
                }
            })
        }
        async fn matches(
            &self,
            nonce: [u8; 32],
            binding: [u8; 32],
            now: Timestamp,
        ) -> Result<bool, Error> {
            check_timestamp(now)?;
            self.db
                .query(MATCH, params![nonce.to_vec(), binding.to_vec(), now as i64])
                .await
                .map(|rows| !rows.is_empty())
                .map_err(crate::error::redact(Error::Storage))
        }
        async fn consume(
            &self,
            nonce: [u8; 32],
            binding: [u8; 32],
            now: Timestamp,
        ) -> Result<bool, Error> {
            check_timestamp(now)?;
            self.db
                .execute(
                    CONSUME,
                    params![nonce.to_vec(), binding.to_vec(), now as i64],
                )
                .await
                .map(|count| count == 1)
                .map_err(crate::error::redact(Error::Storage))
        }
        async fn prune(&self, now: Timestamp) -> Result<u64, Error> {
            check_timestamp(now)?;
            self.db
                .execute(PRUNE, params![now as i64])
                .await
                .map_err(crate::error::redact(Error::Storage))
        }
    }
    impl IssuanceStore for LibsqlStore {
        async fn consume_issuance(&self, issuance: VerifiedIssuance) -> Result<bool, Error> {
            let (nonce, binding, now, person, tag) = issuance.fields();
            check_timestamp(now)?;
            let mut tx = self
                .db
                .tx()
                .await
                .map_err(crate::error::redact(Error::Storage))?;
            if tx
                .query(MATCH, params![nonce.to_vec(), binding.to_vec(), now as i64])
                .await
                .map_err(crate::error::redact(Error::Storage))?
                .is_empty()
            {
                return finish_issuance_transaction(tx, 0).await;
            }
            let owners = tx
                .query(TAG_OWNER, params![tag.to_bytes().to_vec()])
                .await
                .map_err(crate::error::redact(Error::Storage))?;
            if let Some(owner) = owners.first()
                && owner
                    .get_value(0)
                    .map_err(crate::error::redact(Error::Storage))?
                    != &crlt::Value::Blob(person.to_vec())
            {
                return Err(Error::IssuerTagClaimed);
            }
            let rows = tx
                .query(TAG, params![person.to_vec()])
                .await
                .map_err(crate::error::redact(Error::Storage))?;
            if let Some(row) = rows.first() {
                if row
                    .get_value(0)
                    .map_err(crate::error::redact(Error::Storage))?
                    != &crlt::Value::Blob(tag.to_bytes().to_vec())
                {
                    tx.rollback()
                        .await
                        .map_err(crate::error::redact(Error::Storage))?;
                    return Err(Error::IssuerTagMismatch);
                }
            } else {
                tx.execute(
                    REGISTER_TAG,
                    params![person.to_vec(), tag.to_bytes().to_vec()],
                )
                .await
                .map_err(crate::error::redact(Error::Storage))?;
            }
            let consumed = tx
                .execute(
                    CONSUME,
                    params![nonce.to_vec(), binding.to_vec(), now as i64],
                )
                .await
                .map_err(crate::error::redact(Error::Storage))?;
            finish_issuance_transaction(tx, consumed).await
        }
    }

    pub(crate) async fn finish_issuance_transaction(
        tx: crlt::Transaction,
        consumed: u64,
    ) -> Result<bool, Error> {
        if consumed != 1 {
            tx.rollback()
                .await
                .map_err(crate::error::redact(Error::Storage))?;
            return Ok(false);
        }
        tx.commit()
            .await
            .map_err(crate::error::redact(Error::Storage))?;
        Ok(true)
    }
}

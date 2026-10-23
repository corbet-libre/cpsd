//! Real libSQL and in-memory tests of stamp issuance and the one-use ledger.

#![cfg(all(feature = "storage", not(target_arch = "wasm32")))]

use cpsd::{
    storage::libsql::{
        ISSUANCE_SCHEMA, ISSUANCE_UNIQUENESS_SCHEMA, LibsqlStore, SCHEMA, STAMP_ISSUANCE_SCHEMA,
    },
    *,
};
use crlt::{Config, Db, Migration};
use rand::{SeedableRng, rngs::StdRng};

/// 200 s into hour cohort 1000; the stamp expires at the end of cohort 1001.
const NOW: Timestamp = 3_600_200;
const EXPIRES: Timestamp = 3_607_200;
const EPOCH: u64 = 2;

fn scope(name: &str) -> CommunityId {
    CommunityId::new(name).unwrap()
}

fn all_migrations() -> [Migration<'static>; 4] {
    [
        Migration::new(1, "cpsd challenges", SCHEMA),
        Migration::new(2, "issuer continuity", ISSUANCE_SCHEMA),
        Migration::new(3, "unique issuer tags", ISSUANCE_UNIQUENESS_SCHEMA),
        Migration::new(4, "stamp issuer tags", STAMP_ISSUANCE_SCHEMA),
    ]
}

/// Opens another pool on the same file; every handle loads the migrations.
async fn reopen(url: &str, migrations: &[Migration<'_>]) -> Db {
    let db = Db::open(Config::new(url, "")).await.unwrap();
    db.migrate(migrations).await.unwrap();
    db
}

async fn database(migrations: &[Migration<'_>]) -> (tempfile::TempDir, Db, String) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("cpsd.db").display());
    let mut config = Config::new(url.clone(), "");
    config.max_connections = 4;
    let db = Db::open(config).await.unwrap();
    db.migrate(migrations).await.unwrap();
    (dir, db, url)
}

fn params() -> StampParams {
    StampParams::new(3_600).unwrap()
}

fn stamp_key(rng: &mut StdRng) -> StampIssuerKey {
    StampIssuerKey::generate(rng, KeyId::new("stamp").unwrap(), &params()).unwrap()
}

fn holder(seed: u8) -> OpaqueHolder {
    OpaqueHolder::from_seed(&mut [seed; 32])
}

fn approval(n: u8) -> (StampScope, StampAction) {
    (
        StampScope::new(
            scope(&format!("community-{n}")),
            CommunityFingerprint::from_bytes([n; 32]),
        ),
        StampAction::new(
            ActionKind::new("device.revoke").unwrap(),
            PayloadDigest::from_bytes([n; 32]),
            StampSalt::from_bytes([n; 32]),
        ),
    )
}

/// The wallet's context after it verified the user verification that covers
/// exactly this request and nonce.
fn confirmed(
    auth: &AuthenticatedStampIssuance,
    request: &StampIssuanceRequest,
    nonce: &IssuanceChallenge,
) -> AuthenticatedStampIssuance {
    auth.clone()
        .with_user_verification(request.confirmation_challenge(nonce))
}

async fn issue<S: StampIssuanceStore>(
    rng: &mut StdRng,
    store: &S,
    key: &StampIssuerKey,
    holder: &mut OpaqueHolder,
    auth: &AuthenticatedStampIssuance,
) -> Result<BlindStamp, Error> {
    let nonce = stamp_issuance_challenge(rng, store, key.public_key(), auth, NOW + 100).await?;
    holder.cancel_stamp();
    let request = holder.begin_stamp(rng, key.public_key(), &nonce, &[approval(9)], NOW)?;
    let auth = confirmed(auth, &request, &nonce);
    issue_stamp_once(rng, store, key, &auth, &request, &nonce, EPOCH, NOW).await
}

async fn registry_contract(store: impl StampIssuanceStore) {
    let mut rng = StdRng::seed_from_u64(31);
    let key = stamp_key(&mut rng);
    let mut alice = holder(1);
    let mut mallory = holder(2);
    let member = |id: u8, holder: &OpaqueHolder| {
        AuthenticatedStampIssuance::new([id; 32], [id; 32], holder.issuer_tag())
    };
    for _ in 0..2 {
        let auth = member(1, &alice);
        issue(&mut rng, &store, &key, &mut alice, &auth)
            .await
            .unwrap();
    }
    let auth = member(2, &alice);
    assert_eq!(
        issue(&mut rng, &store, &key, &mut alice, &auth).await.err(),
        Some(Error::IssuerTagClaimed)
    );
    let auth = member(1, &mallory);
    assert_eq!(
        issue(&mut rng, &store, &key, &mut mallory, &auth)
            .await
            .err(),
        Some(Error::IssuerTagMismatch)
    );
    let auth = member(3, &mallory);
    issue(&mut rng, &store, &key, &mut mallory, &auth)
        .await
        .unwrap();
}

#[tokio::test]
async fn stamp_tag_registry_has_the_same_contract_on_both_backends() {
    registry_contract(MemoryStore::new(scope("wallet"), 20).unwrap()).await;
    let (_dir, db, _) = database(&all_migrations()).await;
    let store = LibsqlStore::new(&db, scope("wallet"), 20).unwrap();
    registry_contract(store.clone()).await;
    store.check_stamp_issuance_indexes().await.unwrap();
    store.check_issuance_indexes().await.unwrap();
}

#[tokio::test]
async fn stamp_and_passport_registries_share_a_database_without_interfering() {
    let (_dir, db, _) = database(&all_migrations()).await;
    let store = LibsqlStore::new(&db, scope("wallet"), 20).unwrap();
    let mut rng = StdRng::seed_from_u64(32);
    let key = stamp_key(&mut rng);
    let passport = IssuerKey::generate(&mut rng, KeyId::new("passport").unwrap(), vec![]).unwrap();
    let mut alice = holder(1);
    // Stamps register member 1 -> alice's tag.
    let auth = AuthenticatedStampIssuance::new([1; 32], [1; 32], alice.issuer_tag());
    issue(&mut rng, &store, &key, &mut alice, &auth)
        .await
        .unwrap();
    // The passport registry still lets person 2 register alice's tag: the
    // stamp registry never blocks or registers passport tags.
    let person = AuthenticatedIssuance::new([2; 32], [2; 32]);
    let nonce = issuance_challenge(&mut rng, &store, passport.public_key(), &person, NOW)
        .await
        .unwrap();
    let request = alice
        .begin_issuance(&mut rng, passport.public_key(), &nonce)
        .unwrap();
    let blind = issue_blind_once(
        &mut rng,
        &store,
        &passport,
        &person,
        &request,
        &nonce,
        &PassportAttributes::new(NOW + 1000, 1),
        NOW,
    )
    .await
    .unwrap();
    alice.finish_issuance(&blind).unwrap();
    // And the stamp registry is unchanged by that passport registration.
    issue(&mut rng, &store, &key, &mut alice, &auth)
        .await
        .unwrap();
}

#[tokio::test]
async fn missing_stamp_registry_fails_closed_and_keeps_the_nonce() {
    let (_dir, db, _) = database(&[Migration::new(1, "cpsd challenges", SCHEMA)]).await;
    let store = LibsqlStore::new(&db, scope("wallet"), 10).unwrap();
    let mut rng = StdRng::seed_from_u64(33);
    let key = stamp_key(&mut rng);
    let mut holder = holder(5);
    let auth = AuthenticatedStampIssuance::new([5; 32], [6; 32], holder.issuer_tag());
    let nonce = stamp_issuance_challenge(&mut rng, &store, key.public_key(), &auth, NOW)
        .await
        .unwrap();
    let request = holder
        .begin_stamp(&mut rng, key.public_key(), &nonce, &[approval(1)], NOW)
        .unwrap();
    let auth = confirmed(&auth, &request, &nonce);
    macro_rules! once {
        () => {
            issue_stamp_once(&mut rng, &store, &key, &auth, &request, &nonce, EPOCH, NOW)
        };
    }
    assert_eq!(once!().await.err(), Some(Error::Storage));
    assert_eq!(
        store.check_stamp_issuance_indexes().await,
        Err(Error::Storage)
    );
    db.migrate(&[
        Migration::new(1, "cpsd challenges", SCHEMA),
        Migration::new(2, "stamp issuer tags", STAMP_ISSUANCE_SCHEMA),
    ])
    .await
    .unwrap();
    store.check_stamp_issuance_indexes().await.unwrap();
    holder
        .finish_stamp(&once!().await.unwrap(), EPOCH, NOW)
        .unwrap();
    assert!(holder.stamp_covers(&approval(1).0, &approval(1).1, NOW));
    assert_eq!(once!().await.err(), Some(Error::InvalidChallenge));
}

struct Presented {
    key: StampPublicKey,
    scope: StampScope,
    action: StampAction,
    presentation: StampPresentation,
}

fn presented(seed: u64) -> Presented {
    let mut rng = StdRng::seed_from_u64(seed);
    let key = stamp_key(&mut rng);
    let mut holder = holder(seed as u8);
    let scope = StampScope::new(
        scope("community"),
        CommunityFingerprint::from_bytes([3; 32]),
    );
    let action = StampAction::new(
        ActionKind::new("device.revoke").unwrap(),
        PayloadDigest::from_bytes([4; 32]),
        StampSalt::generate(&mut rng),
    );
    let nonce = IssuanceChallenge::generate(&mut rng);
    let request = holder
        .begin_stamp(
            &mut rng,
            key.public_key(),
            &nonce,
            &[(scope.clone(), action.clone())],
            NOW,
        )
        .unwrap();
    let blind = key
        .issue_blind(&mut rng, &request, &nonce, EPOCH, NOW)
        .unwrap();
    holder.finish_stamp(&blind, EPOCH, NOW).unwrap();
    let presentation = holder
        .present_stamp(&mut rng, &scope, &action, NOW)
        .unwrap();
    Presented {
        key: key.public_key().clone(),
        scope,
        action,
        presentation,
    }
}

#[tokio::test]
async fn ledger_refuses_replays_across_pools_and_after_reopen() {
    let p = presented(34);
    let migrations = [Migration::new(1, "community challenges", SCHEMA)];
    let (_dir, db, url) = database(&migrations).await;
    let ledger = |db: &Db| {
        StampLedger::new(
            LibsqlStore::new(db, scope("community"), 10).unwrap(),
            *p.scope.fingerprint(),
            vec![p.key.clone()],
            params(),
        )
        .unwrap()
    };
    let first = ledger(&db);
    let verified = first
        .accept(&p.action, &p.presentation, EPOCH, NOW)
        .await
        .unwrap();
    assert!(first.recorded(&verified, NOW).await.unwrap());
    let db2 = reopen(&url, &migrations).await;
    let second = ledger(&db2);
    assert_eq!(
        second
            .accept(&p.action, &p.presentation, EPOCH, NOW)
            .await
            .err(),
        Some(Error::StampReplayed)
    );
    drop((first, second, db, db2));
    let db = reopen(&url, &migrations).await;
    let reopened = ledger(&db);
    assert_eq!(
        reopened
            .accept(&p.action, &p.presentation, EPOCH, NOW + 1)
            .await
            .err(),
        Some(Error::StampReplayed)
    );
    assert!(reopened.release(&verified, NOW).await.unwrap());
    reopened
        .accept(&p.action, &p.presentation, EPOCH, NOW)
        .await
        .unwrap();
    // Records outlive their stamps by the prune margin, also in libSQL.
    assert_eq!(reopened.prune(EXPIRES + 1).await.unwrap(), 0);
    assert_eq!(
        reopened
            .prune(EXPIRES + STAMP_PRUNE_MARGIN_SECONDS)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        reopened
            .prune(EXPIRES + STAMP_PRUNE_MARGIN_SECONDS + 1)
            .await
            .unwrap(),
        1
    );
}

/// X2 M2 on libSQL: `Verifier::prune` of the shared community table keeps the
/// stamp prune margin, so a lagging node still refuses the replay.
#[tokio::test]
async fn verifier_prune_keeps_the_stamp_margin_in_the_shared_libsql_table() {
    let p = presented(36);
    let migrations = [Migration::new(1, "community challenges", SCHEMA)];
    let (_dir, db, _url) = database(&migrations).await;
    let ledger = StampLedger::new(
        LibsqlStore::new(&db, scope("community"), 10).unwrap(),
        *p.scope.fingerprint(),
        vec![p.key.clone()],
        params(),
    )
    .unwrap();
    let verifier = Verifier::new(
        LibsqlStore::new(&db, scope("community"), 10).unwrap(),
        vec![],
    )
    .unwrap();
    let verified = ledger
        .accept(&p.action, &p.presentation, EPOCH, NOW)
        .await
        .unwrap();
    assert_eq!(verifier.prune(EXPIRES + 1).await.unwrap(), 0);
    assert_eq!(
        ledger
            .accept(&p.action, &p.presentation, EPOCH, EXPIRES - 1)
            .await
            .err(),
        Some(Error::StampReplayed)
    );
    assert!(ledger.recorded(&verified, EXPIRES - 1).await.unwrap());
    assert_eq!(
        verifier
            .prune(EXPIRES + STAMP_PRUNE_MARGIN_SECONDS)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        verifier
            .prune(EXPIRES + STAMP_PRUNE_MARGIN_SECONDS + 1)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_records_of_one_digest_yield_exactly_one_success() {
    let p = std::sync::Arc::new(presented(35));
    let migrations = [Migration::new(1, "community challenges", SCHEMA)];
    let (_dir, db, url) = database(&migrations).await;
    let db2 = reopen(&url, &migrations).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut jobs = Vec::new();
    for db in [db, db2] {
        let p = p.clone();
        let barrier = barrier.clone();
        jobs.push(tokio::spawn(async move {
            let ledger = StampLedger::new(
                LibsqlStore::new(&db, scope("community"), 10).unwrap(),
                *p.scope.fingerprint(),
                vec![p.key.clone()],
                params(),
            )
            .unwrap();
            barrier.wait().await;
            ledger
                .accept(&p.action, &p.presentation, EPOCH, NOW)
                .await
                .map(|_| ())
        }));
    }
    let mut outcomes = Vec::new();
    for job in jobs {
        outcomes.push(job.await.unwrap());
    }
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
    assert!(outcomes.contains(&Err(Error::StampReplayed)));
}

async fn double_issuance_race<S: StampIssuanceStore + Clone + 'static>(a: S, b: S) {
    let mut rng = StdRng::seed_from_u64(36);
    let key = std::sync::Arc::new(stamp_key(&mut rng));
    let mut holder = holder(8);
    let auth = AuthenticatedStampIssuance::new([8; 32], [8; 32], holder.issuer_tag());
    let nonce = stamp_issuance_challenge(&mut rng, &a, key.public_key(), &auth, NOW)
        .await
        .unwrap();
    let request = holder
        .begin_stamp(&mut rng, key.public_key(), &nonce, &[approval(2)], NOW)
        .unwrap();
    let auth = confirmed(&auth, &request, &nonce);
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut jobs = Vec::new();
    for (i, store) in [a, b].into_iter().enumerate() {
        let (key, auth, request, barrier) =
            (key.clone(), auth.clone(), request.clone(), barrier.clone());
        jobs.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(i as u64);
            barrier.wait().await;
            issue_stamp_once(&mut rng, &store, &key, &auth, &request, &nonce, EPOCH, NOW)
                .await
                .map(|_| ())
        }));
    }
    let mut outcomes = Vec::new();
    for job in jobs {
        outcomes.push(job.await.unwrap());
    }
    // One signature is released; the other attempt finds the nonce spent,
    // before or after its own proof check.
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
    assert!(outcomes.contains(&Err(Error::InvalidChallenge)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_issuance_nonce_releases_one_stamp_under_races() {
    let memory = MemoryStore::new(scope("wallet"), 10).unwrap();
    double_issuance_race(memory.clone(), memory).await;
    let migrations = all_migrations();
    let (_dir, db, url) = database(&migrations).await;
    let db2 = reopen(&url, &migrations).await;
    double_issuance_race(
        LibsqlStore::new(&db, scope("wallet"), 10).unwrap(),
        LibsqlStore::new(&db2, scope("wallet"), 10).unwrap(),
    )
    .await;
}

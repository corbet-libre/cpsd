//! Real libSQL and in-memory session, concurrency and isolation tests.

#![cfg(all(feature = "storage", not(target_arch = "wasm32")))]

mod common;
use common::TestPresentation;

use cpsd::{
    storage::libsql::{ISSUANCE_SCHEMA, ISSUANCE_UNIQUENESS_SCHEMA, LibsqlStore, SCHEMA},
    *,
};
use crlt::{Config, Db, Migration};
use rand::{SeedableRng, rngs::StdRng};

fn scope(name: &str) -> CommunityId {
    CommunityId::new(name).unwrap()
}
fn record(n: u8, expires: Timestamp) -> ChallengeRecord {
    ChallengeRecord {
        nonce: [n; 32],
        binding: [n + 1; 32],
        expires,
    }
}
async fn database() -> (tempfile::TempDir, Db, String) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("cpsd.db").display());
    let mut config = Config::new(url.clone(), "");
    config.max_connections = 4;
    let db = Db::open(config).await.unwrap();
    assert_eq!(
        db.migrate(&[
            Migration::new(1, "cpsd challenges", SCHEMA),
            Migration::new(2, "issuer continuity", ISSUANCE_SCHEMA),
            Migration::new(3, "unique issuer tags", ISSUANCE_UNIQUENESS_SCHEMA)
        ])
        .await
        .unwrap(),
        3
    );
    assert_eq!(
        db.migrate(&[
            Migration::new(1, "cpsd challenges", SCHEMA),
            Migration::new(2, "issuer continuity", ISSUANCE_SCHEMA),
            Migration::new(3, "unique issuer tags", ISSUANCE_UNIQUENESS_SCHEMA)
        ])
        .await
        .unwrap(),
        0
    );
    (dir, db, url)
}

async fn contract(store: &impl ChallengeStore) {
    assert!(store.reserve(record(1, 10)).await.unwrap());
    assert!(!store.reserve(record(1, 20)).await.unwrap());
    assert!(store.matches([1; 32], [2; 32], 10).await.unwrap());
    assert!(!store.matches([1; 32], [2; 32], 11).await.unwrap());
    assert!(!store.matches([1; 32], [3; 32], 10).await.unwrap());
    assert!(!store.matches([2; 32], [2; 32], 10).await.unwrap());
    assert!(!store.consume([1; 32], [9; 32], 5).await.unwrap());
    assert!(!store.consume([1; 32], [2; 32], 11).await.unwrap());
    assert!(store.consume([1; 32], [2; 32], 10).await.unwrap());
    assert!(!store.consume([1; 32], [2; 32], 10).await.unwrap());
    assert!(store.reserve(record(2, 20)).await.unwrap());
    assert!(store.reserve(record(3, 30)).await.unwrap());
    assert_eq!(store.prune(20).await.unwrap(), 0);
    assert_eq!(store.prune(21).await.unwrap(), 1);
    assert_eq!(store.prune(31).await.unwrap(), 1);
    assert_eq!(store.prune(32).await.unwrap(), 0);
    assert_eq!(
        store.reserve(record(4, 0)).await,
        Err(Error::InvalidTimestamp)
    );
    assert_eq!(
        store.consume([4; 32], [5; 32], 0).await,
        Err(Error::InvalidTimestamp)
    );
    assert_eq!(store.prune(TIME_LIMIT).await, Err(Error::InvalidTimestamp));
}

#[tokio::test]
async fn memory_and_libsql_share_real_storage_semantics() {
    contract(&MemoryStore::new(scope("memory"), 10).unwrap()).await;
    let (_dir, db, _) = database().await;
    let store = LibsqlStore::new(&db, scope("libsql"), 10).unwrap();
    contract(&store).await;
    store.check_indexes().await.unwrap();
}

#[tokio::test]
async fn capacity_is_bounded_and_collisions_never_replace() {
    let (_dir, db, _) = database().await;
    async fn check(store: impl ChallengeStore) {
        assert!(store.reserve(record(1, 20)).await.unwrap());
        assert!(!store.reserve(record(1, 50)).await.unwrap());
        assert_eq!(
            store.reserve(record(2, 30)).await,
            Err(Error::StorageCapacity)
        );
        assert!(!store.consume([1; 32], [2; 32], 21).await.unwrap());
        store.prune(21).await.unwrap();
        assert!(store.reserve(record(2, 30)).await.unwrap());
    }
    check(MemoryStore::new(scope("mem"), 1).unwrap()).await;
    check(LibsqlStore::new(&db, scope("sql"), 1).unwrap()).await;
    assert!(MemoryStore::new(scope("bad"), 0).is_err());
    assert!(LibsqlStore::new(&db, scope("bad"), 0).is_err());
}

#[tokio::test]
async fn two_communities_cannot_consume_or_prune_each_others_rows() {
    let (_dir, db, _) = database().await;
    let a = LibsqlStore::new(&db, scope("a"), 10).unwrap();
    let b = LibsqlStore::new(&db, scope("b"), 10).unwrap();
    assert!(a.reserve(record(1, 10)).await.unwrap());
    assert!(!b.consume([1; 32], [2; 32], 5).await.unwrap());
    assert_eq!(b.prune(20).await.unwrap(), 0);
    assert!(b.reserve(record(1, 20)).await.unwrap());
    assert_eq!(a.prune(11).await.unwrap(), 1);
    assert!(b.consume([1; 32], [2; 32], 15).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_pools_race_without_double_consumption_or_capacity_overflow() {
    let (_dir, db, url) = database().await;
    let db2 = Db::open(Config::new(url, "")).await.unwrap();
    db2.migrate(&[
        Migration::new(1, "cpsd challenges", SCHEMA),
        Migration::new(2, "issuer continuity", ISSUANCE_SCHEMA),
        Migration::new(3, "unique issuer tags", ISSUANCE_UNIQUENESS_SCHEMA),
    ])
    .await
    .unwrap();
    let a = LibsqlStore::new(&db, scope("race"), 1).unwrap();
    let b = LibsqlStore::new(&db2, scope("race"), 1).unwrap();
    a.reserve(record(1, 100)).await.unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = Vec::new();
    for store in [a.clone(), b.clone()] {
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume([1; 32], [2; 32], 10).await
        }));
    }
    let x = tasks.remove(0).await.unwrap().unwrap();
    let y = tasks.remove(0).await.unwrap().unwrap();
    assert_eq!(usize::from(x) + usize::from(y), 1);
    let mut tasks = Vec::new();
    for (store, nonce) in [(a, 2), (b, 3)] {
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.reserve(record(nonce, 100)).await
        }));
    }
    let x = tasks.remove(0).await.unwrap();
    let y = tasks.remove(0).await.unwrap();
    assert_eq!(usize::from(x == Ok(true)) + usize::from(y == Ok(true)), 1);
    assert!(x == Err(Error::StorageCapacity) || y == Err(Error::StorageCapacity));
}

#[tokio::test]
async fn consumed_nonces_stay_rejected_after_database_reopen() {
    let (_dir, db, url) = database().await;
    let a = LibsqlStore::new(&db, scope("a"), 10).unwrap();
    a.reserve(record(1, 100)).await.unwrap();
    a.reserve(record(2, 100)).await.unwrap();
    a.consume([1; 32], [2; 32], 10).await.unwrap();
    drop(a);
    drop(db);
    let db = Db::open(Config::new(url, "")).await.unwrap();
    db.migrate(&[
        Migration::new(1, "cpsd challenges", SCHEMA),
        Migration::new(2, "issuer continuity", ISSUANCE_SCHEMA),
        Migration::new(3, "unique issuer tags", ISSUANCE_UNIQUENESS_SCHEMA),
    ])
    .await
    .unwrap();
    let b = LibsqlStore::new(&db, scope("a"), 10).unwrap();
    assert!(!b.consume([1; 32], [2; 32], 10).await.unwrap());
    assert!(b.consume([2; 32], [3; 32], 10).await.unwrap());
}

#[tokio::test]
async fn unavailable_schema_fails_closed_without_leaking_database_errors() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(Config::new(
        format!("file://{}", dir.path().join("unmigrated.db").display()),
        "",
    ))
    .await
    .unwrap();
    let store = LibsqlStore::new(&db, scope("private-scope"), 10).unwrap();
    assert_eq!(store.reserve(record(1, 100)).await, Err(Error::Storage));
    assert_eq!(
        store.consume([1; 32], [2; 32], 10).await,
        Err(Error::Storage)
    );
    assert_eq!(Error::Storage.to_string(), "challenge storage failed");
}

async fn end_to_end(
    issuer_store: impl IssuanceStore,
    verifier_store: impl ChallengeStore + Clone,
    shared_epoch: bool,
) {
    let mut rng = StdRng::seed_from_u64(101);
    let gate = GateId::new("phone").unwrap();
    let issuer = IssuerKey::generate(
        &mut rng,
        KeyId::new("shared-key").unwrap(),
        vec![gate.clone()],
    )
    .unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let authenticated = AuthenticatedIssuance::new([1; 32], [2; 32]);
    let challenge = issuance_challenge(
        &mut rng,
        &issuer_store,
        issuer.public_key(),
        &authenticated,
        100,
    )
    .await
    .unwrap();
    let (request, pending) =
        request_issue(&mut rng, &secret, issuer.public_key(), &challenge).unwrap();
    let attrs = PassportAttributes::new(300, 1).with_gate(gate.clone(), 300);
    let blind = issue_blind_once(
        &mut rng,
        &issuer_store,
        &issuer,
        &authenticated,
        &request,
        &challenge,
        &attrs,
        90,
    )
    .await
    .unwrap();
    assert!(matches!(
        issue_blind_once(
            &mut rng,
            &issuer_store,
            &issuer,
            &authenticated,
            &request,
            &challenge,
            &attrs,
            90
        )
        .await,
        Err(Error::InvalidChallenge)
    ));
    let passport = pending.finish(&blind).unwrap();
    let verifier =
        Verifier::new(verifier_store.clone(), vec![issuer.public_key().clone()]).unwrap();
    let challenge = if shared_epoch {
        verifier
            .request_for_epoch(&mut rng, 1, [gate], 200, 300)
            .await
            .unwrap()
    } else {
        verifier.request(&mut rng, 1, [gate], 200).await.unwrap()
    };
    let proof = passport.present_trusted(&mut rng, &challenge).unwrap();
    assert_eq!(
        verifier.verify(&mut rng, &challenge, &proof, 2, 190).await,
        Err(Error::WrongEpoch)
    );
    assert_eq!(
        verifier.verify(&mut rng, &challenge, &proof, 1, 201).await,
        Err(Error::InvalidChallenge)
    );

    // A holder can generate a valid proof for a tampered request but cannot
    // substitute that request for the one whose digest the verifier stored.
    let tampered = PresentationRequest::with_challenge(
        challenge.community().clone(),
        1,
        [],
        200,
        challenge.challenge(),
    )
    .unwrap();
    let other = passport.present_trusted(&mut rng, &tampered).unwrap();
    assert_eq!(
        verifier.verify(&mut rng, &tampered, &other, 1, 190).await,
        Err(Error::InvalidChallenge)
    );
    assert!(
        verifier
            .verify(&mut rng, &challenge, &other, 1, 190)
            .await
            .is_err()
    );
    let mut rng_b = StdRng::seed_from_u64(202);
    let other_verifier = Verifier::new(verifier_store, vec![issuer.public_key().clone()]).unwrap();
    let (a, b) = tokio::join!(
        verifier.verify(&mut rng, &challenge, &proof, 1, 190),
        other_verifier.verify(&mut rng_b, &challenge, &proof, 1, 190)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        verifier.verify(&mut rng, &challenge, &proof, 1, 190).await,
        Err(Error::InvalidChallenge)
    );
    let unregistered =
        PresentationRequest::new(&mut rng, challenge.community().clone(), 1, [], 200).unwrap();
    let proof = passport.present_trusted(&mut rng, &unregistered).unwrap();
    assert_eq!(
        verifier
            .verify(&mut rng, &unregistered, &proof, 1, 190)
            .await,
        Err(Error::InvalidChallenge)
    );
}

#[tokio::test]
async fn real_crypto_sessions_reject_replays_with_both_backends() {
    for shared_epoch in [false, true] {
        end_to_end(
            MemoryStore::new(scope("issuer"), 10).unwrap(),
            MemoryStore::new(scope("community"), 10).unwrap(),
            shared_epoch,
        )
        .await;
        let (_dir, db, _) = database().await;
        end_to_end(
            LibsqlStore::new(&db, scope("issuer"), 10).unwrap(),
            LibsqlStore::new(&db, scope("community"), 10).unwrap(),
            shared_epoch,
        )
        .await;
    }
}

#[tokio::test]
async fn optional_real_turso_roundtrip() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        println!("SKIP real Turso: TURSO_URL and TURSO_TOKEN are not both set");
        return;
    };
    if url.is_empty() || token.is_empty() {
        println!("SKIP real Turso: empty configuration");
        return;
    }
    // The caller supplies a disposable test database. No credentials are printed.
    let db = Db::open(Config::new(url, token))
        .await
        .expect("open configured Turso database");
    db.migrate(&[
        Migration::new(1, "cpsd challenges", SCHEMA),
        Migration::new(2, "issuer continuity", ISSUANCE_SCHEMA),
        Migration::new(3, "unique issuer tags", ISSUANCE_UNIQUENESS_SCHEMA),
    ])
    .await
    .unwrap();
    let store = LibsqlStore::new(&db, scope("cpsd-integration"), 100).unwrap();
    contract(&store).await;
    store.check_indexes().await.unwrap();
}

async fn issuance_security(store: impl IssuanceStore + Clone) {
    let mut rng = StdRng::seed_from_u64(301);
    let issuer = IssuerKey::generate(&mut rng, KeyId::new("issuer").unwrap(), vec![]).unwrap();
    let foreign = IssuerKey::generate(&mut rng, KeyId::new("foreign").unwrap(), vec![]).unwrap();
    let auth = AuthenticatedIssuance::new([1; 32], [2; 32]);
    let secret = HolderSecret::generate(&mut rng);
    let attrs = PassportAttributes::new(300, 1);
    let nonce = issuance_challenge(&mut rng, &store, issuer.public_key(), &auth, 100)
        .await
        .unwrap();
    let (request, pending) = request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
    for wrong in [
        AuthenticatedIssuance::new([3; 32], [2; 32]),
        AuthenticatedIssuance::new([1; 32], [3; 32]),
    ] {
        assert!(matches!(
            issue_blind_once(
                &mut rng, &store, &issuer, &wrong, &request, &nonce, &attrs, 90
            )
            .await,
            Err(Error::InvalidChallenge)
        ));
    }
    // Expiry and issuer binding are rejected before the mismatched proof is used.
    assert!(matches!(
        issue_blind_once(
            &mut rng, &store, &issuer, &auth, &request, &nonce, &attrs, 101
        )
        .await,
        Err(Error::InvalidChallenge)
    ));
    let (other_request, _) =
        request_issue(&mut rng, &secret, foreign.public_key(), &nonce).unwrap();
    assert!(matches!(
        issue_blind_once(
            &mut rng,
            &store,
            &foreign,
            &auth,
            &other_request,
            &nonce,
            &attrs,
            90
        )
        .await,
        Err(Error::InvalidChallenge)
    ));
    // Invalid proofs cannot consume a challenge or register a tag.
    let another_nonce = IssuanceChallenge::generate(&mut rng);
    let malicious_secret = HolderSecret::generate(&mut rng);
    let (bad, _) = request_issue(
        &mut rng,
        &malicious_secret,
        issuer.public_key(),
        &another_nonce,
    )
    .unwrap();
    assert!(matches!(
        issue_blind_once(&mut rng, &store, &issuer, &auth, &bad, &nonce, &attrs, 90).await,
        Err(Error::InvalidIssuanceRequest)
    ));
    let answer = issue_blind_once(
        &mut rng, &store, &issuer, &auth, &request, &nonce, &attrs, 100,
    )
    .await
    .unwrap();
    let passport = pending.finish(&answer).unwrap();
    // The same holder cannot use a second person account to evade suspension.
    let second_person = AuthenticatedIssuance::new([99; 32], [98; 32]);
    let duplicate_nonce =
        issuance_challenge(&mut rng, &store, issuer.public_key(), &second_person, 150)
            .await
            .unwrap();
    let (duplicate, _) =
        request_issue(&mut rng, &secret, issuer.public_key(), &duplicate_nonce).unwrap();
    assert!(matches!(
        issue_blind_once(
            &mut rng,
            &store,
            &issuer,
            &second_person,
            &duplicate,
            &duplicate_nonce,
            &attrs,
            100
        )
        .await,
        Err(Error::IssuerTagClaimed)
    ));
    // Refusal burns neither nonce nor another holder's ability to claim that person.
    let independent_secret = HolderSecret::generate(&mut rng);
    let (independent, pending) = request_issue(
        &mut rng,
        &independent_secret,
        issuer.public_key(),
        &duplicate_nonce,
    )
    .unwrap();
    let independent = issue_blind_once(
        &mut rng,
        &store,
        &issuer,
        &second_person,
        &independent,
        &duplicate_nonce,
        &attrs,
        100,
    )
    .await
    .unwrap();
    pending.finish(&independent).unwrap();

    store.prune(200).await.unwrap();
    // New session and rotated issuer still require the same registered tag.
    let renewal_auth = AuthenticatedIssuance::new([1; 32], [4; 32]);
    let nonce = issuance_challenge(&mut rng, &store, foreign.public_key(), &renewal_auth, 200)
        .await
        .unwrap();
    let (bad, _) =
        request_issue(&mut rng, &malicious_secret, foreign.public_key(), &nonce).unwrap();
    assert!(matches!(
        issue_blind_once(
            &mut rng,
            &store,
            &foreign,
            &renewal_auth,
            &bad,
            &nonce,
            &attrs,
            190
        )
        .await,
        Err(Error::IssuerTagMismatch)
    ));
    let (good, pending) = request_issue(&mut rng, &secret, foreign.public_key(), &nonce).unwrap();
    let answer = issue_blind_once(
        &mut rng,
        &store,
        &foreign,
        &renewal_auth,
        &good,
        &nonce,
        &attrs,
        190,
    )
    .await
    .unwrap();
    assert_eq!(
        passport.pseudonym(&scope("community")),
        pending
            .finish(&answer)
            .unwrap()
            .pseudonym(&scope("community"))
    );
    // A different authenticated person has a separate immutable binding.
    let other_auth = AuthenticatedIssuance::new([2; 32], [4; 32]);
    let nonce = issuance_challenge(&mut rng, &store, issuer.public_key(), &other_auth, 200)
        .await
        .unwrap();
    let (request, pending) =
        request_issue(&mut rng, &malicious_secret, issuer.public_key(), &nonce).unwrap();
    let answer = issue_blind_once(
        &mut rng,
        &store,
        &issuer,
        &other_auth,
        &request,
        &nonce,
        &attrs,
        190,
    )
    .await
    .unwrap();
    pending.finish(&answer).unwrap();
}

#[tokio::test]
async fn issuance_binds_person_session_issuer_expiry_and_tag_on_both_backends() {
    issuance_security(MemoryStore::new(scope("global"), 20).unwrap()).await;
    let (_dir, db, _) = database().await;
    let store = LibsqlStore::new(&db, scope("global"), 20).unwrap();
    issuance_security(store.clone()).await;
    store.check_issuance_indexes().await.unwrap();
}

async fn race_first_registration<S: IssuanceStore + Clone + 'static>(a: S, b: S) {
    let mut rng = StdRng::seed_from_u64(404);
    let issuer = std::sync::Arc::new(
        IssuerKey::generate(&mut rng, KeyId::new("race").unwrap(), vec![]).unwrap(),
    );
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut jobs = Vec::new();
    let mut retry = Vec::new();
    for (i, store) in [a.clone(), b].into_iter().enumerate() {
        let auth = AuthenticatedIssuance::new([9; 32], [i as u8; 32]);
        let nonce = issuance_challenge(&mut rng, &store, issuer.public_key(), &auth, 100)
            .await
            .unwrap();
        let secret = HolderSecret::generate(&mut rng);
        let (request, pending) =
            request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
        retry.push((auth.clone(), nonce, secret));
        let issuer = issuer.clone();
        let barrier = barrier.clone();
        jobs.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(i as u64);
            barrier.wait().await;
            let result = issue_blind_once(
                &mut rng,
                &store,
                &issuer,
                &auth,
                &request,
                &nonce,
                &PassportAttributes::new(200, 1),
                90,
            )
            .await;
            result.map(|blind| pending.finish(&blind).unwrap())
        }));
    }
    let x = jobs.remove(0).await.unwrap();
    let y = jobs.remove(0).await.unwrap();
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    let (winner, loser) = if x.is_ok() { (0, 1) } else { (1, 0) };
    assert!(matches!(
        if loser == 0 { &x } else { &y },
        Err(Error::IssuerTagMismatch)
    ));
    // Failed registration must leave the losing nonce available. Answer it with
    // the winner's secret; this also checks the winning tag wasn't overwritten.
    let (auth, nonce, _) = &retry[loser];
    let (request, pending) =
        request_issue(&mut rng, &retry[winner].2, issuer.public_key(), nonce).unwrap();
    let answer = issue_blind_once(
        &mut rng,
        &a,
        &issuer,
        auth,
        &request,
        nonce,
        &PassportAttributes::new(200, 1),
        90,
    )
    .await
    .unwrap();
    pending.finish(&answer).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_first_tags_are_atomic_across_clones_and_independent_pools() {
    let memory = MemoryStore::new(scope("global"), 20).unwrap();
    race_first_registration(memory.clone(), memory).await;
    let (_dir, db, url) = database().await;
    let db2 = Db::open(Config::new(url, "")).await.unwrap();
    db2.migrate(&[
        Migration::new(1, "cpsd challenges", SCHEMA),
        Migration::new(2, "issuer continuity", ISSUANCE_SCHEMA),
        Migration::new(3, "unique issuer tags", ISSUANCE_UNIQUENESS_SCHEMA),
    ])
    .await
    .unwrap();
    race_first_registration(
        LibsqlStore::new(&db, scope("global"), 20).unwrap(),
        LibsqlStore::new(&db2, scope("global"), 20).unwrap(),
    )
    .await;
}

#[tokio::test]
async fn nonce_preflight_rejects_before_pairing_and_does_not_consume() {
    // A valid proof for an unknown issuer would yield UnknownKey without the
    // preflight; absent/spent/mismatched nonces must return InvalidChallenge.
    let store = MemoryStore::new(scope("community"), 10).unwrap();
    let mut rng = StdRng::seed_from_u64(501);
    let issuer = IssuerKey::generate(&mut rng, KeyId::new("a").unwrap(), vec![]).unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let nonce = IssuanceChallenge::generate(&mut rng);
    let (request, pending) = request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
    let blind = issuer
        .issue_blind(&mut rng, &request, &nonce, &PassportAttributes::new(300, 1))
        .unwrap();
    let passport = pending.finish(&blind).unwrap();
    let verifier = Verifier::new(store, vec![]).unwrap();
    let missing =
        PresentationRequest::for_epoch(&mut rng, scope("community"), 1, [], 200, 300).unwrap();
    let proof = passport.present_trusted(&mut rng, &missing).unwrap();
    assert_eq!(
        verifier.verify(&mut rng, &missing, &proof, 1, 190).await,
        Err(Error::InvalidChallenge)
    );
    let registered = verifier
        .request_for_epoch(&mut rng, 1, [], 200, 300)
        .await
        .unwrap();
    let proof = passport.present_trusted(&mut rng, &registered).unwrap();
    for _ in 0..2 {
        assert_eq!(
            verifier.verify(&mut rng, &registered, &proof, 1, 190).await,
            Err(Error::UnknownKey)
        );
    }
}

#[tokio::test]
async fn tag_registration_rolls_back_on_consume_failure_and_survives_reopen() {
    let (_dir, db, url) = database().await;
    let migrations = [
        Migration::new(1, "cpsd challenges", SCHEMA),
        Migration::new(2, "issuer continuity", ISSUANCE_SCHEMA),
        Migration::new(3, "unique issuer tags", ISSUANCE_UNIQUENESS_SCHEMA),
        Migration::new(
            4,
            "inject real database failure",
            "CREATE TABLE cpsd_test_blocker (
            community_id TEXT NOT NULL, nonce BLOB NOT NULL,
            PRIMARY KEY (community_id, nonce),
            FOREIGN KEY (community_id, nonce) REFERENCES cpsd_challenges (community_id, nonce) ON DELETE RESTRICT
        ) WITHOUT ROWID;",
        ),
    ];
    db.migrate(&migrations).await.unwrap();
    let store = LibsqlStore::new(&db, scope("global"), 10).unwrap();
    let mut rng = StdRng::seed_from_u64(601);
    let issuer = IssuerKey::generate(&mut rng, KeyId::new("a").unwrap(), vec![]).unwrap();
    let auth = AuthenticatedIssuance::new([7; 32], [8; 32]);
    let secret = HolderSecret::generate(&mut rng);
    let nonce = issuance_challenge(&mut rng, &store, issuer.public_key(), &auth, 100)
        .await
        .unwrap();
    let scoped = db.community("cpsd/676c6f62616c").unwrap(); // hex("global")
    scoped
        .execute(
            "INSERT INTO cpsd_test_blocker (nonce) VALUES (?1)",
            crlt::params![nonce.to_bytes().to_vec()],
        )
        .await
        .unwrap();
    let (request, _) = request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
    let attrs = PassportAttributes::new(300, 1);
    assert!(matches!(
        issue_blind_once(
            &mut rng, &store, &issuer, &auth, &request, &nonce, &attrs, 90
        )
        .await,
        Err(Error::Storage)
    ));
    scoped
        .execute(
            "DELETE FROM cpsd_test_blocker WHERE nonce = ?1",
            crlt::params![nonce.to_bytes().to_vec()],
        )
        .await
        .unwrap();
    drop(scoped);
    let other_secret = HolderSecret::generate(&mut rng);
    let (other_request, pending) =
        request_issue(&mut rng, &other_secret, issuer.public_key(), &nonce).unwrap();
    // Same nonce, different tag succeeds: neither tag nor nonce escaped rollback.
    let answer = issue_blind_once(
        &mut rng,
        &store,
        &issuer,
        &auth,
        &other_request,
        &nonce,
        &attrs,
        90,
    )
    .await
    .unwrap();
    pending.finish(&answer).unwrap();
    drop(store);
    drop(db);
    let db = Db::open(Config::new(url, "")).await.unwrap();
    db.migrate(&migrations).await.unwrap();
    let store = LibsqlStore::new(&db, scope("global"), 10).unwrap();
    let nonce = issuance_challenge(&mut rng, &store, issuer.public_key(), &auth, 100)
        .await
        .unwrap();
    let (request, _) = request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
    assert!(matches!(
        issue_blind_once(
            &mut rng, &store, &issuer, &auth, &request, &nonce, &attrs, 90
        )
        .await,
        Err(Error::IssuerTagMismatch)
    ));
    let other_scope = LibsqlStore::new(&db, scope("separate-global-deployment"), 10).unwrap();
    let nonce = issuance_challenge(&mut rng, &other_scope, issuer.public_key(), &auth, 100)
        .await
        .unwrap();
    let (request, pending) = request_issue(&mut rng, &secret, issuer.public_key(), &nonce).unwrap();
    let answer = issue_blind_once(
        &mut rng,
        &other_scope,
        &issuer,
        &auth,
        &request,
        &nonce,
        &attrs,
        90,
    )
    .await
    .unwrap();
    pending.finish(&answer).unwrap();
    store.check_indexes().await.unwrap();
}

#[tokio::test]
async fn community_verifier_database_requires_no_global_person_registry() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(Config::new(
        format!("file://{}", directory.path().join("community.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[Migration::new(1, "community challenges", SCHEMA)])
        .await
        .unwrap();
    let store = LibsqlStore::new(&db, scope("community"), 10).unwrap();
    contract(&store).await;
    store.check_indexes().await.unwrap();
    assert_eq!(store.check_issuance_indexes().await, Err(Error::Storage));
}

#[tokio::test]
async fn index_verification_fails_closed_without_migrations() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(Config::new(
        format!("file://{}", directory.path().join("bare.db").display()),
        "",
    ))
    .await
    .unwrap();
    let store = LibsqlStore::new(&db, scope("bare"), 10).unwrap();
    assert_eq!(store.check_indexes().await, Err(Error::Storage));
}

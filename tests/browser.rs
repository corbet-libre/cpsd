//! Real browser cryptographic round trips and performance measurements.

#![cfg(target_arch = "wasm32")]

mod common;
use common::TestPresentation;

use cpsd::*;
use rand::{
    SeedableRng,
    rngs::{OsRng, StdRng},
};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn browser_roundtrip_and_performance() {
    let clock = web_sys::window().unwrap().performance().unwrap();
    let mut rng = StdRng::from_rng(OsRng).unwrap();
    let gates: Vec<_> = ["phone", "human", "government-id"]
        .into_iter()
        .map(|g| GateId::new(g).unwrap())
        .collect();
    let issuer = IssuerKey::generate(
        &mut rng,
        KeyId::new("browser-shared").unwrap(),
        gates.clone(),
    )
    .unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, pending) =
        request_issue(&mut rng, &secret, issuer.public_key(), &challenge).unwrap();
    let request = IssuanceRequest::from_bytes(&request.to_bytes()).unwrap();
    let mut attrs = PassportAttributes::new(1900, 1);
    for gate in &gates {
        attrs = attrs.with_gate(gate.clone(), 1900);
    }
    let blind = issuer
        .issue_blind(&mut rng, &request, &challenge, &attrs)
        .unwrap();
    let passport = pending
        .finish(&BlindPassport::from_bytes(&blind.to_bytes()).unwrap())
        .unwrap();
    for shared_epoch in [false, true] {
        for gate_count in [0, 1, 3] {
            let request = PresentationRequest::new(
                &mut rng,
                CommunityId::new(b"browser-community").unwrap(),
                1,
                gates[..gate_count].to_vec(),
                1000,
            )
            .unwrap();
            let request = if shared_epoch {
                request.with_epoch_expiry(1900).unwrap()
            } else {
                request
            };
            let mut proving = Vec::new();
            let mut verifying = Vec::new();
            let mut size = 0;
            for _ in 0..5 {
                let start = clock.now();
                let proof = passport.present_trusted(&mut rng, &request).unwrap();
                proving.push(clock.now() - start);
                let bytes = proof.to_bytes();
                size = bytes.len();
                let proof = Presentation::from_bytes(&bytes).unwrap();
                let start = clock.now();
                let nym =
                    verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap();
                verifying.push(clock.now() - start);
                assert_eq!(nym, passport.pseudonym(request.community()));
                let wrong = PresentationRequest::new(
                    &mut rng,
                    request.community().clone(),
                    1,
                    gates[..gate_count].to_vec(),
                    1000,
                )
                .unwrap();
                let wrong = if shared_epoch {
                    wrong.with_epoch_expiry(1900).unwrap()
                } else {
                    wrong
                };
                assert!(verify(&mut rng, &[issuer.public_key().clone()], &wrong, &proof).is_err());
            }
            let first = proving[0];
            proving.sort_by(f64::total_cmp);
            verifying.sort_by(f64::total_cmp);
            console_log!(
                "browser shared_epoch={shared_epoch}, gates={gate_count}, first_present_ms={first:.1}, median_present_ms={:.1}, median_verify_ms={:.1}, bytes={size}",
                proving[2],
                verifying[2]
            );
            if shared_epoch {
                assert!(
                    proving[2] < 1000.0,
                    "browser proof exceeded 1s median: {}ms",
                    proving[2]
                );
            }
        }
    }
}

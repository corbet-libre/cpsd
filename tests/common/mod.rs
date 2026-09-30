//! Synthetic signing context for real cryptographic tests only.
use cpsd::*;

pub fn signer(seed: u8) -> csgn::Signer {
    csgn::Signer::new(
        "cmnt:test",
        csgn::SecretKey::from_seed(&mut [seed; 32]),
        0,
        TIME_LIMIT,
    )
    .unwrap()
}

pub fn signed(signer: &mut csgn::Signer, request: &PresentationRequest) -> Vec<u8> {
    signer
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            0,
            request.now() + 1,
        )
        .unwrap()
}

pub trait TestPresentation {
    fn present_trusted<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        request: &PresentationRequest,
    ) -> Result<Presentation, Error>;
}
impl TestPresentation for Passport {
    fn present_trusted<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        request: &PresentationRequest,
    ) -> Result<Presentation, Error> {
        let mut signer = signer(42);
        let cose = signed(&mut signer, request);
        let expected = AuthenticatedCommunity::from_authenticated_origin(
            request.community().clone(),
            signer.key_ring().clone(),
        );
        self.present(rng, &expected, &cose, request.now())
    }
}

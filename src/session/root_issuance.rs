//! Root issuance with the source verifier's independently installed full ring.
use super::*;

impl<S: ChallengeStore> Verifier<S> {
    /// Verify the original root-store nonce and same-holder proof with THIS
    /// source verifier's configured global keys. Neither the request nor the
    /// root issuer supplies a replacement ring. The caller must still acquire
    /// and retain actual source role authority through consumption and release.
    pub async fn verify_root_board_issuance<T: ChallengeStore>(
        &self,
        root_store: &T,
        context: &RootBoardIssuanceContext,
        request: &RootBoardIssuanceRequest,
        now: Timestamp,
    ) -> Result<VerifiedRootBoardIssuance, Error> {
        if context.source_request().community() != self.store.community() {
            return Err(Error::InvalidChallenge);
        }
        verify_stored_root_board_issuance(root_store, &self.keys, context, request, now).await
    }
}

//! Unauthenticated fallback: AuthFetch.ts:680-705.

use super::{
    auth_fetch::{AuthFetch, AuthFetchOptions},
    response::words,
    state::PeerState,
    Response,
};
use crate::{auth::Transport, wallet::WalletInterface, Result};

impl<W: WalletInterface + 'static, T: Transport + 'static> AuthFetch<W, T> {
    #[cfg(feature = "http")]
    pub(super) async fn fallback(
        &self,
        url: &str,
        options: &AuthFetchOptions,
        state: &PeerState<W, T>,
    ) -> Result<Response> {
        let response = crate::auth::transports::fetch_client::fetch(
            &self.http_client,
            url,
            options,
            self.max_response_bytes,
        )
        .await?;
        if response
            .headers
            .keys()
            .any(|name| name.starts_with("x-bsv"))
        {
            return Err(words(
                "The server is trying to claim it has been authenticated when it has not!",
            ));
        }
        if !response.ok() {
            return Err(words(&format!(
                "Request failed with status: {}",
                response.status
            )));
        }
        *state.mutual.write().await = Some(false);
        Ok(response)
    }

    #[cfg(not(feature = "http"))]
    pub(super) async fn fallback(
        &self,
        _url: &str,
        _options: &AuthFetchOptions,
        _state: &PeerState<W, T>,
    ) -> Result<Response> {
        Err(words("HTTP feature not enabled"))
    }
}

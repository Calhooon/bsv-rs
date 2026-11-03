//! The transport's HTTP client and its redirect refusal (bsv-rs#320).
//!
//! The reference's constructor takes a caller's fetch (`fetchClient: typeof
//! fetch = defaultFetch`, `ts-stack@edf6e03`
//! `packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:64-67`) and
//! both of its fetches set `redirect: 'error'` (`:128`, `:212`): a redirect is
//! a thrown fetch, read as `Network error while sending authenticated request
//! to {url}` (`:453-462`), never a followed hop. This crate takes a caller's
//! `reqwest::Client` in [`SimplifiedFetchTransport::with_client`] and refuses
//! every answer with a redirect status on both paths, whatever the client.

use std::sync::Arc;
use std::sync::RwLock as StdRwLock;

use reqwest::Response;

use super::SimplifiedFetchTransport;
use crate::{Error, Result};

/// The request timeout of the client [`SimplifiedFetchTransport::new`]
/// builds: 30 s, the bound on the cosigner hang of [`default_client`]
/// (pinned by this file's tests, #676).
pub(super) const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The client [`SimplifiedFetchTransport::new`] builds, its request timeout
/// [`REQUEST_TIMEOUT`].
///
/// Egress-NAT'd hosts (e.g. Cloudflare Containers) silently drop idle
/// keep-alive sockets. reqwest's default pool then reuses a half-dead
/// connection and the next request HANGS INDEFINITELY — `Client::new()` sets
/// no timeout, so there is nothing to break the hang. This wedged the BRC-104
/// General POST (`/sendMessage`) from the deployed MPC cosigner. Bound every
/// request (overall + connect) and disable idle-socket reuse so a dropped
/// keep-alive forces a fresh connection instead of a hang. Redirects are not
/// followed (#320): a hop would replay the signed request to another host.
pub(super) fn default_client() -> reqwest::Client {
    default_client_with(REQUEST_TIMEOUT)
}

/// [`default_client`] with a request timeout of `timeout`, the seam its
/// tests read the timeout through without waiting 30 s.
pub(super) fn default_client_with(timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

impl SimplifiedFetchTransport {
    /// Creates an HTTP transport that sends every request through `client`,
    /// the reference's `fetchClient` parameter (bsv-rs#320).
    ///
    /// The client is used as given: its timeouts, pool, proxy, resolution
    /// and redirect policy are the caller's. [`SimplifiedFetchTransport::new`]
    /// builds one with a 30 s request timeout (`REQUEST_TIMEOUT`) and a 10 s
    /// connect timeout, no idle connection reuse and no redirect followed.
    /// Whatever the client, an answer with a redirect status (301, 302, 303,
    /// 307, 308) is refused as [`Error::AuthError`] on the handshake and the
    /// general path alike, as the reference's `redirect: 'error'` refuses it;
    /// a client that follows redirects itself has followed them before the
    /// transport sees the answer, so a caller who supplies one supplies its
    /// policy too (`reqwest::redirect::Policy::none()` keeps the default's).
    ///
    /// # Arguments
    /// * `base_url` - Base URL of the remote server (e.g., `https://example.com`)
    /// * `client` - The client every request of this transport goes through
    pub fn with_client(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            limits: super::body::ResponseLimits::default(),
            callback: Arc::new(StdRwLock::new(None)),
        }
    }
}

/// Refuses an answer with a redirect status, the fetch standard's 301, 302,
/// 303, 307 and 308, in Node 22's outer wrapper words for its thrown fetch
/// (#410). The reference retains `TypeError: fetch failed` with a cause of
/// `Error: unexpected redirect`; `AuthError` has no JS cause/stack chain. The far
/// side answered, so it is the named host's answer (`AuthError`), never a
/// [`crate::TransportFault`]: the request was received, and nothing of it
/// went anywhere else.
pub(super) fn refuse_redirect(url: &str, response: &Response) -> Result<()> {
    let status = response.status();
    if !matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
        return Ok(());
    }
    Err(Error::AuthError(format!(
        "Network error while sending authenticated request to {}: fetch failed",
        url
    )))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    // reqwest has no getter for a client's timeout, and its `Debug` names the
    // field by `type_name`, which Rust does not promise to keep: the pins are
    // the constant, the construction path (the default's `Debug` that of the
    // seam at the constant, never `Client::new()`'s) and the seam's timeout
    // read on the wire.
    #[test]
    fn the_default_client_times_a_request_out_at_thirty_seconds() {
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(30));
        let default = format!("{:?}", default_client());
        assert_eq!(
            default,
            format!("{:?}", default_client_with(REQUEST_TIMEOUT))
        );
        assert!(default.contains("30s"), "{default}");
        assert_ne!(default, format!("{:?}", reqwest::Client::new()));
    }

    #[tokio::test]
    async fn the_default_clients_timeout_ends_a_request_the_far_side_never_answers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let err = default_client_with(Duration::from_secs(1))
            .post(server.uri())
            .send()
            .await
            .unwrap_err();
        assert!(err.is_timeout(), "{err:?}");
    }
}

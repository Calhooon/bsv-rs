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

/// The client [`SimplifiedFetchTransport::new`] builds.
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
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
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
    /// builds one with a 30 s request and 10 s connect timeout, no idle
    /// connection reuse and no redirect followed. Whatever the client, an
    /// answer with a redirect status (301, 302, 303, 307, 308) is refused as
    /// [`Error::AuthError`] on the handshake and the general path alike, as
    /// the reference's `redirect: 'error'` refuses it; a client that follows
    /// redirects itself has followed them before the transport sees the
    /// answer, so a caller who supplies one supplies its policy too
    /// (`reqwest::redirect::Policy::none()` keeps the default's).
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

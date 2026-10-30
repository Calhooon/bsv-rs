//! Native HTTP adapter for `AuthFetch`'s unauthenticated fallback (#423).

use crate::auth::clients::{AuthFetchOptions, Response};
use crate::{Error, Result};
use indexmap::IndexMap;

/// A caller-supplied native HTTP client, also accepted by `SimplifiedFetchTransport`.
#[cfg(feature = "http")]
pub type NativeFetchClient = reqwest::Client;

pub(crate) fn default_client() -> NativeFetchClient {
    NativeFetchClient::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| NativeFetchClient::new())
}

pub(crate) async fn fetch(
    client: &NativeFetchClient,
    url: &str,
    options: &AuthFetchOptions,
    max_response_bytes: usize,
) -> Result<Response> {
    let method = reqwest::Method::from_bytes(options.method.as_deref().unwrap_or("GET").as_bytes())
        .map_err(|_| Error::AuthError("Invalid HTTP method".into()))?;
    let mut request = client.request(method, url);
    for (name, value) in &options.headers {
        request = request.header(name, value);
    }
    if let Some(body) = &options.body {
        request = request.body(body.clone());
    }
    let response = request
        .send()
        .await
        .map_err(|_| Error::AuthError("fetch failed".into()))?;
    if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        return Err(Error::AuthError("fetch failed".into()));
    }
    let status = response.status().as_u16();
    let mut headers: IndexMap<String, String> = IndexMap::new();
    for (name, value) in response.headers() {
        let value: String = value
            .as_bytes()
            .iter()
            .map(|byte| char::from(*byte))
            .collect();
        headers
            .entry(name.to_string())
            .and_modify(|previous| {
                previous.push_str(", ");
                previous.push_str(&value);
            })
            .or_insert(value);
    }
    headers.sort_keys();
    let body = read_body(response, url, max_response_bytes).await?;
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// The reference's plain-fetch fallback has no body cap. This native safeguard
/// checks Content-Length and each chunk before extending the owned buffer.
async fn read_body(mut response: reqwest::Response, url: &str, maximum: usize) -> Result<Vec<u8>> {
    let oversized = || {
        Error::AuthError(format!(
            "Unauthenticated response from {url} exceeds {maximum} bytes"
        ))
    };
    if response
        .content_length()
        .is_some_and(|size| size > maximum as u64)
    {
        return Err(oversized());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error::AuthError("fetch failed".into()))?
    {
        if chunk.len() > maximum.saturating_sub(body.len()) {
            return Err(oversized());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

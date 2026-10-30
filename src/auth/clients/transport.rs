//! The reference transport's body checks at its send boundary, for client use.

use super::response::words;
use crate::auth::transports::{HttpRequest, TransportCallback};
use crate::auth::{AuthMessage, MessageType, Transport};
use crate::Result;

pub(super) struct FetchTransport<T> {
    inner: T,
    max_payload_bytes: usize,
}

// AuthFetch.ts:355-364 keeps room for a request or a response plus its framing.
fn payload_limit(response_limit: usize) -> usize {
    response_limit
        .saturating_add(super::response::OVERHEAD)
        .min(usize::try_from(super::response::MAX_SAFE_INTEGER).unwrap_or(usize::MAX))
        .max(16 * 1024 * 1024)
}

pub(super) fn validate_payload(length: usize, response_limit: usize) -> Result<()> {
    let maximum = payload_limit(response_limit);
    if length > maximum {
        return Err(words(&format!(
            "general.payload must be a dense byte array of at most {maximum} bytes."
        )));
    }
    Ok(())
}

impl<T> FetchTransport<T> {
    pub(super) fn new(inner: T, response_limit: usize) -> Self {
        Self {
            inner,
            max_payload_bytes: payload_limit(response_limit),
        }
    }
}

#[async_trait::async_trait]
impl<T: Transport> Transport for FetchTransport<T> {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        if message.message_type == MessageType::General {
            if let Some(payload) = &message.payload {
                let request = HttpRequest::from_payload(payload)?;
                if !request.body.is_empty() {
                    let content_type = request
                        .headers
                        .iter()
                        .find(|(name, _)| name == "content-type")
                        .map(|(_, value)| value.as_str())
                        .ok_or_else(|| {
                            words("Content-Type header is required for requests with a body.")
                        })?;
                    if [
                        "application/json",
                        "application/x-www-form-urlencoded",
                        "text/plain",
                    ]
                    .iter()
                    .any(|kind| content_type.contains(kind))
                    {
                        std::str::from_utf8(&request.body).map_err(|_| {
                            words("The encoded data was not valid for encoding utf-8")
                        })?;
                    }
                }
            }
        }
        self.inner.send(message).await
    }
    fn set_callback(&self, callback: Box<TransportCallback>) {
        let maximum = self.max_payload_bytes;
        self.inner.set_callback(Box::new(move |message| {
            if message.message_type == MessageType::General
                && message
                    .payload
                    .as_ref()
                    .is_some_and(|payload| payload.len() > maximum)
            {
                return Box::pin(async {
                    Err(words("Authentication message array exceeds its limit."))
                });
            }
            callback(message)
        }));
    }
    fn clear_callback(&self) {
        self.inner.clear_callback();
    }
}

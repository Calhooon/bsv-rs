//! The four HTTP shapes that hold headers write a redacting `Debug` (the
//! secret Debug fold, 2026-11-10; every value since its second fold): every
//! field as the derive printed it, every header name, every header value and a request's `search`
//! written `<redacted>`, never its text or its length, save the names whose
//! values are public by their protocol (`crate::util::debug_redact`'s
//! `PUBLIC_HEADERS`, any case). `tests/secret_debug.rs` pins each output.

use std::fmt::{Debug, Formatter, Result};

use super::transports::http::{HttpRequest, HttpResponse};
use super::{AuthFetchOptions, Response};
use crate::util::debug_redact::{HeaderList as Pairs, HeaderMap as Map};

/// A request's query (`search`), a URL's query: `""` when empty, else
/// `<redacted>` (the second fold: a query can carry a credential).
struct Search<'a>(&'a str);

impl Debug for Search<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        if self.0.is_empty() {
            f.write_str("\"\"")
        } else {
            f.write_str("<redacted>")
        }
    }
}

impl Debug for HttpRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("HttpRequest")
            .field("request_id", &self.request_id)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("search", &Search(&self.search))
            .field("headers", &Pairs(&self.headers))
            .field("body", &self.body)
            .finish()
    }
}

impl Debug for HttpResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("HttpResponse")
            .field("request_id", &self.request_id)
            .field("status", &self.status)
            .field("headers", &Pairs(&self.headers))
            .field("body", &self.body)
            .finish()
    }
}

impl Debug for AuthFetchOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("AuthFetchOptions")
            .field("method", &self.method)
            .field("headers", &Map(&self.headers))
            .field("body", &self.body)
            .field("retry_counter", &self.retry_counter)
            .field("payment_retry_attempts", &self.payment_retry_attempts)
            .field("labels", &self.labels)
            .finish()
    }
}

impl Debug for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("headers", &Map(&self.headers))
            .field("body", &self.body)
            .finish()
    }
}

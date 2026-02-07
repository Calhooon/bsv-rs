# BSV Auth Transports Module
> Transport layer implementations for BRC-31 authentication messages

## Overview

This module provides transport layer implementations for sending and receiving authentication messages in the BRC-31 (Authrite) protocol. It defines the `Transport` trait for pluggable transports and includes HTTP-based and mock implementations. The HTTP transport implements BRC-104 for authenticated HTTP communication.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with exports and usage examples | ~42 |
| `http.rs` | Transport trait, HTTP transport, mock transport, BRC-104 payload types | ~1215 |

## Key Exports

### Transport Trait

The core abstraction for message transport:

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends an authentication message.
    async fn send(&self, message: &AuthMessage) -> Result<()>;

    /// Registers a callback for incoming messages.
    fn set_callback(&self, callback: Box<TransportCallback>);

    /// Clears the registered callback.
    fn clear_callback(&self);
}
```

### TransportCallback

Type alias for async callback functions:

```rust
pub type TransportCallback =
    dyn Fn(AuthMessage) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync;
```

### SimplifiedFetchTransport

HTTP-based transport for production use:

```rust
pub struct SimplifiedFetchTransport {
    base_url: String,
    #[cfg(feature = "http")]
    client: reqwest::Client,
    callback: Arc<StdRwLock<Option<Box<TransportCallback>>>>,
}

impl SimplifiedFetchTransport {
    pub fn new(base_url: &str) -> Self
    pub fn base_url(&self) -> &str
    pub fn message_to_headers(&self, message: &AuthMessage) -> Vec<(String, String)>
    pub fn headers_to_message_fields(&self, header_map: &[(String, String)])
        -> Result<(Option<String>, Option<String>, Option<Vec<u8>>)>
}
```

Features:
- Sends handshake messages (InitialRequest, InitialResponse, CertificateRequest, CertificateResponse) as JSON POST to `/.well-known/auth`
- Sends General messages via BRC-104: deserializes payload as `HttpRequest`, makes actual HTTP request with auth headers, wraps response in `HttpResponse` payload
- Automatically strips trailing slashes from base URL
- Uses `reqwest` client (requires `http` feature)
- Uses `std::sync::RwLock` for callback storage (synchronous access, no tokio::spawn needed)
- Invokes registered callback with response messages
- Implements `Debug` trait with redacted internal fields

### MockTransport

Testing transport for unit tests:

```rust
#[derive(Default)]
pub struct MockTransport {
    sent_messages: Arc<RwLock<Vec<AuthMessage>>>,
    response_queue: Arc<RwLock<Vec<AuthMessage>>>,
    callback: Arc<RwLock<Option<Box<TransportCallback>>>>,
}

impl MockTransport {
    pub fn new() -> Self
    pub async fn queue_response(&self, message: AuthMessage)
    pub async fn get_sent_messages(&self) -> Vec<AuthMessage>
    pub async fn clear_sent(&self)
    pub async fn receive_message(&self, message: AuthMessage) -> Result<()>
}
```

Features:
- Records all sent messages for assertion
- Queues response messages to be returned in order (FIFO)
- Simulates incoming messages via `receive_message()`
- Thread-safe with `Arc<RwLock<...>>` for concurrent access (uses `tokio::sync::RwLock`)
- Uses `tokio::spawn` for `set_callback`/`clear_callback` (async write to tokio RwLock from sync methods)
- Implements `Default` and `Debug` traits

### HttpRequest

Deserialized HTTP request from General message payload (BRC-104):

```rust
pub struct HttpRequest {
    pub request_id: [u8; 32],   // Request correlation ID
    pub method: String,          // HTTP method (GET, POST, etc.)
    pub path: String,            // URL path (e.g., "/api/users")
    pub search: String,          // URL query string (e.g., "?foo=bar")
    pub headers: Vec<(String, String)>,  // HTTP headers
    pub body: Vec<u8>,           // Request body
}

impl HttpRequest {
    pub fn from_payload(payload: &[u8]) -> Result<Self>
    pub fn to_payload(&self) -> Vec<u8>
    pub fn url_postfix(&self) -> String  // Returns path + search
}
```

Payload format: `[request_id: 32][method: varint+str][path: varint+str][search: varint+str][headers: varint+pairs][body: varint+bytes]`

### HttpResponse

HTTP response to be serialized as General message payload (BRC-104):

```rust
pub struct HttpResponse {
    pub request_id: [u8; 32],   // Request ID from response header
    pub status: u16,             // HTTP status code
    pub headers: Vec<(String, String)>,  // x-bsv-* and authorization headers
    pub body: Vec<u8>,           // Response body
}

impl HttpResponse {
    pub fn from_payload(payload: &[u8]) -> Result<Self>
    pub fn to_payload(&self) -> Vec<u8>
}
```

Payload format: `[request_id: 32][status: varint][headers: varint+pairs][body: varint+bytes]`

### BRC-104 HTTP Headers

The `headers` module defines constants for authenticated HTTP communication:

```rust
pub mod headers {
    pub const VERSION: &str = "x-bsv-auth-version";
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    pub const NONCE: &str = "x-bsv-auth-nonce";
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
    pub const REQUESTED_CERTIFICATES: &str = "x-bsv-auth-requested-certificates";
}
```

| Header | Purpose | Format |
|--------|---------|--------|
| `x-bsv-auth-version` | Protocol version | `"0.1"` |
| `x-bsv-auth-identity-key` | Sender's public key | hex |
| `x-bsv-auth-nonce` | Sender's nonce | base64 |
| `x-bsv-auth-your-nonce` | Peer's previous nonce | base64 |
| `x-bsv-auth-signature` | Message signature | base64 or hex |
| `x-bsv-auth-message-type` | Message type | string |
| `x-bsv-auth-request-id` | Request correlation ID | base64 |
| `x-bsv-auth-requested-certificates` | Certificate requirements | JSON |

## Usage

### Creating an HTTP Transport

```rust
use bsv_sdk::auth::transports::SimplifiedFetchTransport;

let transport = SimplifiedFetchTransport::new("https://example.com");
assert_eq!(transport.base_url(), "https://example.com");
```

### Creating HTTP Request Payloads

```rust
use bsv_sdk::auth::transports::HttpRequest;

let request = HttpRequest {
    request_id: [42u8; 32],
    method: "POST".to_string(),
    path: "/api/v1/users".to_string(),
    search: String::new(),
    headers: vec![
        ("content-type".to_string(), "application/json".to_string()),
    ],
    body: b"{\"name\":\"Alice\"}".to_vec(),
};

let payload = request.to_payload();
let decoded = HttpRequest::from_payload(&payload).unwrap();
assert_eq!(decoded.url_postfix(), "/api/v1/users");
```

### Creating HTTP Response Payloads

```rust
use bsv_sdk::auth::transports::HttpResponse;

let response = HttpResponse {
    request_id: [42u8; 32],
    status: 200,
    headers: vec![
        ("content-type".to_string(), "application/json".to_string()),
    ],
    body: b"{\"id\":123}".to_vec(),
};

let payload = response.to_payload();
let decoded = HttpResponse::from_payload(&payload).unwrap();
```

### Implementing a Custom Transport

```rust
use bsv_sdk::auth::transports::{Transport, TransportCallback};
use bsv_sdk::auth::types::AuthMessage;
use bsv_sdk::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

struct MyTransport {
    callback: Arc<RwLock<Option<Box<TransportCallback>>>>,
}

#[async_trait]
impl Transport for MyTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        // Send the message via your transport
        Ok(())
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        let store = self.callback.clone();
        tokio::spawn(async move {
            let mut cb = store.write().await;
            *cb = Some(callback);
        });
    }

    fn clear_callback(&self) {
        let store = self.callback.clone();
        tokio::spawn(async move {
            let mut cb = store.write().await;
            *cb = None;
        });
    }
}
```

### Using MockTransport in Tests

```rust
use bsv_sdk::auth::transports::{MockTransport, Transport};
use bsv_sdk::auth::types::{AuthMessage, MessageType};
use bsv_sdk::primitives::PrivateKey;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_auth_flow() {
    let transport = MockTransport::new();

    // Set up callback to capture received messages
    let received = Arc::new(RwLock::new(Vec::new()));
    let received_clone = received.clone();
    transport.set_callback(Box::new(move |msg| {
        let received = received_clone.clone();
        Box::pin(async move {
            received.write().await.push(msg);
            Ok(())
        })
    }));

    // Wait for callback to be set
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Queue a response
    let response = AuthMessage::new(
        MessageType::InitialResponse,
        PrivateKey::random().public_key(),
    );
    transport.queue_response(response).await;

    // Send a message
    let request = AuthMessage::new(
        MessageType::InitialRequest,
        PrivateKey::random().public_key(),
    );
    transport.send(&request).await.unwrap();

    // Verify sent messages
    assert_eq!(transport.get_sent_messages().await.len(), 1);
}
```

## Internal Methods

### SimplifiedFetchTransport Internal Methods

| Method | Purpose |
|--------|---------|
| `auth_url()` | Returns `{base_url}/.well-known/auth` |
| `message_to_headers()` | Converts AuthMessage to HTTP header pairs |
| `headers_to_message_fields()` | Parses HTTP headers into nonce, your_nonce, signature |
| `invoke_callback()` | Invokes the registered callback with a message |

### Varint Encoding (Internal)

The module uses Bitcoin-style varint encoding for payload serialization:

| Function | Purpose |
|----------|---------|
| `read_varint(bytes)` | Reads a varint, returns `(i64_value, bytes_consumed)` |
| `write_varint(value)` | Writes an i64 value as varint bytes |

Varint sizes (Bitcoin-style):
- `0-252`: 1 byte (value directly)
- `253-65535`: 3 bytes (0xFD prefix + 2 bytes LE)
- `65536-4294967295`: 5 bytes (0xFE prefix + 4 bytes LE)
- Larger values: 9 bytes (0xFF prefix + 8 bytes LE)
- `-1` (empty/missing convention): 9 bytes (0xFF + 8 bytes of 0xFF)

## Message Routing

`SimplifiedFetchTransport` routes messages based on `MessageType`:

| Message Type | Destination |
|--------------|-------------|
| `InitialRequest` | POST to `/.well-known/auth` as JSON |
| `InitialResponse` | POST to `/.well-known/auth` as JSON |
| `CertificateRequest` | POST to `/.well-known/auth` as JSON |
| `CertificateResponse` | POST to `/.well-known/auth` as JSON |
| `General` | BRC-104: Parse payload as `HttpRequest`, make HTTP request with auth headers, wrap response in `HttpResponse` payload |

### General Message Flow (BRC-104)

1. Deserialize `AuthMessage.payload` as `HttpRequest`
2. Build HTTP request to `{base_url}{url_postfix}` with method from payload
3. Add auth headers (version, identity_key, nonce, your_nonce, signature, request_id)
4. Include original headers (`x-bsv-*`, `authorization`, `content-type`) excluding `x-bsv-auth-*`
5. Send request with body from payload
6. Parse response: extract request ID from headers (falls back to original if absent)
7. Filter response headers: include `x-bsv-*` (excluding `x-bsv-auth-*`) and `authorization`, sorted alphabetically
8. Build `HttpResponse` payload with status, filtered headers, body
9. Create response `AuthMessage`: identity key from response header if present, otherwise uses request's identity key (auth headers on response are optional)
10. Extract optional nonce, your_nonce, signature from response headers; check for certificate request in response message type header
11. Invoke callback with response message

## Feature Flags

```toml
# HTTP transport requires the http feature
bsv-sdk = { version = "0.2", features = ["auth", "http"] }
```

Without the `http` feature, `SimplifiedFetchTransport::send()` returns an error:

```rust
Error::AuthError("HTTP transport requires the 'http' feature".into())
```

## Dependencies

- `async_trait` - Async trait support for `Transport`
- `std::sync::RwLock` - Synchronous callback storage for `SimplifiedFetchTransport`
- `tokio::sync::RwLock` - Async state storage for `MockTransport`
- `reqwest` - HTTP client (optional, requires `http` feature)
- `serde_json` - JSON serialization for certificate requests and auth messages

## Error Handling

| Error | Cause |
|-------|-------|
| `AuthError("HTTP transport requires the 'http' feature")` | Sending without `http` feature |
| `AuthError("HTTP request failed: {}")` | Network error from reqwest |
| `AuthError("Auth endpoint returned {status}: {body}")` | Non-2xx handshake HTTP response |
| `AuthError("Failed to read auth response: {}")` | Failed to read handshake response body |
| `AuthError("Failed to parse auth response: {} - body: {}")` | Invalid JSON in handshake response |
| `AuthError("General message must have payload")` | General message missing payload |
| `AuthError("Failed to read response: {}")` | Failed to read General message HTTP response body |
| `AuthError("Payload too short for ...")` | Malformed payload during deserialization |
| `AuthError("Invalid ... UTF-8: {}")` | Non-UTF8 string in payload |
| `AuthError("Empty varint")` | Empty bytes when reading varint |
| `AuthError("Incomplete varint (fd/fe/ff)")` | Truncated varint encoding |
| `AuthError("Response payload too short for request ID")` | HttpResponse payload < 32 bytes |
| `AuthError("Invalid request ID length")` | Response request ID not 32 bytes |
| `AuthError("Failed to acquire callback lock")` | Poisoned std::sync::RwLock on callback |

## Testing

Run transport tests:

```bash
# Without HTTP (mock transport only)
cargo test --features auth transports

# With HTTP transport
cargo test --features auth,http transports
```

## Thread Safety

`SimplifiedFetchTransport` uses `std::sync::RwLock` (not tokio) for callback storage, so `set_callback()` and `clear_callback()` operate synchronously without spawning tasks. The `invoke_callback()` method acquires a read lock briefly to get the future, then drops the lock before awaiting.

`MockTransport` uses `tokio::sync::RwLock` for all internal state. Since `set_callback()` and `clear_callback()` are synchronous trait methods, it uses `tokio::spawn` to write to the async RwLock. When testing, a small delay may be needed after setting callbacks:

```rust
transport.set_callback(callback);
tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
// Now callback is guaranteed to be set
```

## Exports

From `mod.rs`:

```rust
pub use http::{
    headers, HttpRequest, HttpResponse, MockTransport, SimplifiedFetchTransport, Transport,
    TransportCallback,
};
```

## Related Documentation

- `../CLAUDE.md` - Auth module overview
- `../types.rs` - AuthMessage and MessageType definitions
- `../../wallet/CLAUDE.md` - Wallet module (WalletInterface)
- `../../primitives/CLAUDE.md` - PublicKey, base64/hex encoding

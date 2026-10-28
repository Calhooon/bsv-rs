# BSV Auth Transports Module
> Transport layer implementations for BRC-31 authentication messages

## Overview

This module provides transport layer implementations for sending and receiving authentication messages in the BRC-31 (Authrite) protocol. It defines the `Transport` trait for pluggable transports and includes three implementations: HTTP-based (`SimplifiedFetchTransport`), WebSocket-based (`WebSocketTransport`), and mock (`MockTransport`). The HTTP transport implements BRC-104 for authenticated HTTP communication.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with exports and usage examples | ~49 |
| `http.rs` | Transport trait, HTTP transport, mock transport, BRC-104 payload types | 1061 |
| `http/client.rs` | The HTTP transport's client (`http` feature, #320): `default_client` (`new`'s), `with_client`, `refuse_redirect` | ~80 |
| `http/handshake.rs` | Handshake send/status/JSON words (#410), bounded body and certificate-header parse (#416) | ~70 |
| `http/body.rs` | #416: streaming caps, Content-Length check, 1 MiB handshake / 16 MiB application defaults, configurable through positive-safe-integer builders | 99 |
| `http/response_bounds.rs` | #416: bounded hex signature; optional canonical 32-byte request ID; signed headers: 512, name 1–1,024 bytes, value ≤32,768 bytes, total ≤262,144 bytes; fetch's joined UTF-8 text | 130 |
| `http/general.rs` | General exchange moved from `http.rs`; applies response checks, preserves `certificateRequest`, omits an absent request ID | 133 |
| `http/json_syntax.rs` | Node 22 JSON syntax diagnostics after serde refuses; iterative, input-bounded states, no fixed depth cutoff, 20-unit context (#410) | ~310 |
| `http/unauthenticated.rs` | A general answer's authentication (`http` feature, #354): `head` (the status, the status line's own reason phrase from hyper's `ext::ReasonPhrase`, the headers), `refuse_unauthenticated`, `sender` (the answer's identity key), the reference's `#validateResponseAuthentication` and `#createUnauthenticatedResponseError` with its body preview, an unsigned 429, 502, 503 or 504 a transport fault by `status_fault` | ~226 |
| `websocket_transport.rs` | WebSocket transport (requires `websocket` feature) | ~599 |

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
    // Private response limits behind the http feature (1 MiB / 16 MiB).
    callback: Arc<StdRwLock<Option<Box<TransportCallback>>>>,
}

impl SimplifiedFetchTransport {
    pub fn new(base_url: &str) -> Self
    #[cfg(feature = "http")]
    pub fn with_client(base_url: &str, client: reqwest::Client) -> Self   // #320
    #[cfg(feature = "http")]
    pub fn with_max_response_bytes(self, bytes: usize) -> Result<Self>
    #[cfg(feature = "http")]
    pub fn with_max_handshake_response_bytes(self, bytes: usize) -> Result<Self>
    pub fn base_url(&self) -> &str
    pub fn message_to_headers(&self, message: &AuthMessage) -> Vec<(String, String)>
    pub fn headers_to_message_fields(&self, header_map: &[(String, String)])
        -> Result<(Option<String>, Option<String>, Option<Vec<u8>>)>
}
```

Features:
- Sends handshake messages (InitialRequest, InitialResponse, CertificateRequest, CertificateResponse) as JSON POST to `/.well-known/auth`
- Sends General messages via BRC-104: deserializes payload as `HttpRequest`, makes actual HTTP request with auth headers, writes the response payload (the request ID omitted when its header is absent)
- Automatically strips trailing slashes from base URL
- Uses `reqwest` client (requires `http` feature): `new` builds one with a 30 s request and 10 s connect timeout, `pool_max_idle_per_host(0)` and `redirect(Policy::none())`; `with_client` takes the caller's, used as given (its timeouts, proxy, resolution and redirect policy the caller's), the reference's `fetchClient` (`ts-stack@edf6e03` `SimplifiedFetchTransport.ts:64-67`; #320)
- Refuses an answer with a redirect status (301, 302, 303, 307, 308) on both paths before its body, whatever the client, as the reference's `redirect: 'error'` (`:128`, `:212`) does; a client that follows redirects has followed them before the transport sees the answer
- Refuses a general answer missing any of `x-bsv-auth-version`, `x-bsv-auth-identity-key`, `x-bsv-auth-signature` (absent, or white space alone) after its body is read and before a message is built, in the reference's words (`SimplifiedFetchTransport.ts:220-232`, `:464-494`, the body preview `:512-579`; #354), the reason phrase the status line's own (the canonical one when the line carries that one), an unsigned 429, 502, 503 or 504 a `TransportFault` of #87's class with those words its detail; a successful handshake's answer has no header check, as in the reference; a non-2xx handshake uses the same formatter with `response lacked required BSV auth headers` (#410)
- Uses `std::sync::RwLock` for callback storage (synchronous access, no tokio::spawn needed)
- Invokes registered callback with response messages
- Implements `Debug` trait with redacted internal fields

### WebSocketTransport

WebSocket-based transport for full-duplex communication (requires `websocket` feature):

```rust
pub struct WebSocketTransport {
    base_url: String,
    sink: Arc<Mutex<Option<WsSink>>>,
    on_data_callbacks: Arc<RwLock<Vec<Box<TransportCallback>>>>,
    read_deadline_secs: u64,
}

impl WebSocketTransport {
    pub fn new(options: WebSocketTransportOptions) -> Result<Self>
    pub fn base_url(&self) -> &str
    pub fn read_deadline_secs(&self) -> u64
}
```

Configuration:

```rust
pub struct WebSocketTransportOptions {
    pub base_url: String,           // Must start with ws:// or wss://
    pub read_deadline_secs: Option<u64>,  // Defaults to 30 if None or 0
}
```

Features:
- Lazy connection: WebSocket connection established on first `send()` call
- Background receive loop: spawns a tokio task that reads incoming messages and dispatches to all registered callbacks
- JSON-serialized `AuthMessage` payloads over WebSocket text frames (also accepts binary frames); written with `to_string` and read with `from_str`, so the signed certificate texts pass through as transmitted (#280)
- Connection dropped on send/receive errors (matches Go SDK behavior)
- Requires at least one callback registered before sending (returns `TransportError` otherwise)
- URL validation: rejects non-`ws://`/`wss://` schemes and empty hosts
- Supports multiple callbacks (unlike HTTP transport which stores a single callback)
- Ping/Pong handled automatically by tungstenite
- Malformed incoming JSON messages silently skipped (matches Go SDK behavior)
- Implements `Debug` trait with base_url and read_deadline_secs

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
| `x-bsv-auth-signature` | Response signature | nonempty even-length hex, at most 2,048 characters |
| `x-bsv-auth-message-type` | Message type | string |
| `x-bsv-auth-request-id` | Request correlation ID | base64 |
| `x-bsv-auth-requested-certificates` | Certificate requirements | JSON |

## Usage

### Creating an HTTP Transport

```rust
use bsv_rs::auth::transports::SimplifiedFetchTransport;

let transport = SimplifiedFetchTransport::new("https://example.com");
assert_eq!(transport.base_url(), "https://example.com");
```

### Creating a WebSocket Transport

```rust
use bsv_rs::auth::transports::{WebSocketTransport, WebSocketTransportOptions};

let transport = WebSocketTransport::new(WebSocketTransportOptions {
    base_url: "wss://example.com/ws".to_string(),
    read_deadline_secs: Some(60),
}).unwrap();
assert_eq!(transport.base_url(), "wss://example.com/ws");
assert_eq!(transport.read_deadline_secs(), 60);
```

### Creating HTTP Request Payloads

```rust
use bsv_rs::auth::transports::HttpRequest;

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

### Using MockTransport in Tests

```rust
use bsv_rs::auth::transports::{MockTransport, Transport};
use bsv_rs::auth::types::{AuthMessage, MessageType};

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

    // Wait for callback to be set (tokio::spawn in set_callback)
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Queue a response and send a message
    let response = AuthMessage::new(MessageType::InitialResponse, key);
    transport.queue_response(response).await;
    transport.send(&request).await.unwrap();
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

### WebSocketTransport Internal Methods

| Method | Purpose |
|--------|---------|
| `connect()` | Establishes WebSocket connection, spawns background receive loop |

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

`WebSocketTransport` sends all message types as JSON text frames over WebSocket.

### General Message Flow (BRC-104, HTTP only)

1. Deserialize `AuthMessage.payload` as `HttpRequest`
2. Build HTTP request to `{base_url}{url_postfix}` with method from payload
3. Add auth headers (version, identity_key, nonce, your_nonce, signature, request_id)
4. Include original headers (`x-bsv-*`, `authorization`, `content-type`) excluding `x-bsv-auth-*`
5. Send request with body from payload
6. Read the body, then refuse the answer unless it carries `x-bsv-auth-version`, `x-bsv-auth-identity-key` and `x-bsv-auth-signature` (#354); parse response: extract request ID from headers (falls back to original if absent)
7. Filter response headers: include `x-bsv-*` (excluding `x-bsv-auth-*`) and `authorization`, sorted alphabetically
8. Build `HttpResponse` payload with status, filtered headers, body
9. Create the response `AuthMessage` with the answer's identity key as its sender (until 0.9.0-beta.1 the request's own key when the header was absent)
10. Extract the nonce, your_nonce and signature from response headers; check for certificate request in response message type header
11. Invoke callback with response message

## Feature Flags

```toml
# HTTP transport requires the http feature
bsv-rs = { version = "0.3", features = ["auth", "http"] }

# WebSocket transport requires the websocket feature (adds tokio-tungstenite, futures-util)
bsv-rs = { version = "0.3", features = ["auth", "websocket"] }
```

Without the `http` feature, `SimplifiedFetchTransport::send()` returns an error:

```rust
Error::AuthError("HTTP transport requires the 'http' feature".into())
```

The `websocket` feature is opt-in and not included in `full`. It gates:
- The `websocket_transport` submodule in `mod.rs`
- The `WebSocketTransport` and `WebSocketTransportOptions` re-exports

## Dependencies

- `async_trait` - Async trait support for `Transport`
- `std::sync::RwLock` - Synchronous callback storage for `SimplifiedFetchTransport`
- `tokio::sync::RwLock` - Async state storage for `MockTransport` and `WebSocketTransport`
- `tokio::sync::Mutex` - Async mutex for WebSocket write half
- `reqwest` - HTTP client (optional, requires `http` feature)
- `tokio-tungstenite` - WebSocket client (optional, requires `websocket` feature)
- `futures-util` - Stream/Sink extensions for WebSocket (optional, requires `websocket` feature)
- `serde_json` - JSON serialization for certificate requests and auth messages

## Error Handling

| Error | Cause |
|-------|-------|
| `AuthError("HTTP transport requires the 'http' feature")` | Sending without `http` feature |
| `TransportFault { fault, status: None, detail: "HTTP request failed: {}" }` | A connection error (`NeverSent`) or a timeout, reset or other send failure (`MayHaveBeenReceived`), both paths (#87); a request that could not be built stays `AuthError` with the same text |
| `TransportFault { fault, status: Some(s), detail: "Received HTTP {status} {reason} from {url} without valid BSV authentication (response lacked required BSV auth headers)" }` | With ` - body preview: {preview}` for a nonempty body (#410). A handshake answered 429, or 503 with `Retry-After` (`RateLimited` with its wait), or 502, 503, 504 (`MayHaveBeenReceived`); the status read before the body (#87) |
| `AuthError("Network error while sending authenticated request to {url}: fetch failed")` | An answer with a redirect status (301, 302, 303, 307, 308) on either path, read before the body; the named host's answer, not a `TransportFault` (#320); Node 22's outer wrapper matched, its `TypeError: fetch failed` → `Error: unexpected redirect` cause chain absent here (#410) |
| `AuthError("Received HTTP {status} {reason} from {url} without valid BSV authentication (response lacked required BSV auth headers)")` | Any other non-2xx handshake HTTP response, with the same optional body preview (#410) |
| `TransportFault`, else `AuthError("Failed to read auth response: {}")` | Failed to read handshake response body |
| `AuthError("Unexpected token ...")`, `AuthError("Unexpected end of JSON input")`, or Node 22's positioned syntax diagnostic | Invalid JSON in a handshake response, with no header wrapper (#410); syntactically valid JSON that Rust's `AuthMessage` cannot represent keeps `Failed to parse auth response: {serde error} - body: {body}` |
| `AuthError("Failed to parse x-bsv-auth-requested-certificates returned by {url}: {value}. {cause}")` | Malformed certificate-request header on any general response; `{cause}` is Node 22's syntax diagnostic (#410); typed shape errors retain serde's words |
| `AuthError("General message must have payload")` | General message missing payload |
| `TransportFault`, else `AuthError("Failed to read response: {}")` | Failed to read General message HTTP response body (a signed General answer of any status but a redirect is passed to the caller as its `HttpResponse`, unchanged) |
| `TransportFault { fault, status: Some(s), detail: "Received HTTP {status} {reason} from {url} without valid BSV authentication (missing headers: {names})" }`, then ` - body preview: {preview}` for a body | A General answer missing any of the three auth headers with status 429, or 503 with `Retry-After` (`RateLimited` with its wait), or 502, 503, 504 (`MayHaveBeenReceived`): a gateway's or a limiter's answer, not the named host's (#354, #87) |
| `AuthError("Received HTTP {status} {reason} from {url} without valid BSV authentication (missing headers: {names})")`, then ` - body preview: {preview}` for a body | The same answer with any other status, the named host's answer; the missing names in the reference's order, `{reason}` the status line's own phrase, the canonical one when the line carries that one, none when it is blank or carries a byte above `0x7e` (#354) |
| `TransportFault { fault: MayHaveBeenReceived, status: None, detail: "SocketIoTransport::send: ws: {e}" }` | The Socket.IO sink failed (it cannot say how much of the frame it wrote; was `AuthError`, #87) |
| `AuthError("Payload too short for ...")` | Malformed payload during deserialization |
| `AuthError("Invalid ... UTF-8: {}")` | Non-UTF8 string in payload |
| `AuthError("Empty varint")` | Empty bytes when reading varint |
| `AuthError("Incomplete varint (fd/fe/ff)")` | Truncated varint encoding |
| `AuthError("Response payload too short for request ID")` | HttpResponse payload < 32 bytes |
| `AuthError("Authenticated response request ID must encode exactly 32 bytes")` | Response request ID has the wrong decoded length or padding bits (#416) |
| `AuthError("Authenticated response request ID must be canonical base64")` | Response request ID has malformed base64 framing (#416) |
| `AuthError("Failed to acquire callback lock")` | Poisoned std::sync::RwLock on callback |
| `TransportError("base_url is required...")` | WebSocket created with empty URL |
| `TransportError("WebSocket URL must start with ws://...")` | Invalid WebSocket URL scheme |
| `TransportError("failed to connect to WebSocket: {}")`, `TransportError("failed to send WebSocket message: {}")` | The WebSocket transport's connection and send failures: a transport variant already, kept as it is (its tests pin it); its `NeverSent`/`MayHaveBeenReceived` split waits on the owner's word (#87) |
| `TransportError("WebSocket URL must include a host")` | WebSocket URL has no host component |
| `TransportError("no handler registered")` | WebSocket send before setting callback |
| `TransportError("failed to marshal auth message: {}")` | JSON serialization error |
| `TransportError("WebSocket connection not available")` | Connection dropped after error |

The #410 entry names the handshake, malformed JSON, malformed certificate
header and redirect changes. Its 12 tests still replay the original 75
cases per reference; the final three now require #416's conforming header,
signature and certificateRequest outcomes. The new six-test suite and its
66-case-per-reference vector cover the full response bound set; two more
tests cover configured body limits, chunked reads and option validation.

The #416 header wrappers are `Failed to parse {header} returned by {url}: `
followed by `[oversized]. header exceeds its byte limit` or
`[invalid]. signature must be bounded even-length hexadecimal`. Bodies use
`Authenticated response from {url} exceeds {maximum} bytes`; their limits
are configurable even for a caller-supplied client. A response request ID
is optional and omitted when absent; when present it must be canonical
base64 (`Authenticated response request ID must be canonical base64`) of
exactly 32 bytes (`Authenticated response request ID must encode exactly
32 bytes`), without comparison to the outgoing ID. Signed-header limits
use `Authenticated response contains an oversized signed header` for a
name/value and `Authenticated response signed headers exceed their limit`
for count/total. See the changelog's #416 entry for all six old/new pairs.

The syntax scanner has no fixed depth cutoff; its states grow with input
depth. Node 22 accepts arrays and objects at 127, 128, 200, 1,000, 10,000 and
100,000 levels, up to its handshake-body default of 1 MiB and beyond in
`JSON.parse` alone. Rust applies the same configurable body cap since #416. Valid-JSON
typed refusals remain serde's, including out-of-range numbers: nine inputs
in the saved 80,096-case probe, all finite-double overflows (`86e427` reads
as `Infinity` in V8).

## Testing

Run transport tests:

```bash
# Without HTTP (mock transport only)
cargo test --features auth transports

# With HTTP transport
cargo test --features auth,http transports

# With WebSocket transport
cargo test --features auth,websocket transports
```

## Thread Safety

`SimplifiedFetchTransport` uses `std::sync::RwLock` (not tokio) for callback storage, so `set_callback()` and `clear_callback()` operate synchronously without spawning tasks. The `invoke_callback()` method acquires a read lock briefly to get the future, then drops the lock before awaiting.

`MockTransport` uses `tokio::sync::RwLock` for all internal state. Since `set_callback()` and `clear_callback()` are synchronous trait methods, it uses `tokio::spawn` to write to the async RwLock. When testing, a small delay may be needed after setting callbacks.

`WebSocketTransport` uses `tokio::sync::Mutex` for the write-half sink and `tokio::sync::RwLock` for callbacks. Like `MockTransport`, `set_callback()` and `clear_callback()` use `tokio::spawn`. It supports multiple concurrent callbacks (stored as `Vec<Box<TransportCallback>>`).

## Exports

From `mod.rs`:

```rust
// Always exported
pub use http::{
    headers, HttpRequest, HttpResponse, MockTransport, SimplifiedFetchTransport, Transport,
    TransportCallback,
};

// Exported with websocket feature
#[cfg(feature = "websocket")]
pub use websocket_transport::{WebSocketTransport, WebSocketTransportOptions};
```

## Related Documentation

- `../CLAUDE.md` - Auth module overview
- `../types.rs` - AuthMessage and MessageType definitions
- `../../wallet/CLAUDE.md` - Wallet module (WalletInterface)
- `../../primitives/CLAUDE.md` - PublicKey, base64/hex encoding

# BSV Auth Transports Module
> Transport layer implementations for BRC-31 authentication messages

## Overview

This module provides transport layer implementations for sending and receiving authentication messages in the BRC-31 (Authrite) protocol. It defines the `Transport` trait for pluggable transports and includes HTTP-based and mock implementations.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with exports and documentation | ~40 |
| `http.rs` | Transport trait, HTTP transport, mock transport, BRC-104 headers | ~450 |

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
impl SimplifiedFetchTransport {
    /// Creates a new HTTP transport.
    pub fn new(base_url: &str) -> Self

    /// Returns the base URL.
    pub fn base_url(&self) -> &str
}
```

Features:
- Sends handshake messages (InitialRequest, InitialResponse, CertificateRequest, CertificateResponse) as JSON POST to `/.well-known/auth`
- Sends General messages with BRC-104 auth headers
- Automatically strips trailing slashes from base URL
- Uses `reqwest` client (requires `http` feature)
- Invokes registered callback with response messages

### MockTransport

Testing transport for unit tests:

```rust
impl MockTransport {
    /// Creates a new mock transport.
    pub fn new() -> Self

    /// Queues a response message.
    pub async fn queue_response(&self, message: AuthMessage)

    /// Gets all sent messages.
    pub async fn get_sent_messages(&self) -> Vec<AuthMessage>

    /// Clears sent messages.
    pub async fn clear_sent(&self)

    /// Simulates receiving a message from the remote peer.
    pub async fn receive_message(&self, message: AuthMessage) -> Result<()>
}
```

Features:
- Records all sent messages for assertion
- Queues response messages to be returned
- Simulates incoming messages via `receive_message()`
- Thread-safe with `Arc<RwLock<...>>` for concurrent access

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
| `x-bsv-auth-signature` | Message signature | base64 (DER) |
| `x-bsv-auth-message-type` | Message type | string |
| `x-bsv-auth-request-id` | Request correlation ID | string |
| `x-bsv-auth-requested-certificates` | Certificate requirements | JSON |

## Usage

### Creating an HTTP Transport

```rust
use bsv_sdk::auth::transports::SimplifiedFetchTransport;

let transport = SimplifiedFetchTransport::new("https://example.com");
assert_eq!(transport.base_url(), "https://example.com");
```

### Implementing a Custom Transport

```rust
use bsv_sdk::auth::transports::{Transport, TransportCallback};
use bsv_sdk::auth::types::AuthMessage;
use bsv_sdk::Result;
use async_trait::async_trait;

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
        // Store the callback for incoming messages
        let store = self.callback.clone();
        tokio::spawn(async move {
            let mut cb = store.write().await;
            *cb = Some(callback);
        });
    }

    fn clear_callback(&self) {
        // Clear the callback
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
use bsv_sdk::auth::transports::MockTransport;
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
            let mut r = received.write().await;
            r.push(msg);
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
    let sent = transport.get_sent_messages().await;
    assert_eq!(sent.len(), 1);
}
```

## Internal Methods

### SimplifiedFetchTransport Internal Methods

| Method | Purpose |
|--------|---------|
| `auth_url()` | Returns `{base_url}/.well-known/auth` |
| `message_to_headers()` | Converts AuthMessage to HTTP header pairs |
| `headers_to_message_fields()` | Parses HTTP headers into message fields |
| `invoke_callback()` | Invokes the registered callback with a message |

## Message Routing

`SimplifiedFetchTransport` routes messages based on `MessageType`:

| Message Type | Destination |
|--------------|-------------|
| `InitialRequest` | POST to `/.well-known/auth` as JSON |
| `InitialResponse` | POST to `/.well-known/auth` as JSON |
| `CertificateRequest` | POST to `/.well-known/auth` as JSON |
| `CertificateResponse` | POST to `/.well-known/auth` as JSON |
| `General` | POST to `/.well-known/auth` as JSON (with auth headers) |

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
- `tokio::sync::RwLock` - Thread-safe callback storage
- `reqwest` - HTTP client (optional, requires `http` feature)
- `serde_json` - JSON serialization for certificate requests

## Error Handling

| Error | Cause |
|-------|-------|
| `AuthError("HTTP transport requires the 'http' feature")` | Sending without `http` feature |
| `AuthError("HTTP request failed: {}")` | Network error from reqwest |
| `AuthError("Auth endpoint returned {status}: {body}")` | Non-2xx HTTP response |
| `AuthError("Failed to parse auth response: {}")` | Invalid JSON response |

## Testing

Run transport tests:

```bash
# Without HTTP (mock transport only)
cargo test --features auth transports

# With HTTP transport
cargo test --features auth,http transports
```

## Related Documentation

- `../CLAUDE.md` - Auth module overview
- `../types.rs` - AuthMessage and MessageType definitions
- `../../wallet/CLAUDE.md` - Wallet module (WalletInterface)
- `../../primitives/CLAUDE.md` - PublicKey, base64 encoding

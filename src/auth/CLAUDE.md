# BSV Auth Module
> BRC-31 Peer-to-Peer Authentication for the BSV Rust SDK

## Overview

This module provides peer-to-peer authentication using the BRC-31 (Authrite) protocol, with certificate-based identity verification implementing BRC-52/53 and HTTP transport via BRC-104.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with re-exports (incl. WebSocket gated exports) | 85 |
| `types.rs` | Core types (AuthMessage, PeerSession, MessageType) | 457 |
| `session_manager.rs` | Session management with dual indexing | 444 |
| `peer.rs` | Core Peer implementation with `start()` transport setup | 996 |
| `certificates/` | Certificate submodule | - |
| `transports/` | Transport layer implementations (HTTP, WebSocket, Mock) | - |
| `utils/` | Utility functions | - |

## Submodules

### certificates/
Certificate types for BRC-52/53 selective disclosure:
- `mod.rs` - Re-exports and constants
- `certificate.rs` - Base Certificate type with signing/verification
- `master.rs` - MasterCertificate with field encryption and keyring management
- `verifiable.rs` - VerifiableCertificate with verifier-specific keyring

### transports/
Transport layer implementations for auth messages:
- `mod.rs` - Transport trait and re-exports (conditionally exports WebSocket types)
- `http.rs` - SimplifiedFetchTransport for HTTP (BRC-104), MockTransport for testing, HttpRequest/HttpResponse types
- `websocket_transport.rs` - WebSocketTransport for full-duplex WebSocket communication (requires `websocket` feature)
- See `transports/CLAUDE.md` for detailed transport documentation

### utils/
Utility functions:
- `mod.rs` - Re-exports
- `nonce.rs` - Nonce creation and verification
- `validation.rs` - Certificate validation, matching, encoding validation, and request set validation

## Constants

```rust
pub const AUTH_VERSION: &str = "0.1";
pub const AUTH_PROTOCOL_ID: &str = "auth message signature";
```

## Key Exports

Re-exports from `mod.rs`:
- `Certificate`, `MasterCertificate`, `VerifiableCertificate` (certificates)
- `Peer`, `PeerOptions` (peer)
- `SessionManager` (session_manager)
- `MockTransport`, `SimplifiedFetchTransport`, `Transport` (transports)
- `headers`, `TransportCallback`, `HttpRequest`, `HttpResponse` (transports)
- `WebSocketTransport`, `WebSocketTransportOptions` (transports, gated behind `websocket` feature)
- `current_time_ms`, `AuthMessage`, `MessageType`, `PeerSession`, `RequestedCertificateSet`, `AUTH_PROTOCOL_ID`, `AUTH_VERSION` (types)
- `create_nonce`, `validate_certificate_encoding`, `validate_certificates`, `validate_requested_certificate_set`, `verify_nonce` (utils)

### Types

**MessageType** - Authentication message types:
- `InitialRequest` - Initiates handshake
- `InitialResponse` - Responds to handshake
- `CertificateRequest` - Requests certificates
- `CertificateResponse` - Sends certificates
- `General` - Authenticated message

```rust
impl MessageType {
    pub fn as_str(&self) -> &'static str
    pub fn from_str(s: &str) -> Option<Self>
    pub fn is_handshake(&self) -> bool       // InitialRequest or InitialResponse
    pub fn is_certificate(&self) -> bool     // CertificateRequest or CertificateResponse
}

impl Display for MessageType { ... }         // Outputs as_str() format
```

**AuthMessage** - Full authentication message structure:
```rust
pub struct AuthMessage {
    pub version: String,                    // "0.1"
    pub message_type: MessageType,
    pub identity_key: PublicKey,
    pub nonce: Option<String>,              // base64
    pub initial_nonce: Option<String>,
    pub your_nonce: Option<String>,
    pub certificates: Option<Vec<VerifiableCertificate>>,
    pub requested_certificates: Option<RequestedCertificateSet>,
    pub payload: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,         // DER
}

impl AuthMessage {
    pub fn new(message_type: MessageType, identity_key: PublicKey) -> Self
    pub fn signing_data(&self) -> Vec<u8>
    pub fn get_key_id(&self, peer_session_nonce: Option<&str>) -> String
    pub fn validate(&self) -> Result<()>
}
```

**validate()** field requirements by message type:
- `InitialRequest` - requires `initial_nonce`
- `InitialResponse` - requires (`nonce` OR `initial_nonce`) + `your_nonce` + `signature`. Accepts either `nonce` or `initial_nonce` for cross-SDK compat (Go sends both, TS only sends `initialNonce`)
- `CertificateRequest` - requires `requested_certificates`
- `CertificateResponse` - requires `certificates`
- `General` - requires `signature`

**signing_data()** behavior by message type:
- `InitialRequest` - Empty (not signed, starts handshake)
- `InitialResponse` - `your_nonce || initial_nonce` (base64-decoded, initiator nonce then responder nonce; matches Go/TS)
- `General` - The payload bytes
- `CertificateRequest` - JSON-serialized `requested_certificates`
- `CertificateResponse` - JSON-serialized `certificates`

**get_key_id()** behavior by message type:
- `InitialResponse` - `"{your_nonce} {initial_nonce}"` (uses the message's own fields, ignoring `peer_session_nonce` param)
- All others - `"{nonce} {peer_session_nonce}"` (message nonce + the passed-in peer nonce)

**PeerSession** - Session state between peers:
```rust
pub struct PeerSession {
    pub is_authenticated: bool,
    pub session_nonce: Option<String>,
    pub peer_nonce: Option<String>,
    pub peer_identity_key: Option<PublicKey>,
    pub last_update: u64,
    pub certificates_required: bool,
    pub certificates_validated: bool,
}

impl PeerSession {
    pub fn new() -> Self
    pub fn with_nonce(session_nonce: String) -> Self
    pub fn touch(&mut self)                  // Update last_update to now
    pub fn is_ready(&self) -> bool           // Authenticated and certs validated (if required)
}
```

**RequestedCertificateSet** - Certificate request specification:
```rust
pub struct RequestedCertificateSet {
    pub certifiers: Vec<String>,            // hex-encoded public keys
    pub types: HashMap<String, Vec<String>>, // type_id -> field_names
}

impl RequestedCertificateSet {
    pub fn new() -> Self
    pub fn is_empty(&self) -> bool
    pub fn add_certifier(&mut self, certifier_hex: impl Into<String>)
    pub fn add_type(&mut self, type_id: impl Into<String>, fields: Vec<String>)
    pub fn is_certifier_trusted(&self, certifier_hex: &str) -> bool
    pub fn is_type_requested(&self, type_id: &str) -> bool
    pub fn get_fields_for_type(&self, type_id: &str) -> Option<&Vec<String>>
}
```

**current_time_ms** - Utility function:
```rust
pub fn current_time_ms() -> u64  // Milliseconds since Unix epoch
```

### Session Manager

**SessionManager** - Manages concurrent sessions with dual indexing:
```rust
impl SessionManager {
    pub fn new() -> Self
    pub fn add_session(&mut self, session: PeerSession) -> Result<()>
    pub fn update_session(&mut self, session: PeerSession)
    pub fn get_session(&self, identifier: &str) -> Option<&PeerSession>
    pub fn get_session_mut(&mut self, session_nonce: &str) -> Option<&mut PeerSession>
    pub fn remove_session(&mut self, session: &PeerSession)
    pub fn remove_by_nonce(&mut self, session_nonce: &str)
    pub fn has_session(&self, identifier: &str) -> bool
    pub fn len(&self) -> usize
    pub fn is_empty(&self) -> bool
    pub fn get_sessions_for_identity(&self, identity_key_hex: &str) -> Vec<&PeerSession>
    pub fn iter(&self) -> impl Iterator<Item = &PeerSession>
    pub fn clear(&mut self)
    pub fn prune_stale_sessions(&mut self, max_age_ms: u64) -> usize
}
```

Session lookup (`get_session`):
1. First tries as session nonce (exact match)
2. Then tries as identity key (returns best session)
3. "Best" = authenticated preferred, then most recent

Note: `get_session_mut` only searches by session nonce (not identity key).

### Peer

**Callback types**:
```rust
pub type GeneralMessageCallback = Box<dyn Fn(PublicKey, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;
pub type CertificateCallback = Box<dyn Fn(PublicKey, Vec<VerifiableCertificate>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;
pub type CertificateRequestCallback = Box<dyn Fn(PublicKey, RequestedCertificateSet) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;
```

**Peer** - Main authentication handler:
```rust
impl<W: WalletInterface, T: Transport> Peer<W, T> {
    pub fn new(options: PeerOptions<W, T>) -> Self
    pub fn start(&self)                      // Sets up client-side transport callback (ignores InitialRequest)
    pub fn start_server(self: &Arc<Self>)    // Sets up server-side transport callback (handles ALL message types)

    // Sending messages
    pub async fn to_peer(&self, message: &[u8], identity_key: Option<&str>, max_wait_time: Option<u64>) -> Result<()>
    pub async fn get_authenticated_session(&self, identity_key: Option<&str>, max_wait_time: Option<u64>) -> Result<PeerSession>
    pub async fn request_certificates(&self, requested: RequestedCertificateSet, identity_key: Option<&str>, max_wait_time: Option<u64>) -> Result<()>
    pub async fn send_certificate_response(&self, verifier_identity_key: &str, certificates: Vec<VerifiableCertificate>) -> Result<()>

    // Listening for general messages
    pub async fn listen_for_general_messages<F>(&self, callback: F) -> u32
    pub async fn stop_listening_for_general_messages(&self, callback_id: u32)

    // Listening for certificates
    pub async fn listen_for_certificates_received<F>(&self, callback: F) -> u32
    pub async fn stop_listening_for_certificates_received(&self, callback_id: u32)
    pub async fn listen_for_certificates_requested<F>(&self, callback: F) -> u32
    pub async fn stop_listening_for_certificates_requested(&self, callback_id: u32)

    // Session and identity
    pub fn session_manager(&self) -> &Arc<RwLock<SessionManager>>
    pub async fn get_identity_key(&self) -> Result<PublicKey>
    pub async fn handle_incoming_message(&self, message: AuthMessage) -> Result<()>
}
```

**Internal methods** (private):
- `sign_message()` - Signs an AuthMessage using BRC-42 key derivation with the session's peer identity key
- `verify_message_signature()` - Verifies an incoming AuthMessage signature
- `initiate_handshake()` - Creates session, sends InitialRequest, waits for InitialResponse via oneshot channel with timeout
- `process_initial_request()` - Server-side: creates session, sends InitialResponse, optionally sends certificates
- `process_initial_response()` - Client-side: delegates to `process_initial_response_inner()`, sends errors through oneshot channel
- `process_initial_response_inner()` - Verifies InitialResponse signature, updates session, resolves pending handshake
- `process_certificate_request()` - Verifies signature, notifies certificate request callbacks
- `process_certificate_response()` - Verifies signature, validates certificates, updates session, notifies callbacks
- `process_general_message()` - Verifies auth and signature, updates peer nonce, notifies callbacks

**PeerOptions** - Configuration for creating a Peer:
```rust
pub struct PeerOptions<W: WalletInterface, T: Transport> {
    pub wallet: W,
    pub transport: T,
    pub certificates_to_request: Option<RequestedCertificateSet>,
    pub session_manager: Option<SessionManager>,
    pub auto_persist_last_session: bool,
    pub originator: Option<String>,
}
```

### Certificates

See `certificates/CLAUDE.md` for full API details. Key types:

- **Certificate** - Base certificate (BRC-52): `cert_type`, `serial_number`, `subject`, `certifier`, `fields` (encrypted), `signature`. Methods: `new()`, `sign()`, `verify()`, `to_binary()`/`from_binary()`, field encryption key ID helpers.
- **MasterCertificate** - Wraps `Certificate` + `master_keyring`. Methods: `create_certificate_fields()`, `create_keyring_for_verifier()`, `issue_for_subject()`, `decrypt_field()`/`decrypt_fields()`. Derefs to `Certificate`.
- **VerifiableCertificate** - Wraps `Certificate` + verifier `keyring`. Methods: `decrypt_field()`/`decrypt_fields()`, `revealable_fields()`, `to_json_value()`, accessor methods (`subject()`, `certifier()`, etc.). Derefs to `Certificate`.

```rust
pub const CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL: &str = "certificate field encryption";
pub const CERTIFICATE_SIGNATURE_PROTOCOL: &str = "certificate signature";
```

### Transport

See `transports/CLAUDE.md` for full API details.

**Transport** - Trait for message transport:
```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, message: &AuthMessage) -> Result<()>;
    fn set_callback(&self, callback: Box<TransportCallback>);
    fn clear_callback(&self);
}

pub type TransportCallback = dyn Fn(AuthMessage) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync;
```

Three implementations:
- **SimplifiedFetchTransport** - HTTP transport (BRC-104): `new(base_url)`, `message_to_headers()`, `headers_to_message_fields()`
- **WebSocketTransport** - Full-duplex WebSocket (requires `websocket` feature): lazy connect on first `send()`, background receive loop, JSON payloads, connection dropped on errors. Config via `WebSocketTransportOptions { base_url, read_deadline_secs }`
- **MockTransport** - Testing: `queue_response()`, `get_sent_messages()`, `receive_message()`

**HttpRequest** / **HttpResponse** - BRC-104 binary payload types for General messages (request_id, method/status, path, headers, body).

### Utils

**Nonce functions**: `create_nonce()`, `verify_nonce()`, `validate_nonce_format()`, `get_nonce_random()` (protocol: `"server hmac"`)

**Validation functions**: `validate_certificates()`, `validate_certificate()`, `get_verifiable_certificates()`, `certificates_match_request()`

**Encoding validation**: `validate_certificate_encoding()` (structural checks on cert fields), `validate_requested_certificate_set()` (well-formedness of request sets)

## Usage Examples

### Client-Side Peer Authentication

```rust
use bsv_sdk::auth::{Peer, PeerOptions, SimplifiedFetchTransport};
use bsv_sdk::wallet::ProtoWallet;
use bsv_sdk::primitives::PrivateKey;

let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let transport = SimplifiedFetchTransport::new("https://example.com");

let peer = Peer::new(PeerOptions {
    wallet,
    transport,
    certificates_to_request: None,
    session_manager: None,
    auto_persist_last_session: false,
    originator: Some("myapp.com".into()),
});
peer.start(); // Client-side: handles responses but not incoming InitialRequest
peer.to_peer(b"Hello, world!", None, None).await?;
```

### Server-Side Peer Authentication

```rust
use std::sync::Arc;

let peer = Arc::new(Peer::new(PeerOptions {
    wallet,
    transport,
    certificates_to_request: None,
    session_manager: None,
    auto_persist_last_session: false,
    originator: Some("myserver.com".into()),
}));
peer.start_server(); // Server-side: handles ALL messages including InitialRequest
```

### Listening for Messages

```rust
let callback_id = peer.listen_for_general_messages(|sender, payload| {
    Box::pin(async move {
        println!("From {}: {:?}", sender.to_hex(), payload);
        Ok(())
    })
}).await;
peer.stop_listening_for_general_messages(callback_id).await;
```

### Certificate Exchange

```rust
let mut requested = RequestedCertificateSet::new();
requested.add_certifier(trusted_certifier_hex);
requested.add_type(cert_type_base64, vec!["name".into(), "email".into()]);
peer.request_certificates(requested, Some(&peer_identity_key), None).await?;
```

### WebSocket Transport

```rust
use bsv_sdk::auth::{Peer, PeerOptions, WebSocketTransport, WebSocketTransportOptions};

let transport = WebSocketTransport::new(WebSocketTransportOptions {
    base_url: "wss://example.com/ws".to_string(),
    read_deadline_secs: Some(60),
})?;

let peer = Peer::new(PeerOptions {
    wallet,
    transport,
    certificates_to_request: None,
    session_manager: None,
    auto_persist_last_session: false,
    originator: Some("myapp.com".into()),
});
peer.start();
```

## Protocol Details

### Peer Lifecycle

1. **Create**: `Peer::new(options)` - constructs peer with wallet and transport
2. **Start**: Choose one:
   - `peer.start()` - client-side callback (handles InitialResponse, General, Certificate messages; ignores InitialRequest)
   - `peer.start_server()` - server-side callback (handles ALL message types including InitialRequest). Requires `Arc<Peer>` since it routes through `handle_incoming_message()`.
3. **Communicate**: `to_peer()`, `request_certificates()`, etc.

### Authentication Flow

1. **InitialRequest**: Initiator sends `initial_nonce` (session nonce) + optional certificate request
2. **InitialResponse**: Responder sends `nonce` and `initial_nonce` (both set to responder's session nonce), `your_nonce` (initiator's nonce echoed back), and signature over `your_nonce || initial_nonce`
3. **CertificateExchange** (optional): Peers exchange verifiable certificates
4. **General**: Authenticated messages with payload, signed with per-message random nonce

### InitialResponse Field Mapping (Cross-SDK)

The InitialResponse field mapping matches Go and TS SDKs:
- `initial_nonce` = responder's session nonce (Go: `InitialNonce = session.SessionNonce`)
- `nonce` = responder's session nonce (same value, Go: `Nonce = ourNonce`)
- `your_nonce` = initiator's nonce echoed back (for session lookup by initiator)

On the initiator side, the responder's session nonce (`initial_nonce`) is stored as `peer_nonce`.

**TS SDK compatibility**: The TS SDK's InitialResponse has NO `nonce` field (only `initialNonce`, `yourNonce`). The Go SDK sends both `Nonce` and `InitialNonce`. The Rust SDK accepts either: both `start()` callback and `process_initial_response()` fall back to `initial_nonce` when `nonce` is absent.

### Error Propagation

Errors during InitialResponse processing (e.g., signature verification failure) are sent through the oneshot channel to the waiting `initiate_handshake()` caller. This is implemented in two places:

1. **`start()` callback**: Extracts nonces in a closure; on error, sends through oneshot before returning
2. **`process_initial_response()`**: Delegates to `process_initial_response_inner()`; on error, sends through oneshot

Without this, errors would be swallowed by the routing task and the caller would time out instead of receiving the actual error.

### Nonce Generation

Message nonces for General/CertificateRequest/CertificateResponse use simple 32-byte random values (base64-encoded), matching TypeScript's `Utils.toBase64(Random(32))`. Session nonces use HMAC-based `create_nonce()` with counterparty=Self (None).

Nonce verification on InitialResponse uses `nonce` if present, falls back to `initial_nonce` for TS SDK compat. Verification failure is non-fatal (matches Go/TS behavior).

### Cryptographic Details

- **Signature**: Protocol `"auth message signature"`, security level 2 (Counterparty), key ID `"{nonce} {peer_session_nonce}"`
- **InitialResponse key ID**: `"{your_nonce} {initial_nonce}"` (uses message's own fields)
- **Nonce**: 32 bytes (16 random + 16 HMAC via `"server hmac"` protocol), base64 encoded
- **Certificate fields**: Protocol `"certificate field encryption"`, security level 2. Master key ID: `"{field_name}"`, verifiable key ID: `"{serial_number_base64} {field_name}"`

## BRC-104 HTTP Headers

Headers: `x-bsv-auth-version`, `x-bsv-auth-identity-key` (hex), `x-bsv-auth-nonce` (base64), `x-bsv-auth-your-nonce`, `x-bsv-auth-signature` (base64), `x-bsv-auth-message-type`, `x-bsv-auth-request-id` (base64), `x-bsv-auth-requested-certificates` (JSON).

Payload format for General messages: **Request** `[request_id: 32][method: varint+str][path: varint+str][search: varint+str][headers: varint+pairs][body: varint+bytes]`, **Response** `[request_id: 32][status: varint][headers: varint+pairs][body: varint+bytes]`.

## Error Types

| Error | Description |
|-------|-------------|
| `AuthError(String)` | General authentication error |
| `SessionNotFound(String)` | Session not found by identifier |
| `CertificateValidationError(String)` | Certificate validation failed |
| `TransportError(String)` | Transport layer error |
| `InvalidNonce(String)` | Nonce format or verification error |

## Feature Flags

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["auth"] }

# With HTTP transport
bsv-sdk = { version = "0.2", features = ["auth", "http"] }

# With WebSocket transport
bsv-sdk = { version = "0.2", features = ["auth", "websocket"] }
```

The `auth` feature requires `wallet` and `messages` features (included automatically).
The `websocket` feature is opt-in (not included in `full`) and adds `tokio-tungstenite`, `futures-util`, and `url` dependencies.

## Cross-SDK Compatibility

This module maintains API compatibility with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `Peer`, `SessionManager`, `Certificate`
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `Peer`, `SessionManager`, `Certificate`

Authentication messages and certificates are wire-compatible across all SDK implementations.

Key compatibility details:
- InitialResponse `signing_data` signs `your_nonce || initial_nonce` (matches Go/TS byte order)
- InitialResponse `get_key_id` uses `"{your_nonce} {initial_nonce}"` format (matches Go `keyID()`)
- `create_nonce` uses counterparty=Self (matches Go/TS)
- Nonce verification on InitialResponse is optional (non-fatal failure, matches Go/TS behavior)

## Dependencies

The auth module uses:
- `tokio` - Async runtime (sync primitives, time, spawn)
- `async_trait` - Async trait support
- `serde`, `serde_json` - Serialization
- `rand` - Random number generation
- `reqwest` - HTTP client (with `http` feature)
- `tokio-tungstenite` - WebSocket client (with `websocket` feature)
- `futures-util` - Stream/Sink utilities for WebSocket (with `websocket` feature)
- Wallet module for key operations
- Primitives module for cryptography

## Testing

Run auth module tests:

```bash
cargo test --features auth
```

Run with HTTP transport tests:

```bash
cargo test --features auth,http
```

Run with WebSocket transport tests:

```bash
cargo test --features auth,websocket
```

**Test pattern note**: `ChannelTransport` (MockTransport) in tests never invokes the `start()` callback. Messages go through `handle_incoming_message` → `process_initial_response`, NOT through the `start()` callback. The `start()` callback path is only exercised by real transports (HTTP, WebSocket) that invoke the registered callback when they receive data.

## Related Documentation

- `transports/CLAUDE.md` - Transport layer implementations
- `../wallet/CLAUDE.md` - Wallet module (WalletInterface)
- `../primitives/CLAUDE.md` - Cryptographic primitives

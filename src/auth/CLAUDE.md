# BSV Auth Module
> BRC-31 Peer-to-Peer Authentication for the BSV Rust SDK

## Overview

This module provides peer-to-peer authentication using the BRC-31 (Authrite) protocol, with certificate-based identity verification implementing BRC-52/53.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with re-exports | ~70 |
| `types.rs` | Core types (AuthMessage, PeerSession, MessageType) | ~350 |
| `session_manager.rs` | Session management with dual indexing | ~260 |
| `peer.rs` | Core Peer implementation | ~550 |
| `certificates/` | Certificate submodule | - |
| `transports/` | Transport layer implementations | - |
| `utils/` | Utility functions | - |

## Submodules

### certificates/
Certificate types for BRC-52/53:
- `certificate.rs` - Base Certificate type
- `master.rs` - MasterCertificate with field encryption
- `verifiable.rs` - VerifiableCertificate with keyring

### transports/
Transport layer implementations:
- `http.rs` - SimplifiedFetchTransport for HTTP
- `MockTransport` - Testing transport

### utils/
Utility functions:
- `nonce.rs` - Nonce creation and verification
- `validation.rs` - Certificate validation

## Key Exports

### Types

**MessageType** - Authentication message types:
- `InitialRequest` - Initiates handshake
- `InitialResponse` - Responds to handshake
- `CertificateRequest` - Requests certificates
- `CertificateResponse` - Sends certificates
- `General` - Authenticated message

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
```

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
```

**RequestedCertificateSet** - Certificate request specification:
```rust
pub struct RequestedCertificateSet {
    pub certifiers: Vec<String>,            // hex-encoded public keys
    pub types: HashMap<String, Vec<String>>, // type_id -> field_names
}
```

### Session Manager

**SessionManager** - Manages concurrent sessions:
```rust
impl SessionManager {
    pub fn new() -> Self
    pub fn add_session(&mut self, session: PeerSession) -> Result<()>
    pub fn update_session(&mut self, session: PeerSession)
    pub fn get_session(&self, identifier: &str) -> Option<&PeerSession>
    pub fn get_session_mut(&mut self, nonce: &str) -> Option<&mut PeerSession>
    pub fn remove_session(&mut self, session: &PeerSession)
    pub fn has_session(&self, identifier: &str) -> bool
}
```

Session lookup:
1. First tries as session nonce (exact match)
2. Then tries as identity key (returns best session)
3. "Best" = authenticated preferred, then most recent

### Peer

**Peer** - Main authentication handler:
```rust
impl<W: WalletInterface, T: Transport> Peer<W, T> {
    pub fn new(options: PeerOptions<W, T>) -> Self

    // Sending messages
    pub async fn to_peer(&self, message: &[u8], identity_key: Option<&str>, max_wait: Option<u64>) -> Result<()>
    pub async fn get_authenticated_session(&self, identity_key: Option<&str>, max_wait: Option<u64>) -> Result<PeerSession>
    pub async fn request_certificates(&self, requested: RequestedCertificateSet, identity_key: Option<&str>, max_wait: Option<u64>) -> Result<()>
    pub async fn send_certificate_response(&self, verifier_key: &str, certs: Vec<VerifiableCertificate>) -> Result<()>

    // Listening
    pub async fn listen_for_general_messages<F>(&self, callback: F) -> u32
    pub async fn stop_listening_for_general_messages(&self, id: u32)
    pub async fn listen_for_certificates_received<F>(&self, callback: F) -> u32
    pub async fn listen_for_certificates_requested<F>(&self, callback: F) -> u32

    // Internal
    pub async fn get_identity_key(&self) -> Result<PublicKey>
    pub async fn handle_incoming_message(&self, message: AuthMessage) -> Result<()>
}
```

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

**Certificate** - Base certificate (BRC-52):
```rust
pub struct Certificate {
    pub cert_type: [u8; 32],
    pub serial_number: [u8; 32],
    pub subject: PublicKey,
    pub certifier: PublicKey,
    pub revocation_outpoint: Option<Outpoint>,
    pub fields: HashMap<String, Vec<u8>>,    // encrypted
    pub signature: Option<Vec<u8>>,
}

impl Certificate {
    pub fn new(...) -> Self
    pub fn sign(&mut self, certifier_key: &PrivateKey) -> Result<()>
    pub fn verify(&self) -> Result<bool>
    pub fn to_binary(&self, include_signature: bool) -> Vec<u8>
    pub fn from_binary(data: &[u8]) -> Result<Self>
}
```

**MasterCertificate** - Certificate with master keyring:
```rust
pub struct MasterCertificate {
    pub certificate: Certificate,
    pub master_keyring: HashMap<String, Vec<u8>>,
}

impl MasterCertificate {
    pub async fn create_certificate_fields<W: WalletInterface>(...) -> Result<(fields, keyring)>
    pub async fn create_keyring_for_verifier<W: WalletInterface>(...) -> Result<HashMap<String, Vec<u8>>>
    pub async fn issue_for_subject<W: WalletInterface>(...) -> Result<Self>
    pub async fn decrypt_field<W: WalletInterface>(...) -> Result<String>
    pub async fn decrypt_fields<W: WalletInterface>(...) -> Result<HashMap<String, String>>
}
```

**VerifiableCertificate** - Certificate with verifier keyring:
```rust
pub struct VerifiableCertificate {
    pub certificate: Certificate,
    pub keyring: HashMap<String, Vec<u8>>,
}

impl VerifiableCertificate {
    pub fn new(certificate: Certificate, keyring: HashMap<String, Vec<u8>>) -> Self
    pub async fn decrypt_field<W: WalletInterface>(...) -> Result<String>
    pub async fn decrypt_fields<W: WalletInterface>(...) -> Result<HashMap<String, String>>
    pub fn verify(&self) -> Result<bool>
}
```

### Transport

**Transport** - Trait for message transport:
```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, message: &AuthMessage) -> Result<()>;
    fn set_callback(&self, callback: Box<TransportCallback>);
    fn clear_callback(&self);
}
```

**SimplifiedFetchTransport** - HTTP transport:
```rust
impl SimplifiedFetchTransport {
    pub fn new(base_url: &str) -> Self
    pub fn base_url(&self) -> &str
}
```

**MockTransport** - Testing transport:
```rust
impl MockTransport {
    pub fn new() -> Self
    pub async fn queue_response(&self, message: AuthMessage)
    pub async fn get_sent_messages(&self) -> Vec<AuthMessage>
    pub async fn receive_message(&self, message: AuthMessage) -> Result<()>
}
```

### Utils

**Nonce functions**:
```rust
pub async fn create_nonce<W: WalletInterface>(wallet: &W, counterparty: Option<&PublicKey>, originator: &str) -> Result<String>
pub async fn verify_nonce<W: WalletInterface>(nonce: &str, wallet: &W, counterparty: Option<&PublicKey>, originator: &str) -> Result<bool>
pub fn validate_nonce_format(nonce: &str) -> Result<()>
```

**Validation functions**:
```rust
pub async fn validate_certificates<W: WalletInterface>(verifier_wallet: &W, message: &AuthMessage, requested: Option<&RequestedCertificateSet>, originator: &str) -> Result<()>
pub async fn get_verifiable_certificates<W: WalletInterface>(wallet: &W, requested: &RequestedCertificateSet, verifier_key: &PublicKey, originator: &str) -> Result<Vec<VerifiableCertificate>>
pub fn certificates_match_request(certs: &[VerifiableCertificate], requested: &RequestedCertificateSet) -> bool
```

## Usage Examples

### Basic Peer Authentication

```rust
use bsv_sdk::auth::{Peer, PeerOptions, SimplifiedFetchTransport};
use bsv_sdk::wallet::ProtoWallet;
use bsv_sdk::primitives::PrivateKey;

// Create wallet and transport
let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let transport = SimplifiedFetchTransport::new("https://example.com");

// Create peer
let peer = Peer::new(PeerOptions {
    wallet,
    transport,
    certificates_to_request: None,
    session_manager: None,
    auto_persist_last_session: false,
    originator: Some("myapp.com".into()),
});

// Send authenticated message
peer.to_peer(b"Hello, world!", None, None).await?;
```

### Listening for Messages

```rust
let callback_id = peer.listen_for_general_messages(|sender, payload| {
    Box::pin(async move {
        println!("From {}: {:?}", sender.to_hex(), payload);
        Ok(())
    })
}).await;

// Later: stop listening
peer.stop_listening_for_general_messages(callback_id).await;
```

### Certificate Exchange

```rust
use bsv_sdk::auth::RequestedCertificateSet;

// Request certificates from peer
let mut requested = RequestedCertificateSet::new();
requested.add_certifier(trusted_certifier_hex);
requested.add_type(cert_type_base64, vec!["name".into(), "email".into()]);

peer.request_certificates(requested, Some(&peer_identity_key), None).await?;

// Listen for certificates
peer.listen_for_certificates_received(|sender, certs| {
    Box::pin(async move {
        for cert in certs {
            println!("Received certificate from: {}", cert.certifier().to_hex());
        }
        Ok(())
    })
}).await;
```

## Protocol Details

### Authentication Flow

1. **InitialRequest**: Initiator sends session nonce and optional certificate request
2. **InitialResponse**: Responder sends own nonce and signs `initialNonce || sessionNonce`
3. **CertificateExchange** (optional): Peers exchange verifiable certificates
4. **General**: Authenticated messages with payload

### Signature Protocol

- Protocol ID: `"auth message signature"`
- Security Level: 2 (counterparty-specific)
- Key ID: `"{nonce} {peer_session_nonce}"`

### Nonce Format

- Total size: 32 bytes (base64 encoded)
- Random: 16 bytes
- HMAC: 16 bytes (using `"server hmac"` protocol)

### Certificate Field Encryption

- Protocol: `"certificate field encryption"`
- Security Level: 2
- Master Key ID: `"{field_name}"`
- Verifiable Key ID: `"{serial_number_base64} {field_name}"`

## BRC-104 HTTP Headers

For HTTP transport:
- `x-bsv-auth-version`: Protocol version
- `x-bsv-auth-identity-key`: Sender's public key (hex)
- `x-bsv-auth-nonce`: Sender's nonce (base64)
- `x-bsv-auth-your-nonce`: Peer's previous nonce
- `x-bsv-auth-signature`: Message signature (base64)
- `x-bsv-auth-message-type`: Message type
- `x-bsv-auth-requested-certificates`: Certificate requirements (JSON)

## Error Types

| Error | Description |
|-------|-------------|
| `AuthError(String)` | General authentication error |
| `SessionNotFound(String)` | Session not found by identifier |
| `CertificateValidationError(String)` | Certificate validation failed |
| `TransportError(String)` | Transport layer error |

## Feature Flags

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["auth"] }

# With HTTP transport
bsv-sdk = { version = "0.2", features = ["auth", "http"] }
```

The `auth` feature requires `wallet` and `messages` features (included automatically).

## Cross-SDK Compatibility

This module maintains API compatibility with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `Peer`, `SessionManager`, `Certificate`
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `Peer`, `SessionManager`, `Certificate`

Authentication messages and certificates are wire-compatible across all SDK implementations.

## Dependencies

The auth module uses:
- `tokio` - Async runtime (sync primitives, time)
- `async_trait` - Async trait support
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

## Related Documentation

- `../wallet/CLAUDE.md` - Wallet module (WalletInterface)
- `../messages/CLAUDE.md` - Messages module (BRC-77/78)
- `../primitives/CLAUDE.md` - Cryptographic primitives

# BSV Auth Module
> BRC-31 Peer-to-Peer Authentication for the BSV Rust SDK

## Overview

This module provides peer-to-peer authentication using the BRC-31 (Authrite) protocol, with certificate-based identity verification implementing BRC-52/53 and HTTP transport via BRC-104.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with re-exports (incl. WebSocket gated exports) | 85 |
| `types.rs` | Core types (AuthMessage with its signed texts and hand-written serde, PeerSession, MessageType, RequestedCertificateSet with its ordered types) | ~660 |
| `requested_certificates_json.rs` | #426: parsed-object request preimages; ordered maps, JavaScript integer keys, UTF-16 escapes and ECMAScript numbers; no recursive parser stack | 217 |
| `session_manager.rs` | Session management with dual indexing and nonce-claim API | 452 |
| `session_nonces.rs` | #362: atomic signed claims (100,000 per session), initial-request window (100,000 total / 256 per identity / 30 minutes), expiry and removal | 156 |
| `session_nonces_tests.rs` | Four #362 store-capacity, eviction and lifetime witnesses against the Node recorder | 116 |
| `peer.rs` | Peer API, transport ownership, handshake initiation and signatures; incoming handlers split for #362-364 | 687 |
| `peer_incoming.rs` | #362-364: signed nonce claims and authentication; certificate yourNonce, exact session and identity checks; listener errors; ready flag on the response session; since #445 a nonempty certificate response matched to its configured policy (none means empty), then the shared concurrent validator | 233 |
| `peer_initial.rs` | #362-364 fold: responder policy and matching proofs in the initial response; initiator validation, exact-session readiness, listeners and automatic answer (`Peer.ts:832-874,957-1035`); the signer decodes both nonces with `?` (#445) | 187 |
| `peer_certificates.rs` | #445: shared concurrent validator, subject then signature/policy then decryption; runtime-independent continuation turns preserve the Node 22 measured rejection order. `require_requested_certificates` matches the configured policy, including the empty default, before validation; empty and unrequested keyrings refused, nonempty subsets accepted | 138 |
| `peer_certificate_wait.rs` | #364: shared per-session certificate wait and 30-second deadline, resolved after validation | 83 |
| `peer_tests.rs` | `Peer`'s unit tests (`#[path]` from `peer.rs`, moved out with #294 to keep `peer.rs` under its ratchet bound); the shared validator's empty and 101 refusals before any signature (#445) | 81 |
| `certificates/` | Certificate submodule | - |
| `transports/` | Transport layer implementations (HTTP, WebSocket, Mock) | - |
| `utils/` | Utility functions | - |

## Submodules

### certificates/
Certificate types for BRC-52/53 selective disclosure:
- `mod.rs` - Re-exports and constants
- `certificate_json.rs` - `Certificate`'s JSON serde and `revocation_outpoint_from_str`, `pub(crate)` (#268)
- `bounds.rs` - The reference's certificate bounds and decrypt wrappers, each in its words (#297): the 100,000-field count and names of `toBinary`/`fromBinary`, the master constructor's checks, the 2048-byte keyring entry, the 64 KiB plaintext, canonical base64 Since #301 also the 16 MiB frame and 72-byte signature bounds of `to_binary`/`from_binary` (`require_written_frame`, `require_read_frame`, `require_written_signature`, `require_read_signature`).
- `certificate.rs` - Base Certificate type with signing/verification; `from_binary` refuses a revocation outpoint index above `u32::MAX` (#122) through the wire's `integer_refusal` (`Invalid revocation outpoint index: expected an integer from 0 to 4294967295, received N`, the name this crate's: the reference's reader has no bound, `Certificate.ts:353`; #258)
- `master.rs` - MasterCertificate with field encryption and keyring management
- `verifiable.rs` - VerifiableCertificate with verifier-specific keyring

### transports/
Transport layer implementations for auth messages:
- `mod.rs` - Transport trait and re-exports (conditionally exports WebSocket types)
- `http.rs` - SimplifiedFetchTransport for HTTP (BRC-104), MockTransport for testing, HttpRequest/HttpResponse types
- `http/client.rs` - the transport's client (`http` feature, #320): `new`'s default (30 s and 10 s timeouts, no idle reuse, no redirect followed), `with_client(base_url, client)` (the reference's `fetchClient`, the caller's client used as given), and the refusal of an answer with a redirect status on both paths (`AuthError`, `Network error while sending authenticated request to {url}: fetch failed; Node 22's wrapper, #410, without its cause chain`)
- `http/handshake.rs` - Handshake status/JSON words and certificate-header parsing (#410); since #416 the body is capped at the configurable 1 MiB default and the certificate header at 262,144 UTF-8 bytes, before retaining `requested_certificates_text` and parsing the typed set; the Peer re-serializes the complete object for its signature with #426's ordered parser
- `http/body.rs` - #416: streamed body caps, default 1 MiB handshake and 16 MiB application; `with_max_handshake_response_bytes` and `with_max_response_bytes` configure positive safe integers, Content-Length checked first
- `http/body_tests.rs` - the recorded invalid and oversized declared Content-Length cases, on constructed Responses to isolate the SDK guard from native HTTP framing
- `http/response_bounds.rs` - #416: bounded even-length hex signature, optional canonical base64 request ID of 32 bytes, signed headers bounded at 512 / 1,024-byte name / 32,768-byte value / 262,144-byte total; repeated values joined and Latin-1 header text signed as UTF-8
- `http/general.rs` - general request/response path moved from `http.rs`; preserves `certificateRequest`, applies the six response checks in the reference's order, omits an absent response request ID from the payload
- `http/json_syntax.rs` - Node 22 JSON syntax diagnostics (#410), an iterative scanner used only after serde refuses, with states proportional to input depth, no fixed nesting cutoff, and a 20-unit context; depth 127 and 200 replayed from the recorder. Node accepts arrays through depth 524,287 with a scalar within its 1 MiB handshake-body default; Rust applies that body default too since #416. Syntactically valid values that Rust cannot represent keep serde's refusal, including numbers outside finite double range (`86e427` is V8 `Infinity`); the saved 80,096-input probe leaves nine such differences (the parity note)
- `http/unauthenticated.rs` - a general answer's authentication (`http` feature, #354): an answer missing any of `x-bsv-auth-version`, `x-bsv-auth-identity-key`, `x-bsv-auth-signature` refused before it becomes a message, in the reference's words (`AuthError`, `Received HTTP {status} {reason} from {url} without valid BSV authentication (missing headers: ...)`, its body preview after ` - body preview: `, the reason phrase the status line's own), the named host's answer; an unsigned 429, 502, 503 or 504 a gateway's or a limiter's, `TransportFault` of #87's class in the same words; the message's sender the answer's identity key, never the client's own
- `websocket_transport.rs` - WebSocketTransport for full-duplex WebSocket communication (requires `websocket` feature)
- `socketio/` - SocketIoTransport (`socketio` feature) and the Engine.IO/Socket.IO codec: send writes the message's text through `SocketIoSink::send_socketio_text` (default: decode and `send_socketio`, whose `Value` sorts keys; a sink that writes text overrides it), the dispatch reads the event argument's text (`codec::decode_event_args_text`), so the signed certificate texts pass through unchanged (#280); `packet_rules.rs` is the reference's reading of a packet's id and payload (#110: `socket.io-parser` 4.2.7's `decodeString` id run, white space included, and `isPayloadValid` in its words, `invalid payload`), the id carried on every packet (`Connect`, `Disconnect`, `ConnectError` take `ack_id: Option<u64>`) and written back by `encode`
- See `transports/CLAUDE.md` for detailed transport documentation
- A transport fault (a connection error, a timeout, a handshake answered 429, 502, 503 or 504, a Socket.IO sink failure) is `Error::TransportFault { fault, status, detail }`, never `AuthError(String)` (#87); the WebSocket transport keeps `TransportError`

### utils/
Utility functions:
- `mod.rs` - Re-exports
- `nonce.rs` - Nonce creation and verification
- `validation.rs` - Certificate validation, matching, encoding validation, and request set validation
- `requested_set.rs` - `assert_requested_certificate_set`, the reference's `assertRequestedCertificateSet` in its words, and the receipt check `Peer` calls before any handler (#294); `assert_canonical_base64` and `canonical_base64`, the required-length and text checks of `assertCanonicalBase64` (#445)
- `received_message.rs` - `check_received_message` (#445): the 100-certificate bound, then required canonical nonces and decoded lengths in reference order (`AuthMessageValidation.ts:348-389`). Session nonces are 48 bytes; later per-message nonces 32. Missing/noncanonical text and wrong lengths retain the reference's words. The 0.3.6 legacy acceptance window is deliberately closed at Peer intake.

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
- `current_time_ms`, `AuthMessage`, `MessageType`, `PeerSession`, `RequestedCertificateSet`, `RequestedCertificateTypes`, `AUTH_PROTOCOL_ID`, `AUTH_VERSION` (types)
- `assert_requested_certificate_set`, `create_nonce`, `validate_certificate_encoding`, `validate_certificates`, `validate_requested_certificate_set`, `verify_nonce` (utils)

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
    pub certificates_text: Option<Box<RawValue>>,           // as received, or as sent (#280)
    pub requested_certificates_text: Option<Box<RawValue>>, // as received, or as sent (#280)
}

impl AuthMessage {
    pub fn new(message_type: MessageType, identity_key: PublicKey) -> Self
    pub fn set_certificates(&mut self, certificates: Vec<VerifiableCertificate>)  // the value and its compact text
    pub fn set_requested_certificates(&mut self, requested: RequestedCertificateSet)
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
- `CertificateRequest` - JSON.stringify of the parsed `requestedCertificates` object (`requested_certificates_text`), preserving insertion order and extra properties (#426)
- `CertificateResponse` - the `certificates` JSON text as transmitted (`certificates_text`) (the reference's certificate JSON since #268)

The signed certificate texts (#280, #426): BRC-103 names no serialization (`0103.md:133-137,172`); the reference signs and verifies `JSON.stringify` (`Peer.ts:453,1068,1140,1203`). `AuthMessage` retains raw member text and a typed view. Its serializer writes retained text while it still matches the typed member; a mutation uses the typed value. CertificateRequest signing now parses the complete retained object into ordered maps and re-serializes it: whitespace disappears, redundant escapes decode, lone UTF-16 surrogates use lowercase `\uXXXX`, control characters use JSON.stringify's escapes, finite numbers use ECMAScript notation. Array-index keys come first in numeric order; other keys keep their first insertion position, duplicates replacing values. Extra properties remain signed. CertificateResponse retains #280's raw-text preimage. This request body is #400's byte-compared exception: never parse through a sorted `serde_json::Value`. Reading a message through `from_value` has already lost its original map order; read certificate messages from their text. Setters build compact outgoing text. A struct literal adds `certificates_text: None, requested_certificates_text: None`.

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
    pub types: RequestedCertificateTypes,    // type_id -> field_names, insertion order (#288)
}

pub type RequestedCertificateTypes = indexmap::IndexMap<String, Vec<String>>;

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

`types` keeps insertion order, as the reference's `Record` does (`ts-stack@edf6e03` `types.ts:21-23`; #288): a JSON read keeps the text's order, `add_type` appends a new type (one present keeps its place), and the JSON written, the bytes a certificateRequest signs (`Peer.ts:451-453`), is that order, so a set's JSON is a fixed point and the reference's `JSON.stringify(policy)` byte for byte. `indexmap` is a dependency of `auth` for it. A literal builds `types` with `.into_iter().collect()` or `RequestedCertificateTypes::from([...])`.

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
    pub fn claim_message_nonce(&mut self, session_nonce: &str, nonce: &str) -> Result<bool>
    pub fn claim_initial_request_nonce(&mut self, identity: &str, nonce: &str) -> Result<bool>
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
    pub fn start(&self)                      // Installs handle_incoming_message as the transport callback (both roles, #353)
    pub fn start_server(self: &Arc<Self>)    // The same as start(), kept for Arc holders

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

`Peer`'s intake (#445) refuses more than 100 certificates, then every required nonce in the reference's order and words. initialRequest requires initialNonce:48; initialResponse initialNonce:48 and yourNonce:48; certificateRequest and certificateResponse nonce:32, initialNonce:48, yourNonce:48; general nonce:32 and yourNonce:48. Outgoing certificate messages include initialNonce. `send_certificate_response` refuses 101 before any session or wallet work (`Peer.ts:1132-1134`).

`Peer` refuses a malformed requested certificate set where the reference does (#294), with `assert_requested_certificate_set`: `request_certificates` before it seeks a session or signs (`Peer.ts:434`); its own `certificates_to_request` in `initiate_handshake` before a nonce or the initialRequest (`:630`) and on a received initialRequest before `process_initial_request` signs the response (`:811`), the reference's construction-time refusal (`:158`) moved to the first snapshot since `new` cannot fail; a received message's `requestedCertificates` in `handle_incoming_message` (the `start` callback since #353) after the version check, before routing (`AuthMessageValidation.ts:345-346`; a certificateRequest without one `requestedCertificates must be an object.`, `:367`), the refusal the callback's `Err`.

**Internal methods** (private):
- `sign_message()` - Signs an AuthMessage using BRC-42 key derivation with the session's peer identity key
- `verify_message_signature()` - Verifies an incoming AuthMessage signature
- `initiate_handshake()` - Creates the session pinned to the identity key given (a string that is not one refused), sends InitialRequest, waits for InitialResponse via oneshot channel with timeout; a failed handshake's session removed (`Peer.ts:658-664`)
- `process_initial_request()` - Creates the session, lets request listeners select certificates or queries the wallet, then sends matching proofs and its own policy in InitialResponse; signs only the decoded nonces (`Peer.ts:832-874`)
- `process_initial_response()` - Authenticates, validates nonempty certificates under its own policy, marks the exact session ready and releases certificate waiters before listeners, then releases handshake waiters and answers the responder's request; errors before handshake release go through its oneshot (`Peer.ts:957-1035`)
- `authenticate_initial_response()` - The reference's `authenticateInitialResponse` (`Peer.ts:886-956`): own `your_nonce`, its session, pinned identity, signature, initial nonce, replay claim; updates the session before certificate validation (#353, #362)
- `process_certificate_request()` - Own `yourNonce`, exact session and matching identity, signature, nonce claim, authentication; returns a listener's error (#362, #363)
- `process_certificate_response()` - Authenticates and matches nonempty certificates to its configured policy (none means empty, so refused) before the shared concurrent validator; marks the exact session ready, releases waiters and then notifies listeners (#445).
- `process_general_message()` - The reference's `processGeneralMessage` (`Peer.ts:1270-1314`) in its order and words: `your_nonce` made by this wallet, its session, the session's peer the sender, the signature, the nonce and the session's nonce present; claims the nonce, marks the session authenticated, waits for required certificate validation, notifies callbacks (a listener's error the message's) (#353, #362, #364)
- `verify_own_nonce()` - `verify_nonce` with counterparty self, a malformed nonce `false` (the reference's `verifyNonce`)

**PeerOptions** - Configuration for creating a Peer:
```rust
pub struct PeerOptions<W: WalletInterface, T: Transport> {
    pub wallet: W,
    pub transport: T,
    pub certificates_to_request: Option<RequestedCertificateSet>,
    pub session_manager: Option<SessionManager>,
    pub auto_persist_last_session: bool,
    pub originator: Option<String>,   // None: no originator to the wallet ("unknown" until #329)
}
```

### Certificates

See `certificates/CLAUDE.md` for full API details. Key types:

- **Certificate** - Base certificate (BRC-52); its JSON and its two subclasses' are the reference's (`type`, the signature hex, the keyrings base64 strings, the absent outpoint the zero sentinel, the txid alone read as index 0; #268, `tests/auth_certificate_json_268.rs`): `cert_type`, `serial_number`, `subject`, `certifier`, `fields` (`IndexMap<String, String>` in insertion order, the reference's `Record`, its bounds checked in that order and sorted only to write, #394; each value its base64 text, its UTF-8 bytes written and signed, never decoded before decryption: BRC-52 `0052.md:41,97`, #261; in JSON the string itself; `from_binary` refuses a value that is not UTF-8; a value over 1 MiB refused by `to_binary` (now `Result`, `sign`, `verify`, `signing_hash` through it) and `from_binary` in the reference's and the wire's one text, and decrypted only from canonical base64, #275), `signature`. Methods: `new()`, `sign()`, `verify()`, `signature_key_id()`, `to_binary()`/`from_binary()`, field encryption key ID helpers. `sign` refuses a certificate already signed in the reference's words (`Certificate.ts:450-453`; `set_signature(None)` to re-sign, #262). `sign` and `verify` use BRC-52's derived key (#251): the certifier's child under protocol `[2, "certificate signature"]`, keyID `"<type> <serial>"` (the base64 strings, one space), counterparty anyone; `verify` derives the certifier's public child with the anyone key, as the reference's `Certificate.ts:428-431` does. A raw-key signature (this crate's before #251) is `Ok(false)`. `#[non_exhaustive]` since #249: build with `new()` and `with_revocation_outpoint`/`with_fields`/`with_signature`, change with `set_*` (the fields stay public). `received_unsigned` (`#[serde(skip)]`) keeps the unsigned prefix `from_binary` read or `sign` signed (`sign` always serializes afresh, in the reference's order, as `Certificate.ts:458` does); `verify`, `signing_hash` and `to_binary` use it while it parses to the current values (BRC-52 `0052.md:103`), the serializer otherwise; `set_field`/`set_fields`/`set_revocation_outpoint` clear it. `from_binary` refuses a repeated field name in the reference's words. The serializer orders names as the reference's `localeCompare` (`Certificate.ts:282`) under ICU root for U+0000..U+00FF (`collation.rs`, the DUCET table and the `l·` contraction; above U+00FF the residual: code point order after the table).
- **MasterCertificate** - Its random field AES keys and wallet-encrypted master/verifier keyrings retain 32-byte BRC-2 keys after the HMAC amendment (#379); `auth_hmac_issuance_379` pins a leading-zero derived key in each keyring against ts-stack PR 1423 at `9a2787b8c`. Wraps `Certificate` + `master_keyring`. Methods: `create_certificate_fields()`, `create_keyring_for_verifier()` (the reference's parameters in its order, `MasterCertificate.ts:325-346`: the fields, the fields to reveal, the master keyring, the serial, `privileged`, `privileged_reason`, then `originator`), `issue_for_subject()`, `decrypt_field()`/`decrypt_fields()` (each but `issue_for_subject` carries the privileged pair into the wallet's `encrypt`/`decrypt`, as the reference does; #261). `new()` returns `Result`, refused as the reference's constructor refuses (#297); the decrypt paths answer in the reference's wrappers (`Failed to decrypt certificate field!`, `Failed to decrypt all master certificate fields.`). Derefs to `Certificate`. Encrypts as the reference does (#261, `MasterCertificate.ts:254-310` at `ts-stack@edf6e03`): a random symmetric key per field, the field the base64 text of its ciphertext, the master keyring that key encrypted by the wallet, held as its base64 text (`IndexMap<String, String>`, decoded only at the wallet's decrypt; #268; insertion order, the walks of `new`, `create_certificate_fields`, `create_keyring_for_verifier` and `decrypt_fields` the map's, #394).
- **VerifiableCertificate** - Wraps `Certificate` + verifier `keyring` (`IndexMap<String, String>` in insertion order, `decrypt_fields` walking it so, #394; each value the base64 text of the field's revelation key encrypted to the verifier, decoded only at the wallet's decrypt; #268). Methods: `decrypt_field()`/`decrypt_fields()`, `revealable_fields()`, `to_json_value()`, accessor methods (`subject()`, `certifier()`, etc.). Derefs to `Certificate`.

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
- **SimplifiedFetchTransport** - HTTP transport (BRC-104): `new(base_url)`, `with_client(base_url, client)` (`http`, #320), `message_to_headers()`, `headers_to_message_fields()`
- **WebSocketTransport** - Full-duplex WebSocket (requires `websocket` feature): lazy connect on first `send()`, background receive loop, JSON payloads, connection dropped on errors. Config via `WebSocketTransportOptions { base_url, read_deadline_secs }`
- **MockTransport** - Testing: `queue_response()`, `get_sent_messages()`, `receive_message()`

**HttpRequest** / **HttpResponse** - BRC-104 binary payload types for General messages (request_id, method/status, path, headers, body).

### Utils

**Nonce functions**: `create_nonce()`, `verify_nonce()`, `validate_nonce_format()`, `get_nonce_random()` (protocol: `"server hmac"`)

**Validation functions**: `validate_certificates()`, `validate_certificate()`, `get_verifiable_certificates()` (holds each field of the wallet's result as its text, #261, and the wallet's `keyringForVerifier` strings as given, #268), `certificates_match_request()`

**Encoding validation**: `validate_certificate_encoding()` (structural checks on cert fields), `validate_requested_certificate_set()` (well-formedness of request sets, this crate's words; refuses an empty set; `Peer` does not call it), `assert_requested_certificate_set()` (the reference's `assertRequestedCertificateSet` in its words, `AuthMessageValidation.ts:107-162`; an empty set valid; `Error::AuthError`; the one `Peer` calls, #294)

## Usage Examples

### Client-Side Peer Authentication

```rust
use bsv_rs::auth::{Peer, PeerOptions, SimplifiedFetchTransport};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::primitives::PrivateKey;

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
peer.start(); // Every message through handle_incoming_message, verified (#353)
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
peer.start_server(); // The same path as start()
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
use bsv_rs::auth::{Peer, PeerOptions, WebSocketTransport, WebSocketTransportOptions};

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
   - `peer.start()` - installs `handle_incoming_message()` as the transport callback: every message type, each verified (until #353 `start` installed an unverifying callback of its own and ignored InitialRequest). The callback owns a Peer over the same state whose transport is a `Weak` (`TransportHold::Callback`), upgraded for each send, so the transport's callback is no cycle and a dropped Peer frees its transport and state; a send from the callback after the Peer is dropped is `AuthError("Peer has been dropped")`
   - `peer.start_server()` - the same, on an `Arc<Peer>`
3. **Communicate**: `to_peer()`, `request_certificates()`, etc.

### Authentication Flow

1. **InitialRequest**: Initiator sends `initial_nonce` (session nonce) + optional certificate request
2. **InitialResponse**: Responder sends `initial_nonce` (its session nonce), `your_nonce` (initiator's nonce echoed back), matching certificates and its own requested certificate set; the signature covers only decoded `your_nonce || initial_nonce` (`Peer.ts:854-874`)
3. **CertificateExchange** (optional): Initiator validates the initial response's certificates, marks its session ready, notifies listeners, releases handshake waiters, then answers the responder's request (`Peer.ts:957-1035`)
4. **General**: Authenticated messages with payload, signed with per-message random nonce

### InitialResponse Field Mapping (Cross-SDK)

The InitialResponse field mapping follows the TypeScript SDK:
- `initial_nonce` = responder's session nonce (Go: `InitialNonce = session.SessionNonce`)
- `nonce` is omitted, as in TypeScript (`Peer.ts:865-874`); Go sends it as `Nonce = ourNonce`
- `your_nonce` = initiator's nonce echoed back (for session lookup by initiator)

On the initiator side, the responder's session nonce (`initial_nonce`) is stored as `peer_nonce`.

**TS SDK compatibility**: Rust and TypeScript send `initialNonce` and `yourNonce` without `nonce`. The Go SDK sends both `Nonce` and `InitialNonce`. Rust reads and requires `initial_nonce` (at intake, in `initialResponse.initialNonce must be canonical base64.` or `initialResponse.initialNonce must encode exactly 48 bytes.`, #445). The initial response carries `certificates` when automatic selection ran (including an empty array, read by the initiator as the reference reads it: the session waits for certificates, no listener runs, nothing answered; `tests/auth_peer_certificate_paths_445.rs`, #445), followed by `requestedCertificates` (the responder's own policy, including an empty set), then `signature` (`Peer.ts:865-874`).

### Error Propagation

Errors during InitialResponse processing (e.g., signature verification failure) are sent through the oneshot channel to the waiting `initiate_handshake()` caller: `process_initial_response()` delegates to `authenticate_initial_response()` and on an error sends it through the oneshot named by `your_nonce` (a `your_nonce` naming none of ours leaves the handshake to time out, as the reference's does).

Without this, errors would be swallowed by the routing task and the caller would time out instead of receiving the actual error.

General messages preserve the wallet's rejection too (#407): a `ProtoWallet`
throws `Signature is not valid` for a non-verifying signature in both pinned
TypeScript references, and neither the Peer's wallet call nor its dispatcher
catches it. Only a returned `valid: false` produces `Invalid signature in
generalMessage from <identityKey>`, with the session identity's compressed
hex (no `0x`). Rust's existing behavior is the same. Unparseable bytes throw
before that branch: since #415 Rust propagates the wallet's canonical-DER
parameter error (code 6), matching `ts-stack@edf6e03`; `ts-sdk@9e3ede6b` still
has the DER parser's words. #415 removes the old #407 parser-word divergence
row. The two references are recorded in
`tests/auth_peer_general_message_words_407.rs` and the #407 changelog entry.
Do not turn every wallet error into a signature
verdict: an unavailable wallet must keep its own error.

### Nonce Generation

Message nonces for General/CertificateRequest/CertificateResponse use simple 32-byte random values (base64-encoded), matching TypeScript's `Utils.toBase64(Random(32))`. Session nonces use HMAC-based `create_nonce()` with counterparty=Self (None); `ProtoWallet::create_hmac` now issues the amended BRC-56 minimal-length key, with the 32-byte-key tag only a named and counted legacy verification acceptance (#379, owner 19.5 (a)).

An InitialResponse's, certificate request's, certificate response's and General message's `your_nonce` is verified against this peer's own wallet (counterparty self), a failure a refusal, as the reference and Go refuse it (#353; until then the responder's nonce was checked against the responder's key, which no wallet but the responder's can match, and the failure passed). Every accepted nonce is claimed since #362 (`Peer.ts:258-283,808,935,1085,1220,1314`), the initial request before wallet work, the four signed kinds after verification. A replay is `Replayed initialRequest nonce.` or `Replayed <messageType> message nonce.`. Signed claims fail closed at 100,000 per session and expire with session removal or 30 minutes idle (checked at claim time); initial claims survive session removal, expire at 30 minutes and evict oldest-first at 256 per identity or 100,000 total. General messages wait on one shared per-session validation result for up to 30 seconds (`Peer.ts:286-329,1318-1325`); a nonempty validated initial response or certificate response releases it, before notifying certificate listeners. See the #362-364 changelog parity paragraph for the retained session-policy and certificate-policy differences.

### Cryptographic Details

- **Signature**: Protocol `"auth message signature"`, security level 2 (Counterparty), key ID `"{nonce} {peer_session_nonce}"`
- **InitialResponse key ID**: `"{your_nonce} {initial_nonce}"` (uses message's own fields)
- **Nonce**: 48 bytes (16 random + the 32-byte HMAC via `"server hmac"` protocol), base64 encoded; Peer intake deliberately closes the 0.3.6 legacy window (#445), while standalone `verify_nonce` still accepts the legacy 32-byte form (16 + the HMAC's leading 16 bytes). The wallet's answer is a `[u8; 32]`, so the comparison never runs past it; a substrate refuses a short body as `WalletError("Invalid createHmac result hmac: expected 32 bytes")` (pinned, #139, #408)
- **Certificate fields**: each field encrypted (AES-256-GCM, `SymmetricKey`) under its own random revelation key; the key, not the field, is wallet-encrypted under protocol `"certificate field encryption"`, security level 2. Master key ID: `"{field_name}"`, verifiable key ID: `"{serial_number_base64} {field_name}"` (#261)

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
bsv-rs = { version = "0.3", features = ["auth"] }

# With HTTP transport
bsv-rs = { version = "0.3", features = ["auth", "http"] }

# With WebSocket transport
bsv-rs = { version = "0.3", features = ["auth", "websocket"] }
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
- Nonce verification on InitialResponse and all three signed follow-ups is mandatory; nonce claims prevent replay (#353, #362, #363).

## Dependencies

The auth module uses:
- `tokio` - Async runtime (sync primitives, time, spawn)
- `async_trait` - Async trait support
- `serde`, `serde_json` - Serialization
- `ryu-js` - ECMAScript number formatting in certificate-request preimages (#426)
- `indexmap` - `RequestedCertificateTypes`, the requested set's `types` in insertion order (#288); the certificates' field and keyring maps (#394); through `wallet` since #385
- `rand` - Random number generation
- `reqwest` - HTTP client (with `http` feature)
- `tokio-tungstenite` - WebSocket client (with `websocket` feature)
- `futures-util` - Stream/Sink utilities for WebSocket (with `websocket` feature)
- Wallet module for key operations
- Primitives module for cryptography

## Testing

| Witness | Tests | Contract |
|---|---|---|
| `transport_handshake_refusal_366.rs` | 4 | #354's recorder on 16 handshake answers: #410's reference status/URL/preview words, #87's 429/502/503/504 fault classes, no auth-header validation on success, redirects never replayed |
| `transport_header_collation_369.rs` | 3 | #416's signed-header collation: lowercase letter/digit/dash names equal byte order (1,407 Node 22.18.0 / ICU 77.1 probes); wider HTTP token punctuation needs locale order; three reference payloads byte for byte |

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

**Test pattern note**: `auth_peer_nonces_362_364`, `auth_peer_initial_response_certificates_362_364` and #353 use in-process transports whose deliveries invoke the callback installed by `start()`. The older `auth_peer_e2e_tests` channel routers call `handle_incoming_message` directly. Neither needs a network port.

## Related Documentation

- `transports/CLAUDE.md` - Transport layer implementations
- `../wallet/CLAUDE.md` - Wallet module (WalletInterface)
- `../primitives/CLAUDE.md` - Cryptographic primitives

# Wallet Substrates Module
> HTTP transport substrates for wallet communication

## Overview

This module provides transport substrates for communicating with BSV wallets over HTTP. Substrates implement the [`WalletWire`] trait or provide direct method implementations, handling the actual network communication.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, constants, re-exports | ~66 |
| `http_wire.rs` | Binary wire protocol over HTTP; the frame's originator validated, refused when not the configured one, sent raw as `Origin` (#323) | ~243 |
| `http_json.rs` | JSON API over HTTP; an error body read as its `WalletRefusalClass` by name or code (#137); the constructor's originator sent as `Origin` and `Originator`, a call with none refused, a body over 256 MiB refused (#323) | ~1100 |
| `origin.rs` | The two substrates' shared rules (#323): the reference's `normalizeWalletHttpBaseUrl` and `toOriginHeader`, the client `new` builds (`redirect::Policy::none()`), the redirect refusal | ~195 |
| `http_json/key_requests.rs` | The nine key-related calls' JSON bodies; the seven key-related requests carry `privileged`, `privilegedReason` and `seekPermission` in the reference's names, an absent one omitted (`JsonPermission`, flattened; bsv-rs#193) | ~246 |
| `CLAUDE.md` | This documentation | ~260 |

## Available Substrates

| Substrate | Protocol | Default Port | Use Case |
|-----------|----------|--------------|----------|
| `HttpWalletWire` | Binary | 3301 | High performance, low overhead |
| `HttpWalletJson` | JSON | 3321 | Debugging, simple integration |

## Platform-Specific Substrates (Not Included)

The following TypeScript SDK substrates are NOT included in the Rust SDK:

| Substrate | Reason |
|-----------|--------|
| `XDM` | Requires browser `window.parent.postMessage()` API |
| `ReactNativeWebView` | Requires React Native bridge |
| `WindowCWI` | Requires browser extension injection |

**Rationale**: These substrates require a JavaScript browser/WebView runtime with the `window` global, which doesn't exist in native Rust code. The Go SDK also excludes these for the same reason.

## HttpWalletWire

Binary wire protocol transport over HTTP. Implements the `WalletWire` trait.

### Constructors

```rust
// The originator validated, the base URL normalized; a client that follows no redirect
HttpWalletWire::new(originator: Option<String>, base_url: Option<String>) -> Result<Self, Error>

// A custom reqwest::Client (timeouts, TLS, proxies), used as given: its redirect policy too
HttpWalletWire::with_client(client: Client, originator: Option<String>, base_url: Option<String>) -> Result<Self, Error>
```

### Accessors

- `base_url(&self) -> &str` - The base URL's origin, as normalized
- `originator(&self) -> Option<&str>` - The originator, as `validate_originator` normalized it (the port dropped)

### Usage

```rust
use bsv_rs::wallet::substrates::HttpWalletWire;
use bsv_rs::wallet::wire::WalletWireTransceiver;

// Create wire transport
let wire = HttpWalletWire::new(
    Some("myapp.example.com".into()),
    None, // Uses default http://localhost:3301
)?;

// Wrap with transceiver for wallet operations
let wallet = WalletWireTransceiver::new(wire);

// Make wallet calls
let version = wallet.get_version("myapp.example.com").await?;
```

### HTTP Request Format

- **Method**: POST
- **URL**: `{base_url}/{call_name}` (e.g., `http://localhost:3301/getPublicKey`)
- **Content-Type**: `application/octet-stream`
- **Headers**: `Origin`, the frame's originator raw as validated (`example.com`), empty when the frame has none
- **Body**: Raw binary payload (excluding call code and originator)

### Wire Message Parsing

The wire extracts the call name and originator from the binary message:

```
[call_code: 1 byte][originator_len: 1 byte][originator: N bytes][payload: ...]
```

The call code maps to endpoint names via `WalletCall::method_name()`.

## HttpWalletJson

JSON API transport over HTTP. Provides direct method implementations rather than implementing `WalletWire`.

### Constructors

```rust
// The base URL normalized, the originator validated; a client that follows no redirect
HttpWalletJson::new(originator: Option<String>, base_url: Option<String>) -> Result<Self, Error>

// A custom reqwest::Client (timeouts, TLS, proxies), used as given: its redirect policy too
HttpWalletJson::with_client(client: Client, originator: Option<String>, base_url: Option<String>) -> Result<Self, Error>
```

### Accessors

- `base_url(&self) -> &str` - The base URL's origin, as normalized
- `originator(&self) -> Option<&str>` - The originator, as `validate_originator` normalized it (the port dropped)

### Usage

```rust
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};

let client = HttpWalletJson::new(
    Some("myapp.example.com".into()),
    None, // Uses default http://localhost:3321
)?;

let result = client.get_public_key(
    GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    },
    "myapp.example.com",
).await?;
```

### HTTP Request Format

- **Method**: POST
- **URL**: `{base_url}/{method_name}` (e.g., `http://localhost:3321/getPublicKey`)
- **Content-Type**: `application/json`; **Accept**: `application/json`
- **Headers**: `Origin` and `Originator`, both the constructor's originator in the origin form (`http://example.com`)
- **Body**: JSON-encoded method arguments

### Implemented Methods

**Cryptographic Methods:**
- `get_public_key` - Get wallet public key (identity or derived)
- `encrypt` / `decrypt` - Encrypt/decrypt data with derived keys
- `create_hmac` / `verify_hmac` - Create/verify HMACs
- `create_signature` / `verify_signature` - Create/verify ECDSA signatures

**Wallet Status Methods:**
- `is_authenticated` - Check authentication status
- `wait_for_authentication` - Wait until authenticated
- `get_height` - Get current block height
- `get_network` - Get network (mainnet/testnet)
- `get_version` - Get wallet version string

**Action Methods:**
- `create_action` - Create a new transaction action
- `sign_action` - Sign a previously created action
- `abort_action` - Abort an in-progress action
- `list_actions` - List wallet actions (transactions)
- `internalize_action` - Internalize an external transaction

**Output Methods:**
- `list_outputs` - List wallet outputs
- `relinquish_output` - Relinquish an output from a basket

**Certificate Methods:**
- `acquire_certificate` - Acquire a certificate
- `list_certificates` - List certificates
- `prove_certificate` - Prove a certificate
- `relinquish_certificate` - Relinquish a certificate

**Discovery Methods:**
- `discover_by_identity_key` - Discover certificates by identity key
- `discover_by_attributes` - Discover certificates by attributes

**Chain Methods:**
- `get_header` - Get a block header for a given height

### Binary Data Encoding

The bodies are BRC-100's and the reference's `HTTPWalletJSON`'s (#105; `wallet/0100.md` at `5119a9b`, `Wallet.interfaces.ts` at `ts-stack@edf6e03`; pinned in both directions by `tests/wallet_http_json_shapes_105.rs`):
- Bytes are arrays of byte numbers: `plaintext`, `ciphertext`, `data`, `hmac`, `signature`, `hashToDirectlySign`, `hashToDirectlyVerify`, `encryptedLinkage`, `encryptedLinkageProof`, createAction's `inputBEEF`, the action results' `tx` and `signableTransaction.tx`, internalizeAction's `tx`
- Hex strings: public keys (33 bytes compressed), txids (the action results' `txid`, the options' `knownTxids` and `sendWith`), scripts
- Base64: `signableTransaction.reference`
- The key-related requests name `protocolID` (the `[level, name]` pair) and `keyID`; getPublicKey writes `identityKey` only when true; the options name `returnTXIDOnly`
- A certificate's type field is `type`; list and discovery entries carry the certificate's fields flat; `keyringRevealer` is `"certifier"` or the key's hex; the linkage results are flat

## Constants

```rust
pub const DEFAULT_WIRE_PORT: u16 = 3301;
pub const DEFAULT_JSON_PORT: u16 = 3321;
pub const DEFAULT_WIRE_URL: &str = "http://localhost:3301";
pub const DEFAULT_JSON_URL: &str = "http://localhost:3321";
pub const SECURE_JSON_URL: &str = "https://localhost:2121";
```

## Feature Flag

All substrate implementations require the `http` feature:

```toml
[dependencies]
bsv-rs = { version = "0.3", features = ["wallet", "http"] }
```

## Error Handling

Substrates return `Error::WalletError` for:
- Empty or malformed messages (HttpWalletWire)
- HTTP request failures that are not transport faults (a request that could not be built, a redirect refused)
- Non-2xx status codes (except HttpWalletJson's busy and transport answers below)
- JSON parsing errors (HttpWalletJson)
- Invalid response data (base64 decoding, wrong HMAC length, etc.)

`HttpWalletJson` reads an error answer's body as `Error::WalletRefusal` with its class (#137): the body's `name`, else its `code` (an SDK code 2 to 8, or a `WalletRefusalClass` name such as `WERR_UNAUTHORIZED`), names the class (`from_name`, `from_code`; the name decides, so `WERR_INVALID_MERKLE_ROOT` with its toolbox code 8 is that class and a bare 8 `abortRefused`), the words its `message`, else its `description`, else the name. It reads the SDK's `unknownToJson`, the toolbox's `toJson` and its `asStatus` bodies (`ts-stack@edf6e03`; the reference's own client types codes 5, 6, 7 of a 400 body alone and refuses a non-integer code, `HTTPWalletJSON.ts:199-267`: the CHANGELOG's parity note). A numeric `code` no class names, with a `description`, stays `WalletError("wallet error (code N): <description>")`. The substrate is a client: it writes no error body.

`HttpWalletJson` reads `Error::WalletBusy` from the body's code, never from the HTTP status: a body whose `code` is `STORE_BUSY` (bsv-wallet-cli) or `ERR_SERVER_BUSY` (the TS toolbox edge), at any non-2xx status, is the wallet's answer that it refused the call before acting and promised that nothing was written, built or locked, so the caller may repeat the same call unchanged after `retry_after_ms`, or after a moment when it is `None`. The SDK reports the server's promise; it cannot check it. The detail is the body's `message`, else its `description`, else the code; `Retry-After` in delta-seconds becomes `retry_after_ms` (unbounded, the server's word), an HTTP-date `None`. A 503 without that code is `WalletTransport` (below). `HttpWalletWire` has no busy code on the wire (the BRC-100 result frame defines 5, 6, 7 and none for busy), so it keeps `WalletError`.

`HttpWalletJson` answers `Error::WalletTransport { status, detail }` when the way to the wallet failed, with no answer in the wallet's word: a 502, 503 or 504 whose body carries no busy code, no wallet class and no numeric wallet code (`status` the code, `detail` the usual `HTTP <status> for <method>: <body>` text), and a connection error (refused, reset, DNS) or a timeout (`status` `None`). A caller may retry it; it carries no promise about what the wallet did (the request may or may not have reached it), which is the one way it differs from `WalletBusy`. A 4xx, a 500, and a 5xx with a numeric wallet code keep `WalletError` (a class's body is `WalletRefusal` at any status, #137); the crate never retries by itself. Since #87 `HttpWalletWire` answers `WalletTransport` for the same faults (it answered `WalletError`), both substrates ask the one classifier (`transaction/broadcasters/transport_fault.rs`), and a body cut (a decode error whose source is not `serde_json`'s) is `WalletTransport { status: None }` too; a success body that is not the expected JSON stays `WalletError`.

A 429 without a busy code, at either substrate, is `Error::TransportFault { fault: TransportFault::RateLimited { retry_after_ms }, status: Some(429), detail }` (#87; was `WalletError`), the wait read from delta seconds or an HTTP date. A 503 with `Retry-After` and no busy code stays `WalletTransport { status: Some(503) }` (0.8.2's pinned answer, its wait not carried: `WalletTransport` has no field for it). `WalletBusy` keeps 0.8.2's delta-seconds reading (an HTTP date `None`, pinned). `Error::transport_fault()` reads either fault variant's class (`WalletTransport` as `MayHaveBeenReceived`).

## Originator Handling

The reference's rule (#323; `ts-stack@edf6e03` `HTTPWalletJSON.ts:280-314`, `HTTPWalletWire.ts:17-20`, `:43-66`, `utils/toOriginHeader.ts`, `validationHelpers.ts:996-1037`):
- The constructors validate the originator with `validate_originator` (a canonical DNS hostname with an optional port, trimmed and lower-cased, the port dropped: `Example.com:8080` is `example.com`; a scheme-prefixed originator is refused, the colon read as a port separator) and normalize the base URL to its origin (no credentials, path, query or fragment; at most 2048 units; cleartext HTTP only to `localhost`, `*.localhost`, `127.0.0.1` or `[::1]`), each refusal in the reference's words; they return `Result`.
- `HttpWalletJson` sends the constructor's originator, never a method's `originator` argument, as both `Origin` and `Originator` in the origin form (`http://example.com`); a call with none configured is refused before a request, `HTTPWalletJSON: originator is required when using the HTTP substrate in Node.js. ...`. The reference skips the rule in a browser, whose `fetch` sets `Origin`; `http` is native-only here (`build.rs`, #152), so the rule is unconditional. A body over 256 MiB is refused unsent (`HTTPWalletJSON request exceeds the maximum permitted size`).
- `HttpWalletWire` validates the frame's originator (more than 250 bytes refused in the reference's words) and, when one is configured, refuses a frame whose originator is not it (`Wallet Wire frame originator does not match the configured originator`); it sends the frame's originator raw as `Origin`, empty when the frame has none. A frame over 256 MiB is refused.
- The client `new` builds takes `redirect::Policy::none()` (the reference's `redirect: 'error'`); a 3xx is answered `WalletError("HTTP 302 Found for <call>: a redirect is refused")`, never followed. A client given to `with_client` is used as given, its redirect policy too. reqwest's wasm32 client has no redirect policy (the browser's `fetch` follows); moot while `http` does not build for wasm32.
- Go (`go-sdk@2ca481c` `wallet/substrates/http_wallet_json.go:22-33`, `:51-53`; `http_wallet_wire.go:20-31`, `:81-83`) validates nothing, sends `Originator` raw only when set (JSON) and the frame's `Origin` raw (wire), takes any base URL, and follows redirects (`http.DefaultClient`).

## Testing

Run substrate tests:

```bash
cargo test wallet::substrates --features "wallet http"
```

Tests cover:
- The base-URL and origin-header rules (`origin.rs`), the originator rule (`wallet/validation/originator.rs`)
- Default and custom URL handling, the originator accessors
- Protocol and counterparty JSON serialization

The integration tests run against `wiremock` (`tests/wallet_http_*`, `tests/transport_fault_wallet.rs`; the #323 rules in `tests/wallet_http_originator_323.rs`).

## Cross-SDK Compatibility

The substrates are compatible with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) wallet servers
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) wallet servers

Both JSON and wire protocols use identical message formats across SDKs.

## Related Documentation

- `../wire/CLAUDE.md` - Wire protocol documentation
- `../CLAUDE.md` - Wallet module documentation
- `../../CLAUDE.md` - Project root documentation

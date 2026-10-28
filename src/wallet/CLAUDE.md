# BSV Wallet Module
> BRC-42 Key Derivation, ProtoWallet, WalletClient, WalletInterface, and Validation for the BSV Rust SDK

## Overview

This module provides the wallet interface, key derivation, and cryptographic operations for interacting with BSV wallets. It implements the BRC-42 key derivation standard and provides types compatible with the TypeScript and Go BSV SDKs.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with feature-gated exports and re-exports | ~253 |
| `types.rs` | Core wallet type definitions (70+ types, hex serde helpers) | ~1919 |
| `types/json_forms.rs` | The JSON forms of #105 that are neither serde's default nor the hex helpers: `hex_txid_option`, `base64_bytes` (the signable reference) and `KeyringRevealer`'s serde (`"certifier"` or the key's hex) | ~95 |
| `types/linkage.rs` | The two key-linkage results and `KeyLinkageResult`, re-exported from `types`; their JSON flat with byte arrays, `protocolID` through the private `protocol_tuple` helper, `keyID` (#105) | ~83 |
| `interface.rs` | WalletInterface async trait (28 methods, `originator: Option<&str>`, #329) + marker traits | ~319 |
| `key_deriver.rs` | BRC-42 key derivation with KeyDeriverApi trait | ~680 |
| `cached_key_deriver.rs` | Thread-safe LRU-cached key deriver (Mutex-based) | ~528 |
| `key_args.rs` | The seven key-related args and results; each args type ends with `privileged`, `privileged_reason`, `seek_permission` (the reference's names and defaults) and has `Default` (bsv-rs#193) | ~209 |
| `proto_wallet.rs` | ProtoWallet struct + WalletInterface impl; the signature/HMAC family validates its arguments before crypto (#415); one keyring, no permission prompts | ~1280 |
| `validation/crypto.rs` | Shared typed argument checks for ProtoWallet and the wire processor: protocol, key ID, privilege, data/hash exclusivity, byte bounds and canonical DER, in the reference's order (#415) | ~200 |
| `validation.rs` | 40+ input validation helpers + validated structs; `validation/create_action_input.rs` (`validate_create_action_input`, #282), `validation/internalize.rs` (#117) and `validation/originator.rs` (`validate_originator`, #323) re-exported from it | ~1111 |
| `collation.rs` | A certificate's field-name order, the reference's `localeCompare` under ICU root for U+0000..U+00FF (#249): `sort_field_names`, `pub(crate)`, the one order `auth::Certificate` signs over and `WireWriter::write_wallet_certificate` writes (here since #246: `wallet` builds the wire without `auth`); the table parsed at compile time | ~325 |
| `collation_latin1.txt` | The DUCET 13.0.0 rows of U+0000..U+00FF and the two `l·` contractions, ranked; written by `tests/support/certificate_collation_table_249.mjs`, never edited by hand (#249) | 264 |
| `client.rs` | Multi-substrate WalletClient (requires `http` feature); every call forwarded by one macro over the three substrates, including both linkage calls through the transceiver since #406 | ~633 |
| `client_instance.rs` | The instance substrate of `WalletClient::with_substrate` (#335): `Instance`, dereferencing to the `WalletInterface` and adapting the six status and header answers to the client's shapes | ~64 |
| `substrates/` | Transport substrate implementations | - |
| `wire/` | Wire protocol encoding/decoding | - |

## Submodules

### substrates/
Transport layer implementations for wallet communication (requires `http` feature):
- `mod.rs` - Module definitions, re-exports, `SECURE_JSON_URL` constant
- `http_json.rs` - JSON over HTTP substrate (`HttpWalletJson`)
- `http_wire.rs` - Binary wire protocol over HTTP substrate (`HttpWalletWire`)
- `origin.rs` - The base-URL and origin-header rules both share, the client that follows no redirect (#323); the constructors return `Result`, the originator validated and required at a JSON call
- See `substrates/CLAUDE.md` for details

### wire/
Wire protocol implementation for binary wallet communication:
- `mod.rs` - Module definitions and re-exports
- `encoding.rs` - Binary encoding/decoding for all wallet types (~2,493 lines)
- `calls.rs` - Call frame definitions for all 28 wallet operations
- `transceiver.rs` - Protocol transceiver (`WalletWireTransceiver`); `linkage.rs` its two linkage calls (#406)
- `processor.rs` - Request/response processing (`WalletWireProcessor`)
- See `wire/CLAUDE.md` for details

## Key Exports

### WalletInterface Trait

The `WalletInterface` trait defines all 28 wallet operations (async with `originator: Option<&str>`, the reference's optional `originator?`: `None` absent, `Some("")` empty, two values a wallet can give two verdicts on; #329):

| Category | Methods |
|----------|---------|
| Key (9) | `get_public_key`, `encrypt`, `decrypt`, `create_hmac`, `verify_hmac`, `create_signature`, `verify_signature`, `reveal_counterparty_key_linkage`, `reveal_specific_key_linkage` |
| Action (5) | `create_action`, `sign_action`, `abort_action`, `list_actions`, `internalize_action` |
| Output (2) | `list_outputs`, `relinquish_output` |
| Certificate (4) | `acquire_certificate`, `list_certificates`, `prove_certificate`, `relinquish_certificate` |
| Discovery (2) | `discover_by_identity_key`, `discover_by_attributes` |
| Status (6) | `is_authenticated`, `wait_for_authentication`, `get_height`, `get_header_for_height`, `get_network`, `get_version` |

Marker traits: `CryptoWallet` (crypto-only), `FullWallet` (all methods supported).

The trait requires `Send + Sync` and uses `#[async_trait]`. Unsupported methods should return `Err(Error::WalletError(...))`.

### WalletClient (requires `http` feature)

```rust
pub enum SubstrateType {
    Auto,           // Auto-detect (SecureJsonApi -> JsonApi -> Cicada)
    JsonApi,        // HTTP JSON API (port 3321)
    Cicada,         // Wire protocol over HTTP (port 3301)
    SecureJsonApi,  // Secure local JSON API (port 2121)
}

pub struct WalletClient {
    pub fn new(substrate_type: SubstrateType, originator: Option<String>) -> Self
    // The reference's `substrate: WalletInterface` alternative (#335): the instance is the
    // connected substrate, nothing probed; substrate_type() answers Auto
    pub fn with_substrate(substrate: Arc<dyn WalletInterface>, originator: Option<String>) -> Self
    pub fn substrate_type(&self) -> SubstrateType
    pub fn originator(&self) -> Option<&str>   // passed to every call as given; None when none is set (#329)
    // All 28 wallet operations as async methods (connect lazily on first call); both
    // linkage calls go through the transceiver on the wire substrate since #406
}
```

**Substrate Selection:**

| Type | Protocol | Default Port | Use Case |
|------|----------|--------------|----------|
| `Auto` | Various | - | Production apps (probes in order: Secure -> JSON -> Wire) |
| `JsonApi` | JSON | 3321 | Debugging, simple integration |
| `Cicada` | Binary | 3301 | High performance |
| `SecureJsonApi` | JSON/TLS | 2121 | Secure local communication |

Internally uses `ConnectedSubstrate` enum dispatching to `HttpWalletJson`, `WalletWireTransceiver<HttpWalletWire>` or the caller's instance (`client_instance::Instance`, #335), each call through the `forward!` macro with the client's originator (the configured one or `None`, #329).

### ProtoWallet

```rust
pub struct ProtoWallet {
    // Construction
    pub fn new(root_key: Option<PrivateKey>) -> Self
    pub fn anyone() -> Self

    // Identity
    pub fn key_deriver(&self) -> &CachedKeyDeriver
    pub fn identity_key(&self) -> PublicKey
    pub fn identity_key_hex(&self) -> String

    // Public Key
    pub fn get_public_key(&self, args: GetPublicKeyArgs) -> Result<GetPublicKeyResult>

    // Encryption (AES-256-GCM)
    pub fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult>
    pub fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult>

    // HMAC (SHA-256)
    pub fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult>
    pub fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult>

    // Signatures (ECDSA)
    pub fn create_signature(&self, args: CreateSignatureArgs) -> Result<CreateSignatureResult>
    pub fn verify_signature(&self, args: VerifySignatureArgs) -> Result<VerifySignatureResult>

    // Key Linkage Revelation
    pub fn reveal_counterparty_key_linkage(&self, args: RevealCounterpartyKeyLinkageArgs) -> Result<RevealCounterpartyKeyLinkageResult>
    pub fn reveal_specific_key_linkage(&self, args: RevealSpecificKeyLinkageArgs) -> Result<RevealSpecificKeyLinkageResult>
}

// ProtoWallet implements WalletInterface (async trait)
impl WalletInterface for ProtoWallet { ... }
```

#### ProtoWallet Capabilities

ProtoWallet can:
- Derive keys using BRC-42 (via internal CachedKeyDeriver wrapped in Arc)
- Create and verify ECDSA signatures
- Encrypt and decrypt data (AES-256-GCM via derived symmetric keys)
- Create and verify HMACs (SHA-256 with constant-time comparison)
- Reveal key linkages for verification (with Schnorr ZK proofs for counterparty linkage)
- Implement all `WalletInterface` methods (unsupported methods return errors)

ProtoWallet does NOT:
- Create transactions (returns error)
- Manage UTXOs (returns error)
- Interact with the blockchain
- Manage certificates (returns error)
- Store any persistent data

#### Default Counterparty Behavior

- `create_signature`: Defaults counterparty to `Anyone` (publicly derivable), matching Go/TS SDK behavior
- All other operations (`encrypt`, `decrypt`, `create_hmac`, `verify_hmac`, `verify_signature`, `get_public_key`): Default counterparty to `Self_`

#### WalletInterface Implementation

ProtoWallet implements `WalletInterface` (via `#[async_trait]`) with full support for cryptographic operations:
- Key operations: All 9 methods fully implemented (synchronous internally, wrapped as async)
- Action/Output/Certificate/Discovery operations: Return `Error::WalletError` indicating full wallet required
- Status operations: `is_authenticated` returns true, `wait_for_authentication` returns true, `get_network` returns `Network::Mainnet`, `get_version` returns `bsv-rs-<CARGO_PKG_VERSION>` (`bsv-rs-0.9.0`; BRC-100's vendor-1.0.0 shape, 7 to 30 bytes as the wire processor checks it, #222), `get_height` returns 0, `get_header_for_height` returns error

#### Schnorr Proof for Counterparty Key Linkage

`reveal_counterparty_key_linkage` generates a real 98-byte Schnorr ZK proof demonstrating knowledge of the private key and correct ECDH computation. The proof is encoded as:
- `R` (33 bytes, compressed point)
- `S'` (33 bytes, compressed point)
- `z` (32 bytes, scalar)

Both the linkage and proof are encrypted for the verifier using the "counterparty linkage revelation" protocol with the revelation timestamp as key_id.

### ProtoWallet argument-validator inventory (#415)

Read at `ts-stack@edf6e03`, `packages/sdk/src/wallet/ProtoWallet.ts:159-396`
and `validationHelpers.ts:1717-1804`. These are all nine methods in that
ProtoWallet; its constructor has no argument validator. `ts-sdk@9e3ede6b`
has none of these calls. The common encryption checks are the raw protocol
name (5..400 UTF-8 bytes), key ID (1..800 bytes), optional counterparty,
then privilege. A present privileged reason must have 5..50 UTF-8 bytes
even when not privileged; a true privileged flag requires a reason.

| Method | Reference validator, in order | Rust at base 326b0836 | Rust after #415 |
|---|---|---|---|
| `get_public_key` | `validateGetPublicKeyArgs`: identityKey true/absent, forSelf boolean; identity branch validates any supplied protocol/key/counterparty and privilege, otherwise common encryption checks | Required protocol/key checks; key-deriver validation only on derivation, identity branch bypasses it | Unchanged; follow-up |
| `reveal_counterparty_key_linkage` | `validateRevealCounterpartyKeyLinkageArgs`: counterparty public key, verifier public key, privilege (no seekPermission) | Parsed keys; trait adapter drops privilege fields | Unchanged; follow-up |
| `reveal_specific_key_linkage` | `validateRevealSpecificKeyLinkageArgs`: counterparty, verifier, protocol, key ID, privilege (no seekPermission) | Parsed keys and key-deriver checks; trait adapter drops privilege fields | Unchanged; follow-up |
| `encrypt` | `validateWalletEncryptArgs`: common encryption checks, plaintext byte array <=268435456 bytes | Key-deriver checks only, then encryption | Unchanged; follow-up |
| `decrypt` | `validateWalletDecryptArgs`: common encryption checks, ciphertext byte array <=268435456 bytes | Key-deriver checks only, then decryption | Unchanged; follow-up |
| `create_hmac` | `validateCreateHmacArgs`: common encryption checks, data byte array <=268435456 bytes | Key-deriver checks only, then HMAC | Shared validator before crypto |
| `verify_hmac` | `validateVerifyHmacArgs`: common encryption checks, data byte array <=268435456 bytes, HMAC exactly 32 bytes | Key-deriver checks; HMAC length enforced by type | Shared validator before crypto; same type guarantee |
| `create_signature` | `validateCreateSignatureArgs`: common encryption checks, exactly one data/hash, selected byte array (data <=268435456, hash exactly 32) | Missing data/hash refused; both accepted (hash wins); key-deriver checks | Shared validator before crypto; hash length enforced by type |
| `verify_signature` | `validateVerifySignatureArgs`: common encryption checks, exclusive data/hash and their bytes, signature byte array <=72, canonical DER with both scalars in 1..n-1, forSelf boolean | Missing data/hash refused; both accepted; key-deriver then DER parser | Shared validator before crypto; hash/forSelf types enforced |

Every refusal is `Error::WalletRefusal { class: InvalidParameter, message }`,
the reference's `WERR_INVALID_PARAMETER` (code 6), like the sibling originator
and internalize validators. No low-S rule is added. The key deriver's later
name normalization and syntax rules still run after argument validation.
The wire processor used the same typed checks except that its data-type
flag already guaranteed exclusivity; it now shares the four whole validators
and common checks. The canonical DER predicate is also shared with its result
validator. Neither path reclassifies a valid DER signature's crypto miss.

The reference's JS-only checks are recorded too: a plain object, at most
100000 properties, safe string keys and data properties; a two-element
protocol tuple with a safe integer in 0..2; string fields; a compressed
counterparty point (or self/anyone); booleans; dense byte arrays and exact
hash/HMAC lengths. Rust's structs, enums, parsed `PublicKey`, strings, byte
vectors, fixed arrays and `Option<bool>` enforce these without runtime
refusals. `tests/vectors/wallet_proto_args_415.json` records 202 cases from
the actual reference under Node 22: 117 replayable and 85 type-enforced.
`tests/wallet_proto_args_415.rs` pins each representable refusal text and
ordering; `auth_peer_general_message_words_407.rs` pins propagation through
both Peer entry points. No current-reference DER-word divergence remains;
the older ts-sdk still throws `Signature DER must start with 0x30` for the
recorded malformed bytes because it has no argument validator.

Follow-up for the captain: conform the remaining five methods above, including
the getPublicKey identity branch's supplied fields, both linkage trait
adapters' privilege checks, and encrypt/decrypt's byte bounds, in the
reference's order and words. Preserve the typed guarantees and record base-red
witnesses for each reachable refusal. These methods are not conformed here.

### Validation Module

The `validation` module (`validation.rs`) provides 40+ validation functions for wallet API inputs:

| Category | Functions |
|----------|-----------|
| Satoshis | `validate_satoshis` (with optional min) |
| Integers | `validate_integer`, `validate_integer_u32`, `validate_positive_integer_or_zero` |
| Strings | `validate_string_length`, `validate_optional_string_length`, `validate_hex_string`, `validate_optional_hex_string`, `validate_base64_string`, `validate_optional_base64_string`, `is_hex_string` |
| Identifiers | `validate_basket`, `validate_optional_basket`, `validate_label`, `validate_tag` (all normalize to lowercase, trim whitespace) |
| Originator | `validate_originator` (`validation/originator.rs`, #323): the reference's `validateOriginator` (`validationHelpers.ts:996-1037` at `ts-stack@edf6e03`): trimmed, lower-cased, 1 to 250 bytes, a canonical DNS hostname (parts 1 to 63 bytes of `[a-z0-9]`, inner hyphens) with an optional port (1 to 5 digits, at most 65535) dropped from the answer; each refusal `WalletRefusal` of class `InvalidParameter` in the reference's words (`The originator parameter must be a canonical DNS hostname with an optional port`); both HTTP substrates call it at construction |
| Outpoints | `parse_wallet_outpoint`, `validate_outpoint_string`, `validate_optional_outpoint_string` |
| Descriptions | `validate_description_5_2000`, `validate_description_5_50` |
| Actions | `validate_create_action_args`, `validate_create_action_input` (`validation/create_action_input.rs`), `validate_create_action_output`, `validate_create_action_options`, `validate_sign_action_spend`; an input's empty `unlockingScript` refused in the reference's words (`The unlockingScript parameter must be hexadecimal string.`, `validationHelpers.ts:595` at `ts-stack@edf6e03`) and an `unlockingScriptLength` of 0 as BRC-100's positive integer (`0100.md:649`; the reference permits it, `:598`), both `WalletRefusal` of class `InvalidParameter` (#282) |
| Internalize | `validate_internalize_action_args` (`validation/internalize.rs`): per output in the reference's `validateInternalizeOutput` order (`validationHelpers.ts:966-984`, #384), the protocol `wallet payment` or `basket insertion`, then its one remittance and no other (`WERR_INVALID_PARAMETER` in the reference's words, `The output remittance parameter must be only paymentRemittance for wallet payment` and the twin), then the insertion's `customInstructions` at most 1,000 UTF-8 bytes (BRC-100 at `5119a9b`, TS's `validateBasketInsertion`; #117), called by `ProtoWallet`, `WalletClient`, `HttpWalletJson` and `WalletWireTransceiver` before they act or send; the createAction output's copy stays unbounded |
| Certificates | `validate_certificate_fields` (1-50 byte field names, walked in the map's order: the first bad name given refused, #385), `validate_keyring_revealer` ("certifier" or 66-char hex pubkey) |
| Protocol | `validate_protocol_tuple`, `validate_query_mode` |

Validated structs (used after validation):
- `ValidCreateActionInput`, `ValidCreateActionOutput`, `ValidCreateActionOptions`, `ValidCreateActionArgs`
- `ValidSignActionSpend`, `ValidListOutputsArgs`, `ValidListActionsArgs`
- Raw counterparts (`CreateActionInputRaw`, `CreateActionOutputRaw`, `CreateActionOptionsRaw`, `CreateActionArgsRaw`, `SignActionSpendRaw`) for unvalidated input

### Hex Serialization Helpers (in `types.rs`)

The `types.rs` module includes serde helper modules for cross-SDK JSON compatibility:
- `hex_bytes` - Serializes `Vec<u8>` as hex strings (use with `#[serde(with = "hex_bytes")]`)
- `hex_bytes_option` - Serializes `Option<Vec<u8>>` as optional hex strings (use with `skip_serializing_if`)
- `hex_txid` - Serializes `[u8; 32]` TxId as hex strings
- `hex_txid_vec_option` - Serializes `Option<Vec<[u8; 32]>>` as optional arrays of hex strings

These serialize the byte fields that carry them as hex strings (e.g., `"76a914"`) rather than JSON arrays (e.g., `[118, 169, 20]`): scripts and txids, as BRC-100's `HexString` and `TXIDHexString`. BRC-100's `Byte[]`, `BEEF` and `AtomicBEEF` (`inputBEEF`, the action results' `tx`, internalizeAction's `tx`, listOutputs' `BEEF`) are serde's default arrays; `types/json_forms.rs` holds `hex_txid_option` (an optional txid) and `base64_bytes` (the signable reference, a `Base64String`). All types use `#[serde(rename_all = "camelCase")]` for JSON field naming consistency, with the BRC-100 names where camelCase is not it.

The certificate and key-linkage shapes are BRC-100's and the reference's `HTTPWalletJSON`'s (#105; `wallet/0100.md` at `5119a9b`, `Wallet.interfaces.ts` at `ts-stack@edf6e03`): `WalletCertificate`, `AcquireCertificateArgs` and `RelinquishCertificateArgs` write and read the Rust `certificate_type` as `type`; `RevealCounterpartyKeyLinkageResult` and `RevealSpecificKeyLinkageResult` flatten their `linkage` (`KeyLinkageResult`'s `encryptedLinkage` and `encryptedLinkageProof` as arrays of byte numbers, the reference's `Byte[]`), and the specific result writes `protocol` as `protocolID`, the `[level, name]` pair (the private `protocol_tuple` helper in `types/linkage.rs`; a level other than 0, 1 or 2 refused), and `key_id` as `keyID`. Since #105's second part the rest are too: `CertificateResult` and `IdentityCertificate` flatten their `certificate`; `KeyringRevealer` is `"certifier"` or the key's hex; `CreateActionArgs.input_beef` is `inputBEEF`, an array; the action results' `txid` hex and `tx` arrays; `SignableTransaction`'s `tx` an array and `reference` base64; the options' `knownTxids` and `sendWith` hex and `return_txid_only` `returnTXIDOnly`; `InternalizeActionArgs.tx` an array; `ListOutputsResult.beef` `BEEF`, an array (the substrate's key-related requests are `substrates/`'s). The discovery entry's `certifier_info`, `publicly_revealed_keyring` and `decrypted_fields`, and `IdentityCertifier`'s `icon_url` and `description`, are required, no `Option`, as BRC-100 (`0100.md:1401-1411`) and the reference have them (#105 item 4, 0.9.0): an entry without one is refused on intake naming it, an empty map is written `{}`, and the binary wire's reader and writer carry the same shape (`read_identity_certificate`, `write_identity_certificate`). Pinned against the reference's bodies in both directions by `tests/wallet_http_json_shapes_105.rs`. `wallet::Certificate`, which the JSON substrate does not carry, keeps `certificateType`. The nine certificate field and keyring maps (the three `fields`, `keyring_for_subject`, `keyring`, `keyring_for_verifier`, `publicly_revealed_keyring`, `decrypted_fields`, `attributes`) are `indexmap::IndexMap<String, String>`, the reference's `Record`s in insertion order, read and written in the text's order (#385); pinned by `tests/wallet_certificate_field_order_385.rs`.

### Core Types

**SecurityLevel** - User interaction level for key derivation:
- `Silent` (0): No user interaction required
- `App` (1): Requires user approval per application
- `Counterparty` (2): Requires user approval per counterparty per application

**Protocol** - Combines `SecurityLevel` and `protocol_name` (5-400 chars, or 430 for "specific linkage revelation" protocols; lowercase, no consecutive spaces, cannot end with " protocol").

**Counterparty** - Key derivation target: `Self_`, `Anyone` (publicly derivable), or `Other(PublicKey)`.

**Network** - Bitcoin network: `Mainnet` (default) or `Testnet`.

**ActionStatus** - Transaction status: `Completed`, `Unprocessed`, `Sending`, `Unproven`, `Unsigned`, `NoSend`, `NonFinal`, `Failed`.

**QueryMode** - Filter mode for lists: `Any` (default) or `All`.

**OutputInclude** - What to include in output listings: `LockingScripts` or `EntireTransactions`.

**Outpoint** - Transaction outpoint with `txid: TxId` and `vout: u32`. Parses from "txid.vout" string format. Supports both string and object serialization for cross-SDK compatibility.

**TxId** - Type alias for `[u8; 32]`.

**SatoshiValue** - Type alias for `u64`. Max: `MAX_SATOSHIS` (2.1 quadrillion).

### Key Derivation

**KeyDeriver** - BRC-42 key derivation from root private key:
- `new(root_key: Option<PrivateKey>)` - Creates deriver; None uses "anyone" key
- `anyone_key() -> (PrivateKey, PublicKey)` - Returns the special "anyone" key pair (scalar value 1)
- `root_key() -> &PrivateKey` - Returns the root private key
- `identity_key() -> PublicKey` - Returns the identity public key (root key's public key)
- `identity_key_hex() -> String` - Returns identity key as hex string
- `derive_public_key(protocol, key_id, counterparty, for_self)` - Derive public key
- `derive_private_key(protocol, key_id, counterparty)` - Derive private key
- `derive_private_key_raw(invoice_number, counterparty)` - Derive private key with raw invoice number (bypasses BRC-43 protocol name validation)
- `derive_symmetric_key(protocol, key_id, counterparty)` - Derive symmetric key for encryption
- `reveal_specific_secret()`, `reveal_counterparty_secret()` - For linkage revelation

**CachedKeyDeriver** - Thread-safe LRU-cached wrapper (default 1000 entries per cache):
- `new(root_key: Option<PrivateKey>, config: Option<CacheConfig>)`
- `inner() -> &KeyDeriver` - Access underlying deriver
- `root_key() -> &PrivateKey` - Returns the root private key
- Implements same `KeyDeriverApi` trait as `KeyDeriver`
- Maintains 3 separate `Mutex<LruCache<T>>` caches: public keys, private keys, symmetric keys
- Cache keys are formatted as `"{method}:{level}:{protocol}:{key_id}:{counterparty}:{for_self}"`
- Secrets (`reveal_specific_secret`, `reveal_counterparty_secret`) are NOT cached for security reasons

**KeyDeriverApi** - Trait implemented by both `KeyDeriver` and `CachedKeyDeriver`:
- `identity_key()`, `identity_key_hex()`
- `derive_public_key()`, `derive_private_key()`, `derive_private_key_raw()`, `derive_symmetric_key()`
- `reveal_specific_secret()`, `reveal_counterparty_secret()`

**CacheConfig** - Configuration for CachedKeyDeriver:
- `max_size: usize` - Maximum entries per cache (default 1000)

## Usage Examples

### ProtoWallet - Signing

```rust
let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let signed = wallet.create_signature(CreateSignatureArgs {
    data: Some(b"Hello, BSV!".to_vec()),
    hash_to_directly_sign: None,
    protocol_id: Protocol::new(SecurityLevel::App, "signing app"),
    key_id: "sig-1".to_string(),
    counterparty: None, // defaults to Anyone
    ..Default::default() // privileged, privileged_reason, seek_permission (#193)
}).unwrap();
```

### Two-Party Encryption

```rust
let alice = ProtoWallet::new(Some(PrivateKey::random()));
let bob = ProtoWallet::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "secure messaging");

let encrypted = alice.encrypt(EncryptArgs {
    plaintext: b"Secret message".to_vec(),
    protocol_id: protocol.clone(),
    key_id: "msg-1".to_string(),
    counterparty: Some(Counterparty::Other(bob.identity_key())),
    ..Default::default()
}).unwrap();

let decrypted = bob.decrypt(DecryptArgs {
    ciphertext: encrypted.ciphertext,
    protocol_id: protocol,
    key_id: "msg-1".to_string(),
    counterparty: Some(Counterparty::Other(alice.identity_key())),
    ..Default::default()
}).unwrap();
```

### WalletClient and Key Derivation

```rust
// Remote wallet via auto-detected substrate
let mut client = WalletClient::new(SubstrateType::Auto, Some("myapp.com".into()));
let version = client.get_version().await?;

// Direct key derivation
let deriver = KeyDeriver::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "my application");
let pub_key = deriver.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap();

// Cached key derivation
let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
let pub_key = cached.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap();
```

## BRC-42 Key Derivation Algorithm

**Private key**: `new_key = (self + HMAC-SHA256(ECDH(self, counterparty), invoice_number)) mod n`
**Public key**: `new_pubkey = counterparty + G * HMAC-SHA256(ECDH(self_priv, counterparty), invoice_number)`
**Invoice number format**: `{security_level}-{protocol_name}-{key_id}` (e.g., `1-my application-invoice-12345`)

## Feature Flags

```toml
[dependencies]
# Basic wallet functionality (key derivation, ProtoWallet, validation)
bsv-rs = { version = "0.3", features = ["wallet"] }

# With remote wallet communication (WalletClient)
bsv-rs = { version = "0.3", features = ["wallet", "http"] }
```

## Argument and Result Types

ProtoWallet operations use dedicated argument/result structs:

| Operation | Args Type | Result Type |
|-----------|-----------|-------------|
| `get_public_key` | `GetPublicKeyArgs` | `GetPublicKeyResult` |
| `encrypt` | `EncryptArgs` | `EncryptResult` |
| `decrypt` | `DecryptArgs` | `DecryptResult` |
| `create_hmac` | `CreateHmacArgs` | `CreateHmacResult` |
| `verify_hmac` | `VerifyHmacArgs` | `VerifyHmacResult` |
| `create_signature` | `CreateSignatureArgs` | `CreateSignatureResult` |
| `verify_signature` | `VerifySignatureArgs` | `VerifySignatureResult` |
| `reveal_counterparty_key_linkage` | `RevealCounterpartyKeyLinkageArgs` | `RevealCounterpartyKeyLinkageResult` |
| `reveal_specific_key_linkage` | `RevealSpecificKeyLinkageArgs` | `RevealSpecificKeyLinkageResult` |

Additional types in `types.rs` cover all wallet operations (actions, outputs, certificates, discovery).

## Error Types

| Error | Description |
|-------|-------------|
| `WalletError(String)` | General wallet error (includes validation failures) |
| `WalletRefusal { class, message }` | A wallet's refusal with its class (#137): `WalletRefusalClass`, the reference's table by name (`ts-stack@edf6e03`: the SDK's codes 2 to 8, `WalletError.ts:71-80`, and the toolbox's `WERR_*` classes, `WERR_errors.ts`; twenty, `ALL`), `name()` the reference's name, `code()` its number where assigned, `wire_code()` the binary frame's byte (the SDK's 2 to 8; the toolbox's merkle-root 8 none), `from_name`, `from_code`. The wire processor frames a class with a wire code with it and its words, every other as `Wallet operation failed`, code 1; the transceiver reads 2 to 8 back as the class; `HttpWalletJson` reads an error body's class by `name` or `code`. `Display` is the message alone |
| `WalletReviewActions(Box<ReviewActionsRefusal>)` | A wallet's `WERR_REVIEW_ACTIONS` with the reference's five members (#327, #339; `review_actions.rs`): `review_action_results`, `send_with_results`, `txid`, `tx`, `no_send_change` (`WERR_REVIEW_ACTIONS.ts:17-27` at `ts-stack@edf6e03`), beside `message`; the evidence the identity revocation's double-spend retry reads (`identity/double_spend.rs`, the reference's `withDoubleSpendRetry`). `ReviewActionsRefusal::new` (the results alone) and `with_members` (the reference's constructor) carry the reference's words (`Undelayed createAction or signAction results require review.`). `HttpWalletJson` reads all five from a 400 code-5 body with `reviewActionResults`, each validated in the reference's words (`substrates/http_json/review_actions.rs`, #339); the wire processor frames it with code 5 and its words, the members not on the wire (the reference's frame carries none), so it is read back as `WalletRefusal` of the `ReviewActions` class, which no retry repeats. `Display` is the message alone |
| `WalletBusy { detail, retry_after_ms }` | The wallet answered that it refused the call before acting (a contended store, a lock not acquired) and promised that nothing was written, built or locked, so the caller may repeat the same call unchanged after `retry_after_ms`, or after a moment when it is `None`. The SDK reports the server's promise; it cannot check it. `HttpWalletJson` reads it from the body's code (`STORE_BUSY`, `ERR_SERVER_BUSY`), never from the HTTP status; a 503 without that code is `WalletTransport` |
| `WalletTransport { status, detail }` | The way to the wallet failed, with no answer in the wallet's word: a caller may retry it; it carries no promise about what the wallet did (the request may or may not have reached it), which is the one way it differs from `WalletBusy`. `HttpWalletJson` answers it for a 502, 503 or 504 (`status` set) whose body carries no busy code and no numeric wallet code, and for a connection error (refused, reset, DNS) or a timeout (`status` `None`). Every refusal stays `WalletError`; the crate never retries |
| `HmacMinimalLengthKey { leading_zero_bytes }` | `verify_hmac`'s refusal of a tag made under the minimal-length key: BRC-56 (`5119a9b` `wallet/0056.md:66`) keys the HMAC with the 32-byte X coordinate; a sender that drops its leading zero bytes (ts-sdk) makes another tag for one key in 256. Computed only on a miss whose key begins with a zero byte; never an acceptance. A tag matching neither key stays `WalletError("HMAC is not valid")` (#148) |
| `KeyDerivationError(String)` | Key derivation failed |
| `ProtocolValidationError(String)` | Invalid protocol name or parameters |
| `InvalidCounterparty(String)` | Invalid counterparty specification |

## Cross-SDK Compatibility

This module maintains API compatibility with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `KeyDeriver`, `CachedKeyDeriver`, `ProtoWallet`, `WalletClient`, all wallet methods
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `KeyDeriver`, `ProtoWallet`

Key derivation uses the same algorithm (BRC-42) and produces identical keys across all SDK implementations.

**Notable difference:** Go SDK's `create_signature` defaults counterparty to `Anyone`; Rust and TS SDKs also default to `Anyone`.

### Type Mapping

| TypeScript | Rust |
|------------|------|
| `WalletProtocol` (tuple) | `Protocol` (struct with `from_tuple`/`to_tuple`) |
| `SecurityLevel` (0\|1\|2) | `SecurityLevel` (enum with `from_u8`/`as_u8`) |
| `Counterparty` (string\|PublicKey) | `Counterparty` (enum: `Self_`, `Anyone`, `Other(PublicKey)`) |
| `KeyDeriverApi` (interface) | `KeyDeriverApi` (trait) |
| `WalletInterface` (interface) | `WalletInterface` (async trait) |
| `ProtoWallet` (class) | `ProtoWallet` (struct, implements `WalletInterface`) |
| `Wallet` (class) | `WalletClient` (struct, multi-substrate) |
| `validationHelpers.ts` functions | `validation` module functions |

## Internal Dependencies

The wallet module uses:
- `PrivateKey`, `PublicKey`, `SymmetricKey`, `Signature` from primitives module
- `sha256`, `sha256_hmac` from `primitives::hash`
- `Schnorr`, `SchnorrProof` from `primitives::bsv::schnorr` for counterparty linkage ZK proofs
- `derive_child`, `derive_shared_secret` methods on `PrivateKey`/`PublicKey` for BRC-42 derivation
- `subtle` crate for constant-time comparison (HMAC verification, `key_deriver::verify_hmac_tag`)
- `async_trait` crate for async trait methods (`WalletInterface`)
- `serde` / `serde_json` for serialization of types (JSON API compatibility)
- `hex` crate for hex encoding/decoding in serde helpers
- `reqwest` (optional, with `http` feature) for HTTP substrate communication

## Testing

Run wallet module tests:

```bash
cargo test wallet --features wallet         # Core wallet tests
cargo test wallet --features wallet,http    # Including HTTP client tests
cargo test --features full -- wallet        # As part of full suite
```

Each source file includes inline `#[cfg(test)]` modules covering type conversions, hex serde roundtrips, key derivation determinism, two-party agreement, LRU cache eviction, ProtoWallet crypto operations, Schnorr proof generation/verification, and all validation boundary cases.

## Implementation Notes

- **Timestamp generation**: `proto_wallet.rs` implements ISO 8601 timestamps without external crate dependencies (uses `std::time::SystemTime` with manual date calculation)
- **Thread safety**: `CachedKeyDeriver` uses `std::sync::Mutex` (not `tokio::sync::Mutex`) since lock hold times are very short
- **Clone**: `ProtoWallet` wraps `CachedKeyDeriver` in `Arc` for cheap cloning
- **Debug**: Both `ProtoWallet` and `KeyDeriver` implement custom `Debug` that shows only the identity key hex (never the private key)
- **Serde**: `Counterparty` does not implement `Serialize`/`Deserialize` directly - it's converted to/from strings and `PublicKey` at API boundaries
- **Outpoint serde**: Custom `Serialize`/`Deserialize` impl accepts both string format (`"txid.vout"`) and object format (`{"txid":"...","vout":N}`)

## Related Documentation

- `substrates/CLAUDE.md` - Transport substrate implementations
- `wire/CLAUDE.md` - Wire protocol encoding/decoding
- `../primitives/CLAUDE.md` - Cryptographic primitives
- `../primitives/ec/CLAUDE.md` - EC operations and BRC-42 derivation

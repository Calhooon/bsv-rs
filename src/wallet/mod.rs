//! Wallet module for BSV SDK.
//!
//! This module provides the wallet interface, key derivation, and cryptographic
//! operations for interacting with BSV wallets. It implements the BRC-42 key
//! derivation standard and provides types compatible with the TypeScript and Go SDKs.
//!
//! # Overview
//!
//! The wallet module is organized into the following components:
//!
//! - **Types**: Core wallet type definitions including security levels, protocols,
//!   counterparty identifiers, transaction types, and certificate structures.
//!
//! - **Key Derivation**: BRC-42 compliant key derivation using [`KeyDeriver`] and
//!   the cached variant [`CachedKeyDeriver`] for optimized performance.
//!
//! - **ProtoWallet**: Foundational cryptographic operations using [`ProtoWallet`],
//!   which provides signing, encryption, HMAC, and key linkage revelation.
//!
//! - **Validation**: Comprehensive input validation helpers in the [`validation`] module.
//!
//! # Key Derivation
//!
//! BRC-42 key derivation allows two parties to independently derive corresponding
//! key pairs. This enables secure, deterministic key generation for various protocols
//! without requiring a shared secret to be transmitted.
//!
//! ```rust
//! use bsv_sdk::wallet::{KeyDeriver, Protocol, SecurityLevel, Counterparty};
//! use bsv_sdk::primitives::PrivateKey;
//!
//! // Create derivers for Alice and Bob
//! let alice_deriver = KeyDeriver::new(Some(PrivateKey::random()));
//! let bob_deriver = KeyDeriver::new(Some(PrivateKey::random()));
//!
//! // Define a protocol
//! let protocol = Protocol::new(SecurityLevel::App, "payment system");
//! let key_id = "invoice-12345";
//!
//! // Bob creates a counterparty reference to Alice
//! let alice_counterparty = Counterparty::Other(alice_deriver.identity_key());
//!
//! // Bob derives his private key
//! let bob_priv = bob_deriver.derive_private_key(&protocol, key_id, &alice_counterparty).unwrap();
//!
//! // Bob's public key can be derived by either party
//! let bob_pub_self = bob_deriver.derive_public_key(&protocol, key_id, &alice_counterparty, true).unwrap();
//!
//! // They match
//! assert_eq!(bob_priv.public_key().to_compressed(), bob_pub_self.to_compressed());
//! ```
//!
//! # ProtoWallet
//!
//! [`ProtoWallet`] provides foundational cryptographic operations without blockchain interaction:
//!
//! ```rust
//! use bsv_sdk::wallet::{ProtoWallet, Protocol, SecurityLevel, CreateSignatureArgs};
//! use bsv_sdk::primitives::PrivateKey;
//!
//! // Create a ProtoWallet
//! let wallet = ProtoWallet::new(Some(PrivateKey::random()));
//!
//! // Sign data
//! let signature = wallet.create_signature(CreateSignatureArgs {
//!     data: Some(b"Hello, BSV!".to_vec()),
//!     hash_to_directly_sign: None,
//!     protocol_id: Protocol::new(SecurityLevel::App, "signing app"),
//!     key_id: "sig-1".to_string(),
//!     counterparty: None,
//! }).unwrap();
//! ```
//!
//! # Caching
//!
//! For performance-critical applications, use [`CachedKeyDeriver`]:
//!
//! ```rust
//! use bsv_sdk::wallet::{CachedKeyDeriver, CacheConfig, Protocol, SecurityLevel, Counterparty, KeyDeriverApi};
//! use bsv_sdk::primitives::PrivateKey;
//!
//! // Create with custom cache size
//! let config = CacheConfig { max_size: 500 };
//! let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), Some(config));
//!
//! // Use like KeyDeriver - results are cached automatically
//! let protocol = Protocol::new(SecurityLevel::App, "my application");
//! let key1 = deriver.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap();
//! let key2 = deriver.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap(); // From cache
//! ```
//!
//! # Security Levels
//!
//! The [`SecurityLevel`] enum defines the level of user interaction required:
//!
//! - **Level 0 (Silent)**: No user interaction; keys derived silently
//! - **Level 1 (App)**: User approval required per application
//! - **Level 2 (Counterparty)**: User approval required per counterparty per application
//!
//! # Feature Flag
//!
//! This module requires the `wallet` feature flag:
//!
//! ```toml
//! [dependencies]
//! bsv-sdk = { version = "0.2", features = ["wallet"] }
//! ```

mod cached_key_deriver;
mod key_deriver;
mod proto_wallet;
pub mod types;
pub mod validation;
pub mod wire;

// Re-export all public types
pub use cached_key_deriver::{CacheConfig, CachedKeyDeriver};
pub use key_deriver::{KeyDeriver, KeyDeriverApi};
pub use proto_wallet::{
    // Argument types
    CreateHmacArgs,
    CreateHmacResult,
    CreateSignatureArgs,
    CreateSignatureResult,
    DecryptArgs,
    DecryptResult,
    EncryptArgs,
    EncryptResult,
    GetPublicKeyArgs,
    GetPublicKeyResult,
    // ProtoWallet
    ProtoWallet,
    RevealCounterpartyKeyLinkageArgs,
    RevealCounterpartyKeyLinkageResult as ProtoWalletRevealCounterpartyResult,
    RevealSpecificKeyLinkageArgs,
    RevealSpecificKeyLinkageResult as ProtoWalletRevealSpecificResult,
    VerifyHmacArgs,
    VerifyHmacResult,
    VerifySignatureArgs,
    VerifySignatureResult,
};
pub use types::{
    // Validation helpers
    validate_description,
    validate_key_id,
    validate_protocol_name,
    validate_satoshis,
    // Certificate types
    AcquisitionProtocol,
    // Action status
    ActionStatus,

    Certificate,
    // Security and protocols
    Counterparty,
    // Create action types
    CreateActionInput,
    CreateActionOptions,
    CreateActionOutput,
    CreateActionResult,
    // Key linkage
    KeyLinkageResult,
    KeyringRevealer,

    // Primitive types
    Network,
    // Outpoint
    Outpoint,

    Protocol,
    RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageResult,

    // Action results
    ReviewActionResult,
    ReviewActionResultStatus,
    SatoshiValue,
    SecurityLevel,

    SendWithResult,
    SendWithResultStatus,
    SignableTransaction,

    TrustSelf,

    TxId,
    // Wallet action types
    WalletAction,
    WalletActionInput,
    WalletActionOutput,
    WalletOutput,

    MAX_SATOSHIS,
};

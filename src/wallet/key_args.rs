//! The arguments and results of the seven key-related calls (getPublicKey,
//! encrypt, decrypt, createHmac, verifyHmac, createSignature, verifySignature),
//! moved out of `proto_wallet.rs`.
//!
//! Each args type carries the reference's `privileged`, `privilegedReason`
//! and `seekPermission` (`WalletEncryptionArgs`, `Wallet.interfaces.ts:663-672`
//! at `ts-stack@edf6e03`; BRC-100 `wallet/0100.md`), an absent field the
//! reference's default: not privileged, no reason, permission sought (#193).
//! A literal takes the three fields or `..Default::default()`.

use super::types::{Counterparty, Protocol, SecurityLevel};

/// The three permission fields every key-related args type ends with, and its
/// `Default`: the protocol the reference writes for a getPublicKey that names
/// none (`[SecurityLevels.Silent, 'default']`, `WalletWireTransceiver.ts:761`),
/// an empty key ID, every option absent.
macro_rules! key_args {
    ($(#[$doc:meta])* pub struct $name:ident { $($(#[$fdoc:meta])* pub $field:ident: $ty:ty = $default:expr,)* }) => {
        $(#[$doc])*
        #[derive(Debug, Clone)]
        pub struct $name {
            $($(#[$fdoc])* pub $field: $ty,)*
            /// Whether the request is for the privileged keyring (`privileged`,
            /// absent read as false).
            pub privileged: Option<bool>,
            /// Why privileged access is asked (`privilegedReason`, 5 to 50 bytes
            /// in the reference's validator; required when `privileged`).
            pub privileged_reason: Option<String>,
            /// Whether to seek the user's permission where it is needed
            /// (`seekPermission`, absent read as true; false fails rather than
            /// asks).
            pub seek_permission: Option<bool>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    $($field: $default,)*
                    privileged: None,
                    privileged_reason: None,
                    seek_permission: None,
                }
            }
        }
    };
}

pub(crate) fn default_protocol() -> Protocol {
    Protocol::new(SecurityLevel::Silent, "default")
}

key_args! {
    /// Arguments for getting a public key.
    pub struct GetPublicKeyArgs {
        /// If true, return the identity (root) public key.
        pub identity_key: bool = false,
        /// The protocol identifier (required if identity_key is false).
        pub protocol_id: Option<Protocol> = None,
        /// The key identifier (required if identity_key is false).
        pub key_id: Option<String> = None,
        /// The counterparty for derivation.
        pub counterparty: Option<Counterparty> = None,
        /// If true, derive the key for self; otherwise for counterparty.
        pub for_self: Option<bool> = None,
    }
}

/// Result of getting a public key.
#[derive(Debug, Clone)]
pub struct GetPublicKeyResult {
    /// The public key as a hex string.
    pub public_key: String,
}

key_args! {
    /// Arguments for encryption.
    pub struct EncryptArgs {
        /// The plaintext data to encrypt.
        pub plaintext: Vec<u8> = Vec::new(),
        /// The protocol identifier.
        pub protocol_id: Protocol = default_protocol(),
        /// The key identifier.
        pub key_id: String = String::new(),
        /// The counterparty for key derivation.
        pub counterparty: Option<Counterparty> = None,
    }
}

/// Result of encryption.
#[derive(Debug, Clone)]
pub struct EncryptResult {
    /// The encrypted ciphertext (IV + ciphertext + auth tag).
    pub ciphertext: Vec<u8>,
}

key_args! {
    /// Arguments for decryption.
    pub struct DecryptArgs {
        /// The ciphertext to decrypt (IV + ciphertext + auth tag).
        pub ciphertext: Vec<u8> = Vec::new(),
        /// The protocol identifier.
        pub protocol_id: Protocol = default_protocol(),
        /// The key identifier.
        pub key_id: String = String::new(),
        /// The counterparty for key derivation.
        pub counterparty: Option<Counterparty> = None,
    }
}

/// Result of decryption.
#[derive(Debug, Clone)]
pub struct DecryptResult {
    /// The decrypted plaintext.
    pub plaintext: Vec<u8>,
}

key_args! {
    /// Arguments for creating an HMAC.
    pub struct CreateHmacArgs {
        /// The data to create HMAC for.
        pub data: Vec<u8> = Vec::new(),
        /// The protocol identifier.
        pub protocol_id: Protocol = default_protocol(),
        /// The key identifier.
        pub key_id: String = String::new(),
        /// The counterparty for key derivation.
        pub counterparty: Option<Counterparty> = None,
    }
}

/// Result of creating an HMAC.
#[derive(Debug, Clone)]
pub struct CreateHmacResult {
    /// The HMAC (32 bytes).
    pub hmac: [u8; 32],
}

key_args! {
    /// Arguments for verifying an HMAC.
    pub struct VerifyHmacArgs {
        /// The data that was HMACed.
        pub data: Vec<u8> = Vec::new(),
        /// The HMAC to verify.
        pub hmac: [u8; 32] = [0; 32],
        /// The protocol identifier.
        pub protocol_id: Protocol = default_protocol(),
        /// The key identifier.
        pub key_id: String = String::new(),
        /// The counterparty for key derivation.
        pub counterparty: Option<Counterparty> = None,
    }
}

/// Result of verifying an HMAC.
#[derive(Debug, Clone)]
pub struct VerifyHmacResult {
    /// True if the HMAC is valid.
    pub valid: bool,
}

key_args! {
    /// Arguments for creating a signature.
    pub struct CreateSignatureArgs {
        /// The data to sign (will be SHA-256 hashed if hash_to_directly_sign is None).
        pub data: Option<Vec<u8>> = None,
        /// A pre-computed hash to sign directly.
        pub hash_to_directly_sign: Option<[u8; 32]> = None,
        /// The protocol identifier.
        pub protocol_id: Protocol = default_protocol(),
        /// The key identifier.
        pub key_id: String = String::new(),
        /// The counterparty for key derivation.
        pub counterparty: Option<Counterparty> = None,
    }
}

/// Result of creating a signature.
#[derive(Debug, Clone)]
pub struct CreateSignatureResult {
    /// The DER-encoded signature.
    pub signature: Vec<u8>,
}

key_args! {
    /// Arguments for verifying a signature.
    pub struct VerifySignatureArgs {
        /// The data that was signed.
        pub data: Option<Vec<u8>> = None,
        /// The pre-computed hash that was signed.
        pub hash_to_directly_verify: Option<[u8; 32]> = None,
        /// The DER-encoded signature to verify.
        pub signature: Vec<u8> = Vec::new(),
        /// The protocol identifier.
        pub protocol_id: Protocol = default_protocol(),
        /// The key identifier.
        pub key_id: String = String::new(),
        /// The counterparty for key derivation.
        pub counterparty: Option<Counterparty> = None,
        /// If true, verify with own derived public key; otherwise with counterparty's.
        pub for_self: Option<bool> = None,
    }
}

/// Result of verifying a signature.
#[derive(Debug, Clone)]
pub struct VerifySignatureResult {
    /// True if the signature is valid.
    pub valid: bool,
}

//! Bitcoin address (P2PKH) representation.
//!
//! This module provides the [`Address`] struct for working with Bitcoin P2PKH addresses,
//! including parsing from strings, creating from public keys or hashes, and encoding
//! to Base58Check format.
//!
//! # Example
//!
//! ```rust
//! use bsv_sdk::script::Address;
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! let private_key = PrivateKey::from_hex(
//!     "0000000000000000000000000000000000000000000000000000000000000001",
//! ).unwrap();
//! let address = Address::new_from_public_key(&private_key.public_key(), true).unwrap();
//! assert_eq!(address.to_string(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
//! ```

use std::fmt;
use std::str::FromStr;

use crate::primitives::ec::PublicKey;
use crate::primitives::encoding::{from_base58_check, to_base58_check};
use crate::primitives::hash::hash160;
use crate::{Error, Result};

/// Mainnet P2PKH address version byte.
const MAINNET_PREFIX: u8 = 0x00;

/// Testnet P2PKH address version byte.
const TESTNET_PREFIX: u8 = 0x6f;

/// A Bitcoin P2PKH address.
///
/// Contains the 20-byte public key hash and the network prefix byte.
/// Supports both mainnet (prefix `0x00`, addresses start with `1`) and
/// testnet (prefix `0x6f`, addresses start with `m` or `n`).
///
/// # Cross-SDK Compatibility
///
/// This implementation is compatible with the Go SDK's `script.Address` and
/// the TypeScript SDK's address handling. The same address strings are produced
/// for the same public keys across all three SDKs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The 20-byte RIPEMD160(SHA256(pubkey)) hash.
    pub_key_hash: [u8; 20],
    /// The network version prefix byte (0x00 for mainnet, 0x6f for testnet).
    prefix: u8,
}

impl Address {
    /// Creates an Address from a Base58Check encoded address string.
    ///
    /// Validates the checksum and ensures the address uses a supported version
    /// prefix (mainnet `0x00` or testnet `0x6f`).
    ///
    /// # Arguments
    ///
    /// * `address` - A P2PKH address string
    ///
    /// # Returns
    ///
    /// The parsed Address, or an error if the string is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::script::Address;
    ///
    /// let addr = Address::new_from_string("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").unwrap();
    /// assert_eq!(addr.to_string(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    /// ```
    pub fn new_from_string(address: &str) -> Result<Self> {
        let (version, payload) = from_base58_check(address)?;

        if version.len() != 1 {
            return Err(Error::InvalidAddress(format!(
                "invalid address version length for '{}'",
                address
            )));
        }

        let prefix = version[0];
        match prefix {
            MAINNET_PREFIX | TESTNET_PREFIX => {}
            _ => {
                return Err(Error::UnsupportedAddress(address.to_string()));
            }
        }

        if payload.len() != 20 {
            return Err(Error::InvalidAddressLength(address.to_string()));
        }

        let mut pub_key_hash = [0u8; 20];
        pub_key_hash.copy_from_slice(&payload);

        Ok(Self {
            pub_key_hash,
            prefix,
        })
    }

    /// Creates an Address from a raw 20-byte public key hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 20-byte public key hash (RIPEMD160(SHA256(pubkey)))
    /// * `mainnet` - If true, creates a mainnet address; otherwise testnet
    ///
    /// # Returns
    ///
    /// The Address, or an error if the hash is not 20 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::script::Address;
    ///
    /// let hash = [0u8; 20];
    /// let addr = Address::new_from_public_key_hash(&hash, true).unwrap();
    /// ```
    pub fn new_from_public_key_hash(hash: &[u8], mainnet: bool) -> Result<Self> {
        if hash.len() != 20 {
            return Err(Error::InvalidDataLength {
                expected: 20,
                actual: hash.len(),
            });
        }

        let mut pub_key_hash = [0u8; 20];
        pub_key_hash.copy_from_slice(hash);

        let prefix = if mainnet {
            MAINNET_PREFIX
        } else {
            TESTNET_PREFIX
        };

        Ok(Self {
            pub_key_hash,
            prefix,
        })
    }

    /// Creates an Address from a PublicKey.
    ///
    /// Computes the hash160 (RIPEMD160(SHA256(compressed_pubkey))) and creates
    /// a mainnet or testnet address.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to derive the address from
    /// * `mainnet` - If true, creates a mainnet address; otherwise testnet
    ///
    /// # Returns
    ///
    /// The Address.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::script::Address;
    /// use bsv_sdk::primitives::ec::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// let addr = Address::new_from_public_key(&key.public_key(), true).unwrap();
    /// ```
    pub fn new_from_public_key(public_key: &PublicKey, mainnet: bool) -> Result<Self> {
        let h = hash160(&public_key.to_compressed());
        Self::new_from_public_key_hash(&h, mainnet)
    }

    /// Returns the 20-byte public key hash.
    ///
    /// This is the RIPEMD160(SHA256(compressed_pubkey)) value that is the same
    /// regardless of the network type (mainnet or testnet).
    pub fn public_key_hash(&self) -> &[u8] {
        &self.pub_key_hash
    }

    /// Returns the network prefix byte.
    ///
    /// - `0x00` for mainnet
    /// - `0x6f` for testnet
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Returns true if this is a mainnet address.
    pub fn is_mainnet(&self) -> bool {
        self.prefix == MAINNET_PREFIX
    }

    /// Validates whether a string is a valid P2PKH address.
    ///
    /// Returns true if the address can be parsed successfully with a valid
    /// checksum and a supported version prefix.
    ///
    /// # Arguments
    ///
    /// * `address` - The address string to validate
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::script::Address;
    ///
    /// assert!(Address::is_valid_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));
    /// assert!(!Address::is_valid_address("invalid"));
    /// ```
    pub fn is_valid_address(address: &str) -> bool {
        Self::new_from_string(address).is_ok()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            to_base58_check(&self.pub_key_hash, &[self.prefix])
        )
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new_from_string(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::ec::PrivateKey;
    use crate::primitives::encoding::{from_hex, to_hex};

    const TEST_PUBLIC_KEY_HEX: &str =
        "026cf33373a9f3f6c676b75b543180703df225f7f8edbffedc417718a8ad4e89ce";
    const TEST_PUBLIC_KEY_HASH: &str = "00ac6144c4db7b5790f343cf0477a65fb8a02eb7";

    #[test]
    fn test_new_from_string_mainnet() {
        let address_str = "1E7ucTTWRTahCyViPhxSMor2pj4VGQdFMr";
        let addr = Address::new_from_string(address_str).unwrap();

        assert_eq!(
            to_hex(addr.public_key_hash()),
            "8fe80c75c9560e8b56ed64ea3c26e18d2c52211b"
        );
        assert_eq!(addr.to_string(), address_str);
        assert!(addr.is_mainnet());
    }

    #[test]
    fn test_new_from_string_testnet() {
        let address_str = "mtdruWYVEV1wz5yL7GvpBj4MgifCB7yhPd";
        let addr = Address::new_from_string(address_str).unwrap();

        assert_eq!(
            to_hex(addr.public_key_hash()),
            "8fe80c75c9560e8b56ed64ea3c26e18d2c52211b"
        );
        assert_eq!(addr.to_string(), address_str);
        assert!(!addr.is_mainnet());
    }

    #[test]
    fn test_new_from_string_short_address() {
        let result = Address::new_from_string("ADD8E55");
        assert!(result.is_err());
    }

    #[test]
    fn test_new_from_string_unsupported_address() {
        let result = Address::new_from_string("27BvY7rFguYQvEL872Y7Fo77Y3EBApC2EK");
        assert!(result.is_err());
    }

    #[test]
    fn test_new_from_public_key_hash_mainnet() {
        let hash = from_hex(TEST_PUBLIC_KEY_HASH).unwrap();
        let addr = Address::new_from_public_key_hash(&hash, true).unwrap();

        assert_eq!(to_hex(addr.public_key_hash()), TEST_PUBLIC_KEY_HASH);
        assert_eq!(addr.to_string(), "114ZWApV4EEU8frr7zygqQcB1V2BodGZuS");
    }

    #[test]
    fn test_new_from_public_key_hash_testnet() {
        let hash = from_hex(TEST_PUBLIC_KEY_HASH).unwrap();
        let addr = Address::new_from_public_key_hash(&hash, false).unwrap();

        assert_eq!(to_hex(addr.public_key_hash()), TEST_PUBLIC_KEY_HASH);
        assert_eq!(addr.to_string(), "mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk");
    }

    #[test]
    fn test_new_from_public_key_hash_invalid_length() {
        let result = Address::new_from_public_key_hash(&[0u8; 19], true);
        assert!(result.is_err());

        let result = Address::new_from_public_key_hash(&[0u8; 21], true);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_from_public_key_mainnet() {
        let pubkey = PublicKey::from_hex(TEST_PUBLIC_KEY_HEX).unwrap();
        let addr = Address::new_from_public_key(&pubkey, true).unwrap();

        assert_eq!(to_hex(addr.public_key_hash()), TEST_PUBLIC_KEY_HASH);
        assert_eq!(addr.to_string(), "114ZWApV4EEU8frr7zygqQcB1V2BodGZuS");
    }

    #[test]
    fn test_new_from_public_key_testnet() {
        let pubkey = PublicKey::from_hex(TEST_PUBLIC_KEY_HEX).unwrap();
        let addr = Address::new_from_public_key(&pubkey, false).unwrap();

        assert_eq!(to_hex(addr.public_key_hash()), TEST_PUBLIC_KEY_HASH);
        assert_eq!(addr.to_string(), "mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk");
    }

    #[test]
    fn test_roundtrip_mainnet() {
        let address_str = "114ZWApV4EEU8frr7zygqQcB1V2BodGZuS";
        let addr = Address::new_from_string(address_str).unwrap();
        assert_eq!(addr.to_string(), address_str);
    }

    #[test]
    fn test_roundtrip_testnet() {
        let address_str = "mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk";
        let addr = Address::new_from_string(address_str).unwrap();
        assert_eq!(addr.to_string(), address_str);
    }

    #[test]
    fn test_from_str_trait() {
        let addr: Address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH".parse().unwrap();
        assert!(addr.is_mainnet());
    }

    #[test]
    fn test_display_trait() {
        let addr = Address::new_from_string("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").unwrap();
        let displayed = format!("{}", addr);
        assert_eq!(displayed, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_is_valid_address() {
        assert!(Address::is_valid_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));
        assert!(Address::is_valid_address("114ZWApV4EEU8frr7zygqQcB1V2BodGZuS"));
        assert!(Address::is_valid_address("mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk"));
        assert!(!Address::is_valid_address("invalid"));
        assert!(!Address::is_valid_address(""));
    }

    #[test]
    fn test_invalid_checksum() {
        // Modify last character to break checksum
        let result = Address::new_from_string("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3");
        assert!(result.is_err());
    }

    #[test]
    fn test_generator_point_address() {
        // Known test vector: generator point compressed public key
        let pubkey = PublicKey::from_hex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let addr = Address::new_from_public_key(&pubkey, true).unwrap();
        assert_eq!(addr.to_string(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_private_key_address_consistency() {
        // Verify Address matches PublicKey::to_address()
        let private_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let pubkey = private_key.public_key();

        let addr_from_address = Address::new_from_public_key(&pubkey, true).unwrap();
        let addr_from_pubkey = pubkey.to_address();

        assert_eq!(addr_from_address.to_string(), addr_from_pubkey);
    }

    #[test]
    fn test_locking_script_to_address() {
        use crate::script::templates::P2PKH;
        use crate::script::template::ScriptTemplate;

        let private_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let pubkey = private_key.public_key();
        let pubkey_hash = pubkey.hash160();

        // Create P2PKH locking script
        let locking = P2PKH::new().lock(&pubkey_hash).unwrap();

        // Extract address from locking script
        let addr = locking.to_address();
        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert_eq!(addr.to_string(), pubkey.to_address());
    }

    #[test]
    fn test_locking_script_to_address_non_p2pkh() {
        use crate::script::LockingScript;

        // OP_RETURN script
        let op_return = LockingScript::from_asm("OP_RETURN").unwrap();
        assert!(op_return.to_address().is_none());

        // P2SH script
        let p2sh = LockingScript::from_hex(
            "a914000000000000000000000000000000000000000087",
        )
        .unwrap();
        assert!(p2sh.to_address().is_none());

        // Empty script
        let empty = LockingScript::new();
        assert!(empty.to_address().is_none());
    }
}

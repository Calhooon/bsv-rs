//! BIP-32 Hierarchical Deterministic (HD) Key Derivation.
//!
//! This module implements [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//! for generating hierarchical deterministic wallets.
//!
//! # Features
//!
//! - Generate master keys from seeds
//! - Derive child keys (both normal and hardened)
//! - Parse and serialize extended keys (xprv/xpub, tprv/tpub)
//! - Convert between private and public extended keys ("neutering")
//!
//! # Examples
//!
//! ```rust
//! use bsv_sdk::compat::bip32::{ExtendedKey, Network, HARDENED_KEY_START};
//!
//! // Generate master key from seed
//! let seed = [0u8; 32];
//! let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
//!
//! // Derive child keys
//! let child = master.derive_child(0).unwrap();
//! let hardened = master.derive_child(0 + HARDENED_KEY_START).unwrap();
//!
//! // Derive using path notation
//! let derived = master.derive_path("m/44'/0'/0'/0/0").unwrap();
//!
//! // Serialize to xprv/xpub format
//! let xprv = master.to_string();
//! assert!(xprv.starts_with("xprv"));
//! ```

use std::cmp::Ordering;

use crate::error::{Error, Result};
use crate::primitives::ec::{PrivateKey, PublicKey};
use crate::primitives::encoding::{from_base58, to_base58};
use crate::primitives::hash::{hash160, sha256d, sha512_hmac};
use crate::primitives::BigNumber;

/// Start index for hardened key derivation (2^31).
pub const HARDENED_KEY_START: u32 = 0x80000000;

/// Minimum seed length in bytes.
pub const MIN_SEED_BYTES: usize = 16;

/// Maximum seed length in bytes.
pub const MAX_SEED_BYTES: usize = 64;

/// Recommended seed length in bytes.
pub const RECOMMENDED_SEED_LEN: usize = 32;

/// Serialized extended key length (without checksum).
const SERIALIZED_KEY_LEN: usize = 78;

/// Master key derivation constant.
const MASTER_KEY: &[u8] = b"Bitcoin seed";

// Version bytes for extended keys
const MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // xprv
const MAINNET_PUBLIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E]; // xpub
const TESTNET_PRIVATE: [u8; 4] = [0x04, 0x35, 0x83, 0x94]; // tprv
const TESTNET_PUBLIC: [u8; 4] = [0x04, 0x35, 0x87, 0xCF]; // tpub

/// Network type for extended key version bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin mainnet (xprv/xpub)
    Mainnet,
    /// Bitcoin testnet (tprv/tpub)
    Testnet,
}

/// BIP-32 Extended Key.
///
/// An extended key combines a key (private or public) with a chain code
/// to enable deterministic key derivation.
#[derive(Clone)]
pub struct ExtendedKey {
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    chain_code: [u8; 32],
    key: [u8; 33], // 0x00 || privkey (33 bytes) or compressed pubkey (33 bytes)
    is_private: bool,
}

impl ExtendedKey {
    /// Creates a new master extended private key from a seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed bytes (16-64 bytes, 32 recommended)
    /// * `network` - The network to use for version bytes
    ///
    /// # Returns
    ///
    /// A new master extended private key
    ///
    /// # Errors
    ///
    /// Returns an error if the seed length is invalid or the derived key is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip32::{ExtendedKey, Network};
    ///
    /// let seed = [0u8; 32];
    /// let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
    /// assert!(master.is_private());
    /// ```
    pub fn new_master(seed: &[u8], network: Network) -> Result<Self> {
        // Validate seed length
        if seed.len() < MIN_SEED_BYTES || seed.len() > MAX_SEED_BYTES {
            return Err(Error::InvalidExtendedKey(format!(
                "Seed length must be between {} and {} bytes, got {}",
                MIN_SEED_BYTES,
                MAX_SEED_BYTES,
                seed.len()
            )));
        }

        // I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)
        let hmac = sha512_hmac(MASTER_KEY, seed);

        // Split I into IL and IR
        let (il, ir) = hmac.split_at(32);

        // IL is the master secret key, IR is the master chain code
        let secret_key: [u8; 32] = il.try_into().unwrap();
        let chain_code: [u8; 32] = ir.try_into().unwrap();

        // Verify the key is valid (not zero and less than curve order)
        let key_num = BigNumber::from_bytes_be(&secret_key);
        let order = BigNumber::secp256k1_order();
        if key_num.is_zero() || key_num.compare(&order) != Ordering::Less {
            return Err(Error::InvalidExtendedKey(
                "Derived master key is invalid".to_string(),
            ));
        }

        // Build the key data: 0x00 || secret_key
        let mut key = [0u8; 33];
        key[0] = 0x00;
        key[1..33].copy_from_slice(&secret_key);

        let version = match network {
            Network::Mainnet => MAINNET_PRIVATE,
            Network::Testnet => TESTNET_PRIVATE,
        };

        Ok(Self {
            version,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
            chain_code,
            key,
            is_private: true,
        })
    }

    /// Parses an extended key from its Base58Check string representation.
    ///
    /// # Arguments
    ///
    /// * `s` - The Base58Check encoded extended key (xprv/xpub/tprv/tpub)
    ///
    /// # Returns
    ///
    /// The parsed extended key
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip32::ExtendedKey;
    ///
    /// let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    /// let key = ExtendedKey::from_string(xprv).unwrap();
    /// assert!(key.is_private());
    /// ```
    pub fn from_string(s: &str) -> Result<Self> {
        let decoded = from_base58(s)?;

        // Should be 78 bytes (serialized) + 4 bytes (checksum)
        if decoded.len() != SERIALIZED_KEY_LEN + 4 {
            return Err(Error::InvalidExtendedKey(format!(
                "Invalid length: expected {}, got {}",
                SERIALIZED_KEY_LEN + 4,
                decoded.len()
            )));
        }

        // Split payload and checksum
        let payload = &decoded[..SERIALIZED_KEY_LEN];
        let checksum = &decoded[SERIALIZED_KEY_LEN..];

        // Verify checksum
        let expected_checksum = sha256d(payload);
        if checksum != &expected_checksum[..4] {
            return Err(Error::InvalidChecksum);
        }

        // Parse fields
        let version: [u8; 4] = payload[0..4].try_into().unwrap();
        let depth = payload[4];
        let parent_fingerprint: [u8; 4] = payload[5..9].try_into().unwrap();
        let child_number = u32::from_be_bytes(payload[9..13].try_into().unwrap());
        let chain_code: [u8; 32] = payload[13..45].try_into().unwrap();
        let key_data: [u8; 33] = payload[45..78].try_into().unwrap();

        // Determine if private or public key
        let is_private = key_data[0] == 0x00;

        // Validate key
        if is_private {
            // Private key: first byte is 0x00, remaining 32 bytes are the key
            let key_bytes = &key_data[1..33];
            let key_num = BigNumber::from_bytes_be(key_bytes);
            let order = BigNumber::secp256k1_order();
            if key_num.is_zero() || key_num.compare(&order) != Ordering::Less {
                return Err(Error::InvalidExtendedKey(
                    "Invalid private key value".to_string(),
                ));
            }
        } else {
            // Public key: 33 bytes compressed public key (02 or 03 prefix)
            if key_data[0] != 0x02 && key_data[0] != 0x03 {
                return Err(Error::InvalidExtendedKey(
                    "Invalid public key prefix".to_string(),
                ));
            }
            // Validate the public key is on the curve
            PublicKey::from_bytes(&key_data)?;
        }

        Ok(Self {
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            key: key_data,
            is_private,
        })
    }

    /// Serializes the extended key to Base58Check format.
    ///
    /// # Returns
    ///
    /// The Base58Check encoded string (xprv/xpub/tprv/tpub)
    fn serialize(&self) -> String {
        let mut data = Vec::with_capacity(SERIALIZED_KEY_LEN + 4);

        // version (4) || depth (1) || parent fingerprint (4) ||
        // child number (4) || chain code (32) || key data (33)
        data.extend_from_slice(&self.version);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number.to_be_bytes());
        data.extend_from_slice(&self.chain_code);

        if self.is_private {
            // For private keys: 0x00 || key (already in this format)
            data.extend_from_slice(&self.key);
        } else {
            // For public keys: compressed pubkey
            data.extend_from_slice(&self.key);
        }

        // Add checksum
        let checksum = sha256d(&data);
        data.extend_from_slice(&checksum[..4]);

        to_base58(&data)
    }

    /// Derives a child extended key.
    ///
    /// # Arguments
    ///
    /// * `index` - The child index. Use `index + HARDENED_KEY_START` for hardened derivation.
    ///
    /// # Returns
    ///
    /// The derived child extended key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Attempting hardened derivation from a public key
    /// - The derived key is invalid
    /// - Maximum depth (255) exceeded
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip32::{ExtendedKey, Network, HARDENED_KEY_START};
    ///
    /// let seed = [0u8; 32];
    /// let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
    ///
    /// // Normal derivation
    /// let child = master.derive_child(0).unwrap();
    ///
    /// // Hardened derivation
    /// let hardened = master.derive_child(0 + HARDENED_KEY_START).unwrap();
    /// ```
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        // Check depth limit
        if self.depth == 255 {
            return Err(Error::InvalidExtendedKey(
                "Cannot derive beyond depth 255".to_string(),
            ));
        }

        let is_hardened = index >= HARDENED_KEY_START;

        // Hardened derivation requires private key
        if is_hardened && !self.is_private {
            return Err(Error::HardenedFromPublic);
        }

        // Build HMAC data
        let mut data = Vec::with_capacity(37);

        if is_hardened {
            // Hardened: 0x00 || private_key || index
            data.push(0x00);
            data.extend_from_slice(&self.key[1..33]); // Skip leading 0x00
        } else {
            // Normal: public_key || index
            let pubkey_bytes = self.public_key_bytes()?;
            data.extend_from_slice(&pubkey_bytes);
        }
        data.extend_from_slice(&index.to_be_bytes());

        // I = HMAC-SHA512(chain_code, data)
        let hmac = sha512_hmac(&self.chain_code, &data);
        let (il, ir) = hmac.split_at(32);

        let il_num = BigNumber::from_bytes_be(il);
        let order = BigNumber::secp256k1_order();

        // Validate IL is valid (< curve order)
        if il_num.compare(&order) != Ordering::Less {
            return Err(Error::InvalidExtendedKey(
                "Derived key is invalid".to_string(),
            ));
        }

        // Child chain code is IR
        let child_chain_code: [u8; 32] = ir.try_into().unwrap();

        // Derive child key
        let (child_key, child_is_private) = if self.is_private {
            // Private key derivation: child_key = (IL + parent_key) mod n
            let parent_key_num = BigNumber::from_bytes_be(&self.key[1..33]);
            let child_key_num = il_num.add(&parent_key_num).modulo(&order);

            if child_key_num.is_zero() {
                return Err(Error::InvalidExtendedKey(
                    "Derived key is invalid".to_string(),
                ));
            }

            let mut key = [0u8; 33];
            key[0] = 0x00;
            let key_bytes = child_key_num.to_bytes_be(32);
            key[1..33].copy_from_slice(&key_bytes);

            (key, true)
        } else {
            // Public key derivation: child_key = point(IL) + parent_key
            let parent_pubkey = PublicKey::from_bytes(&self.key)?;

            // Compute G * IL
            let il_bytes: [u8; 32] = il.try_into().unwrap();
            let offset_point = PublicKey::from_scalar_mul_generator(&il_bytes)?;

            // Add to parent public key
            let child_pubkey = parent_pubkey.add(&offset_point)?;

            (child_pubkey.to_compressed(), false)
        };

        // Parent fingerprint is first 4 bytes of HASH160(parent_pubkey)
        let parent_pubkey = self.public_key_bytes()?;
        let parent_hash = hash160(&parent_pubkey);
        let parent_fp: [u8; 4] = parent_hash[..4].try_into().unwrap();

        Ok(Self {
            version: self.version,
            depth: self.depth + 1,
            parent_fingerprint: parent_fp,
            child_number: index,
            chain_code: child_chain_code,
            key: child_key,
            is_private: child_is_private,
        })
    }

    /// Derives an extended key using a BIP-32 path.
    ///
    /// # Arguments
    ///
    /// * `path` - The derivation path (e.g., "m/44'/0'/0'/0/0")
    ///
    /// # Path Format
    ///
    /// - `m` - Master key (optional for relative paths)
    /// - `/` - Separator
    /// - `N` - Normal child at index N
    /// - `N'` or `Nh` or `NH` - Hardened child at index N
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip32::{ExtendedKey, Network};
    ///
    /// let seed = [0u8; 32];
    /// let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
    ///
    /// // BIP-44 Bitcoin path
    /// let derived = master.derive_path("m/44'/0'/0'/0/0").unwrap();
    /// ```
    pub fn derive_path(&self, path: &str) -> Result<Self> {
        let path = path.trim();

        // Handle empty path
        if path.is_empty() || path == "m" || path == "M" {
            return Ok(self.clone());
        }

        // Parse path components
        let path = path
            .strip_prefix("m/")
            .or_else(|| path.strip_prefix("M/"))
            .or_else(|| path.strip_prefix('/'))
            .unwrap_or(path);

        let mut current = self.clone();

        for component in path.split('/') {
            let component = component.trim();
            if component.is_empty() {
                continue;
            }

            // Check for hardened notation
            let (index_str, hardened) = if component.ends_with('\'')
                || component.ends_with('h')
                || component.ends_with('H')
            {
                (&component[..component.len() - 1], true)
            } else {
                (component, false)
            };

            let index: u32 = index_str.parse().map_err(|_| {
                Error::InvalidDerivationPath(format!("Invalid index: {}", index_str))
            })?;

            let child_index = if hardened {
                index
                    .checked_add(HARDENED_KEY_START)
                    .ok_or_else(|| Error::InvalidDerivationPath("Index overflow".to_string()))?
            } else {
                index
            };

            current = current.derive_child(child_index)?;
        }

        Ok(current)
    }

    /// Returns the private key if this is a private extended key.
    ///
    /// # Returns
    ///
    /// The private key, or an error if this is a public extended key
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip32::{ExtendedKey, Network};
    ///
    /// let seed = [0u8; 32];
    /// let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
    /// let private_key = master.private_key().unwrap();
    /// ```
    pub fn private_key(&self) -> Result<PrivateKey> {
        if !self.is_private {
            return Err(Error::InvalidExtendedKey(
                "Cannot extract private key from public extended key".to_string(),
            ));
        }

        PrivateKey::from_bytes(&self.key[1..33])
    }

    /// Returns the public key.
    ///
    /// For private extended keys, this computes the public key.
    /// For public extended keys, this returns the stored public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        if self.is_private {
            let private_key = self.private_key()?;
            Ok(private_key.public_key())
        } else {
            PublicKey::from_bytes(&self.key)
        }
    }

    /// Converts a private extended key to a public extended key ("neutering").
    ///
    /// # Returns
    ///
    /// A public extended key derived from this private key.
    /// If this is already a public key, returns a clone.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip32::{ExtendedKey, Network};
    ///
    /// let seed = [0u8; 32];
    /// let xprv = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
    /// let xpub = xprv.neuter().unwrap();
    ///
    /// assert!(!xpub.is_private());
    /// assert!(xpub.to_string().starts_with("xpub"));
    /// ```
    pub fn neuter(&self) -> Result<Self> {
        if !self.is_private {
            return Ok(self.clone());
        }

        let public_key = self.public_key()?;
        let pubkey_bytes = public_key.to_compressed();

        // Convert version bytes from private to public
        let version = match self.version {
            MAINNET_PRIVATE => MAINNET_PUBLIC,
            TESTNET_PRIVATE => TESTNET_PUBLIC,
            _ => {
                return Err(Error::InvalidExtendedKey(
                    "Unknown version bytes".to_string(),
                ))
            }
        };

        Ok(Self {
            version,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: self.chain_code,
            key: pubkey_bytes,
            is_private: false,
        })
    }

    /// Returns whether this is a private extended key.
    pub fn is_private(&self) -> bool {
        self.is_private
    }

    /// Returns the depth in the derivation hierarchy.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the child number (index) of this key.
    pub fn child_number(&self) -> u32 {
        self.child_number
    }

    /// Returns the parent's fingerprint.
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    /// Returns the chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Returns the fingerprint of this key (first 4 bytes of HASH160(pubkey)).
    pub fn fingerprint(&self) -> Result<[u8; 4]> {
        let pubkey_bytes = self.public_key_bytes()?;
        let hash = hash160(&pubkey_bytes);
        Ok(hash[..4].try_into().unwrap())
    }

    /// Returns the network this key is for.
    pub fn network(&self) -> Option<Network> {
        match self.version {
            MAINNET_PRIVATE | MAINNET_PUBLIC => Some(Network::Mainnet),
            TESTNET_PRIVATE | TESTNET_PUBLIC => Some(Network::Testnet),
            _ => None,
        }
    }

    /// Returns the Bitcoin address for this key.
    pub fn address(&self, mainnet: bool) -> Result<String> {
        let pubkey_bytes = self.public_key_bytes()?;
        let hash = hash160(&pubkey_bytes);
        let version = if mainnet { 0x00 } else { 0x6f };
        Ok(crate::primitives::encoding::to_base58_check(
            &hash,
            &[version],
        ))
    }

    /// Helper to get public key bytes.
    fn public_key_bytes(&self) -> Result<[u8; 33]> {
        if self.is_private {
            let private_key = self.private_key()?;
            Ok(private_key.public_key().to_compressed())
        } else {
            Ok(self.key)
        }
    }
}

impl std::fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedKey")
            .field("depth", &self.depth)
            .field("child_number", &self.child_number)
            .field("is_private", &self.is_private)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ExtendedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

/// Generates a random seed and creates a master extended key.
///
/// # Arguments
///
/// * `seed_length` - The seed length in bytes (16-64, 32 recommended)
/// * `network` - The network for version bytes
///
/// # Returns
///
/// A new master extended key generated from random entropy
pub fn generate_hd_key(seed_length: usize, network: Network) -> Result<ExtendedKey> {
    if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&seed_length) {
        return Err(Error::InvalidExtendedKey(format!(
            "Seed length must be between {} and {} bytes, got {}",
            MIN_SEED_BYTES, MAX_SEED_BYTES, seed_length
        )));
    }

    let mut seed = vec![0u8; seed_length];
    getrandom::getrandom(&mut seed)
        .map_err(|e| Error::CryptoError(format!("Failed to generate random seed: {}", e)))?;

    ExtendedKey::new_master(&seed, network)
}

/// Generates a master extended key from a BIP-39 mnemonic.
///
/// # Arguments
///
/// * `mnemonic` - The BIP-39 mnemonic
/// * `passphrase` - Optional passphrase for seed derivation
/// * `network` - The network for version bytes
///
/// # Returns
///
/// A master extended key derived from the mnemonic's seed
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::bip32::{generate_hd_key_from_mnemonic, Network};
/// use bsv_sdk::compat::bip39::Mnemonic;
///
/// let mnemonic = Mnemonic::from_phrase(
///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
/// ).unwrap();
/// let master = generate_hd_key_from_mnemonic(&mnemonic, "", Network::Mainnet).unwrap();
/// ```
pub fn generate_hd_key_from_mnemonic(
    mnemonic: &super::bip39::Mnemonic,
    passphrase: &str,
    network: Network,
) -> Result<ExtendedKey> {
    let seed = mnemonic.to_seed(passphrase);
    ExtendedKey::new_master(&seed, network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::encoding::from_hex;

    // BIP-32 Test Vector 1
    // Seed: 000102030405060708090a0b0c0d0e0f
    #[test]
    fn test_vector_1_master() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

        assert_eq!(
            master.to_string(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );

        let xpub = master.neuter().unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
    }

    #[test]
    fn test_vector_1_chain_m_0h() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
        let child = master.derive_child(HARDENED_KEY_START).unwrap();

        assert_eq!(
            child.to_string(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );

        let xpub = child.neuter().unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        );
    }

    #[test]
    fn test_vector_1_chain_m_0h_1() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0'/1").unwrap();

        assert_eq!(
            child.to_string(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        );

        let xpub = child.neuter().unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        );
    }

    #[test]
    fn test_vector_1_chain_m_0h_1_2h() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
        let child = master.derive_path("m/0'/1/2'").unwrap();

        assert_eq!(
            child.to_string(),
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
        );

        let xpub = child.neuter().unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        );
    }

    // BIP-32 Test Vector 2
    // Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    #[test]
    fn test_vector_2_master() {
        let seed = from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

        assert_eq!(
            master.to_string(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        );

        let xpub = master.neuter().unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        );
    }

    #[test]
    fn test_vector_2_chain_m_0() {
        let seed = from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();
        let child = master.derive_child(0).unwrap();

        assert_eq!(
            child.to_string(),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        );

        let xpub = child.neuter().unwrap();
        assert_eq!(
            xpub.to_string(),
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        );
    }

    #[test]
    fn test_parse_xprv() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let key = ExtendedKey::from_string(xprv).unwrap();
        assert!(key.is_private());
        assert_eq!(key.depth(), 0);
        assert_eq!(key.to_string(), xprv);
    }

    #[test]
    fn test_parse_xpub() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let key = ExtendedKey::from_string(xpub).unwrap();
        assert!(!key.is_private());
        assert_eq!(key.depth(), 0);
        assert_eq!(key.to_string(), xpub);
    }

    #[test]
    fn test_hardened_from_public_fails() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let key = ExtendedKey::from_string(xpub).unwrap();
        let result = key.derive_child(HARDENED_KEY_START);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_path_variants() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

        // Test various path formats
        let _ = master.derive_path("m/0'/1").unwrap();
        let _ = master.derive_path("m/0h/1").unwrap();
        let _ = master.derive_path("m/0H/1").unwrap();
        let _ = master.derive_path("0'/1").unwrap();
        let _ = master.derive_path("/0'/1").unwrap();
    }

    #[test]
    fn test_public_key_derivation() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

        // Derive from private key
        let priv_child = master.derive_child(0).unwrap();

        // Derive from public key
        let pub_master = master.neuter().unwrap();
        let pub_child = pub_master.derive_child(0).unwrap();

        // Public keys should match
        assert_eq!(
            priv_child.neuter().unwrap().to_string(),
            pub_child.to_string()
        );
    }

    #[test]
    fn test_testnet_keys() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Testnet).unwrap();

        assert!(master.to_string().starts_with("tprv"));

        let xpub = master.neuter().unwrap();
        assert!(xpub.to_string().starts_with("tpub"));
    }

    #[test]
    fn test_invalid_seed_length() {
        // Too short
        let result = ExtendedKey::new_master(&[0u8; 15], Network::Mainnet);
        assert!(result.is_err());

        // Too long
        let result = ExtendedKey::new_master(&[0u8; 65], Network::Mainnet);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_checksum() {
        let mut xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".to_string();
        // Corrupt last character
        xprv.pop();
        xprv.push('j');

        let result = ExtendedKey::from_string(&xprv);
        assert!(result.is_err());
    }

    #[test]
    fn test_address_generation() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

        let address = master.address(true).unwrap();
        assert!(address.starts_with('1'));

        let testnet_address = master.address(false).unwrap();
        assert!(testnet_address.starts_with('m') || testnet_address.starts_with('n'));
    }

    #[test]
    fn test_generate_hd_key() {
        let key = generate_hd_key(32, Network::Mainnet).unwrap();
        assert!(key.is_private());
        assert!(key.to_string().starts_with("xprv"));
    }

    #[test]
    fn test_generate_from_mnemonic() {
        use super::super::bip39::Mnemonic;

        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();

        let master = generate_hd_key_from_mnemonic(&mnemonic, "", Network::Mainnet).unwrap();
        assert!(master.is_private());

        // With passphrase
        let master_with_pass =
            generate_hd_key_from_mnemonic(&mnemonic, "TREZOR", Network::Mainnet).unwrap();
        assert!(master_with_pass.is_private());

        // Different passwords should produce different keys
        assert_ne!(master.to_string(), master_with_pass.to_string());
    }
}

//! Header frame: bitcoin-sv@6504a3af `src/primitives/block.h:23-65`,
//! `block.cpp:16-18`, through bsv-script-lean@50d437b
//! `lean/BsvChain/Header.lean:24-67` (#63).

use super::{check_proof_of_work, ChainWork, CompactTarget, PowError};
use crate::primitives::{from_hex, sha256d, Hash32, Reader, Writer, U256};
use crate::{Error, Result};

/// Size of a serialized block header.
/// ```
/// assert_eq!(bsv_rs::block::HEADER_SIZE, 80);
/// ```
pub const HEADER_SIZE: usize = 80;

/// The 80-byte header, with signed version and internal-order hashes.
/// Height, accumulated work and JSON representation belong to the host.
/// ```
/// use bsv_rs::block::BlockHeader;
/// let header = BlockHeader::from_binary(&[0; 80])?;
/// assert_eq!(header.to_binary(), [0; 80]);
/// # Ok::<(), bsv_rs::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    /// The node's signed `int32_t` version.
    pub version: i32,
    /// Parent digest in internal wire order.
    pub prev_hash: Hash32,
    /// Merkle root in internal wire order.
    pub merkle_root: Hash32,
    /// Timestamp in seconds since the Unix epoch.
    pub time: u32,
    /// Compact target exactly as carried on the wire.
    pub bits: u32,
    /// Proof-of-work nonce.
    pub nonce: u32,
}

impl BlockHeader {
    /// Parse exactly 80 bytes, refusing trailing data.
    /// ```
    /// use bsv_rs::block::BlockHeader;
    /// assert!(BlockHeader::from_binary(&[0; 79]).is_err());
    /// assert!(BlockHeader::from_binary(&[0; 81]).is_err());
    /// ```
    pub fn from_binary(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_SIZE {
            return Err(Error::InvalidDataLength {
                expected: HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        Self::from_reader(&mut Reader::new(bytes))
    }

    /// Parse a hex-encoded exact frame.
    /// ```
    /// use bsv_rs::block::BlockHeader;
    /// assert_eq!(BlockHeader::from_hex(&"00".repeat(80))?.version, 0);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self> {
        Self::from_binary(&from_hex(hex)?)
    }

    /// Read one frame, leaving following bytes in the reader.
    /// ```
    /// use bsv_rs::{block::BlockHeader, primitives::Reader};
    /// let mut reader = Reader::new(&[0; 81]);
    /// BlockHeader::from_reader(&mut reader)?;
    /// assert_eq!(reader.remaining(), 1);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn from_reader(reader: &mut Reader<'_>) -> Result<Self> {
        let bytes = reader.read_bytes(HEADER_SIZE)?;
        Ok(Self {
            version: i32::from_le_bytes(bytes[..4].try_into().expect("four bytes")),
            prev_hash: bytes[4..36].try_into().expect("32 bytes"),
            merkle_root: bytes[36..68].try_into().expect("32 bytes"),
            time: u32::from_le_bytes(bytes[68..72].try_into().expect("four bytes")),
            bits: u32::from_le_bytes(bytes[72..76].try_into().expect("four bytes")),
            nonce: u32::from_le_bytes(bytes[76..80].try_into().expect("four bytes")),
        })
    }

    /// Serialize without allocating.
    /// ```
    /// # use bsv_rs::block::BlockHeader;
    /// assert_eq!(BlockHeader::from_binary(&[0; 80])?.to_binary(), [0; 80]);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn to_binary(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0; HEADER_SIZE];
        bytes[..4].copy_from_slice(&self.version.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.prev_hash);
        bytes[36..68].copy_from_slice(&self.merkle_root);
        bytes[68..72].copy_from_slice(&self.time.to_le_bytes());
        bytes[72..76].copy_from_slice(&self.bits.to_le_bytes());
        bytes[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    /// Serialize to 160 lowercase hex digits.
    /// ```
    /// # use bsv_rs::block::BlockHeader;
    /// assert_eq!(BlockHeader::from_binary(&[0; 80])?.to_hex(), "00".repeat(80));
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_binary())
    }

    /// Append the frame to a writer.
    /// ```
    /// use bsv_rs::{block::BlockHeader, primitives::Writer};
    /// let mut writer = Writer::new();
    /// BlockHeader::from_binary(&[0; 80])?.to_writer(&mut writer);
    /// assert_eq!(writer.len(), 80);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn to_writer(&self, writer: &mut Writer) {
        writer.write_bytes(&self.to_binary());
    }

    /// Double SHA-256 of the frame, in internal order.
    /// ```
    /// use bsv_rs::{block::BlockHeader, primitives::sha256d};
    /// assert_eq!(BlockHeader::from_binary(&[0; 80])?.hash(), sha256d(&[0; 80]));
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn hash(&self) -> Hash32 {
        sha256d(&self.to_binary())
    }

    /// The block hash in reversed, display hex order.
    /// ```
    /// # use bsv_rs::block::BlockHeader;
    /// let h = BlockHeader::from_binary(&[0; 80])?;
    /// assert_eq!(h.id(), h.hash_number().to_hex());
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn id(&self) -> String {
        self.hash_number().to_hex()
    }

    /// Read the internal hash as a little-endian number, as `UintToArith256`.
    /// ```
    /// # use bsv_rs::block::BlockHeader;
    /// let h = BlockHeader::from_binary(&[0; 80])?;
    /// assert_eq!(h.hash_number().to_le_bytes(), h.hash());
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn hash_number(&self) -> U256 {
        U256::from_le_bytes(self.hash())
    }

    /// Decode the carried compact target and its flags.
    /// ```
    /// # use bsv_rs::block::BlockHeader;
    /// assert!(!BlockHeader::from_binary(&[0; 80])?.target().is_valid());
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn target(&self) -> CompactTarget {
        CompactTarget::from_bits(self.bits)
    }

    /// Work credited to these bits; zero for invalid bits.
    /// ```
    /// use bsv_rs::block::{BlockHeader, ChainWork};
    /// assert_eq!(BlockHeader::from_binary(&[0; 80])?.work(), ChainWork::ZERO);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn work(&self) -> ChainWork {
        ChainWork::from_bits(self.bits)
    }

    /// Check the frame's hash and bits against a network limit.
    /// The expected difficulty for its chain position is the caller's check.
    /// ```
    /// use bsv_rs::block::{BlockHeader, POW_LIMIT_MAIN, PowError};
    /// assert_eq!(BlockHeader::from_binary(&[0; 80])?.check_proof_of_work(&POW_LIMIT_MAIN),
    ///            Err(PowError::BitsZero { bits: 0 }));
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn check_proof_of_work(&self, pow_limit: &U256) -> std::result::Result<(), PowError> {
        check_proof_of_work(&self.hash(), self.bits, pow_limit)
    }

    /// Parent hash in display hex order.
    /// ```
    /// # use bsv_rs::block::BlockHeader;
    /// assert_eq!(BlockHeader::from_binary(&[0; 80])?.prev_id(), "0".repeat(64));
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn prev_id(&self) -> String {
        U256::from_le_bytes(self.prev_hash).to_hex()
    }

    /// Merkle root in display hex order, for a chain tracker's root comparison.
    /// ```
    /// # use bsv_rs::block::BlockHeader;
    /// assert_eq!(BlockHeader::from_binary(&[0; 80])?.merkle_root_hex(), "0".repeat(64));
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn merkle_root_hex(&self) -> String {
        U256::from_le_bytes(self.merkle_root).to_hex()
    }
}

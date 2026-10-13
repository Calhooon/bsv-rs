//! Header, proof-of-work, chain-work and merkle primitives.
//!
//! Rules follow bitcoin-sv v1.2.3 at `6504a3af`, through
//! bsv-script-lean@50d437b `lean/BsvChain/{Header,Pow,Merkle}.lean`
//! (#63, #64, #65). Height, chain selection and difficulty adjustment belong
//! to the caller. Hash bytes are in internal wire order.
//!
//! ```
//! use bsv_rs::block::{CompactTarget, ChainWork, POW_LIMIT_MAIN};
//! assert!(CompactTarget::from_bits(0x1d00ffff).target <= POW_LIMIT_MAIN);
//! assert!(ChainWork::from_bits(0x1d00ffff) > ChainWork::ZERO);
//! ```

pub mod header;
pub mod merkle;
pub mod target;
pub mod work;

pub use header::{BlockHeader, HEADER_SIZE};
#[cfg(feature = "transaction")]
pub use merkle::block_merkle_root;
pub use merkle::{merkle_parent, merkle_root, MerkleRoot};
pub use target::{
    check_proof_of_work, CompactTarget, PowError, POW_LIMIT_MAIN, POW_LIMIT_REGTEST, POW_LIMIT_STN,
    POW_LIMIT_TEST,
};
pub use work::ChainWork;

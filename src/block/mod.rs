//! Header, proof-of-work, chain-work and merkle primitives.
//!
//! Rules follow bitcoin-sv v1.2.3 at `6504a3af`, through
//! bsv-script-lean@50d437b `lean/BsvChain/{Header,Pow,Merkle}.lean`
//! (#63, #64, #65). The difficulty rule (`next_work_required`, with
//! `ChainParams` for main, test and regtest) is the node's `GetNextWorkRequired`
//! at the same pin; height, chain selection, checkpoints and the store of
//! ancestors belong to the caller. Hash bytes are in internal wire order.
//!
//! ```
//! use bsv_rs::block::{CompactTarget, ChainWork, POW_LIMIT_MAIN};
//! assert!(CompactTarget::from_bits(0x1d00ffff).target <= POW_LIMIT_MAIN);
//! assert!(ChainWork::from_bits(0x1d00ffff) > ChainWork::ZERO);
//! ```

mod activation;
pub mod difficulty;
pub mod header;
pub mod merkle;
pub mod params;
pub mod target;
pub mod work;

pub use difficulty::{
    calculate_next_work_required, chain_work_between, median_time_past, next_cash_work_required,
    next_work_required, DifficultyError, HeaderAncestry, HeaderLink,
};
pub use header::{BlockHeader, HEADER_SIZE};
#[cfg(feature = "transaction")]
pub use merkle::block_merkle_root;
pub use merkle::{merkle_parent, merkle_root, MerkleRoot};
pub use params::ChainParams;
pub use target::{
    check_proof_of_work, CompactTarget, PowError, POW_LIMIT_MAIN, POW_LIMIT_REGTEST, POW_LIMIT_STN,
    POW_LIMIT_TEST,
};
pub use work::ChainWork;

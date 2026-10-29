//! Network names for the chain parameters, including script activation.

use super::ChainParams;

impl ChainParams {
    /// Mainnet parameters, including Genesis at 620,538 and Chronicle at
    /// 943,816 (`bitcoin-sv@879fc8b src/chainparams.cpp:18,23`).
    /// This is also [`Self::main`].
    /// ```
    /// assert_eq!(bsv_rs::block::ChainParams::mainnet().genesis_height, 620_538);
    /// ```
    #[must_use]
    pub fn mainnet() -> Self {
        Self::main()
    }

    /// Testnet parameters, including Genesis at 1,344,302 and Chronicle at
    /// 1,713,168 (`bitcoin-sv@879fc8b src/chainparams.cpp:20,25`).
    /// This is also [`Self::test`]. Match any activation overrides on the node.
    /// ```
    /// assert_eq!(bsv_rs::block::ChainParams::testnet().chronicle_height, 1_713_168);
    /// ```
    #[must_use]
    pub fn testnet() -> Self {
        Self::test()
    }
}

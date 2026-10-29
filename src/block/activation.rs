//! Network names and checked script activation overrides.

use std::fmt;

use super::ChainParams;

/// An activation override the node cannot use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActivationHeightsError {
    /// Genesis must activate at a positive height.
    ZeroGenesis,
    /// Chronicle must activate at a positive height.
    ZeroChronicle,
}

impl ActivationHeightsError {
    pub(crate) const fn message(self) -> &'static str {
        // bitcoin-sv@879fc8b src/configscriptpolicy.cpp:310-321,353-364.
        match self {
            Self::ZeroGenesis => {
                "Genesis activation height cannot be configured with a zero or negative value."
            }
            Self::ZeroChronicle => {
                "Chronicle activation height cannot be configured with a zero or negative value."
            }
        }
    }
}

impl fmt::Display for ActivationHeightsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ActivationHeightsError {}

impl ChainParams {
    /// Overrides this network's inclusive Genesis and Chronicle heights.
    ///
    /// # Errors
    /// Refuses zero for either height, as bitcoin-sv@879fc8b does in
    /// `src/configscriptpolicy.cpp:310-321,353-364`. The node reads each option
    /// as a signed 32-bit integer (`init.cpp:2474,2478`), so it also refuses a
    /// height of 2^31 or more, which this `u32` accepts; no chain nears it.
    /// Other network parameters are preserved.
    /// ```
    /// use bsv_rs::block::{ActivationHeightsError, ChainParams};
    /// let teranode = ChainParams::regtest().with_activation_heights(100, 200)?;
    /// assert_eq!((teranode.genesis_height, teranode.chronicle_height), (100, 200));
    /// assert_eq!(
    ///     ChainParams::regtest().with_activation_heights(0, 200),
    ///     Err(ActivationHeightsError::ZeroGenesis),
    /// );
    /// # Ok::<(), ActivationHeightsError>(())
    /// ```
    pub fn with_activation_heights(
        mut self,
        genesis: u32,
        chronicle: u32,
    ) -> Result<Self, ActivationHeightsError> {
        self.genesis_height = genesis;
        self.chronicle_height = chronicle;
        self.check_activation_heights()?;
        Ok(self)
    }

    pub(crate) fn check_activation_heights(&self) -> Result<(), ActivationHeightsError> {
        if self.genesis_height == 0 {
            return Err(ActivationHeightsError::ZeroGenesis);
        }
        if self.chronicle_height == 0 {
            return Err(ActivationHeightsError::ZeroChronicle);
        }
        Ok(())
    }

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

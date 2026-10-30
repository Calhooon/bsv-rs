//! The node's transaction flags combined with each coin's creation-era bits.

use super::{NotJudgedCause, ProtocolEra, ScriptFlags, ScriptFlagsError};
use crate::block::ChainParams;

/// Computes the node's word for one input from chain facts, never a caller's
/// flag word or era resolver. `spend_height` is the candidate block height
/// (tip + 1), or the containing block height when `mined`. For optional heights
/// and typed refusals, use [`ChainParams::word_for_input`], which owns the no-tip rule.
/// `source_proven_height` is the source transaction's verified BUMP height;
/// an unproven source (`None`) takes the spend's era.
///
/// Transaction flags follow the spend's era; only `UTXO_AFTER_GENESIS` and
/// `UTXO_AFTER_CHRONICLE` follow the source. `mined` selects the block word,
/// otherwise the standard word. These are `InputScriptVerifyFlags`
/// (`bitcoin-sv@879fc8b src/policy/policy.h:226-245`) and the block-era rule
/// (`src/validation.cpp:2973-2982`), as recorded in the sibling's
/// `docs/PARAMETERS.md:103,123,125,168`.
///
/// # Errors
/// A zero activation height is refused as [`ScriptFlagsError::NotApplicable`]
/// in the node's words (`bitcoin-sv@879fc8b
/// src/configscriptpolicy.cpp:310-321,353-364`), including public field overrides.
/// A pre-Genesis spend or coin is unsupported by this interpreter, and is
/// refused explicitly rather than silently assigned a post-Genesis era.
///
/// ```
/// use bsv_rs::{block::ChainParams, script::{input_script_flags, ScriptFlags}};
/// let word = input_script_flags(&ChainParams::mainnet(), 943_816, Some(800_000), false)?;
/// assert!(word.contains(ScriptFlags::CHRONICLE));
/// assert!(!word.contains(ScriptFlags::UTXO_AFTER_CHRONICLE));
/// # Ok::<(), bsv_rs::script::ScriptFlagsError>(())
/// ```
pub fn input_script_flags(
    chain: &ChainParams,
    spend_height: u32,
    source_proven_height: Option<u32>,
    mined: bool,
) -> Result<ScriptFlags, ScriptFlagsError> {
    checked_input_script_flags(chain, spend_height, source_proven_height, mined)
        .map_err(|cause| ScriptFlagsError::NotApplicable(cause.flags_message()))
}

pub(crate) fn checked_input_script_flags(
    chain: &ChainParams,
    spend_height: u32,
    source_proven_height: Option<u32>,
    mined: bool,
) -> Result<ScriptFlags, NotJudgedCause> {
    chain
        .check_activation_heights()
        .map_err(NotJudgedCause::ZeroActivationHeight)?;
    let era_at =
        |height| ProtocolEra::at_height(height, chain.genesis_height, chain.chronicle_height);
    let spend_era = era_at(spend_height).ok_or(NotJudgedCause::PreGenesisSpend {
        height: spend_height,
        genesis_height: chain.genesis_height,
    })?;
    let source_height = source_proven_height.unwrap_or(spend_height);
    let source_era = era_at(source_height).ok_or(NotJudgedCause::PreGenesisCoin {
        height: source_height,
        genesis_height: chain.genesis_height,
    })?;
    let word = if mined {
        ScriptFlags::block(spend_era)
    } else {
        ScriptFlags::standard(spend_era)
    };
    let coin_bits = ScriptFlags::UTXO_AFTER_GENESIS | ScriptFlags::UTXO_AFTER_CHRONICLE;
    let mut source_bits = ScriptFlags::UTXO_AFTER_GENESIS;
    if source_era.is_chronicle() {
        source_bits |= ScriptFlags::UTXO_AFTER_CHRONICLE;
    }
    Ok(word.without(coin_bits) | source_bits)
}

/// Which node word to use for an input, independent of its script era.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Word {
    /// Mempool policy, used at a live wallet, topic or tracker door.
    Standard,
    /// Consensus rules, used for a transaction in a mined block.
    Block,
}

impl ChainParams {
    /// Resolves the node's word for one input from this chain's activation heights.
    ///
    /// [`Word::Standard`] selects the live door's policy; [`Word::Block`] selects
    /// the consensus word for a mined transaction. `spend_height` is the candidate
    /// block height (tip + 1), or the containing block height for a mined spend.
    /// With `None`, the no-tip rule uses the latest era the parameters know:
    /// `max(genesis_height, chronicle_height)`. An activation is held back only
    /// for a named spend height that has not reached it. This is the live-door
    /// rule at `bsv-wallet-toolbox-rs@819dbcef`
    /// `src/storage/sqlx/beef_verification/live_word.rs:55-70`, moved here on the
    /// [keeper's #520 ruling](https://github.com/Calhooon/bsv-rs/issues/520#issuecomment-6530114599).
    ///
    /// Transaction flags follow the spend's era. Only `UTXO_AFTER_GENESIS` and
    /// `UTXO_AFTER_CHRONICLE` follow `source_height`, the source's verified BUMP
    /// height. `None` is an unmined parent taking the spend's era. Both use the
    /// inclusive era table in `src/script/flags.rs:102-110`
    /// ([`ProtocolEra::at_height`]); the word is composed by the same private
    /// helper as [`input_script_flags`]. Requires the `script` and `block` features.
    ///
    /// # Errors
    /// Returns [`NotJudgedCause`] in the existing order: a zero Genesis height,
    /// a zero Chronicle height, a pre-Genesis spend, then a pre-Genesis coin.
    /// Callers derive these `u32` heights before calling: an overflowing tip + 1
    /// is [`NotJudgedCause::TipHeightOverflow`]; an out-of-range wider source is
    /// [`NotJudgedCause::SourceHeightOverflow`]. These conversion refusals cannot
    /// arise from already-representable heights. The stream retains its existing
    /// source-conversion-before-tip-conversion order when both overflow.
    ///
    /// ```
    /// use bsv_rs::{block::ChainParams, script::{ScriptFlags, Word}};
    /// let flags = ChainParams::mainnet()
    ///     .word_for_input(Word::Standard, None, Some(800_000))?;
    /// assert!(flags.contains(ScriptFlags::CHRONICLE));
    /// assert!(!flags.contains(ScriptFlags::UTXO_AFTER_CHRONICLE));
    /// # Ok::<(), bsv_rs::script::NotJudgedCause>(())
    /// ```
    pub fn word_for_input(
        &self,
        word: Word,
        spend_height: Option<u32>,
        source_height: Option<u32>,
    ) -> Result<ScriptFlags, NotJudgedCause> {
        checked_input_script_flags(
            self,
            spend_height.unwrap_or_else(|| self.genesis_height.max(self.chronicle_height)),
            source_height,
            word == Word::Block,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_activation_defaults_match_chainparams_at_879fc8b() {
        for (chain, genesis, chronicle) in [
            (ChainParams::mainnet(), 620_538, 943_816),
            (ChainParams::testnet(), 1_344_302, 1_713_168),
            (ChainParams::regtest(), 10_000, 15_000),
        ] {
            assert_eq!(
                (chain.genesis_height, chain.chronicle_height),
                (genesis, chronicle)
            );
        }
        assert_eq!(ChainParams::main(), ChainParams::mainnet());
        assert_eq!(ChainParams::test(), ChainParams::testnet());
        assert_eq!(
            ChainParams::mainnet().genesis_height,
            ProtocolEra::MAINNET_GENESIS_HEIGHT
        );
        assert_eq!(
            ChainParams::mainnet().chronicle_height,
            ProtocolEra::MAINNET_CHRONICLE_HEIGHT
        );
    }

    /// PARAMETERS.md:103,123,125,168; policy.h:226-245; validation.cpp:2980.
    #[test]
    fn transaction_era_and_both_utxo_markers_follow_their_own_heights() {
        let chain = ChainParams::regtest();
        for (spend, source, standard, block) in [
            (10_000, Some(10_000), 0x0d47ff, 0x0d462f),
            (14_999, None, 0x0d47ff, 0x0d462f),
            (15_000, Some(14_999), 0x1d47ff, 0x1d462f),
            (15_000, Some(15_000), 0x3d47ff, 0x3d462f),
            (15_000, None, 0x3d47ff, 0x3d462f),
        ] {
            assert_eq!(
                input_script_flags(&chain, spend, source, false)
                    .unwrap()
                    .bits(),
                standard
            );
            assert_eq!(
                input_script_flags(&chain, spend, source, true)
                    .unwrap()
                    .bits(),
                block
            );
        }
    }

    #[test]
    fn pre_genesis_is_refused_and_custom_network_heights_are_used() {
        // Teranode regtest: go-chaincfg v1.6.2 params.go:475-476, not SV node defaults.
        let chain = ChainParams::regtest()
            .with_activation_heights(100, 200)
            .unwrap();
        assert!(input_script_flags(&chain, 99, None, false).is_err());
        assert!(input_script_flags(&chain, 200, Some(99), false).is_err());
        assert_eq!(
            input_script_flags(&chain, 200, Some(100), false)
                .unwrap()
                .bits(),
            0x1d47ff
        );
    }

    #[test]
    fn a_zero_genesis_activation_height_is_refused() {
        let mut chain = ChainParams::regtest();
        chain.genesis_height = 0;
        for mined in [false, true] {
            for source in [None, Some(0), Some(15_000)] {
                assert_eq!(
                    input_script_flags(&chain, 15_000, source, mined),
                    Err(ScriptFlagsError::NotApplicable(
                        "Genesis activation height cannot be configured with a zero or negative value."
                    ))
                );
            }
        }
        assert_eq!(
            ChainParams::regtest().with_activation_heights(0, 15_000),
            Err(crate::block::ActivationHeightsError::ZeroGenesis)
        );
    }

    #[test]
    fn a_zero_chronicle_activation_height_is_refused() {
        let mut chain = ChainParams::regtest();
        chain.chronicle_height = 0;
        for mined in [false, true] {
            for source in [None, Some(0), Some(15_000)] {
                assert_eq!(
                    input_script_flags(&chain, 15_000, source, mined),
                    Err(ScriptFlagsError::NotApplicable(
                        "Chronicle activation height cannot be configured with a zero or negative value."
                    ))
                );
            }
        }
        assert_eq!(
            ChainParams::regtest().with_activation_heights(10_000, 0),
            Err(crate::block::ActivationHeightsError::ZeroChronicle)
        );
    }
}

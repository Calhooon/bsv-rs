//! The node's transaction flags combined with each coin's creation-era bits.

use super::{ProtocolEra, ScriptFlags, ScriptFlagsError};
use crate::block::ChainParams;

/// Computes the node's word for one input from chain facts, never a caller's
/// flag word or era resolver. `spend_height` is the candidate block height
/// (tip + 1), or the containing block height when `mined`. With no mining tip,
/// callers use the latest activation height in `chain` for an unmined spend.
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
    let era_at =
        |height| ProtocolEra::at_height(height, chain.genesis_height, chain.chronicle_height);
    let spend_era = era_at(spend_height).ok_or(ScriptFlagsError::NotApplicable(
        "The spending transaction is before Genesis; its script era is unsupported.",
    ))?;
    let source_era = era_at(source_proven_height.unwrap_or(spend_height)).ok_or(
        ScriptFlagsError::NotApplicable(
            "The source output was created before Genesis; its script era is unsupported.",
        ),
    )?;
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
        let mut chain = ChainParams::regtest();
        chain.genesis_height = 100;
        chain.chronicle_height = 200;
        assert!(input_script_flags(&chain, 99, None, false).is_err());
        assert!(input_script_flags(&chain, 200, Some(99), false).is_err());
        assert_eq!(
            input_script_flags(&chain, 200, Some(100), false)
                .unwrap()
                .bits(),
            0x1d47ff
        );
    }
}

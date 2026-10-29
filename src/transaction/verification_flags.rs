//! Height facts shared by the streaming and whole-transaction verifiers.

use crate::block::ChainParams;
use crate::script::{input_script_flags, ScriptFlags, ScriptFlagsError};

pub(super) fn verification_flags(
    chain: &ChainParams,
    tip_height: Option<u32>,
    source_height: Option<u32>,
) -> Result<ScriptFlags, ScriptFlagsError> {
    let spend_height = match tip_height {
        Some(height) => height
            .checked_add(1)
            .ok_or(ScriptFlagsError::NotApplicable(
                "The mining tip has no next block height in u32.",
            ))?,
        // RULINGS-2026-10-12.md, 2026-10-29 10:5xZ: no tip means the
        // latest era the chain constants know, for transaction and unproven coin.
        None => chain.genesis_height.max(chain.chronicle_height),
    };
    input_script_flags(chain, spend_height, source_height, false)
}

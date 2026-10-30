//! Height facts shared by the streaming and whole-transaction verifiers.

use crate::block::ChainParams;
use crate::script::{NotJudgedCause, ScriptFlags, Word};

pub(super) fn verification_flags(
    chain: &ChainParams,
    tip_height: Option<u32>,
    source_height: Option<u32>,
) -> Result<ScriptFlags, NotJudgedCause> {
    let spend_height = tip_height
        .map(|height| {
            height
                .checked_add(1)
                .ok_or(NotJudgedCause::TipHeightOverflow { tip: height })
        })
        .transpose()?;
    chain.word_for_input(Word::Standard, spend_height, source_height)
}

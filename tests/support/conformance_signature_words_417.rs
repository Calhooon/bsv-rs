//! #417's visible wrapper hides the individual rule from the census.
//! Keep each audited vector in its existing capability class: nine low-S
//! cases and five undefined legacy hash types. No verdict or total moves.

use super::MismatchContext;

const LOW_S: &[&str] = &[
    "node.script.bitcoin-sv.1424",
    "node.script.teranode.1375",
    "node.tx-valid.shared.0023",
    "node.tx-valid.shared.0053",
    "node.tx-valid.shared.0073",
    "node.tx-valid.shared.0074",
    "node.tx-valid.shared.0076",
    "node.tx-valid.shared.0078",
    "node.tx-valid.shared.0080",
];

const UNDEFINED_LEGACY_TYPE: &[&str] = &[
    "node.script.bitcoin-sv.1435",
    "node.script.bitcoin-sv.1437",
    "node.script.bitcoin-sv.1441",
    "node.script.teranode.1386",
    "node.script.teranode.1392",
];

pub(super) fn classify_signature_words_417(
    id: &str,
    ctx: &MismatchContext<'_>,
) -> Option<&'static str> {
    if !ctx.expected_valid || ctx.error_message != "The signature format is invalid." {
        return None;
    }
    let has = |flag: &str| ctx.flags.iter().any(|f| f == flag);
    if LOW_S.contains(&id) && !has("LOW_S") {
        return Some(
            "the default mode enforces LOW_S at version <= 1 (a word would express the fixture)",
        );
    }
    if UNDEFINED_LEGACY_TYPE.contains(&id) && !has("SIGHASH_FORKID") {
        return Some("bsv-rs always requires SIGHASH_FORKID (legacy-signature fixtures)");
    }
    None
}

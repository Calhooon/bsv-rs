//! #417's visible wrapper hides the individual rule from the census.
//! Keep each audited vector in its actual capability class: nine original
//! low-S cases, two exposed by #429, and five undefined legacy hash types.

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
    // #429 reaches a later high-S signature after accepting a legacy one.
    "node.tx-valid.shared.0055",
    "node.tx-valid.shared.0097",
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
    if !ctx.expected_valid
        || !matches!(
            ctx.error_message,
            "The signature format is invalid."
                | "OP_CHECKMULTISIG requires correct encoding for the public key and signature."
        )
    {
        return None;
    }
    let has = |flag: &str| ctx.flags.iter().any(|f| f == flag);
    if LOW_S.contains(&id) && !has("LOW_S") {
        return Some(
            "the default mode enforces LOW_S at version <= 1 (a word would express the fixture)",
        );
    }
    if UNDEFINED_LEGACY_TYPE.contains(&id) && !has("SIGHASH_FORKID") {
        return Some(
            "the default mode enforces defined hash types (legacy fixtures without STRICTENC)",
        );
    }
    None
}

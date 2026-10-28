//! The default-mode census's enumerated capability classes and their pins.
//! #397 moves teranode.1388 (scope 0x21) from the legacy-FORKID class (36 to
//! 35) to the version-1 Chronicle hash gate (1); totals are unchanged.

use super::MismatchContext;

const CHRONICLE_HASH_TYPE: &str =
    "the default mode forbids SIGHASH_CHRONICLE at version <= 1 (a word would express the fixture)";

/// The fixture has no flags and scope 0x21 (ALL | CHRONICLE, no FORKID).
/// It was already refused, at the FORKID check; #397 refuses it earlier at
/// the version gate. Name the exact fixture so other mismatches fail loudly.
pub(super) fn classify_chronicle_hash_type(
    id: &str,
    ctx: &MismatchContext<'_>,
) -> Option<&'static str> {
    (id == "node.script.teranode.1388"
        && ctx.expected_valid
        && ctx.flags.is_empty()
        && ctx.error_message == "The signature hash type is invalid before Chronicle.")
        .then_some(CHRONICLE_HASH_TYPE)
}

/// Pinned per-class unsupported counts for sdk.scripts.evaluation.
/// Audited empirically against corpus stats (5,116 vectors, META.json
/// last_updated 2026-05-19) — see classify_node_mismatch for what each class
/// means. THESE ARE NOT FAILURES — they are enumerated capability gaps of
/// the default mode (strict at version <= 1, post-genesis) and its
/// FORKID-only sighash. Any drift (corpus update, SDK behavior change) fails
/// the assert and forces a re-audit.
pub(super) const EVALUATION_UNSUPPORTED_PINS: &[(&str, usize)] = &[
    (CHRONICLE_HASH_TYPE, 1),
    // 2026-09-23 repin (0.3.27, the five residual consensus rules): the class
    // "UTXO_AFTER_CHRONICLE opcode semantics not implemented" (5) is gone, the
    // census now sets the Chronicle gate from each fixture's flags and the five
    // fixtures execute; "flag-dependent ELSE/ENDIF structure rules" (30) is
    // gone, the post-Genesis fixtures expecting the single-ELSE refusal now
    // pass and the pre-Genesis ones that assert a second OP_ELSE inverting the
    // branch are the new class below (26); "flag-dependent opcode set"
    // 12 -> 4 (undefined opcodes and unexecuted OP_VERIF now judged as the
    // node does); "pre-genesis OP_RETURN semantics" 34 -> 28 and CLEANSTACK
    // 195 -> 194 (a RETURN inside a conditional no longer clears the
    // conditional stack, so those fixtures now match). Zero new mismatches;
    // script-021 (the TS default's multiple OP_ELSE) is a known failure.
    // 2026-07-09 repin (225 -> 195): Spend now mirrors ts-sdk's version-based
    // relaxed mode (tx version > 1 disables CLEANSTACK/LOW_S/MINIMALDATA).
    // 30 version-2 fixtures that previously died at the always-on clean-stack
    // check now execute; 27 pass conformantly (moved to `run`) and 3 progress
    // to the CLTV/CSV gap below (5 -> 8). Zero new mismatches.
    ("the default mode enforces CLEANSTACK at version <= 1 (a word would express the fixture)", 194),
    ("the default mode enforces LOW_S at version <= 1 (a word would express the fixture)", 9),
    ("the default mode enforces MINIMALDATA at version <= 1 (a word would express the fixture)", 181),
    ("the default mode enforces NULLDUMMY at version <= 1 (a word would express the fixture; the census runs the default mode)", 4),
    (
        "bsv-rs always enforces SIGPUSHONLY (push-only unlocking scripts)",
        319,
    ),
    (
        "strict DER/pubkey encodings are always enforced (SIGHASH_FORKID implies STRICTENC on the reference too)",
        54,
    ),
    (
        "bsv-rs always requires SIGHASH_FORKID (cannot reject FORKID-bit sigs)",
        6,
    ),
    (
        "bsv-rs always requires SIGHASH_FORKID (legacy-signature fixtures)",
        35,
    ),
    (
        "flag-dependent opcode set (pre-genesis/Chronicle) not expressible in bsv-rs",
        4,
    ),
    (
        "pre-genesis multiple OP_ELSE (bsv-rs runs the post-genesis single-ELSE rule)",
        26,
    ),
    // NOTE: this is HALF the sighash corpus. The fixture's `regular_hash`
    // uses the original (legacy) digest algorithm whenever the FORKID bit is
    // absent (or the Chronicle bit applies), and `original_hash` is ALWAYS
    // legacy. bsv-rs has no legacy-sighash API at all
    // (`build_sighash_preimage` is BIP-143-only), so the 756 executed
    // sighash vectors cover the FORKID `regular_hash` side only.
    ("legacy/OTDA sighash not implemented in bsv-rs", 1244),
    ("no CLTV/CSV enforcement in bsv-rs (post-genesis NOPs)", 8),
    ("DISCOURAGE_UPGRADABLE_NOPS is not in the default mode (only under a word)", 20),
    ("MINIMALIF is not in the default mode (only under a word)", 6),
    (
        "no P2SH redeem-script evaluation in bsv-rs (post-genesis rules)",
        72,
    ),
    ("no isRelaxed evaluation mode in bsv-rs", 3),
    (
        "pre-genesis OP_RETURN semantics (bsv-rs implements post-genesis skip)",
        28,
    ),
    (
        "pre-genesis limits (bsv-rs runs post-genesis/unlimited rules)",
        14,
    ),
];

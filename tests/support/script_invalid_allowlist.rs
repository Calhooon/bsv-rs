//! Historical invalid vectors accepted by the default evaluator. Each needs
//! the vector's node flags/era, not the SDK default. Pin the exact rows so
//! a percentage tolerance cannot hide a new disagreement (#397).

const ACCEPTED: &[(usize, &str)] = &[
    (
        18,
        "OP_VER runs by default; the historical vector reserves it (#397)",
    ),
    (50, "post-Genesis top-level OP_RETURN ends successfully"),
    (
        51,
        "post-Genesis OP_RETURN inside a conditional ends successfully",
    ),
    (52, "post-Genesis OP_RETURN leaves its suffix unread"),
    (117, "NOP1 is discouraged only under a word"),
    (118, "CHECKLOCKTIMEVERIFY is a NOP for a post-Genesis UTXO"),
    (119, "CHECKSEQUENCEVERIFY is a NOP for a post-Genesis UTXO"),
    (125, "NOP9 is discouraged only under a word"),
    (126, "NOP10 is discouraged only under a word"),
    (207, "the pre-Genesis element size limit is absent"),
    (208, "the pre-Genesis opcode count limit is absent"),
    (
        209,
        "the pre-Genesis opcode count limit is absent in skipped branches",
    ),
];

pub(super) fn assert_accepted(actual: &[usize]) {
    let expected: Vec<_> = ACCEPTED.iter().map(|(index, _)| *index).collect();
    assert_eq!(
        actual, expected,
        "script_invalid default-mode allowlist drift: {ACCEPTED:?}"
    );
}

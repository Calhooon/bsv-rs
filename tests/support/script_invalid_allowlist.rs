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
    (
        408,
        "the default skips the fork-ID gate; a failed CHECKMULTISIG followed by NOT succeeds (#429)",
    ),
    (
        409,
        "the default skips the fork-ID gate; a failed CHECKMULTISIG followed by NOT succeeds (#429)",
    ),
];

pub(super) fn assert_accepted(actual: &[usize]) {
    let expected: Vec<_> = ACCEPTED.iter().map(|(index, _)| *index).collect();
    assert_eq!(
        actual, expected,
        "script_invalid default-mode allowlist drift: {ACCEPTED:?}"
    );
}

#[test]
fn issue_429_historical_invalid_multisig_rows_match_both_reference_defaults() {
    let recorded: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/script_invalid_forkid_429.json")).unwrap();
    assert_eq!(recorded["node"], "v22.18.0");
    assert_eq!(
        recorded["reference"],
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    let vectors = super::load_script_invalid_vectors();
    let cases = recorded["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for c in cases {
        let index = usize::try_from(c["index"].as_u64().unwrap()).unwrap();
        let v = &vectors[index];
        assert_eq!(v.script_sig, c["unlock"].as_str().unwrap());
        assert_eq!(v.script_pub_key, c["lock"].as_str().unwrap());
        assert_eq!(c["valid"], true);
        let v = super::SpendVector {
            script_sig: v.script_sig.clone(),
            script_pub_key: v.script_pub_key.clone(),
            comment: v.comment.clone(),
        };
        assert_eq!(super::run_spend_vector(index, &v), Ok(true), "row {index}");
    }
}

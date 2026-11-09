#![cfg(test)]
//! #728: the two `ls_identity` parsers on the BEEFs of
//! `tests/vectors/identity_beef_subject_728.json` handed to them directly,
//! each at its recorded output index. Every public door reaches them
//! through `LookupResolver`'s dedup, which drops an output whose BEEF
//! `Transaction::from_beef` refuses, as the reference's resolver does
//! (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts:2232-2237`), so the
//! txid-only subjects never reach a parser there; here the parsers' own
//! rule is pinned: an output index past the subject's outputs skipped, a
//! txid-only entry last or named by the atomic header skipped (until #721
//! `beef.txs.first()` read the token's transaction beside it), and since
//! #730 the parent whose BUMP names another txid skipped where the
//! reference's `assertUnconfirmedGraph` refuses it (`TransactionEvidence.ts:143`),
//! the parsers running that walk (`src/identity/evidence.rs`); every shape
//! the reference's outcome (`tests/identity_beef_subject_728.rs`). RED on
//! `11bb04ce` on the other-txid BUMP (read there).

use super::*;

#[tokio::test]
async fn the_parsers_skip_each_728_beef_as_the_reference_728() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/identity_beef_subject_728.json"
    ))
    .unwrap();
    let shapes = v["shapes"].as_array().unwrap();
    assert_eq!(shapes.len(), 5, "the vector's five BEEFs of four shapes");
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());
    let mut differ = Vec::new();
    for case in shapes {
        let name = case["name"].as_str().unwrap();
        let output = OutputListItem {
            beef: crate::primitives::from_hex(case["beef"].as_str().unwrap()).unwrap(),
            output_index: case["output_index"].as_u64().unwrap() as u32,
            context: None,
            txid: None,
        };
        let reference = case["outcome"] == "read";
        let expected = reference;
        let certificate = client.parse_output_to_certificate(&output).await.unwrap();
        let verifiable = client
            .parse_output_to_verifiable_certificate(&output)
            .await
            .unwrap();
        let got = (certificate.is_some(), verifiable.is_some());
        if got != (expected, expected) {
            differ.push(format!("{name}: {got:?}, expected {expected}"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

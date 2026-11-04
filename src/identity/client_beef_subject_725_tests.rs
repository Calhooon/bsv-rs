#![cfg(test)]
//! #725: the two `ls_identity` parsers on the BEEFs of
//! `tests/vectors/identity_beef_subject_725.json` handed to them directly.
//! Every public door reaches them through `LookupResolver`'s dedup, which
//! drops an output whose BEEF `Transaction::from_beef` refuses, as the
//! reference's resolver does (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts:2232-2237`), so the
//! atomic header naming an absent txid never reaches a parser there; here
//! the parsers' own rule is pinned: that shape skipped (until #721
//! `beef.txs.first()` read the token's transaction), the chain read from its
//! subject, and since #730 the txid-only parent skipped where the
//! reference's `assertUnconfirmedGraph` refuses it (`TransactionEvidence.ts:143`),
//! the parsers running that walk (`src/identity/evidence.rs`); every shape
//! the reference's outcome (`tests/identity_beef_subject_725.rs`). RED on
//! `11bb04ce` on the two txid-only parent BEEFs (read there).

use super::*;

#[tokio::test]
async fn the_parsers_read_or_skip_each_725_beef_as_the_reference_725() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/identity_beef_subject_725.json"
    ))
    .unwrap();
    let shapes = v["shapes"].as_array().unwrap();
    assert_eq!(shapes.len(), 5, "the vector's five BEEFs of three shapes");
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());
    let mut differ = Vec::new();
    for case in shapes {
        let name = case["name"].as_str().unwrap();
        let output = OutputListItem {
            beef: crate::primitives::from_hex(case["beef"].as_str().unwrap()).unwrap(),
            output_index: 0,
            context: None,
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

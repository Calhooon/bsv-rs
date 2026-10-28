//! #427: both entry points return the current reference's counterparty keys.
//! The older reference's aliases are retained as a separate observation.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/wallet_proto_args_420.rs"]
mod replay;

use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::{
    Counterparty, ProtoWallet, Protocol, RevealSpecificKeyLinkageArgs, SecurityLevel,
};
use serde_json::Value;

fn assert_counterparty(name: &str) {
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/wallet_specific_linkage_427.json")).unwrap();
    assert_eq!(fixture["node"], "v22.18.0");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    let case = cases.iter().find(|case| case["name"] == name).unwrap();
    let args = &case["args"];
    let counterparty = match args["counterparty"].as_str().unwrap() {
        "self" => Counterparty::Self_,
        "anyone" => Counterparty::Anyone,
        key => Counterparty::from_hex(key).unwrap(),
    };
    let wallet = ProtoWallet::new(Some(
        PrivateKey::from_hex(&format!("{:064x}", fixture["key"].as_u64().unwrap())).unwrap(),
    ));
    let result = wallet
        .reveal_specific_key_linkage(RevealSpecificKeyLinkageArgs {
            counterparty,
            verifier: PublicKey::from_hex(args["verifier"].as_str().unwrap()).unwrap(),
            protocol_id: Protocol::new(
                SecurityLevel::from_u8(args["protocolID"][0].as_u64().unwrap() as u8).unwrap(),
                args["protocolID"][1].as_str().unwrap(),
            ),
            key_id: args["keyID"].as_str().unwrap().into(),
        })
        .unwrap();
    assert_eq!(
        result.counterparty,
        case["expected"]["result"]["counterparty"]
    );

    // Read the returned fields, decrypt both entry points' linkage and proof,
    // and compare to the recording; never reconstruct a returned counterparty.
    for inherent in [false, true] {
        let mut call = case.clone();
        call["inherent"] = inherent.into();
        assert_eq!(replay::invoke(&call).unwrap(), case["expected"]["observed"]);
    }
    let older = fixture["olderReference"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    assert_eq!(
        older["expected"]["result"]["counterparty"],
        args["counterparty"]
    );
}

#[test]
fn self_specific_linkage_returns_the_identity_key_on_both_entry_points() {
    assert_counterparty("self");
}

#[test]
fn anyone_specific_linkage_returns_the_anyone_key_on_both_entry_points() {
    assert_counterparty("anyone");
}

#[test]
fn other_specific_linkage_keeps_the_public_key_on_both_entry_points() {
    assert_counterparty("other");
}

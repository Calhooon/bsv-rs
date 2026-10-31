//! #553: the identity client's two `ls_identity` parsers run the record
//! checks and byte bounds the reference's discovery runs on a revelation
//! token (`ts-stack@edf6e03`
//! `wallet-toolbox/src/utility/identityUtils.ts:87-132,497-559`, reached by
//! the SDK's `IdentityClient.resolveByIdentityKey` and `resolveByAttributes`
//! through their wallet's discovery, `IdentityClient.ts:559-655`,
//! `Wallet.ts:904-1010`), a record that fails skipped. Against
//! `tests/vectors/identity_certificate_record_553.json`
//! (`tests/support/identity_certificate_record_553.mjs`, Node v22.18.0): the
//! reference's own token and twenty-five signed for the subject 9 over its JSON
//! changed in one respect, each with `parseResults`' outcome. Hermetic: an
//! in-process resolver on an `.invalid` host.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::identity::IdentityClient;
use bsv_rs::primitives::{from_hex, sha256, to_hex};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::Value;

/// The two cases whose transaction passes the reference evidence layer's
/// 256 KiB script bound (`TransactionEvidence.ts:155-172`), refused whole by
/// the toolbox wallet's verifier before the record is read; this crate has
/// no evidence layer, so its parsers answer as `decodeIdentityOutput` does.
const EVIDENCE_REFUSED: [&str; 2] = ["certificate_at_bound", "certificate_over_bound"];

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap()
}

/// The case's token: the recorded script, or, for a 256 KiB certificate,
/// the reference's text padded with spaces under its recorded signature,
/// locked by this crate's writer with the reference token's key, the
/// script's hash the reference's.
fn script(v: &Value, case: &Value) -> LockingScript {
    if let Some(hex) = case["locking_script"].as_str() {
        return LockingScript::from_hex(hex).unwrap();
    }
    let reference = LockingScript::from_hex(v["cases"][0]["locking_script"].as_str().unwrap());
    let key = PushDrop::decode(&reference.unwrap())
        .unwrap()
        .locking_public_key;
    let padding = case["padding"].as_u64().unwrap() as usize;
    let text = format!(
        "{}{}",
        v["reference_text"].as_str().unwrap(),
        " ".repeat(padding)
    );
    let signature = from_hex(case["signature"].as_str().unwrap()).unwrap();
    let script = PushDrop::new(key, vec![text.into_bytes(), signature]).lock();
    assert_eq!(
        to_hex(&sha256(&script.to_binary())),
        case["locking_script_sha256"].as_str().unwrap(),
        "{}: the rebuilt token is not the reference's",
        case["name"]
    );
    script
}

/// How many identities and certificates the two parsers return for `script`.
async fn read(script: LockingScript, subject: &str) -> Result<(usize, usize), String> {
    let resolver = lock_position::answering("ls_identity", script);
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .map_err(|e| e.to_string())?;
    let certificates = client
        .discover_certificates(subject)
        .await
        .map_err(|e| e.to_string())?;
    Ok((identities.len(), certificates.len()))
}

#[tokio::test]
async fn an_identity_record_is_read_only_when_the_reference_discovery_reads_it_553() {
    let v = vector();
    let subject = v["subject"].as_str().unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 26);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = match case["decode"]["outcome"].as_str().unwrap() {
            "read" => Ok((1, 1)),
            "skipped" => Ok((0, 0)),
            other => panic!("{name}: unexpected outcome {other}"),
        };
        assert_eq!(
            read(script(&v, case), subject).await,
            expected,
            "{name}: {}",
            case["check"]
        );
        // The wallet's verifier answers the same but where its evidence
        // layer refuses the whole answer first
        if EVIDENCE_REFUSED.contains(&name) {
            assert_eq!(case["wallet"]["outcome"], "refused", "{name}");
            assert_eq!(case["wallet"]["words"], "Transaction evidence: limit");
        } else {
            assert_eq!(case["wallet"], case["decode"], "{name}");
        }
    }
    assert_eq!(cases[0]["name"], "reference");
    assert_eq!(cases[0]["decode"]["outcome"], "read");
}

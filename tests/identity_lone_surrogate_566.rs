//! #566: a lone UTF-16 surrogate escape in an `ls_identity` revelation
//! token's certificate JSON, read as the reference's discovery reads it
//! (`ts-stack@edf6e03`
//! `wallet-toolbox/src/utility/identityUtils.ts:87-132,497-559`: `JSON.parse`
//! keeps a lone unit, `TextEncoder` writes it as U+FFFD under the
//! certificate's signature, `Certificate.ts:73-75,280-296`). Against
//! `tests/vectors/identity_lone_surrogate_566.json`
//! (`tests/support/identity_lone_surrogate_566.mjs`, Node v22.18.0): twenty-one
//! tokens signed for the subject 9, each served through `resolve_by_attributes`
//! and `discover_certificates`, read or skipped as `parseResults` decides,
//! a read certificate's fields held as the bytes `TextEncoder` writes for
//! the reference's strings and its revealed fields decrypted to the
//! reference's; three stated residues enumerated. Hermetic: an in-process
//! resolver on an `.invalid` host.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::identity::IdentityClient;
use bsv_rs::primitives::to_hex;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::Value;

/// The reference reads these and this crate skips them: two field names a
/// `String` holds as one (two lone units, a lone unit beside U+FFFD), and a
/// lone unit ICU sorts before U+E000 (any private-use or unassigned BMP
/// character above U+DFFF) where this crate's collation puts U+FFFD after it, so the binary signed is not the one rebuilt
/// (`Certificate.ts:282`). The #566 parity note states them.
const READ_THERE_SKIPPED_HERE: [&str; 3] = [
    "field_names_two_lone_units",
    "field_names_lone_and_replacement",
    "field_names_lone_and_private_use",
];
fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_lone_surrogate_566.json")).unwrap()
}

fn client(script: LockingScript) -> IdentityClient<ProtoWallet> {
    let resolver = lock_position::answering("ls_identity", script);
    IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver)
}

/// How many identities and certificates the two parsers return for `script`.
async fn counts(script: LockingScript, subject: &str) -> (usize, usize) {
    let client = client(script);
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .unwrap();
    let certificates = client.discover_certificates(subject).await.unwrap();
    (identities.len(), certificates.len())
}

/// A recorded entry list as (name bytes, value bytes) hex pairs.
fn recorded(entries: &Value) -> Vec<(String, String)> {
    entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let text = |k: &str| e[k].as_str().unwrap().to_string();
            (text("name_bytes"), text("value_bytes"))
        })
        .collect()
}

fn held(map: &IndexMap<String, String>) -> Vec<(String, String)> {
    map.iter()
        .map(|(k, v)| (to_hex(k.as_bytes()), to_hex(v.as_bytes())))
        .collect()
}

#[tokio::test]
async fn a_lone_surrogate_escape_is_read_as_the_reference_discovery_reads_it_566() {
    let v = vector();
    let subject = v["subject"].as_str().unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 21);
    assert_eq!(cases[0]["name"], "control");
    let mut read_with_surrogate = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let reference = case["outcome"].as_str().unwrap();
        let expected = match (reference, name) {
            (_, n) if READ_THERE_SKIPPED_HERE.contains(&n) => {
                assert_eq!(reference, "read", "{name}");
                (0, 0)
            }
            ("read", _) => (1, 1),
            ("skipped", _) => (0, 0),
            (other, _) => panic!("{name}: unexpected outcome {other}"),
        };
        assert_eq!(
            counts(script.clone(), subject).await,
            expected,
            "{name}: {}",
            case["check"]
        );
        if reference != "read" || expected == (0, 0) {
            continue;
        }
        // The certificate read: its fields the bytes TextEncoder writes for
        // the reference's strings, in its order; its revealed fields
        // decrypted by anyone to the reference's
        let mut certificate = client(script)
            .discover_certificates(subject)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(
            held(&certificate.certificate.fields),
            recorded(&case["fields"]),
            "{name}: fields"
        );
        let decrypted = certificate
            .decrypt_fields(&ProtoWallet::anyone(), None, None, None)
            .await
            .unwrap();
        assert_eq!(
            held(&decrypted),
            recorded(&case["decrypted_fields"]),
            "{name}: decrypted fields"
        );
        if name != "control" {
            read_with_surrogate += 1;
        }
    }
    // Seven records with a lone surrogate the reference reads, read here
    assert_eq!(read_with_surrogate, 7);
}

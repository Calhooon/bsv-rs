//! bsv-rs#1118s (stable line): the identity resolve-by-key door and the
//! revocation finder read EVERY output of a lookup answer, not only the first,
//! and the key door returns only a record whose subject is the asked key.
//!
//! Two matters of the single-output positional read on the 0.8 line, both
//! closed on the 0.9 line by its list-returning resolve (#737, a breaking
//! Option->Vec change not back-portable as-is):
//!  - availability (audit finding): a non-parsing output at position 0 masked
//!    an honest record at a later index, so the resolve returned `None`;
//!  - integrity (the adjacent question): the key door returned a record whose
//!    subject was not the asked key, so a dishonest host could bind the query
//!    to another key's record.
//!
//! Hermetic: an in-process `ls_identity` resolver on a unique `.invalid` host
//! per client, every token built by this crate's own writers, no network and
//! no wall clock.

#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use std::sync::Arc;

use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{from_base64, to_base64, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, EncryptArgs, KeyDeriver, ProtoWallet, Protocol,
    SecurityLevel,
};

const XCERT: &str = "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=";

fn protocol() -> Protocol {
    Protocol::from_tuple((1, "identity")).unwrap()
}

fn lock_key(subject: &PublicKey) -> PublicKey {
    KeyDeriver::new(None)
        .derive_public_key(
            &protocol(),
            "1",
            &Counterparty::Other(subject.clone()),
            false,
        )
        .unwrap()
}

fn anyone_pub() -> PublicKey {
    let mut b = [0u8; 32];
    b[31] = 1;
    PrivateKey::from_bytes(&b).unwrap().public_key()
}

fn subject_sig(subject: &PrivateKey, field0: &[u8]) -> Vec<u8> {
    ProtoWallet::new(Some(subject.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(field0.to_vec()),
            hash_to_directly_sign: None,
            protocol_id: protocol(),
            key_id: "1".to_string(),
            counterparty: Some(Counterparty::Anyone),
        })
        .unwrap()
        .signature
}

fn anyone_keyring_entry(
    subject: &PrivateKey,
    serial: &[u8; 32],
    field: &str,
    value: &str,
) -> Vec<u8> {
    let proto = Protocol::new(SecurityLevel::Counterparty, "certificate field encryption");
    let key_id = format!("{} {}", to_base64(serial), field);
    ProtoWallet::new(Some(subject.clone()))
        .encrypt(EncryptArgs {
            plaintext: value.as_bytes().to_vec(),
            protocol_id: proto,
            key_id,
            counterparty: Some(Counterparty::Other(anyone_pub())),
        })
        .unwrap()
        .ciphertext
}

/// A subject-authored, signed two-field identity token (the reference form the
/// reader authenticates), whose certifier is `certifier` (a non-anchored key).
fn token(subject: &PrivateKey, certifier: &PrivateKey, name: &str) -> LockingScript {
    use bsv_rs::auth::Certificate;
    let cert_type: [u8; 32] = from_base64(XCERT).unwrap().try_into().unwrap();
    let serial = [2u8; 32];
    let mut cert = Certificate::new(
        cert_type,
        serial,
        subject.public_key(),
        certifier.public_key(),
    );
    cert.set_field("userName".to_string(), b"master-encrypted".to_vec());
    cert.sign(certifier).unwrap();
    let kr = anyone_keyring_entry(subject, &serial, "userName", name);
    let mut fields = serde_json::Map::new();
    fields.insert(
        "userName".into(),
        serde_json::json!(to_base64(b"master-encrypted")),
    );
    let mut keyring = serde_json::Map::new();
    keyring.insert("userName".into(), serde_json::json!(to_base64(&kr)));
    let json = serde_json::json!({
        "type": to_base64(&cert_type),
        "serialNumber": to_base64(&serial),
        "subject": subject.public_key().to_hex(),
        "certifier": certifier.public_key().to_hex(),
        "fields": fields,
        "signature": to_base64(cert.signature.as_ref().unwrap()),
        "keyring": keyring,
    });
    let field0 = serde_json::to_vec(&json).unwrap();
    let field1 = subject_sig(subject, &field0);
    PushDrop::new(lock_key(&subject.public_key()), vec![field0, field1]).lock()
}

/// A PushDrop output that decodes but whose first field is not certificate
/// JSON: `parse_output_to_certificate` returns `Ok(None)` for it. Distinct txid.
fn bad_script(seed: u8) -> LockingScript {
    let mut b = [0u8; 32];
    b[31] = seed;
    let k = PrivateKey::from_bytes(&b).unwrap();
    PushDrop::new(
        lock_key(&k.public_key()),
        vec![format!("not-json-{seed}").into_bytes(), vec![seed]],
    )
    .lock()
}

fn output_of(script: LockingScript) -> OutputListItem {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    let leaf = MerklePathLeaf::new_txid(0, tx.id());
    let mut beef = Beef::new();
    let index = beef.merge_bump(MerklePath::new(900, vec![vec![leaf]]).unwrap());
    let _ = beef.merge_raw_tx(tx.to_binary(), Some(index));
    OutputListItem {
        beef: beef.to_binary(),
        output_index: 0,
        context: None,
    }
}

/// An output whose transaction has NO output at index 0 (a tx with zero
/// outputs): it parses, but the revocation finder cannot read its configured
/// output index, so it must be skipped, not fail the whole call.
fn zero_output_of(seed: u8) -> OutputListItem {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new(format!("{:02x}", seed).repeat(32), 0))
        .unwrap();
    let leaf = MerklePathLeaf::new_txid(0, tx.id());
    let mut beef = Beef::new();
    let index = beef.merge_bump(MerklePath::new(900, vec![vec![leaf]]).unwrap());
    let _ = beef.merge_raw_tx(tx.to_binary(), Some(index));
    OutputListItem {
        beef: beef.to_binary(),
        output_index: 0,
        context: None,
    }
}

fn resolver(tag: &str, outs: Vec<OutputListItem>) -> Arc<LookupResolver> {
    struct Host(Vec<OutputListItem>);
    #[async_trait(?Send)]
    impl OverlayLookupFacilitator for Host {
        async fn lookup(
            &self,
            _u: &str,
            _q: &LookupQuestion,
            _t: Option<u64>,
        ) -> bsv_rs::Result<LookupAnswer> {
            Ok(LookupAnswer::OutputList {
                outputs: self.0.clone(),
            })
        }
    }
    Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Host(outs))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(std::collections::HashMap::from([(
            "ls_identity".to_string(),
            vec![format!("https://ls_identity.{tag}.invalid")],
        )])),
        ..Default::default()
    }))
}

fn client(tag: &str, outs: Vec<OutputListItem>) -> IdentityClient<ProtoWallet> {
    IdentityClient::with_resolver(
        ProtoWallet::new(None),
        IdentityClientConfig::default(),
        resolver(tag, outs),
    )
}

// --- availability: a non-parsing output at position 0 masks nothing ---------

#[tokio::test]
async fn a_non_parsing_output_at_position_zero_does_not_mask_an_honest_record() {
    let party = PrivateKey::random();
    let cert_key = PrivateKey::random();
    let good = output_of(token(&party, &cert_key, "Alice"));
    let bad = output_of(bad_script(7));

    // the honest record sits at index 1, behind a decoding-but-not-a-certificate
    // output at index 0.
    let c = client("avail", vec![bad, good]);
    let got = c
        .resolve_by_identity_key(&party.public_key().to_hex(), false)
        .await
        .unwrap();
    assert!(
        got.is_some(),
        "the honest record at a later index must still be found"
    );
    assert_eq!(got.unwrap().identity_key, party.public_key().to_hex());
}

// --- integrity: the key door binds the returned subject to the asked key -----

#[tokio::test]
async fn resolve_by_key_returns_only_a_record_whose_subject_is_the_asked_key() {
    let party = PrivateKey::random();
    let victim = PrivateKey::random();
    let cert_key = PrivateKey::random();
    assert_ne!(party.public_key().to_hex(), victim.public_key().to_hex());

    // a record of `party`, served for a query about `victim`.
    let c = client(
        "bind",
        vec![output_of(token(&party, &cert_key, "Someone Else"))],
    );
    let got = c
        .resolve_by_identity_key(&victim.public_key().to_hex(), false)
        .await
        .unwrap();
    assert!(
        got.is_none(),
        "a record whose subject is not the asked key must not be returned"
    );
}

// --- the honest case is unchanged -------------------------------------------

#[tokio::test]
async fn an_honest_record_of_the_asked_key_still_resolves() {
    let party = PrivateKey::random();
    let cert_key = PrivateKey::random();
    let c = client("honest", vec![output_of(token(&party, &cert_key, "Alice"))]);
    let got = c
        .resolve_by_identity_key(&party.public_key().to_hex(), false)
        .await
        .unwrap();
    assert_eq!(got.unwrap().identity_key, party.public_key().to_hex());
}

// --- availability: the revocation finder skips an unusable output -----------

#[tokio::test]
async fn the_revocation_finder_skips_an_unusable_output_at_position_zero() {
    // index 0 has a transaction with no output at the configured index; index 1
    // is usable. The finder must reach index 1 (then the key-only ProtoWallet's
    // create_action is what stops it), not fail on index 0's missing output.
    let party = PrivateKey::random();
    let cert_key = PrivateKey::random();
    let c = client(
        "revoke",
        vec![
            zero_output_of(9),
            output_of(token(&party, &cert_key, "Alice")),
        ],
    );
    let err = c
        .revoke_certificate_revelation("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
        .await
        .expect_err("the key-only wallet cannot complete the revocation");
    let msg = format!("{err}");
    assert!(
        !msg.contains("out of range"),
        "the finder must skip the unusable output, not fail on it: {msg}"
    );
    // The finder must REACH the usable revelation at index 1, not stop at the
    // unusable output at index 0. A read of only the first output returns the
    // finder's own "No revelation found" error; reading every output reaches
    // index 1 and attempts the revocation, where the key-only wallet's
    // create_action is what stops the call. Pin both so a first-only regression
    // (reading just output 0) is caught, not only an index-0 panic.
    assert!(
        !msg.contains("No revelation found") && msg.contains("createAction"),
        "the finder must reach the usable output at index 1 (the key-only wallet \
         then stops the revocation at create_action); a first-only read stops at \
         index 0 with \"No revelation found\": {msg}"
    );
}

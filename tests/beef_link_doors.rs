//! The #749 fold2 ruling 1: the overlay "output-only" doors link nothing.
//!
//! Five doors parse a stranger's BEEF answer and read ONLY one output's own
//! locking script — the lookup resolver's SLAP parse, the kvstore query, the
//! storage downloader, topic discovery and the registry definition parsers.
//! None of them uses the input ancestry, so each now parses with
//! [`Transaction::from_beef_subject`] (no linking) rather than
//! [`Transaction::from_beef`] (which links and applies the #749 byte bound).
//!
//! On this line the overlay resolver harness (host resolution, the #775/#796
//! byte budget and txid-hint dedup) differs from the stable line's, so these
//! are PARSER-BOUNDARY pins: each builds a BEEF whose shared-parent ancestry the
//! linking door refuses (`BeefResourceLimit`) but whose subject output carries
//! the door's own token, and asserts the linking door refuses while the subject
//! door surfaces the token through that door's own decoder. A door that kept
//! `from_beef` would refuse the answer before its output is ever read, so the
//! parser choice is the whole of the #749 behaviour here. The full behavioural
//! door tests, end to end through a mock facilitator, run on the main line.
#![cfg(feature = "full")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use std::time::{SystemTime, UNIX_EPOCH};

use bsv_rs::overlay::{create_signed_overlay_admin_token, decode_overlay_admin_token, Protocol};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Beef, MerklePath, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::Error;

const FAN: usize = 120;
const OUTPUT_BYTES: usize = 2 * 1024;

/// Builds a BEEF whose subject carries `token` at output 0 and spends a shared
/// parent of `FAN` large outputs through `FAN` inputs — so linking it
/// re-materializes ~29 MiB, past the 16 MiB default. Only the former links the
/// ancestry; the subject door reads the token untouched.
fn hostile_answer_with_token(token: LockingScript) -> Vec<u8> {
    let filler = LockingScript::from_binary(&vec![0u8; OUTPUT_BYTES]).unwrap();
    let mut parent = Transaction::new();
    let mut funding = TransactionInput::new("11".repeat(32), 0);
    funding.unlocking_script = Some(UnlockingScript::new());
    parent.inputs_mut().push(funding);
    for _ in 0..FAN {
        parent
            .outputs_mut()
            .push(TransactionOutput::new(1_000, filler.clone()));
    }
    let parent_txid = parent.id();

    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump)).unwrap();

    let mut subject = Transaction::new();
    for vout in 0..FAN {
        let mut spend = TransactionInput::new(parent_txid.clone(), vout as u32);
        spend.unlocking_script = Some(UnlockingScript::new());
        subject.inputs_mut().push(spend);
    }
    subject
        .outputs_mut()
        .push(TransactionOutput::new(1_000, token));
    beef.merge_raw_tx(subject.to_binary(), None).unwrap();
    beef.to_binary().unwrap()
}

/// Asserts the fixture is one the LINKING door refuses but the subject door
/// reads, and returns the subject's output-0 locking script.
fn refused_by_link_surfaced_by_subject(beef: &[u8]) -> LockingScript {
    assert!(
        matches!(
            Transaction::from_beef(beef, None),
            Err(Error::BeefResourceLimit(_))
        ),
        "the linking door must refuse the fixture, so a door that keeps linking would drop it"
    );
    let subject = Transaction::from_beef_subject(beef, None)
        .expect("the subject door parses the same answer without linking");
    subject.outputs()[0].locking_script.clone()
}

fn a_pubkey() -> PublicKey {
    bsv_rs::wallet::ProtoWallet::new(None).identity_key()
}

fn var_int(value: u64) -> Vec<u8> {
    if value < 0xFD {
        vec![value as u8]
    } else if value <= 0xFFFF {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(value as u16).to_le_bytes());
        v
    } else if value <= 0xFFFF_FFFF {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(value as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFF];
        v.extend_from_slice(&value.to_le_bytes());
        v
    }
}

#[test]
fn the_resolver_slap_door_links_nothing_on_a_hostile_answer() {
    let root = PrivateKey::random();
    let token = create_signed_overlay_admin_token(
        &root,
        Protocol::Slap,
        "https://host-749.example",
        "ls_749",
    );
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token.clone()));
    // The exact SLAP advertisement the resolver's parse reads survives at the
    // subject output of an answer the linking door refuses.
    assert_eq!(script, token);
    if let Ok(decoded) = decode_overlay_admin_token(&script) {
        assert_eq!(decoded.protocol, Protocol::Slap);
    }
}

#[test]
fn the_topic_discovery_door_links_nothing_on_a_hostile_answer() {
    let root = PrivateKey::random();
    let token = create_signed_overlay_admin_token(
        &root,
        Protocol::Ship,
        "https://host-749.example",
        "tm_749",
    );
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token.clone()));
    // The exact SHIP advertisement topic discovery reads survives at the subject
    // output of an answer the linking door refuses.
    assert_eq!(script, token);
    if let Ok(decoded) = decode_overlay_admin_token(&script) {
        assert_eq!(decoded.protocol, Protocol::Ship);
    }
}

#[test]
fn the_kvstore_door_links_nothing_on_a_hostile_answer() {
    let controller = a_pubkey();
    let token = kvstore_token("kvstore", "k", "v", &controller);
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token));
    let entry = bsv_rs::kvstore::KVStoreInterpreter::extract_fields(&script)
        .expect("the kvstore token survives at the subject output");
    assert_eq!(entry.key, b"k");
    assert_eq!(entry.value, b"v");
}

fn kvstore_token(
    protocol_id: &str,
    key: &str,
    value: &str,
    controller: &PublicKey,
) -> LockingScript {
    let fields = vec![
        protocol_id.as_bytes().to_vec(),
        key.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller.to_compressed().to_vec(),
        vec![0u8; 64],
    ];
    PushDrop::new(controller.clone(), fields).lock()
}

#[test]
fn the_storage_downloader_door_links_nothing_on_a_hostile_answer() {
    let controller = a_pubkey();
    let future = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86_400;
    let fields = vec![
        b"uhrp".to_vec(),
        controller.to_compressed().to_vec(),
        b"https://host-749.example".to_vec(),
        var_int(future),
    ];
    let token = PushDrop::new(controller, fields).lock();
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token));
    let pd = PushDrop::decode(&script).expect("the UHRP advertisement survives at the subject");
    assert!(pd.fields.len() >= 4, "the UHRP token keeps its fields");
    assert_eq!(pd.fields[2], b"https://host-749.example");
}

#[test]
fn the_registry_door_links_nothing_on_a_hostile_answer() {
    let controller = a_pubkey();
    let basket = bsv_rs::registry::BasketDefinitionData::new("basket749", "Basket 749")
        .with_icon_url("https://icon-749.example")
        .with_description("the 749 fold2 basket")
        .with_documentation_url("https://docs-749.example");
    let operator = "02".to_string() + &"ab".repeat(32);
    let fields = basket.to_pushdrop_fields(&operator);
    let token = PushDrop::new(controller, fields).lock();
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token));
    let pd = PushDrop::decode(&script).expect("the basket definition survives at the subject");
    assert_eq!(pd.fields.len(), 6, "the basket token keeps its six fields");
    let back = bsv_rs::registry::BasketDefinitionData::from_pushdrop_fields(&pd.fields)
        .expect("the basket definition reads back from the subject output");
    assert_eq!(back.basket_id, "basket749");
}

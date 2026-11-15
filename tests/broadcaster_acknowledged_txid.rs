//! A broadcaster's success answers the submitted transaction's own id.
//!
//! On an accepted broadcast, `WhatsOnChainBroadcaster` and `ArcBroadcaster`
//! read the id the service names (the WhatsOnChain body, ARC's `txid` field)
//! through one rule (`src/transaction/broadcasters/acknowledged.rs`): a name
//! that is the submitted transaction's id answers as the service wrote it, no
//! name answers the submitted id, and any other name (another transaction's
//! id, or text that is no id) is `ERR_TXID_MISMATCH` carrying the submitted
//! id, never a success. Until this fix both answered the service's text as the
//! success's `txid`. `TeranodeBroadcaster` reads no name and answers the
//! submitted id; its cell is here as the third door of the shape.
//!
//! The cells: the other names through each door (RED before the fix); the
//! honest answers (unchanged); 20,000 honest answers through both doors, the
//! responses' digest pinned, equal on the tree before the fix and after it.
//! Every answer comes from a wiremock server on a loopback port (rule 4).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing
#![cfg(all(feature = "transaction", feature = "http"))]

use std::sync::{Arc, Mutex};

use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
#[allow(deprecated)] // ARC is deprecated on the 0.9 line; its door is still served
use bsv_rs::transaction::{
    ArcBroadcaster, BroadcastResult, BroadcastStatus, Broadcaster, TeranodeBroadcaster,
    Transaction, TransactionInput, TransactionOutput, WhatsOnChainBroadcaster, WocBroadcastNetwork,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A service whose next answer the test sets: (HTTP status, body,
/// content type).
#[derive(Clone, Default)]
struct Scripted(Arc<Mutex<(u16, String, &'static str)>>);

impl Scripted {
    fn set(&self, status: u16, body: impl Into<String>, json: bool) {
        let kind = if json {
            "application/json"
        } else {
            "text/plain"
        };
        *self.0.lock().unwrap() = (status, body.into(), kind);
    }
}

impl Respond for Scripted {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let (status, body, kind) = self.0.lock().unwrap().clone();
        ResponseTemplate::new(status).set_body_raw(body.into_bytes(), kind)
    }
}

struct Doors {
    _server: MockServer,
    service: Scripted,
    woc: WhatsOnChainBroadcaster,
    #[allow(deprecated)]
    arc: ArcBroadcaster,
    teranode: TeranodeBroadcaster,
}

async fn doors() -> Doors {
    let server = MockServer::start().await;
    let service = Scripted::default();
    Mock::given(wiremock::matchers::any())
        .respond_with(service.clone())
        .mount(&server)
        .await;
    #[allow(deprecated)]
    let arc = ArcBroadcaster::new(&server.uri(), None);
    Doors {
        woc: WhatsOnChainBroadcaster::with_base_url(
            &server.uri(),
            WocBroadcastNetwork::Mainnet,
            None,
        ),
        arc,
        teranode: TeranodeBroadcaster::new(&server.uri(), None),
        service,
        _server: server,
    }
}

/// A deterministic generator (xorshift64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn hex(&mut self, n: usize) -> String {
        (0..n).map(|_| format!("{:02x}", self.below(256))).collect()
    }
}

/// A transaction of one input and one output, its fields drawn from `r`
/// (built through `add_input`/`add_output`, doors both lines carry).
fn transaction(r: &mut Rng) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new(r.hex(32), r.below(4) as u32);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    tx.add_input(input).unwrap();
    let mut lock = vec![0x76, 0xa9, 0x14];
    lock.extend((0..20).map(|_| r.below(256) as u8));
    lock.extend([0x88, 0xac]);
    let script = LockingScript::from_binary(&lock).unwrap();
    tx.add_output(TransactionOutput::new(1 + r.below(100_000), script))
        .unwrap();
    tx
}

fn fixed_transaction() -> Transaction {
    transaction(&mut Rng(0x0ac4_0f7e_d7c1_d000))
}

/// One whose input carries its source transaction, as Extended Format (the
/// Teranode door's encoding) asks.
fn fixed_ef_transaction() -> Transaction {
    let source = fixed_transaction();
    let mut input = TransactionInput::with_source_transaction(source, 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        1,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ))
    .unwrap();
    tx
}

fn arc_body(txid: Option<&str>, status: &str) -> String {
    match txid {
        Some(t) => format!(r#"{{"txid":"{t}","txStatus":"{status}"}}"#),
        None => format!(r#"{{"txStatus":"{status}"}}"#),
    }
}

/// The success's `txid` of `result`, or the failure's code and `txid`.
fn verdict(result: &BroadcastResult) -> String {
    match result {
        Ok(r) => format!("ok {:?} {}", r.status, r.txid),
        Err(f) => format!("err {} {:?}", f.code, f.txid),
    }
}

const ANOTHER_TXID: &str = "f67cfb4c12b221ab1b5f6fe6db5a72f82ebc6aad8f28c6d0e5427043a2c5b0a9";

/// What a service may write on a success that does not name the submitted
/// transaction: another transaction's id, a page, an error object, a
/// truncated id, the id with a byte more.
fn other_names(expected: &str) -> Vec<String> {
    vec![
        ANOTHER_TXID.to_string(),
        "<html><body>maintenance</body></html>".to_string(),
        r#"{"error":"busy"}"#.to_string(),
        expected[..63].to_string(),
        format!("{expected}0"),
    ]
}

#[tokio::test]
async fn a_whatsonchain_success_naming_another_transaction_is_a_mismatch() {
    let d = doors().await;
    let tx = fixed_transaction();
    let expected = tx.id();
    for name in other_names(&expected) {
        for body in [name.clone(), format!("\"{name}\"")] {
            d.service.set(200, body.clone(), false);
            let result = d.woc.broadcast(&tx).await;
            assert_eq!(
                verdict(&result),
                format!("err ERR_TXID_MISMATCH Some({expected:?})"),
                "WhatsOnChain answered {body:?}"
            );
        }
    }
}

#[tokio::test]
async fn an_arc_success_naming_another_transaction_is_a_mismatch() {
    let d = doors().await;
    let tx = fixed_transaction();
    let expected = tx.id();
    for name in other_names(&expected) {
        for status in ["SEEN_ON_NETWORK", "MINED", "STORED"] {
            let body = format!(
                r#"{{"txid":{},"txStatus":"{status}"}}"#,
                serde_json::Value::String(name.clone())
            );
            d.service.set(200, body.clone(), true);
            let result = d.arc.broadcast(&tx).await;
            assert_eq!(
                verdict(&result),
                format!("err ERR_TXID_MISMATCH Some({expected:?})"),
                "ARC answered {body}"
            );
        }
    }
}

#[tokio::test]
async fn the_honest_answers_still_succeed_with_the_submitted_id() {
    let d = doors().await;
    let tx = fixed_transaction();
    let expected = tx.id();
    let upper = expected.to_ascii_uppercase();

    for (body, txid) in [
        (expected.clone(), expected.clone()),
        (format!("\"{expected}\""), expected.clone()),
        (format!("\"{expected}\"\n"), expected.clone()),
        (format!("  {expected}  "), expected.clone()),
        (upper.clone(), upper.clone()),
        (String::new(), expected.clone()),
        ("\"\"".to_string(), expected.clone()),
    ] {
        d.service.set(200, body.clone(), false);
        let result = d.woc.broadcast(&tx).await;
        assert_eq!(verdict(&result), format!("ok Success {txid}"), "{body:?}");
    }

    for (named, txid) in [
        (Some(expected.as_str()), expected.clone()),
        (Some(upper.as_str()), upper.clone()),
        (None, expected.clone()),
    ] {
        d.service.set(200, arc_body(named, "SEEN_ON_NETWORK"), true);
        let result = d.arc.broadcast(&tx).await;
        assert_eq!(verdict(&result), format!("ok Success {txid}"), "{named:?}");
    }
}

#[tokio::test]
async fn teranode_answers_the_submitted_id_whatever_the_body_names() {
    let d = doors().await;
    let tx = fixed_ef_transaction();
    let expected = tx.id();
    for body in other_names(&expected).into_iter().chain([expected.clone()]) {
        d.service.set(200, body.clone(), false);
        let result = d.teranode.broadcast(&tx).await;
        let response = result.unwrap();
        assert_eq!(response.status, BroadcastStatus::Success);
        assert_eq!(response.txid, expected, "{body:?}");
    }
}

/// An honest service's answer to the submitted `txid`, the forms drawn by
/// `r`: WhatsOnChain the id bare, quoted, padded, upper-case or nothing, or a
/// refusal; ARC each status word with the id, without it, or a refusal.
fn honest_answer(r: &mut Rng, txid: &str, arc: bool) -> (u16, String) {
    let id = if r.below(8) == 0 {
        txid.to_ascii_uppercase()
    } else {
        txid.to_string()
    };
    if !arc {
        return match r.below(7) {
            0 => (200, id),
            1 => (200, format!("\"{id}\"")),
            2 => (200, format!("\"{id}\"\n")),
            3 => (200, format!(" {id}\r\n")),
            4 => (200, String::new()),
            5 => (400, "Missing inputs".to_string()),
            _ => (500, String::new()),
        };
    }
    const WORDS: [&str; 15] = [
        "SUCCESS",
        "RECEIVED",
        "QUEUED",
        "STORED",
        "ANNOUNCED_TO_NETWORK",
        "REQUESTED_BY_NETWORK",
        "SENT_TO_NETWORK",
        "ACCEPTED_BY_NETWORK",
        "SEEN_ON_NETWORK",
        "MINED",
        "CONFIRMED",
        "IMMUTABLE",
        "REJECTED",
        "DOUBLE_SPEND_ATTEMPTED",
        "SEEN_IN_ORPHAN_MEMPOOL",
    ];
    let word = WORDS[r.below(WORDS.len() as u64) as usize];
    match r.below(6) {
        0 => (200, arc_body(None, word)),
        1 => (
            422,
            r#"{"status":422,"title":"Unprocessable","detail":"bad"}"#.to_string(),
        ),
        _ => (200, arc_body(Some(&id), word)),
    }
}

/// The verdicts of both doors on 20,000 honest answers (10,000 transactions,
/// each through WhatsOnChain and ARC), as one digest: the same on the tree
/// before the fix and after it (`HONEST_DIGEST` was read on both).
const HONEST_DIGEST: &str = "99cc1e2e1e0b1e9e850cbeb7ccdd4c01bb0842fbc9ca2abd99d40eb83b3458ae";

#[tokio::test]
async fn twenty_thousand_honest_answers_are_answered_as_before() {
    let d = doors().await;
    let mut r = Rng(0x3a11_b5c0_de23_1120);
    let mut all = String::new();
    let mut successes = [0usize; 2];
    for _ in 0..10_000 {
        let tx = transaction(&mut r);
        let txid = tx.id();
        for arc in [false, true] {
            let (status, body) = honest_answer(&mut r, &txid, arc);
            d.service.set(status, body, arc);
            let result = if arc {
                d.arc.broadcast(&tx).await
            } else {
                d.woc.broadcast(&tx).await
            };
            successes[usize::from(arc)] += usize::from(result.is_ok());
            match &result {
                Ok(ok) => all.push_str(&format!(
                    "ok {:?} {} {} {:?}\n",
                    ok.status, ok.txid, ok.message, ok.competing_txs
                )),
                Err(e) => all.push_str(&format!(
                    "err {:?} {} {:?} {} {:?}\n",
                    e.status, e.code, e.txid, e.description, e.more
                )),
            }
        }
    }
    assert!(
        successes[0] >= 5_000 && successes[1] >= 4_000,
        "{successes:?}"
    );
    assert_eq!(to_hex(&sha256(all.as_bytes())), HONEST_DIGEST);
}

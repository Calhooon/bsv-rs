//! #815's fold: a host's answer to `/submit` at the door it comes through.
//!
//! `tests/overlay_ship_steak_815.rs` hands the broadcaster a typed `Steak`
//! from a scripted facilitator; a host's answer arrives as bytes, through
//! `HttpsOverlayBroadcastFacilitator::send`. This table sends every answer
//! shape of `vectors/ship_steak_door_815.json` (79 cases;
//! `support/ship_steak_door_815.mjs`, the reference's `TopicBroadcaster`
//! over its own `HTTPSOverlayBroadcastFacilitator` on a stub `fetch`,
//! `ts-stack@edf6e03` under Node v22.18.0) through that door, from a
//! `wiremock` server of its own per case (a loopback listener for the two
//! cases wiremock cannot write: a chunked body and no content type), and
//! reads two answers per case:
//!
//! - `send`: the facilitator's own answer, `Ok` or the refusal's words;
//! - the broadcast's code through a `TopicBroadcaster` whose one interested
//!   host (this crate's signed advertisement, read through a real
//!   `LookupResolver`) is asked through the same facilitator, the `.invalid`
//!   advertised origin mapped onto the case's server.
//!
//! Each cell is the reference's: the broadcast's code on all 79; the
//! refusal's words at `send` wherever the reference refuses the host, save
//! the cells of `WORDS_STATED` (refused on both sides in other words) and
//! `{}`, which `send` hands back empty and the broadcaster refuses.
//!
//! Until the fold `send` read the body with `response.json::<Steak>()`: an
//! instruction with a fourth field, a `coinsRemoved` of `null`, a body past
//! 1 MiB were taken, where the reference refuses each (`SHIPBroadcaster.ts:
//! 251-256`, `:261-265`, `:272-297`), and an index written `1.0`, `1e2` or
//! `-0` and a body behind a BOM were refused, where the reference takes
//! them. On a scratch copy of `a55b1f1e` both tests are RED: 13 of the 79
//! broadcast verdicts and 63 `send` words differ.
#![cfg(all(feature = "overlay", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, HttpsOverlayBroadcastFacilitator, LookupAnswer,
    LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayBroadcastFacilitator, OverlayLookupFacilitator, Protocol, Steak, TaggedBEEF,
    TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VECTOR: &str = include_str!("vectors/ship_steak_door_815.json");

/// Refused on both sides, in other words (stated in the CHANGELOG's parity
/// note): this crate's status sentence is older than #815, and three bodies
/// the reference parses and then refuses are no JSON to `serde_json`.
const WORDS_STATED: [(&str, &str); 5] = [
    (
        "status_500_with_steak",
        "Broadcast failed with HTTP status: 500 Internal Server Error",
    ),
    (
        "status_404",
        "Broadcast failed with HTTP status: 404 Not Found",
    ),
    ("topic_lone_surrogate", "SHIP response is not valid JSON."),
    ("index_past_double", "SHIP response is not valid JSON."),
    ("index_nested_200", "SHIP response is not valid JSON."),
];

/// A case's body, by its recipe (the recorder's `bodyOf`).
fn body_of(body: &Value, topic: &str) -> Vec<u8> {
    let t = serde_json::to_string(topic).unwrap();
    match body["kind"].as_str().unwrap() {
        "text" => body["text"].as_str().unwrap().as_bytes().to_vec(),
        "hex" => bsv_rs::primitives::from_hex(body["hex"].as_str().unwrap()).unwrap(),
        "padded" => {
            let mut bytes = vec![0x20u8; body["total"].as_u64().unwrap() as usize];
            let text = body["text"].as_str().unwrap().as_bytes();
            bytes[..text.len()].copy_from_slice(text);
            bytes
        }
        "indexes" => {
            let list: Vec<String> = (0..body["count"].as_u64().unwrap())
                .map(|i| i.to_string())
                .collect();
            let list = format!("[{}]", list.join(","));
            let named = body["list"].as_str().unwrap();
            let mut members = vec![
                ("outputsToAdmit", "[]".to_string()),
                ("coinsToRetain", "[]".to_string()),
            ];
            match members.iter_mut().find(|(name, _)| *name == named) {
                Some(member) => member.1 = list,
                None => members.push(("coinsRemoved", list)),
            }
            let members: Vec<String> = members
                .iter()
                .map(|(name, list)| format!("\"{name}\":{list}"))
                .collect();
            format!("{{{t}:{{{}}}}}", members.join(",")).into_bytes()
        }
        "topics" => {
            let entries: Vec<String> = (0..body["count"].as_u64().unwrap() as usize)
                .map(|i| {
                    format!(
                        "\"tm_n{}\":{{\"outputsToAdmit\":[0],\"coinsToRetain\":[]}}",
                        "x".repeat(i)
                    )
                })
                .collect();
            format!("{{{}}}", entries.join(",")).into_bytes()
        }
        "nested" => {
            let depth = body["depth"].as_u64().unwrap() as usize;
            format!(
                "{{{t}:{{\"outputsToAdmit\":[{}{}],\"coinsToRetain\":[]}}}}",
                "[".repeat(depth),
                "]".repeat(depth)
            )
            .into_bytes()
        }
        other => panic!("unknown body kind {other}"),
    }
}

/// What keeps a case's server alive.
enum Server {
    /// Held for its `Drop`, which stops the server.
    Mock(#[allow(dead_code)] MockServer),
    Raw(tokio::task::JoinHandle<()>),
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Server::Raw(task) = self {
            task.abort();
        }
    }
}

/// A loopback listener answering every request with `head` and the body in
/// chunks (no declared length) or whole.
async fn raw_server(head: String, body: Vec<u8>, chunked: bool) -> (String, Server) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            // The request: its head, then the body its length declares
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let text = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length = text
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let mut answer = head.clone().into_bytes();
            if chunked {
                answer
                    .extend_from_slice(b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
                for chunk in body.chunks(64 * 1024) {
                    answer.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    answer.extend_from_slice(chunk);
                    answer.extend_from_slice(b"\r\n");
                }
                answer.extend_from_slice(b"0\r\n\r\n");
            } else {
                answer.extend_from_slice(
                    format!(
                        "Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                answer.extend_from_slice(&body);
            }
            // The client may hang up at its bound: not this server's error
            let _ = stream.write_all(&answer).await;
            let _ = stream.shutdown().await;
        }
    });
    (uri, Server::Raw(task))
}

/// The case's server: its status, content type and body at `POST /submit`.
async fn serve(case: &Value, body: Vec<u8>) -> (String, Server) {
    let status = case["status"].as_u64().unwrap_or(200) as u16;
    let undeclared = case["undeclared"].as_bool().unwrap_or(false);
    let no_type = case.get("contentType").is_some_and(Value::is_null);
    if undeclared || no_type {
        assert_eq!(status, 200);
        let mut head = String::from("HTTP/1.1 200 OK\r\n");
        if !no_type {
            head.push_str("Content-Type: application/json\r\n");
        }
        return raw_server(head, body, undeclared).await;
    }
    let content_type = case["contentType"].as_str().unwrap_or("application/json");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(status).set_body_raw(body, content_type))
        .mount(&server)
        .await;
    (server.uri(), Server::Mock(server))
}

/// A lookup facilitator answering every question with its one answer.
struct Scripted(LookupAnswer);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(self.0.clone())
    }
}

/// The shipped HTTPS facilitator, asked at the case's server whatever
/// origin the advertisement names (an advertisement cannot name loopback).
struct Rerouted {
    door: HttpsOverlayBroadcastFacilitator,
    to: String,
}

#[async_trait::async_trait(?Send)]
impl OverlayBroadcastFacilitator for Rerouted {
    async fn send(&self, _url: &str, tagged: &TaggedBEEF) -> bsv_rs::Result<Steak> {
        self.door.send(&self.to, tagged).await
    }
}

/// One SHIP advertisement of `topic` at `origin` by this crate's writer,
/// proven by a block of its own, as a lookup output; the transaction
/// broadcast is the advertisement itself.
fn advertisement(origin: &str, topic: &str) -> (OutputListItem, Transaction) {
    let script =
        create_signed_overlay_admin_token(&PrivateKey::random(), Protocol::Ship, origin, topic);
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32).parse().unwrap(), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    let txid = tx.id();
    let mut beef = Beef::new();
    let index = beef
        .merge_bump(MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, txid)]]).unwrap());
    beef.merge_raw_tx(tx.to_binary(), Some(index)).unwrap();
    let bytes = beef.to_binary().unwrap();
    let subject = Transaction::from_beef(&bytes, None).unwrap();
    (
        OutputListItem {
            beef: bytes,
            output_index: 0,
            context: None,
            txid: None,
        },
        subject,
    )
}

/// The broadcast's code (`None` on success) with the one interested host
/// asked through the shipped facilitator at `uri`.
async fn broadcast(n: usize, topic: &str, uri: &str) -> Option<String> {
    let (output, subject) = advertisement(
        &format!("https://host-{n}.ship-steak-door-815-rs.invalid"),
        topic,
    );
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Scripted(LookupAnswer::OutputList {
            outputs: vec![output],
        }))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_ship".to_string(),
            vec![format!(
                "https://ls-ship-{n}.ship-steak-door-815-rs.invalid"
            )],
        )])),
        ..Default::default()
    }));
    let b = TopicBroadcaster::new(
        vec![topic.to_string()],
        TopicBroadcasterConfig {
            resolver: Some(resolver),
            facilitator: Some(Arc::new(Rerouted {
                door: HttpsOverlayBroadcastFacilitator::new(true),
                to: uri.to_string(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
    b.broadcast_tx(&subject).await.err().map(|f| f.code)
}

/// Every recorded answer shape through the shipped door: the broadcast's
/// code the reference's on every case, and `send`'s refusal in the
/// reference's words wherever the reference refuses the host.
#[tokio::test]
async fn every_recorded_answer_shape_is_the_references_at_the_door_815() {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let topic = vector["topic"].as_str().unwrap();
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 79, "the vector's count");
    let tagged = TaggedBEEF::new(vec![1, 2, 3], vec![topic.to_string()]);
    let mut differing = Vec::new();
    println!("case | reference (broadcast; words) | here (broadcast; send)");
    for (n, case) in cases.iter().enumerate() {
        let name = case["name"].as_str().unwrap();
        let reference = &case["reference"];
        let ref_code = reference["broadcast"].as_str().map(str::to_string);
        let ref_words = reference["words"].as_str();
        let (uri, _server) = serve(case, body_of(&case["body"], topic)).await;

        let sent = HttpsOverlayBroadcastFacilitator::new(true)
            .send(&uri, &tagged)
            .await;
        let send = match &sent {
            Ok(steak) if steak.is_empty() => "Ok(empty)".to_string(),
            Ok(_) => "Ok".to_string(),
            Err(Error::OverlayError(words)) => words.clone(),
            Err(other) => format!("{other:?}"),
        };
        let code = broadcast(n, topic, &uri).await;
        println!("{name} | {ref_code:?}; {ref_words:?} | {code:?}; {send}");

        if code != ref_code {
            differing.push(format!(
                "{name}: the broadcast is {code:?} here, {ref_code:?} in the reference (send: {send})"
            ));
        }
        let refused_there = ref_code.as_deref() == Some("ERR_ALL_HOSTS_REJECTED");
        let expected = if !refused_there {
            "Ok".to_string()
        } else if name == "body_empty_object" {
            // Handed back empty; the broadcaster refuses it in the same words
            assert_eq!(ref_words, Some("Steak has no topics."));
            "Ok(empty)".to_string()
        } else if let Some((_, stated)) = WORDS_STATED.iter().find(|(stated, _)| *stated == name) {
            assert_ne!(ref_words, Some(*stated), "{name}: no longer a difference");
            stated.to_string()
        } else {
            ref_words.expect("a refused host's words").to_string()
        };
        if send != expected {
            differing.push(format!(
                "{name}: send is {send:?} here, {expected:?} expected"
            ));
        }
    }
    assert!(
        differing.is_empty(),
        "{} cells differ:\n{}",
        differing.len(),
        differing.join("\n")
    );
}

/// The finding by name: an instruction carrying a field other than
/// `outputsToAdmit`, `coinsToRetain` and `coinsRemoved` is refused by the
/// shipped facilitator in the reference's words (`:251-256`), and the host
/// that sent it is a failed host. On `a55b1f1e` `send` answered `Ok` and the
/// broadcast succeeded.
#[tokio::test]
async fn an_instruction_with_a_fourth_field_fails_its_host_at_the_door_815() {
    let topic = "tm_ship_steak";
    let body =
        format!("{{\"{topic}\":{{\"outputsToAdmit\":[0],\"coinsToRetain\":[],\"extra\":1}}}}");
    let case = serde_json::json!({});
    let (uri, _server) = serve(&case, body.into_bytes()).await;
    let sent = HttpsOverlayBroadcastFacilitator::new(true)
        .send(&uri, &TaggedBEEF::new(vec![1], vec![topic.to_string()]))
        .await;
    assert_eq!(
        sent.err(),
        Some(Error::OverlayError(
            "SHIP response contains unexpected instruction fields.".into()
        ))
    );
    assert_eq!(
        broadcast(1000, topic, &uri).await.as_deref(),
        Some("ERR_ALL_HOSTS_REJECTED")
    );
}

/// The door's topic bound at its edge (#815's second fold, the strength
/// read): a host that answers every one of the 64 topics it was sent is
/// taken, as `validateSTEAK` takes it (`:243`, `keys.length >
/// MAX_SHIP_TOPICS`), and the 65th answered topic is refused in its words
/// (the vector's `topics_65`). Until the fold no case had 64 topics sent,
/// so `>=` for `>` at `steak_body.rs`'s count went unseen.
#[tokio::test]
async fn a_host_answering_all_64_topics_it_was_sent_is_taken_at_the_door_815() {
    // `tm_` and two letters: 64 canonical names (`/^tm_[a-z]+(?:_[a-z]+)*$/`)
    let name = |i: usize| {
        let letter = |n: usize| char::from(b'a' + u8::try_from(n % 26).unwrap());
        format!("tm_{}{}", letter(i / 26), letter(i))
    };
    let answer = |count: usize| {
        let entries: Vec<String> = (0..count)
            .map(|i| {
                format!(
                    "\"{}\":{{\"outputsToAdmit\":[0],\"coinsToRetain\":[]}}",
                    name(i)
                )
            })
            .collect();
        format!("{{{}}}", entries.join(",")).into_bytes()
    };
    let sent: Vec<String> = (0..64).map(name).collect();
    let case = serde_json::json!({});
    let (uri, _server) = serve(&case, answer(64)).await;
    let steak = HttpsOverlayBroadcastFacilitator::new(true)
        .send(&uri, &TaggedBEEF::new(vec![1], sent.clone()))
        .await
        .unwrap();
    assert_eq!(steak.len(), 64);
    assert!(sent.iter().all(|topic| steak.contains_key(topic)));
    let (uri, _server) = serve(&case, answer(65)).await;
    let mut sent_65 = sent;
    sent_65.push(name(64));
    assert_eq!(
        HttpsOverlayBroadcastFacilitator::new(true)
            .send(&uri, &TaggedBEEF::new(vec![1], sent_65))
            .await
            .err(),
        Some(Error::OverlayError(
            "SHIP response contains too many topics.".into()
        ))
    );
}

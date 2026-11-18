//! #843: `ListOutputsResult.total_outputs` is 64-bit, as the reference's
//! `PositiveInteger64OrZero` is at its head (`ts-stack@11faa7d16`, `@bsv/sdk`
//! 4.1.1, `Wallet.interfaces.ts:36-44,662-673`; a `u32` here until 0.9.0, the
//! reference's `PositiveIntegerOrZero` at `edf6e03`).
//!
//! For a BRC-112 balance query (a basket of `balance <basket>` or
//! `p <module> balance <basket>`, `moduleBalanceQuery.ts:1,19-21`) the total
//! is the balance: the whole canonical varint on the binary wire
//! (`readVarIntBnStrict`, `WalletWireTransceiver.ts:725-733`), any nonnegative
//! integer in JSON, with no outputs and no BEEF
//! (`WalletResultValidation.ts:2093-2106`). Every other query keeps its count
//! rule: at most `2^32 - 1` on the wire, a safe integer in JSON.
//!
//! The wire frames are this crate's `WireWriter`'s; the totals 180, 2^40,
//! 2^64 - 2048 and 2^64 - 1, the count frame of 2^40 and the six framing
//! frames are the values of the reference's own tests
//! (`substrates/__tests/WalletWire.security.test.ts`, `reads a balance frame
//! as the full varint, converted to a number` and `keeps canonical
//! CompactSize framing for a balance frame`), the JSON values those of
//! `__tests/WalletResultValidation.security.test.ts`, `BRC-112 balance
//! results`. Every JSON spelling of the balance answer's three members is
//! replayed against the reference's own recorded answers
//! (`vectors/list_outputs_balance_843.json`, the last test).
//!
//! The totals are compared through the result's JSON, so the file compiles
//! against the `u32` field too and its failures there are runs, not builds.

#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde_json::{json, Value};

const BALANCE_BASKETS: [&str; 2] = ["balance default", "p color balance aa"];
const TWO_32: u64 = 1 << 32;
const TWO_53: u64 = 1 << 53;

/// Answers every call with the success byte and `body`.
struct CannedWire {
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl WalletWire for CannedWire {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        let mut answer = vec![0u8];
        answer.extend_from_slice(&self.body);
        Ok(answer)
    }
}

fn args(basket: &str) -> ListOutputsArgs {
    ListOutputsArgs {
        basket: basket.to_string(),
        tags: None,
        tag_query_mode: None,
        include: None,
        include_custom_instructions: None,
        include_tags: None,
        include_labels: None,
        limit: None,
        offset: None,
        seek_permission: None,
    }
}

/// `[totalOutputs: varint][BEEF: absent]`, this crate's writer's bytes.
fn frame(total: u64) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_var_int(total).write_optional_bytes(None);
    writer.into_bytes()
}

async fn read_wire(basket: &str, body: Vec<u8>) -> bsv_rs::Result<ListOutputsResult> {
    WalletWireTransceiver::new(CannedWire { body })
        .list_outputs(args(basket), None)
        .await
}

fn words(result: bsv_rs::Result<ListOutputsResult>) -> String {
    match result {
        Err(Error::WalletError(words)) => words,
        other => panic!("expected a WalletError, got {other:?}"),
    }
}

/// The total as the result's JSON writes it, and the JSON read back.
fn total_of(result: &ListOutputsResult) -> Value {
    let written = serde_json::to_value(result).unwrap();
    let back: ListOutputsResult = serde_json::from_value(written.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), written);
    written["totalOutputs"].clone()
}

#[tokio::test]
async fn a_balance_past_two_to_the_32_crosses_the_binary_wire_whole_843() {
    for basket in BALANCE_BASKETS {
        for total in [
            0,
            180,
            u64::from(u32::MAX),
            TWO_32,
            1 << 40,
            TWO_53,
            TWO_53 + 2,
            u64::MAX - 2047,
            u64::MAX,
        ] {
            let read = read_wire(basket, frame(total)).await.unwrap();
            assert_eq!(total_of(&read), json!(total), "{basket} {total}");
            assert!(read.outputs.is_empty() && read.beef.is_none());
        }
    }
}

#[tokio::test]
async fn a_count_past_two_to_the_32_stays_refused_on_the_binary_wire_843() {
    // "A count frame keeps its 2^32 - 1 bound."
    for basket in ["savings", "balance", "p color balance", "p  balance aa"] {
        assert_eq!(
            words(read_wire(basket, frame(1 << 40)).await),
            "Invalid listOutputs totalOutputs: expected an integer from 0 to 4294967295, received 1099511627776",
            "{basket}"
        );
        assert_eq!(
            words(read_wire(basket, frame(TWO_53)).await),
            "number too large to retain precision - use readVarIntBn",
            "{basket}"
        );
        let read = read_wire(basket, frame(u64::from(u32::MAX))).await.unwrap();
        assert_eq!(total_of(&read), json!(u32::MAX));
    }
}

fn output() -> WalletOutput {
    serde_json::from_value(json!({
        "outpoint": format!("{}.0", "ab".repeat(32)),
        "satoshis": 1,
        "spendable": true,
    }))
    .unwrap()
}

#[tokio::test]
async fn an_ordinary_count_and_its_page_still_cross_the_binary_wire_843() {
    let mut writer = WireWriter::new();
    writer.write_var_int(7).write_optional_bytes(None);
    writer.write_wallet_output(&output());
    let read = read_wire("savings", writer.into_bytes()).await.unwrap();
    assert_eq!(total_of(&read), json!(7));
    assert_eq!(read.outputs.len(), 1);
    assert_eq!(read.outputs[0].satoshis, 1);
}

#[tokio::test]
async fn a_balance_answer_carrying_an_output_or_a_beef_is_refused_on_the_wire_843() {
    for basket in BALANCE_BASKETS {
        let mut writer = WireWriter::new();
        writer.write_var_int(5).write_optional_bytes(None);
        writer.write_wallet_output(&output());
        assert_eq!(
            words(read_wire(basket, writer.into_bytes()).await),
            "Invalid listOutputs result outputs: expected an empty array for a balance query",
            "{basket}"
        );
        let mut writer = WireWriter::new();
        writer.write_var_int(5).write_optional_bytes(Some(&[1]));
        assert_eq!(
            words(read_wire(basket, writer.into_bytes()).await),
            "Invalid listOutputs result BEEF: expected absent for a balance query",
            "{basket}"
        );
        // More entries than the declared balance: the page count's words,
        // ahead of the result's check, as the reference's order is.
        let mut writer = WireWriter::new();
        writer.write_var_int(0).write_optional_bytes(None);
        writer.write_wallet_output(&output());
        assert_eq!(
            words(read_wire(basket, writer.into_bytes()).await),
            "Wallet Wire listOutputs response returned 1 records but declared a total of 0",
            "{basket}"
        );
    }
}

#[tokio::test]
async fn a_balance_frame_keeps_canonical_varint_framing_843() {
    let absent = [0xffu8; 9];
    // 1 written with a 3-, 5- and 9-byte prefix.
    for total in [
        vec![0xfd, 0x01, 0x00],
        vec![0xfe, 0x01, 0x00, 0x00, 0x00],
        vec![0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ] {
        let mut body = total.clone();
        body.extend_from_slice(&absent);
        // The reference's `non-canonical varInt`, this wire's every varint's
        // variant here.
        assert!(
            matches!(
                read_wire("p color balance aa", body).await,
                Err(Error::NonCanonicalVarInt { value: 1, .. })
            ),
            "{total:02x?}"
        );
    }
    // Truncated varints.
    for total in [
        vec![0xfd, 0x01],
        vec![0xfe, 0x01, 0x00, 0x01],
        vec![0xff, 0x01, 0x00, 0x00, 0x00, 0x01],
    ] {
        assert!(
            read_wire("p color balance aa", total.clone())
                .await
                .is_err(),
            "{total:02x?}"
        );
    }
}

#[test]
fn a_total_past_two_to_the_32_round_trips_through_json_843() {
    for total in [0, 7, u64::from(u32::MAX), TWO_32, TWO_53, u64::MAX] {
        let text = format!(r#"{{"totalOutputs":{total},"outputs":[]}}"#);
        let read: ListOutputsResult = serde_json::from_str(&text).unwrap();
        assert_eq!(serde_json::to_string(&read).unwrap(), text);
    }
    // 2^64: no 64-bit value (the stated cell; the reference's JSON reads it).
    for text in [
        r#"{"totalOutputs":18446744073709551616,"outputs":[]}"#,
        r#"{"totalOutputs":-1,"outputs":[]}"#,
        r#"{"totalOutputs":1.5,"outputs":[]}"#,
        r#"{"totalOutputs":"5","outputs":[]}"#,
    ] {
        assert!(
            serde_json::from_str::<ListOutputsResult>(text).is_err(),
            "{text}"
        );
    }
}

#[cfg(feature = "http")]
mod http_json {
    use super::*;
    use bsv_rs::wallet::substrates::HttpWalletJson;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// One answer from a wiremock host on an ephemeral port.
    async fn read_json(basket: &str, body: &str) -> bsv_rs::Result<ListOutputsResult> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/listOutputs"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(body.to_owned(), "application/json"),
            )
            .mount(&server)
            .await;
        HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri()))
            .unwrap()
            .list_outputs(args(basket), None)
            .await
    }

    fn body(total: &str) -> String {
        format!(r#"{{"totalOutputs":{total},"outputs":[]}}"#)
    }

    #[tokio::test]
    async fn a_balance_past_two_to_the_32_is_read_from_json_843() {
        for basket in BALANCE_BASKETS {
            for total in [0, 5, TWO_32, TWO_53, TWO_53 + 2, u64::MAX - 2047, u64::MAX] {
                let read = read_json(basket, &body(&total.to_string())).await.unwrap();
                assert_eq!(total_of(&read), json!(total), "{basket} {total}");
            }
            // An integral number in another spelling, as the reference's
            // `Number.isInteger` and `>= 0` take it.
            for (spelling, total) in [("4294967296.0", TWO_32), ("-0", 0)] {
                let read = read_json(basket, &body(spelling)).await.unwrap();
                assert_eq!(total_of(&read), json!(total), "{basket} {spelling}");
            }
        }
    }

    #[tokio::test]
    async fn a_balance_that_is_no_nonnegative_integer_is_refused_in_json_843() {
        for basket in BALANCE_BASKETS {
            for total in ["\"5\"", "-1", "1.5", "-0.5", "null", "true"] {
                assert_eq!(
                    words(read_json(basket, &body(total)).await),
                    "Invalid listOutputs result totalOutputs: expected a nonnegative integer balance for a balance query",
                    "{basket} {total}"
                );
            }
            assert_eq!(
                words(read_json(basket, r#"{"outputs":[]}"#).await),
                "Invalid listOutputs result totalOutputs: expected a nonnegative integer balance for a balance query",
            );
        }
    }

    #[tokio::test]
    async fn a_balance_answer_with_outputs_or_a_beef_is_refused_in_json_843() {
        let output = format!(
            r#"{{"outpoint":"{}.0","satoshis":1,"spendable":true}}"#,
            "ab".repeat(32)
        );
        for basket in BALANCE_BASKETS {
            for total in ["5", "18446744073709551616"] {
                assert_eq!(
                    words(read_json(basket, &format!(r#"{{"totalOutputs":{total},"outputs":[{output}]}}"#)).await),
                    "Invalid listOutputs result outputs: expected an empty array for a balance query",
                );
                assert_eq!(
                    words(read_json(basket, &format!(r#"{{"totalOutputs":{total}}}"#)).await),
                    "Invalid listOutputs result outputs: expected an empty array for a balance query",
                );
                // A present BEEF, `null` included (the reference's `!== undefined`).
                for beef in ["[1]", "null"] {
                    assert_eq!(
                        words(
                            read_json(
                                basket,
                                &format!(
                                    r#"{{"totalOutputs":{total},"outputs":[],"BEEF":{beef}}}"#
                                )
                            )
                            .await
                        ),
                        "Invalid listOutputs result BEEF: expected absent for a balance query",
                        "{basket} {total} {beef}"
                    );
                }
            }
        }
    }

    /// The stated cell: the reference's JSON carries a balance of 2^64 or
    /// more as its Number; a `u64` cannot, and the typed read refuses it.
    #[tokio::test]
    async fn a_json_balance_of_two_to_the_64_is_refused_where_the_reference_reads_it_stated_843() {
        for basket in BALANCE_BASKETS {
            for total in ["18446744073709551616", "36893488147419103232", "1e30"] {
                let refusal = words(read_json(basket, &body(total)).await);
                assert!(
                    refusal.contains("invalid type"),
                    "{basket} {total}: {refusal}"
                );
            }
        }
    }

    #[tokio::test]
    async fn an_ordinary_count_in_json_keeps_the_safe_integer_rule_843() {
        // A count past 2^32 - 1 is a safe integer: read, as the reference's
        // validator reads it (#432's R47 residue, closed for this total).
        for total in [0, 1, u64::from(u32::MAX), TWO_32, TWO_53 - 1] {
            let read = read_json("savings", &body(&total.to_string()))
                .await
                .unwrap();
            assert_eq!(total_of(&read), json!(total), "{total}");
        }
        for total in [
            TWO_53.to_string(),
            u64::MAX.to_string(),
            "-1".into(),
            "1.5".into(),
        ] {
            assert_eq!(
                words(read_json("savings", &body(&total)).await),
                "Invalid listOutputs result totalOutputs: expected an integer from 0 to 9007199254740991",
                "{total}"
            );
        }
    }

    /// The cells where this crate answers otherwise than the reference, each
    /// with its reason; every other cell of the recording is answered as the
    /// reference answers it.
    ///
    /// `EXACT_HERE`: a JSON balance past 2^53 is held exactly by the `u64`,
    /// where the reference's Number rounds it to the nearest double (the
    /// stated cell of the CHANGELOG's parity note); the test asks that the
    /// two are one double. `REFUSED_PAST_U64`: a balance of 2^64 or more,
    /// which the reference carries as its Number and a `u64` cannot hold, is
    /// refused at the typed read in serde's words (the same stated cell).
    const EXACT_HERE: [&str; 2] = ["totalOutputs_two_53_plus_one", "totalOutputs_u64_max"];
    const REFUSED_PAST_U64: [&str; 4] = [
        "totalOutputs_two_64",
        "totalOutputs_two_64_exponent",
        "totalOutputs_two_65",
        "totalOutputs_big_exponent",
    ];

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct BalanceCase {
        name: String,
        args: Value,
        body_text: String,
        reference: Value,
    }

    /// Every spelling of every member the balance reader judges, against the
    /// reference's own answers (`vectors/list_outputs_balance_843.json`,
    /// `support/list_outputs_balance_843.mjs`: `HTTPWalletJSON.listOutputs`
    /// at `ts-stack@11faa7d16` under Node v22.18.0, two runs byte-identical),
    /// for both balance baskets with and without a `limit`.
    #[tokio::test]
    async fn every_spelling_of_a_balance_answer_is_judged_as_the_reference_judges_it_843() {
        #[derive(serde::Deserialize)]
        struct Vector {
            source: String,
            node: String,
            cases: Vec<BalanceCase>,
        }
        let vector: Vector =
            serde_json::from_str(include_str!("vectors/list_outputs_balance_843.json")).unwrap();
        assert_eq!(vector.source, "ts-stack@11faa7d16");
        assert_eq!(vector.node, "v22.18.0");
        assert_eq!(vector.cases.len(), 248);
        let server = MockServer::start().await;
        let (mut agreeing, mut stated) = (0, 0);
        for case in &vector.cases {
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/listOutputs"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(case.body_text.clone(), "application/json"),
                )
                .mount(&server)
                .await;
            let mut asked = args(case.args["basket"].as_str().unwrap());
            asked.limit = case.args["limit"]
                .as_u64()
                .map(|n| u32::try_from(n).unwrap());
            let read = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri()))
                .unwrap()
                .list_outputs(asked, None)
                .await;
            let at = format!("{} {} {}", case.name, case.args, case.body_text);
            let name = case.name.as_str();
            if let Some(words) = case.reference["error"].as_str() {
                assert_eq!(super::words(read), words, "{at}");
                agreeing += 1;
            } else if REFUSED_PAST_U64.contains(&name) {
                let refusal = super::words(read);
                assert!(refusal.contains("invalid type"), "{at}: {refusal}");
                stated += 1;
            } else {
                let there: u128 = case.reference["accepted"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                let read = read.unwrap_or_else(|e| panic!("{at}: refused {e:?}"));
                assert!(read.outputs.is_empty() && read.beef.is_none(), "{at}");
                let here = read.total_outputs;
                if EXACT_HERE.contains(&name) {
                    assert_ne!(u128::from(here), there, "{at}");
                    #[allow(clippy::cast_precision_loss)] // the one double both name
                    let one_double = here as f64 == there as f64;
                    assert!(one_double, "{at}: {here} and {there}");
                    stated += 1;
                } else {
                    assert_eq!(u128::from(here), there, "{at}");
                    agreeing += 1;
                }
            }
        }
        // Four cells a basket and a request shape: 2 x 2 x 6.
        assert_eq!((agreeing, stated), (224, 24));
    }
}

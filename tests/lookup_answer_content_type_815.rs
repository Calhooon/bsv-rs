//! #815: a lookup answer's content type and a leading BOM read as the
//! reference reads them (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts`):
//!
//! ```text
//! 512: function isOctetStream(contentType: string | null): boolean {
//! 513:   if (typeof contentType !== 'string') return false
//! 514:   const baseType = contentType.split(';', 1)[0].trim().toLowerCase()
//! 515:   return baseType === 'application/octet-stream'
//! 845:      if (isOctetStream(response.headers.get('content-type'))) {
//! 846:        return await this.parseOctetStreamLookup(payload, signal, options)
//! 850:        text = new TextDecoder('utf-8', { fatal: true }).decode(payload)
//! 852:        throw new Error('Overlay response is not valid UTF-8.')
//! 854:      answer = JSON.parse(text)
//! ```
//!
//! Until #815 the binary path was taken for a type containing
//! `octet-stream` in its case (so `Application/Octet-Stream` went to the
//! JSON path and `text/x-octet-stream-ish` to the binary one), and a UTF-8
//! BOM before the JSON failed the parse; `TextDecoder` drops one leading
//! BOM. Each answer is served by a `wiremock` host of its own, the binary
//! body built by this crate's writers.
#![cfg(all(feature = "overlay", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    HttpsOverlayLookupFacilitator, LookupAnswer, LookupQuestion, OverlayLookupFacilitator,
};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A BEEF of one transaction proven by a block of its own, and its txid.
fn proven_beef() -> (Vec<u8>, String) {
    let mut input = TransactionInput::new("11".repeat(32).parse().unwrap(), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        1,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let mut beef = Beef::new();
    let index = beef.merge_bump(
        MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap(),
    );
    beef.merge_raw_tx(tx.to_binary(), Some(index)).unwrap();
    (beef.to_binary().unwrap(), tx.id())
}

/// A binary aggregated answer of one outpoint (`txid`, index 0, no
/// context), then the BEEF (`LookupResolver.ts:872-936`).
fn binary_answer(txid: &str, beef: &[u8]) -> Vec<u8> {
    let mut body = vec![1];
    body.extend(bsv_rs::primitives::from_hex(txid).unwrap());
    body.extend([0, 0]);
    body.extend_from_slice(beef);
    body
}

/// The facilitator's answer to `body` served with `content_type`.
async fn served(body: Vec<u8>, content_type: &str) -> bsv_rs::Result<LookupAnswer> {
    served_bytes(body, content_type.as_bytes()).await
}

/// The same, the header value as bytes (a byte above `0x7e` included).
async fn served_bytes(body: Vec<u8>, content_type: &[u8]) -> bsv_rs::Result<LookupAnswer> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body)
                .insert_header("Content-Type", content_type),
        )
        .expect(1)
        .mount(&server)
        .await;
    HttpsOverlayLookupFacilitator::new(true)
        .lookup(
            &server.uri(),
            &LookupQuestion::new("ls_test", serde_json::json!({})),
            None,
        )
        .await
}

fn outputs(answer: bsv_rs::Result<LookupAnswer>) -> Vec<bsv_rs::overlay::OutputListItem> {
    match answer {
        Ok(LookupAnswer::OutputList { outputs }) => outputs,
        other => panic!("not an output list: {other:?}"),
    }
}

/// `Application/Octet-Stream` and a type with parameters are the binary
/// path; on the base the JSON path refused the bytes (`Failed to parse
/// JSON`).
#[tokio::test]
async fn an_upper_case_octet_stream_type_is_read_as_binary_815() {
    let (beef, txid) = proven_beef();
    for content_type in [
        "Application/Octet-Stream",
        "APPLICATION/OCTET-STREAM; charset=binary",
        " application/octet-stream ;x=1",
        "application/octet-stream",
    ] {
        let read = outputs(served(binary_answer(&txid, &beef), content_type).await);
        assert_eq!(read.len(), 1, "{content_type}");
        assert_eq!(
            read[0].txid.as_deref(),
            Some(txid.as_str()),
            "{content_type}"
        );
    }
}

/// A type that merely contains `octet-stream` is the JSON path; on the base
/// the binary reader took the JSON body and refused it.
#[tokio::test]
async fn a_type_merely_containing_octet_stream_is_read_as_json_815() {
    let body = br#"{"type":"output-list","outputs":[]}"#.to_vec();
    for content_type in [
        "text/x-octet-stream-ish",
        "application/octet-streamx",
        "octet-stream",
    ] {
        assert_eq!(
            outputs(served(body.clone(), content_type).await).len(),
            0,
            "{content_type}"
        );
    }
}

/// One leading BOM is dropped before the parse, as `TextDecoder` drops it;
/// bytes that are not UTF-8 are refused in the reference's words.
#[tokio::test]
async fn a_json_answer_behind_a_bom_is_read_815() {
    let (beef, _) = proven_beef();
    let json = serde_json::json!({
        "type": "output-list",
        "outputs": [{ "beef": beef, "outputIndex": 0 }],
    });
    let mut body = b"\xef\xbb\xbf".to_vec();
    body.extend(serde_json::to_vec(&json).unwrap());
    let read = outputs(served(body, "application/json").await);
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].beef, beef);
    let refused = served(b"{\"type\":\"\xff\"}".to_vec(), "application/json").await;
    assert_eq!(
        refused.map(|_| ()),
        Err(bsv_rs::Error::OverlayError(
            "Overlay response is not valid UTF-8.".into()
        ))
    );
}

/// #815's second fold: the base type is trimmed by ECMAScript's `trim` set
/// (`LookupResolver.ts:514`), which keeps U+0085, so a host whose type ends
/// in the byte `0x85` is read on the JSON path, as the reference reads it
/// (`tests/vectors/lookup_header_trim_815.json`'s `0085` cells, `fetch`'s
/// `Headers` holding the byte); the fold's tip took the binary path, Rust's
/// `str::trim` taking U+0085. The byte `0xa0`, which both trims take, is the
/// binary path on both sides.
#[tokio::test]
async fn a_type_ending_in_byte_0x85_is_read_as_json_as_the_reference_reads_it_815() {
    let json = br#"{"type":"output-list","outputs":[]}"#.to_vec();
    for content_type in [
        &b"application/octet-stream\x85"[..],
        b"\x85application/octet-stream",
        b"application/octet-stream\x85; x=1",
    ] {
        assert_eq!(
            outputs(served_bytes(json.clone(), content_type).await).len(),
            0,
            "{content_type:?}"
        );
    }
    let (beef, txid) = proven_beef();
    for content_type in [
        &b"application/octet-stream\xa0"[..],
        b"application/octet-stream\xa0; x=1",
    ] {
        let read = outputs(served_bytes(binary_answer(&txid, &beef), content_type).await);
        assert_eq!(read.len(), 1, "{content_type:?}");
    }
}

//! #815: a binary aggregated SLAP answer through the real HTTPS facilitator
//! and `find_competent_hosts`, the path the reads of #786 found read only
//! (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/LookupResolver.ts`):
//!
//! ```text
//! 905:  // the aggregated BEEF parsed once, each outpoint given the Atomic
//!       // BEEF of its own txid and that txid as its hint (`:905-936`)
//! 2201:      if (output.txid !== undefined && output.txid.toLowerCase() !== txid) continue
//! 2203:      if (selectedOutput == null || selectedOutput.satoshis !== 1) continue
//! ```
//!
//! A `wiremock` tracker answers `ls_slap` with an
//! `application/octet-stream` body, written by this crate's writers: two
//! outpoints, a SLAP advertisement of 1 satoshi and one of 2, both proven
//! in one BEEF. The binary reader hands each output its outpoint's txid as
//! the hint, which agrees with its subject, and the Atomic BEEF of that
//! txid; the discovery admits the 1-satoshi host and skips the other.
#![cfg(all(feature = "overlay", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, HttpsOverlayLookupFacilitator, LookupResolver,
    LookupResolverConfig, Protocol,
};
use bsv_rs::primitives::{from_hex, PrivateKey};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use std::sync::Arc;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SERVICE: &str = "ls_slap_binary";

/// A SLAP advertisement of `host` at `satoshis`, merged into `beef` with a
/// block of its own at `height`; its txid.
fn advertise(beef: &mut Beef, host: &str, satoshis: u64, height: u32) -> String {
    let script =
        create_signed_overlay_admin_token(&PrivateKey::random(), Protocol::Slap, host, SERVICE);
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new(
        "33".repeat(32).parse().unwrap(),
        height,
    ))
    .unwrap();
    tx.add_output(TransactionOutput::new(satoshis, script))
        .unwrap();
    let index = beef.merge_bump(
        MerklePath::new(height, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap(),
    );
    beef.merge_raw_tx(tx.to_binary(), Some(index)).unwrap();
    tx.id()
}

#[tokio::test]
async fn a_binary_slap_answer_admits_its_one_satoshi_host_815() {
    let admitted = "https://admitted.slap-binary-815.invalid";
    let refused = "https://refused.slap-binary-815.invalid";
    let mut beef = Beef::new();
    let one = advertise(&mut beef, admitted, 1, 900);
    let two = advertise(&mut beef, refused, 2, 901);
    // The aggregated answer: the outpoint count, each outpoint (txid, index,
    // context length), then the BEEF (`LookupResolver.ts:872-904`)
    let mut body = vec![2];
    for txid in [&one, &two] {
        body.extend(from_hex(txid).unwrap());
        body.extend([0, 0]);
    }
    body.extend(beef.to_binary().unwrap());

    let tracker = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .and(body_string_contains("ls_slap"))
        .and(body_string_contains(SERVICE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body)
                .insert_header("Content-Type", "application/octet-stream"),
        )
        .expect(1)
        .mount(&tracker)
        .await;

    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(HttpsOverlayLookupFacilitator::new(true))),
        slap_trackers: Some(vec![tracker.uri()]),
        ..Default::default()
    });
    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(hosts, [admitted]);
}

//! #537, site 6: the storage downloader decodes a UHRP advertisement
//! lock-before alone, as its counterpart does (`ts-stack@edf6e03`
//! `UHRPAdvertisementValidation.ts:40`, `decodeCanonicalPushDrop` over
//! `PushDrop.decode` at its default position): a lock-after advertisement
//! names no host, as the reference's catch at `StorageDownloader.ts:121`
//! skips it. The advertisement's first field is the host's identity key, so
//! its realistic lock-after form is the corner, refused here before and
//! after #537.
#![cfg(feature = "storage")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_decode_618.rs"]
mod decode_618;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::script::LockingScript;
use bsv_rs::storage::{StorageDownloader, StorageDownloaderConfig};
use serde_json::Value;

/// The hosts the downloader resolves for the case's URL from `script`.
async fn hosts(case: &Value, script: LockingScript) -> Vec<String> {
    let downloader = StorageDownloader::new(StorageDownloaderConfig {
        resolver: Some(lock_position::answering("ls_uhrp", script)),
        ..Default::default()
    });
    downloader
        .resolve(case["uhrp_url"].as_str().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_lock_after_advertisement_names_no_host_as_in_the_reference_537() {
    let cases = lock_position::cases("storage_downloader");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        let found = hosts(case, lock_position::script(case)).await;
        assert!(found.is_empty(), "{}: {found:?}", case["name"]);
    }
    // The same fields locked before named their host until #544; since then
    // the reference's reader skips them too: the first field is no host key
    // (`UHRPAdvertisementValidation.ts:46-48`).
    let control = lock_position::relocked_before(&cases[0]);
    assert!(hosts(&cases[0], control).await.is_empty());
}

/// The #537 case a #618 case was built from.
fn from_537<'a>(cases: &'a [Value], case: &Value) -> &'a Value {
    cases
        .iter()
        .find(|old| old["name"] == case["from_537"])
        .unwrap()
}

/// #618: a key alone and a token without CHECKSIG second, which the public
/// `PushDrop::decode` reads as the reference does, name no host, as
/// `decodeCanonicalPushDrop` refuses them (`UHRPAdvertisementValidation.ts:40`,
/// `PushDropValidation.ts:54-79`) and the downloader's catch skips them
/// (`StorageDownloader.ts:121`).
#[tokio::test]
async fn a_key_only_and_a_no_checksig_advertisement_name_no_host_as_in_the_reference_618() {
    let old = lock_position::cases("storage_downloader");
    let cases = decode_618::cases("storage_downloader");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        let from = from_537(&old, case);
        let script = decode_618::script(case, from);
        let found = hosts(from, script).await;
        assert!(found.is_empty(), "{}: {found:?}", case["name"]);
    }
}

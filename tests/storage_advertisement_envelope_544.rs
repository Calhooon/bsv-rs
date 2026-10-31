//! #544, site 6: the storage downloader names a host only for an
//! advertisement the reference's reader authenticates and binds to the file
//! asked for (`ts-stack@edf6e03` `StorageDownloader.ts:62-126`: each output
//! through `decodeAndVerifyUHRPAdvertisement`, `UHRPAdvertisementValidation.ts:37-115`,
//! then the hash binding and the expiry at `:117`, one host per location, a
//! refused output skipped at `:121`). Against the storage cases of
//! `tests/vectors/token_envelope_544.json` (`tests/support/token_envelope_544.mjs`,
//! Node v22.18.0): the reference's advertisement names its host; one for
//! another file, an expired one, an `http:` location, an unsigned one, a
//! loosely dropped one, a wrongly locked and a wrongly signed one name none,
//! as `StorageDownloader.resolve` gives them. The reader's words are pinned
//! in `src/storage/advertisement.rs`. Hermetic: an in-process resolver on
//! an `.invalid` host.
#![cfg(feature = "storage")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::script::LockingScript;
use bsv_rs::storage::{StorageDownloader, StorageDownloaderConfig};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap()
}

#[tokio::test]
async fn a_host_is_named_only_for_an_authenticated_advertisement_of_the_file_544() {
    let v = vector();
    let url = v["storage"]["uhrp_url"].as_str().unwrap();
    let cases = v["storage"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let downloader = StorageDownloader::new(StorageDownloaderConfig {
            resolver: Some(lock_position::answering("ls_uhrp", script)),
            ..Default::default()
        });
        let hosts = downloader.resolve(url).await.unwrap();
        let expected: Vec<String> = serde_json::from_value(case["hosts"].clone()).unwrap();
        assert_eq!(hosts, expected, "{}: {}", case["name"], case["words"]);
    }
}

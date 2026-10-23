//! Public-surface golden files. Only BSV_FIXTURES_RECORD=1 writes snapshots.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/fixtures/mod.rs"]
mod fixtures;

#[tokio::test]
async fn fixtures_replay() {
    fixtures::run().await;
}

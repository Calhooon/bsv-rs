//! `Headers::mining_tip`: `None` by default, and a reference to a `Headers` forwards its own.
#![cfg(feature = "transaction")]
use bsv_rs::transaction::beef_stream::{ChainTip, Hash32, Headers};
struct OldHeaders;
impl Headers for OldHeaders {
    fn carries(&self, _: u64, _: &Hash32) -> bool {
        false
    }
}
struct Context(ChainTip);
impl Headers for Context {
    fn carries(&self, _: u64, _: &Hash32) -> bool {
        false
    }
    fn mining_tip(&self) -> Option<ChainTip> {
        Some(self.0)
    }
}
#[test]
fn mining_tip_defaults_and_reference_forwarding() {
    assert_eq!(OldHeaders.mining_tip(), None);
    let headers = Context(ChainTip::new(800_000, 1_700_000_000));
    assert_eq!(
        (headers.0.csv_height, headers.0.next_block_time),
        (419_328, None)
    );
    assert_eq!(Headers::mining_tip(&&headers), Some(headers.0));
}

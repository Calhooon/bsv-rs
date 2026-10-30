//! Complete the eleven result-validation paths exercised by fuzz_wire_protocol.
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver};

pub async fn exercise<T: WalletWire>(client: &WalletWireTransceiver<T>) {
    // #473 already exercises createAction, signAction, listOutputs and proof.
    for call in [12, 14, 15, 18, 19] {
        crate::support::call_shared!(client, call, None);
    }
    let _ = client
        .reveal_counterparty_key_linkage(crate::support::reveal_counterparty(), None)
        .await;
    let _ = client
        .reveal_specific_key_linkage(crate::support::reveal_specific(), None)
        .await;
}

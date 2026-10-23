#![no_main]
//! Each wallet call's wire decoders (BRC-100's binary substrate), the call
//! chosen by the leading byte. An even first byte hands the rest to
//! `WalletWireProcessor::process_message` over a `ProtoWallet` as a request
//! frame (its own leading byte the call code, then the originator and the
//! call's arguments: the request decoders); an odd one answers the wire
//! transceiver's call `data[1]` with the rest (the result decoders). The
//! assertion is that each returns; no verdict is judged.
use async_trait::async_trait;
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::wire::{WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Error;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

mod support;

/// A wire whose wallet answers every call with the fuzzer's bytes.
struct Answer(Vec<u8>);

#[async_trait]
impl WalletWire for Answer {
    async fn transmit_to_wallet(&self, _message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

fn processor() -> &'static WalletWireProcessor<ProtoWallet> {
    static PROCESSOR: OnceLock<WalletWireProcessor<ProtoWallet>> = OnceLock::new();
    PROCESSOR.get_or_init(|| {
        let key = PrivateKey::from_bytes(&[1; 32]).expect("a fixed key");
        WalletWireProcessor::new(ProtoWallet::new(Some(key)))
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        let response = futures::executor::block_on(processor().process_message(rest));
        // The processor encodes every failure into its response frame.
        assert!(
            response.is_ok(),
            "the processor returned an Err: {response:?}"
        );
    } else {
        let Some((&call, answer)) = rest.split_first() else {
            return;
        };
        let transceiver = WalletWireTransceiver::new(Answer(answer.to_vec()));
        futures::executor::block_on(async {
            support::call_shared!(&transceiver, call, "fuzz.example");
        });
    }
});

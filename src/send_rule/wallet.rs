//! The `wallet` module's doors (`send_rule`'s header has the rule).

use super::{send, Values};
use crate::script::templates::{LockPosition, PushDrop};
#[cfg(feature = "http")]
use crate::wallet::substrates::HttpWalletJson;
use crate::wallet::wire::{WalletWire, WalletWireProcessor, WalletWireTransceiver};
use crate::wallet::{Counterparty, Protocol, WalletClient, WalletInterface};

// src/wallet/interface.rs
fn wallet_interface<V: Values, W: WalletInterface + ?Sized>(v: &V) {
    let wallet = v.any::<&W>();
    send(wallet.get_public_key(v.any(), v.any()));
    send(wallet.encrypt(v.any(), v.any()));
    send(wallet.decrypt(v.any(), v.any()));
    send(wallet.create_hmac(v.any(), v.any()));
    send(wallet.verify_hmac(v.any(), v.any()));
    send(wallet.create_signature(v.any(), v.any()));
    send(wallet.verify_signature(v.any(), v.any()));
    send(wallet.reveal_counterparty_key_linkage(v.any(), v.any()));
    send(wallet.reveal_specific_key_linkage(v.any(), v.any()));
    send(wallet.create_action(v.any(), v.any()));
    send(wallet.sign_action(v.any(), v.any()));
    send(wallet.abort_action(v.any(), v.any()));
    send(wallet.list_actions(v.any(), v.any()));
    send(wallet.internalize_action(v.any(), v.any()));
    send(wallet.list_outputs(v.any(), v.any()));
    send(wallet.relinquish_output(v.any(), v.any()));
    send(wallet.acquire_certificate(v.any(), v.any()));
    send(wallet.list_certificates(v.any(), v.any()));
    send(wallet.prove_certificate(v.any(), v.any()));
    send(wallet.relinquish_certificate(v.any(), v.any()));
    send(wallet.discover_by_identity_key(v.any(), v.any()));
    send(wallet.discover_by_attributes(v.any(), v.any()));
    send(wallet.is_authenticated(v.any()));
    send(wallet.wait_for_authentication(v.any()));
    send(wallet.get_height(v.any()));
    send(wallet.get_header_for_height(v.any(), v.any()));
    send(wallet.get_network(v.any()));
    send(wallet.get_version(v.any()));
}

// src/wallet/wire/mod.rs
fn wallet_wire<V: Values, T: WalletWire + ?Sized>(v: &V) {
    let wire = v.any::<&T>();
    send(wire.transmit_to_wallet(v.any()));
}

// src/wallet/client.rs
fn wallet_client<V: Values>(v: &V) {
    let client = v.any::<&WalletClient>();
    send(client.get_public_key(v.any()));
    send(client.encrypt(v.any()));
    send(client.decrypt(v.any()));
    send(client.create_hmac(v.any()));
    send(client.verify_hmac(v.any()));
    send(client.create_signature(v.any()));
    send(client.verify_signature(v.any()));
    send(client.is_authenticated());
    send(client.get_height());
    send(client.get_network());
    send(client.get_version());
    send(client.reveal_counterparty_key_linkage(v.any()));
    send(client.reveal_specific_key_linkage(v.any()));
    send(client.create_action(v.any()));
    send(client.sign_action(v.any()));
    send(client.abort_action(v.any()));
    send(client.list_actions(v.any()));
    send(client.internalize_action(v.any()));
    send(client.list_outputs(v.any()));
    send(client.relinquish_output(v.any()));
    send(client.acquire_certificate(v.any()));
    send(client.list_certificates(v.any()));
    send(client.prove_certificate(v.any()));
    send(client.relinquish_certificate(v.any()));
    send(client.discover_by_identity_key(v.any()));
    send(client.discover_by_attributes(v.any()));
    send(client.get_header(v.any()));
    send(client.wait_for_authentication());
}

// src/wallet/substrates/http_json.rs
#[cfg(feature = "http")]
fn http_wallet_json<V: Values>(v: &V) {
    let json = v.any::<&HttpWalletJson>();
    send(json.get_public_key(v.any(), v.any()));
    send(json.encrypt(v.any(), v.any()));
    send(json.decrypt(v.any(), v.any()));
    send(json.create_hmac(v.any(), v.any()));
    send(json.verify_hmac(v.any(), v.any()));
    send(json.create_signature(v.any(), v.any()));
    send(json.verify_signature(v.any(), v.any()));
    send(json.is_authenticated(v.any()));
    send(json.get_height(v.any()));
    send(json.get_network(v.any()));
    send(json.get_version(v.any()));
    send(json.create_action(v.any(), v.any()));
    send(json.sign_action(v.any(), v.any()));
    send(json.abort_action(v.any(), v.any()));
    send(json.list_actions(v.any(), v.any()));
    send(json.internalize_action(v.any(), v.any()));
    send(json.list_outputs(v.any(), v.any()));
    send(json.relinquish_output(v.any(), v.any()));
    send(json.acquire_certificate(v.any(), v.any()));
    send(json.list_certificates(v.any(), v.any()));
    send(json.prove_certificate(v.any(), v.any()));
    send(json.relinquish_certificate(v.any(), v.any()));
    send(json.discover_by_identity_key(v.any(), v.any()));
    send(json.discover_by_attributes(v.any(), v.any()));
    send(json.get_header(v.any(), v.any()));
    send(json.wait_for_authentication(v.any()));
    send(json.reveal_counterparty_key_linkage(v.any(), v.any()));
    send(json.reveal_specific_key_linkage(v.any(), v.any()));
}

// src/wallet/wire/transceiver.rs
fn transceiver<V: Values, T: WalletWire>(v: &V) {
    let transceiver = v.any::<&WalletWireTransceiver<T>>();
    send(transceiver.get_public_key(v.any(), v.any()));
    send(transceiver.encrypt(v.any(), v.any()));
    send(transceiver.decrypt(v.any(), v.any()));
    send(transceiver.create_hmac(v.any(), v.any()));
    send(transceiver.verify_hmac(v.any(), v.any()));
    send(transceiver.create_signature(v.any(), v.any()));
    send(transceiver.verify_signature(v.any(), v.any()));
    send(transceiver.is_authenticated(v.any()));
    send(transceiver.get_height(v.any()));
    send(transceiver.get_network(v.any()));
    send(transceiver.get_version(v.any()));
    send(transceiver.create_action(v.any(), v.any()));
    send(transceiver.sign_action(v.any(), v.any()));
    send(transceiver.abort_action(v.any(), v.any()));
    send(transceiver.list_actions(v.any(), v.any()));
    send(transceiver.internalize_action(v.any(), v.any()));
    send(transceiver.list_outputs(v.any(), v.any()));
    send(transceiver.relinquish_output(v.any(), v.any()));
    send(transceiver.acquire_certificate(v.any(), v.any()));
    send(transceiver.list_certificates(v.any(), v.any()));
    send(transceiver.prove_certificate(v.any(), v.any()));
    send(transceiver.relinquish_certificate(v.any(), v.any()));
    send(transceiver.get_header(v.any(), v.any()));
    send(transceiver.wait_for_authentication(v.any()));
}

// src/wallet/wire/discovery.rs
fn transceiver_discovery<V: Values, T: WalletWire>(v: &V) {
    let discovering = v.any::<&WalletWireTransceiver<T>>();
    send(discovering.discover_by_identity_key(v.any(), v.any()));
    send(discovering.discover_by_attributes(v.any(), v.any()));
}

// src/wallet/wire/linkage.rs
fn transceiver_linkage<V: Values, T: WalletWire>(v: &V) {
    let revealing = v.any::<&WalletWireTransceiver<T>>();
    send(revealing.reveal_counterparty_key_linkage(v.any(), v.any()));
    send(revealing.reveal_specific_key_linkage(v.any(), v.any()));
}

// src/wallet/wire/processor.rs
fn processor<V: Values, W: WalletInterface>(v: &V) {
    let processor = v.any::<&WalletWireProcessor<W>>();
    send(processor.process_message(v.any()));
}

// src/script/templates/pushdrop_wallet.rs
fn pushdrop_lock<V: Values, W: WalletInterface + ?Sized>(v: &V) {
    let wallet = v.any::<&W>();
    send(PushDrop::lock_with_wallet(
        wallet,
        v.any::<Option<&str>>(),
        v.any::<Vec<Vec<u8>>>(),
        v.any::<Protocol>(),
        v.any::<&str>(),
        v.any::<Counterparty>(),
        v.any::<bool>(),
        v.any::<bool>(),
        v.any::<LockPosition>(),
    ));
}

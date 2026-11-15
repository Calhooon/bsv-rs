//! An empty value is no `GlobalKVStore` entry: PushDrop writes an empty field
//! and a field of one zero byte as the same `OP_0`, which every reader reads
//! back as the one zero byte, so a controller's signature over an empty value
//! never verifies. The interpreter reads no entry from such a token, as the
//! reference's `decodeAndVerifyKVStoreToken` reads none (`ts-stack@edf6e03`
//! `kvStoreTokenValidation.ts:85-119`: the signature is invalid); the token
//! is built from the one `set` writes for one zero byte, its signature made
//! again over an empty value.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, KVStoreInterpreter};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use identity_reveal_wallet::Counting;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A lookup host that answers every question with no output.
struct NoOutputs;

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for NoOutputs {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList { outputs: vec![] })
    }
}

fn store(wallet: &Counting) -> GlobalKVStore<Counting> {
    let config = KVStoreConfig::default();
    let host = format!(
        "https://kvstore-empty-value-{}.invalid",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        host_overrides: Some([(config.service_name.clone(), vec![host])].into()),
        slap_trackers: Some(vec![]),
        facilitator: Some(Arc::new(NoOutputs)),
        ..Default::default()
    });
    GlobalKVStore::with_resolver(wallet.clone(), config, NetworkPreset::Local, resolver)
}

/// The locking script `set` hands the wallet for `value`.
async fn written(value: &str) -> LockingScript {
    let wallet = Counting::of_scalar(9);
    // The wallet omits the signed result, so the action ends in an error after
    // its output is written.
    let _ = store(&wallet).set("alpha", value, None).await;
    let created = wallet.created.lock().unwrap();
    let outputs = created
        .as_ref()
        .expect("an action")
        .outputs
        .as_ref()
        .unwrap();
    LockingScript::from_binary(&outputs[0].locking_script).unwrap()
}

/// One zero byte: its token carries the value as `OP_0` too, which its token
/// carries as `OP_0` and the interpreter reads back as written.
#[tokio::test]
async fn a_value_of_one_zero_byte_is_written_and_read_back() {
    let script = written("\0").await;
    let entry = KVStoreInterpreter::interpret_script(&script, None).expect("an entry");
    assert_eq!(entry.value, "\0");
    assert_eq!(entry.key, "alpha");
}

/// A token whose value field is `OP_0` under a signature over an empty value
/// (what `set` writes for an empty value) is no entry:
/// its bytes differ from the zero-byte token's only in the signature.
#[tokio::test]
async fn a_token_signed_over_an_empty_value_is_no_entry() {
    let zero = written("\0").await;
    let decoded = PushDrop::decode(&zero).unwrap();
    let mut fields = decoded.fields.clone();
    assert_eq!(
        fields[2],
        vec![0u8],
        "the value field reads as one zero byte"
    );
    assert_eq!(
        PushDrop::new(decoded.locking_public_key.clone(), fields.clone()).lock(),
        zero,
        "the rebuilt token is the writer's"
    );
    let mut scalar = [0u8; 32];
    scalar[31] = 9;
    let signer = ProtoWallet::new(Some(PrivateKey::from_bytes(&scalar).unwrap()));
    let data_fields = fields.clone();
    let signed = |value: &[u8]| {
        let data = [
            &data_fields[0][..],
            &data_fields[1][..],
            value,
            &data_fields[3][..],
        ]
        .concat();
        signer
            .create_signature(CreateSignatureArgs {
                data: Some(data),
                protocol_id: Protocol::new(SecurityLevel::App, "kvstore"),
                key_id: "alpha".into(),
                counterparty: Some(Counterparty::Anyone),
                ..Default::default()
            })
            .unwrap()
            .signature
    };
    // The zero-byte signature reproduces the writer's token: the signer is the writer's.
    let last = fields.len() - 1;
    fields[last] = signed(&[0]);
    let control = PushDrop::new(decoded.locking_public_key.clone(), fields.clone()).lock();
    assert_eq!(
        KVStoreInterpreter::interpret_script(&control, None).map(|e| e.value),
        Some("\0".to_string())
    );
    fields[last] = signed(&[]);
    let empty = PushDrop::new(decoded.locking_public_key, fields).lock();
    assert!(KVStoreInterpreter::interpret_script(&empty, None).is_none());
}

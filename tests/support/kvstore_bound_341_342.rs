#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::identity_reveal_wallet::Counting;
use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, KVStoreSetOptions, LocalKVStore};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

// The resolver shares a process-wide reputation tracker, even with a fake facilitator.
static NEXT_LOOKUP: AtomicUsize = AtomicUsize::new(0);

struct Lookup(Arc<Mutex<Option<Vec<u8>>>>);
#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Lookup {
    async fn lookup(
        &self,
        _: &str,
        _: &LookupQuestion,
        _: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self
                .0
                .lock()
                .unwrap()
                .iter()
                .map(|bytes| OutputListItem {
                    beef: bytes.clone(),
                    output_index: 0,
                    context: None,
                })
                .collect(),
        })
    }
}

pub enum Store {
    Global(GlobalKVStore<Counting>),
    Local(LocalKVStore<Counting>),
}
impl Store {
    pub async fn set(&self, value: &str) -> bsv_rs::Result<String> {
        match self {
            Self::Global(store) => {
                store
                    .set(
                        "alpha",
                        value,
                        Some(KVStoreSetOptions::new().with_tags(vec!["t".into()])),
                    )
                    .await
            }
            Self::Local(store) => store.set("alpha", value, None).await,
        }
    }
    pub async fn remove(&self) -> bsv_rs::Result<()> {
        match self {
            Self::Global(store) => store.remove("alpha", None).await.map(|_| ()),
            Self::Local(store) => store.remove("alpha", None).await.map(|_| ()),
        }
    }
}

pub fn source(lock: &[u8], value: u64) -> Transaction {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(
        value,
        LockingScript::from_binary(lock).unwrap(),
    ))
    .unwrap();
    tx
}

pub async fn setup(global: bool, config: KVStoreConfig) -> (Store, Counting) {
    setup_with_options(global, config, None).await
}

pub async fn setup_with_options(
    global: bool,
    config: KVStoreConfig,
    options: Option<(bool, bool)>,
) -> (Store, Counting) {
    let wallet = Counting::of_scalar(9);
    *wallet.spending.lock().unwrap() = Some(source(&[0x51], 2));
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: vec![],
        total_outputs: 0,
        beef: None,
    });
    let token = Arc::new(Mutex::new(None));
    let store = if global {
        let resolver = LookupResolver::new(LookupResolverConfig {
            network_preset: NetworkPreset::Local,
            host_overrides: Some(
                [(
                    config.service_name.clone(),
                    vec![format!(
                        "https://kvstore-{}.invalid",
                        NEXT_LOOKUP.fetch_add(1, Ordering::Relaxed)
                    )],
                )]
                .into(),
            ),
            slap_trackers: Some(vec![]),
            facilitator: Some(Arc::new(Lookup(token.clone()))),
            ..Default::default()
        });
        let store =
            GlobalKVStore::with_resolver(wallet.clone(), config, NetworkPreset::Local, resolver);
        Store::Global(match options {
            Some((accept_delayed_broadcast, no_send)) => store
                .with_accept_delayed_broadcast(accept_delayed_broadcast)
                .with_no_send(no_send),
            None => store,
        })
    } else {
        let store = LocalKVStore::new(wallet.clone(), config).unwrap();
        Store::Local(match options {
            Some((accept_delayed_broadcast, _)) => {
                store.with_accept_delayed_broadcast(accept_delayed_broadcast)
            }
            None => store,
        })
    };
    store.set("one").await.unwrap_err();
    let args = wallet.created.lock().unwrap().clone().unwrap();
    let output = &args.outputs.unwrap()[0];
    let tx = source(&output.locking_script, output.satoshis);
    *wallet.spending.lock().unwrap() = Some(tx.clone());
    *token.lock().unwrap() = Some(tx.to_beef(true).unwrap());
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: vec![WalletOutput {
            outpoint: Outpoint::from_string(&format!("{}.0", tx.id())).unwrap(),
            satoshis: output.satoshis,
            locking_script: Some(output.locking_script.clone()),
            spendable: true,
            custom_instructions: None,
            tags: Some(vec!["alpha".into()]),
            labels: None,
        }],
        total_outputs: 1,
        beef: Some(tx.to_beef(true).unwrap()),
    });
    wallet.signs.lock().unwrap().clear();
    wallet.aborts.lock().unwrap().clear();
    (store, wallet)
}

pub fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!("../vectors/kvstore_bound_action_341_342.json")).unwrap()
}

// #470 adds local action context around the same bound-action refusal.
pub fn inner_bound_error(error: bsv_rs::Error) -> bsv_rs::Error {
    match error {
        bsv_rs::Error::KvStoreLocalError(message) => bsv_rs::Error::KvStoreError(
            message
                .strip_prefix(
                    "There are 1 outputs with tag alpha that cannot be unlocked. Original error: ",
                )
                .expect("the local action wrapper")
                .into(),
        ),
        error => error,
    }
}

pub fn assert_options(wallet: &Counting, global: bool, operation: &str, mode: &str) {
    let fixture = vector();
    let kind = if global { "global" } else { "local" };
    let case = &fixture[mode][kind][operation];
    let args = wallet.created.lock().unwrap().clone().unwrap();
    assert_eq!(
        serde_json::to_value(args.options).unwrap(),
        case["create_action_options"]
    );
    let sign = wallet.signed.lock().unwrap().clone().unwrap();
    assert_eq!(
        serde_json::to_value(sign.options).unwrap(),
        case["sign_action"]["options"]
    );
}

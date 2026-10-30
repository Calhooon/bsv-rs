#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::identity_reveal_wallet::Counting;
use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, LocalKVStore};
use bsv_rs::overlay::{
    create_signed_overlay_admin_token, AdmittanceInstructions, LookupAnswer, LookupQuestion,
    LookupResolver, LookupResolverConfig, NetworkPreset, OutputListItem,
    OverlayBroadcastFacilitator, OverlayLookupFacilitator, Protocol, Steak, TaggedBEEF,
    TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::{from_hex, to_base64, PrivateKey};
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{
    ListOutputsResult, Outpoint, ReviewActionResult, ReviewActionResultStatus,
    ReviewActionsRefusal, WalletOutput,
};
use bsv_rs::{Error, Result};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

pub fn fixture(name: &str) -> Value {
    let vector: Value =
        serde_json::from_str(include_str!("../vectors/kvstore_retry_340.json")).unwrap();
    vector["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap()
        .clone()
}

fn token_outputs(tokens: &Value) -> Vec<OutputListItem> {
    tokens
        .as_array()
        .unwrap()
        .iter()
        .map(|token| OutputListItem {
            beef: from_hex(token["beef"].as_str().unwrap()).unwrap(),
            output_index: token["output_index"].as_u64().unwrap() as u32,
            context: None,
        })
        .collect()
}

fn listing(tokens: &Value) -> ListOutputsResult {
    let outputs = token_outputs(tokens);
    let mut beef = Beef::new();
    let outputs: Vec<_> = outputs
        .iter()
        .map(|item| {
            let tx = Transaction::from_beef(&item.beef, None).unwrap();
            let output = &tx.outputs[item.output_index as usize];
            let result = WalletOutput {
                outpoint: Outpoint::from_string(&format!(
                    "{}.{index}",
                    tx.id(),
                    index = item.output_index
                ))
                .unwrap(),
                satoshis: output.satoshis.unwrap(),
                locking_script: Some(output.locking_script.to_binary()),
                spendable: true,
                custom_instructions: None,
                tags: Some(vec!["alpha".into()]),
                labels: None,
            };
            beef.merge_transaction(tx);
            result
        })
        .collect();
    ListOutputsResult {
        total_outputs: outputs.len() as u64,
        outputs,
        beef: Some(beef.to_binary()),
    }
}

pub fn review(case: &Value) -> Error {
    Error::WalletReviewActions(Box::new(ReviewActionsRefusal::new(vec![
        ReviewActionResult {
            txid: [0x22; 32],
            status: ReviewActionResultStatus::DoubleSpend,
            competing_txs: Some(vec![from_hex(case["competing"]["txid"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()]),
            competing_beef: Some(from_hex(case["competing"]["beef"].as_str().unwrap()).unwrap()),
        },
    ])))
}

struct Lookup {
    case: Value,
    stage: Arc<AtomicUsize>,
    queries: Arc<AtomicUsize>,
    advertisement: OutputListItem,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Lookup {
    async fn lookup(
        &self,
        url: &str,
        question: &LookupQuestion,
        _: Option<u64>,
    ) -> Result<LookupAnswer> {
        assert!(url.starts_with("https://kvstore-340-") && url.ends_with(".invalid"));
        let outputs = match question.service.as_str() {
            "ls_ship" => vec![self.advertisement.clone()],
            "ls_kvstore" => {
                self.queries.fetch_add(1, Ordering::SeqCst);
                let field = if self.stage.load(Ordering::SeqCst) == 0 {
                    "initial_tokens"
                } else {
                    "fresh_tokens"
                };
                token_outputs(&self.case[field])
            }
            other => panic!("unexpected lookup: {other}"),
        };
        Ok(LookupAnswer::OutputList { outputs })
    }
}

struct Ship {
    wallet: Counting,
    competing: String,
    stage: Arc<AtomicUsize>,
    sent: Arc<Mutex<Vec<String>>>,
    fail: Arc<AtomicBool>,
    host: String,
}

#[async_trait::async_trait(?Send)]
impl OverlayBroadcastFacilitator for Ship {
    async fn send(&self, url: &str, tagged: &TaggedBEEF) -> Result<Steak> {
        assert_eq!(url, self.host);
        assert_eq!(tagged.topics, ["tm_kvstore"]);
        let txid = Transaction::from_beef(&tagged.beef, None).unwrap().id();
        self.sent.lock().unwrap().push(txid.clone());
        if txid == self.competing {
            let attempt = self.stage.fetch_add(1, Ordering::SeqCst);
            let aborts = self.wallet.aborts.lock().unwrap();
            assert_eq!(
                aborts.len(),
                attempt + 1,
                "abort must precede synchronization"
            );
            assert_eq!(
                aborts[attempt].reference,
                to_base64(&[0x52 + attempt as u8; 8])
            );
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::OverlayError("synchronization refused".into()));
        }
        Ok([(
            "tm_kvstore".into(),
            AdmittanceInstructions {
                outputs_to_admit: vec![],
                coins_to_retain: vec![],
                coins_removed: Some(vec![0]),
            },
        )]
        .into())
    }
}

pub enum Store {
    Global(GlobalKVStore<Counting>),
    Local(LocalKVStore<Counting>),
}

pub struct Harness {
    pub store: Store,
    pub wallet: Counting,
    pub case: Value,
    pub queries: Arc<AtomicUsize>,
    pub sent: Arc<Mutex<Vec<String>>>,
    pub fail: Arc<AtomicBool>,
}

impl Harness {
    pub async fn run(&self) -> Result<()> {
        match (&self.store, self.case["operation"].as_str().unwrap()) {
            (Store::Global(s), "set") => s.set("alpha", "two", None).await.map(|_| ()),
            (Store::Global(s), _) => s.remove("alpha", None).await.map(|_| ()),
            (Store::Local(s), "set") => s.set("alpha", "two", None).await.map(|_| ()),
            (Store::Local(s), _) => s.remove("alpha", None).await.map(|_| ()),
        }
    }
}

pub fn setup(name: &str) -> Harness {
    let case = fixture(name);
    let mut wallet = Counting::of_scalar(9);
    wallet.create_from_request = true;
    *wallet.sign_mode.lock().unwrap() = "valid";
    wallet
        .create_references
        .lock()
        .unwrap()
        .extend((0..5).map(|n| vec![0x52 + n; 8]));
    let failures = if case["mode"] == "always" { 6 } else { 1 };
    wallet
        .sign_answers
        .lock()
        .unwrap()
        .extend((0..failures).map(|_| Err(review(&case))));
    wallet
        .list_answers
        .lock()
        .unwrap()
        .push_back(listing(&case["initial_tokens"]));
    *wallet.listed.lock().unwrap() = Some(listing(&case["fresh_tokens"]));

    let host = format!(
        "https://kvstore-340-{}.invalid",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let key = PrivateKey::from_hex(&"09".repeat(32)).unwrap();
    let lock = create_signed_overlay_admin_token(&key, Protocol::Ship, &host, "tm_kvstore");
    let mut advertisement = Transaction::new();
    advertisement
        .add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    advertisement
        .add_output(TransactionOutput::new(1, lock))
        .unwrap();
    let stage = Arc::new(AtomicUsize::new(0));
    let queries = Arc::new(AtomicUsize::new(0));
    let resolver = || {
        LookupResolver::new(LookupResolverConfig {
            network_preset: NetworkPreset::Mainnet,
            host_overrides: Some(
                [
                    ("ls_kvstore".into(), vec![host.clone()]),
                    ("ls_ship".into(), vec![host.clone()]),
                ]
                .into(),
            ),
            slap_trackers: Some(vec![]),
            facilitator: Some(Arc::new(Lookup {
                case: case.clone(),
                stage: stage.clone(),
                queries: queries.clone(),
                advertisement: OutputListItem {
                    beef: advertisement.to_beef(true).unwrap(),
                    output_index: 0,
                    context: None,
                },
            })),
            ..Default::default()
        })
    };
    let sent = Arc::new(Mutex::new(vec![]));
    let fail = Arc::new(AtomicBool::new(false));
    let broadcaster = TopicBroadcaster::new(
        vec!["tm_kvstore".into()],
        TopicBroadcasterConfig {
            resolver: Some(Arc::new(resolver())),
            facilitator: Some(Arc::new(Ship {
                wallet: wallet.clone(),
                competing: case["competing"]["txid"].as_str().unwrap().into(),
                stage: stage.clone(),
                sent: sent.clone(),
                fail: fail.clone(),
                host: host.clone(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
    let store = if case["kind"] == "global" {
        Store::Global(
            GlobalKVStore::with_resolver(
                wallet.clone(),
                KVStoreConfig::default(),
                NetworkPreset::Mainnet,
                resolver(),
            )
            .with_broadcaster(broadcaster),
        )
    } else {
        Store::Local(
            LocalKVStore::new(wallet.clone(), KVStoreConfig::default().with_encrypt(false))
                .unwrap(),
        )
    };
    Harness {
        store,
        wallet,
        case,
        queries,
        sent,
        fail,
    }
}

pub fn assert_attempts(h: &Harness, attempts: usize, aborts: usize) {
    let creates = h.wallet.creates.lock().unwrap();
    assert_eq!(creates.len(), attempts, "reference attempt count");
    let signs = h.wallet.signs.lock().unwrap();
    assert_eq!(signs.len(), attempts);
    let aborted = h.wallet.aborts.lock().unwrap();
    assert_eq!(aborted.len(), aborts);
    let lookups = if h.case["kind"] == "global" {
        h.queries.load(Ordering::SeqCst)
    } else {
        h.wallet
            .calls()
            .iter()
            .filter(|&&c| c == "list_outputs")
            .count()
    };
    assert_eq!(lookups, attempts, "each attempt repeats the lookup");
    for (i, create) in creates.iter().enumerate() {
        let field = if i == 0 {
            "initial_tokens"
        } else {
            "fresh_tokens"
        };
        let expected: Vec<_> = h.case[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["outpoint"].as_str().unwrap())
            .collect();
        let actual: Vec<_> = create
            .inputs
            .iter()
            .flatten()
            .map(|input| {
                assert_eq!(input.unlocking_script_length, Some(74));
                input.outpoint.to_string()
            })
            .collect();
        assert_eq!(
            actual, expected,
            "attempt {i} must spend the fresh lookup's tokens"
        );
        let beef = create.input_beef.as_deref().unwrap();
        for item in token_outputs(&h.case[field]) {
            let tx = Transaction::from_beef(&item.beef, None).unwrap();
            assert_eq!(
                Transaction::from_beef(beef, Some(&tx.id())).unwrap().id(),
                tx.id()
            );
        }
        assert_eq!(signs[i].spends.len(), expected.len());
        let reference = to_base64(&[0x52 + i as u8; 8]);
        assert_eq!(signs[i].reference, reference);
        if let Some(recorded) = h.case["create_actions"].get(i) {
            assert_eq!(
                serde_json::to_value(&create.inputs).unwrap(),
                recorded["inputs"],
                "recorded createAction inputs for attempt {i}"
            );
            assert_eq!(signs[i].reference, h.case["sign_actions"][i]["reference"]);
        }
        if i < aborts {
            assert_eq!(aborted[i].reference, reference);
        }
    }
}

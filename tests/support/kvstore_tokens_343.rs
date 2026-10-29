#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::identity_reveal_wallet::Counting;
use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, LocalKVStore};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::primitives::bsv::sighash::parse_transaction;
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, Spend, SpendParams};
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, Protocol, SecurityLevel, WalletInterface,
};
use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Lookup {
    outputs: Arc<Mutex<Vec<OutputListItem>>>,
    questions: Arc<Mutex<Vec<LookupQuestion>>>,
}
#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Lookup {
    async fn lookup(
        &self,
        _: &str,
        question: &LookupQuestion,
        _: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.questions.lock().unwrap().push(question.clone());
        Ok(LookupAnswer::OutputList {
            outputs: self.outputs.lock().unwrap().clone(),
        })
    }
}

pub enum Store {
    Global(GlobalKVStore<Counting>),
    Local(LocalKVStore<Counting>),
}
impl Store {
    pub async fn set(&self, value: &str) {
        let result = match self {
            Self::Global(store) => store.set("alpha", value, None).await,
            Self::Local(store) => store.set("alpha", value, None).await,
        };
        // The wallet deliberately omits the signed result, so no broadcast is possible.
        assert!(result.is_err());
    }
    pub async fn remove(&self) {
        let result = match self {
            Self::Global(store) => store.remove("alpha", None).await.map(|_| ()),
            Self::Local(store) => store.remove("alpha", None).await.map(|_| ()),
        };
        assert!(result.is_err());
    }
}

fn source(lock: &LockingScript, index: u32, value: u64) -> Transaction {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), index))
        .unwrap();
    for _ in 0..index {
        tx.add_output(TransactionOutput::new(
            0,
            LockingScript::from_binary(&[0x00, 0x6a]).unwrap(),
        ))
        .unwrap();
    }
    tx.add_output(TransactionOutput::new(value, lock.clone()))
        .unwrap();
    tx
}

pub struct Harness {
    pub store: Store,
    pub wallet: Counting,
    pub sources: Vec<(Transaction, u32)>,
    pub lookup: Arc<Mutex<Vec<OutputListItem>>>,
    pub questions: Arc<Mutex<Vec<LookupQuestion>>>,
}

pub async fn setup(global: bool, count: usize) -> Harness {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: vec![],
        total_outputs: 0,
        beef: None,
    });
    let lookup = Arc::new(Mutex::new(vec![]));
    let questions = Arc::new(Mutex::new(vec![]));
    let store = make_store(global, &wallet, lookup.clone(), questions.clone());
    store.set("one").await;
    let lock = token_lock(global, &wallet);
    let sources: Vec<_> = (0..count)
        .map(|i| (source(&lock, i as u32, i as u64 + 2), i as u32))
        .collect();
    let mut beef = Beef::new();
    for (tx, index) in &sources {
        beef.merge_transaction(tx.clone());
        lookup.lock().unwrap().push(OutputListItem {
            beef: tx.to_beef(true).unwrap(),
            output_index: *index,
            context: None,
        });
    }
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: count as u32,
        beef: Some(beef.to_binary()),
        outputs: sources
            .iter()
            .map(|(tx, index)| WalletOutput {
                outpoint: Outpoint::from_string(&format!("{}.{index}", tx.id())).unwrap(),
                satoshis: tx.outputs[*index as usize].satoshis.unwrap(),
                locking_script: Some(lock.to_binary()),
                spendable: true,
                custom_instructions: None,
                tags: Some(vec!["alpha".into()]),
                labels: None,
            })
            .collect(),
    });
    *wallet.spending_many.lock().unwrap() = sources.clone();
    wallet.signs.lock().unwrap().clear();
    wallet.signature_args.lock().unwrap().clear();
    Harness {
        store,
        wallet,
        sources,
        lookup,
        questions,
    }
}

fn token_lock(global: bool, wallet: &Counting) -> LockingScript {
    if global {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/kvstore_tags_344.json")).unwrap();
        LockingScript::from_hex(fixture["cases"][0]["script"].as_str().unwrap()).unwrap()
    } else {
        LockingScript::from_binary(
            &wallet
                .created
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .outputs
                .as_ref()
                .unwrap()[0]
                .locking_script,
        )
        .unwrap()
    }
}

fn make_store(
    global: bool,
    wallet: &Counting,
    lookup: Arc<Mutex<Vec<OutputListItem>>>,
    questions: Arc<Mutex<Vec<LookupQuestion>>>,
) -> Store {
    let config = KVStoreConfig::default();
    if !global {
        return Store::Local(LocalKVStore::new(wallet.clone(), config).unwrap());
    }
    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        host_overrides: Some(
            [(
                config.service_name.clone(),
                vec![format!(
                    "https://kvstore-343-{}.invalid",
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )],
            )]
            .into(),
        ),
        slap_trackers: Some(vec![]),
        facilitator: Some(Arc::new(Lookup {
            outputs: lookup,
            questions,
        })),
        ..Default::default()
    });
    Store::Global(GlobalKVStore::with_resolver(
        wallet.clone(),
        config,
        NetworkPreset::Local,
        resolver,
    ))
}

pub fn assert_spends(h: &Harness) {
    let args = h.wallet.created.lock().unwrap().clone().unwrap();
    let expected: HashSet<_> = h
        .sources
        .iter()
        .map(|(tx, index)| format!("{}.{index}", tx.id()))
        .collect();
    let inputs: Vec<_> = args.inputs.iter().flatten().collect();
    assert_eq!(
        inputs.len(),
        expected.len(),
        "every current token must be an input"
    );
    assert_eq!(
        inputs
            .iter()
            .map(|input| input.outpoint.to_string())
            .collect::<HashSet<_>>(),
        expected
    );
    let beef = Beef::from_binary(args.input_beef.as_deref().expect("merged input BEEF")).unwrap();
    for (source, _) in &h.sources {
        assert!(
            beef.find_txid(&source.id()).is_some(),
            "merged BEEF must carry every token transaction"
        );
    }
    let signs = h.wallet.signs.lock().unwrap();
    let signed = signs.last().expect("signAction after binding");
    assert_eq!(
        signed.spends.len(),
        expected.len(),
        "one signer for each token"
    );
    let mut tx = requested_transaction(h, &args);
    for (index, spend) in &signed.spends {
        assert!(
            !spend.unlocking_script.is_empty(),
            "token unlocker must sign"
        );
        tx.inputs[*index as usize].unlocking_script =
            Some(bsv_rs::script::UnlockingScript::from_binary(&spend.unlocking_script).unwrap());
    }
    verify_inputs(&tx);
}

fn requested_transaction(h: &Harness, args: &bsv_rs::wallet::CreateActionArgs) -> Transaction {
    let mut tx = Transaction::new();
    for (source, index) in h.sources.iter().rev() {
        tx.add_input(TransactionInput::with_source_transaction(
            source.clone(),
            *index,
        ))
        .unwrap();
    }
    for output in args.outputs.iter().flatten() {
        tx.add_output(TransactionOutput::new(
            output.satoshis,
            LockingScript::from_binary(&output.locking_script).unwrap(),
        ))
        .unwrap();
    }
    if tx.outputs.is_empty() {
        tx.add_output(TransactionOutput::new(
            0,
            LockingScript::from_binary(&[0x00, 0x6a]).unwrap(),
        ))
        .unwrap();
    }
    tx
}

fn verify_inputs(tx: &Transaction) {
    let parsed = parse_transaction(&tx.to_binary()).unwrap();
    for (index, input) in tx.inputs.iter().enumerate() {
        let source =
            &input.source_transaction.as_ref().unwrap().outputs[input.source_output_index as usize];
        let mut spend = Spend::new(SpendParams {
            source_txid: parsed.inputs[index].txid,
            source_output_index: input.source_output_index,
            source_satoshis: source.satoshis.unwrap(),
            locking_script: source.locking_script.clone(),
            transaction_version: parsed.version,
            other_inputs: parsed
                .inputs
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != index)
                .map(|(_, input)| input.clone())
                .collect(),
            outputs: parsed.outputs.clone(),
            input_index: index,
            unlocking_script: input.unlocking_script.clone().unwrap(),
            input_sequence: input.sequence,
            lock_time: tx.lock_time,
            memory_limit: None,
            work_limit: None,
        });
        assert!(
            spend.validate().unwrap(),
            "token signature must spend its own outpoint"
        );
    }
}

pub async fn unrelated_tokens() -> Vec<OutputListItem> {
    let mut tokens = Vec::new();
    for (scalar, namespace, key) in [
        (9, "kvstore", "other"),
        (9, "other space", "alpha"),
        (10, "kvstore", "alpha"),
    ] {
        let lock = unrelated_lock(scalar, namespace, key).await;
        tokens.push(OutputListItem {
            beef: source(&lock, 0, 1).to_beef(true).unwrap(),
            output_index: 0,
            context: None,
        });
    }
    tokens
}

async fn unrelated_lock(scalar: u8, namespace: &str, key: &str) -> LockingScript {
    let wallet = Counting::of_scalar(scalar);
    let protocol = Protocol::new(SecurityLevel::App, namespace);
    let controller = wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: true,
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let mut fields = vec![
        serde_json::to_vec(&(1, namespace)).unwrap(),
        key.as_bytes().to_vec(),
        b"one".to_vec(),
        bsv_rs::primitives::from_hex(&controller.public_key).unwrap(),
    ];
    let signature = wallet
        .create_signature(
            CreateSignatureArgs {
                data: Some(fields.concat()),
                protocol_id: protocol.clone(),
                key_id: key.into(),
                counterparty: Some(Counterparty::Anyone),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    fields.push(signature.signature);
    let public_key = wallet
        .get_public_key(
            GetPublicKeyArgs {
                protocol_id: Some(protocol),
                key_id: Some(key.into()),
                counterparty: Some(Counterparty::Anyone),
                for_self: Some(true),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    PushDrop::new(
        bsv_rs::primitives::PublicKey::from_hex(&public_key.public_key).unwrap(),
        fields,
    )
    .lock()
}

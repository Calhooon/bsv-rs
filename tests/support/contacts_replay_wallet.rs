//! The basket wallet of the contacts replay (#904's seventh fold), the twin
//! of `basketWallet` in `contacts_replay_reference.mjs`: the ProtoWallet of
//! the scalar 9 over a basket of contact outputs it keeps. A listing answers
//! the basket's entries in the order they were added (filtered by a tag when
//! one is asked; their transactions merged into one BEEF for `entire
//! transactions`, their scripts for `locking scripts`); a createAction
//! without inputs commits its outputs at once and answers the finished
//! transaction (one made-up input, the recorder's `sourceOf`); one with
//! inputs answers a signable transaction spending the outpoints asked from
//! the input BEEF and commits it at signAction (the spent entries dropped,
//! the new contact outputs added after the rest); abortAction drops the
//! pending action; `pad` fills the basket with outputs that are no
//! contact's. A step's faults (`<call>`, its turn within the step, a
//! mode) are the recorder's: `throw` answers `<call> failed`, `no_tx` an
//! answer without a transaction, the bound and signed modes the #326
//! double's; two modes on one call apply together. Each call is recorded
//! by the reference's name, with the arguments the recorder records.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{from_base64, PrivateKey};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The reference text createAction answers with: the recorder's, the base64
/// of eight bytes of 0x52.
pub const REFERENCE: &str = "UlJSUlJSUlI=";

/// One fault of a step: the call it names, its turn within the step (from
/// 1) and its mode.
#[derive(Clone, Debug)]
pub struct Fault {
    pub call: String,
    pub turn: u32,
    pub mode: String,
}

struct Entry {
    /// The entry's transaction, none for a `pad` output (never in a BEEF:
    /// it carries no tag, and a load reads no BEEF).
    tx: Option<Transaction>,
    txid: String,
    vout: u32,
    satoshis: u64,
    locking_script: Vec<u8>,
    custom_instructions: Option<String>,
    tags: Vec<String>,
}

impl Entry {
    fn outpoint(&self) -> String {
        format!("{}.{}", self.txid, self.vout)
    }
}

#[derive(Default)]
struct Step {
    faults: Vec<Fault>,
    turns: HashMap<&'static str, u32>,
    calls: Vec<&'static str>,
    args: Vec<Value>,
}

#[derive(Default)]
struct World {
    basket: Vec<Entry>,
    pending: Option<(CreateActionArgs, Transaction)>,
    step: Step,
}

/// The wallet; clones share the basket.
#[derive(Clone)]
pub struct Basket {
    inner: Arc<ProtoWallet>,
    world: Arc<Mutex<World>>,
}

impl Default for Basket {
    fn default() -> Self {
        Self::new()
    }
}

impl Basket {
    pub fn new() -> Self {
        let mut scalar = [0u8; 32];
        scalar[31] = 9;
        Self {
            inner: Arc::new(ProtoWallet::new(Some(
                PrivateKey::from_bytes(&scalar).unwrap(),
            ))),
            world: Arc::default(),
        }
    }

    /// A step begins: its faults armed, its calls and arguments emptied.
    pub fn begin(&self, faults: Vec<Fault>) {
        self.world.lock().unwrap().step = Step {
            faults,
            ..Step::default()
        };
    }

    /// The step's calls in order and the arguments recorded.
    pub fn end(&self) -> (Vec<&'static str>, Vec<Value>) {
        let step = std::mem::take(&mut self.world.lock().unwrap().step);
        (step.calls, step.args)
    }

    /// The call recorded, its turn counted; its fault's mode, `<call>
    /// failed` for `throw`.
    fn enter(&self, name: &'static str) -> bsv_rs::Result<Vec<String>> {
        let mut world = self.world.lock().unwrap();
        let step = &mut world.step;
        step.calls.push(name);
        let turn = step.turns.entry(name).or_insert(0);
        *turn += 1;
        let turn = *turn;
        let modes: Vec<String> = step
            .faults
            .iter()
            .filter(|f| f.call == name && f.turn == turn)
            .map(|f| f.mode.clone())
            .collect();
        if modes.iter().any(|m| m == "throw") {
            return Err(bsv_rs::Error::WalletError(format!("{name} failed")));
        }
        Ok(modes)
    }

    /// The wallet's own step (`pad`): the basket filled with outputs that are
    /// no contact's (no custom instructions, `OP_1`) to `total` entries.
    pub fn pad(&self, total: usize) {
        let mut world = self.world.lock().unwrap();
        let missing = total.saturating_sub(world.basket.len());
        if missing == 0 {
            return;
        }
        let one = CreateActionOutput {
            locking_script: vec![0x51],
            satoshis: 1,
            output_description: String::new(),
            basket: None,
            custom_instructions: None,
            tags: None,
        };
        let txid = finished(&vec![one; missing]).id();
        for vout in 0..missing {
            world.basket.push(Entry {
                tx: None,
                txid: txid.clone(),
                vout: vout as u32,
                satoshis: 1,
                locking_script: vec![0x51],
                custom_instructions: None,
                tags: Vec::new(),
            });
        }
    }

    fn note(&self, args: Value) {
        self.world.lock().unwrap().step.args.push(args);
    }
}

/// The finished transaction a create without inputs answers: one made-up
/// input, the outputs asked (`sourceOf`).
fn finished(outputs: &[CreateActionOutput]) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new("11".repeat(32), 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    tx.add_input(input).unwrap();
    for output in outputs {
        let lock = LockingScript::from_binary(&output.locking_script).unwrap();
        tx.add_output(TransactionOutput::new(output.satoshis, lock))
            .unwrap();
    }
    tx
}

fn outpoint_text(outpoint: &Outpoint) -> String {
    format!(
        "{}.{}",
        bsv_rs::primitives::to_hex(&outpoint.txid),
        outpoint.vout
    )
}

fn txid_of(tx: &Transaction) -> TxId {
    Outpoint::from_string(&format!("{}.0", tx.id()))
        .unwrap()
        .txid
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl: the six key calls through the ProtoWallet under `enter`, the
// five the basket answers, the rest the ProtoWallet's unrecorded.
macro_rules! basket {
    ($(($method:ident, $name:literal, $args:ty, $result:ty)),* ; $(($other:ident, $oargs:ty, $oresult:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Basket {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> bsv_rs::Result<$result> {
                self.enter($name)?;
                WalletInterface::$method(&*self.inner, args, o).await
            })*
            $(async fn $other(&self, args: $oargs, o: Option<&str>) -> bsv_rs::Result<$oresult> {
                WalletInterface::$other(&*self.inner, args, o).await
            })*

            async fn list_outputs(
                &self,
                args: ListOutputsArgs,
                _o: Option<&str>,
            ) -> bsv_rs::Result<ListOutputsResult> {
                self.enter("listOutputs")?;
                let tags = args.tags.clone().unwrap_or_default();
                self.note(json!({
                    "call": "listOutputs",
                    "basket": args.basket,
                    "include": args.include,
                    "tags": tags,
                    "limit": args.limit,
                    "include_custom_instructions": args.include_custom_instructions,
                }));
                let world = self.world.lock().unwrap();
                let listed: Vec<&Entry> = world
                    .basket
                    .iter()
                    .filter(|e| tags.is_empty() || e.tags.iter().any(|t| tags.contains(t)))
                    .collect();
                let scripts = args.include == Some(OutputInclude::LockingScripts);
                let outputs: Vec<WalletOutput> = listed
                    .iter()
                    .map(|e| WalletOutput {
                        satoshis: e.satoshis,
                        locking_script: scripts.then(|| e.locking_script.clone()),
                        spendable: true,
                        custom_instructions: e.custom_instructions.clone(),
                        tags: None,
                        outpoint: Outpoint::from_string(&e.outpoint()).unwrap(),
                        labels: None,
                    })
                    .collect();
                let beef = (args.include == Some(OutputInclude::EntireTransactions)
                    && !listed.is_empty())
                .then(|| {
                    let mut beef = Beef::new();
                    for tx in listed.iter().filter_map(|e| e.tx.clone()) {
                        beef.merge_transaction(tx);
                    }
                    beef.to_binary().unwrap()
                });
                Ok(ListOutputsResult {
                    total_outputs: outputs.len() as u32,
                    outputs,
                    beef,
                })
            }

            async fn create_action(
                &self,
                args: CreateActionArgs,
                _o: Option<&str>,
            ) -> bsv_rs::Result<CreateActionResult> {
                let mode = self.enter("createAction")?;
                let outputs = args.outputs.clone().unwrap_or_default();
                self.note(json!({
                    "call": "createAction",
                    "description": args.description,
                    "input_beef": args.input_beef.is_some(),
                    "inputs": args.inputs.as_ref().map(|inputs| inputs.iter().map(|i| json!({
                        "input_description": i.input_description,
                        "unlocking_script_length": i.unlocking_script_length,
                    })).collect::<Vec<_>>()),
                    "outputs": outputs.iter().map(|o| json!({
                        "output_description": o.output_description,
                        "satoshis": o.satoshis,
                        "basket": o.basket,
                        "tags": o.tags,
                        "custom_instructions": o.custom_instructions.is_some(),
                    })).collect::<Vec<_>>(),
                    "labels": args.labels,
                    "options": args.options,
                }));
                let has = |m: &str| mode.iter().any(|x| x == m);
                if has("no_tx") {
                    return Ok(CreateActionResult::default());
                }
                let mut world = self.world.lock().unwrap();
                let Some(inputs) = &args.inputs else {
                    let tx = finished(&outputs);
                    let txid = tx.id();
                    for (vout, o) in outputs.iter().enumerate() {
                        if o.basket.as_deref() == Some("contacts") {
                            world.basket.push(Entry {
                                tx: Some(tx.clone()),
                                txid: txid.clone(),
                                vout: vout as u32,
                                satoshis: o.satoshis,
                                locking_script: o.locking_script.clone(),
                                custom_instructions: o.custom_instructions.clone(),
                                tags: o.tags.clone().unwrap_or_default(),
                            });
                        }
                    }
                    return Ok(CreateActionResult {
                        txid: Some(txid_of(&tx)),
                        tx: Some(tx.to_atomic_beef(true).unwrap()),
                        ..Default::default()
                    });
                };
                let beef = args.input_beef.as_deref().unwrap();
                let mut partial = Transaction::new();
                for input in inputs {
                    let txid = bsv_rs::primitives::to_hex(&input.outpoint.txid);
                    let source = Transaction::from_beef(beef, Some(&txid)).unwrap();
                    partial
                        .add_input(TransactionInput::with_source_transaction(source, input.outpoint.vout))
                        .unwrap();
                }
                if outputs.is_empty() {
                    let data = LockingScript::from_binary(&[0x00, 0x6a]).unwrap();
                    partial.add_output(TransactionOutput::new(0, data)).unwrap();
                }
                for o in &outputs {
                    let lock = LockingScript::from_binary(&o.locking_script).unwrap();
                    partial.add_output(TransactionOutput::new(o.satoshis, lock)).unwrap();
                }
                if has("duplicate_input") {
                    let lead = partial.inputs()[0].clone();
                    partial.inputs_mut().push(lead);
                }
                if has("missing_input") {
                    partial.inputs_mut()[0].source_output_index = 1;
                }
                if has("output") {
                    partial.outputs_mut()[0].satoshis = Some(0);
                }
                let tx = partial.to_atomic_beef(true).unwrap();
                world.pending = Some((args.clone(), partial));
                Ok(CreateActionResult {
                    signable_transaction: Some(SignableTransaction {
                        tx,
                        reference: from_base64(REFERENCE).unwrap(),
                    }),
                    ..Default::default()
                })
            }

            async fn sign_action(
                &self,
                args: SignActionArgs,
                _o: Option<&str>,
            ) -> bsv_rs::Result<SignActionResult> {
                let mode = self.enter("signAction")?;
                let mut keys: Vec<u32> = args.spends.keys().copied().collect();
                keys.sort_unstable();
                self.note(json!({
                    "call": "signAction",
                    "spends": keys.iter().map(u32::to_string).collect::<Vec<_>>(),
                    "reference": args.reference,
                    "options": args.options,
                }));
                let has = |m: &str| mode.iter().any(|x| x == m);
                if has("no_tx") {
                    return Ok(SignActionResult { txid: None, tx: None, send_with_results: None });
                }
                let mut world = self.world.lock().unwrap();
                let (asked, partial) = world.pending.take().unwrap();
                let mut signed = Transaction::from_atomic_beef(&partial.to_atomic_beef(true).unwrap()).unwrap();
                for (index, spend) in &args.spends {
                    signed.inputs_mut()[*index as usize].unlocking_script =
                        Some(UnlockingScript::from_binary(&spend.unlocking_script).unwrap());
                }
                if has("signed_version") {
                    signed.set_version(2);
                }
                if has("signed_output") {
                    signed.outputs_mut()[0].satoshis = Some(0);
                }
                if has("signed_script") {
                    signed.inputs_mut()[0].unlocking_script =
                        Some(UnlockingScript::from_binary(&[0]).unwrap());
                }
                let spent: Vec<String> = asked
                    .inputs
                    .iter()
                    .flatten()
                    .map(|i| outpoint_text(&i.outpoint))
                    .collect();
                world.basket.retain(|e| !spent.contains(&e.outpoint()));
                let txid = signed.id();
                for (vout, o) in asked.outputs.iter().flatten().enumerate() {
                    if o.basket.as_deref() == Some("contacts") {
                        let out = &signed.outputs()[vout];
                        world.basket.push(Entry {
                            tx: Some(signed.clone()),
                            txid: txid.clone(),
                            vout: vout as u32,
                            satoshis: out.satoshis.unwrap(),
                            locking_script: out.locking_script.to_binary(),
                            custom_instructions: o.custom_instructions.clone(),
                            tags: o.tags.clone().unwrap_or_default(),
                        });
                    }
                }
                Ok(SignActionResult {
                    txid: Some(txid_of(&signed)),
                    tx: Some(signed.to_atomic_beef(true).unwrap()),
                    send_with_results: None,
                })
            }

            async fn abort_action(
                &self,
                args: AbortActionArgs,
                _o: Option<&str>,
            ) -> bsv_rs::Result<AbortActionResult> {
                self.enter("abortAction")?;
                self.note(json!({ "call": "abortAction", "reference": args.reference }));
                self.world.lock().unwrap().pending = None;
                Ok(AbortActionResult { aborted: true })
            }

            async fn prove_certificate(
                &self,
                args: ProveCertificateArgs,
                o: Option<&str>,
            ) -> bsv_rs::Result<ProveCertificateResult> {
                WalletInterface::prove_certificate(&*self.inner, args, o).await
            }
            async fn is_authenticated(&self, o: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> {
                WalletInterface::is_authenticated(&*self.inner, o).await
            }
            async fn wait_for_authentication(&self, o: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> {
                WalletInterface::wait_for_authentication(&*self.inner, o).await
            }
            async fn get_height(&self, o: Option<&str>) -> bsv_rs::Result<GetHeightResult> {
                WalletInterface::get_height(&*self.inner, o).await
            }
            async fn get_network(&self, o: Option<&str>) -> bsv_rs::Result<GetNetworkResult> {
                WalletInterface::get_network(&*self.inner, o).await
            }
            async fn get_version(&self, o: Option<&str>) -> bsv_rs::Result<GetVersionResult> {
                WalletInterface::get_version(&*self.inner, o).await
            }
        }
    };
}

basket! {
    (get_public_key, "getPublicKey", GetPublicKeyArgs, GetPublicKeyResult),
    (create_signature, "createSignature", CreateSignatureArgs, CreateSignatureResult),
    (verify_signature, "verifySignature", VerifySignatureArgs, VerifySignatureResult),
    (create_hmac, "createHmac", CreateHmacArgs, CreateHmacResult),
    (encrypt, "encrypt", EncryptArgs, EncryptResult),
    (decrypt, "decrypt", DecryptArgs, DecryptResult);
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult),
}

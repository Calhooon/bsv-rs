//! The counting wallet of the identity reveal's tests (#307, #310): a
//! ProtoWallet under a client that records each call, answers
//! proveCertificate with a keyring it is given and createAction with no
//! transaction, so nothing is broadcast; createAction's arguments and
//! originator kept (#315); every call's originator kept, and with a
//! signable transaction set createAction answers it and signAction's
//! arguments are kept, signAction answering no transaction (#318); every
//! createAction, signAction and abortAction's arguments kept in order,
//! signAction answering from a queue when one is set, abortAction
//! answering `aborted: true` (#327); with a listing set listOutputs answers
//! it, and with a source set createAction answers a signable transaction
//! spending its output 0, so the contacts manager and the key-value stores
//! reach signAction (#326); signAction answered by another wallet when one
//! is set, the JSON substrate under wiremock (#339).
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{from_base64, PrivateKey};
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// The reference text the #326 wallet answers createAction with: the
/// recorder's, the base64 of eight bytes of 0x52.
pub const SIGNABLE_REFERENCE: &str = "UlJSUlJSUlI=";

/// A signable transaction spending output 0 of `source` to `outputs`.
fn spending_signable(source: &Transaction, outputs: &[CreateActionOutput]) -> SignableTransaction {
    let mut partial = Transaction::new();
    partial
        .add_input(TransactionInput::with_source_transaction(source.clone(), 0))
        .unwrap();
    if outputs.is_empty() {
        let data = LockingScript::from_binary(&[0x00, 0x6a]).unwrap();
        partial.add_output(TransactionOutput::new(0, data)).unwrap();
    }
    for output in outputs {
        let lock = LockingScript::from_binary(&output.locking_script).unwrap();
        partial
            .add_output(TransactionOutput::new(output.satoshis, lock))
            .unwrap();
    }
    SignableTransaction {
        tx: partial.to_atomic_beef(true).unwrap(),
        reference: from_base64(SIGNABLE_REFERENCE).unwrap(),
    }
}

/// A ProtoWallet that records each call by name; proveCertificate answers
/// a keyring of the names asked (or of `keyring` when set), createAction
/// no transaction; getPublicKey's and createSignature's arguments kept.
#[derive(Clone)]
pub struct Counting {
    inner: Arc<ProtoWallet>,
    calls: Arc<Mutex<Vec<&'static str>>>,
    originators: Arc<Mutex<Vec<Option<String>>>>,
    /// The signable transaction createAction answers (its atomic BEEF and
    /// reference), none by default (#318).
    pub signable: Option<SignableTransaction>,
    pub signed: Arc<Mutex<Option<SignActionArgs>>>,
    /// What listOutputs answers when set; the ProtoWallet's answer otherwise
    /// (#326).
    pub listed: Arc<Mutex<Option<ListOutputsResult>>>,
    /// A source transaction: when set, createAction answers a signable
    /// transaction spending its output 0 to the outputs asked (one
    /// `OP_FALSE OP_RETURN` when none), its reference `SIGNABLE_REFERENCE`
    /// decoded, as a substrate hands the wallet's text over (#326).
    pub spending: Arc<Mutex<Option<Transaction>>>,
    pub keyring: Option<indexmap::IndexMap<String, String>>,
    pub created: Arc<Mutex<Option<CreateActionArgs>>>,
    pub created_originator: Arc<Mutex<Option<String>>>,
    pub public_key_args: Arc<Mutex<Vec<GetPublicKeyArgs>>>,
    pub signature_args: Arc<Mutex<Vec<CreateSignatureArgs>>>,
    /// signAction's answers in turn, no transaction once empty (#327).
    pub sign_answers: Arc<Mutex<VecDeque<bsv_rs::Result<SignActionResult>>>>,
    pub creates: Arc<Mutex<Vec<CreateActionArgs>>>,
    pub signs: Arc<Mutex<Vec<SignActionArgs>>>,
    pub aborts: Arc<Mutex<Vec<AbortActionArgs>>>,
    /// The wallet that answers signAction in place of the queue (#339).
    pub sign_via: Option<Arc<dyn WalletInterface>>,
    /// #341: mutation applied to the owned createAction answer.
    pub create_mode: Arc<Mutex<&'static str>>,
    pub sign_mode: Arc<Mutex<&'static str>>,
    pending: Arc<Mutex<Option<SignableTransaction>>>,
}

// The key-value stores ask their wallet for `Debug` (#326).
impl std::fmt::Debug for Counting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Counting")
    }
}

impl Counting {
    /// The #307 wallet: the key of 32 bytes of 5.
    pub fn new() -> Self {
        Self::of_key(PrivateKey::from_bytes(&[5u8; 32]).unwrap())
    }

    /// A wallet of the scalar `n`, the reference's `new PrivateKey(n)`.
    pub fn of_scalar(n: u8) -> Self {
        let mut scalar = [0u8; 32];
        scalar[31] = n;
        Self::of_key(PrivateKey::from_bytes(&scalar).unwrap())
    }

    fn of_key(key: PrivateKey) -> Self {
        Self {
            inner: Arc::new(ProtoWallet::new(Some(key))),
            calls: Arc::default(),
            originators: Arc::default(),
            signable: None,
            signed: Arc::default(),
            listed: Arc::default(),
            spending: Arc::default(),
            keyring: None,
            created: Arc::default(),
            created_originator: Arc::default(),
            public_key_args: Arc::default(),
            signature_args: Arc::default(),
            sign_answers: Arc::default(),
            creates: Arc::default(),
            signs: Arc::default(),
            aborts: Arc::default(),
            sign_via: None,
            create_mode: Arc::new(Mutex::new("")),
            sign_mode: Arc::new(Mutex::new("")),
            pending: Arc::default(),
        }
    }

    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    /// The originator each call received, in the order of `calls` (#318;
    /// `None` an absent one, #329).
    pub fn originators(&self) -> Vec<Option<String>> {
        self.originators.lock().unwrap().clone()
    }

    fn note(&self, name: &'static str, originator: Option<&str>) {
        self.calls.lock().unwrap().push(name);
        self.originators
            .lock()
            .unwrap()
            .push(originator.map(str::to_string));
    }
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! counting {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Counting {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> bsv_rs::Result<$result> {
                self.note(stringify!($method), o);
                WalletInterface::$method(&*self.inner, args, o).await
            })*

            async fn prove_certificate(
                &self,
                args: ProveCertificateArgs,
                o: Option<&str>,
            ) -> bsv_rs::Result<ProveCertificateResult> {
                self.note("prove_certificate", o);
                let asked = args.fields_to_reveal.iter().map(|f| (f.clone(), "AAAA".to_string()));
                Ok(ProveCertificateResult {
                    keyring_for_verifier: self.keyring.clone().unwrap_or_else(|| asked.collect()),
                    certificate: None,
                    verifier: None,
                })
            }
            async fn create_action(
                &self,
                args: CreateActionArgs,
                o: Option<&str>,
            ) -> bsv_rs::Result<CreateActionResult> {
                self.note("create_action", o);
                self.creates.lock().unwrap().push(args.clone());
                let spent = self.spending.lock().unwrap().clone();
                let mut signable = match spent {
                    Some(source) => {
                        Some(spending_signable(&source, args.outputs.as_deref().unwrap_or(&[])))
                    }
                    None => self.signable.clone(),
                };
                if let Some(answer) = &mut signable {
                    mutate_bound_answer(answer, &self.create_mode.lock().unwrap());
                }
                *self.pending.lock().unwrap() = signable.clone();
                *self.created.lock().unwrap() = Some(args);
                *self.created_originator.lock().unwrap() = o.map(str::to_string);
                Ok(CreateActionResult {
                    signable_transaction: signable,
                    ..Default::default()
                })
            }
            async fn sign_action(
                &self,
                args: SignActionArgs,
                o: Option<&str>,
            ) -> bsv_rs::Result<SignActionResult> {
                self.note("sign_action", o);
                self.signs.lock().unwrap().push(args.clone());
                *self.signed.lock().unwrap() = Some(args.clone());
                let mode = *self.sign_mode.lock().unwrap();
                if !mode.is_empty() {
                    return Ok(bound_sign_answer(self.pending.lock().unwrap().as_ref().unwrap(), &args, mode));
                }
                if let Some(via) = &self.sign_via {
                    return via.sign_action(args, o).await;
                }
                self.sign_answers.lock().unwrap().pop_front().unwrap_or(Ok(SignActionResult {
                    txid: None,
                    tx: None,
                    send_with_results: None,
                }))
            }
            async fn abort_action(
                &self,
                args: AbortActionArgs,
                o: Option<&str>,
            ) -> bsv_rs::Result<AbortActionResult> {
                self.note("abort_action", o);
                self.aborts.lock().unwrap().push(args);
                Ok(AbortActionResult { aborted: true })
            }
            async fn list_outputs(
                &self,
                args: ListOutputsArgs,
                o: Option<&str>,
            ) -> bsv_rs::Result<ListOutputsResult> {
                self.note("list_outputs", o);
                if let Some(listed) = self.listed.lock().unwrap().clone() {
                    return Ok(listed);
                }
                WalletInterface::list_outputs(&*self.inner, args, o).await
            }
            async fn get_public_key(
                &self,
                args: GetPublicKeyArgs,
                o: Option<&str>,
            ) -> bsv_rs::Result<GetPublicKeyResult> {
                self.note("get_public_key", o);
                self.public_key_args.lock().unwrap().push(args.clone());
                WalletInterface::get_public_key(&*self.inner, args, o).await
            }
            async fn create_signature(
                &self,
                args: CreateSignatureArgs,
                o: Option<&str>,
            ) -> bsv_rs::Result<CreateSignatureResult> {
                self.note("create_signature", o);
                self.signature_args.lock().unwrap().push(args.clone());
                WalletInterface::create_signature(&*self.inner, args, o).await
            }
            async fn is_authenticated(&self, o: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> {
                self.note("is_authenticated", o);
                WalletInterface::is_authenticated(&*self.inner, o).await
            }
            async fn wait_for_authentication(
                &self,
                o: Option<&str>,
            ) -> bsv_rs::Result<AuthenticatedResult> {
                self.note("wait_for_authentication", o);
                WalletInterface::wait_for_authentication(&*self.inner, o).await
            }
            async fn get_height(&self, o: Option<&str>) -> bsv_rs::Result<GetHeightResult> {
                self.note("get_height", o);
                WalletInterface::get_height(&*self.inner, o).await
            }
            async fn get_network(&self, o: Option<&str>) -> bsv_rs::Result<GetNetworkResult> {
                self.note("get_network", o);
                WalletInterface::get_network(&*self.inner, o).await
            }
            async fn get_version(&self, o: Option<&str>) -> bsv_rs::Result<GetVersionResult> {
                self.note("get_version", o);
                WalletInterface::get_version(&*self.inner, o).await
            }
        }
    };
}

counting! {
    (encrypt, EncryptArgs, EncryptResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
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

/// Mutations whose refusals were recorded by the #326 Node recorder's extension.
fn mutate_bound_answer(answer: &mut SignableTransaction, mode: &str) {
    if mode.is_empty() {
        return;
    }
    if mode == "empty_reference" {
        answer.reference.clear();
        return;
    }
    let mut tx = Transaction::from_atomic_beef(&answer.tx).unwrap();
    match mode {
        "version" | "version_before_input" => tx.version = 2,
        "lock_time" => tx.lock_time = 1,
        "sequence" => tx.inputs[0].sequence = 0,
        "duplicate_input" => tx.inputs.push(tx.inputs[0].clone()),
        "output" => tx.outputs[0].satoshis = Some(0),
        "inflation" | "unrequested_output" => {
            let value = if mode == "inflation" { 2 } else { 1 };
            tx.add_output(TransactionOutput::new(
                value,
                LockingScript::from_binary(&[0x51]).unwrap(),
            ))
            .unwrap();
        }
        _ => {}
    }
    if mode == "missing_input" || mode == "version_before_input" {
        tx.inputs[0].source_output_index = 1;
    }
    tx.invalidate_caches();
    answer.tx = tx.to_atomic_beef(true).unwrap();
}

fn bound_sign_answer(
    pending: &SignableTransaction,
    args: &SignActionArgs,
    mode: &str,
) -> SignActionResult {
    let mut tx = Transaction::from_atomic_beef(&pending.tx).unwrap();
    for (index, spend) in &args.spends {
        tx.inputs[*index as usize].unlocking_script =
            Some(bsv_rs::script::UnlockingScript::from_binary(&spend.unlocking_script).unwrap());
    }
    match mode {
        "signed_version" => tx.version = 2,
        "signed_output" => tx.outputs[0].satoshis = Some(0),
        "signed_script" => {
            tx.inputs[0].unlocking_script =
                Some(bsv_rs::script::UnlockingScript::from_binary(&[0]).unwrap())
        }
        _ => {}
    }
    tx.invalidate_caches();
    let id = if mode == "txid_mismatch" {
        let mut other = tx.clone();
        other.lock_time += 1;
        other.invalidate_caches();
        other.id()
    } else {
        tx.id()
    };
    let id = Outpoint::from_string(&format!("{id}.0")).unwrap().txid;
    SignActionResult {
        tx: Some(tx.to_atomic_beef(true).unwrap()),
        txid: Some(id),
        send_with_results: None,
    }
}

//! The three identity paths that sign a token input through the wallet
//! (`IdentityClient::revoke_certificate_revelation`, the contact update inside
//! `ContactsManager::add_contact`, `ContactsManager::remove_contact`), their
//! unlocking scripts run through `Spend` under the node's block word.
//!
//! Each path builds the BIP143 preimage and asks the wallet to sign a digest
//! directly (`hash_to_directly_sign`). Until 0.7.0 that digest was ONE
//! SHA-256 of the preimage, while the node verifies against the double SHA-256
//! (bitcoin-sv v1.2.3 `SignatureHashBIP143`, `ss.GetHash()`); the reference
//! hashes twice too (`@bsv/sdk` passes `data: sha256(preimage)` and the wallet
//! hashes `data` again, ts-stack@4d0ea63 `packages/sdk/src/script/templates/PushDrop.ts:245-248`).
//! Every signature these paths produced was one the node refuses. The paths
//! now sign `compute_sighash_dispatched_for_signing`, the dispatcher every
//! template reaches through `SigningContext`.
//!
//! Hermetic: the wallet is a `ProtoWallet` for the keys and a mock for the
//! actions, the overlay lookup is an injected facilitator, and the revocation
//! stops before its broadcast (the mock's `signAction` returns no transaction).
//! Since #327 the revocation spends only a token it authenticates: the
//! subject's wallet (key 9) revokes the reference's token for #318's
//! certificate (`vectors/identity_wallet_calls_318.json`, the token this
//! crate's reveal writes byte for byte, #310), carried by a source
//! transaction of this crate's writer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::identity::{
    Contact, ContactsManager, ContactsManagerConfig, IdentityClient, IdentityClientConfig,
};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult, Counterparty,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, Network, Outpoint, ProtoWallet, Protocol,
    ProveCertificateArgs, ProveCertificateResult, RelinquishCertificateArgs,
    RelinquishCertificateResult, RelinquishOutputArgs, RelinquishOutputResult,
    RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult, SecurityLevel,
    SignActionArgs, SignActionResult, SignableTransaction, VerifyHmacArgs, VerifyHmacResult,
    VerifySignatureArgs, VerifySignatureResult, WalletCertificate, WalletInterface, WalletOutput,
    WalletRevealCounterpartyArgs, WalletRevealSpecificArgs,
};
use bsv_rs::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const CONTACT_KEY_ID: &str = "contact-key-1";

/// A transaction input the test can name: the source's own input spends a
/// made-up outpoint, the source's output 0 is the token.
fn source_transaction(lock: &LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new("11".repeat(32), 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(1, lock.clone()))
        .unwrap();
    tx
}

/// What the mock wallet saw: the partial transaction it handed out, and the
/// unlocking script the identity path sent back for input 0.
#[derive(Default)]
struct Seen {
    partial: Option<Transaction>,
    signed: Vec<(Transaction, Vec<u8>)>,
}

/// `ProtoWallet` for every key operation, a mock for the action calls: the
/// listed output is the token, `createAction` spends it with the source
/// attached, `signAction` records the unlocking script.
#[derive(Clone)]
struct TokenWallet {
    keys: Arc<ProtoWallet>,
    source: Arc<Mutex<Option<Transaction>>>,
    seen: Arc<Mutex<Seen>>,
}

impl TokenWallet {
    fn new() -> Self {
        Self::of_key(PrivateKey::from_hex(&"07".repeat(32)).unwrap())
    }

    /// A wallet of the scalar `n`, the reference's `new PrivateKey(n)`.
    fn of_scalar(n: u8) -> Self {
        let mut scalar = [0u8; 32];
        scalar[31] = n;
        Self::of_key(PrivateKey::from_bytes(&scalar).unwrap())
    }

    fn of_key(key: PrivateKey) -> Self {
        Self {
            keys: Arc::new(ProtoWallet::new(Some(key))),
            source: Arc::new(Mutex::new(None)),
            seen: Arc::new(Mutex::new(Seen::default())),
        }
    }

    async fn derived_key(&self, protocol: Protocol, key_id: &str, who: Counterparty) -> PublicKey {
        let result = WalletInterface::get_public_key(
            self.keys.as_ref(),
            GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(protocol),
                key_id: Some(key_id.to_string()),
                counterparty: Some(who),
                for_self: Some(true),
                ..Default::default()
            },
            Some("test"),
        )
        .await
        .unwrap();
        PublicKey::from_hex(&result.public_key).unwrap()
    }

    fn set_source(&self, tx: Transaction) {
        *self.source.lock().unwrap() = Some(tx);
    }

    fn source(&self) -> Transaction {
        self.source.lock().unwrap().clone().unwrap()
    }

    fn signed(&self) -> Vec<(Transaction, Vec<u8>)> {
        self.seen.lock().unwrap().signed.clone()
    }
}

#[async_trait::async_trait]
impl WalletInterface for TokenWallet {
    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult> {
        WalletInterface::get_public_key(self.keys.as_ref(), args, originator).await
    }

    async fn encrypt(&self, args: EncryptArgs, originator: Option<&str>) -> Result<EncryptResult> {
        WalletInterface::encrypt(self.keys.as_ref(), args, originator).await
    }

    async fn decrypt(&self, args: DecryptArgs, originator: Option<&str>) -> Result<DecryptResult> {
        WalletInterface::decrypt(self.keys.as_ref(), args, originator).await
    }

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: Option<&str>,
    ) -> Result<CreateHmacResult> {
        WalletInterface::create_hmac(self.keys.as_ref(), args, originator).await
    }

    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: Option<&str>,
    ) -> Result<VerifyHmacResult> {
        WalletInterface::verify_hmac(self.keys.as_ref(), args, originator).await
    }

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: Option<&str>,
    ) -> Result<CreateSignatureResult> {
        WalletInterface::create_signature(self.keys.as_ref(), args, originator).await
    }

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: Option<&str>,
    ) -> Result<VerifySignatureResult> {
        WalletInterface::verify_signature(self.keys.as_ref(), args, originator).await
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        _args: WalletRevealCounterpartyArgs,
        _originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn reveal_specific_key_linkage(
        &self,
        _args: WalletRevealSpecificArgs,
        _originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    /// Spends the token (input 0, its source attached) to the outputs asked
    /// for, or to one data output when none is asked for, as a wallet adds
    /// change; hands the partial transaction out as BEEF.
    async fn create_action(
        &self,
        args: CreateActionArgs,
        _originator: Option<&str>,
    ) -> Result<CreateActionResult> {
        let source = self.source();
        let mut partial = Transaction::new();
        partial.add_input(TransactionInput::with_source_transaction(source, 0))?;
        let outputs = args.outputs.unwrap_or_default();
        if outputs.is_empty() {
            let data = LockingScript::from_binary(&[0x00, 0x6a])?;
            partial.add_output(TransactionOutput::new(0, data))?;
        }
        for output in outputs {
            let lock = LockingScript::from_binary(&output.locking_script)?;
            partial.add_output(TransactionOutput::new(output.satoshis, lock))?;
        }
        // atomic, as a wallet answers a signable transaction (BRC-100)
        let beef = partial.to_atomic_beef(true)?;
        self.seen.lock().unwrap().partial = Some(partial);
        Ok(CreateActionResult {
            txid: None,
            tx: None,
            no_send_change: None,
            send_with_results: None,
            signable_transaction: Some(SignableTransaction {
                tx: beef,
                reference: vec![0x52; 8],
            }),
            input_type: None,
            inputs: None,
            reference_number: None,
            beef: None,
        })
    }

    /// Records the unlocking script for input 0 and returns a txid and no
    /// transaction: the contact paths finish, the revocation stops before it
    /// would broadcast.
    async fn sign_action(
        &self,
        args: SignActionArgs,
        _originator: Option<&str>,
    ) -> Result<SignActionResult> {
        let unlock = args.spends.get(&0).unwrap().unlocking_script.clone();
        let mut seen = self.seen.lock().unwrap();
        let partial = seen.partial.clone().unwrap();
        seen.signed.push((partial, unlock));
        Ok(SignActionResult {
            txid: Some([0xab; 32]),
            tx: None,
            send_with_results: None,
        })
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _originator: Option<&str>,
    ) -> Result<AbortActionResult> {
        Ok(AbortActionResult { aborted: true })
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _originator: Option<&str>,
    ) -> Result<ListActionsResult> {
        Ok(ListActionsResult {
            actions: vec![],
            total_actions: 0,
        })
    }

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _originator: Option<&str>,
    ) -> Result<InternalizeActionResult> {
        Ok(InternalizeActionResult { accepted: true })
    }

    /// The token, with the key ID the contact paths read from its custom
    /// instructions.
    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _originator: Option<&str>,
    ) -> Result<ListOutputsResult> {
        let source = self.source();
        Ok(ListOutputsResult {
            outputs: vec![WalletOutput {
                satoshis: 1,
                locking_script: None,
                spendable: true,
                custom_instructions: Some(
                    serde_json::json!({ "keyID": CONTACT_KEY_ID }).to_string(),
                ),
                tags: None,
                outpoint: Outpoint::from_string(&format!("{}.0", source.id()))?,
                labels: None,
            }],
            total_outputs: 1,
            beef: Some(source.to_beef(true)?),
        })
    }

    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _originator: Option<&str>,
    ) -> Result<RelinquishOutputResult> {
        Ok(RelinquishOutputResult { relinquished: true })
    }

    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<WalletCertificate> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _originator: Option<&str>,
    ) -> Result<ListCertificatesResult> {
        Ok(ListCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<ProveCertificateResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult> {
        Ok(RelinquishCertificateResult { relinquished: true })
    }

    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        Ok(DiscoverCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        Ok(DiscoverCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    async fn is_authenticated(&self, _originator: Option<&str>) -> Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn wait_for_authentication(
        &self,
        _originator: Option<&str>,
    ) -> Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn get_height(&self, _originator: Option<&str>) -> Result<GetHeightResult> {
        Ok(GetHeightResult { height: 800_000 })
    }

    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
        _originator: Option<&str>,
    ) -> Result<GetHeaderResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn get_network(&self, _originator: Option<&str>) -> Result<GetNetworkResult> {
        Ok(GetNetworkResult {
            network: Network::Mainnet,
        })
    }

    async fn get_version(&self, _originator: Option<&str>) -> Result<GetVersionResult> {
        Ok(GetVersionResult {
            version: "token-wallet-1.0".to_string(),
        })
    }
}

/// Answers every lookup with the token's BEEF at output 0.
struct TokenLookup {
    beef: Vec<u8>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for TokenLookup {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: vec![OutputListItem {
                beef: self.beef.clone(),
                output_index: 0,
                context: None,
            }],
        })
    }
}

/// The node's verdict on input 0 of `spend` against the token: the block
/// word after Chronicle, the source output's lock and value.
fn node_verdict(
    spend: &Transaction,
    lock: &LockingScript,
    unlock: &[u8],
) -> std::result::Result<bool, String> {
    let raw = spend.to_binary();
    let tx = bsv_rs::primitives::bsv::sighash::parse_transaction(&raw).unwrap();
    let input = &tx.inputs[0];
    let mut node = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: 1,
        locking_script: lock.clone(),
        transaction_version: tx.version,
        other_inputs: Vec::new(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| bsv_rs::primitives::bsv::sighash::TxOutput {
                satoshis: o.satoshis,
                script: o.script.clone(),
            })
            .collect(),
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(unlock).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
        work_limit: None,
    });
    node.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    node.validate().map_err(|e| format!("{e:?}"))
}

/// A PushDrop token locked to `key`, as the identity paths lock theirs.
fn token(key: PublicKey) -> LockingScript {
    PushDrop::new(key, vec![b"token".to_vec()]).lock()
}

fn contact(identity_key: &str) -> Contact {
    Contact {
        identity_key: identity_key.to_string(),
        name: "Alice".to_string(),
        avatar_url: None,
        added_at: 1_700_000_000_000,
        notes: None,
        tags: Vec::new(),
        metadata: None,
    }
}

fn assert_every_spend_verifies(wallet: &TokenWallet, lock: &LockingScript, expected: usize) {
    let signed = wallet.signed();
    assert_eq!(signed.len(), expected, "the path signed no token input");
    for (spend, unlock) in signed {
        // the unlocking script is the signature push alone, scope ALL|FORKID
        assert_eq!(unlock[0] as usize, unlock.len() - 1);
        assert_eq!(*unlock.last().unwrap(), 0x41);
        assert_eq!(node_verdict(&spend, lock, &unlock), Ok(true));
    }
}

#[tokio::test]
async fn an_identity_revocation_signature_verifies_under_the_node_word() {
    let wallet = TokenWallet::of_scalar(9);
    let config = IdentityClientConfig::default();
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("vectors/identity_wallet_calls_318.json")).unwrap();
    let serial = vector["certificate"]["serialNumber"].as_str().unwrap();
    let beef = bsv_rs::primitives::from_hex(vector["revocation"]["lookup_beef"].as_str().unwrap())
        .unwrap();
    let lock = Transaction::from_beef(&beef, None).unwrap().outputs[0]
        .locking_script
        .clone();
    let source = source_transaction(&lock);
    wallet.set_source(source.clone());

    let mut host_overrides = HashMap::new();
    host_overrides.insert(
        "ls_identity".to_string(),
        vec!["http://token-lookup.invalid".to_string()],
    );
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        facilitator: Some(Arc::new(TokenLookup {
            beef: source.to_beef(true).unwrap(),
        }) as Arc<dyn OverlayLookupFacilitator>),
        slap_trackers: Some(vec![]),
        host_overrides: Some(host_overrides),
        ..Default::default()
    }));
    let client = IdentityClient::with_resolver(wallet.clone(), config, resolver);

    // the mock's signAction returns no transaction, so the call stops there,
    // before the broadcast, with the unlocking script recorded
    let stopped = client.revoke_certificate_revelation(serial).await;
    assert_eq!(
        stopped,
        Err(Error::IdentityError(
            "Failed to sign transaction".to_string()
        ))
    );
    assert_every_spend_verifies(&wallet, &lock, 1);
}

#[tokio::test]
async fn a_contact_update_signature_verifies_under_the_node_word() {
    let wallet = TokenWallet::new();
    let protocol = Protocol::new(SecurityLevel::App, "contact");
    let lock = token(
        wallet
            .derived_key(protocol, CONTACT_KEY_ID, Counterparty::Self_)
            .await,
    );
    wallet.set_source(source_transaction(&lock));
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());

    manager
        .add_contact(contact(&"02".repeat(33)))
        .await
        .unwrap();
    assert_every_spend_verifies(&wallet, &lock, 1);
}

#[tokio::test]
async fn a_contact_removal_signature_verifies_under_the_node_word() {
    let wallet = TokenWallet::new();
    let protocol = Protocol::new(SecurityLevel::App, "contact");
    let lock = token(
        wallet
            .derived_key(protocol, CONTACT_KEY_ID, Counterparty::Self_)
            .await,
    );
    wallet.set_source(source_transaction(&lock));
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let identity_key = "03".repeat(33);
    // the contact enters the cache through an update of the listed token
    manager.add_contact(contact(&identity_key)).await.unwrap();

    manager.remove_contact(&identity_key).await.unwrap();
    assert_every_spend_verifies(&wallet, &lock, 2);
}

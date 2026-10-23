use super::wallet_json::FixtureJson;
use bsv_rs::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireTransceiver};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

pub const CALL_COUNT: u8 = 28;
pub const ORIGINATOR: &str = "fixtures.invalid";

pub fn calls() -> impl Iterator<Item = WalletCall> {
    (1..=CALL_COUNT).map(|code| WalletCall::try_from(code).unwrap())
}

#[derive(Clone)]
pub struct Stub {
    pub reply: Value,
    pub error: Option<Error>,
    pub observed: Arc<Mutex<Option<Value>>>,
}

impl Stub {
    pub fn new(reply: Value) -> Self {
        Self {
            reply,
            error: None,
            observed: Arc::default(),
        }
    }

    fn answer<T: FixtureJson>(
        &self,
        method: &str,
        args: Value,
        originator: &str,
    ) -> bsv_rs::Result<T> {
        *self.observed.lock().unwrap() =
            Some(json!({"method": method, "args": args, "originator": originator}));
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(T::from_fixture(self.reply.clone())),
        }
    }
}

pub struct WireWallet<T: WalletWire>(pub WalletWireTransceiver<T>);

macro_rules! methods {
    ($m:ident) => { $m! {
        (CreateAction, create_action, CreateActionArgs, CreateActionResult),
        (SignAction, sign_action, SignActionArgs, SignActionResult),
        (AbortAction, abort_action, AbortActionArgs, AbortActionResult),
        (ListActions, list_actions, ListActionsArgs, ListActionsResult),
        (InternalizeAction, internalize_action, InternalizeActionArgs, InternalizeActionResult),
        (ListOutputs, list_outputs, ListOutputsArgs, ListOutputsResult),
        (RelinquishOutput, relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
        (GetPublicKey, get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
        (Encrypt, encrypt, EncryptArgs, EncryptResult),
        (Decrypt, decrypt, DecryptArgs, DecryptResult),
        (CreateHmac, create_hmac, CreateHmacArgs, CreateHmacResult),
        (VerifyHmac, verify_hmac, VerifyHmacArgs, VerifyHmacResult),
        (CreateSignature, create_signature, CreateSignatureArgs, CreateSignatureResult),
        (VerifySignature, verify_signature, VerifySignatureArgs, VerifySignatureResult),
        (AcquireCertificate, acquire_certificate, AcquireCertificateArgs, WalletCertificate),
        (ListCertificates, list_certificates, ListCertificatesArgs, ListCertificatesResult),
        (ProveCertificate, prove_certificate, ProveCertificateArgs, ProveCertificateResult),
        (RelinquishCertificate, relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
        (DiscoverByIdentityKey, discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
        (DiscoverByAttributes, discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    }};
}

macro_rules! implementations {
    ($(($call:ident, $method:ident, $args:ty, $result:ty)),* $(,)?) => {
        pub async fn invoke(wallet: &dyn WalletInterface, call: WalletCall, input: Value) -> bsv_rs::Result<Value> {
            Ok(match call {
                $(WalletCall::$call => wallet.$method(<$args>::from_fixture(input), ORIGINATOR).await?.fixture(),)*
                WalletCall::IsAuthenticated => wallet.is_authenticated(ORIGINATOR).await?.fixture(),
                WalletCall::WaitForAuthentication => wallet.wait_for_authentication(ORIGINATOR).await?.fixture(),
                WalletCall::GetHeight => wallet.get_height(ORIGINATOR).await?.fixture(),
                WalletCall::GetNetwork => wallet.get_network(ORIGINATOR).await?.fixture(),
                WalletCall::GetVersion => wallet.get_version(ORIGINATOR).await?.fixture(),
                WalletCall::RevealCounterpartyKeyLinkage => wallet.reveal_counterparty_key_linkage(RevealCounterpartyKeyLinkageArgs::from_fixture(input), ORIGINATOR).await?.fixture(),
                WalletCall::RevealSpecificKeyLinkage => wallet.reveal_specific_key_linkage(RevealSpecificKeyLinkageArgs::from_fixture(input), ORIGINATOR).await?.fixture(),
                WalletCall::GetHeaderForHeight => wallet.get_header_for_height(GetHeaderArgs::from_fixture(input), ORIGINATOR).await?.fixture(),
            })
        }

        #[async_trait::async_trait]
        impl WalletInterface for Stub {
            $(async fn $method(&self, args: $args, originator: &str) -> bsv_rs::Result<$result> {
                self.answer(stringify!($method), args.fixture(), originator)
            })*
            async fn is_authenticated(&self, originator: &str) -> bsv_rs::Result<AuthenticatedResult> { self.answer("is_authenticated", json!({}), originator) }
            async fn wait_for_authentication(&self, originator: &str) -> bsv_rs::Result<AuthenticatedResult> { self.answer("wait_for_authentication", json!({}), originator) }
            async fn get_height(&self, originator: &str) -> bsv_rs::Result<GetHeightResult> { self.answer("get_height", json!({}), originator) }
            async fn get_network(&self, originator: &str) -> bsv_rs::Result<GetNetworkResult> { self.answer("get_network", json!({}), originator) }
            async fn get_version(&self, originator: &str) -> bsv_rs::Result<GetVersionResult> { self.answer("get_version", json!({}), originator) }
            async fn reveal_counterparty_key_linkage(&self, args: RevealCounterpartyKeyLinkageArgs, originator: &str) -> bsv_rs::Result<RevealCounterpartyKeyLinkageResult> { self.answer("reveal_counterparty_key_linkage", args.fixture(), originator) }
            async fn reveal_specific_key_linkage(&self, args: RevealSpecificKeyLinkageArgs, originator: &str) -> bsv_rs::Result<RevealSpecificKeyLinkageResult> { self.answer("reveal_specific_key_linkage", args.fixture(), originator) }
            async fn get_header_for_height(&self, args: GetHeaderArgs, originator: &str) -> bsv_rs::Result<GetHeaderResult> { self.answer("get_header_for_height", args.fixture(), originator) }
        }

        #[async_trait::async_trait]
        impl<T: WalletWire> WalletInterface for WireWallet<T> {
            $(async fn $method(&self, args: $args, originator: &str) -> bsv_rs::Result<$result> {
                self.0.$method(args, originator).await
            })*
            async fn is_authenticated(&self, originator: &str) -> bsv_rs::Result<AuthenticatedResult> {
                Ok(AuthenticatedResult { authenticated: self.0.is_authenticated(originator).await? })
            }
            async fn wait_for_authentication(&self, originator: &str) -> bsv_rs::Result<AuthenticatedResult> {
                Ok(AuthenticatedResult { authenticated: self.0.wait_for_authentication(originator).await? })
            }
            async fn get_height(&self, originator: &str) -> bsv_rs::Result<GetHeightResult> {
                Ok(GetHeightResult { height: self.0.get_height(originator).await?.try_into().unwrap() })
            }
            async fn get_network(&self, originator: &str) -> bsv_rs::Result<GetNetworkResult> {
                Ok(GetNetworkResult { network: self.0.get_network(originator).await? })
            }
            async fn get_version(&self, originator: &str) -> bsv_rs::Result<GetVersionResult> {
                Ok(GetVersionResult { version: self.0.get_version(originator).await? })
            }
            async fn get_header_for_height(&self, args: GetHeaderArgs, originator: &str) -> bsv_rs::Result<GetHeaderResult> {
                self.0.get_header(args, originator).await
            }
            async fn reveal_counterparty_key_linkage(&self, args: RevealCounterpartyKeyLinkageArgs, originator: &str) -> bsv_rs::Result<RevealCounterpartyKeyLinkageResult> {
                super::wire::counterparty(&self.0, args, originator).await
            }
            async fn reveal_specific_key_linkage(&self, args: RevealSpecificKeyLinkageArgs, originator: &str) -> bsv_rs::Result<RevealSpecificKeyLinkageResult> {
                super::wire::specific(&self.0, args, originator).await
            }
        }
    };
}
methods!(implementations);

pub fn outcome(result: bsv_rs::Result<Value>) -> Value {
    match result {
        Ok(value) => json!({"ok": value}),
        Err(error) => json!({"error": format!("{error:?}"), "display": error.to_string()}),
    }
}

//! `WalletInterface` takes `originator: Option<&str>`, the reference's
//! optional `originator?` on all 28 methods (#329; `ts-stack@edf6e03`
//! `packages/sdk/src/wallet/Wallet.interfaces.ts`), so an absent originator
//! and an empty one reach a wallet as two values: `validateOriginator`
//! accepts `undefined` and refuses `""` (`validationHelpers.ts:1003-1006`).
//! The binary wire writes `None` as the length-0 originator and reads length
//! 0 back as `None`; the HTTP JSON substrate sends no `Originator` header for
//! `None` with none configured; every client passes `None` when it has no
//! originator configured, `Some` when it has one, and `Some("")` through.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "wallet")]

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use std::sync::{Arc, Mutex};

/// Each call's name and the originator it received.
type Seen = Vec<(&'static str, Option<String>)>;

/// A ProtoWallet that records each call's name and the originator it
/// received, as given.
#[derive(Clone, Debug)]
struct Recording {
    inner: Arc<ProtoWallet>,
    seen: Arc<Mutex<Seen>>,
}

impl Recording {
    fn new() -> Self {
        let key = PrivateKey::from_bytes(&[7; 32]).unwrap();
        Self {
            inner: Arc::new(ProtoWallet::new(Some(key))),
            seen: Arc::default(),
        }
    }

    fn note(&self, name: &'static str, originator: Option<&str>) {
        let originator = originator.map(str::to_string);
        self.seen.lock().unwrap().push((name, originator));
    }

    /// The first call the wallet received and its originator.
    fn first(&self) -> (&'static str, Option<String>) {
        self.seen
            .lock()
            .unwrap()
            .first()
            .cloned()
            .expect("a wallet call")
    }
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! recording {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?; $(($bare:ident, $bare_result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Recording {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> bsv_rs::Result<$result> {
                self.note(stringify!($method), o);
                WalletInterface::$method(&*self.inner, args, o).await
            })*
            $(async fn $bare(&self, o: Option<&str>) -> bsv_rs::Result<$bare_result> {
                self.note(stringify!($bare), o);
                WalletInterface::$bare(&*self.inner, o).await
            })*
        }
    };
}

recording! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (encrypt, EncryptArgs, EncryptResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (reveal_counterparty_key_linkage, RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult),
    (create_action, CreateActionArgs, CreateActionResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (prove_certificate, ProveCertificateArgs, ProveCertificateResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult);
    (is_authenticated, AuthenticatedResult),
    (wait_for_authentication, AuthenticatedResult),
    (get_height, GetHeightResult),
    (get_network, GetNetworkResult),
    (get_version, GetVersionResult),
}

/// The transceiver over the processor in memory, every frame kept.
struct Loop {
    processor: WalletWireProcessor<Recording>,
    frames: Mutex<Vec<Vec<u8>>>,
}

#[async_trait::async_trait]
impl WalletWire for Loop {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.frames.lock().unwrap().push(message.to_vec());
        self.processor.process_message(message).await
    }
}

fn wire(wallet: &Recording) -> WalletWireTransceiver<Loop> {
    WalletWireTransceiver::new(Loop {
        processor: WalletWireProcessor::new(wallet.clone()),
        frames: Mutex::default(),
    })
}

fn identity_key_args() -> GetPublicKeyArgs {
    GetPublicKeyArgs {
        identity_key: true,
        ..Default::default()
    }
}

/// `None` is written as the length-0 originator, and the processor reads
/// length 0 back as `None`.
#[tokio::test]
async fn an_absent_originator_crosses_the_binary_wire_as_length_zero_and_back_as_none() {
    let wallet = Recording::new();
    let client = wire(&wallet);
    client
        .get_public_key(identity_key_args(), None)
        .await
        .unwrap();
    let frame = client.wire().frames.lock().unwrap()[0].clone();
    assert_eq!(frame[..2], [WalletCall::GetPublicKey.as_u8(), 0]);
    assert_eq!(wallet.first(), ("get_public_key", None));

    // A frame written by hand with length 0, read by the processor alone
    let processor = WalletWireProcessor::new(wallet.clone());
    let answer = processor
        .process_message(&[WalletCall::GetVersion.as_u8(), 0])
        .await
        .unwrap();
    assert_eq!(answer[0], 0, "a success frame");
    assert_eq!(wallet.seen.lock().unwrap()[1], ("get_version", None));
}

/// A named originator is written with its length and read back as given.
#[tokio::test]
async fn a_named_originator_round_trips_on_the_binary_wire() {
    let wallet = Recording::new();
    let client = wire(&wallet);
    client
        .get_public_key(identity_key_args(), Some("example.com"))
        .await
        .unwrap();
    let frame = client.wire().frames.lock().unwrap()[0].clone();
    assert_eq!(frame[1] as usize, "example.com".len());
    assert_eq!(&frame[2..2 + 11], b"example.com");
    assert_eq!(
        wallet.first(),
        ("get_public_key", Some("example.com".to_string()))
    );
}

/// The wire has one form for an absent and an empty originator, length 0,
/// as the reference's transceiver writes `''` (`WalletWireTransceiver.ts:92-100`):
/// `Some("")` is written as length 0 and read back as `None`.
#[tokio::test]
async fn an_empty_originator_is_written_as_length_zero_and_read_back_as_none() {
    let wallet = Recording::new();
    let client = wire(&wallet);
    client.get_version(Some("")).await.unwrap();
    let frame = client.wire().frames.lock().unwrap()[0].clone();
    assert_eq!(frame, [WalletCall::GetVersion.as_u8(), 0]);
    assert_eq!(wallet.first(), ("get_version", None));
}

/// In process, `Some("")` reaches the wallet as `Some("")`, never mapped to
/// `None`, so the wallet can give the reference's refusal.
#[tokio::test]
async fn an_empty_originator_reaches_an_in_process_wallet_as_given() {
    let wallet = Recording::new();
    let dyn_wallet: &dyn WalletInterface = &wallet;
    dyn_wallet.get_version(Some("")).await.unwrap();
    dyn_wallet.get_version(None).await.unwrap();
    let seen = wallet.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [("get_version", Some(String::new())), ("get_version", None)]
    );
}

#[cfg(feature = "http")]
mod http_json {
    use bsv_rs::wallet::substrates::HttpWalletJson;
    use bsv_rs::Error;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn originator_header(configured: Option<&str>, call: Option<&str>) -> Option<String> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/getVersion"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v-1.0.0"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let wallet = HttpWalletJson::new(configured.map(str::to_string), Some(server.uri()))
            .expect("the substrate is configured");
        wallet.get_version(call).await.unwrap();
        let requests = server.received_requests().await.unwrap();
        let header = requests[0].headers.get("Originator");
        header.map(|value| value.to_str().unwrap().to_string())
    }

    /// No originator configured and none given: the call is refused before
    /// a request, in the reference's words (#323), whatever the call gives.
    #[tokio::test]
    async fn the_json_substrate_refuses_a_call_with_no_originator_configured() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let wallet =
            HttpWalletJson::new(None, Some(server.uri())).expect("the substrate is configured");
        for call in [None, Some(""), Some("app.example.com")] {
            assert_eq!(
                wallet.get_version(call).await,
                Err(Error::WalletError(
                    "HTTPWalletJSON: originator is required when using the HTTP substrate in \
                     Node.js. Pass an originator (e.g. \"example.com\") to the constructor."
                        .to_string()
                ))
            );
        }
    }

    /// A configured originator is sent for a call that gives none.
    #[tokio::test]
    async fn the_json_substrate_sends_the_configured_originator_for_none() {
        assert_eq!(
            originator_header(Some("app.example.com"), None).await,
            Some("http://app.example.com".to_string())
        );
    }
}

#[cfg(feature = "identity")]
mod identity {
    use super::*;
    use bsv_rs::identity::{
        ContactsManager, ContactsManagerConfig, IdentityClient, IdentityClientConfig,
    };

    async fn identity_client(config: IdentityClientConfig) -> (&'static str, Option<String>) {
        let wallet = Recording::new();
        let client = IdentityClient::new(wallet.clone(), config);
        client.get_identity_key().await.unwrap();
        wallet.first()
    }

    /// The identity client passes `None` with none configured, the
    /// configured one otherwise, `""` included.
    #[tokio::test]
    async fn the_identity_client_passes_none_unless_an_originator_is_configured() {
        let default = identity_client(IdentityClientConfig::default()).await;
        assert_eq!(default, ("get_public_key", None));
        let named = identity_client(IdentityClientConfig::with_originator("app.example")).await;
        assert_eq!(named.1.as_deref(), Some("app.example"));
        let empty = identity_client(IdentityClientConfig::with_originator("")).await;
        assert_eq!(empty.1.as_deref(), Some(""));
    }

    async fn contacts(config: ContactsManagerConfig) -> Option<String> {
        let wallet = Recording::new();
        let manager = ContactsManager::new(wallet.clone(), config);
        let _ = manager.list_contacts_with_refresh(true).await;
        wallet.first().1
    }

    /// The contacts manager passes `None` with none configured.
    #[tokio::test]
    async fn the_contacts_manager_passes_none_unless_an_originator_is_configured() {
        assert_eq!(contacts(ContactsManagerConfig::default()).await, None);
        let named = contacts(ContactsManagerConfig::with_originator("app.example")).await;
        assert_eq!(named.as_deref(), Some("app.example"));
    }
}

#[cfg(feature = "kvstore")]
mod kvstore {
    use super::*;
    use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, LocalKVStore};
    use bsv_rs::overlay::{
        LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
        OverlayLookupFacilitator,
    };
    use std::collections::HashMap;

    async fn local(config: KVStoreConfig) -> Option<String> {
        let wallet = Recording::new();
        let store = LocalKVStore::new(wallet.clone(), config).unwrap();
        let _ = store.get("key", "default").await;
        wallet.first().1
    }

    /// The local kvstore passes `None` with none configured, where it passed
    /// `"kvstore"` until #329.
    #[tokio::test]
    async fn the_local_kvstore_passes_none_unless_an_originator_is_configured() {
        assert_eq!(local(KVStoreConfig::default()).await, None);
        let named = local(KVStoreConfig::default().with_originator("app.example")).await;
        assert_eq!(named.as_deref(), Some("app.example"));
    }

    /// A facilitator that cannot succeed, so the global store's lookup
    /// never reaches the network (tests are hermetic).
    struct Failing;

    #[async_trait::async_trait(?Send)]
    impl OverlayLookupFacilitator for Failing {
        async fn lookup(
            &self,
            url: &str,
            _question: &LookupQuestion,
            _timeout_ms: Option<u64>,
        ) -> bsv_rs::Result<LookupAnswer> {
            Err(Error::OverlayError(format!(
                "hermetic lookup failure for {url}"
            )))
        }
    }

    async fn global(config: KVStoreConfig) -> Option<String> {
        let wallet = Recording::new();
        let mut host_overrides = HashMap::new();
        host_overrides.insert(
            "ls_kvstore".to_string(),
            vec!["https://overlay.invalid".to_string()],
        );
        let resolver = LookupResolver::new(LookupResolverConfig {
            network_preset: NetworkPreset::Local,
            facilitator: Some(Arc::new(Failing)),
            slap_trackers: Some(Vec::new()),
            host_overrides: Some(host_overrides),
            ..Default::default()
        });
        let store =
            GlobalKVStore::with_resolver(wallet.clone(), config, NetworkPreset::Local, resolver);
        let _ = store.set("key", "value", None).await;
        wallet.first().1
    }

    /// The global kvstore passes `None` with none configured, where it passed
    /// `"kvstore"` until #329.
    #[tokio::test]
    async fn the_global_kvstore_passes_none_unless_an_originator_is_configured() {
        assert_eq!(global(KVStoreConfig::default()).await, None);
        let named = global(KVStoreConfig::default().with_originator("app.example")).await;
        assert_eq!(named.as_deref(), Some("app.example"));
    }
}

#[cfg(feature = "registry")]
mod registry {
    use super::*;
    use bsv_rs::registry::{DefinitionType, RegistryClient, RegistryClientConfig};

    async fn registry(config: RegistryClientConfig) -> Option<String> {
        let wallet = Recording::new();
        let client = RegistryClient::new(wallet.clone(), config);
        let _ = client
            .list_own_registry_entries(DefinitionType::Basket)
            .await;
        wallet.first().1
    }

    /// The registry client passes `None` with none configured, where it
    /// passed `"registry-client"` until #329.
    #[tokio::test]
    async fn the_registry_client_passes_none_unless_an_originator_is_configured() {
        assert_eq!(registry(RegistryClientConfig::new()).await, None);
        let named = registry(RegistryClientConfig::new().with_originator("app.example")).await;
        assert_eq!(named.as_deref(), Some("app.example"));
    }
}

#[cfg(feature = "auth")]
mod auth {
    use super::*;
    use bsv_rs::auth::{MockTransport, Peer, PeerOptions};

    async fn peer(originator: Option<&str>) -> Option<String> {
        let wallet = Recording::new();
        let peer = Peer::new(PeerOptions {
            wallet: wallet.clone(),
            transport: MockTransport::new(),
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: false,
            originator: originator.map(str::to_string),
        });
        peer.get_identity_key().await.unwrap();
        wallet.first().1
    }

    /// The peer passes `None` with none configured, as the reference's
    /// `#originator` (`Peer.ts:145-152`), where it passed `"unknown"` until
    /// #329.
    #[tokio::test]
    async fn the_peer_passes_none_unless_an_originator_is_configured() {
        assert_eq!(peer(None).await, None);
        assert_eq!(
            peer(Some("app.example")).await.as_deref(),
            Some("app.example")
        );
    }
}

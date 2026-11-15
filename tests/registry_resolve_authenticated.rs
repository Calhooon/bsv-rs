//! The registry resolves return a definition only when they can
//! authenticate it as its named operator's: `resolve_basket`,
//! `resolve_protocol` and `resolve_certificate` return no definition locked
//! by a key that is not its operator's, nor one its operator's own key locks
//! without the operator's signature; the lookup is still asked, and a lookup
//! that fails fails as before.
//!
//! The tokens are laid out as `to_pushdrop_fields` lays a definition out (the
//! operator's key the last field) and answered by a scripted facilitator for
//! a host that is never dialled (rule 4).

#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::registry::{
    BasketDefinitionData, BasketQuery, CertificateDefinitionData, CertificateQuery, DefinitionType,
    ProtocolDefinitionData, ProtocolQuery, RegistryClient, RegistryClientConfig,
};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{ProtoWallet, Protocol, SecurityLevel};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct Answering {
    outputs: Option<Vec<OutputListItem>>,
    asked: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        question: &LookupQuestion,
        _timeout: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.asked
            .lock()
            .unwrap()
            .push((question.service.clone(), question.query.clone()));
        match &self.outputs {
            Some(outputs) => Ok(LookupAnswer::OutputList {
                outputs: outputs.clone(),
            }),
            None => Err(bsv_rs::Error::OverlayError("no host answered".into())),
        }
    }
}

fn item(script: &LockingScript) -> OutputListItem {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script.clone()))
        .unwrap();
    let beef = tx.to_beef(true).unwrap();
    serde_json::from_value(json!({ "beef": beef, "outputIndex": 0 })).unwrap()
}

type Asked = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

/// A client whose one host (`https://<host>.invalid`, never dialled) answers
/// `outputs`, or fails. Each cell names its own host: a host's reputation is
/// process-wide, an empty answer counts against it, and a host in backoff is
/// not asked.
fn client(
    host: &str,
    definition_type: DefinitionType,
    outputs: Option<Vec<LockingScript>>,
) -> (RegistryClient<ProtoWallet>, Asked) {
    let asked = Asked::default();
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering {
            outputs: outputs.map(|scripts| scripts.iter().map(item).collect()),
            asked: asked.clone(),
        })),
        host_overrides: Some(HashMap::from([(
            definition_type.lookup_service().to_string(),
            vec![format!("https://{host}-{definition_type:?}.invalid")],
        )])),
        ..Default::default()
    });
    let client = RegistryClient::new(
        ProtoWallet::new(Some(PrivateKey::from_hex(&"77".repeat(32)).unwrap())),
        RegistryClientConfig::new().with_resolver(Arc::new(resolver)),
    );
    (client, asked)
}

fn key(byte: &str) -> PrivateKey {
    PrivateKey::from_hex(&byte.repeat(32)).unwrap()
}

/// The three definitions as `to_pushdrop_fields` lays them out, naming `operator`.
fn definitions(operator: &str) -> [(DefinitionType, Vec<Vec<u8>>); 3] {
    let basket = BasketDefinitionData::new("payments", "Payments")
        .with_icon_url("https://icon.example/i.png")
        .with_description("Payments basket")
        .with_documentation_url("https://docs.example/d");
    let protocol =
        ProtocolDefinitionData::new(Protocol::new(SecurityLevel::App, "payments"), "Payments")
            .with_icon_url("https://icon.example/i.png")
            .with_description("Payments protocol")
            .with_documentation_url("https://docs.example/d");
    let certificate = CertificateDefinitionData::new("dHlwZQ==", "Identity")
        .with_icon_url("https://icon.example/i.png")
        .with_description("An identity certificate")
        .with_documentation_url("https://docs.example/d");
    [
        (DefinitionType::Basket, basket.to_pushdrop_fields(operator)),
        (
            DefinitionType::Protocol,
            protocol.to_pushdrop_fields(operator).unwrap(),
        ),
        (
            DefinitionType::Certificate,
            certificate.to_pushdrop_fields(operator).unwrap(),
        ),
    ]
}

async fn resolved(
    client: &RegistryClient<ProtoWallet>,
    definition_type: DefinitionType,
) -> bsv_rs::Result<usize> {
    Ok(match definition_type {
        DefinitionType::Basket => client.resolve_basket(BasketQuery::new()).await?.len(),
        DefinitionType::Protocol => client.resolve_protocol(ProtocolQuery::new()).await?.len(),
        DefinitionType::Certificate => client
            .resolve_certificate(CertificateQuery::new())
            .await?
            .len(),
    })
}

#[tokio::test]
async fn a_definition_its_named_operator_did_not_sign_is_not_returned_by_each_resolve() {
    let operator = key("a5");
    let stranger = key("5a");
    for (definition_type, fields) in definitions(&operator.public_key().to_hex()) {
        // Locked by a stranger's key, naming the operator.
        let forged = PushDrop::new(stranger.public_key(), fields.clone()).lock();
        let (c, _) = client("forged", definition_type, Some(vec![forged]));
        assert_eq!(
            resolved(&c, definition_type).await.unwrap(),
            0,
            "{definition_type:?}"
        );
        // Locked by the operator's own key, with no operator's signature.
        let written = PushDrop::new(operator.public_key(), fields).lock();
        let (c, _) = client("written", definition_type, Some(vec![written]));
        assert_eq!(
            resolved(&c, definition_type).await.unwrap(),
            0,
            "{definition_type:?}"
        );
    }
}

#[tokio::test]
async fn the_lookup_is_asked_as_before_and_its_failure_is_the_callers() {
    let operator = key("a5").public_key().to_hex();
    let unsigned = |definition_type| {
        let fields = definitions(&operator)
            .into_iter()
            .find(|(t, _)| *t == definition_type)
            .unwrap()
            .1;
        vec![PushDrop::new(key("5a").public_key(), fields).lock()]
    };
    let (basket, asked) = client(
        "asked",
        DefinitionType::Basket,
        Some(unsigned(DefinitionType::Basket)),
    );
    let query = BasketQuery::new()
        .with_basket_id("payments")
        .with_registry_operators(vec![operator.clone()]);
    assert_eq!(basket.resolve_basket(query.clone()).await.unwrap().len(), 0);
    let (protocol, protocol_asked) = client(
        "asked",
        DefinitionType::Protocol,
        Some(unsigned(DefinitionType::Protocol)),
    );
    let protocol_query = ProtocolQuery::new().with_name("Payments");
    assert_eq!(
        protocol
            .resolve_protocol(protocol_query.clone())
            .await
            .unwrap()
            .len(),
        0
    );
    let (certificate, certificate_asked) = client(
        "asked",
        DefinitionType::Certificate,
        Some(unsigned(DefinitionType::Certificate)),
    );
    let certificate_query = CertificateQuery::new().with_name("Identity");
    assert_eq!(
        certificate
            .resolve_certificate(certificate_query.clone())
            .await
            .unwrap()
            .len(),
        0
    );
    let one = |service: &str, query: serde_json::Value| vec![(service.to_string(), query)];
    assert_eq!(
        *asked.lock().unwrap(),
        one("ls_basketmap", serde_json::to_value(&query).unwrap())
    );
    assert_eq!(
        *protocol_asked.lock().unwrap(),
        one(
            "ls_protomap",
            serde_json::to_value(&protocol_query).unwrap()
        )
    );
    assert_eq!(
        *certificate_asked.lock().unwrap(),
        one(
            "ls_certmap",
            serde_json::to_value(&certificate_query).unwrap()
        )
    );

    // A host that fails: none while the resolver keeps asking it, then its
    // backoff error, the caller's to read.
    for definition_type in [
        DefinitionType::Basket,
        DefinitionType::Protocol,
        DefinitionType::Certificate,
    ] {
        let (c, _) = client("down", definition_type, None);
        let mut answers = Vec::new();
        for _ in 0..10 {
            answers.push(resolved(&c, definition_type).await.ok());
        }
        assert!(answers.iter().all(|a| matches!(a, None | Some(0))));
        assert!(answers.contains(&None), "{definition_type:?}");
    }
}

// The 0.8 line alone: it reads no operator-signed definition token, so it
// returns none for one either.
#[tokio::test]
async fn an_operator_signed_definition_is_still_not_returned() {
    use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, KeyDeriver};
    let operator = key("a5");
    let wallet = ProtoWallet::new(Some(operator.clone()));
    for (definition_type, mut fields) in definitions(&operator.public_key().to_hex()) {
        let protocol = Protocol::new(
            SecurityLevel::App,
            match definition_type {
                DefinitionType::Basket => "basketmap",
                DefinitionType::Protocol => "protomap",
                DefinitionType::Certificate => "certmap",
            },
        );
        let signature = wallet
            .create_signature(CreateSignatureArgs {
                data: Some(fields.concat()),
                hash_to_directly_sign: None,
                protocol_id: protocol.clone(),
                key_id: "1".into(),
                counterparty: Some(Counterparty::Anyone),
            })
            .unwrap()
            .signature;
        let lock = KeyDeriver::new(Some(operator.clone()))
            .derive_public_key(&protocol, "1", &Counterparty::Anyone, true)
            .unwrap();
        fields.push(signature);
        let (c, _) = client(
            "signed",
            definition_type,
            Some(vec![PushDrop::new(lock, fields).lock()]),
        );
        assert_eq!(resolved(&c, definition_type).await.unwrap(), 0);
    }
}

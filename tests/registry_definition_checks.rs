//! The registry reader's checks on a resolved definition: each of the three
//! resolves returns a definition only when its fields pass the reference
//! client's definition checks and it answers the query that was asked.
//!
//! Every token here is written as this crate's writer writes one
//! (`PushDrop::lock_with_wallet` with the operator's wallet, protocol
//! `[1, basketmap|protomap|certmap]`, key ID `1`, counterparty `anyone`, for
//! self, signed, lock-before), and answered by a scripted facilitator for a
//! host that is never dialled (rule 4). The reference's verdicts are recorded
//! in `tests/vectors/registry_definition_checks.json` by
//! `tests/support/registry_definition_checks.mjs` (`ts-stack@edf6e03`).

#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::registry::{
    decode_and_verify_registry_token, BasketDefinitionData, BasketQuery, CertificateDefinitionData,
    CertificateFieldDescriptor, CertificateQuery, DefinitionType, ProtocolDefinitionData,
    ProtocolQuery, RegistryClient, RegistryClientConfig,
};
use bsv_rs::script::templates::{LockPosition, PushDrop};
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{Counterparty, ProtoWallet, Protocol, SecurityLevel};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Answering(Vec<OutputListItem>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self.0.clone(),
        })
    }
}

fn operator() -> PrivateKey {
    PrivateKey::from_hex(&format!("{:064x}", 9)).unwrap()
}

fn operator_hex() -> String {
    operator().public_key().to_hex()
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

fn client(
    definition_type: DefinitionType,
    scripts: &[LockingScript],
) -> RegistryClient<ProtoWallet> {
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(scripts.iter().map(item).collect()))),
        host_overrides: Some(HashMap::from([(
            definition_type.lookup_service().to_string(),
            vec!["https://h.invalid".to_string()],
        )])),
        ..Default::default()
    });
    RegistryClient::new(
        ProtoWallet::new(Some(PrivateKey::from_hex(&"77".repeat(32)).unwrap())),
        RegistryClientConfig::new().with_resolver(Arc::new(resolver)),
    )
}

fn protocol_of(definition_type: DefinitionType) -> Protocol {
    let name = match definition_type {
        DefinitionType::Basket => "basketmap",
        DefinitionType::Protocol => "protomap",
        DefinitionType::Certificate => "certmap",
    };
    Protocol::new(SecurityLevel::App, name)
}

/// The token the writer writes for these data fields (the operator's key
/// appended last), signed by `key`.
async fn written_by(
    key: &PrivateKey,
    definition_type: DefinitionType,
    data: &[&str],
) -> LockingScript {
    let mut fields: Vec<Vec<u8>> = data.iter().map(|f| f.as_bytes().to_vec()).collect();
    fields.push(key.public_key().to_hex().into_bytes());
    PushDrop::lock_with_wallet(
        &ProtoWallet::new(Some(key.clone())),
        None,
        fields,
        protocol_of(definition_type),
        "1",
        Counterparty::Anyone,
        true,
        true,
        LockPosition::Before,
    )
    .await
    .unwrap()
}

async fn written(definition_type: DefinitionType, data: &[&str]) -> LockingScript {
    written_by(&operator(), definition_type, data).await
}

/// The data fields each door returned (the operator's key last), or none.
async fn resolved(definition_type: DefinitionType, script: &LockingScript) -> Option<Vec<String>> {
    let scripts = std::slice::from_ref(script);
    let fields = match definition_type {
        DefinitionType::Basket => client(definition_type, scripts)
            .resolve_basket(BasketQuery::new())
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.to_pushdrop_fields(&d.registry_operator))
            .collect::<Vec<_>>(),
        DefinitionType::Protocol => client(definition_type, scripts)
            .resolve_protocol(ProtocolQuery::new())
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.to_pushdrop_fields(&d.registry_operator).unwrap())
            .collect(),
        DefinitionType::Certificate => client(definition_type, scripts)
            .resolve_certificate(CertificateQuery::new())
            .await
            .unwrap()
            .into_iter()
            .map(|d| {
                let mut f = d.to_pushdrop_fields(&d.registry_operator).unwrap();
                // The fields JSON is re-serialized from the parsed map; compare the rest.
                f[5] = b"-".to_vec();
                f
            })
            .collect(),
    };
    assert!(fields.len() <= 1);
    fields.into_iter().next().map(|f| {
        f.into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect()
    })
}

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/registry_definition_checks.json")).unwrap()
}

fn type_of(name: &str) -> DefinitionType {
    match name {
        "basket" => DefinitionType::Basket,
        "protocol" => DefinitionType::Protocol,
        _ => DefinitionType::Certificate,
    }
}

#[tokio::test]
async fn each_resolve_answers_each_recorded_definition_as_the_reference_client_does() {
    let recorded = vector();
    assert_eq!(recorded["operator"].as_str(), Some(operator_hex().as_str()));
    let cases = recorded["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 57, "the recorded census moved");
    let mut tally = HashMap::new();
    for case in cases {
        let definition_type = type_of(case["type"].as_str().unwrap());
        let data: Vec<&str> = case["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap())
            .collect();
        let script = written(definition_type, &data).await;
        let got = resolved(definition_type, &script).await;
        let want = case["returned"].as_bool().unwrap();
        assert_eq!(got.is_some(), want, "{} {}", case["type"], case["label"]);
        if let Some(fields) = got {
            // Returned as signed: no field is rewritten.
            let mut expected: Vec<String> = data.iter().map(|f| f.to_string()).collect();
            expected.push(operator_hex());
            if definition_type == DefinitionType::Certificate {
                expected[5] = "-".into();
            }
            assert_eq!(fields, expected, "{}", case["label"]);
        }
        *tally.entry(want).or_insert(0) += 1;
    }
    assert_eq!((tally[&true], tally[&false]), (20, 37));
}

#[tokio::test]
async fn a_definition_the_query_did_not_ask_for_is_skipped() {
    let operator = operator_hex();
    let other = PrivateKey::from_hex(&"5a".repeat(32))
        .unwrap()
        .public_key()
        .to_hex();
    let icon = "https://icon.example/i.png";
    let docs = "https://docs.example/d";

    let basket = written(
        DefinitionType::Basket,
        &["payments", "Payments", icon, "Payments basket", docs],
    )
    .await;
    let baskets = |query: BasketQuery| {
        let basket = basket.clone();
        async move {
            client(DefinitionType::Basket, &[basket])
                .resolve_basket(query)
                .await
                .unwrap()
                .len()
        }
    };
    let ops = |list: &[&String]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // Answers the query: returned.
    assert_eq!(
        baskets(
            BasketQuery::new()
                .with_basket_id("payments")
                .with_registry_operators(ops(&[&operator]))
        )
        .await,
        1
    );
    assert_eq!(
        baskets(
            BasketQuery::new()
                .with_name("pay")
                .with_registry_operators(ops(&[&other, &operator]))
        )
        .await,
        1
    );
    assert_eq!(
        baskets(
            BasketQuery::new()
                .with_name("PMTS")
                .with_registry_operators(ops(&[&operator]))
        )
        .await,
        1
    );
    assert_eq!(
        baskets(BasketQuery::new().with_registry_operators(ops(&[&operator.to_uppercase()]))).await,
        1
    );
    // The ID decides when the query names one, as the lookup service decides.
    assert_eq!(
        baskets(
            BasketQuery::new()
                .with_basket_id("payments")
                .with_name("zzz")
                .with_registry_operators(ops(&[&operator]))
        )
        .await,
        1
    );
    // Does not: skipped.
    assert_eq!(
        baskets(
            BasketQuery::new()
                .with_basket_id("receipts")
                .with_registry_operators(ops(&[&operator]))
        )
        .await,
        0
    );
    assert_eq!(
        baskets(
            BasketQuery::new()
                .with_basket_id("invoices")
                .with_registry_operators(ops(&[&operator]))
        )
        .await,
        0
    );
    assert_eq!(
        baskets(
            BasketQuery::new()
                .with_name("Invoices")
                .with_registry_operators(ops(&[&operator]))
        )
        .await,
        0
    );
    assert_eq!(
        baskets(
            BasketQuery::new()
                .with_basket_id("payments")
                .with_registry_operators(ops(&[&other]))
        )
        .await,
        0
    );
    assert_eq!(
        baskets(BasketQuery::new().with_registry_operators(ops(&[&other]))).await,
        0
    );

    let protocol = written(
        DefinitionType::Protocol,
        &[
            r#"[1,"payments"]"#,
            "Payments",
            icon,
            "Payments protocol",
            docs,
        ],
    )
    .await;
    let protocols = |query: ProtocolQuery| {
        let protocol = protocol.clone();
        async move {
            client(DefinitionType::Protocol, &[protocol])
                .resolve_protocol(query)
                .await
                .unwrap()
                .len()
        }
    };
    let id = |level, name: &str| Protocol::new(level, name);
    let mut q = ProtocolQuery::new().with_registry_operators(ops(&[&operator]));
    q.protocol_id = Some(id(SecurityLevel::App, "payments"));
    assert_eq!(protocols(q.clone()).await, 1);
    assert_eq!(
        protocols(
            ProtocolQuery::new()
                .with_name("Payments")
                .with_registry_operators(ops(&[&operator]))
        )
        .await,
        1
    );
    // The name decides when the query names one (exactly, as the service matches it).
    assert_eq!(protocols(q.clone().with_name("Payments")).await, 1);
    assert_eq!(protocols(q.clone().with_name("Pay")).await, 0);
    q.protocol_id = Some(id(SecurityLevel::Counterparty, "payments"));
    assert_eq!(protocols(q.clone()).await, 0);
    q.protocol_id = Some(id(SecurityLevel::App, "invoices"));
    assert_eq!(protocols(q).await, 0);
    assert_eq!(
        protocols(
            ProtocolQuery::new()
                .with_name("Payments")
                .with_registry_operators(ops(&[&other]))
        )
        .await,
        0
    );

    let fields = r#"{"name":{"friendlyName":"Name","description":"The holder name","type":"text","fieldIcon":""}}"#;
    let certificate = written(
        DefinitionType::Certificate,
        &[
            "dHlwZQ==",
            "Identity",
            icon,
            "An identity certificate",
            docs,
            fields,
        ],
    )
    .await;
    let certificates = |query: CertificateQuery| {
        let certificate = certificate.clone();
        async move {
            client(DefinitionType::Certificate, &[certificate])
                .resolve_certificate(query)
                .await
                .unwrap()
                .len()
        }
    };
    let mut q = CertificateQuery::new().with_registry_operators(ops(&[&operator]));
    q.cert_type = Some("dHlwZQ==".into());
    assert_eq!(certificates(q.clone()).await, 1);
    assert_eq!(certificates(q.clone().with_name("zzz")).await, 1);
    let mut by_name = CertificateQuery::new().with_registry_operators(ops(&[&operator]));
    by_name.name = Some("ident".into());
    assert_eq!(certificates(by_name.clone()).await, 1);
    by_name.name = Some("Receipt".into());
    assert_eq!(certificates(by_name).await, 0);
    q.cert_type = Some("b3RoZXI=".into());
    assert_eq!(certificates(q).await, 0);
    let mut stranger = CertificateQuery::new().with_registry_operators(ops(&[&other]));
    stranger.cert_type = Some("dHlwZQ==".into());
    assert_eq!(certificates(stranger).await, 0);
}

#[tokio::test]
async fn a_well_formed_definition_this_crates_writer_writes_resolves_as_written() {
    let operator = operator_hex();
    let ops = vec![operator.clone()];
    let definitions = [
        (
            "payments",
            "Payments",
            "https://icon.example/i.png",
            "Payments basket",
            "https://docs.example/d",
        ),
        (
            "todo-items",
            "Tâches à faire 📝",
            "http://icon.example/t.png",
            "A list\nof things",
            "https://docs.example/t?x=1",
        ),
        ("b", "B", "//icon.example/b.png", "d", "docs/b.html"),
    ];
    for (id, name, icon, description, docs) in definitions {
        let data = BasketDefinitionData::new(id, name)
            .with_icon_url(icon)
            .with_description(description)
            .with_documentation_url(docs);
        let fields = data.to_pushdrop_fields(&operator);
        let text: Vec<&str> = fields[..5]
            .iter()
            .map(|f| std::str::from_utf8(f).unwrap())
            .collect();
        let script = written(DefinitionType::Basket, &text).await;
        for query in [
            BasketQuery::new(),
            BasketQuery::new()
                .with_basket_id(id)
                .with_registry_operators(ops.clone()),
            BasketQuery::new()
                .with_name(name)
                .with_registry_operators(ops.clone()),
        ] {
            let got = client(DefinitionType::Basket, std::slice::from_ref(&script))
                .resolve_basket(query)
                .await
                .unwrap();
            assert_eq!(got.len(), 1, "{id}");
            assert_eq!(got[0].to_pushdrop_fields(&operator), fields);
        }
    }
    let protocol = ProtocolDefinitionData::new(
        Protocol::new(SecurityLevel::Counterparty, "my protocol"),
        "Mine",
    )
    .with_icon_url("https://icon.example/p.png")
    .with_description("Mine")
    .with_documentation_url("https://docs.example/p");
    let fields = protocol.to_pushdrop_fields(&operator).unwrap();
    let text: Vec<&str> = fields[..5]
        .iter()
        .map(|f| std::str::from_utf8(f).unwrap())
        .collect();
    let script = written(DefinitionType::Protocol, &text).await;
    let mut q = ProtocolQuery::new().with_registry_operators(ops.clone());
    q.protocol_id = Some(protocol.protocol_id.clone());
    let got = client(DefinitionType::Protocol, std::slice::from_ref(&script))
        .resolve_protocol(q)
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].to_pushdrop_fields(&operator).unwrap(), fields);

    let certificate = CertificateDefinitionData::new("dHlwZQ==", "Identity")
        .with_icon_url("https://icon.example/c.png")
        .with_description("An identity certificate")
        .with_documentation_url("https://docs.example/c")
        .with_field(
            "name",
            CertificateFieldDescriptor::new("Name", "text")
                .with_description("The holder name")
                .with_icon("https://icon.example/f.png"),
        );
    let fields = certificate.to_pushdrop_fields(&operator).unwrap();
    let text: Vec<&str> = fields[..6]
        .iter()
        .map(|f| std::str::from_utf8(f).unwrap())
        .collect();
    let script = written(DefinitionType::Certificate, &text).await;
    let got = client(DefinitionType::Certificate, std::slice::from_ref(&script))
        .resolve_certificate(CertificateQuery::new())
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].fields.len(), 1);
    assert_eq!(got[0].name, "Identity");
}

#[tokio::test]
async fn a_hostile_definition_is_refused_quickly_and_without_a_panic() {
    let deep = format!("{}{}", "[".repeat(16_000), "]".repeat(16_000));
    let wide = format!("https://h.example/{}", "@:.".repeat(5_000));
    let cases: Vec<(DefinitionType, Vec<String>)> = vec![
        (
            DefinitionType::Protocol,
            vec![deep.clone(), "N".into(), "x".into(), "x".into(), "x".into()],
        ),
        (
            DefinitionType::Certificate,
            vec![
                "t".into(),
                "N".into(),
                "x".into(),
                "x".into(),
                "x".into(),
                deep,
            ],
        ),
        (
            DefinitionType::Basket,
            vec!["b".into(), "N".into(), wide.clone(), "x".into(), wide],
        ),
        (
            DefinitionType::Basket,
            vec![
                "b".into(),
                "é".repeat(8_000),
                "x".into(),
                "x".into(),
                "x".into(),
            ],
        ),
    ];
    for (definition_type, data) in cases {
        let data: Vec<&str> = data.iter().map(String::as_str).collect();
        let script = written(definition_type, &data).await;
        let started = Instant::now();
        assert_eq!(resolved(definition_type, &script).await, None);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}

#[tokio::test]
async fn the_token_decoder_keeps_the_reference_functions_verdict() {
    // The decoder reads the token; the definition checks are the client's.
    let script = written(
        DefinitionType::Basket,
        &[
            "payments",
            "Payments",
            "ftp://icon.example/i.png",
            "d",
            "https://docs.example/d",
        ],
    )
    .await;
    let fields = decode_and_verify_registry_token(DefinitionType::Basket, &script).unwrap();
    assert_eq!(fields[2], "ftp://icon.example/i.png");
    assert_eq!(resolved(DefinitionType::Basket, &script).await, None);
}

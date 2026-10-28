//! Named HTTP substrates and discovery; the client core needs none of these.

use super::{ConnectedSubstrate, SubstrateType};
use crate::wallet::substrates::{HttpWalletJson, HttpWalletWire, SECURE_JSON_URL};
use crate::wallet::wire::WalletWireTransceiver;
use crate::Error;

pub(super) type JsonApi = HttpWalletJson;

pub(super) async fn connect(
    substrate_type: SubstrateType,
    originator: Option<String>,
) -> Result<ConnectedSubstrate, Error> {
    match substrate_type {
        SubstrateType::Auto => auto_detect(originator).await,
        SubstrateType::JsonApi => Ok(ConnectedSubstrate::JsonApi(HttpWalletJson::new(
            originator, None,
        )?)),
        SubstrateType::Cicada => Ok(ConnectedSubstrate::WireApi(WalletWireTransceiver::new(
            HttpWalletWire::new(originator, None)?,
        ))),
        SubstrateType::SecureJsonApi => Ok(ConnectedSubstrate::JsonApi(HttpWalletJson::new(
            originator,
            Some(SECURE_JSON_URL.to_string()),
        )?)),
    }
}

/// Keep the existing probe order: secure JSON, JSON, then HTTP wire.
async fn auto_detect(originator: Option<String>) -> Result<ConnectedSubstrate, Error> {
    let secure = HttpWalletJson::new(originator.clone(), Some(SECURE_JSON_URL.to_string()))?;
    if let Ok(version) = secure.get_version(originator.as_deref()).await {
        if !version.is_empty() {
            return Ok(ConnectedSubstrate::JsonApi(secure));
        }
    }

    let json = HttpWalletJson::new(originator.clone(), None)?;
    if let Ok(version) = json.get_version(originator.as_deref()).await {
        if !version.is_empty() {
            return Ok(ConnectedSubstrate::JsonApi(json));
        }
    }

    let wire = WalletWireTransceiver::new(HttpWalletWire::new(originator.clone(), None)?);
    if let Ok(version) = wire.get_version(originator.as_deref()).await {
        if !version.is_empty() {
            return Ok(ConnectedSubstrate::WireApi(wire));
        }
    }

    Err(Error::WalletError(
        "no wallet available over any communication substrate".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::client::WalletClient;
    use crate::wallet::interface::{
        RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs,
    };
    use futures::lock::Mutex;
    use std::sync::OnceLock;

    #[tokio::test]
    async fn the_clients_wire_arms_send_both_linkage_calls_406() {
        use crate::wallet::{Counterparty, Protocol, SecurityLevel};
        use serde_json::Value;
        use wiremock::matchers::{body_bytes, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let vector: Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/wallet_wire/linkage_calls_406.json"
        ))
        .unwrap();
        let originator = vector["originator"].as_str().unwrap();
        for name in ["counterparty-minimal", "specific-key"] {
            let case = vector["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == name)
                .unwrap();
            let request = hex::decode(case["request_hex"].as_str().unwrap()).unwrap();
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(format!("/{}", case["call"].as_str().unwrap())))
                .and(header("Origin", originator))
                .and(body_bytes(request[2 + originator.len()..].to_vec()))
                .respond_with(
                    ResponseTemplate::new(200).set_body_bytes(
                        hex::decode(case["response_hex"].as_str().unwrap()).unwrap(),
                    ),
                )
                .expect(1)
                .mount(&server)
                .await;
            let wire = HttpWalletWire::new(Some(originator.into()), Some(server.uri())).unwrap();
            // Set the actual wire arm; no default URL or auto-detection is used.
            let client = WalletClient {
                substrate_type: SubstrateType::Cicada,
                originator: Some(originator.into()),
                connected: OnceLock::from(ConnectedSubstrate::WireApi(WalletWireTransceiver::new(
                    wire,
                ))),
                connecting: Mutex::new(()),
            };
            let key = |field: &str| {
                crate::primitives::PublicKey::from_bytes(
                    &hex::decode(case["args"][field].as_str().unwrap()).unwrap(),
                )
                .unwrap()
            };
            let result = if name == "counterparty-minimal" {
                serde_json::to_value(
                    client
                        .reveal_counterparty_key_linkage(RevealCounterpartyKeyLinkageArgs {
                            counterparty: key("counterparty"),
                            verifier: key("verifier"),
                            privileged: None,
                            privileged_reason: None,
                        })
                        .await
                        .unwrap(),
                )
            } else {
                serde_json::to_value(
                    client
                        .reveal_specific_key_linkage(RevealSpecificKeyLinkageArgs {
                            counterparty: Counterparty::Other(key("counterparty")),
                            verifier: key("verifier"),
                            protocol_id: Protocol::new(
                                SecurityLevel::Counterparty,
                                "fixture linkage",
                            ),
                            key_id: "key-1".into(),
                            privileged: None,
                            privileged_reason: None,
                        })
                        .await
                        .unwrap(),
                )
            }
            .unwrap();
            assert_eq!(result, case["result"], "{name}");
        }
    }
}

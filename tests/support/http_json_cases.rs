//! Shared HTTP result-vector replay; all listeners use wiremock's ephemeral port.
use super::wallet_json::FixtureJson;
use bsv_rs::{wallet::substrates::HttpWalletJson, Error};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Case {
    pub name: String,
    pub group: String,
    pub call: String,
    pub args: Value,
    pub args_text: Option<String>,
    pub body_text: String,
    pub expansion: Option<Expansion>,
    pub reference: Value,
    pub residue: Option<String>,
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    pub status: Option<u16>,
}

#[derive(Deserialize)]
pub struct Expansion {
    marker: String,
    length: usize,
    #[serde(default)]
    array: bool,
    item: Option<Value>,
}

impl Case {
    pub fn body(&self) -> String {
        match &self.expansion {
            Some(e) => {
                let expanded = if e.array {
                    serde_json::to_string(&vec![e.item.clone().unwrap(); e.length]).unwrap()
                } else {
                    "x".repeat(e.length)
                };
                self.body_text.replace(&e.marker, &expanded)
            }
            None => self.body_text.clone(),
        }
    }
}

pub fn cases() -> Vec<Case> {
    #[derive(Deserialize)]
    struct Vector {
        source: String,
        node: String,
        cases: Vec<Case>,
    }
    let vector: Vector =
        serde_json::from_str(include_str!("../vectors/http_json_result_values_408.json")).unwrap();
    assert_eq!(vector.source, "ts-stack@edf6e03");
    assert!(vector.node.starts_with("v22."));
    vector.cases
}

pub async fn invoke(wallet: &HttpWalletJson, c: &Case) -> Result<(), Error> {
    macro_rules! call {
        ($name:ident) => {
            wallet
                .$name(FixtureJson::from_fixture(c.args.clone()), None)
                .await
                .map(|_| ())
        };
    }
    match c.call.as_str() {
        "createAction" => call!(create_action),
        "signAction" => call!(sign_action),
        "abortAction" => call!(abort_action),
        "listActions" => call!(list_actions),
        "internalizeAction" => call!(internalize_action),
        "listOutputs" => call!(list_outputs),
        "relinquishOutput" => call!(relinquish_output),
        "acquireCertificate" => call!(acquire_certificate),
        "listCertificates" => call!(list_certificates),
        "proveCertificate" => call!(prove_certificate),
        "relinquishCertificate" => call!(relinquish_certificate),
        "discoverByIdentityKey" => call!(discover_by_identity_key),
        "discoverByAttributes" => {
            let args = c
                .args_text
                .as_ref()
                .map(|text| serde_json::from_str(text).unwrap())
                .unwrap_or_else(|| FixtureJson::from_fixture(c.args.clone()));
            wallet.discover_by_attributes(args, None).await.map(|_| ())
        }
        "getPublicKey" => call!(get_public_key),
        "encrypt" => call!(encrypt),
        "decrypt" => call!(decrypt),
        "createHmac" => call!(create_hmac),
        "verifyHmac" => call!(verify_hmac),
        "createSignature" => call!(create_signature),
        "verifySignature" => call!(verify_signature),
        "revealCounterpartyKeyLinkage" => call!(reveal_counterparty_key_linkage),
        "revealSpecificKeyLinkage" => call!(reveal_specific_key_linkage),
        "getHeaderForHeight" => call!(get_header),
        "getHeight" => {
            let a = wallet.get_height(None).await?;
            let b = bsv_rs::wallet::WalletInterface::get_height(wallet, None).await?;
            assert_eq!(a, u64::from(b.height));
            Ok(())
        }
        "getNetwork" => wallet.get_network(None).await.map(|_| ()),
        "getVersion" => wallet.get_version(None).await.map(|_| ()),
        "isAuthenticated" => wallet.is_authenticated(None).await.map(|_| ()),
        "waitForAuthentication" => wallet.wait_for_authentication(None).await.map(|_| ()),
        call => panic!("unknown call {call}"),
    }
}

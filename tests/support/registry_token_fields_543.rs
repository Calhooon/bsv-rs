//! The #543 vector (`tests/vectors/registry_token_fields_543.json`, written
//! by `tests/support/registry_token_fields_543.mjs`) and the definitions its
//! reference tokens were written from.
#![allow(dead_code)]

use bsv_rs::registry::{
    BasketDefinitionData, CertificateDefinitionData, CertificateFieldDescriptor, DefinitionData,
    DefinitionType, ProtocolDefinitionData,
};
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{Protocol, SecurityLevel};
use serde_json::Value;

pub fn vector() -> Value {
    serde_json::from_str(include_str!("../vectors/registry_token_fields_543.json")).unwrap()
}

pub fn cases(group: &str) -> Vec<Value> {
    vector()[group].as_array().unwrap().clone()
}

pub fn definition_type(case: &Value) -> DefinitionType {
    match case["definition_type"].as_str().unwrap() {
        "basket" => DefinitionType::Basket,
        "protocol" => DefinitionType::Protocol,
        _ => DefinitionType::Certificate,
    }
}

pub fn script(case: &Value) -> LockingScript {
    LockingScript::from_hex(case["script"].as_str().unwrap()).unwrap()
}

/// The data fields the reference wrote, as bytes.
pub fn fields(case: &Value) -> Vec<Vec<u8>> {
    case["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| bsv_rs::primitives::from_hex(field.as_str().unwrap()).unwrap())
        .collect()
}

/// The definition the reference's `registerDefinition` was given.
pub fn definition(case: &Value) -> DefinitionData {
    let d = &case["definition"];
    let text = |key: &str| d[key].as_str().unwrap().to_string();
    match definition_type(case) {
        DefinitionType::Basket => BasketDefinitionData::new(text("basketID"), text("name"))
            .with_icon_url(text("iconURL"))
            .with_description(text("description"))
            .with_documentation_url(text("documentationURL"))
            .into(),
        DefinitionType::Protocol => {
            assert_eq!(d["protocolID"][0], 1);
            let protocol = Protocol::new(SecurityLevel::App, d["protocolID"][1].as_str().unwrap());
            ProtocolDefinitionData::new(protocol, text("name"))
                .with_icon_url(text("iconURL"))
                .with_description(text("description"))
                .with_documentation_url(text("documentationURL"))
                .into()
        }
        DefinitionType::Certificate => {
            let mut data = CertificateDefinitionData::new(text("type"), text("name"))
                .with_icon_url(text("iconURL"))
                .with_description(text("description"))
                .with_documentation_url(text("documentationURL"));
            for (name, field) in d["fields"].as_object().unwrap() {
                let member = |key: &str| field[key].as_str().unwrap();
                data = data.with_field(
                    name.as_str(),
                    CertificateFieldDescriptor::new(member("friendlyName"), member("type"))
                        .with_description(member("description"))
                        .with_icon(member("fieldIcon")),
                );
            }
            data.into()
        }
    }
}

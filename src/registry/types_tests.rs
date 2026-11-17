//! `types.rs`'s unit tests, moved beside it for the file's line ceiling (#843d9); the module is still `tests`.
#![cfg(test)]

use super::*;

#[test]
fn test_definition_type_as_str() {
    assert_eq!(DefinitionType::Basket.as_str(), "basket");
    assert_eq!(DefinitionType::Protocol.as_str(), "protocol");
    assert_eq!(DefinitionType::Certificate.as_str(), "certificate");
}

#[test]
fn test_definition_type_try_from_str() {
    assert_eq!(
        DefinitionType::try_from_str("basket"),
        Some(DefinitionType::Basket)
    );
    assert_eq!(
        DefinitionType::try_from_str("PROTOCOL"),
        Some(DefinitionType::Protocol)
    );
    assert_eq!(
        DefinitionType::try_from_str("Certificate"),
        Some(DefinitionType::Certificate)
    );
    assert_eq!(DefinitionType::try_from_str("invalid"), None);
}

#[test]
fn test_definition_type_from_str() {
    assert_eq!(
        "basket".parse::<DefinitionType>().unwrap(),
        DefinitionType::Basket
    );
    assert_eq!(
        "PROTOCOL".parse::<DefinitionType>().unwrap(),
        DefinitionType::Protocol
    );
    assert!("invalid".parse::<DefinitionType>().is_err());
}

#[test]
fn test_definition_type_display() {
    assert_eq!(format!("{}", DefinitionType::Basket), "basket");
    assert_eq!(format!("{}", DefinitionType::Protocol), "protocol");
    assert_eq!(format!("{}", DefinitionType::Certificate), "certificate");
}

#[test]
fn test_definition_type_lookup_service() {
    assert_eq!(DefinitionType::Basket.lookup_service(), "ls_basketmap");
    assert_eq!(DefinitionType::Protocol.lookup_service(), "ls_protomap");
    assert_eq!(DefinitionType::Certificate.lookup_service(), "ls_certmap");
}

#[test]
fn test_definition_type_broadcast_topic() {
    assert_eq!(DefinitionType::Basket.broadcast_topic(), "tm_basketmap");
    assert_eq!(DefinitionType::Protocol.broadcast_topic(), "tm_protomap");
    assert_eq!(DefinitionType::Certificate.broadcast_topic(), "tm_certmap");
}

#[test]
fn test_definition_type_wallet_basket() {
    assert_eq!(DefinitionType::Basket.wallet_basket(), "basketmap");
    assert_eq!(DefinitionType::Protocol.wallet_basket(), "protomap");
    assert_eq!(DefinitionType::Certificate.wallet_basket(), "certmap");
}

#[test]
fn test_definition_type_wallet_protocol() {
    assert_eq!(DefinitionType::Basket.wallet_protocol(), (1, "basketmap"));
    assert_eq!(DefinitionType::Protocol.wallet_protocol(), (1, "protomap"));
    assert_eq!(
        DefinitionType::Certificate.wallet_protocol(),
        (1, "certmap")
    );
}

#[test]
fn test_definition_type_expected_field_count() {
    assert_eq!(DefinitionType::Basket.expected_field_count(), 7);
    assert_eq!(DefinitionType::Protocol.expected_field_count(), 7);
    assert_eq!(DefinitionType::Certificate.expected_field_count(), 8);
}

#[test]
fn test_token_data_new() {
    let token = TokenData::new("abc123".to_string(), 0, 1000, "76a914...88ac".to_string());
    assert_eq!(token.txid, "abc123");
    assert_eq!(token.output_index, 0);
    assert_eq!(token.satoshis, 1000);
    assert!(token.beef.is_none());
}

#[test]
fn test_token_data_with_beef() {
    let beef = vec![0xbe, 0xef];
    let token = TokenData::with_beef(
        "abc123".to_string(),
        1,
        500,
        "76a914...88ac".to_string(),
        beef,
    );
    assert_eq!(token.txid, "abc123");
    assert_eq!(token.output_index, 1);
    assert!(token.beef.is_some());
}

#[test]
fn test_token_data_outpoint() {
    let token = TokenData::new("abc123".to_string(), 2, 1000, "script".to_string());
    assert_eq!(token.outpoint(), "abc123.2");
}

#[test]
fn test_basket_definition_new() {
    let data = BasketDefinitionData::new("my_basket", "My Basket");
    assert_eq!(data.definition_type, DefinitionType::Basket);
    assert_eq!(data.basket_id, "my_basket");
    assert_eq!(data.name, "My Basket");
    assert_eq!(data.icon_url, "");
    assert_eq!(data.description, "");
    assert_eq!(data.documentation_url, "");
}

#[test]
fn test_basket_definition_builder() {
    let data = BasketDefinitionData::new("my_basket", "My Basket")
        .with_icon_url("https://example.com/icon.png")
        .with_description("A test basket")
        .with_documentation_url("https://example.com/docs");

    assert_eq!(data.icon_url, "https://example.com/icon.png");
    assert_eq!(data.description, "A test basket");
    assert_eq!(data.documentation_url, "https://example.com/docs");
}

#[test]
fn test_basket_definition_serialization() {
    let data = BasketDefinitionData::new("my_basket", "My Basket").with_description("Test");
    let json = serde_json::to_string(&data).unwrap();

    // Check correct JSON field names (not camelCase but specific capitalization)
    assert!(json.contains("\"basketID\":\"my_basket\""));
    assert!(json.contains("\"iconURL\":\"\""));
    assert!(json.contains("\"documentationURL\":\"\""));
    assert!(json.contains("\"definitionType\":\"basket\""));
}

#[test]
fn test_basket_definition_pushdrop_fields() {
    let data = BasketDefinitionData::new("my_basket", "My Basket")
        .with_icon_url("icon.png")
        .with_description("desc")
        .with_documentation_url("docs.html");

    let fields = data.to_pushdrop_fields("02abc123");
    assert_eq!(fields.len(), 6);
    assert_eq!(String::from_utf8(fields[0].clone()).unwrap(), "my_basket");
    assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "My Basket");
    assert_eq!(String::from_utf8(fields[2].clone()).unwrap(), "icon.png");
    assert_eq!(String::from_utf8(fields[3].clone()).unwrap(), "desc");
    assert_eq!(String::from_utf8(fields[4].clone()).unwrap(), "docs.html");
    assert_eq!(String::from_utf8(fields[5].clone()).unwrap(), "02abc123");
}

#[test]
fn test_basket_definition_from_pushdrop_fields() {
    let fields = vec![
        b"my_basket".to_vec(),
        b"My Basket".to_vec(),
        b"icon.png".to_vec(),
        b"desc".to_vec(),
        b"docs.html".to_vec(),
        b"02abc123".to_vec(),
    ];

    let data = BasketDefinitionData::from_pushdrop_fields(&fields).unwrap();
    assert_eq!(data.basket_id, "my_basket");
    assert_eq!(data.name, "My Basket");
    assert_eq!(data.icon_url, "icon.png");
    assert_eq!(data.description, "desc");
    assert_eq!(data.documentation_url, "docs.html");
    assert_eq!(data.registry_operator, "02abc123");
}

#[test]
fn test_protocol_definition_new() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
    let data = ProtocolDefinitionData::new(protocol, "My Protocol");
    assert_eq!(data.definition_type, DefinitionType::Protocol);
    assert_eq!(data.protocol_id.protocol_name, "my_protocol");
    assert_eq!(data.name, "My Protocol");
}

#[test]
fn test_protocol_definition_identifier() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
    let data = ProtocolDefinitionData::new(protocol, "My Protocol");
    assert_eq!(data.identifier(), "[1, \"my_protocol\"]");
}

#[test]
fn test_protocol_definition_serialization() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
    let data = ProtocolDefinitionData::new(protocol, "My Protocol");
    let json = serde_json::to_string(&data).unwrap();

    assert!(json.contains("\"protocolID\""));
    assert!(json.contains("\"iconURL\":\"\""));
    assert!(json.contains("\"documentationURL\":\"\""));
    assert!(json.contains("\"definitionType\":\"protocol\""));
}

#[test]
fn test_protocol_definition_pushdrop_fields() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
    let data = ProtocolDefinitionData::new(protocol, "My Protocol").with_description("desc");

    let fields = data.to_pushdrop_fields("02abc123").unwrap();
    assert_eq!(fields.len(), 6);
    // Field 0 should be JSON serialized protocol
    let protocol_json = String::from_utf8(fields[0].clone()).unwrap();
    assert!(protocol_json.contains("1")); // Security level
    assert!(protocol_json.contains("my_protocol"));
}

#[test]
fn test_deserialize_wallet_protocol() {
    let protocol = deserialize_wallet_protocol("[1,\"my_protocol\"]").unwrap();
    assert_eq!(protocol.security_level, SecurityLevel::App);
    assert_eq!(protocol.protocol_name, "my_protocol");

    let protocol2 = deserialize_wallet_protocol("[0, \"silent_protocol\"]").unwrap();
    assert_eq!(protocol2.security_level, SecurityLevel::Silent);
    assert_eq!(protocol2.protocol_name, "silent_protocol");

    let protocol3 = deserialize_wallet_protocol("[2, \"counterparty_protocol\"]").unwrap();
    assert_eq!(protocol3.security_level, SecurityLevel::Counterparty);
}

#[test]
fn test_deserialize_wallet_protocol_errors() {
    assert!(deserialize_wallet_protocol("invalid").is_err());
    assert!(deserialize_wallet_protocol("[1]").is_err());
    assert!(deserialize_wallet_protocol("[1, 2, 3]").is_err());
    assert!(deserialize_wallet_protocol("[3, \"proto\"]").is_err()); // Invalid security level
    assert!(deserialize_wallet_protocol("[1, 123]").is_err()); // Protocol not a string
}

#[test]
fn test_certificate_field_descriptor() {
    let field = CertificateFieldDescriptor::text("Email")
        .with_description("User email")
        .with_icon("email-icon");

    assert_eq!(field.friendly_name, "Email");
    assert_eq!(field.field_type, "text");
    assert_eq!(field.description, "User email");
    assert_eq!(field.field_icon, "email-icon");
}

#[test]
fn test_certificate_field_descriptor_image_url() {
    let field = CertificateFieldDescriptor::image_url("Avatar");
    assert_eq!(field.field_type, "imageURL");
}

#[test]
fn test_certificate_field_descriptor_serialization() {
    let field = CertificateFieldDescriptor::text("Email").with_description("desc");
    let json = serde_json::to_string(&field).unwrap();

    assert!(json.contains("\"friendlyName\":\"Email\""));
    assert!(json.contains("\"fieldIcon\":\"\""));
}

#[test]
fn test_certificate_definition_new() {
    let data = CertificateDefinitionData::new("cert_type_123", "My Certificate");
    assert_eq!(data.definition_type, DefinitionType::Certificate);
    assert_eq!(data.cert_type, "cert_type_123");
    assert_eq!(data.name, "My Certificate");
    assert!(data.fields.is_empty());
}

#[test]
fn test_certificate_definition_with_fields() {
    let data = CertificateDefinitionData::new("cert_type", "Cert")
        .with_field("email", CertificateFieldDescriptor::text("Email"))
        .with_field("avatar", CertificateFieldDescriptor::image_url("Avatar"));

    assert_eq!(data.fields.len(), 2);
    assert!(data.fields.contains_key("email"));
    assert!(data.fields.contains_key("avatar"));
}

#[test]
fn test_certificate_definition_pushdrop_fields() {
    let data = CertificateDefinitionData::new("cert_type", "My Cert")
        .with_description("desc")
        .with_field("email", CertificateFieldDescriptor::text("Email"));

    let fields = data.to_pushdrop_fields("02abc123").unwrap();
    assert_eq!(fields.len(), 7);
    assert_eq!(String::from_utf8(fields[0].clone()).unwrap(), "cert_type");
    assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "My Cert");
    // Field 5 should be JSON serialized fields map
    let fields_json = String::from_utf8(fields[5].clone()).unwrap();
    assert!(fields_json.contains("email"));
}

#[test]
fn test_definition_data_enum() {
    let basket = DefinitionData::Basket(BasketDefinitionData::new("b", "Basket"));
    assert_eq!(basket.get_definition_type(), DefinitionType::Basket);
    assert!(basket.as_basket().is_some());
    assert!(basket.as_protocol().is_none());

    let protocol = DefinitionData::Protocol(ProtocolDefinitionData::new(
        WalletProtocol::new(SecurityLevel::App, "p"),
        "Protocol",
    ));
    assert_eq!(protocol.get_definition_type(), DefinitionType::Protocol);
    assert!(protocol.as_protocol().is_some());
}

#[test]
fn test_definition_data_from() {
    let basket = BasketDefinitionData::new("b", "Basket");
    let data: DefinitionData = basket.into();
    assert_eq!(data.get_definition_type(), DefinitionType::Basket);
}

#[test]
fn test_registry_record() {
    let basket = BasketDefinitionData::new("b", "Basket");
    let token = TokenData::new("txid".to_string(), 0, 1, "script".to_string());
    let record = RegistryRecord::basket(basket, token);

    assert_eq!(record.get_definition_type(), DefinitionType::Basket);
    assert_eq!(record.txid(), "txid");
    assert_eq!(record.output_index(), 0);
    assert_eq!(record.outpoint(), "txid.0");
    assert!(record.as_basket().is_some());
}

#[test]
fn test_basket_query() {
    let query = BasketQuery::new()
        .with_basket_id("my_basket")
        .with_registry_operator("02abc...");

    assert_eq!(query.basket_id, Some("my_basket".to_string()));
    assert_eq!(query.registry_operators, Some(vec!["02abc...".to_string()]));
}

#[test]
fn test_basket_query_serialization() {
    let query = BasketQuery::new().with_basket_id("test");
    let json = serde_json::to_string(&query).unwrap();
    assert!(json.contains("\"basketID\":\"test\""));
}

#[test]
fn test_protocol_query() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "proto");
    let query = ProtocolQuery::new()
        .with_protocol_id(protocol)
        .with_name("Protocol");

    assert!(query.protocol_id.is_some());
    assert_eq!(query.name, Some("Protocol".to_string()));
}

#[test]
fn test_protocol_query_serialization() {
    let query = ProtocolQuery::new().with_name("test");
    let json = serde_json::to_string(&query).unwrap();
    assert!(json.contains("\"name\":\"test\""));
}

#[test]
fn test_certificate_query() {
    let query = CertificateQuery::new()
        .with_cert_type("cert_type")
        .with_registry_operators(vec!["op1".to_string(), "op2".to_string()]);

    assert_eq!(query.cert_type, Some("cert_type".to_string()));
    assert_eq!(
        query.registry_operators,
        Some(vec!["op1".to_string(), "op2".to_string()])
    );
}

#[test]
fn test_certificate_query_serialization() {
    let query = CertificateQuery::new().with_cert_type("test");
    let json = serde_json::to_string(&query).unwrap();
    assert!(json.contains("\"type\":\"test\""));
}

#[test]
fn test_register_definition_result() {
    let success_result = RegisterDefinitionResult {
        success: Some(BroadcastSuccess {
            txid: "abc123".to_string(),
            message: "success".to_string(),
        }),
        failure: None,
    };
    assert!(success_result.is_success());
    assert!(!success_result.is_failure());

    let failure_result = RegisterDefinitionResult {
        success: None,
        failure: Some(BroadcastFailure {
            code: "ERR".to_string(),
            description: "Failed".to_string(),
        }),
    };
    assert!(!failure_result.is_success());
    assert!(failure_result.is_failure());
}

#[test]
fn test_update_definition_result() {
    let success_result = UpdateDefinitionResult {
        success: Some(BroadcastSuccess {
            txid: "abc123".to_string(),
            message: "success".to_string(),
        }),
        failure: None,
    };
    assert!(success_result.is_success());
    assert!(!success_result.is_failure());

    let failure_result = UpdateDefinitionResult {
        success: None,
        failure: Some(BroadcastFailure {
            code: "ERR".to_string(),
            description: "Failed".to_string(),
        }),
    };
    assert!(!failure_result.is_success());
    assert!(failure_result.is_failure());
}

#[test]
fn test_revoke_definition_result() {
    let success_result = RevokeDefinitionResult {
        success: Some(BroadcastSuccess {
            txid: "abc123".to_string(),
            message: "success".to_string(),
        }),
        failure: None,
    };
    assert!(success_result.is_success());
    assert!(!success_result.is_failure());

    let failure_result = RevokeDefinitionResult {
        success: None,
        failure: Some(BroadcastFailure {
            code: "ERR".to_string(),
            description: "Failed".to_string(),
        }),
    };
    assert!(!failure_result.is_success());
    assert!(failure_result.is_failure());
}

/// `try_from_str` against the definition (#843d9): the list is held to the
/// definition by `VARIANT_NAMES`, which `non_exhaustive_enum!` writes from
/// it, and each listed type's text reads back as itself.
#[test]
fn every_definition_type_of_the_definition_reads_back_from_its_text_843d9() {
    let every = [
        DefinitionType::Basket,
        DefinitionType::Protocol,
        DefinitionType::Certificate,
    ];
    let names: Vec<String> = every.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(names, DefinitionType::VARIANT_NAMES);
    for definition_type in every {
        assert_eq!(
            DefinitionType::try_from_str(definition_type.as_str()),
            Some(definition_type)
        );
    }
}

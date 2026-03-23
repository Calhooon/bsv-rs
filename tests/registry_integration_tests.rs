//! Registry module integration tests.
//!
//! Tests full registry workflows including definition registration, resolution,
//! listing owned entries, revocation, and update operations.

#![cfg(feature = "registry")]

use bsv_rs::overlay::NetworkPreset;
use bsv_rs::registry::{
    BasketDefinitionData, BasketQuery, BroadcastFailure, BroadcastSuccess,
    CertificateDefinitionData, CertificateFieldDescriptor, CertificateQuery, DefinitionData,
    DefinitionType, ProtocolDefinitionData, ProtocolQuery, RegisterDefinitionResult,
    RegistryClientConfig, RegistryRecord, RevokeDefinitionResult, TokenData,
    UpdateDefinitionResult,
};
use bsv_rs::wallet::{Protocol as WalletProtocol, SecurityLevel};

// =================
// DefinitionType Tests
// =================

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
fn test_definition_type_expected_field_count() {
    // Rust/Go SDK field counts (data fields only, not including OP_DROP)
    assert_eq!(DefinitionType::Basket.expected_field_count(), 6);
    assert_eq!(DefinitionType::Protocol.expected_field_count(), 6);
    assert_eq!(DefinitionType::Certificate.expected_field_count(), 7);
}

// =================
// BasketDefinitionData Tests
// =================

#[test]
fn test_basket_definition_creation() {
    let basket = BasketDefinitionData::new("my_basket", "My Basket")
        .with_icon_url("https://example.com/icon.png")
        .with_description("A test basket for organizing outputs")
        .with_documentation_url("https://example.com/docs");

    assert_eq!(basket.definition_type, DefinitionType::Basket);
    assert_eq!(basket.basket_id, "my_basket");
    assert_eq!(basket.name, "My Basket");
    assert_eq!(basket.icon_url, "https://example.com/icon.png");
    assert_eq!(basket.description, "A test basket for organizing outputs");
    assert_eq!(basket.documentation_url, "https://example.com/docs");
    assert_eq!(basket.registry_operator, "");
}

#[test]
fn test_basket_definition_identifier() {
    let basket = BasketDefinitionData::new("test_id", "Test");
    assert_eq!(basket.identifier(), "test_id");
}

#[test]
fn test_basket_definition_pushdrop_fields() {
    let basket = BasketDefinitionData::new("my_basket", "My Basket")
        .with_icon_url("icon.png")
        .with_description("desc")
        .with_documentation_url("docs.html");

    let fields = basket.to_pushdrop_fields("02abc123def456");
    assert_eq!(fields.len(), 6);
    assert_eq!(String::from_utf8(fields[0].clone()).unwrap(), "my_basket");
    assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "My Basket");
    assert_eq!(String::from_utf8(fields[2].clone()).unwrap(), "icon.png");
    assert_eq!(String::from_utf8(fields[3].clone()).unwrap(), "desc");
    assert_eq!(String::from_utf8(fields[4].clone()).unwrap(), "docs.html");
    assert_eq!(
        String::from_utf8(fields[5].clone()).unwrap(),
        "02abc123def456"
    );
}

#[test]
fn test_basket_definition_from_pushdrop_fields() {
    let fields = vec![
        b"my_basket".to_vec(),
        b"My Basket".to_vec(),
        b"icon.png".to_vec(),
        b"A description".to_vec(),
        b"docs.html".to_vec(),
        b"02abc123".to_vec(),
    ];

    let basket = BasketDefinitionData::from_pushdrop_fields(&fields).unwrap();
    assert_eq!(basket.basket_id, "my_basket");
    assert_eq!(basket.name, "My Basket");
    assert_eq!(basket.icon_url, "icon.png");
    assert_eq!(basket.description, "A description");
    assert_eq!(basket.documentation_url, "docs.html");
    assert_eq!(basket.registry_operator, "02abc123");
}

#[test]
fn test_basket_definition_from_pushdrop_fields_wrong_count() {
    // Should fail with 5 fields instead of 6
    let fields = vec![
        b"id".to_vec(),
        b"name".to_vec(),
        b"icon".to_vec(),
        b"desc".to_vec(),
        b"docs".to_vec(),
    ];
    assert!(BasketDefinitionData::from_pushdrop_fields(&fields).is_err());
}

#[test]
fn test_basket_definition_json_serialization() {
    let basket = BasketDefinitionData::new("my_basket", "My Basket").with_description("Test");

    let json = serde_json::to_string(&basket).unwrap();

    // Verify correct JSON field names (Go SDK compatible)
    assert!(json.contains("\"basketID\":\"my_basket\""));
    assert!(json.contains("\"iconURL\":\"\""));
    assert!(json.contains("\"documentationURL\":\"\""));
    assert!(json.contains("\"definitionType\":\"basket\""));
}

// =================
// ProtocolDefinitionData Tests
// =================

#[test]
fn test_protocol_definition_creation() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
    let data = ProtocolDefinitionData::new(protocol, "My Protocol")
        .with_icon_url("https://example.com/icon.png")
        .with_description("A test protocol")
        .with_documentation_url("https://example.com/docs");

    assert_eq!(data.definition_type, DefinitionType::Protocol);
    assert_eq!(data.protocol_id.security_level, SecurityLevel::App);
    assert_eq!(data.protocol_id.protocol_name, "my_protocol");
    assert_eq!(data.name, "My Protocol");
    assert_eq!(data.icon_url, "https://example.com/icon.png");
    assert_eq!(data.description, "A test protocol");
}

#[test]
fn test_protocol_definition_identifier() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
    let data = ProtocolDefinitionData::new(protocol, "My Protocol");
    assert_eq!(data.identifier(), "[1, \"my_protocol\"]");
}

#[test]
fn test_protocol_definition_pushdrop_fields() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
    let data = ProtocolDefinitionData::new(protocol, "My Protocol").with_description("desc");

    let fields = data.to_pushdrop_fields("02abc123").unwrap();
    assert_eq!(fields.len(), 6);

    // First field should be JSON serialized protocol
    let protocol_json = String::from_utf8(fields[0].clone()).unwrap();
    assert!(protocol_json.contains("my_protocol"));

    assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "My Protocol");
    assert_eq!(String::from_utf8(fields[5].clone()).unwrap(), "02abc123");
}

#[test]
fn test_protocol_definition_all_security_levels() {
    let silent = WalletProtocol::new(SecurityLevel::Silent, "silent_proto");
    let app = WalletProtocol::new(SecurityLevel::App, "app_proto");
    let counterparty = WalletProtocol::new(SecurityLevel::Counterparty, "cp_proto");

    let data1 = ProtocolDefinitionData::new(silent, "Silent");
    let data2 = ProtocolDefinitionData::new(app, "App");
    let data3 = ProtocolDefinitionData::new(counterparty, "Counterparty");

    assert_eq!(data1.identifier(), "[0, \"silent_proto\"]");
    assert_eq!(data2.identifier(), "[1, \"app_proto\"]");
    assert_eq!(data3.identifier(), "[2, \"cp_proto\"]");
}

// =================
// CertificateDefinitionData Tests
// =================

#[test]
fn test_certificate_definition_creation() {
    let data = CertificateDefinitionData::new("cert_type_abc123", "My Certificate")
        .with_icon_url("https://example.com/icon.png")
        .with_description("A test certificate type")
        .with_documentation_url("https://example.com/docs")
        .with_field("email", CertificateFieldDescriptor::text("Email Address"))
        .with_field(
            "avatar",
            CertificateFieldDescriptor::image_url("Profile Picture"),
        );

    assert_eq!(data.definition_type, DefinitionType::Certificate);
    assert_eq!(data.cert_type, "cert_type_abc123");
    assert_eq!(data.name, "My Certificate");
    assert_eq!(data.fields.len(), 2);
    assert!(data.fields.contains_key("email"));
    assert!(data.fields.contains_key("avatar"));
}

#[test]
fn test_certificate_field_descriptor_types() {
    let text = CertificateFieldDescriptor::text("Name");
    assert_eq!(text.field_type, "text");
    assert_eq!(text.friendly_name, "Name");

    let image = CertificateFieldDescriptor::image_url("Photo");
    assert_eq!(image.field_type, "imageURL");
    assert_eq!(image.friendly_name, "Photo");

    let custom = CertificateFieldDescriptor::new("Custom", "other")
        .with_description("A custom field")
        .with_icon("custom-icon");
    assert_eq!(custom.field_type, "other");
    assert_eq!(custom.description, "A custom field");
    assert_eq!(custom.field_icon, "custom-icon");
}

#[test]
fn test_certificate_definition_pushdrop_fields() {
    let data = CertificateDefinitionData::new("cert_type", "My Cert")
        .with_description("desc")
        .with_field("email", CertificateFieldDescriptor::text("Email"));

    let fields = data.to_pushdrop_fields("02abc123").unwrap();
    assert_eq!(fields.len(), 7); // Certificate has 7 fields

    assert_eq!(String::from_utf8(fields[0].clone()).unwrap(), "cert_type");
    assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "My Cert");

    // Field 5 should be JSON serialized fields map
    let fields_json = String::from_utf8(fields[5].clone()).unwrap();
    assert!(fields_json.contains("email"));

    assert_eq!(String::from_utf8(fields[6].clone()).unwrap(), "02abc123");
}

// =================
// DefinitionData Enum Tests
// =================

#[test]
fn test_definition_data_from_basket() {
    let basket = BasketDefinitionData::new("b", "Basket");
    let data: DefinitionData = basket.into();

    assert_eq!(data.get_definition_type(), DefinitionType::Basket);
    assert!(data.as_basket().is_some());
    assert!(data.as_protocol().is_none());
    assert!(data.as_certificate().is_none());
}

#[test]
fn test_definition_data_from_protocol() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "p");
    let proto_data = ProtocolDefinitionData::new(protocol, "Protocol");
    let data: DefinitionData = proto_data.into();

    assert_eq!(data.get_definition_type(), DefinitionType::Protocol);
    assert!(data.as_basket().is_none());
    assert!(data.as_protocol().is_some());
    assert!(data.as_certificate().is_none());
}

#[test]
fn test_definition_data_from_certificate() {
    let cert_data = CertificateDefinitionData::new("type", "Cert");
    let data: DefinitionData = cert_data.into();

    assert_eq!(data.get_definition_type(), DefinitionType::Certificate);
    assert!(data.as_basket().is_none());
    assert!(data.as_protocol().is_none());
    assert!(data.as_certificate().is_some());
}

#[test]
fn test_definition_data_set_registry_operator() {
    let basket = BasketDefinitionData::new("b", "Basket");
    let mut data: DefinitionData = basket.into();

    assert_eq!(data.get_registry_operator(), "");
    data.set_registry_operator("02abc123".to_string());
    assert_eq!(data.get_registry_operator(), "02abc123");
}

#[test]
fn test_definition_data_identifier() {
    let basket: DefinitionData = BasketDefinitionData::new("basket_id", "Basket").into();
    assert_eq!(basket.identifier(), "basket_id");

    let protocol: DefinitionData =
        ProtocolDefinitionData::new(WalletProtocol::new(SecurityLevel::App, "proto"), "Protocol")
            .into();
    assert_eq!(protocol.identifier(), "[1, \"proto\"]");

    let cert: DefinitionData = CertificateDefinitionData::new("cert_type", "Cert").into();
    assert_eq!(cert.identifier(), "cert_type");
}

// =================
// TokenData Tests
// =================

#[test]
fn test_token_data_creation() {
    let token = TokenData::new(
        "abc123def456".to_string(),
        0,
        1000,
        "76a914...88ac".to_string(),
    );

    assert_eq!(token.txid, "abc123def456");
    assert_eq!(token.output_index, 0);
    assert_eq!(token.satoshis, 1000);
    assert_eq!(token.locking_script, "76a914...88ac");
    assert!(token.beef.is_none());
}

#[test]
fn test_token_data_with_beef() {
    let beef_data = vec![0xbe, 0xef, 0x01, 0x02];
    let token = TokenData::with_beef(
        "txid".to_string(),
        1,
        500,
        "script".to_string(),
        beef_data.clone(),
    );

    assert!(token.beef.is_some());
    assert_eq!(token.beef.unwrap(), beef_data);
}

#[test]
fn test_token_data_outpoint() {
    let token = TokenData::new("abc123".to_string(), 2, 1000, "script".to_string());
    assert_eq!(token.outpoint(), "abc123.2");
}

// =================
// RegistryRecord Tests
// =================

#[test]
fn test_registry_record_basket() {
    let basket = BasketDefinitionData::new("b", "Basket");
    let token = TokenData::new("txid123".to_string(), 0, 1, "script".to_string());
    let record = RegistryRecord::basket(basket, token);

    assert_eq!(record.get_definition_type(), DefinitionType::Basket);
    assert_eq!(record.txid(), "txid123");
    assert_eq!(record.output_index(), 0);
    assert_eq!(record.outpoint(), "txid123.0");
    assert!(record.as_basket().is_some());
}

#[test]
fn test_registry_record_protocol() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "proto");
    let proto_data = ProtocolDefinitionData::new(protocol, "Protocol");
    let token = TokenData::new("txid456".to_string(), 1, 1, "script".to_string());
    let record = RegistryRecord::protocol(proto_data, token);

    assert_eq!(record.get_definition_type(), DefinitionType::Protocol);
    assert!(record.as_protocol().is_some());
}

#[test]
fn test_registry_record_certificate() {
    let cert = CertificateDefinitionData::new("type", "Cert");
    let token = TokenData::new("txid789".to_string(), 2, 1, "script".to_string());
    let record = RegistryRecord::certificate(cert, token);

    assert_eq!(record.get_definition_type(), DefinitionType::Certificate);
    assert!(record.as_certificate().is_some());
}

// =================
// Query Types Tests
// =================

#[test]
fn test_basket_query_builder() {
    let query = BasketQuery::new()
        .with_basket_id("my_basket")
        .with_registry_operator("02abc123")
        .with_name("Basket Name");

    assert_eq!(query.basket_id, Some("my_basket".to_string()));
    assert_eq!(query.registry_operators, Some(vec!["02abc123".to_string()]));
    assert_eq!(query.name, Some("Basket Name".to_string()));
}

#[test]
fn test_basket_query_multiple_operators() {
    let query =
        BasketQuery::new().with_registry_operators(vec!["op1".to_string(), "op2".to_string()]);

    assert_eq!(
        query.registry_operators,
        Some(vec!["op1".to_string(), "op2".to_string()])
    );
}

#[test]
fn test_basket_query_json_serialization() {
    let query = BasketQuery::new().with_basket_id("test");
    let json = serde_json::to_string(&query).unwrap();
    assert!(json.contains("\"basketID\":\"test\""));
}

#[test]
fn test_protocol_query_builder() {
    let protocol = WalletProtocol::new(SecurityLevel::App, "my_proto");
    let query = ProtocolQuery::new()
        .with_protocol_id(protocol)
        .with_name("Protocol Name")
        .with_registry_operator("02abc123");

    assert!(query.protocol_id.is_some());
    assert_eq!(query.name, Some("Protocol Name".to_string()));
    assert_eq!(query.registry_operators, Some(vec!["02abc123".to_string()]));
}

#[test]
fn test_certificate_query_builder() {
    let query = CertificateQuery::new()
        .with_cert_type("cert_type_123")
        .with_name("Cert Name")
        .with_registry_operators(vec!["op1".to_string(), "op2".to_string()]);

    assert_eq!(query.cert_type, Some("cert_type_123".to_string()));
    assert_eq!(query.name, Some("Cert Name".to_string()));
    assert_eq!(
        query.registry_operators,
        Some(vec!["op1".to_string(), "op2".to_string()])
    );
}

#[test]
fn test_certificate_query_json_serialization() {
    let query = CertificateQuery::new().with_cert_type("test");
    let json = serde_json::to_string(&query).unwrap();
    assert!(json.contains("\"type\":\"test\""));
}

// =================
// Result Types Tests
// =================

#[test]
fn test_register_definition_result() {
    let success = RegisterDefinitionResult {
        success: Some(BroadcastSuccess {
            txid: "abc123".to_string(),
            message: "success".to_string(),
        }),
        failure: None,
    };
    assert!(success.is_success());
    assert!(!success.is_failure());

    let failure = RegisterDefinitionResult {
        success: None,
        failure: Some(BroadcastFailure {
            code: "ERR".to_string(),
            description: "Failed".to_string(),
        }),
    };
    assert!(!failure.is_success());
    assert!(failure.is_failure());
}

#[test]
fn test_revoke_definition_result() {
    let success = RevokeDefinitionResult {
        success: Some(BroadcastSuccess {
            txid: "abc123".to_string(),
            message: "revoked".to_string(),
        }),
        failure: None,
    };
    assert!(success.is_success());
    assert!(!success.is_failure());

    let failure = RevokeDefinitionResult {
        success: None,
        failure: Some(BroadcastFailure {
            code: "REVOKE_ERR".to_string(),
            description: "Revocation failed".to_string(),
        }),
    };
    assert!(!failure.is_success());
    assert!(failure.is_failure());
}

#[test]
fn test_update_definition_result() {
    let success = UpdateDefinitionResult {
        success: Some(BroadcastSuccess {
            txid: "abc123".to_string(),
            message: "updated".to_string(),
        }),
        failure: None,
    };
    assert!(success.is_success());
    assert!(!success.is_failure());

    let failure = UpdateDefinitionResult {
        success: None,
        failure: Some(BroadcastFailure {
            code: "UPDATE_ERR".to_string(),
            description: "Update failed".to_string(),
        }),
    };
    assert!(!failure.is_success());
    assert!(failure.is_failure());
}

// =================
// RegistryClientConfig Tests
// =================

#[test]
fn test_registry_client_config_defaults() {
    let config = RegistryClientConfig::default();
    assert_eq!(config.network_preset, NetworkPreset::Mainnet);
    assert!(config.resolver.is_none());
    assert!(config.originator.is_none());
    assert!(!config.accept_delayed_broadcast);
}

#[test]
fn test_registry_client_config_builder() {
    let config = RegistryClientConfig::new()
        .with_network(NetworkPreset::Testnet)
        .with_originator("myapp.example.com")
        .with_delayed_broadcast(true);

    assert_eq!(config.network_preset, NetworkPreset::Testnet);
    assert_eq!(config.originator, Some("myapp.example.com".to_string()));
    assert!(config.accept_delayed_broadcast);
}

#[test]
fn test_registry_client_config_local_network() {
    let config = RegistryClientConfig::new().with_network(NetworkPreset::Local);
    assert_eq!(config.network_preset, NetworkPreset::Local);
}

// =================
// Cross-SDK Compatibility Tests
// =================

#[test]
fn test_pushdrop_field_format_basket_matches_go_sdk() {
    // Verify the field format matches Go SDK exactly
    // Go SDK: basketID, name, iconURL, description, documentationURL, registryOperator
    let basket = BasketDefinitionData::new("test_basket", "Test Basket")
        .with_icon_url("https://example.com/icon.png")
        .with_description("A test basket")
        .with_documentation_url("https://example.com/docs");

    let operator = "02abc123def456789";
    let fields = basket.to_pushdrop_fields(operator);

    assert_eq!(fields.len(), 6, "Basket should have exactly 6 fields");
    assert_eq!(String::from_utf8(fields[0].clone()).unwrap(), "test_basket");
    assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "Test Basket");
    assert_eq!(
        String::from_utf8(fields[2].clone()).unwrap(),
        "https://example.com/icon.png"
    );
    assert_eq!(
        String::from_utf8(fields[3].clone()).unwrap(),
        "A test basket"
    );
    assert_eq!(
        String::from_utf8(fields[4].clone()).unwrap(),
        "https://example.com/docs"
    );
    assert_eq!(String::from_utf8(fields[5].clone()).unwrap(), operator);
}

#[test]
fn test_pushdrop_field_format_protocol_matches_go_sdk() {
    // Verify the field format matches Go SDK exactly
    // Go SDK: protocolID (JSON), name, iconURL, description, documentationURL, registryOperator
    let protocol = WalletProtocol::new(SecurityLevel::App, "test_protocol");
    let data = ProtocolDefinitionData::new(protocol, "Test Protocol")
        .with_icon_url("https://example.com/icon.png")
        .with_description("A test protocol")
        .with_documentation_url("https://example.com/docs");

    let operator = "02abc123def456789";
    let fields = data.to_pushdrop_fields(operator).unwrap();

    assert_eq!(fields.len(), 6, "Protocol should have exactly 6 fields");

    // First field is JSON serialized protocol
    let protocol_json = String::from_utf8(fields[0].clone()).unwrap();
    // Should contain the security level and protocol name
    assert!(
        protocol_json.contains("test_protocol"),
        "Protocol JSON should contain protocol name"
    );

    assert_eq!(
        String::from_utf8(fields[1].clone()).unwrap(),
        "Test Protocol"
    );
    assert_eq!(String::from_utf8(fields[5].clone()).unwrap(), operator);
}

#[test]
fn test_pushdrop_field_format_certificate_matches_go_sdk() {
    // Verify the field format matches Go SDK exactly
    // Go SDK: type, name, iconURL, description, documentationURL, fields (JSON), registryOperator
    let data = CertificateDefinitionData::new("test_cert_type", "Test Certificate")
        .with_icon_url("https://example.com/icon.png")
        .with_description("A test certificate")
        .with_documentation_url("https://example.com/docs")
        .with_field("email", CertificateFieldDescriptor::text("Email"));

    let operator = "02abc123def456789";
    let fields = data.to_pushdrop_fields(operator).unwrap();

    assert_eq!(fields.len(), 7, "Certificate should have exactly 7 fields");
    assert_eq!(
        String::from_utf8(fields[0].clone()).unwrap(),
        "test_cert_type"
    );
    assert_eq!(
        String::from_utf8(fields[1].clone()).unwrap(),
        "Test Certificate"
    );

    // Field 5 is JSON serialized fields map
    let fields_json = String::from_utf8(fields[5].clone()).unwrap();
    assert!(
        fields_json.contains("email"),
        "Fields JSON should contain email field"
    );

    assert_eq!(String::from_utf8(fields[6].clone()).unwrap(), operator);
}

#[test]
fn test_pushdrop_roundtrip_basket() {
    // Test that we can encode and decode basket data
    let original = BasketDefinitionData::new("roundtrip_basket", "Roundtrip Basket")
        .with_icon_url("icon.png")
        .with_description("Testing roundtrip")
        .with_documentation_url("docs.html");

    let operator = "02abc123";
    let fields = original.to_pushdrop_fields(operator);
    let decoded = BasketDefinitionData::from_pushdrop_fields(&fields).unwrap();

    assert_eq!(decoded.basket_id, original.basket_id);
    assert_eq!(decoded.name, original.name);
    assert_eq!(decoded.icon_url, original.icon_url);
    assert_eq!(decoded.description, original.description);
    assert_eq!(decoded.documentation_url, original.documentation_url);
    assert_eq!(decoded.registry_operator, operator);
}

#[test]
fn test_pushdrop_roundtrip_protocol() {
    let original = ProtocolDefinitionData::new(
        WalletProtocol::new(SecurityLevel::Counterparty, "roundtrip_proto"),
        "Roundtrip Protocol",
    )
    .with_icon_url("icon.png")
    .with_description("Testing roundtrip")
    .with_documentation_url("docs.html");

    let operator = "02abc123";
    let fields = original.to_pushdrop_fields(operator).unwrap();
    let decoded = ProtocolDefinitionData::from_pushdrop_fields(&fields).unwrap();

    assert_eq!(
        decoded.protocol_id.security_level,
        original.protocol_id.security_level
    );
    assert_eq!(
        decoded.protocol_id.protocol_name,
        original.protocol_id.protocol_name
    );
    assert_eq!(decoded.name, original.name);
    assert_eq!(decoded.registry_operator, operator);
}

#[test]
fn test_pushdrop_roundtrip_certificate() {
    let original = CertificateDefinitionData::new("cert_type", "Roundtrip Cert")
        .with_icon_url("icon.png")
        .with_description("Testing roundtrip")
        .with_documentation_url("docs.html")
        .with_field(
            "field1",
            CertificateFieldDescriptor::text("Field 1").with_description("First field"),
        );

    let operator = "02abc123";
    let fields = original.to_pushdrop_fields(operator).unwrap();
    let decoded = CertificateDefinitionData::from_pushdrop_fields(&fields).unwrap();

    assert_eq!(decoded.cert_type, original.cert_type);
    assert_eq!(decoded.name, original.name);
    assert_eq!(decoded.fields.len(), original.fields.len());
    assert!(decoded.fields.contains_key("field1"));
    assert_eq!(decoded.registry_operator, operator);
}

// =================
// Constants Tests
// =================

#[test]
fn test_registry_constants() {
    use bsv_rs::registry::{
        LS_BASKETMAP, LS_CERTMAP, LS_PROTOMAP, REGISTRANT_KEY_ID, REGISTRANT_TOKEN_AMOUNT,
        TM_BASKETMAP, TM_CERTMAP, TM_PROTOMAP,
    };

    assert_eq!(LS_BASKETMAP, "ls_basketmap");
    assert_eq!(LS_PROTOMAP, "ls_protomap");
    assert_eq!(LS_CERTMAP, "ls_certmap");

    assert_eq!(TM_BASKETMAP, "tm_basketmap");
    assert_eq!(TM_PROTOMAP, "tm_protomap");
    assert_eq!(TM_CERTMAP, "tm_certmap");

    assert_eq!(REGISTRANT_TOKEN_AMOUNT, 1);
    assert_eq!(REGISTRANT_KEY_ID, "1");
}

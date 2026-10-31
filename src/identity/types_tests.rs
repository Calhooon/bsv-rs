//! Unit tests of `types.rs`, separated from production (#552, the ratchet
//! holding `types.rs` at its size).
#![cfg(test)]

use super::*;

#[test]
fn test_known_certificate_type_names() {
    assert_eq!(KnownCertificateType::IdentiCert.name(), "IdentiCert");
    assert_eq!(KnownCertificateType::DiscordCert.name(), "DiscordCert");
    assert_eq!(KnownCertificateType::PhoneCert.name(), "PhoneCert");
    assert_eq!(KnownCertificateType::XCert.name(), "XCert");
    assert_eq!(KnownCertificateType::Registrant.name(), "Registrant");
    assert_eq!(KnownCertificateType::EmailCert.name(), "EmailCert");
    assert_eq!(KnownCertificateType::Anyone.name(), "Anyone");
    assert_eq!(KnownCertificateType::SelfCert.name(), "Self");
    assert_eq!(KnownCertificateType::CoolCert.name(), "CoolCert");
}

#[test]
fn test_known_certificate_type_ids() {
    // Verify IDs match TypeScript/Go SDKs
    assert_eq!(
        KnownCertificateType::IdentiCert.type_id(),
        "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="
    );
    assert_eq!(
        KnownCertificateType::XCert.type_id(),
        "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="
    );
    assert_eq!(
        KnownCertificateType::Anyone.type_id(),
        "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis="
    );
    assert_eq!(
        KnownCertificateType::SelfCert.type_id(),
        "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g="
    );
}

#[test]
fn test_known_certificate_type_from_id() {
    assert_eq!(
        KnownCertificateType::from_type_id("z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="),
        Some(KnownCertificateType::IdentiCert)
    );
    assert_eq!(
        KnownCertificateType::from_type_id("vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="),
        Some(KnownCertificateType::XCert)
    );
    assert_eq!(KnownCertificateType::from_type_id("unknown"), None);
}

#[test]
fn test_known_certificate_type_roundtrip() {
    for cert_type in KnownCertificateType::all() {
        let type_id = cert_type.type_id();
        let parsed = KnownCertificateType::from_type_id(type_id);
        assert_eq!(parsed, Some(*cert_type));
    }
}

#[test]
fn test_displayable_identity_from_key() {
    // 66 hex chars = 33 bytes compressed public key
    let identity = DisplayableIdentity::from_key(
        "02abc123def456789012345678901234567890123456789012345678901234abcd",
    );
    assert!(identity.abbreviated_key.contains("..."));
    assert_eq!(identity.identity_key.len(), 66);
    assert_eq!(identity.abbreviated_key, "02abc1...abcd");
}

#[test]
fn test_displayable_identity_from_short_key() {
    let identity = DisplayableIdentity::from_key("short");
    assert_eq!(identity.abbreviated_key, "short");
    assert_eq!(identity.identity_key, "short");
}

#[test]
fn test_displayable_identity_serialization() {
    let identity = DisplayableIdentity {
        name: "Alice".to_string(),
        avatar_url: "https://example.com/avatar.png".to_string(),
        identity_key: "02abc123".to_string(),
        abbreviated_key: "02ab...".to_string(),
        badge_icon_url: "https://example.com/badge.png".to_string(),
        badge_label: "Verified".to_string(),
        badge_click_url: "https://example.com/verify".to_string(),
    };

    let json = serde_json::to_string(&identity).unwrap();
    assert!(json.contains("\"name\":\"Alice\""));
    assert!(json.contains("\"avatarUrl\":")); // camelCase

    let decoded: DisplayableIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.name, "Alice");
    assert_eq!(decoded.identity_key, "02abc123");
}

#[test]
fn test_contact_serialization() {
    let contact = Contact::new("Bob", "02abc123")
        .with_avatar_url("https://example.com/avatar.png")
        .with_added_at(1700000000000)
        .with_notes("Friend")
        .with_tags(["work", "friend"]);

    let json = serde_json::to_string(&contact).unwrap();
    assert!(json.contains("\"name\":\"Bob\""));
    assert!(json.contains("\"identityKey\":\"02abc123\"")); // camelCase

    let decoded: Contact = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.name, "Bob");
    assert_eq!(decoded.tags.len(), 2);
}

#[test]
fn test_contact_without_optional_fields() {
    let contact = Contact::new("Charlie", "02abc123");

    let json = serde_json::to_string(&contact).unwrap();
    // Optional fields should not be serialized when None
    assert!(!json.contains("avatarUrl"));
    assert!(!json.contains("notes"));
    assert!(!json.contains("metadata"));
}

#[test]
fn test_identity_query_default() {
    let query = IdentityQuery::default();
    assert!(query.identity_key.is_none());
    assert!(query.attributes.is_none());
    assert!(query.certificate_type.is_none());
    assert!(query.certifier.is_none());
    assert!(query.limit.is_none());
}

#[test]
fn test_identity_query_by_identity_key() {
    let query = IdentityQuery::by_identity_key("02abc123");
    assert_eq!(query.identity_key, Some("02abc123".to_string()));
    assert!(query.attributes.is_none());
}

#[test]
fn test_identity_query_by_attributes() {
    let mut attrs = IndexMap::new();
    attrs.insert("email".to_string(), "test@example.com".to_string());

    let query = IdentityQuery::by_attributes(attrs);
    assert!(query.identity_key.is_none());
    assert!(query.attributes.is_some());
    assert_eq!(
        query.attributes.as_ref().unwrap().get("email"),
        Some(&"test@example.com".to_string())
    );
}

#[test]
fn test_identity_query_builder() {
    let query = IdentityQuery::by_attribute("email", "test@example.com")
        .with_limit(10)
        .with_offset(5)
        .with_certifier("02certifier");

    assert_eq!(query.limit, Some(10));
    assert_eq!(query.offset, Some(5));
    assert_eq!(query.certifier, Some("02certifier".to_string()));
}

#[test]
fn test_identity_query_serialization() {
    let query = IdentityQuery::by_attribute("email", "test@example.com").with_limit(10);

    let json = serde_json::to_string(&query).unwrap();
    assert!(json.contains("test@example.com"));
    assert!(json.contains("\"limit\":10"));

    let decoded: IdentityQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.limit, Some(10));
}

#[test]
fn test_identity_client_config_default() {
    let config = IdentityClientConfig::default();
    assert_eq!(config.network_preset, NetworkPreset::Mainnet);
    assert_eq!(config.protocol_id, (1, "identity".to_string()));
    assert_eq!(config.key_id, "1");
    assert_eq!(config.token_amount, 1);
    assert_eq!(config.output_index, 0);
    assert!(config.originator.is_none());
}

#[test]
fn test_identity_client_config_builder() {
    let config = IdentityClientConfig::with_originator("myapp.com")
        .with_network(NetworkPreset::Testnet)
        .with_token_amount(100);

    assert_eq!(config.originator, Some("myapp.com".to_string()));
    assert_eq!(config.network_preset, NetworkPreset::Testnet);
    assert_eq!(config.token_amount, 100);
}

#[test]
fn test_contacts_manager_config_default() {
    let config = ContactsManagerConfig::default();
    assert_eq!(config.protocol_id, (2, "contact".to_string()));
    assert_eq!(config.basket, "contacts");
    assert!(config.originator.is_none());
}

#[test]
fn test_certifier_info_default() {
    let info = CertifierInfo::default();
    assert_eq!(info.name, "Unknown Certifier");
    assert_eq!(info.trust, 0);
}

#[test]
fn test_contact_from_identity() {
    let identity = DisplayableIdentity::from_key("02abc123");
    let contact = Contact::from_identity(identity.clone());

    assert_eq!(contact.identity_key, identity.identity_key);
    assert_eq!(contact.name, identity.name);
    assert!(contact.added_at > 0);
}

#[test]
fn test_contact_to_displayable_identity() {
    let contact = Contact::new(
        "Test User",
        "02abc123def456789012345678901234567890123456789012345678901234567890",
    )
    .with_avatar_url("https://example.com/avatar.png")
    .with_added_at(1700000000000);

    let identity = contact.to_displayable_identity();
    assert_eq!(identity.name, "Test User");
    assert_eq!(identity.avatar_url, "https://example.com/avatar.png");
    assert!(identity.abbreviated_key.contains("..."));
}

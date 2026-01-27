//! Identity module integration tests.
//!
//! Tests for IdentityClient, ContactsManager, and identity types including
//! certificate type handling, identity resolution, and contact management.
//!
//! Note: IdentityClient requires `W: WalletInterface + Clone`, but ProtoWallet
//! does not implement Clone. The IdentityClient tests focus on configuration
//! and static methods that don't require a Clone wallet.

#![cfg(feature = "identity")]

use bsv_sdk::identity::{
    BroadcastFailure, BroadcastResult, BroadcastSuccess, CertifierInfo, Contact,
    ContactsManagerConfig, DefaultIdentityValues, DisplayableIdentity, IdentityClientConfig,
    IdentityQuery, KnownCertificateType, StaticAvatarUrls, DEFAULT_SOCIALCERT_CERTIFIER,
};
use bsv_sdk::overlay::NetworkPreset;
use std::collections::HashMap;

// =================
// KnownCertificateType Tests
// =================

#[test]
fn test_known_certificate_type_all_types() {
    let all = KnownCertificateType::all();
    assert_eq!(all.len(), 9);

    // Verify all expected types are present
    assert!(all.contains(&KnownCertificateType::IdentiCert));
    assert!(all.contains(&KnownCertificateType::DiscordCert));
    assert!(all.contains(&KnownCertificateType::PhoneCert));
    assert!(all.contains(&KnownCertificateType::XCert));
    assert!(all.contains(&KnownCertificateType::Registrant));
    assert!(all.contains(&KnownCertificateType::EmailCert));
    assert!(all.contains(&KnownCertificateType::Anyone));
    assert!(all.contains(&KnownCertificateType::SelfCert));
    assert!(all.contains(&KnownCertificateType::CoolCert));
}

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
fn test_known_certificate_type_ids_cross_sdk_compatible() {
    // These type IDs must match TypeScript and Go SDK implementations
    assert_eq!(
        KnownCertificateType::IdentiCert.type_id(),
        "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="
    );
    assert_eq!(
        KnownCertificateType::DiscordCert.type_id(),
        "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4="
    );
    assert_eq!(
        KnownCertificateType::PhoneCert.type_id(),
        "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A="
    );
    assert_eq!(
        KnownCertificateType::XCert.type_id(),
        "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="
    );
    assert_eq!(
        KnownCertificateType::Registrant.type_id(),
        "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0="
    );
    assert_eq!(
        KnownCertificateType::EmailCert.type_id(),
        "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA="
    );
    assert_eq!(
        KnownCertificateType::Anyone.type_id(),
        "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis="
    );
    assert_eq!(
        KnownCertificateType::SelfCert.type_id(),
        "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g="
    );
    assert_eq!(
        KnownCertificateType::CoolCert.type_id(),
        "AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo="
    );
}

#[test]
fn test_known_certificate_type_from_type_id() {
    // All known types should be recoverable from their type ID
    for cert_type in KnownCertificateType::all() {
        let type_id = cert_type.type_id();
        let recovered = KnownCertificateType::from_type_id(type_id);
        assert_eq!(recovered, Some(*cert_type), "Failed for {:?}", cert_type);
    }
}

#[test]
fn test_known_certificate_type_from_unknown_id() {
    assert_eq!(KnownCertificateType::from_type_id("unknown"), None);
    assert_eq!(KnownCertificateType::from_type_id(""), None);
    assert_eq!(KnownCertificateType::from_type_id("AAAA"), None);
    assert_eq!(
        KnownCertificateType::from_type_id("invalid-base64-!@#$"),
        None
    );
}

#[test]
fn test_known_certificate_type_equality() {
    assert_eq!(KnownCertificateType::XCert, KnownCertificateType::XCert);
    assert_ne!(KnownCertificateType::XCert, KnownCertificateType::EmailCert);
}

#[test]
fn test_known_certificate_type_copy() {
    let cert = KnownCertificateType::XCert;
    let copy = cert;
    assert_eq!(cert, copy); // cert still usable after copy
}

// =================
// DisplayableIdentity Tests
// =================

#[test]
fn test_displayable_identity_from_key_long() {
    // 66 hex chars = 33 bytes compressed public key
    let key = "02abc123def456789012345678901234567890123456789012345678901234abcd";
    let identity = DisplayableIdentity::from_key(key);

    assert_eq!(identity.identity_key, key);
    assert_eq!(identity.abbreviated_key, "02abc1...abcd");
    assert_eq!(identity.name, "02abc1...abcd"); // Name defaults to abbreviated key
    assert_eq!(identity.avatar_url, DefaultIdentityValues::AVATAR_URL);
    assert_eq!(
        identity.badge_icon_url,
        DefaultIdentityValues::BADGE_ICON_URL
    );
    assert_eq!(identity.badge_label, DefaultIdentityValues::BADGE_LABEL);
    assert_eq!(
        identity.badge_click_url,
        DefaultIdentityValues::BADGE_CLICK_URL
    );
}

#[test]
fn test_displayable_identity_from_key_short() {
    let key = "short";
    let identity = DisplayableIdentity::from_key(key);

    assert_eq!(identity.identity_key, "short");
    assert_eq!(identity.abbreviated_key, "short"); // No abbreviation for short keys
    assert_eq!(identity.name, "short");
}

#[test]
fn test_displayable_identity_from_key_exactly_ten_chars() {
    let key = "0123456789";
    let identity = DisplayableIdentity::from_key(key);

    // 10 chars is not > 10, so no abbreviation
    assert_eq!(identity.abbreviated_key, "0123456789");
}

#[test]
fn test_displayable_identity_from_key_eleven_chars() {
    let key = "01234567890";
    let identity = DisplayableIdentity::from_key(key);

    // 11 chars > 10, so should abbreviate
    assert_eq!(identity.abbreviated_key, "012345...7890");
}

#[test]
fn test_displayable_identity_unknown() {
    let identity = DisplayableIdentity::unknown();

    assert_eq!(identity.name, DefaultIdentityValues::NAME);
    assert_eq!(identity.avatar_url, DefaultIdentityValues::AVATAR_URL);
    assert!(identity.identity_key.is_empty());
    assert!(identity.abbreviated_key.is_empty());
    assert_eq!(identity.badge_label, DefaultIdentityValues::BADGE_LABEL);
}

#[test]
fn test_displayable_identity_default() {
    let identity = DisplayableIdentity::default();
    let unknown = DisplayableIdentity::unknown();

    // Default should equal unknown
    assert_eq!(identity.name, unknown.name);
    assert_eq!(identity.avatar_url, unknown.avatar_url);
    assert_eq!(identity.identity_key, unknown.identity_key);
}

#[test]
fn test_displayable_identity_json_serialization() {
    let identity = DisplayableIdentity {
        name: "Alice".to_string(),
        avatar_url: "https://example.com/avatar.png".to_string(),
        identity_key: "02abc123".to_string(),
        abbreviated_key: "02ab...".to_string(),
        badge_icon_url: "https://example.com/badge.png".to_string(),
        badge_label: "Verified User".to_string(),
        badge_click_url: "https://example.com/verify".to_string(),
    };

    let json = serde_json::to_string(&identity).unwrap();

    // Verify camelCase serialization for cross-SDK compatibility
    assert!(json.contains("\"name\":\"Alice\""));
    assert!(json.contains("\"avatarUrl\":"));
    assert!(json.contains("\"identityKey\":"));
    assert!(json.contains("\"abbreviatedKey\":"));
    assert!(json.contains("\"badgeIconUrl\":"));
    assert!(json.contains("\"badgeLabel\":"));
    assert!(json.contains("\"badgeClickUrl\":"));

    // Verify roundtrip
    let decoded: DisplayableIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, identity);
}

#[test]
fn test_displayable_identity_json_deserialization() {
    let json = r#"{
        "name": "Bob",
        "avatarUrl": "https://example.com/bob.png",
        "identityKey": "02def456",
        "abbreviatedKey": "02de...",
        "badgeIconUrl": "https://example.com/icon.png",
        "badgeLabel": "Certified",
        "badgeClickUrl": "https://example.com"
    }"#;

    let identity: DisplayableIdentity = serde_json::from_str(json).unwrap();
    assert_eq!(identity.name, "Bob");
    assert_eq!(identity.identity_key, "02def456");
    assert_eq!(identity.badge_label, "Certified");
}

// =================
// Contact Tests
// =================

#[test]
fn test_contact_creation() {
    let contact = Contact {
        identity_key: "02abc123".to_string(),
        name: "Alice".to_string(),
        avatar_url: Some("https://example.com/avatar.png".to_string()),
        added_at: 1700000000000,
        notes: Some("Met at conference".to_string()),
        tags: vec!["work".to_string(), "friend".to_string()],
        metadata: Some(serde_json::json!({"source": "import"})),
    };

    assert_eq!(contact.identity_key, "02abc123");
    assert_eq!(contact.name, "Alice");
    assert_eq!(contact.tags.len(), 2);
    assert!(contact.metadata.is_some());
}

#[test]
fn test_contact_default() {
    let contact = Contact::default();

    assert!(contact.identity_key.is_empty());
    assert!(contact.name.is_empty());
    assert!(contact.avatar_url.is_none());
    assert_eq!(contact.added_at, 0);
    assert!(contact.notes.is_none());
    assert!(contact.tags.is_empty());
    assert!(contact.metadata.is_none());
}

#[test]
fn test_contact_from_identity() {
    let identity = DisplayableIdentity::from_key(
        "02abc123def456789012345678901234567890123456789012345678901234abcd",
    );
    let contact = Contact::from_identity(identity.clone());

    assert_eq!(contact.identity_key, identity.identity_key);
    assert_eq!(contact.name, identity.name);
    assert!(contact.avatar_url.is_some());
    assert!(contact.added_at > 0); // Should have current timestamp
    assert!(contact.notes.is_none());
    assert!(contact.tags.is_empty());
}

#[test]
fn test_contact_to_displayable_identity() {
    let contact = Contact {
        identity_key: "02abc123def456789012345678901234567890123456789012345678901234567890"
            .to_string(),
        name: "Test User".to_string(),
        avatar_url: Some("https://example.com/avatar.png".to_string()),
        added_at: 1700000000000,
        notes: None,
        tags: Vec::new(),
        metadata: None,
    };

    let identity = contact.to_displayable_identity();

    assert_eq!(identity.name, "Test User");
    assert_eq!(identity.avatar_url, "https://example.com/avatar.png");
    assert_eq!(identity.identity_key, contact.identity_key);
    assert!(identity.abbreviated_key.contains("..."));
    assert_eq!(identity.badge_label, "Personal contact");
}

#[test]
fn test_contact_to_displayable_identity_no_avatar() {
    let contact = Contact {
        identity_key: "02abc123".to_string(),
        name: "No Avatar User".to_string(),
        avatar_url: None,
        added_at: 0,
        notes: None,
        tags: Vec::new(),
        metadata: None,
    };

    let identity = contact.to_displayable_identity();
    assert_eq!(identity.avatar_url, DefaultIdentityValues::AVATAR_URL);
}

#[test]
fn test_contact_json_serialization() {
    let contact = Contact {
        identity_key: "02abc123".to_string(),
        name: "Bob".to_string(),
        avatar_url: Some("https://example.com/avatar.png".to_string()),
        added_at: 1700000000000,
        notes: Some("Friend".to_string()),
        tags: vec!["work".to_string()],
        metadata: None,
    };

    let json = serde_json::to_string(&contact).unwrap();

    // Verify camelCase serialization
    assert!(json.contains("\"identityKey\":\"02abc123\""));
    assert!(json.contains("\"avatarUrl\":"));
    assert!(json.contains("\"addedAt\":"));

    // Verify roundtrip
    let decoded: Contact = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.name, "Bob");
    assert_eq!(decoded.tags.len(), 1);
}

#[test]
fn test_contact_json_without_optional_fields() {
    let contact = Contact {
        identity_key: "02abc123".to_string(),
        name: "Charlie".to_string(),
        avatar_url: None,
        added_at: 0,
        notes: None,
        tags: Vec::new(),
        metadata: None,
    };

    let json = serde_json::to_string(&contact).unwrap();

    // Optional None fields should not be serialized
    assert!(!json.contains("avatarUrl"));
    assert!(!json.contains("notes"));
    assert!(!json.contains("metadata"));
}

// =================
// IdentityQuery Tests
// =================

#[test]
fn test_identity_query_default() {
    let query = IdentityQuery::default();

    assert!(query.identity_key.is_none());
    assert!(query.attributes.is_none());
    assert!(query.certificate_type.is_none());
    assert!(query.certifier.is_none());
    assert!(query.limit.is_none());
    assert!(query.offset.is_none());
}

#[test]
fn test_identity_query_by_identity_key() {
    let query = IdentityQuery::by_identity_key("02abc123");

    assert_eq!(query.identity_key, Some("02abc123".to_string()));
    assert!(query.attributes.is_none());
}

#[test]
fn test_identity_query_by_identity_key_string() {
    let key = String::from("02abc123");
    let query = IdentityQuery::by_identity_key(key);

    assert_eq!(query.identity_key, Some("02abc123".to_string()));
}

#[test]
fn test_identity_query_by_attribute() {
    let query = IdentityQuery::by_attribute("email", "test@example.com");

    assert!(query.identity_key.is_none());
    assert!(query.attributes.is_some());

    let attrs = query.attributes.unwrap();
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs.get("email"), Some(&"test@example.com".to_string()));
}

#[test]
fn test_identity_query_by_attributes() {
    let mut attrs = HashMap::new();
    attrs.insert("email".to_string(), "test@example.com".to_string());
    attrs.insert("firstName".to_string(), "Alice".to_string());

    let query = IdentityQuery::by_attributes(attrs);

    let result_attrs = query.attributes.unwrap();
    assert_eq!(result_attrs.len(), 2);
    assert_eq!(
        result_attrs.get("email"),
        Some(&"test@example.com".to_string())
    );
    assert_eq!(result_attrs.get("firstName"), Some(&"Alice".to_string()));
}

#[test]
fn test_identity_query_builder_pattern() {
    let query = IdentityQuery::by_attribute("email", "test@example.com")
        .with_limit(10)
        .with_offset(5)
        .with_certifier("02certifier");

    assert_eq!(query.limit, Some(10));
    assert_eq!(query.offset, Some(5));
    assert_eq!(query.certifier, Some("02certifier".to_string()));
    assert!(query.attributes.is_some());
}

#[test]
fn test_identity_query_json_serialization() {
    let query = IdentityQuery::by_attribute("email", "test@example.com").with_limit(10);

    let json = serde_json::to_string(&query).unwrap();
    assert!(json.contains("\"limit\":10"));
    assert!(json.contains("test@example.com"));

    // Verify roundtrip
    let decoded: IdentityQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.limit, Some(10));
}

#[test]
fn test_identity_query_json_skips_none_fields() {
    let query = IdentityQuery::by_identity_key("02abc123");

    let json = serde_json::to_string(&query).unwrap();

    // None fields should not be serialized
    assert!(!json.contains("attributes"));
    assert!(!json.contains("certificateType"));
    assert!(!json.contains("certifier"));
    assert!(!json.contains("limit"));
    assert!(!json.contains("offset"));
}

// =================
// IdentityClientConfig Tests
// =================

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
fn test_identity_client_config_with_originator() {
    let config = IdentityClientConfig::with_originator("myapp.example.com");

    assert_eq!(config.originator, Some("myapp.example.com".to_string()));
    assert_eq!(config.network_preset, NetworkPreset::Mainnet);
    assert_eq!(config.protocol_id, (1, "identity".to_string()));
}

#[test]
fn test_identity_client_config_with_network() {
    let config =
        IdentityClientConfig::with_originator("myapp.com").with_network(NetworkPreset::Testnet);

    assert_eq!(config.network_preset, NetworkPreset::Testnet);
    assert_eq!(config.originator, Some("myapp.com".to_string()));
}

#[test]
fn test_identity_client_config_with_token_amount() {
    let config = IdentityClientConfig::with_originator("myapp.com").with_token_amount(100);

    assert_eq!(config.token_amount, 100);
}

#[test]
fn test_identity_client_config_builder_chaining() {
    let config = IdentityClientConfig::with_originator("myapp.com")
        .with_network(NetworkPreset::Testnet)
        .with_token_amount(500);

    assert_eq!(config.originator, Some("myapp.com".to_string()));
    assert_eq!(config.network_preset, NetworkPreset::Testnet);
    assert_eq!(config.token_amount, 500);
}

// =================
// ContactsManagerConfig Tests
// =================

#[test]
fn test_contacts_manager_config_default() {
    let config = ContactsManagerConfig::default();

    assert_eq!(config.protocol_id, (2, "contact".to_string()));
    assert_eq!(config.basket, "contacts");
    assert!(config.originator.is_none());
}

#[test]
fn test_contacts_manager_config_with_originator() {
    let config = ContactsManagerConfig::with_originator("myapp.example.com");

    assert_eq!(config.originator, Some("myapp.example.com".to_string()));
    assert_eq!(config.protocol_id, (2, "contact".to_string()));
    assert_eq!(config.basket, "contacts");
}

// =================
// CertifierInfo Tests
// =================

#[test]
fn test_certifier_info_default() {
    let info = CertifierInfo::default();

    assert_eq!(info.name, "Unknown Certifier");
    assert_eq!(info.icon_url, DefaultIdentityValues::BADGE_ICON_URL);
    assert_eq!(info.description, "No information available");
    assert_eq!(info.trust, 0);
}

#[test]
fn test_certifier_info_creation() {
    let info = CertifierInfo {
        name: "SocialCert".to_string(),
        icon_url: "https://socialcert.net/icon.png".to_string(),
        description: "Social media certificate authority".to_string(),
        trust: 8,
    };

    assert_eq!(info.name, "SocialCert");
    assert_eq!(info.trust, 8);
}

#[test]
fn test_certifier_info_json_serialization() {
    let info = CertifierInfo {
        name: "TestCert".to_string(),
        icon_url: "https://example.com/icon.png".to_string(),
        description: "Test certifier".to_string(),
        trust: 5,
    };

    let json = serde_json::to_string(&info).unwrap();

    // Verify camelCase
    assert!(json.contains("\"iconUrl\":"));

    let decoded: CertifierInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.name, "TestCert");
    assert_eq!(decoded.trust, 5);
}

// =================
// BroadcastResult Tests
// =================

#[test]
fn test_broadcast_success() {
    let success = BroadcastSuccess {
        txid: "abc123def456".to_string(),
        message: Some("Transaction accepted".to_string()),
    };

    assert_eq!(success.txid, "abc123def456");
    assert_eq!(success.message, Some("Transaction accepted".to_string()));
}

#[test]
fn test_broadcast_failure() {
    let failure = BroadcastFailure {
        code: "REJECTED".to_string(),
        description: "Transaction rejected by network".to_string(),
    };

    assert_eq!(failure.code, "REJECTED");
}

#[test]
fn test_broadcast_result_success() {
    let result = BroadcastResult::Success(BroadcastSuccess {
        txid: "abc123".to_string(),
        message: None,
    });

    assert!(result.is_success());
    assert_eq!(result.txid(), Some("abc123"));
}

#[test]
fn test_broadcast_result_failure() {
    let result = BroadcastResult::Failure(BroadcastFailure {
        code: "ERROR".to_string(),
        description: "Test error".to_string(),
    });

    assert!(!result.is_success());
    assert!(result.txid().is_none());
}

#[test]
fn test_broadcast_result_into_result_success() {
    let result = BroadcastResult::Success(BroadcastSuccess {
        txid: "abc123".to_string(),
        message: None,
    });

    let inner = result.into_result();
    assert!(inner.is_ok());
    assert_eq!(inner.unwrap().txid, "abc123");
}

#[test]
fn test_broadcast_result_into_result_failure() {
    let result = BroadcastResult::Failure(BroadcastFailure {
        code: "ERROR".to_string(),
        description: "Test error".to_string(),
    });

    let inner = result.into_result();
    assert!(inner.is_err());
    assert_eq!(inner.unwrap_err().code, "ERROR");
}

// =================
// Static Avatar URLs Tests
// =================

#[test]
fn test_static_avatar_urls() {
    // Verify all static avatars are UHRP-style hashes (start with XU)
    assert!(StaticAvatarUrls::EMAIL.starts_with("XU"));
    assert!(StaticAvatarUrls::PHONE.starts_with("XU"));
    assert!(StaticAvatarUrls::ANYONE.starts_with("XU"));
    assert!(StaticAvatarUrls::SELF.starts_with("XU"));

    // Verify they're all different
    assert_ne!(StaticAvatarUrls::EMAIL, StaticAvatarUrls::PHONE);
    assert_ne!(StaticAvatarUrls::ANYONE, StaticAvatarUrls::SELF);
}

// =================
// Default Identity Values Tests
// =================

#[test]
fn test_default_identity_values() {
    assert_eq!(DefaultIdentityValues::NAME, "Unknown Identity");
    assert!(DefaultIdentityValues::AVATAR_URL.starts_with("XU"));
    assert!(DefaultIdentityValues::BADGE_ICON_URL.starts_with("XU"));
    assert!(!DefaultIdentityValues::BADGE_LABEL.is_empty());
    assert!(DefaultIdentityValues::BADGE_CLICK_URL.starts_with("https://"));
}

// =================
// DEFAULT_SOCIALCERT_CERTIFIER Tests
// =================

#[test]
fn test_default_socialcert_certifier() {
    // Should be a valid hex-encoded public key (66 hex chars for compressed)
    assert_eq!(DEFAULT_SOCIALCERT_CERTIFIER.len(), 66);
    assert!(DEFAULT_SOCIALCERT_CERTIFIER.starts_with("02"));

    // Verify it's valid hex
    let bytes = bsv_sdk::primitives::from_hex(DEFAULT_SOCIALCERT_CERTIFIER);
    assert!(bytes.is_ok());
    assert_eq!(bytes.unwrap().len(), 33); // 33 bytes for compressed public key
}

// =================
// ContactsManager with ProtoWallet Tests
// =================

mod contacts_manager_tests {
    use super::*;
    use bsv_sdk::identity::ContactsManager;
    use bsv_sdk::wallet::ProtoWallet;

    fn create_test_contact(key: &str, name: &str) -> Contact {
        Contact {
            identity_key: key.to_string(),
            name: name.to_string(),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            added_at: 1700000000000,
            notes: None,
            tags: Vec::new(),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn test_add_and_get_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact.clone()).await.unwrap();

        let retrieved = manager.get_contact("02abc123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Alice");
    }

    #[tokio::test]
    async fn test_get_nonexistent_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let result = manager.get_contact("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        // Add initial contact
        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact).await.unwrap();

        // Update the contact
        let updated = Contact {
            identity_key: "02abc123".to_string(),
            name: "Alice Updated".to_string(),
            notes: Some("Updated notes".to_string()),
            ..Default::default()
        };
        manager.update_contact("02abc123", updated).await.unwrap();

        // Verify update
        let retrieved = manager.get_contact("02abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Alice Updated");
        assert_eq!(retrieved.notes, Some("Updated notes".to_string()));
    }

    #[tokio::test]
    async fn test_update_nonexistent_contact_fails() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        let result = manager.update_contact("nonexistent", contact).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact).await.unwrap();

        // Verify contact exists
        assert!(manager.get_contact("02abc123").await.unwrap().is_some());

        // Remove contact
        manager.remove_contact("02abc123").await.unwrap();

        // Verify contact is removed
        assert!(manager.get_contact("02abc123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_contact_fails() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let result = manager.remove_contact("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_contacts() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        // Add multiple contacts
        manager
            .add_contact(create_test_contact("02abc123", "Alice"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02def456", "Bob"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02ghi789", "Charlie"))
            .await
            .unwrap();

        let contacts = manager.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 3);
    }

    #[tokio::test]
    async fn test_search_contacts_by_name() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        manager
            .add_contact(create_test_contact("02abc123", "Alice Smith"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02def456", "Bob Jones"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02ghi789", "Alice Johnson"))
            .await
            .unwrap();

        let results = manager.search_contacts("alice").await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_search_contacts_case_insensitive() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        manager
            .add_contact(create_test_contact("02abc123", "ALICE"))
            .await
            .unwrap();

        // Search should be case insensitive
        assert_eq!(manager.search_contacts("alice").await.unwrap().len(), 1);
        assert_eq!(manager.search_contacts("ALICE").await.unwrap().len(), 1);
        assert_eq!(manager.search_contacts("Alice").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_search_contacts_by_tag() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact1 = create_test_contact("02abc123", "Alice");
        contact1.tags = vec!["work".to_string(), "engineering".to_string()];

        let mut contact2 = create_test_contact("02def456", "Bob");
        contact2.tags = vec!["personal".to_string()];

        manager.add_contact(contact1).await.unwrap();
        manager.add_contact(contact2).await.unwrap();

        let results = manager.search_contacts("work").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");
    }

    #[tokio::test]
    async fn test_search_contacts_by_notes() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact = create_test_contact("02abc123", "Alice");
        contact.notes = Some("Met at the blockchain conference".to_string());

        manager.add_contact(contact).await.unwrap();

        let results = manager.search_contacts("conference").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");
    }

    #[tokio::test]
    async fn test_get_contacts_by_tag() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact1 = create_test_contact("02abc123", "Alice");
        contact1.tags = vec!["work".to_string()];

        let mut contact2 = create_test_contact("02def456", "Bob");
        contact2.tags = vec!["personal".to_string()];

        manager.add_contact(contact1).await.unwrap();
        manager.add_contact(contact2).await.unwrap();

        let work_contacts = manager.get_contacts_by_tag("work").await.unwrap();
        assert_eq!(work_contacts.len(), 1);
        assert_eq!(work_contacts[0].name, "Alice");

        // Case insensitive
        let personal_contacts = manager.get_contacts_by_tag("Personal").await.unwrap();
        assert_eq!(personal_contacts.len(), 1);
        assert_eq!(personal_contacts[0].name, "Bob");
    }

    #[tokio::test]
    async fn test_cache_management() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        assert!(!manager.is_cache_initialized().await);
        assert_eq!(manager.cached_count().await, 0);

        manager
            .add_contact(create_test_contact("02abc123", "Alice"))
            .await
            .unwrap();
        assert_eq!(manager.cached_count().await, 1);

        manager.clear_cache().await;
        assert_eq!(manager.cached_count().await, 0);
        assert!(!manager.is_cache_initialized().await);
    }

    #[tokio::test]
    async fn test_add_contact_replaces_existing() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact1 = create_test_contact("02abc123", "Alice V1");
        manager.add_contact(contact1).await.unwrap();

        let contact2 = Contact {
            identity_key: "02abc123".to_string(),
            name: "Alice V2".to_string(),
            notes: Some("Updated".to_string()),
            ..Default::default()
        };
        manager.add_contact(contact2).await.unwrap();

        let contacts = manager.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 1);

        let retrieved = manager.get_contact("02abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Alice V2");
    }

    #[tokio::test]
    async fn test_empty_search_returns_empty() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        manager
            .add_contact(create_test_contact("02abc123", "Alice"))
            .await
            .unwrap();

        // Search for something that doesn't match
        let results = manager.search_contacts("xyz123").await.unwrap();
        assert!(results.is_empty());
    }
}

// =================
// IdentityClient Configuration Tests
// =================
// Note: IdentityClient requires `W: WalletInterface + Clone`, but ProtoWallet
// does not implement Clone. These tests focus on configuration and parsing
// functionality that doesn't require a Clone wallet.

mod identity_client_tests {
    use super::*;

    // Test static methods that don't require Clone
    #[test]
    fn test_identity_client_config_defaults() {
        let config = IdentityClientConfig::default();

        // Verify default values match TypeScript/Go SDKs
        assert_eq!(config.protocol_id, (1, "identity".to_string()));
        assert_eq!(config.key_id, "1");
        assert_eq!(config.token_amount, 1);
        assert_eq!(config.output_index, 0);
        assert_eq!(config.network_preset, NetworkPreset::Mainnet);
        assert!(config.originator.is_none());
    }

    #[test]
    fn test_identity_client_config_builder() {
        let config = IdentityClientConfig::with_originator("test-app.example.com")
            .with_network(NetworkPreset::Testnet)
            .with_token_amount(5);

        assert_eq!(config.originator, Some("test-app.example.com".to_string()));
        assert_eq!(config.network_preset, NetworkPreset::Testnet);
        assert_eq!(config.token_amount, 5);
    }

    #[test]
    fn test_identity_client_config_protocol_defaults() {
        let config = IdentityClientConfig::default();

        // Protocol should be (1, "identity") to match other SDKs
        assert_eq!(config.protocol_id.0, 1); // Security level
        assert_eq!(config.protocol_id.1, "identity"); // Protocol name
    }

    // Test parse_identity static method using a mock IdentityCertificate
    // Note: This requires constructing a full IdentityCertificate which needs auth module types
    // For now, we test the configuration and type exports
}

// =================
// Cross-SDK Compatibility Tests
// =================

#[test]
fn test_certificate_type_ids_are_base64() {
    for cert_type in KnownCertificateType::all() {
        let type_id = cert_type.type_id();

        // Should be valid base64
        let decoded = bsv_sdk::primitives::from_base64(type_id);
        assert!(
            decoded.is_ok(),
            "Type ID for {:?} is not valid base64",
            cert_type
        );

        // Should decode to 32 bytes (SHA-256 hash)
        let bytes = decoded.unwrap();
        assert_eq!(
            bytes.len(),
            32,
            "Type ID for {:?} should be 32 bytes",
            cert_type
        );
    }
}

#[test]
fn test_json_field_names_are_camel_case() {
    // Verify DisplayableIdentity uses camelCase
    let identity = DisplayableIdentity::from_key("02abc123");
    let json = serde_json::to_string(&identity).unwrap();
    assert!(json.contains("avatarUrl"));
    assert!(json.contains("identityKey"));
    assert!(json.contains("abbreviatedKey"));
    assert!(json.contains("badgeIconUrl"));
    assert!(json.contains("badgeLabel"));
    assert!(json.contains("badgeClickUrl"));

    // Verify Contact uses camelCase
    let contact = Contact::from_identity(identity);
    let json = serde_json::to_string(&contact).unwrap();
    assert!(json.contains("identityKey"));
    assert!(json.contains("avatarUrl"));
    assert!(json.contains("addedAt"));

    // Verify IdentityQuery uses camelCase
    let query = IdentityQuery::by_identity_key("02abc123")
        .with_certifier("02cert")
        .with_limit(10);
    let json = serde_json::to_string(&query).unwrap();
    assert!(json.contains("identityKey"));
    assert!(!json.contains("identity_key")); // Underscore version should NOT be present
}

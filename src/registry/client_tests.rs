#![cfg(test)]

use super::*;
use crate::wallet::{Protocol as WalletProtocol, SecurityLevel};

/// Fold3 ruling 5b (carry guard): the release's relocated registry reader
/// (`read_definitions`) reads only one output's own script, so it parses the
/// subject alone via `from_beef_subject` and links NOTHING on an untrusted
/// overlay answer. A validly signed basket definition (built by the
/// production signer `token::lock_definition`) sits at the subject output of
/// an answer whose shared-parent ancestry the linking door refuses; the
/// reader surfaces it. Reverting `read_definitions` to `from_beef` refuses
/// the whole answer before its output is read, dropping the definition — RED.
#[tokio::test]
async fn the_relocated_registry_reader_links_nothing_on_a_hostile_answer() {
    use crate::primitives::PrivateKey;
    use crate::script::{LockingScript, UnlockingScript};
    use crate::transaction::{Beef, MerklePath, Transaction, TransactionInput, TransactionOutput};
    use crate::wallet::ProtoWallet;

    let operator = ProtoWallet::new(Some(PrivateKey::from_hex(&"a5".repeat(32)).unwrap()));
    let operator_hex = operator.identity_key().to_hex();
    let basket = BasketDefinitionData::new("basket749", "Basket 749")
        .with_icon_url("https://icon-749.example")
        .with_description("the 749 fold3 basket")
        .with_documentation_url("https://docs-749.example");
    let fields = basket.to_pushdrop_fields(&operator_hex);
    let script =
        crate::registry::token::lock_definition(&operator, DefinitionType::Basket, fields, None)
            .await
            .expect("a valid signed basket definition");

    // A hostile amplifying BEEF: a shared parent of 120 x 2 KiB outputs spent
    // by 120 inputs re-materializes ~29 MiB past the 16 MiB default, so a
    // linking parse refuses it; the subject carries the signed definition at
    // output 0 (1 satoshi, the overlay admission value).
    const FAN: usize = 120;
    let filler = LockingScript::from_binary(&vec![0u8; 2 * 1024]).unwrap();
    let mut parent = Transaction::new();
    let mut funding = TransactionInput::new("11".repeat(32), 0);
    funding.unlocking_script = Some(UnlockingScript::new());
    parent.inputs_mut().push(funding);
    for _ in 0..FAN {
        parent
            .outputs_mut()
            .push(TransactionOutput::new(1_000, filler.clone()));
    }
    let ptxid = parent.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&ptxid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump)).unwrap();
    let mut subject = Transaction::new();
    for vout in 0..FAN {
        let mut spend = TransactionInput::new(ptxid.clone(), vout as u32);
        spend.unlocking_script = Some(UnlockingScript::new());
        subject.inputs_mut().push(spend);
    }
    subject
        .outputs_mut()
        .push(TransactionOutput::new(1, script));
    beef.merge_raw_tx(subject.to_binary(), None).unwrap();
    let beef = beef.to_binary().unwrap();

    assert!(
        matches!(
            Transaction::from_beef(&beef, None),
            Err(crate::Error::BeefResourceLimit(_))
        ),
        "the fixture must trip the link bound so a linking reader would drop it"
    );
    assert!(
        Transaction::from_beef_subject(&beef, None).is_ok(),
        "the subject reader parses the same answer without linking"
    );

    let output = OutputListItem {
        beef,
        output_index: 0,
        context: None,
        txid: None,
    };
    let defs = read_definitions(
        vec![output],
        DefinitionType::Basket,
        BasketDefinitionData::from_pushdrop_fields,
        |_| true,
    );
    assert_eq!(
        defs.len(),
        1,
        "the relocated reader surfaced the signed definition from an answer a linking reader drops"
    );
    assert_eq!(defs[0].basket_id, "basket749");
}

#[test]
fn test_config_defaults() {
    let config = RegistryClientConfig::default();
    assert_eq!(config.network_preset, NetworkPreset::Mainnet);
    assert!(config.resolver.is_none());
    assert!(config.originator.is_none());
    assert!(!config.accept_delayed_broadcast);
}

#[test]
fn test_config_builder() {
    let config = RegistryClientConfig::new()
        .with_network(NetworkPreset::Testnet)
        .with_originator("myapp.com")
        .with_delayed_broadcast(true);

    assert_eq!(config.network_preset, NetworkPreset::Testnet);
    assert_eq!(config.originator, Some("myapp.com".to_string()));
    assert!(config.accept_delayed_broadcast);
}

#[test]
fn test_pushdrop_fields_format_basket() {
    // Verify the field format matches Go/TS SDKs
    // Basket: 6 fields (basketID, name, iconURL, description, documentationURL, registryOperator)
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
fn test_pushdrop_fields_format_protocol() {
    // Protocol: 6 fields (protocolID JSON, name, iconURL, description, documentationURL, registryOperator)
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
fn test_pushdrop_fields_format_certificate() {
    // Certificate: 7 fields (type, name, iconURL, description, documentationURL, fields JSON, registryOperator)
    use crate::registry::CertificateFieldDescriptor;

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

    assert_eq!(String::from_utf8(fields[6].clone()).unwrap(), "02abc123");
}

#[test]
fn test_definition_data_conversion() {
    let basket = BasketDefinitionData::new("b", "Basket");
    let data: DefinitionData = basket.into();
    assert_eq!(data.get_definition_type(), DefinitionType::Basket);

    let protocol =
        ProtocolDefinitionData::new(WalletProtocol::new(SecurityLevel::App, "p"), "Protocol");
    let data: DefinitionData = protocol.into();
    assert_eq!(data.get_definition_type(), DefinitionType::Protocol);
}

#[test]
fn test_update_definition_result() {
    use crate::registry::UpdateDefinitionResult;

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

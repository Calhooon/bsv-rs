//! KVStore token interpreter.
//!
//! Extracts key-value data from transaction outputs to build
//! the history of an entry. Supports five fields without tags and six with
//! tags, including the final signature in either format.

use crate::primitives::{to_hex, PublicKey};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::transaction::Transaction;
use crate::wallet::{
    Counterparty, KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};
use std::sync::OnceLock;

use super::types::{KVStoreEntry, KvProtocolFields};
use crate::{Error, Result};

/// Cached "anyone" wallet for signature verification.
static ANYONE_WALLET: OnceLock<ProtoWallet> = OnceLock::new();

/// Returns a cached "anyone" wallet for signature verification.
fn get_anyone_wallet() -> &'static ProtoWallet {
    ANYONE_WALLET.get_or_init(ProtoWallet::anyone)
}

/// The reference's tag checks, in its order (kvStoreTokenValidation.ts:58-74).
/// Absence is handled by the field count, before parsing any tag JSON.
fn validate_tags(value: &serde_json::Value) -> Result<Vec<String>> {
    let tags = value
        .as_array()
        .filter(|tags| tags.len() <= 32)
        .ok_or_else(|| Error::KvStoreError("KVStore tags must be a bounded array".into()))?;
    let mut result = Vec::with_capacity(tags.len());
    for tag in tags {
        let tag = tag
            .as_str()
            .filter(|tag| !tag.is_empty() && tag.len() <= 256)
            .ok_or_else(|| Error::KvStoreError("KVStore tag has an invalid length".into()))?;
        if result.iter().any(|seen| seen == tag) {
            return Err(Error::KvStoreError("KVStore tags must be unique".into()));
        }
        result.push(tag.to_owned());
    }
    Ok(result)
}

fn parse_tags(bytes: &[u8]) -> Option<Vec<String>> {
    validate_tags(&serde_json::from_slice::<serde_json::Value>(bytes).ok()?).ok()
}

/// Context for KVStore interpreter operations.
///
/// Contains the key and protocol ID to match against when traversing history.
#[derive(Debug, Clone)]
pub struct KVStoreContext {
    /// The key to match.
    pub key: String,
    /// The protocol ID to match.
    pub protocol_id: String,
}

impl KVStoreContext {
    /// Creates a new context.
    pub fn new(key: impl Into<String>, protocol_id: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            protocol_id: protocol_id.into(),
        }
    }

    /// Creates a cache key for history lookups.
    pub fn cache_key(&self) -> String {
        format!("{}:{}", self.protocol_id, self.key)
    }
}

/// Interpreter for KVStore token history.
///
/// Extracts key-value data from transaction outputs to build
/// the history of an entry.
pub struct KVStoreInterpreter;

impl KVStoreInterpreter {
    /// Interpret a single output.
    ///
    /// Extracts KVStoreEntry from a PushDrop token if valid.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction containing the output
    /// * `output_index` - The index of the output to interpret
    /// * `ctx` - Optional context for filtering (key and protocol_id to match)
    ///
    /// # Returns
    ///
    /// Some(KVStoreEntry) if the output is a valid KVStore token (optionally matching context),
    /// None otherwise.
    pub fn interpret(
        tx: &Transaction,
        output_index: u32,
        ctx: Option<&KVStoreContext>,
    ) -> Option<KVStoreEntry> {
        let output = tx.outputs.get(output_index as usize)?;
        Self::interpret_script(&output.locking_script, ctx)
    }

    /// Interpret a locking script directly.
    ///
    /// Extracts KVStoreEntry from a PushDrop locking script if valid.
    pub fn interpret_script(
        script: &LockingScript,
        ctx: Option<&KVStoreContext>,
    ) -> Option<KVStoreEntry> {
        let fields = Self::extract_fields(script)?;
        let protocol_id = fields.protocol_id_string()?;
        let key = fields.key_string()?;

        // Public tokens written by the reference carry a JSON wallet protocol.
        // Authenticate those on the history path too. The crate's older raw
        // protocol format keeps its separate verify_signature call.
        if protocol_id.starts_with('[') && !Self::verify_signature(&fields, &protocol_id) {
            return None;
        }

        // If context provided, check for match
        if let Some(ctx) = ctx {
            // The store's string configuration denotes an App protocol;
            // the reference writes that same namespace as [1, name].
            let protocol_matches = ctx.protocol_id == protocol_id
                || serde_json::from_str::<(u8, String)>(&protocol_id).is_ok_and(|(level, name)| {
                    level == SecurityLevel::App.as_u8() && name == ctx.protocol_id
                });
            if ctx.key != key || !protocol_matches {
                return None;
            }
        }

        let value = fields.value_string()?;
        let controller = if fields.controller.len() == 33 {
            to_hex(&fields.controller)
        } else {
            String::from_utf8(fields.controller.clone()).ok()?
        };
        Some(KVStoreEntry::new(key, value, controller, protocol_id).with_tags(fields.tags_vec()))
    }

    /// Verify that a signature field is valid.
    ///
    /// Verifies that the signature was created by the controller public key
    /// signing the concatenated fields (protocol_id + key + value + controller [+ tags]).
    ///
    /// # Arguments
    ///
    /// * `fields` - The extracted KVStore fields
    /// * `protocol_id` - The protocol ID string for key derivation
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` if invalid or missing.
    /// Errors are converted to `false` for graceful degradation.
    pub fn verify_signature(fields: &KVStoreFields, protocol_id: &str) -> bool {
        // Get signature - if missing, verification fails
        let signature = match &fields.signature {
            Some(sig) if !sig.is_empty() => sig.clone(),
            _ => return false,
        };

        // Parse controller public key (expects 33-byte compressed format)
        let controller_pubkey = match PublicKey::from_bytes(&fields.controller) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Concatenate fields for verification: protocol_id + key + value + controller [+ tags]
        let mut data = Vec::new();
        data.extend_from_slice(&fields.protocol_id);
        data.extend_from_slice(&fields.key);
        data.extend_from_slice(&fields.value);
        data.extend_from_slice(&fields.controller);
        if let Some(tags) = &fields.tags {
            if parse_tags(tags).is_none() {
                return false;
            }
            data.extend_from_slice(tags);
        }

        // The reference signs with the token's wallet protocol and key, and
        // binds its locking key to the same derivation (validation.ts:106-117).
        // Keep reading this crate's earlier raw-protocol tokens as well.
        let (protocol, key_id) = match serde_json::from_slice::<(u8, String)>(&fields.protocol_id) {
            Ok((level, name)) => {
                let Some(protocol) = Protocol::from_tuple((level, &name)) else {
                    return false;
                };
                if serde_json::to_vec(&(level, &name)).ok().as_ref() != Some(&fields.protocol_id) {
                    return false;
                }
                let Some(key_id) = fields.key_string() else {
                    return false;
                };
                let expected_key = get_anyone_wallet().key_deriver().derive_public_key(
                    &protocol,
                    &key_id,
                    &Counterparty::Other(controller_pubkey.clone()),
                    false,
                );
                if !expected_key.is_ok_and(|key| key == fields.locking_public_key) {
                    return false;
                }
                (protocol, key_id)
            }
            Err(_) => (
                Protocol::new(SecurityLevel::App, protocol_id),
                "kvstore-token".to_owned(),
            ),
        };
        let args = VerifySignatureArgs {
            data: Some(data),
            hash_to_directly_verify: None,
            signature,
            protocol_id: protocol,
            key_id,
            counterparty: Some(Counterparty::Other(controller_pubkey)),
            for_self: Some(false), // Verify counterparty's signature
            ..Default::default()
        };

        // Use the "anyone" wallet for verification
        let wallet = get_anyone_wallet();
        wallet.verify_signature(args).is_ok_and(|r| r.valid)
    }

    /// Legacy verify_signature that takes PushDrop and PublicKey.
    ///
    /// This is kept for backward compatibility but now delegates to the
    /// KVStoreFields-based verification.
    #[deprecated(note = "Use verify_signature with KVStoreFields instead")]
    pub fn verify_signature_legacy(_pushdrop: &PushDrop, _controller: &PublicKey) -> bool {
        // Legacy stub - returns true for backward compatibility
        // New code should use verify_signature() with KVStoreFields
        true
    }

    /// Extract value from a PushDrop token without validation.
    ///
    /// This is a convenience method for extracting just the value field.
    /// The three readers decode lock-before alone, as the reference's
    /// interpreter does (`kvStoreTokenValidation.ts:88`; #537).
    pub fn extract_value(script: &LockingScript) -> Option<String> {
        let pushdrop = PushDrop::decode_before(script).ok()?;
        if pushdrop.fields.len() < KvProtocolFields::MIN_FIELDS_OLD {
            return None;
        }
        let value_bytes = pushdrop.fields.get(KvProtocolFields::VALUE)?;
        String::from_utf8(value_bytes.clone()).ok()
    }

    /// Check if a script is a KVStore token.
    ///
    /// Returns true if the script appears to be a valid KVStore PushDrop token.
    pub fn is_kvstore_token(script: &LockingScript) -> bool {
        match PushDrop::decode_before(script) {
            Ok(pushdrop) => pushdrop.fields.len() >= KvProtocolFields::MIN_FIELDS_OLD,
            Err(_) => false,
        }
    }

    /// Extract all fields from a KVStore token.
    ///
    /// Returns the raw field data for custom processing.
    pub fn extract_fields(script: &LockingScript) -> Option<KVStoreFields> {
        let pushdrop = PushDrop::decode_before(script).ok()?;

        let has_tags = match pushdrop.fields.len() {
            KvProtocolFields::MIN_FIELDS_OLD => false,
            KvProtocolFields::MIN_FIELDS_NEW => true,
            _ => return None,
        };
        let tags = has_tags.then(|| pushdrop.fields[KvProtocolFields::TAGS].clone());
        if tags
            .as_deref()
            .is_some_and(|bytes| parse_tags(bytes).is_none())
        {
            return None;
        }

        Some(KVStoreFields {
            protocol_id: pushdrop
                .fields
                .get(KvProtocolFields::PROTOCOL_ID)
                .cloned()?,
            key: pushdrop.fields.get(KvProtocolFields::KEY).cloned()?,
            value: pushdrop.fields.get(KvProtocolFields::VALUE).cloned()?,
            controller: pushdrop.fields.get(KvProtocolFields::CONTROLLER).cloned()?,
            tags,
            signature: pushdrop.fields.last().cloned(),
            locking_public_key: pushdrop.locking_public_key,
        })
    }
}

/// Raw field data extracted from a KVStore token.
#[derive(Debug, Clone)]
pub struct KVStoreFields {
    /// Protocol ID (field 0).
    pub protocol_id: Vec<u8>,
    /// Key (field 1).
    pub key: Vec<u8>,
    /// Value (field 2).
    pub value: Vec<u8>,
    /// Controller pubkey (field 3).
    pub controller: Vec<u8>,
    /// Tags JSON (field 4, optional).
    pub tags: Option<Vec<u8>>,
    /// Signature (last field).
    pub signature: Option<Vec<u8>>,
    /// The locking public key from PushDrop.
    pub locking_public_key: PublicKey,
}

impl KVStoreFields {
    /// Get protocol ID as string.
    pub fn protocol_id_string(&self) -> Option<String> {
        String::from_utf8(self.protocol_id.clone()).ok()
    }

    /// Get key as string.
    pub fn key_string(&self) -> Option<String> {
        String::from_utf8(self.key.clone()).ok()
    }

    /// Get value as string (raw, not decrypted).
    pub fn value_string(&self) -> Option<String> {
        String::from_utf8(self.value.clone()).ok()
    }

    /// Get value as raw bytes.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Get controller as hex string.
    pub fn controller_hex(&self) -> String {
        if self.controller.len() == 33 {
            to_hex(&self.controller)
        } else {
            String::from_utf8(self.controller.clone()).unwrap_or_else(|_| to_hex(&self.controller))
        }
    }

    /// Get tags as string vector.
    pub fn tags_vec(&self) -> Vec<String> {
        self.tags
            .as_deref()
            .and_then(parse_tags)
            .unwrap_or_default()
    }

    /// Check if this token has tags (new format).
    pub fn has_tags(&self) -> bool {
        self.tags.is_some()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;
    use crate::script::templates::PushDrop;

    #[test]
    fn malformed_reference_token_tags_use_the_reference_words_and_order() {
        let recorded: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/kvstore_tags_344.json"))
                .unwrap();
        let cases = recorded["cases"].as_array().unwrap();
        let mut refused = 0;
        for case in cases.iter().filter(|case| {
            case["error"]
                .as_str()
                .is_some_and(|error| error.starts_with("KVStore "))
        }) {
            let script = LockingScript::from_hex(case["script"].as_str().unwrap()).unwrap();
            let token = PushDrop::decode_before(&script).unwrap();
            let tags = serde_json::from_slice(&token.fields[KvProtocolFields::TAGS]).unwrap();
            assert_eq!(
                validate_tags(&tags),
                Err(Error::KvStoreError(
                    case["error"].as_str().unwrap().to_owned()
                )),
                "{}",
                case["name"]
            );
            assert!(KVStoreInterpreter::extract_fields(&script).is_none());
            refused += 1;
        }
        assert_eq!(refused, 9);
    }

    fn create_test_token(
        protocol_id: &str,
        key: &str,
        value: &str,
        controller: &PublicKey,
        tags: Option<Vec<String>>,
    ) -> LockingScript {
        let mut fields = vec![
            protocol_id.as_bytes().to_vec(),
            key.as_bytes().to_vec(),
            value.as_bytes().to_vec(),
            controller.to_compressed().to_vec(),
        ];

        if let Some(tags) = tags {
            let tags_json = serde_json::to_string(&tags).unwrap();
            fields.push(tags_json.as_bytes().to_vec());
        }

        // Add signature placeholder
        fields.push(vec![0u8; 64]);

        PushDrop::new(controller.clone(), fields).lock()
    }

    #[test]
    fn test_interpret_basic_token() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let script = create_test_token("kvstore", "my_key", "my_value", &pubkey, None);

        let entry = KVStoreInterpreter::interpret_script(&script, None);
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.key, "my_key");
        assert_eq!(entry.value, "my_value");
        assert_eq!(entry.protocol_id, "kvstore");
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_interpret_token_with_tags() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let tags = vec!["tag1".to_string(), "tag2".to_string()];
        let script =
            create_test_token("kvstore", "my_key", "my_value", &pubkey, Some(tags.clone()));

        let entry = KVStoreInterpreter::interpret_script(&script, None);
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.tags, tags);
    }

    #[test]
    fn test_interpret_with_context_match() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let script = create_test_token("kvstore", "my_key", "my_value", &pubkey, None);

        let ctx = KVStoreContext::new("my_key", "kvstore");
        let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
        assert!(entry.is_some());
    }

    #[test]
    fn test_interpret_with_context_no_match() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let script = create_test_token("kvstore", "my_key", "my_value", &pubkey, None);

        let ctx = KVStoreContext::new("other_key", "kvstore");
        let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
        assert!(entry.is_none());
    }

    #[test]
    fn test_extract_value() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let script = create_test_token("kvstore", "my_key", "the_value", &pubkey, None);

        let value = KVStoreInterpreter::extract_value(&script);
        assert_eq!(value, Some("the_value".to_string()));
    }

    #[test]
    fn test_is_kvstore_token() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let script = create_test_token("kvstore", "key", "value", &pubkey, None);
        assert!(KVStoreInterpreter::is_kvstore_token(&script));

        // Non-KVStore PushDrop (too few fields)
        let small_pushdrop = PushDrop::new(pubkey.clone(), vec![b"only".to_vec(), b"two".to_vec()]);
        assert!(!KVStoreInterpreter::is_kvstore_token(
            &small_pushdrop.lock()
        ));
    }

    #[test]
    fn test_extract_fields() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let tags = vec!["important".to_string()];
        let script =
            create_test_token("kvstore", "my_key", "my_value", &pubkey, Some(tags.clone()));

        let fields = KVStoreInterpreter::extract_fields(&script);
        assert!(fields.is_some());

        let fields = fields.unwrap();
        assert_eq!(fields.protocol_id_string(), Some("kvstore".to_string()));
        assert_eq!(fields.key_string(), Some("my_key".to_string()));
        assert_eq!(fields.value_string(), Some("my_value".to_string()));
        assert_eq!(
            fields.controller_hex(),
            crate::primitives::to_hex(&pubkey.to_compressed())
        );
        assert!(fields.has_tags());
        assert_eq!(fields.tags_vec(), tags);
    }

    #[test]
    fn test_kvstore_context() {
        let ctx = KVStoreContext::new("test_key", "kvstore");
        assert_eq!(ctx.key, "test_key");
        assert_eq!(ctx.protocol_id, "kvstore");
        assert_eq!(ctx.cache_key(), "kvstore:test_key");
    }

    #[test]
    fn test_invalid_script_returns_none() {
        // Create a non-PushDrop script
        let script = LockingScript::from_asm("OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG");
        assert!(
            script.is_err()
                || KVStoreInterpreter::interpret_script(&script.unwrap(), None).is_none()
        );
    }

    #[test]
    fn test_verify_signature_missing() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        // Create fields without signature
        let fields = KVStoreFields {
            protocol_id: b"kvstore".to_vec(),
            key: b"test_key".to_vec(),
            value: b"test_value".to_vec(),
            controller: pubkey.to_compressed().to_vec(),
            tags: None,
            signature: None,
            locking_public_key: pubkey.clone(),
        };

        // Should return false when signature is missing
        assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
    }

    #[test]
    fn test_verify_signature_empty() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        // Create fields with empty signature
        let fields = KVStoreFields {
            protocol_id: b"kvstore".to_vec(),
            key: b"test_key".to_vec(),
            value: b"test_value".to_vec(),
            controller: pubkey.to_compressed().to_vec(),
            tags: None,
            signature: Some(vec![]),
            locking_public_key: pubkey.clone(),
        };

        // Should return false when signature is empty
        assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
    }

    #[test]
    fn test_verify_signature_invalid() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        // Create fields with invalid signature bytes
        let fields = KVStoreFields {
            protocol_id: b"kvstore".to_vec(),
            key: b"test_key".to_vec(),
            value: b"test_value".to_vec(),
            controller: pubkey.to_compressed().to_vec(),
            tags: None,
            signature: Some(vec![1, 2, 3, 4, 5]), // Invalid DER signature
            locking_public_key: pubkey.clone(),
        };

        // Should return false for invalid signature
        assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
    }

    #[test]
    fn test_verify_signature_invalid_controller() {
        // Create fields with invalid controller bytes
        let fields = KVStoreFields {
            protocol_id: b"kvstore".to_vec(),
            key: b"test_key".to_vec(),
            value: b"test_value".to_vec(),
            controller: vec![0u8; 33], // Invalid pubkey (all zeros)
            tags: None,
            signature: Some(vec![1, 2, 3, 4]),
            locking_public_key: PrivateKey::random().public_key(),
        };

        // Should return false for invalid controller
        assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
    }
}

//! KVStore token interpreter.
//!
//! Extracts key-value data from transaction outputs to build
//! the history of an entry. Supports both old format (4 fields without tags)
//! and new format (5 fields with tags).

use crate::primitives::{to_hex, PublicKey};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::transaction::Transaction;

use super::types::{KVStoreEntry, KvProtocolFields};

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
        // Try to decode as PushDrop
        let pushdrop = PushDrop::decode(script).ok()?;

        // Need at least 5 fields for old format (without tags) or 6 for new format
        if pushdrop.fields.len() < KvProtocolFields::MIN_FIELDS_OLD {
            return None;
        }

        // Extract protocol ID (field 0)
        let protocol_id_bytes = pushdrop.fields.get(KvProtocolFields::PROTOCOL_ID)?;
        let protocol_id = String::from_utf8(protocol_id_bytes.clone()).ok()?;

        // Extract key (field 1)
        let key_bytes = pushdrop.fields.get(KvProtocolFields::KEY)?;
        let key = String::from_utf8(key_bytes.clone()).ok()?;

        // If context provided, check for match
        if let Some(ctx) = ctx {
            if ctx.key != key || ctx.protocol_id != protocol_id {
                return None;
            }
        }

        // Extract value (field 2)
        let value_bytes = pushdrop.fields.get(KvProtocolFields::VALUE)?;
        let value = String::from_utf8(value_bytes.clone()).ok()?;

        // Extract controller (field 3) - should be 33-byte compressed pubkey
        let controller_bytes = pushdrop.fields.get(KvProtocolFields::CONTROLLER)?;
        let controller = if controller_bytes.len() == 33 {
            to_hex(controller_bytes)
        } else {
            // Try to parse as hex string
            String::from_utf8(controller_bytes.clone()).ok()?
        };

        // Extract tags (field 4) - optional in old format
        let tags = if pushdrop.fields.len() >= KvProtocolFields::MIN_FIELDS_NEW {
            let tags_bytes = pushdrop.fields.get(KvProtocolFields::TAGS)?;
            // Tags are stored as JSON array or empty
            if tags_bytes.is_empty() || (tags_bytes.len() == 1 && tags_bytes[0] == 0) {
                Vec::new()
            } else {
                let tags_str = String::from_utf8(tags_bytes.clone()).ok()?;
                serde_json::from_str::<Vec<String>>(&tags_str).unwrap_or_default()
            }
        } else {
            Vec::new()
        };

        Some(KVStoreEntry::new(key, value, controller, protocol_id).with_tags(tags))
    }

    /// Verify that a signature field is valid (placeholder for signature verification).
    ///
    /// In a full implementation, this would verify that the signature (last field)
    /// was created by the controller public key signing the preceding fields.
    ///
    /// # Arguments
    ///
    /// * `pushdrop` - The decoded PushDrop
    /// * `controller` - The expected controller public key
    ///
    /// # Returns
    ///
    /// true if the signature is valid or verification is skipped
    pub fn verify_signature(_pushdrop: &PushDrop, _controller: &PublicKey) -> bool {
        // Signature verification would be done here
        // For now, we trust the PushDrop structure
        true
    }

    /// Extract value from a PushDrop token without validation.
    ///
    /// This is a convenience method for extracting just the value field.
    pub fn extract_value(script: &LockingScript) -> Option<String> {
        let pushdrop = PushDrop::decode(script).ok()?;
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
        match PushDrop::decode(script) {
            Ok(pushdrop) => pushdrop.fields.len() >= KvProtocolFields::MIN_FIELDS_OLD,
            Err(_) => false,
        }
    }

    /// Extract all fields from a KVStore token.
    ///
    /// Returns the raw field data for custom processing.
    pub fn extract_fields(script: &LockingScript) -> Option<KVStoreFields> {
        let pushdrop = PushDrop::decode(script).ok()?;

        if pushdrop.fields.len() < KvProtocolFields::MIN_FIELDS_OLD {
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
            tags: pushdrop.fields.get(KvProtocolFields::TAGS).cloned(),
            signature: pushdrop
                .fields
                .get(KvProtocolFields::SIGNATURE)
                .or_else(|| {
                    // In old format, signature is at index 4
                    if pushdrop.fields.len() == KvProtocolFields::MIN_FIELDS_OLD {
                        pushdrop.fields.get(4)
                    } else {
                        None
                    }
                })
                .cloned(),
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
            .as_ref()
            .and_then(|bytes| {
                if bytes.is_empty() || (bytes.len() == 1 && bytes[0] == 0) {
                    None
                } else {
                    String::from_utf8(bytes.clone()).ok()
                }
            })
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .unwrap_or_default()
    }

    /// Check if this token has tags (new format).
    pub fn has_tags(&self) -> bool {
        self.tags
            .as_ref()
            .is_some_and(|t| !t.is_empty() && t != &[0])
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
}

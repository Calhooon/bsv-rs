//! KVStore token interpreter.
//!
//! Extracts key-value data from transaction outputs to build
//! the history of an entry. Supports both old format (4 fields without tags)
//! and new format (5 fields with tags).

use crate::primitives::{to_hex, PublicKey};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::transaction::Transaction;
use crate::wallet::{Counterparty, ProtoWallet, SecurityLevel, VerifySignatureArgs};
use std::sync::OnceLock;

use super::types::{KVStoreEntry, KVStoreQuery, KvProtocolFields};

/// Cached "anyone" wallet for signature verification.
static ANYONE_WALLET: OnceLock<ProtoWallet> = OnceLock::new();

/// Returns a cached "anyone" wallet for signature verification.
fn get_anyone_wallet() -> &'static ProtoWallet {
    ANYONE_WALLET.get_or_init(ProtoWallet::anyone)
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
    /// None otherwise. A valid token is one the controller it names signed
    /// and locked as its writer does; see [`interpret_script`](Self::interpret_script).
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
    /// Extracts KVStoreEntry from a PushDrop locking script if valid: the
    /// controller (field 3, a 33-byte key) signed the bytes of the fields
    /// before the signature (the last field) in the form whose signature
    /// binds the key, the one `GlobalKVStore::set` writes: the protocol ID
    /// as canonical JSON `[level, name]`, the entry's key as key ID, locked
    /// with the controller's key linked to `anyone`. Any other token is
    /// `None`, the form this crate's writer wrote before (the raw protocol
    /// ID, the key ID `kvstore-token`) among them. A context's plain
    /// protocol name matches a token's `[1, name]`.
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

        // If context provided, check for match: the store's string
        // configuration denotes an App protocol, written as [1, name].
        if let Some(ctx) = ctx {
            let protocol_matches = ctx.protocol_id == protocol_id
                || serde_json::from_str::<(u8, String)>(&protocol_id).is_ok_and(|(level, name)| {
                    level == SecurityLevel::App.as_u8() && name == ctx.protocol_id
                });
            if ctx.key != key || !protocol_matches {
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

        // The controller signed the token in the key-bound form and its
        // writer locked it (#544's interpreter site): any other is no entry.
        if !super::token_validation::authenticated(&pushdrop) {
            return None;
        }

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

    /// Verify that a signature field is valid.
    ///
    /// Verifies that the signature was created by the controller public key
    /// signing the concatenated fields (protocol_id + key + value + controller [+ tags])
    /// in the form whose signature binds the key: the protocol field as
    /// canonical JSON `[level, name]`, the key as key ID, the locking key the
    /// controller's linked to `anyone` under that protocol and key. A token
    /// of this crate's earlier form (the raw protocol text, the key ID
    /// `kvstore-token`) answers `false`.
    ///
    /// # Arguments
    ///
    /// * `fields` - The extracted KVStore fields
    /// * `protocol_id` - The protocol the token must name: `[level, name]`
    ///   or a plain name at level 1, compared trimmed and lowercase
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
        // A five-field token's field 4 is its signature, not tags.
        if let Some(tags) = fields
            .tags
            .as_ref()
            .filter(|t| fields.signature.as_ref() != Some(t))
        {
            if !tags.is_empty() && tags != &[0u8] {
                data.extend_from_slice(tags);
            }
        }

        // The one derivation every judging door uses; the protocol field
        // must name the protocol asked.
        let Some((protocol, key_id)) = super::token_derivation::derivation(
            &fields.protocol_id,
            &fields.key,
            &controller_pubkey,
            &fields.locking_public_key,
            Some(protocol_id),
        ) else {
            return false;
        };
        let args = VerifySignatureArgs {
            data: Some(data),
            hash_to_directly_verify: None,
            signature,
            protocol_id: protocol,
            key_id,
            counterparty: Some(Counterparty::Other(controller_pubkey)),
            for_self: Some(false), // Verify counterparty's signature
        };

        // Use the "anyone" wallet for verification
        let wallet = get_anyone_wallet();
        wallet.verify_signature(args).is_ok_and(|r| r.valid)
    }

    /// Legacy verify_signature that takes PushDrop and PublicKey.
    ///
    /// `true` only when `pushdrop` carries a KVStore token of five or six
    /// fields whose controller field is `controller` and whose signature
    /// field is `controller`'s signature over the other fields; `false` for
    /// anything else.
    #[deprecated(note = "A signature verdict alone, for a token in the key-bound form only")]
    pub fn verify_signature_legacy(pushdrop: &PushDrop, controller: &PublicKey) -> bool {
        super::legacy_signature::signed_by(pushdrop, controller, get_anyone_wallet())
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

    /// The reference's `#entryMatchesQuery` (`ts-stack@edf6e03`
    /// `packages/sdk/src/kvstore/GlobalKVStore.ts:663-685`): the query's key,
    /// controller (case-insensitive), protocol and tags (all/any mode) must all
    /// be satisfied by a decoded entry, else it is dropped. The overlay
    /// resolver's answer is the untrusted host's, so a selector query is
    /// re-checked here before an entry is returned.
    pub(crate) fn entry_matches_query(entry: &KVStoreEntry, query: &KVStoreQuery) -> bool {
        if let Some(key) = &query.key {
            if &entry.key != key {
                return false;
            }
        }
        if let Some(controller) = &query.controller {
            if !entry.controller.eq_ignore_ascii_case(controller) {
                return false;
            }
        }
        if let Some(protocol) = &query.protocol_id {
            // The entry's protocol is the token's raw `[level, name]` text; the
            // query names the App-namespace name (or the same raw text), as the
            // context match above reads it.
            let matches = &entry.protocol_id == protocol
                || serde_json::from_str::<(u8, String)>(&entry.protocol_id).is_ok_and(
                    |(level, name)| level == SecurityLevel::App.as_u8() && &name == protocol,
                );
            if !matches {
                return false;
            }
        }
        if let Some(tags) = &query.tags {
            let present: std::collections::HashSet<&String> = entry.tags.iter().collect();
            let all_mode = query.tag_query_mode.as_deref().unwrap_or("all") == "all";
            // `all`: drop if any queried tag is absent; `any`: drop if all are
            // absent (the reference's `some`/`every` over the presence flags).
            let fails = if all_mode {
                tags.iter().any(|tag| !present.contains(tag))
            } else {
                tags.iter().all(|tag| !present.contains(tag))
            };
            if fails {
                return false;
            }
        }
        true
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
    use crate::wallet::{KeyDeriverApi, Protocol};

    fn create_test_token(
        protocol_id: &str,
        key: &str,
        value: &str,
        controller: &PrivateKey,
        tags: Option<Vec<String>>,
    ) -> LockingScript {
        let mut fields = vec![
            serde_json::to_vec(&(1u8, protocol_id)).unwrap(),
            key.as_bytes().to_vec(),
            value.as_bytes().to_vec(),
            controller.public_key().to_compressed().to_vec(),
        ];

        if let Some(tags) = tags {
            let tags_json = serde_json::to_string(&tags).unwrap();
            fields.push(tags_json.as_bytes().to_vec());
        }

        // Signed and locked as GlobalKVStore::set does (the key-bound form)
        let wallet = ProtoWallet::new(Some(controller.clone()));
        let protocol = Protocol::new(SecurityLevel::App, protocol_id);
        let signature = wallet
            .create_signature(crate::wallet::CreateSignatureArgs {
                data: Some(fields.concat()),
                hash_to_directly_sign: None,
                protocol_id: protocol.clone(),
                key_id: key.to_string(),
                counterparty: Some(Counterparty::Anyone),
            })
            .unwrap()
            .signature;
        fields.push(signature);
        let lock = wallet
            .key_deriver()
            .derive_public_key(&protocol, key, &Counterparty::Anyone, true)
            .unwrap();
        PushDrop::new(lock, fields).lock()
    }

    #[test]
    fn test_interpret_basic_token() {
        let privkey = PrivateKey::random();

        let script = create_test_token("kvstore", "my_key", "my_value", &privkey, None);

        let entry = KVStoreInterpreter::interpret_script(&script, None);
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.key, "my_key");
        assert_eq!(entry.value, "my_value");
        assert_eq!(entry.protocol_id, r#"[1,"kvstore"]"#);
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_interpret_token_with_tags() {
        let privkey = PrivateKey::random();

        let tags = vec!["tag1".to_string(), "tag2".to_string()];
        let script = create_test_token(
            "kvstore",
            "my_key",
            "my_value",
            &privkey,
            Some(tags.clone()),
        );

        let entry = KVStoreInterpreter::interpret_script(&script, None);
        assert!(entry.is_some());

        let entry = entry.unwrap();
        assert_eq!(entry.tags, tags);
    }

    #[test]
    fn test_interpret_with_context_match() {
        let privkey = PrivateKey::random();

        let script = create_test_token("kvstore", "my_key", "my_value", &privkey, None);

        let ctx = KVStoreContext::new("my_key", "kvstore");
        let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
        assert!(entry.is_some());
    }

    #[test]
    fn test_interpret_with_context_no_match() {
        let privkey = PrivateKey::random();

        let script = create_test_token("kvstore", "my_key", "my_value", &privkey, None);

        let ctx = KVStoreContext::new("other_key", "kvstore");
        let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
        assert!(entry.is_none());
    }

    #[test]
    fn test_extract_value() {
        let privkey = PrivateKey::random();

        let script = create_test_token("kvstore", "my_key", "the_value", &privkey, None);

        let value = KVStoreInterpreter::extract_value(&script);
        assert_eq!(value, Some("the_value".to_string()));
    }

    #[test]
    fn test_is_kvstore_token() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let script = create_test_token("kvstore", "key", "value", &privkey, None);
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
        let script = create_test_token(
            "kvstore",
            "my_key",
            "my_value",
            &privkey,
            Some(tags.clone()),
        );

        let fields = KVStoreInterpreter::extract_fields(&script);
        assert!(fields.is_some());

        let fields = fields.unwrap();
        assert_eq!(
            fields.protocol_id_string(),
            Some(r#"[1,"kvstore"]"#.to_string())
        );
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

    // ── entry_matches_query: the selector re-check on an overlay host's answer ──
    // `entry_matches_query` is `pub(crate)`, so the integration suite cannot call
    // it directly. On the real query path a keyed query is pre-filtered by
    // `interpret`'s context and the writer stores the bare protocol name, so four
    // of its guards are never exercised through the door. These unit tests reach
    // each guard directly so none is a line the suite cannot see fail.
    fn q() -> KVStoreQuery {
        KVStoreQuery::new()
    }

    fn kv(key: &str, controller: &str, protocol_id: &str, tags: &[&str]) -> KVStoreEntry {
        KVStoreEntry::new(key, "v", controller, protocol_id)
            .with_tags(tags.iter().map(|t| (*t).to_string()).collect())
    }

    #[test]
    fn entry_matches_query_empty_query_keeps_every_entry() {
        let e = kv("k", "02aa", "kvstore", &["x"]);
        assert!(KVStoreInterpreter::entry_matches_query(&e, &q()));
    }

    #[test]
    fn entry_matches_query_key_guard_drops_a_mismatched_key() {
        // Reachable only here: on the real path `interpret`'s context already drops
        // a wrong-key entry before this function is called, so the integration
        // suite never exercises this guard (it mirrors the reference's key check).
        let e = kv("k1", "02aa", "kvstore", &[]);
        assert!(KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_key("k1")
        ));
        assert!(!KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_key("k2")
        ));
    }

    #[test]
    fn entry_matches_query_controller_compare_is_case_insensitive() {
        // Reference parity (`entry.controller.toLowerCase() !== query...toLowerCase()`):
        // the same key in another case still matches; a different key does not.
        let e = kv("k", "02abcdef", "kvstore", &[]);
        assert!(KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_controller("02ABCDEF")
        ));
        assert!(!KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_controller("03abcdef")
        ));
    }

    #[test]
    fn entry_matches_query_protocol_matches_the_writers_bare_name() {
        // `set_internal` writes field 0 as the bare protocol name; the exact-string
        // disjunct keeps such a token under a matching protocol selector (removing
        // it would wrongly drop this crate's own written tokens).
        let e = kv("k", "02aa", "kvstore", &[]);
        assert!(KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_protocol_id("kvstore")
        ));
        assert!(!KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_protocol_id("otherproto")
        ));
    }

    #[test]
    fn entry_matches_query_protocol_matches_the_app_level_tuple() {
        // A token whose field 0 is the reference's `[level, name]` JSON matches the
        // bare-name selector only at the App security level (level 1).
        let app = kv("k", "02aa", "[1,\"kvstore\"]", &[]);
        assert!(KVStoreInterpreter::entry_matches_query(
            &app,
            &q().with_protocol_id("kvstore")
        ));
        let non_app = kv("k", "02aa", "[2,\"kvstore\"]", &[]);
        assert!(!KVStoreInterpreter::entry_matches_query(
            &non_app,
            &q().with_protocol_id("kvstore")
        ));
    }

    #[test]
    fn entry_matches_query_tag_mode_defaults_to_all() {
        // Reference parity (`query.tagQueryMode ?? 'all'`): with no mode set, every
        // queried tag must be present, so a missing tag drops the entry.
        let e = kv("k", "02aa", "kvstore", &["a"]);
        assert!(KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_tags(vec!["a".to_string()])
        ));
        assert!(!KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_tags(vec!["a".to_string(), "b".to_string()])
        ));
    }

    #[test]
    fn entry_matches_query_tag_any_mode_keeps_on_one_present_tag() {
        let e = kv("k", "02aa", "kvstore", &["a"]);
        assert!(KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_tags(vec!["a".to_string(), "b".to_string()])
                .with_tag_query_mode("any")
        ));
        assert!(!KVStoreInterpreter::entry_matches_query(
            &e,
            &q().with_tags(vec!["c".to_string()])
                .with_tag_query_mode("any")
        ));
    }
}

//! The byte fields of a wallet's JSON body read as the reference's
//! `HTTPWalletJSON` reads them (#339, #365; `ts-stack@edf6e03`
//! `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:322-341`): every
//! own member named in `walletByteFieldNames`, at any depth, through
//! `normalizeBRC100ByteArray` (`BRC100ByteEncoding.ts:5-23`, `:81-86`,
//! `:164-190`), then each byte field a success answer carries refused in
//! `bytes`' words when it is no array of bytes
//! (`WalletResultValidation.ts:868-906`, `:2179-2300`).

#[cfg(feature = "http")]
use crate::Error;
use serde_json::Value;

/// The wallet substrates' one byte bound (#526): the reference's
/// `MAX_WALLET_WIRE_FRAME_BYTES` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/substrates/WalletWire.ts:9`), read by
/// `validateWalletResult` (`WalletResultValidation.ts:632-636`, `:680-733`,
/// `:873-879`): `bytes`' default bound here and in `result_values/bytes.rs`,
/// and the request, response and total-byte caps of
/// `result_values/boundary.rs`, `raw_tree.rs` and `wire.rs`.
pub(super) const MAX_BYTES: usize = 256 * 1024 * 1024;

/// `walletByteFieldNames` (`BRC100ByteEncoding.ts:5-23`).
#[cfg(feature = "http")]
const WALLET_BYTE_FIELD_NAMES: [&str; 17] = [
    "BEEF",
    "atomicBEEF",
    "beef",
    "ciphertext",
    "competingBeef",
    "data",
    "encryptedLinkage",
    "encryptedLinkageProof",
    "hashToDirectlySign",
    "hashToDirectlyVerify",
    "hmac",
    "inputBEEF",
    "payload",
    "plaintext",
    "signature",
    "transaction",
    "tx",
];

/// A call, a field's path in its result, and whether its absence is refused
/// where its holder is present.
#[cfg(feature = "http")]
type ResultByteField = (&'static str, &'static [&'static str], bool);

/// The byte fields `validateWalletResult` reads from a call's result, in
/// its order per call, each with whether its absence is refused
/// (`bytes(undefined)`) or skipped (`result.tx === undefined ? ..`): the
/// actions' `tx` (`validateActionResult`, `:1242-1273`; the signable
/// transaction's required when the member is an object, `:1271-1272`,
/// skipped when it is absent), the four key calls'
/// (`:2210-2225`), the linkages' (`validateKeyLinkage`, `:2163-2173`) and
/// listOutputs' `BEEF` (`:2082`).
#[cfg(feature = "http")]
const RESULT_BYTE_FIELDS: [ResultByteField; 10] = [
    ("createAction", &["tx"], false),
    ("createAction", &["signableTransaction", "tx"], true),
    ("signAction", &["tx"], false),
    ("encrypt", &["ciphertext"], true),
    ("decrypt", &["plaintext"], true),
    ("createHmac", &["hmac"], true),
    ("createSignature", &["signature"], true),
    ("revealCounterpartyKeyLinkage", &["encryptedLinkage"], true),
    (
        "revealCounterpartyKeyLinkage",
        &["encryptedLinkageProof"],
        true,
    ),
    ("listOutputs", &["BEEF"], false),
];

/// `revealSpecificKeyLinkage` reads the linkage as its sibling does.
#[cfg(feature = "http")]
fn byte_fields_of(call: &str) -> impl Iterator<Item = &'static ResultByteField> + '_ {
    let call = match call {
        "revealSpecificKeyLinkage" => "revealCounterpartyKeyLinkage",
        other => other,
    };
    RESULT_BYTE_FIELDS.iter().filter(move |(c, ..)| *c == call)
}

/// `normalizeBRC100WalletByteFields` (`BRC100ByteEncoding.ts:164-190`):
/// each member of a wallet byte field's name that [`byte_array`] reads is
/// replaced by its array of bytes; every other value is walked, a byte
/// field it does not read included.
#[cfg(feature = "http")]
pub(super) fn normalize(body: &mut Value) {
    let mut pending = vec![body];
    while let Some(candidate) = pending.pop() {
        match candidate {
            Value::Array(items) => pending.extend(items.iter_mut()),
            Value::Object(members) => {
                for (key, field) in members.iter_mut() {
                    if WALLET_BYTE_FIELD_NAMES.contains(&key.as_str()) {
                        if let Some(bytes) = byte_array(field) {
                            *field = Value::from(bytes);
                            continue;
                        }
                    }
                    pending.push(field);
                }
            }
            _ => {}
        }
    }
}

/// The first byte field of `call`'s normalized answer that is no array of
/// bytes, refused in `bytes`' words (`invalid(call, field, 'an array of
/// bytes')`, `WalletResultValidation.ts:510-512`, `:897`).
#[cfg(feature = "http")]
pub(super) fn refusal(call: &str, body: &Value) -> Option<Error> {
    byte_fields_of(call).find_map(|&(_, path, required)| {
        let (last, members) = path.split_last()?;
        let holder = members.iter().try_fold(body, |v, k| v.get(k))?;
        match holder.get(last) {
            None if !required => None,
            Some(value) if byte_array(value).is_some() => None,
            _ => Some(Error::WalletError(format!(
                "Invalid {call} result {}: expected an array of bytes",
                path.join(".")
            ))),
        }
    })
}

/// `normalizeBRC100ByteArray` (`BRC100ByteEncoding.ts:81-86`), then
/// `bytes(value, call, field)` (`WalletResultValidation.ts:868-906`): an
/// array of integers 0 to 255, or the historical object form, at most 256 MiB.
pub(super) fn byte_array(value: &Value) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = match value {
        Value::Array(items) if items.len() <= MAX_BYTES => {
            items.iter().map(byte).collect::<Option<_>>()?
        }
        Value::Object(_) => historical_bytes(value)?,
        _ => return None,
    };
    (bytes.len() <= MAX_BYTES).then_some(bytes)
}

/// `normalizeHistoricalByteObject` (`BRC100ByteEncoding.ts:52-71`): the
/// object `JSON.stringify(new Uint8Array(..))` writes, at least one key, its
/// keys exactly `"0"` to `"n-1"`, each a byte. `Object.keys` lists integer
/// keys ascending whatever their order in the text, so each index is looked
/// up; `n` keys holding every index below `n` are exactly those. An empty
/// object is refused, as the reference's walker leaves it.
fn historical_bytes(value: &Value) -> Option<Vec<u8>> {
    let keys = value.as_object().filter(|keys| !keys.is_empty())?;
    (0..keys.len())
        .map(|i| keys.get(&i.to_string()).and_then(byte))
        .collect()
}

/// `isByte` (`BRC100ByteEncoding.ts:32-34`): `Number.isInteger` from 0 to
/// 255, so `1.0` and `-0` are bytes as `JSON.parse` reads them.
fn byte(value: &Value) -> Option<u8> {
    if let Some(n) = value.as_u64() {
        return u8::try_from(n).ok();
    }
    // an integral float in range: the first byte not below it is its value
    let n = (value.as_f64()).filter(|n| (0.0..=255.0).contains(n) && n.fract() == 0.0)?;
    (0..=u8::MAX).find(|&b| f64::from(b) >= n)
}

#[cfg(all(test, feature = "http"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_historical_object_form_is_read_by_its_indexes_in_any_text_order() {
        let read = |text: &str| byte_array(&serde_json::from_str(text).unwrap());
        assert_eq!(read(r#"{"0":1,"1":2,"2":255}"#), Some(vec![1, 2, 255]));
        assert_eq!(read(r#"{"2":255,"0":1,"1":2}"#), Some(vec![1, 2, 255]));
        // a repeated key is its last value, as JSON.parse keeps it
        assert_eq!(read(r#"{"0":9,"0":1}"#), Some(vec![1]));
        assert_eq!(read("[1,2,255]"), Some(vec![1, 2, 255]));
        assert_eq!(read("[]"), Some(vec![]));
        // `Number.isInteger`: an integral float and negative zero are bytes
        assert_eq!(read("[1.0,-0.0,2e0]"), Some(vec![1, 0, 2]));
        assert_eq!(read(r#"{"0":255.0}"#), Some(vec![255]));
        // the integer text `-0` (#365)
        assert_eq!(read(r#"{"0":-0,"1":1}"#), Some(vec![0, 1]));
        assert_eq!(read("[-0]"), Some(vec![0]));
    }

    #[test]
    fn an_object_not_the_historical_form_is_refused() {
        for text in [
            "{}",
            r#"{"1":1}"#,
            r#"{"0":1,"2":2}"#,
            r#"{"00":1}"#,
            r#"{"0":1,"01":2}"#,
            r#"{"0":1,"length":1}"#,
            r#"{"0":256}"#,
            r#"{"0":-1}"#,
            r#"{"0":"1"}"#,
            r#"{"0":null}"#,
            r#"{"0":1.5}"#,
        ] {
            assert_eq!(
                byte_array(&serde_json::from_str(text).unwrap()),
                None,
                "{text}"
            );
        }
        assert_eq!(byte_array(&json!("0102")), None);
        assert_eq!(byte_array(&json!([1, 256])), None);
    }

    #[test]
    fn the_walk_reads_a_byte_field_at_any_depth_and_nothing_else() {
        let mut body = json!({
            "ciphertext": {"0": 1},
            "signableTransaction": {"tx": [2.0], "reference": "UlJS"},
            "outputs": [{"customInstructions": {"0": 3}, "payload": {"0": 4}}],
            "header": {"0": 5},
            "tx": {"0": 256, "inner": {"data": {"0": 6}}},
            "beef": "0102",
        });
        normalize(&mut body);
        assert_eq!(
            body,
            json!({
                "ciphertext": [1],
                "signableTransaction": {"tx": [2], "reference": "UlJS"},
                "outputs": [{"customInstructions": {"0": 3}, "payload": [4]}],
                "header": {"0": 5},
                "tx": {"0": 256, "inner": {"data": [6]}},
                "beef": "0102",
            })
        );
    }

    #[test]
    fn a_result_byte_field_is_refused_by_its_path_and_an_absent_optional_one_is_not() {
        let refused = |words: &str| Some(Error::WalletError(words.into()));
        assert_eq!(refusal("createAction", &json!({"txid": "aa"})), None);
        assert_eq!(
            refusal(
                "createAction",
                &json!({"signableTransaction": {"reference": "UlJS"}})
            ),
            refused(
                "Invalid createAction result signableTransaction.tx: expected an array of bytes"
            )
        );
        assert_eq!(
            refusal("createAction", &json!({"signableTransaction": {"tx": {}}})),
            refused(
                "Invalid createAction result signableTransaction.tx: expected an array of bytes"
            )
        );
        assert_eq!(
            refusal("encrypt", &json!({})),
            refused("Invalid encrypt result ciphertext: expected an array of bytes")
        );
        assert_eq!(
            refusal(
                "revealSpecificKeyLinkage",
                &json!({"encryptedLinkage": [1]})
            ),
            refused(
                "Invalid revealSpecificKeyLinkage result encryptedLinkageProof: \
                 expected an array of bytes"
            )
        );
        assert_eq!(refusal("listActions", &json!({"tx": 1})), None);
    }
}

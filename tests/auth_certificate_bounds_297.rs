//! The reference's remaining certificate bounds and its decrypt wrappers
//! (#297), each case's verdict the reference's at `ts-stack@edf6e03` under
//! Node v22.18.0 (`tests/support/certificate_bounds_297.mjs`,
//! `tests/vectors/auth_certificate_bounds_297.json`):
//!
//! - `Certificate.toBinary`'s snapshot: at most 100,000 fields, each name 1
//!   to 50 bytes and none of `__proto__`, `constructor`, `prototype`
//!   (`Certificate.ts:44-129`); `fromBinary`'s count, its share of the bytes
//!   and the declared name length (`:356-374`);
//! - the `MasterCertificate` constructor (`MasterCertificate.ts:195-233`):
//!   100 entries, safe names, a keyring entry for every field, each entry
//!   canonical base64 of 1 to 2048 bytes;
//! - `createCertificateFields`: a plaintext of at most 64 KiB, the wallet's
//!   ciphertext at most 2048 bytes (`:254-305`);
//! - decryption: the plaintext at most 64 KiB (and at least a byte on the
//!   master's side, `denseBytes`, `:612-616`), the keyring entries at most
//!   2048 bytes, and the wrappers a caller sees: `Failed to decrypt
//!   certificate field!` (`:621-623`), `Failed to decrypt all master
//!   certificate fields.` (`:559-561`), `Failed to decrypt selectively
//!   revealed certificate fields using keyring: <words>`
//!   (`VerifiableCertificate.ts:214-217`), the cipher's words in it the
//!   reference's (`Decryption failed!`, `Ciphertext too short`,
//!   `SymmetricKey.ts:205`, `:217`, `:232`) and the verifier's revelation key
//!   exactly 32 bytes (`VerifiableCertificate.ts:203`).
//!
//! A verdict does not depend on a field key's or IV's randomness: each side
//! builds its input from the case's parameters under the same keys.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::{Certificate, MasterCertificate, VerifiableCertificate};
use bsv_rs::primitives::{
    from_base64, from_hex, sha256, to_base64, to_hex, PrivateKey, SymmetricKey,
};
use bsv_rs::wallet::*;
use indexmap::IndexMap;
use serde_json::{json, Value};

const SITES: [(&str, usize); 8] = [
    ("to_binary", 10),
    ("from_binary", 7),
    ("master_new", 11),
    ("create_certificate_fields", 5),
    ("master_decrypt_field", 6),
    ("master_decrypt_fields", 6),
    ("create_keyring_for_verifier", 10),
    ("verifiable_decrypt_fields", 17),
];

fn vector() -> Vec<Value> {
    let text = include_str!("vectors/auth_certificate_bounds_297.json");
    let v: Value = serde_json::from_str(text).unwrap();
    assert_eq!(v["reference"], "ts-stack@edf6e03 packages/sdk");
    v["cases"].as_array().unwrap().clone()
}

fn cases(site: &str) -> Vec<Value> {
    vector().into_iter().filter(|c| c["site"] == site).collect()
}

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32]).unwrap()
}

/// Certifier 43, subject 47, verifier 41.
fn certifier() -> PrivateKey {
    key(43)
}
fn subject() -> PrivateKey {
    key(47)
}
fn verifier() -> PrivateKey {
    key(41)
}
const SERIAL: [u8; 32] = [2; 32];

fn certificate(fields: IndexMap<String, String>) -> Certificate {
    Certificate::new(
        [1; 32],
        SERIAL,
        subject().public_key(),
        certifier().public_key(),
    )
    .with_fields(fields)
}

/// The base64 text of `n` bytes of 0x41.
fn b64(n: usize) -> String {
    to_base64(&vec![0x41; n])
}

/// A verdict as the vector writes it: the value, or the words refused in.
fn verdict(result: bsv_rs::Result<Value>) -> Value {
    match result {
        Ok(v) => json!({ "ok": v }),
        Err(bsv_rs::Error::CertificateValidationError(words)) => json!({ "error": words }),
        Err(other) => json!({ "error": format!("not a certificate refusal: {other:?}") }),
    }
}

fn sha(bytes: &[u8]) -> Value {
    Value::String(to_hex(&sha256(bytes)))
}

/// A `ProtoWallet` whose `encrypt` answers `n` bytes of 0x41, and whose
/// `decrypt` answers `decrypted` bytes of 0x41 when set.
struct Bloated {
    inner: ProtoWallet,
    n: usize,
    decrypted: Option<usize>,
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! bloated {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Bloated {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> bsv_rs::Result<$result> {
                WalletInterface::$method(&self.inner, args, o).await
            })*

            async fn encrypt(&self, _: EncryptArgs, _: Option<&str>) -> bsv_rs::Result<EncryptResult> {
                Ok(EncryptResult { ciphertext: vec![0x41; self.n] })
            }
            async fn decrypt(&self, args: DecryptArgs, o: Option<&str>) -> bsv_rs::Result<DecryptResult> {
                match self.decrypted {
                    Some(n) => Ok(DecryptResult { plaintext: vec![0x41; n] }),
                    None => WalletInterface::decrypt(&self.inner, args, o).await,
                }
            }
            async fn is_authenticated(&self, o: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> {
                WalletInterface::is_authenticated(&self.inner, o).await
            }
            async fn wait_for_authentication(
                &self,
                o: Option<&str>,
            ) -> bsv_rs::Result<AuthenticatedResult> {
                WalletInterface::wait_for_authentication(&self.inner, o).await
            }
            async fn get_height(&self, o: Option<&str>) -> bsv_rs::Result<GetHeightResult> {
                WalletInterface::get_height(&self.inner, o).await
            }
            async fn get_network(&self, o: Option<&str>) -> bsv_rs::Result<GetNetworkResult> {
                WalletInterface::get_network(&self.inner, o).await
            }
            async fn get_version(&self, o: Option<&str>) -> bsv_rs::Result<GetVersionResult> {
                WalletInterface::get_version(&self.inner, o).await
            }
        }
    };
}

bloated! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (create_action, CreateActionArgs, CreateActionResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (prove_certificate, ProveCertificateArgs, ProveCertificateResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult),
}

fn spec(s: &Value) -> String {
    match s.get("text") {
        Some(text) => text.as_str().unwrap().to_string(),
        None => b64(s["bytes"].as_u64().unwrap() as usize),
    }
}

fn record(entries: &Value) -> IndexMap<String, String> {
    entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e[0].as_str().unwrap().to_string(), spec(&e[1])))
        .collect()
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, "certificate field encryption")
}

/// One field `name` of `plaintext` bytes of 0x41, its key in the master
/// keyring (certifier to subject, key ID `name`) and the verifier's
/// (subject to verifier, `<serial> name`), as the script builds it.
struct Issued {
    fields: IndexMap<String, String>,
    master_keyring: IndexMap<String, String>,
    verifier_keyring: IndexMap<String, String>,
}

/// `revelation_key` encrypted by `from`'s wallet to `to` under `key_id`.
async fn encrypt_key(
    revelation_key: &[u8],
    from: PrivateKey,
    key_id: String,
    to: PrivateKey,
) -> String {
    let args = EncryptArgs {
        plaintext: revelation_key.to_vec(),
        protocol_id: protocol(),
        key_id,
        counterparty: Some(Counterparty::Other(to.public_key())),
        ..Default::default()
    };
    let wallet = ProtoWallet::new(Some(from));
    to_base64(
        &WalletInterface::encrypt(&wallet, args, Some("test"))
            .await
            .unwrap()
            .ciphertext,
    )
}

async fn issued(plaintext: usize) -> Issued {
    let field_key = SymmetricKey::random();
    let field = to_base64(&field_key.encrypt(&vec![0x41; plaintext]).unwrap());
    let revelation_key = field_key.as_bytes();
    let serial_name = format!("{} name", to_base64(&SERIAL));
    Issued {
        fields: IndexMap::from([("name".into(), field)]),
        master_keyring: IndexMap::from([(
            "name".into(),
            encrypt_key(revelation_key, certifier(), "name".into(), subject()).await,
        )]),
        verifier_keyring: IndexMap::from([(
            "name".into(),
            encrypt_key(revelation_key, subject(), serial_name, verifier()).await,
        )]),
    }
}

/// The case's input applied to the issued records, as the script's mutators.
fn mutate(c: &mut Issued, input: &Value) {
    if let Some(n) = input["master_keyring_entry_bytes"].as_u64() {
        c.master_keyring.insert("name".into(), b64(n as usize));
    }
    if input["master_keyring_empty"] == true {
        c.master_keyring.clear();
    }
    if input["field_text_unpadded"] == true {
        let text = c.fields["name"].trim_end_matches('=').to_string();
        c.fields.insert("name".into(), text);
    }
    if let Some(n) = input["verifier_keyring_entry_bytes"].as_u64() {
        c.verifier_keyring.insert("name".into(), b64(n as usize));
    }
    if input["verifier_keyring_empty"] == true {
        c.verifier_keyring.clear();
    }
    if input["verifier_keyring_entries"].as_u64() == Some(101) {
        for i in 0..100 {
            c.verifier_keyring.insert(format!("f{i}"), b64(48));
        }
    }
    if input["verifier_keyring_ghost"] == true {
        c.verifier_keyring = IndexMap::from([("ghost".into(), b64(48))]);
    }
    if input["verifier_keyring_proto"] == true {
        c.verifier_keyring = IndexMap::from([("__proto__".into(), b64(48))]);
    }
    if input["field_tampered"] == true {
        let mut bytes = from_base64(&c.fields["name"]).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        c.fields.insert("name".into(), to_base64(&bytes));
    }
    if let Some(n) = input["field_ciphertext_bytes"].as_u64() {
        c.fields.insert("name".into(), b64(n as usize));
    }
}

/// The verifier's wallet a case names, as the script's `verifierOf`: the
/// verifier's `ProtoWallet`, another key's, or one whose `decrypt` answers
/// `revelation_key_bytes` bytes of 0x41.
fn verifier_of(input: &Value) -> Bloated {
    let key_byte = input["verifier_wallet_key"]
        .as_u64()
        .map_or(41, |b| b as u8);
    Bloated {
        inner: ProtoWallet::new(Some(key(key_byte))),
        n: 0,
        decrypted: input["revelation_key_bytes"].as_u64().map(|n| n as usize),
    }
}

async fn decrypt_site(site: &str, input: &Value) -> bsv_rs::Result<Value> {
    let mut c = issued(input["plaintext_bytes"].as_u64().unwrap_or(5) as usize).await;
    mutate(&mut c, input);
    let subject_wallet = ProtoWallet::new(Some(subject()));
    let certifier_key = certifier().public_key();
    // A master certificate carrying the records as given: the constructor's
    // checks are not the decrypt sites' (the reference's are static).
    let master = || {
        let mut m = MasterCertificate::new(certificate(IndexMap::new()), IndexMap::new()).unwrap();
        m.certificate.fields = c.fields.clone();
        m.master_keyring = c.master_keyring.clone();
        m
    };
    match site {
        "master_decrypt_field" => master()
            .decrypt_field(
                &subject_wallet,
                &certifier_key,
                "name",
                None,
                None,
                Some("test"),
            )
            .await
            .map(|p| json!(p.len())),
        "master_decrypt_fields" => master()
            .decrypt_fields(&subject_wallet, &certifier_key, None, None, Some("test"))
            .await
            .map(|r| json!(r.len())),
        "create_keyring_for_verifier" => {
            let reveal: Vec<String> = serde_json::from_value(input["reveal"].clone()).unwrap();
            let args = (&c.fields, reveal.as_slice(), &c.master_keyring, &SERIAL);
            let keyring = match input["ciphertext_bytes"].as_u64() {
                Some(n) => {
                    let wallet = Bloated {
                        inner: subject_wallet,
                        n: n as usize,
                        decrypted: None,
                    };
                    MasterCertificate::create_keyring_for_verifier(
                        &wallet,
                        &certifier_key,
                        &verifier().public_key(),
                        args.0,
                        args.1,
                        args.2,
                        args.3,
                        None,
                        None,
                        Some("test"),
                    )
                    .await
                }
                None => {
                    MasterCertificate::create_keyring_for_verifier(
                        &subject_wallet,
                        &certifier_key,
                        &verifier().public_key(),
                        args.0,
                        args.1,
                        args.2,
                        args.3,
                        None,
                        None,
                        Some("test"),
                    )
                    .await
                }
            };
            keyring.map(|k| json!(k.len()))
        }
        "verifiable_decrypt_fields" => {
            let mut v =
                VerifiableCertificate::new(certificate(c.fields.clone()), c.verifier_keyring);
            v.decrypt_fields(&verifier_of(input), None, None, Some("test"))
                .await
                .map(|r| json!(r.values().map(String::len).sum::<usize>()))
        }
        other => panic!("{other}"),
    }
}

async fn run(case: &Value) -> Value {
    let input = &case["input"];
    let result = match case["site"].as_str().unwrap() {
        "to_binary" => {
            let value = input["value"].as_str().unwrap();
            let fields: IndexMap<String, String> = match input["count"].as_u64() {
                Some(n) => (0..n).map(|i| (format!("f{i}"), value.into())).collect(),
                None => input["names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| (n.as_str().unwrap().to_string(), value.into()))
                    .collect(),
            };
            certificate(fields).to_binary(false).map(|b| sha(&b))
        }
        "from_binary" => {
            let bytes = from_hex(input["hex"].as_str().unwrap()).unwrap();
            Certificate::from_binary(&bytes).map(|c| json!(c.fields.len()))
        }
        "master_new" => MasterCertificate::new(
            certificate(record(&input["fields"])),
            record(&input["keyring"]),
        )
        .and_then(|m| m.to_binary(false))
        .map(|b| sha(&b)),
        "create_certificate_fields" => {
            let plaintexts: IndexMap<String, String> = input["plaintexts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    let len = p[1].as_u64().unwrap() as usize;
                    (p[0].as_str().unwrap().to_string(), "A".repeat(len))
                })
                .collect();
            let inner = ProtoWallet::new(Some(certifier()));
            let to = subject().public_key();
            let result = match input["ciphertext_bytes"].as_u64() {
                Some(n) => {
                    let wallet = Bloated {
                        inner,
                        n: n as usize,
                        decrypted: None,
                    };
                    MasterCertificate::create_certificate_fields(
                        &wallet,
                        &to,
                        plaintexts,
                        None,
                        None,
                        Some("test"),
                    )
                    .await
                }
                None => {
                    MasterCertificate::create_certificate_fields(
                        &inner,
                        &to,
                        plaintexts,
                        None,
                        None,
                        Some("test"),
                    )
                    .await
                }
            };
            result.map(|(fields, _)| json!(fields.len()))
        }
        site => decrypt_site(site, input).await,
    };
    verdict(result)
}

async fn assert_site(site: &str) {
    let cases = cases(site);
    let expected = SITES.iter().find(|(s, _)| *s == site).unwrap().1;
    assert_eq!(cases.len(), expected, "{site}: the vector's case count");
    let mut mismatches = Vec::new();
    for case in cases {
        let got = run(&case).await;
        if got != case["verdict"] {
            mismatches.push((case["id"].clone(), got, case["verdict"].clone()));
        }
    }
    assert_eq!(
        mismatches,
        Vec::new(),
        "{site}: (id, this crate, the reference)"
    );
}

#[test]
fn the_vector_holds_every_site_and_both_sides_of_each_bound_297() {
    let all = vector();
    let counted: usize = SITES.iter().map(|(_, n)| n).sum();
    assert_eq!(all.len(), counted);
    for (site, _) in SITES {
        let cases = cases(site);
        assert!(
            cases.iter().any(|c| c["verdict"].get("ok").is_some()),
            "{site}"
        );
        assert!(
            cases.iter().any(|c| c["verdict"].get("error").is_some()),
            "{site}"
        );
    }
}

#[tokio::test]
async fn to_binary_refuses_a_field_count_over_100000_and_a_name_outside_1_to_50_bytes_or_unsafe_297(
) {
    assert_site("to_binary").await;
}

#[tokio::test]
async fn from_binary_refuses_the_field_count_and_name_length_before_reading_as_the_reference_297() {
    assert_site("from_binary").await;
}

#[tokio::test]
async fn the_master_certificate_constructor_refuses_a_keyring_entry_over_2048_bytes_297() {
    assert_site("master_new").await;
}

#[tokio::test]
async fn create_certificate_fields_refuses_a_plaintext_over_64_kib_and_a_keyring_entry_over_2048_297(
) {
    assert_site("create_certificate_fields").await;
}

#[tokio::test]
async fn master_decrypt_field_refuses_every_failure_in_the_reference_wrapper_297() {
    assert_site("master_decrypt_field").await;
}

#[tokio::test]
async fn master_decrypt_fields_refuses_every_failure_in_the_reference_wrapper_297() {
    assert_site("master_decrypt_fields").await;
}

#[tokio::test]
async fn create_keyring_for_verifier_bounds_the_keyring_entries_and_the_fields_to_reveal_297() {
    assert_site("create_keyring_for_verifier").await;
}

#[tokio::test]
async fn verifiable_decrypt_fields_bounds_the_keyring_and_plaintext_and_quotes_the_failure_297() {
    assert_site("verifiable_decrypt_fields").await;
}

#[tokio::test]
async fn verifiable_decrypt_field_quotes_the_failure_as_decrypt_fields_does_297() {
    // The single-field door (this crate's) refuses as `decryptFields`' loop
    // body for that field refuses (`VerifiableCertificate.ts:174-217`).
    let mut c = issued(64 * 1024 + 1).await;
    let v = VerifiableCertificate::new(certificate(c.fields.clone()), c.verifier_keyring.clone());
    let wallet = ProtoWallet::new(Some(verifier()));
    let oversized = "Failed to decrypt selectively revealed certificate fields using keyring: Decrypted certificate field is oversized";
    assert_eq!(
        v.decrypt_field(&wallet, "name", None, None, Some("test"))
            .await,
        Err(bsv_rs::Error::CertificateValidationError(oversized.into()))
    );
    c.verifier_keyring.insert("name".into(), b64(2049));
    let v = VerifiableCertificate::new(certificate(c.fields), c.verifier_keyring);
    assert_eq!(
        v.decrypt_field(&wallet, "name", None, None, Some("test")).await,
        Err(bsv_rs::Error::CertificateValidationError(
            "Failed to decrypt selectively revealed certificate fields using keyring: Certificate keyring field name is empty, oversized, or non-canonical".into()
        ))
    );
}

#[tokio::test]
async fn issue_for_subject_refuses_a_plaintext_over_64_kib_and_issues_one_at_the_bound_297() {
    let issue = |len: usize| async move {
        MasterCertificate::issue_for_subject(
            &ProtoWallet::new(Some(certifier())),
            &certifier(),
            subject().public_key(),
            IndexMap::from([("name".to_string(), "A".repeat(len))]),
            [1; 32],
            Some(SERIAL),
            Some("test"),
        )
        .await
    };
    let at = issue(64 * 1024).await.unwrap();
    assert_eq!(at.verify(), Ok(true));
    assert_eq!(
        issue(64 * 1024 + 1).await.map(drop),
        Err(bsv_rs::Error::CertificateValidationError(
            "Certificate plaintext field name exceeds the maximum of 65536 bytes".into()
        ))
    );
}

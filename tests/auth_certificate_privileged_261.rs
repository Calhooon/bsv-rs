//! The certificate methods carry the reference's `privileged` and
//! `privilegedReason` into every wallet `encrypt` and `decrypt` they make
//! (#261, the owner's word of 2026-10-26: the reference's signature, once):
//! `MasterCertificate.createCertificateFields` (`ts-stack@edf6e03`
//! `MasterCertificate.ts:254-260`, `:289-290`), `createKeyringForVerifier`
//! (`:325-346`, `:390-391`, `:400-401`), `decryptFields` (`:512-519`,
//! `:553-554`) and `decryptField` (`:564-572`, `:596-597`), and
//! `VerifiableCertificate.decryptFields` (`VerifiableCertificate.ts:152-156`,
//! `:197-198`). A recording wallet sees each call's pair.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::{MasterCertificate, VerifiableCertificate};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::*;
use std::collections::HashMap;
use std::sync::Mutex;

const REASON: &str = "prove the field";

/// One wallet call the certificate made: its name and the pair it carried.
type Call = (&'static str, Option<bool>, Option<String>);

/// A ProtoWallet that records the privileged pair of each `encrypt` and
/// `decrypt` it answers.
struct Recording {
    inner: ProtoWallet,
    calls: Mutex<Vec<Call>>,
}

impl Recording {
    fn new(key: &PrivateKey) -> Self {
        Self {
            inner: ProtoWallet::new(Some(key.clone())),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The calls recorded since the last take.
    fn take(&self) -> Vec<Call> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! recording {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Recording {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> bsv_rs::Result<$result> {
                WalletInterface::$method(&self.inner, args, o).await
            })*

            async fn encrypt(&self, args: EncryptArgs, o: Option<&str>) -> bsv_rs::Result<EncryptResult> {
                let call = ("encrypt", args.privileged, args.privileged_reason.clone());
                self.calls.lock().unwrap().push(call);
                WalletInterface::encrypt(&self.inner, args, o).await
            }
            async fn decrypt(&self, args: DecryptArgs, o: Option<&str>) -> bsv_rs::Result<DecryptResult> {
                let call = ("decrypt", args.privileged, args.privileged_reason.clone());
                self.calls.lock().unwrap().push(call);
                WalletInterface::decrypt(&self.inner, args, o).await
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

recording! {
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

/// Every call privileged with the reason, and as many of each kind as named.
fn assert_privileged(calls: &[Call], encrypts: usize, decrypts: usize) {
    let count = |name| calls.iter().filter(|c| c.0 == name).count();
    assert_eq!((count("encrypt"), count("decrypt")), (encrypts, decrypts));
    for call in calls {
        assert_eq!((call.1, call.2.as_deref()), (Some(true), Some(REASON)));
    }
}

struct Parties {
    certifier: PrivateKey,
    subject: PrivateKey,
    verifier: PrivateKey,
}

fn parties() -> Parties {
    let key = |b: u8| PrivateKey::from_bytes(&[b; 32]).unwrap();
    Parties {
        certifier: key(43),
        subject: key(47),
        verifier: key(41),
    }
}

fn plaintexts() -> HashMap<String, String> {
    HashMap::from([
        ("name".to_string(), "Alice".to_string()),
        ("email".to_string(), "alice@example.com".to_string()),
    ])
}

/// A certificate the certifier issued to the subject, unprivileged.
async fn issued(p: &Parties) -> MasterCertificate {
    MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(p.certifier.clone())),
        &p.certifier,
        p.subject.public_key(),
        plaintexts(),
        [8u8; 32],
        Some([9u8; 32]),
        Some("test"),
    )
    .await
    .unwrap()
}

fn names() -> Vec<String> {
    vec!["email".to_string(), "name".to_string()]
}

#[tokio::test]
async fn create_certificate_fields_passes_privileged_and_its_reason_to_each_encrypt() {
    let p = parties();
    let certifier = Recording::new(&p.certifier);
    MasterCertificate::create_certificate_fields(
        &certifier,
        &p.subject.public_key(),
        plaintexts(),
        Some(true),
        Some(REASON),
        Some("test"),
    )
    .await
    .unwrap();
    assert_privileged(&certifier.take(), 2, 0);
}

#[tokio::test]
async fn create_keyring_for_verifier_passes_privileged_and_its_reason_to_each_decrypt_and_encrypt()
{
    let p = parties();
    let master = issued(&p).await;
    let subject = Recording::new(&p.subject);
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &subject,
        &p.certifier.public_key(),
        &p.verifier.public_key(),
        &master.fields,
        &names(),
        &master.master_keyring,
        &master.serial_number,
        Some(true),
        Some(REASON),
        Some("test"),
    )
    .await
    .unwrap();
    assert_privileged(&subject.take(), 2, 2);

    // The keyring is the verifier's: the fields decrypt under it.
    let mut verifiable = VerifiableCertificate::new(master.certificate.clone(), keyring);
    let decrypted = verifiable
        .decrypt_fields(
            &ProtoWallet::new(Some(p.verifier.clone())),
            None,
            None,
            Some("test"),
        )
        .await
        .unwrap();
    assert_eq!(decrypted, plaintexts());
}

#[tokio::test]
async fn master_decrypt_field_and_decrypt_fields_pass_privileged_and_its_reason_to_each_decrypt() {
    let p = parties();
    let master = issued(&p).await;
    let subject = Recording::new(&p.subject);
    let certifier: PublicKey = p.certifier.public_key();

    let name = master
        .decrypt_field(
            &subject,
            &certifier,
            "name",
            Some(true),
            Some(REASON),
            Some("test"),
        )
        .await
        .unwrap();
    assert_eq!(name, "Alice");
    assert_privileged(&subject.take(), 0, 1);

    let all = master
        .decrypt_fields(&subject, &certifier, Some(true), Some(REASON), Some("test"))
        .await
        .unwrap();
    assert_eq!(all, plaintexts());
    assert_privileged(&subject.take(), 0, 2);
}

#[tokio::test]
async fn verifiable_decrypt_field_and_decrypt_fields_pass_privileged_and_its_reason_to_each_decrypt(
) {
    let p = parties();
    let master = issued(&p).await;
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(p.subject.clone())),
        &p.certifier.public_key(),
        &p.verifier.public_key(),
        &master.fields,
        &names(),
        &master.master_keyring,
        &master.serial_number,
        None,
        None,
        Some("test"),
    )
    .await
    .unwrap();
    let mut verifiable = VerifiableCertificate::new(master.certificate.clone(), keyring);
    let verifier = Recording::new(&p.verifier);

    let email = verifiable
        .decrypt_field(&verifier, "email", Some(true), Some(REASON), Some("test"))
        .await
        .unwrap();
    assert_eq!(email, "alice@example.com");
    assert_privileged(&verifier.take(), 0, 1);

    let all = verifiable
        .decrypt_fields(&verifier, Some(true), Some(REASON), Some("test"))
        .await
        .unwrap();
    assert_eq!(all, plaintexts());
    assert_privileged(&verifier.take(), 0, 2);
}

#[tokio::test]
async fn an_unprivileged_call_passes_neither_privileged_nor_a_reason() {
    let p = parties();
    let master = issued(&p).await;
    let subject = Recording::new(&p.subject);
    master
        .decrypt_fields(
            &subject,
            &p.certifier.public_key(),
            None,
            None,
            Some("test"),
        )
        .await
        .unwrap();
    let calls = subject.take();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|c| c.1.is_none() && c.2.is_none()));
}

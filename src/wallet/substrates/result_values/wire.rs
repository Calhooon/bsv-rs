//! Borrow byte fields from the decoded wire answer; serialize only metadata.
//! Empty arrays stand in for those fields in the graph walk (a byte array is
//! one node). Row predicates read the original slices through `Fields`.

use super::{bytes::Fields, validate_with_bytes, Result};
use crate::wallet::{
    CreateActionResult, DiscoverCertificatesResult, ListCertificatesResult, ListOutputsResult,
    Outpoint, ProveCertificateResult, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageResult, SendWithResult, SignActionResult, WalletCertificate,
    WalletOutput,
};
use serde::Serialize;
use serde_json::Value;

pub(crate) trait WireResult {
    fn check(
        &self,
        call: &str,
        request: &Value,
        action: Option<&crate::wallet::CreateActionArgs>,
    ) -> Result<()>;
}

impl<T: WireResult> WireResult for &T {
    fn check(
        &self,
        call: &str,
        request: &Value,
        action: Option<&crate::wallet::CreateActionArgs>,
    ) -> Result<()> {
        T::check(self, call, request, action)
    }
}

fn check<'a>(
    call: &str,
    metadata: &impl Serialize,
    request: &Value,
    mut bytes: Fields<'a>,
    action: Option<&'a crate::wallet::CreateActionArgs>,
) -> Result<()> {
    bytes.action = action;
    if bytes.binary.iter().map(|(_, b)| b.len()).sum::<usize>() > 256 * 1024 * 1024 {
        return Err(super::invalid(
            call,
            "byte arrays",
            "at most 268435456 total bytes",
        ));
    }
    let text =
        serde_json::to_vec(metadata).map_err(|e| crate::Error::WalletError(e.to_string()))?;
    validate_with_bytes(call, &text, request, call, &bytes).map(|_| ())
}

#[derive(Serialize)]
struct Signable {
    tx: [u8; 0],
    reference: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Action<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx: Option<[u8; 0]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_send_change: Option<&'a [Outpoint]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    send_with_results: Option<&'a [SendWithResult]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signable_transaction: Option<Signable>,
}

impl WireResult for CreateActionResult {
    fn check(
        &self,
        call: &str,
        request: &Value,
        action: Option<&crate::wallet::CreateActionArgs>,
    ) -> Result<()> {
        let mut bytes = Fields::default();
        if let Some(tx) = &self.tx {
            bytes.binary.push(("tx", tx));
        }
        if let Some(tx) = &self.signable_transaction {
            bytes.binary.push(("signableTransaction.tx", &tx.tx));
        }
        let metadata = Action {
            txid: self.txid.map(hex::encode),
            tx: self.tx.as_ref().map(|_| []),
            no_send_change: self.no_send_change.as_deref(),
            send_with_results: self.send_with_results.as_deref(),
            signable_transaction: self.signable_transaction.as_ref().map(|s| Signable {
                tx: [],
                // Every byte vector has valid base64; only the empty reference can fail.
                reference: if s.reference.is_empty() {
                    String::new()
                } else {
                    "AQ==".into()
                },
            }),
        };
        check(call, &metadata, request, bytes, action)
    }
}

impl WireResult for SignActionResult {
    fn check(
        &self,
        call: &str,
        request: &Value,
        action: Option<&crate::wallet::CreateActionArgs>,
    ) -> Result<()> {
        let metadata = Action {
            txid: self.txid.map(hex::encode),
            tx: self.tx.as_ref().map(|_| []),
            no_send_change: None,
            send_with_results: self.send_with_results.as_deref(),
            signable_transaction: None,
        };
        let bytes = Fields {
            binary: self
                .tx
                .as_deref()
                .map(|tx| ("tx", tx))
                .into_iter()
                .collect(),
            ..Fields::default()
        };
        check(call, &metadata, request, bytes, action)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output<'a> {
    satoshis: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    locking_script: Option<&'static str>,
    spendable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_instructions: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<&'a [String]>,
    outpoint: &'a Outpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<&'a [String]>,
}

impl<'a> From<&'a WalletOutput> for Output<'a> {
    fn from(output: &'a WalletOutput) -> Self {
        Self {
            satoshis: output.satoshis,
            locking_script: output.locking_script.as_ref().map(|_| ""),
            spendable: output.spendable,
            custom_instructions: output.custom_instructions.as_deref(),
            tags: output.tags.as_deref(),
            outpoint: &output.outpoint,
            labels: output.labels.as_deref(),
        }
    }
}

impl WireResult for ListOutputsResult {
    fn check(
        &self,
        call: &str,
        request: &Value,
        action: Option<&crate::wallet::CreateActionArgs>,
    ) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Outputs<'a> {
            total_outputs: u32,
            #[serde(rename = "BEEF", skip_serializing_if = "Option::is_none")]
            beef: Option<[u8; 0]>,
            outputs: Vec<Output<'a>>,
        }
        let metadata = Outputs {
            total_outputs: self.total_outputs,
            beef: self.beef.as_ref().map(|_| []),
            outputs: self.outputs.iter().map(Output::from).collect(),
        };
        let bytes = Fields {
            binary: self
                .beef
                .as_deref()
                .map(|b| ("BEEF", b))
                .into_iter()
                .collect(),
            outputs: Some(&self.outputs),
            ..Fields::default()
        };
        check(call, &metadata, request, bytes, action)
    }
}

fn linkage(value: &crate::wallet::KeyLinkageResult) -> (Value, Fields<'_>) {
    let metadata = serde_json::json!({
        "prover": value.prover, "verifier": value.verifier,
        "counterparty": value.counterparty,
        "encryptedLinkage": [], "encryptedLinkageProof": [],
    });
    let bytes = Fields {
        binary: vec![
            ("encryptedLinkage", &value.encrypted_linkage),
            ("encryptedLinkageProof", &value.encrypted_linkage_proof),
        ],
        ..Fields::default()
    };
    (metadata, bytes)
}

impl WireResult for RevealCounterpartyKeyLinkageResult {
    fn check(
        &self,
        call: &str,
        request: &Value,
        action: Option<&crate::wallet::CreateActionArgs>,
    ) -> Result<()> {
        let (mut metadata, bytes) = linkage(&self.linkage);
        metadata["revelationTime"] = Value::String(self.revelation_time.clone());
        check(call, &metadata, request, bytes, action)
    }
}

impl WireResult for RevealSpecificKeyLinkageResult {
    fn check(
        &self,
        call: &str,
        request: &Value,
        action: Option<&crate::wallet::CreateActionArgs>,
    ) -> Result<()> {
        let (mut metadata, bytes) = linkage(&self.linkage);
        metadata["protocolID"] = serde_json::json!(self.protocol.to_tuple());
        metadata["keyID"] = Value::String(self.key_id.clone());
        metadata["proofType"] = Value::from(self.proof_type);
        check(call, &metadata, request, bytes, action)
    }
}

macro_rules! metadata_only {
    ($($ty:ty),+ $(,)?) => {$(
        impl WireResult for $ty {
            fn check(&self, call: &str, request: &Value, action: Option<&crate::wallet::CreateActionArgs>) -> Result<()> {
                check(call, self, request, Fields::default(), action)
            }
        }
    )+};
}
metadata_only!(
    WalletCertificate,
    ListCertificatesResult,
    DiscoverCertificatesResult,
    ProveCertificateResult
);

pub(crate) fn signature(signature: &[u8]) -> Result<()> {
    check(
        "createSignature",
        &serde_json::json!({"signature": []}),
        &Value::Null,
        Fields {
            binary: vec![("signature", signature)],
            ..Fields::default()
        },
        None,
    )
}

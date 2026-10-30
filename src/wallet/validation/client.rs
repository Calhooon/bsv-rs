//! Argument-side checks needed by the result bindings (#487).
//! `validateWalletArgs` precedes transmission at `WalletWireTransceiver.ts`
//! :162,624,1476,1565 (ts-stack@edf6e03). These use the same typed byte and
//! InvalidParameter helpers as the processor's crypto argument validators.

use super::{crypto, originator::invalid_parameter};
use crate::wallet::{CreateActionArgs, ProveCertificateArgs};
use crate::Result;
use std::collections::HashMap;

/// `validationHelpers.ts:775-781`: even unused inputBEEF must be framed.
pub(crate) fn create_action_sources(args: &CreateActionArgs) -> Result<HashMap<String, u64>> {
    let Some(bytes) = &args.input_beef else {
        return Ok(HashMap::new());
    };
    crypto::byte_array(bytes.len(), "inputBEEF")?;
    crate::wallet::substrates::result_values::input_sources(
        bytes,
        args.inputs.as_deref().unwrap_or_default(),
    )
    .map_err(|_| invalid_parameter("inputBEEF", "a complete, exactly framed BEEF envelope"))
}

/// `validationHelpers.ts:1199,1647`: validateInteger(limit, 'limit', 10, 1, 10000).
pub(crate) fn limit(limit: Option<u32>) -> Result<()> {
    match limit {
        Some(0) => Err(invalid_parameter("limit", "at least 1 length.")),
        Some(10001..) => Err(invalid_parameter("limit", "no more than 10000 length.")),
        _ => Ok(()),
    }
}

/// `validationHelpers.ts:1476-1480,93-96`: validateCertificateFields first
/// validates its record's safe own keys, ahead of checking individual names.
pub(crate) fn prove_certificate(args: &ProveCertificateArgs) -> Result<()> {
    if args
        .certificate
        .fields
        .keys()
        .any(|key| matches!(key.as_str(), "__proto__" | "constructor" | "prototype"))
    {
        return Err(invalid_parameter(
            "fields",
            "an object with safe string keys",
        ));
    }
    Ok(())
}

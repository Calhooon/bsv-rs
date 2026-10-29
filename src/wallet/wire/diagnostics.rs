//! Optional tracing events for wallet errors at the processor's framing boundary.

use super::WalletCall;
use crate::error::WalletRefusalClass;
use std::fmt::Display;

/// Keep the processor's event target and fields when a refusal keeps its code.
pub(super) fn kept(call: WalletCall, class: WalletRefusalClass) {
    tracing::warn!(
        target: "bsv_rs::wallet::wire::processor",
        call = call.method_name(),
        class = class.name(),
        "wallet refusal framed with its code"
    );
}

/// Record the words a replacement drops, with the refusal class when present.
pub(super) fn replaced(call: WalletCall, class: Option<&WalletRefusalClass>, error: impl Display) {
    if let Some(class) = class {
        tracing::warn!(
            target: "bsv_rs::wallet::wire::processor",
            call = call.method_name(),
            class = class.name(),
            error = %error,
            "wallet error framed as Wallet operation failed"
        );
    } else {
        tracing::warn!(
            target: "bsv_rs::wallet::wire::processor",
            call = call.method_name(),
            error = %error,
            "wallet error framed as Wallet operation failed"
        );
    }
}

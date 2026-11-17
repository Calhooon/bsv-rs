//! The raw inputs of the action validators (#843): the five records a caller
//! hands `validate_create_action_args`, `validate_create_action_input`,
//! `validate_create_action_output`, `validate_create_action_options` and
//! `validate_sign_action_spend`, each the reference's argument type before
//! its checks (`Wallet.interfaces.ts:261-307,389-404` at `ts-stack@edf6e03`,
//! the same members at its head `11faa7d16`).
//!
//! Each is a parameter block that grows with the reference's argument type,
//! so each is `#[non_exhaustive]`: built with `new` (the reference's required
//! members) and a `with_` setter per optional member; the fields stay
//! readable and assignable, and a pattern over one ends in `..`. Declared
//! here since #843 (`validation.rs` stands at its ratchet line);
//! `wallet::validation::<Name>` as before.

use crate::error::{Error, Result};
use crate::wallet::types::TrustSelf;

/// Raw create action input for validation.
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::wallet::validation::CreateActionInputRaw) -> bsv_rs::wallet::validation::CreateActionInputRaw {
///     bsv_rs::wallet::validation::CreateActionInputRaw { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::wallet::validation::CreateActionInputRaw) -> bsv_rs::wallet::validation::CreateActionInputRaw {
///     value
/// }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CreateActionInputRaw {
    /// The outpoint string "txid.vout".
    pub outpoint: String,
    /// Description of this input.
    pub input_description: String,
    /// Optional unlocking script (hex).
    pub unlocking_script: Option<String>,
    /// Optional unlocking script length.
    pub unlocking_script_length: Option<u32>,
    /// Optional sequence number.
    pub sequence_number: Option<u32>,
}

crate::util::non_exhaustive::assert_no_drop!(
    CreateActionInputRaw,
    bsv_rs::wallet::validation::CreateActionInputRaw
);

impl CreateActionInputRaw {
    /// The input spending `outpoint` ("txid.vout"), described.
    #[must_use]
    pub fn new(outpoint: impl Into<String>, input_description: impl Into<String>) -> Self {
        Self {
            outpoint: outpoint.into(),
            input_description: input_description.into(),
            unlocking_script: None,
            unlocking_script_length: None,
            sequence_number: None,
        }
    }

    /// Sets the unlocking script (hex).
    #[must_use]
    pub fn with_unlocking_script(mut self, unlocking_script: impl Into<String>) -> Self {
        self.unlocking_script = Some(unlocking_script.into());
        self
    }

    /// Sets the unlocking script's length.
    #[must_use]
    pub fn with_unlocking_script_length(mut self, unlocking_script_length: u32) -> Self {
        self.unlocking_script_length = Some(unlocking_script_length);
        self
    }

    /// Sets the sequence number.
    #[must_use]
    pub fn with_sequence_number(mut self, sequence_number: u32) -> Self {
        self.sequence_number = Some(sequence_number);
        self
    }
}

/// Raw create action output for validation.
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::wallet::validation::CreateActionOutputRaw) -> bsv_rs::wallet::validation::CreateActionOutputRaw {
///     bsv_rs::wallet::validation::CreateActionOutputRaw { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::wallet::validation::CreateActionOutputRaw) -> bsv_rs::wallet::validation::CreateActionOutputRaw {
///     value
/// }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CreateActionOutputRaw {
    /// The locking script (hex).
    pub locking_script: String,
    /// The satoshi value.
    pub satoshis: u64,
    /// Description of this output.
    pub output_description: String,
    /// Optional basket name.
    pub basket: Option<String>,
    /// Optional custom instructions.
    pub custom_instructions: Option<String>,
    /// Tags for this output.
    pub tags: Vec<String>,
}

crate::util::non_exhaustive::assert_no_drop!(
    CreateActionOutputRaw,
    bsv_rs::wallet::validation::CreateActionOutputRaw
);

impl CreateActionOutputRaw {
    /// The output of `satoshis` locked by `locking_script` (hex), described.
    #[must_use]
    pub fn new(
        locking_script: impl Into<String>,
        satoshis: u64,
        output_description: impl Into<String>,
    ) -> Self {
        Self {
            locking_script: locking_script.into(),
            satoshis,
            output_description: output_description.into(),
            basket: None,
            custom_instructions: None,
            tags: Vec::new(),
        }
    }

    /// Sets the basket's name.
    #[must_use]
    pub fn with_basket(mut self, basket: impl Into<String>) -> Self {
        self.basket = Some(basket.into());
        self
    }

    /// Sets the custom instructions.
    #[must_use]
    pub fn with_custom_instructions(mut self, custom_instructions: impl Into<String>) -> Self {
        self.custom_instructions = Some(custom_instructions.into());
        self
    }

    /// Sets the tags.
    #[must_use]
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Raw create action options for validation: the reference's
/// `CreateActionOptions`, every member optional, `trustSelf` among them
/// since #843 (`Wallet.interfaces.ts:297-307`).
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::wallet::validation::CreateActionOptionsRaw) -> bsv_rs::wallet::validation::CreateActionOptionsRaw {
///     bsv_rs::wallet::validation::CreateActionOptionsRaw { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::wallet::validation::CreateActionOptionsRaw) -> bsv_rs::wallet::validation::CreateActionOptionsRaw {
///     value
/// }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CreateActionOptionsRaw {
    /// Whether to sign and process immediately.
    pub sign_and_process: Option<bool>,
    /// Whether to accept delayed broadcast.
    pub accept_delayed_broadcast: Option<bool>,
    /// `trustSelf` as the caller gave it: absent or `known`, any other text
    /// refused by `validate_create_action_options` in the reference's words
    /// (`validationHelpers.ts:668-669`).
    pub trust_self: Option<String>,
    /// Known transaction IDs (hex).
    pub known_txids: Vec<String>,
    /// Whether to return only the txid.
    pub return_txid_only: Option<bool>,
    /// Whether to skip sending the transaction.
    pub no_send: Option<bool>,
    /// Change outpoints from prior noSend actions.
    pub no_send_change: Vec<String>,
    /// TXIDs to send with this transaction (hex).
    pub send_with: Vec<String>,
    /// Whether to randomize output order.
    pub randomize_outputs: Option<bool>,
}

crate::util::non_exhaustive::assert_no_drop!(
    CreateActionOptionsRaw,
    bsv_rs::wallet::validation::CreateActionOptionsRaw
);

impl CreateActionOptionsRaw {
    /// No option given: every member absent, the validator's defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `signAndProcess`.
    #[must_use]
    pub fn with_sign_and_process(mut self, sign_and_process: bool) -> Self {
        self.sign_and_process = Some(sign_and_process);
        self
    }

    /// Sets `acceptDelayedBroadcast`.
    #[must_use]
    pub fn with_accept_delayed_broadcast(mut self, accept_delayed_broadcast: bool) -> Self {
        self.accept_delayed_broadcast = Some(accept_delayed_broadcast);
        self
    }

    /// Sets `trustSelf` as text (`known`).
    #[must_use]
    pub fn with_trust_self(mut self, trust_self: impl Into<String>) -> Self {
        self.trust_self = Some(trust_self.into());
        self
    }

    /// Sets the known transaction IDs (hex).
    #[must_use]
    pub fn with_known_txids(mut self, known_txids: Vec<String>) -> Self {
        self.known_txids = known_txids;
        self
    }

    /// Sets `returnTXIDOnly`.
    #[must_use]
    pub fn with_return_txid_only(mut self, return_txid_only: bool) -> Self {
        self.return_txid_only = Some(return_txid_only);
        self
    }

    /// Sets `noSend`.
    #[must_use]
    pub fn with_no_send(mut self, no_send: bool) -> Self {
        self.no_send = Some(no_send);
        self
    }

    /// Sets the change outpoints of prior noSend actions.
    #[must_use]
    pub fn with_no_send_change(mut self, no_send_change: Vec<String>) -> Self {
        self.no_send_change = no_send_change;
        self
    }

    /// Sets the TXIDs to send with this transaction (hex).
    #[must_use]
    pub fn with_send_with(mut self, send_with: Vec<String>) -> Self {
        self.send_with = send_with;
        self
    }

    /// Sets `randomizeOutputs`.
    #[must_use]
    pub fn with_randomize_outputs(mut self, randomize_outputs: bool) -> Self {
        self.randomize_outputs = Some(randomize_outputs);
        self
    }
}

/// `trustSelf` as the reference's `validateCreateActionOptions` reads it
/// (`validationHelpers.ts:668-674`): absent, or `known`; any other text is
/// `WERR_INVALID_PARAMETER` in its words.
pub(super) fn trust_self(given: Option<&str>) -> Result<Option<TrustSelf>> {
    match given {
        None => Ok(None),
        Some("known") => Ok(Some(TrustSelf::Known)),
        Some(_) => Err(Error::WalletRefusal {
            class: crate::error::WalletRefusalClass::InvalidParameter,
            message: "The trustSelf parameter must be undefined or 'known'".to_string(),
        }),
    }
}

/// Raw create action arguments for validation.
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::wallet::validation::CreateActionArgsRaw) -> bsv_rs::wallet::validation::CreateActionArgsRaw {
///     bsv_rs::wallet::validation::CreateActionArgsRaw { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::wallet::validation::CreateActionArgsRaw) -> bsv_rs::wallet::validation::CreateActionArgsRaw {
///     value
/// }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CreateActionArgsRaw {
    /// Description of this action.
    pub description: String,
    /// Optional input BEEF data.
    pub input_beef: Option<Vec<u8>>,
    /// Raw inputs.
    pub inputs: Vec<CreateActionInputRaw>,
    /// Raw outputs.
    pub outputs: Vec<CreateActionOutputRaw>,
    /// Optional lock time.
    pub lock_time: Option<u32>,
    /// Optional version.
    pub version: Option<u32>,
    /// Labels for this action.
    pub labels: Vec<String>,
    /// Raw options.
    pub options: Option<CreateActionOptionsRaw>,
}

crate::util::non_exhaustive::assert_no_drop!(
    CreateActionArgsRaw,
    bsv_rs::wallet::validation::CreateActionArgsRaw
);

impl CreateActionArgsRaw {
    /// The action described, with no input, output, label or option.
    #[must_use]
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            input_beef: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: None,
            version: None,
            labels: Vec::new(),
            options: None,
        }
    }

    /// Sets the input BEEF.
    #[must_use]
    pub fn with_input_beef(mut self, input_beef: Vec<u8>) -> Self {
        self.input_beef = Some(input_beef);
        self
    }

    /// Sets the inputs.
    #[must_use]
    pub fn with_inputs(mut self, inputs: Vec<CreateActionInputRaw>) -> Self {
        self.inputs = inputs;
        self
    }

    /// Sets the outputs.
    #[must_use]
    pub fn with_outputs(mut self, outputs: Vec<CreateActionOutputRaw>) -> Self {
        self.outputs = outputs;
        self
    }

    /// Sets the lock time.
    #[must_use]
    pub fn with_lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = Some(lock_time);
        self
    }

    /// Sets the version.
    #[must_use]
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the labels.
    #[must_use]
    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    /// Sets the options.
    #[must_use]
    pub fn with_options(mut self, options: CreateActionOptionsRaw) -> Self {
        self.options = Some(options);
        self
    }
}

/// Raw sign action spend for validation.
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::wallet::validation::SignActionSpendRaw) -> bsv_rs::wallet::validation::SignActionSpendRaw {
///     bsv_rs::wallet::validation::SignActionSpendRaw { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::wallet::validation::SignActionSpendRaw) -> bsv_rs::wallet::validation::SignActionSpendRaw {
///     value
/// }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignActionSpendRaw {
    /// The unlocking script (hex).
    pub unlocking_script: String,
    /// Optional sequence number.
    pub sequence_number: Option<u32>,
}

crate::util::non_exhaustive::assert_no_drop!(
    SignActionSpendRaw,
    bsv_rs::wallet::validation::SignActionSpendRaw
);

impl SignActionSpendRaw {
    /// The spend unlocked by `unlocking_script` (hex).
    #[must_use]
    pub fn new(unlocking_script: impl Into<String>) -> Self {
        Self {
            unlocking_script: unlocking_script.into(),
            sequence_number: None,
        }
    }

    /// Sets the sequence number.
    #[must_use]
    pub fn with_sequence_number(mut self, sequence_number: u32) -> Self {
        self.sequence_number = Some(sequence_number);
        self
    }
}

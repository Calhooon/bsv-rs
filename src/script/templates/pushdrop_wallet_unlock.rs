//! PushDrop's wallet-aware unlock (#803): the reference's
//! `new PushDrop(wallet, originator).unlock(protocolID, keyID, counterparty,
//! signOutputs, anyoneCanPay, sourceSatoshis, lockingScript)` (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/PushDrop.ts:205-262`), one public door
//! beside the raw [`PushDrop::unlock`], which is unchanged, and the spend of
//! what [`PushDrop::lock_with_wallet`] (#782) locks.
//!
//! The reference's template: `sign(tx, inputIndex)` computes the scope
//! (`computeSignatureScope`, `SignatureUtils.ts:44-68`: `SIGHASH_FORKID` with
//! ALL, NONE or SINGLE, `SIGHASH_ANYONECANPAY` or-ed in), builds the BIP143
//! preimage of the input, asks the wallet's `createSignature` with `data`
//! SHA-256 of the preimage for the protocol, key ID and counterparty
//! (`:245-254`; the wallet hashes once more, so the signature is over the
//! double hash a CHECKSIG verifies), reads the answer with
//! `Signature.fromDER` and pushes its DER and the scope byte (`:255-258`);
//! `estimateLength` answers 73 (`:260`).
//!
//! Three choices of this crate's shape, stated: (a) the template is
//! [`PushDropWalletUnlock`], whose `sign` returns a future as the reference's
//! returns a promise (the context by value, the future `Send`),
//! and not a [`ScriptTemplateUnlock`](crate::script::ScriptTemplateUnlock),
//! whose closure is synchronous and cannot await a wallet (the crate starts
//! no runtime); so `Transaction::sign` does not drive it: a caller signs the
//! input and sets its unlocking script. (b) The source amount and locking
//! script are the [`SigningContext`]'s, as at every template of this crate,
//! where the reference takes them as two optional arguments or from the
//! input's linked source and refuses a disagreement of the two
//! (`resolveSourceDetails`, `SignatureUtils.ts:74-184`); the context names
//! one of each, so there is nothing to disagree. (c) A scriptCode named by
//! [`SigningContext::with_script_code`] is the one signed, as every
//! template's `sign` reads it; the reference signs the locking script.
//!
//! One residue, stated: a wallet's high-S answer is written in its low-S
//! form by this crate's DER writer, where the reference pushes it as
//! answered (`tests/vectors/pushdrop_wallet_unlock_803.json`,
//! `answer_high_s`).

use super::pushdrop::PushDrop;
use crate::primitives::bsv::sighash::{parse_transaction, RawTransaction, SighashParams};
use crate::script::template::{compute_sighash_scope, SignOutputs, SigningContext};
use crate::script::UnlockingScript;
use crate::wallet::{Counterparty, Protocol, WalletInterface};
use crate::{Error, Result};
use std::future::Future;

/// The reference's bound on a source amount, 21e14 satoshis
/// (`MAX_SATOSHIS`, `SignatureUtils.ts:6`).
const MAX_SATOSHIS: u64 = 2_100_000_000_000_000;

/// The reference's `estimateLength` (`PushDrop.ts:260`): one push opcode and
/// a 72-byte signature with its scope byte.
const ESTIMATED_LENGTH: usize = 73;

/// The template [`PushDrop::unlock_with_wallet`] returns: the reference's
/// `{ sign, estimateLength }` (`PushDrop.ts:225-228` at `ts-stack@edf6e03`),
/// its signature asked of a wallet.
///
/// It borrows the wallet and the originator, so it lives no longer than
/// either; build it where the input is signed.
pub struct PushDropWalletUnlock<'a, W: WalletInterface + ?Sized> {
    wallet: &'a W,
    originator: Option<&'a str>,
    protocol_id: Protocol,
    key_id: String,
    counterparty: Counterparty,
    scope: u32,
}

impl PushDrop {
    /// Creates the template that unlocks a PushDrop output with a signature
    /// asked of `wallet`, the reference's `new PushDrop(wallet,
    /// originator).unlock(protocolID, keyID, counterparty, signOutputs,
    /// anyoneCanPay)` (`PushDrop.ts:205-262` at `ts-stack@edf6e03`; its
    /// defaults are `sign_outputs` [`SignOutputs::All`] and `anyone_can_pay`
    /// false). The reference's two further arguments, the source amount and
    /// locking script, are the [`SigningContext`]'s here.
    ///
    /// Nothing is asked of the wallet until
    /// [`sign`](PushDropWalletUnlock::sign). The protocol, key ID and
    /// counterparty are those the output was locked under
    /// ([`lock_with_wallet`](Self::lock_with_wallet)); the scope byte is
    /// `SIGHASH_FORKID` with ALL, NONE or SINGLE, `SIGHASH_ANYONECANPAY`
    /// or-ed in when `anyone_can_pay` (`0x41`, `0x42`, `0x43`, `0xc1`,
    /// `0xc2`, `0xc3`).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use bsv_rs::script::template::{SignOutputs, SigningContext};
    /// use bsv_rs::script::templates::PushDrop;
    /// use bsv_rs::script::LockingScript;
    /// use bsv_rs::wallet::{Counterparty, Protocol, ProtoWallet, SecurityLevel};
    ///
    /// # async fn spend(wallet: &ProtoWallet, raw_tx: &[u8], lock: &LockingScript) -> bsv_rs::Result<()> {
    /// let template = PushDrop::unlock_with_wallet(
    ///     wallet,
    ///     None,
    ///     Protocol::new(SecurityLevel::Counterparty, "my tokens"),
    ///     "1",
    ///     Counterparty::Self_,
    ///     SignOutputs::All,
    ///     false,
    /// );
    /// // Input 0 of `raw_tx` spends a 1-satoshi token locked by `lock`.
    /// let unlocking_script = template
    ///     .sign(SigningContext::new(raw_tx, 0, 1, lock.as_script()))
    ///     .await?;
    /// # let _ = unlocking_script;
    /// # Ok(())
    /// # }
    /// ```
    pub fn unlock_with_wallet<'a, W: WalletInterface + ?Sized>(
        wallet: &'a W,
        originator: Option<&'a str>,
        protocol_id: Protocol,
        key_id: &str,
        counterparty: Counterparty,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> PushDropWalletUnlock<'a, W> {
        PushDropWalletUnlock {
            wallet,
            originator,
            protocol_id,
            key_id: key_id.to_string(),
            counterparty,
            scope: compute_sighash_scope(sign_outputs, anyone_can_pay),
        }
    }
}

impl<W: WalletInterface + ?Sized> PushDropWalletUnlock<'_, W> {
    /// Signs the context's input: the wallet's `createSignature` is asked
    /// once, with `data` SHA-256 of the input's BIP143 preimage under the
    /// template's scope, for its protocol, key ID and counterparty, carrying
    /// its originator; the answer is read as DER and pushed with the scope
    /// byte, one push (`PushDrop.ts:230-259`).
    ///
    /// The scriptCode is the context's locking script, or the one
    /// [`SigningContext::with_script_code`] names.
    ///
    /// # Errors
    ///
    /// Before the wallet is asked: the transaction bytes that do not parse
    /// (this crate's parser's error); an input index past the inputs, in the
    /// reference's words, `inputIndex N is outside the transaction input
    /// range`; a source amount past 21e14, `sourceSatoshis must be a valid
    /// number of satoshis` (both [`Error::TransactionError`]). A wallet error
    /// is returned as it came. An answer that is not a DER signature is
    /// refused by [`Signature::from_der`](crate::primitives::Signature::from_der),
    /// in the reference's `Signature.fromDER` words.
    ///
    /// One residue, stated: a wallet that answers a signature whose S is in
    /// the upper half of the order has it pushed as answered by the
    /// reference (on the recorded case a 72-byte DER, the script 74 bytes),
    /// where this crate's
    /// [`Signature::to_der`](crate::primitives::Signature::to_der) writes
    /// the low-S form of the same signature (73 bytes at most), which every
    /// mode of the interpreter accepts.
    ///
    /// The context is taken by value and read before the future starts, so
    /// the future holds none of it (a [`SigningContext`] borrows a `Script`,
    /// which is not `Sync`) and is `Send`, on every target, as the wallet
    /// trait's own futures are: it borrows the template and awaits owned
    /// data alone. A refusal made before the wallet is asked is still
    /// answered by the future, when it is awaited.
    ///
    /// # What the caller owns across the await
    ///
    /// The future is `Send`; whether the caller's own future is depends on
    /// what the caller holds while it awaits. Where that future must be
    /// `Send` (a method under `#[async_trait]`, a handler a multi-threaded
    /// runtime spawns), hold each locking script OWNED across the await
    /// (parsed or cloned inside the loop, or moved out of an owned list) and
    /// build the context in the call. A `&LockingScript` or `&Script` held
    /// across the await (a loop over a borrowed `&[(usize, LockingScript)]`),
    /// or a `SigningContext` kept alive past it (a clone given to `sign`, the
    /// original used after), makes the caller's future not `Send`, and the
    /// compiler says so at the caller (`future cannot be sent between threads
    /// safely`, naming `Script`'s `RefCell`s): a `Script` is `Send` and not
    /// `Sync`, so a reference to one does not cross threads. The form that
    /// compiles:
    ///
    /// ```rust,no_run
    /// use bsv_rs::script::template::{SignOutputs, SigningContext};
    /// use bsv_rs::script::templates::PushDrop;
    /// use bsv_rs::script::{LockingScript, UnlockingScript};
    /// use bsv_rs::wallet::{Counterparty, Protocol, SecurityLevel, WalletInterface};
    ///
    /// /// Signs each `(input index, locking script hex)` of `raw_tx`.
    /// async fn sign_tokens<W: WalletInterface + ?Sized>(
    ///     wallet: &W,
    ///     raw_tx: &[u8],
    ///     tokens: &[(usize, String)],
    /// ) -> bsv_rs::Result<Vec<UnlockingScript>> {
    ///     let template = PushDrop::unlock_with_wallet(
    ///         wallet,
    ///         None,
    ///         Protocol::new(SecurityLevel::Counterparty, "my tokens"),
    ///         "1",
    ///         Counterparty::Self_,
    ///         SignOutputs::All,
    ///         false,
    ///     );
    ///     let mut scripts = Vec::new();
    ///     for (input_index, lock_hex) in tokens {
    ///         // Owned inside the loop: an owned script may be held across
    ///         // the await, a borrowed one may not.
    ///         let lock = LockingScript::from_hex(lock_hex)?;
    ///         let context = SigningContext::new(raw_tx, *input_index, 1, lock.as_script());
    ///         scripts.push(template.sign(context).await?);
    ///     }
    ///     Ok(scripts)
    /// }
    ///
    /// // The caller's future crosses threads.
    /// fn is_send<T: Send>(_: T) {}
    /// # fn check(wallet: &bsv_rs::wallet::ProtoWallet, raw_tx: &[u8], tokens: &[(usize, String)]) {
    /// is_send(sign_tokens(wallet, raw_tx, tokens));
    /// # }
    /// ```
    pub fn sign(
        &self,
        context: SigningContext<'_>,
    ) -> impl Future<Output = Result<UnlockingScript>> + Send + '_ {
        let read = Read::of(&context);
        async move {
            let read = read?;
            let script = crate::wallet::pushdrop::sign(
                self.wallet,
                &SighashParams {
                    version: read.tx.version,
                    inputs: &read.tx.inputs,
                    outputs: &read.tx.outputs,
                    locktime: read.tx.locktime,
                    input_index: read.input_index,
                    subscript: &read.subscript,
                    satoshis: read.source_satoshis,
                    scope: self.scope,
                },
                self.protocol_id.clone(),
                self.key_id.clone(),
                self.counterparty.clone(),
                self.originator,
            )
            .await?;
            UnlockingScript::from_binary(&script)
        }
    }

    /// The reference's `estimateLength`, 73 bytes (`PushDrop.ts:260`): the
    /// push opcode, a DER signature of at most 71 bytes and the scope byte.
    /// No script [`sign`](Self::sign) writes is longer: a wallet's high-S
    /// answer is written in its low-S form (the residue stated on `sign`).
    pub fn estimate_length(&self) -> usize {
        ESTIMATED_LENGTH
    }
}

/// What `sign` reads of its context before its future starts: owned data
/// alone, judged in the reference's order (the index, then the amount,
/// `SignatureUtils.ts:89-91`, `:16-21`).
struct Read {
    tx: RawTransaction,
    input_index: usize,
    source_satoshis: u64,
    subscript: Vec<u8>,
}

impl Read {
    fn of(context: &SigningContext<'_>) -> Result<Self> {
        let tx = parse_transaction(context.raw_tx)?;
        if context.input_index >= tx.inputs.len() {
            return Err(Error::TransactionError(format!(
                "inputIndex {} is outside the transaction input range",
                context.input_index
            )));
        }
        if context.source_satoshis > MAX_SATOSHIS {
            return Err(Error::TransactionError(
                "sourceSatoshis must be a valid number of satoshis".to_string(),
            ));
        }
        Ok(Self {
            tx,
            input_index: context.input_index,
            source_satoshis: context.source_satoshis,
            subscript: context
                .script_code
                .unwrap_or(context.locking_script)
                .to_binary(),
        })
    }
}

/// The scope and the estimate alone: no wallet, key ID, counterparty or
/// originator is printed.
impl<W: WalletInterface + ?Sized> std::fmt::Debug for PushDropWalletUnlock<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushDropWalletUnlock")
            .field("scope", &self.scope)
            .field("estimate_length", &ESTIMATED_LENGTH)
            .finish_non_exhaustive()
    }
}

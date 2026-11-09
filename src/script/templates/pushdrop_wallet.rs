//! PushDrop's wallet-aware lock (#782): the reference's
//! `new PushDrop(wallet, originator).lock(fields, protocolID, keyID,
//! counterparty, forSelf, includeSignature, lockPosition)` (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/PushDrop.ts:130-202`), one public door
//! beside the raw [`PushDrop::lock`], which is unchanged.
//!
//! The reference's order: the wallet's `getPublicKey` for the protocol, key
//! ID, counterparty and `forSelf` (`:155-163`); when `includeSignature`, its
//! `createSignature` over the fields concatenated, for the same protocol, key
//! ID and counterparty, no `forSelf` (`:173-185`), the signature pushed as the
//! last field as the wallet returned it; the key pushed as the wallet
//! returned it (`:166-172`, #545), never re-encoded.
//!
//! The key text is read right after `getPublicKey` answers and before any
//! signature is asked, as the reference decodes it (`toArray(publicKey,
//! 'hex')`, `:166-172`) before `createSignature` (`:173-185`).
//!
//! Two residues, stated: (a) the reference pushes the wallet's key text
//! unparsed once it decodes as hex, where this door reads it with
//! `PublicKey::from_hex` and refuses a text that is no key in that parser's
//! words (as the crate's five wallet sites do), after the key call alone: a
//! text that is not hex both refuse there, the reference in `Invalid hex
//! string`, this door in the parser's words; a valid-hex text that is no key
//! (`""`, a `05` tag) the reference signs and pushes; and (b) #545's
//! odd-length opcode (the reference's truncated `0x20` before 33 bytes,
//! written here as the 33 bytes' own push).

use super::pushdrop::{LockPosition, PushDrop};
use super::pushdrop_key_bytes::read_wallet_key;
use crate::script::LockingScript;
use crate::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, Protocol, WalletInterface,
};
use crate::Result;

impl PushDrop {
    /// Creates a PushDrop locking script whose key and signature come from
    /// `wallet`, the reference's `new PushDrop(wallet, originator).lock(fields,
    /// protocolID, keyID, counterparty, forSelf, includeSignature,
    /// lockPosition)` (`PushDrop.ts:130-202` at `ts-stack@edf6e03`; its
    /// defaults are `for_self` false, `include_signature` true,
    /// [`LockPosition::Before`]).
    ///
    /// The wallet is asked for the public key of `protocol_id`, `key_id` and
    /// `counterparty` with `for_self`; when `include_signature` is true it is
    /// then asked to sign the fields' bytes concatenated, for the same
    /// protocol, key ID and counterparty, and the signature is pushed as the
    /// last field, as returned. The key is pushed as the wallet returned it
    /// (a compressed answer as 33 bytes, an uncompressed or hybrid one as 65,
    /// #545), where [`lock`](Self::lock) pushes its key compressed. Both
    /// calls carry `originator`.
    ///
    /// # Errors
    ///
    /// A wallet error is returned as it came, and no signature is asked after
    /// a failed key call. A key answer that is no public key is refused in
    /// `PublicKey::from_hex`'s words before any signature is asked (the
    /// reference refuses a text that is not hex there in `Invalid hex
    /// string` and pushes a valid-hex one unparsed).
    #[allow(clippy::too_many_arguments)] // The reference's seven parameters, its wallet and its originator (PushDrop.ts:130-154).
    pub async fn lock_with_wallet<W: WalletInterface + ?Sized>(
        wallet: &W,
        originator: Option<&str>,
        mut fields: Vec<Vec<u8>>,
        protocol_id: Protocol,
        key_id: &str,
        counterparty: Counterparty,
        for_self: bool,
        include_signature: bool,
        position: LockPosition,
    ) -> Result<LockingScript> {
        let key = wallet
            .get_public_key(
                GetPublicKeyArgs {
                    protocol_id: Some(protocol_id.clone()),
                    key_id: Some(key_id.to_string()),
                    counterparty: Some(counterparty.clone()),
                    for_self: Some(for_self),
                    ..Default::default()
                },
                originator,
            )
            .await?;
        // The reference decodes the key text before it asks the signature
        // (`PushDrop.ts:166-172`, then `:173-185`): a text refused here is
        // refused after one wallet call (#782's fold).
        let key = read_wallet_key(&key.public_key)?;
        if include_signature {
            let signed = wallet
                .create_signature(
                    CreateSignatureArgs {
                        data: Some(fields.concat()),
                        protocol_id,
                        key_id: key_id.to_string(),
                        counterparty: Some(counterparty),
                        ..Default::default()
                    },
                    originator,
                )
                .await?;
            fields.push(signed.signature);
        }
        Ok(key.lock(fields, position))
    }
}

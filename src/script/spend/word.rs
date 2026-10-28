//! The flag word applied to a spend and the switches it derives, with the
//! setters that override a derived rule.

use crate::script::flags::{Gates, ScriptFlags};

use super::Spend;

impl Spend {
    /// Overrides MINIMALDATA enforcement (script-number and push minimality).
    ///
    /// Default follows ts-sdk: enforced for version <= 1 transactions, relaxed
    /// for version > 1 (post-Genesis semantics). Called after [`set_flags`](Self::set_flags),
    /// it overrides the rule the word derived.
    pub fn set_require_minimal(&mut self, require: bool) {
        self.require_minimal = require;
    }

    /// Allows opting out of the push-only unlocking-script check.
    ///
    /// The TypeScript `@bsv/sdk` Spend engine does not enforce push-only
    /// unlocking scripts; some OP_PUSH_TX-style covenant designs place
    /// executable code in the unlocking script and verify under that engine.
    /// Default remains `true` (enforced). Called after [`set_flags`](Self::set_flags),
    /// it overrides the rule the word derived (the reference requires push-only
    /// unlocking scripts post-Chronicle only for version <= 1).
    pub fn set_require_push_only(&mut self, require: bool) {
        self.require_push_only = require;
    }

    /// Applies a verification flag word: every rule this interpreter enforces
    /// is re-derived from `flags` and the transaction version exactly as
    /// bitcoin-sv v1.2.2 derives it at the rule's site, including its version
    /// gate `EnforceNonMalleability` (`interpreter.cpp:40-44`; the table on
    /// [`ScriptFlags`]). The TypeScript default mode's switches are replaced,
    /// not merged; `set_require_minimal` and `set_require_push_only` override
    /// a derived rule when called afterwards.
    ///
    /// The memory budget follows the word too: the node's stack memory count
    /// and, on the mempool path, its policy verdict ([`memory_limit`](Self::memory_limit),
    /// [`stack_memory_policy`](Self::stack_memory_policy)); on the block path the
    /// consensus figure's verdict, when one is given
    /// ([`stack_memory_consensus`](Self::stack_memory_consensus)).
    ///
    /// A consensus oracle selects the block word:
    ///
    /// ```rust,ignore
    /// spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    /// ```
    ///
    /// A word this interpreter cannot honor ([`ScriptFlags::check`]) is
    /// accepted here and refused by [`validate`](Self::validate), as the
    /// reference refuses an invalid word at `VerifyScript`
    /// (`interpreter.cpp:2312-2313`).
    pub fn set_flags(&mut self, flags: ScriptFlags) {
        let Gates {
            push_only,
            minimal,
            low_s,
            clean_stack,
            null_dummy,
            null_fail,
            minimal_if,
            discourage_upgradable_nops,
            compressed_pubkey,
            utxo_after_chronicle,
        } = flags.gates(self.transaction_version);
        self.require_push_only = push_only;
        self.require_minimal = minimal;
        self.require_low_s = low_s;
        self.require_clean_stack = clean_stack;
        self.require_null_dummy = null_dummy;
        self.require_null_fail = null_fail;
        self.require_minimal_if = minimal_if;
        self.discourage_upgradable_nops = discourage_upgradable_nops;
        self.require_compressed_pubkey = compressed_pubkey;
        self.utxo_after_chronicle = utxo_after_chronicle;
        self.chronicle_opcodes = utxo_after_chronicle;
        self.flags = Some(flags);
    }

    /// Overrides the UTXO's era for the re-enabled opcodes: `true` runs
    /// `OP_2MUL`, `OP_2DIV`, `OP_VER`, `OP_VERIF`, `OP_VERNOTIF` and the
    /// Chronicle meanings of `0xb3`-`0xb7` (a coin created after Chronicle),
    /// `false` keeps them disabled, `BAD_OPCODE` or NOPs as before it; under a
    /// word it also selects the number length. It sets both switches: the era
    /// (default version > 1, the TypeScript SDK's `isAfterChronicle()`) and
    /// the opcode gate of `0xb3`-`0xb7` (default on at every version, as the
    /// reference's default runs them, bsv-rs#397); under a word both are its
    /// `UTXO_AFTER_CHRONICLE` bit. Called after [`set_flags`](Self::set_flags),
    /// it overrides the bit.
    pub fn set_utxo_after_chronicle(&mut self, after: bool) {
        self.utxo_after_chronicle = after;
        self.chronicle_opcodes = after;
    }

    /// The flag word applied by [`set_flags`](Self::set_flags), or `None` in
    /// the TypeScript default mode.
    pub fn flags(&self) -> Option<ScriptFlags> {
        self.flags
    }
}

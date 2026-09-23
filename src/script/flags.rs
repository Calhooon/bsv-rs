//! Script verification flags: the reference node's flag word, the protocol
//! eras, and the two words a node validates a spend under.
//!
//! A BSV node does not run one script interpreter; it runs one interpreter
//! under a 32-bit **flag word** that selects which rules apply, and it derives
//! two different words for the same transaction:
//!
//! * the **block word** (consensus): what a mining node applies when it
//!   connects a block. This is the only word that decides validity on the
//!   network.
//! * the **standard word** (mempool policy): the block word plus the
//!   standardness restrictions a node applies when it *relays* a
//!   transaction. A spend that fails only a standard-only rule is still valid
//!   in a block.
//!
//! [`ScriptFlags`] is that word with the reference's bit values, so it can
//! be compared with a node's own numbers; [`ScriptFlags::block`] and
//! [`ScriptFlags::standard`] are the reference's two derivations, transcribed
//! function by function; and [`Spend::set_flags`](super::Spend::set_flags)
//! applies a word to the interpreter with the reference's version gate at
//! every site the reference gates. Every citation below is bitcoin-sv v1.2.2
//! (`879fc8b`); a bare `interpreter.cpp:N` is `src/script/interpreter.cpp`.
//!
//! Without a word, [`Spend`](super::Spend) runs the TypeScript SDK's default
//! evaluation mode, which is neither of the node's words (see the table on
//! `ScriptFlags`). A caller that judges a spend **on the network's behalf**,
//! as a consensus oracle, selects the block word.
//!
//! ```rust
//! use bsv_rs::script::{ProtocolEra, ScriptFlags};
//!
//! // The block word of a post-Chronicle block (mainnet since height 943,816).
//! let consensus = ScriptFlags::block(ProtocolEra::PostChronicle);
//! assert!(consensus.contains(ScriptFlags::NULLFAIL));
//! assert!(!consensus.contains(ScriptFlags::MINIMALDATA));
//!
//! // The mempool word of the same block adds exactly the standard-only rules.
//! let relay = ScriptFlags::standard(ProtocolEra::PostChronicle);
//! assert_eq!(
//!     relay.without(consensus),
//!     ScriptFlags::NULLDUMMY
//!         | ScriptFlags::MINIMALDATA
//!         | ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS
//!         | ScriptFlags::CLEANSTACK
//! );
//! ```

use std::fmt;

/// The script-number length limit for a coin created after Genesis, on the
/// block path (`src/consensus/consensus.h:64`, `750 * ONE_KILOBYTE`).
pub const MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS: usize = 750_000;
/// The script-number length limit for a coin created after Chronicle, on the
/// block path (`src/consensus/consensus.h:66`, `32 * ONE_MEGABYTE`).
pub const MAX_SCRIPT_NUM_LENGTH_AFTER_CHRONICLE: usize = 32_000_000;
/// The node's default `-maxscriptnumlengthpolicy`, the script-number length
/// limit on the mempool path (`src/policy/policy.h:156`, `10 * ONE_KILOBYTE`).
pub const DEFAULT_SCRIPT_NUM_LENGTH_POLICY: usize = 10_000;

/// The protocol era of the block that carries the spending transaction, as
/// the reference derives it from a height (`src/protocol_era.cpp:21-39`:
/// below the Genesis activation height pre-Genesis, below the Chronicle
/// activation height post-Genesis, else post-Chronicle).
///
/// This interpreter implements the post-Genesis rule set only (no P2SH
/// evaluation, no pre-Genesis size or count limits, the re-enabled opcodes),
/// so the pre-Genesis era is not a value here: [`ProtocolEra::at_height`]
/// returns `None` below the Genesis height instead of a word this
/// interpreter could not honor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtocolEra {
    /// Genesis active, Chronicle not: mainnet heights 620,538 to 943,815.
    PostGenesis,
    /// Chronicle active: mainnet from height 943,816. Malleability
    /// restrictions are gated on the transaction version here
    /// (`interpreter.cpp:40-44`).
    PostChronicle,
}

impl ProtocolEra {
    /// The mainnet Genesis activation height (`src/chainparams.cpp:18`).
    pub const MAINNET_GENESIS_HEIGHT: u32 = 620_538;
    /// The mainnet Chronicle activation height (`src/chainparams.cpp:23`).
    pub const MAINNET_CHRONICLE_HEIGHT: u32 = 943_816;

    /// The era of a block at `height` on a chain with the given activation
    /// heights (`GetProtocolEra`, `src/protocol_era.cpp:21-39`), or `None`
    /// below the Genesis height (a pre-Genesis block, which this interpreter
    /// does not model).
    pub fn at_height(height: u32, genesis_height: u32, chronicle_height: u32) -> Option<Self> {
        if height < genesis_height {
            None
        } else if height < chronicle_height {
            Some(ProtocolEra::PostGenesis)
        } else {
            Some(ProtocolEra::PostChronicle)
        }
    }

    /// The era of a mainnet block at `height` (`src/chainparams.cpp:18,23`).
    pub fn mainnet(height: u32) -> Option<Self> {
        Self::at_height(
            height,
            Self::MAINNET_GENESIS_HEIGHT,
            Self::MAINNET_CHRONICLE_HEIGHT,
        )
    }

    /// `IsProtocolActive(era, ProtocolName::Chronicle)`
    /// (`src/protocol_era.cpp:95-98`).
    pub fn is_chronicle(self) -> bool {
        matches!(self, ProtocolEra::PostChronicle)
    }
}

/// A script verification flag word with the reference's bit values
/// (`src/script/script_flags.h:13-111`), so `bits()` compares with a node's
/// own numbers (its `-promiscuousmempoolflags` word, its RPC flag names).
///
/// **What the interpreter reads.** Each rule below is enforced at the site the
/// reference enforces it, under the same gate. `enforce` is the reference's
/// version gate `EnforceNonMalleability(flags, version)` =
/// `!(CHRONICLE && version > 1)` (`interpreter.cpp:40-44`).
///
/// | bit | enforced when | site |
/// |---|---|---|
/// | `MINIMALDATA` | flag && enforce | `interpreter.cpp:433` (pushes and numbers) |
/// | `LOW_S` | flag && enforce | `interpreter.cpp:282-288` |
/// | `CLEANSTACK` | flag && enforce | `interpreter.cpp:2436-2445` |
/// | `NULLDUMMY` | flag && enforce | `interpreter.cpp:1664-1670` |
/// | `NULLFAIL` | flag && enforce | `interpreter.cpp:1491-1497`, `1640-1646` |
/// | `MINIMALIF` | flag && enforce | `interpreter.cpp:795-803` |
/// | `SIGPUSHONLY` | flag && ((GENESIS && !CHRONICLE) \|\| (CHRONICLE && version <= 1)) | `interpreter.cpp:2321-2334` |
/// | `DISCOURAGE_UPGRADABLE_NOPS` | flag | `interpreter.cpp:522`, `565`, `765-771` (and the Chronicle names of NOP4-NOP8, `606-700`) |
/// | `COMPRESSED_PUBKEYTYPE` | flag | `interpreter.cpp:322-327` |
///
/// **What is always on.** Strict DER and public-key encodings and the
/// `SIGHASH_FORKID` requirement: the reference forces `STRICTENC` whenever
/// `SIGHASH_FORKID` is set (`interpreter.cpp:2315-2318`) and this interpreter
/// computes only the BIP-143 sighash, so a word must carry `SIGHASH_FORKID`
/// ([`ScriptFlags::check`]). `DERSIG` is then redundant (`interpreter.cpp:275-280`).
///
/// **What has no effect, and why that is faithful.** `P2SH`,
/// `CHECKLOCKTIMEVERIFY` and `CHECKSEQUENCEVERIFY` change nothing for a
/// UTXO created after Genesis on the reference either (`interpreter.cpp:2354`,
/// `520`, `563`), and this interpreter evaluates every UTXO under
/// post-Genesis rules (`UTXO_AFTER_GENESIS` is required by `check`).
///
/// **The UTXO's era.** `UTXO_AFTER_CHRONICLE` re-enables `OP_2MUL`, `OP_2DIV`,
/// `OP_VER`, `OP_VERIF` and `OP_VERNOTIF` and gives `0xb3`-`0xb7` their
/// Chronicle meanings (`OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_LSHIFTNUM`,
/// `OP_RSHIFTNUM`) for that UTXO, as the reference does
/// (`interpreter.cpp:360-375`, `598-812`); without the bit the two arithmetic
/// opcodes are disabled, the three version opcodes are `BAD_OPCODE` when
/// executed, and `0xb3`-`0xb7` are NOPs (discouraged under
/// `DISCOURAGE_UPGRADABLE_NOPS`). The reference's derivation sets the bit for
/// every coin created after Chronicle; `ScriptFlags::block(era)` and
/// `standard(era)` set it for a coin of the same era as the block.
///
/// **The TypeScript SDK's default mode is not a word.** Without `set_flags`,
/// `Spend` enforces `MINIMALDATA`, `LOW_S`, `CLEANSTACK` and `NULLDUMMY` for
/// version <= 1 only and push-only unlocking scripts at every version, never
/// `NULLFAIL`, `MINIMALIF` or `DISCOURAGE_UPGRADABLE_NOPS`: stricter than the
/// block word at version <= 1 (the standard-only rules) and looser than it
/// (no `NULLFAIL`), stricter than both words at version >= 2 (push-only).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    /// No flag (`SCRIPT_VERIFY_NONE`).
    pub const NONE: Self = Self(0);
    /// `SCRIPT_VERIFY_P2SH` (bit 0).
    pub const P2SH: Self = Self(1 << 0);
    /// `SCRIPT_VERIFY_STRICTENC` (bit 1).
    pub const STRICTENC: Self = Self(1 << 1);
    /// `SCRIPT_VERIFY_DERSIG` (bit 2).
    pub const DERSIG: Self = Self(1 << 2);
    /// `SCRIPT_VERIFY_LOW_S` (bit 3).
    pub const LOW_S: Self = Self(1 << 3);
    /// `SCRIPT_VERIFY_NULLDUMMY` (bit 4).
    pub const NULLDUMMY: Self = Self(1 << 4);
    /// `SCRIPT_VERIFY_SIGPUSHONLY` (bit 5).
    pub const SIGPUSHONLY: Self = Self(1 << 5);
    /// `SCRIPT_VERIFY_MINIMALDATA` (bit 6).
    pub const MINIMALDATA: Self = Self(1 << 6);
    /// `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS` (bit 7).
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);
    /// `SCRIPT_VERIFY_CLEANSTACK` (bit 8).
    pub const CLEANSTACK: Self = Self(1 << 8);
    /// `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` (bit 9).
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);
    /// `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` (bit 10).
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);
    /// `SCRIPT_VERIFY_MINIMALIF` (bit 13).
    pub const MINIMALIF: Self = Self(1 << 13);
    /// `SCRIPT_VERIFY_NULLFAIL` (bit 14).
    pub const NULLFAIL: Self = Self(1 << 14);
    /// `SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE` (bit 15).
    pub const COMPRESSED_PUBKEYTYPE: Self = Self(1 << 15);
    /// `SCRIPT_ENABLE_SIGHASH_FORKID` (bit 16).
    pub const SIGHASH_FORKID: Self = Self(1 << 16);
    /// `SCRIPT_GENESIS` (bit 18): the block is in the Genesis era or later.
    pub const GENESIS: Self = Self(1 << 18);
    /// `SCRIPT_UTXO_AFTER_GENESIS` (bit 19): the UTXO was created after
    /// Genesis (a per-input flag).
    pub const UTXO_AFTER_GENESIS: Self = Self(1 << 19);
    /// `SCRIPT_CHRONICLE` (bit 20): the block is in the Chronicle era.
    pub const CHRONICLE: Self = Self(1 << 20);
    /// `SCRIPT_UTXO_AFTER_CHRONICLE` (bit 21): the UTXO was created after
    /// Chronicle (a per-input flag; see the type docs for what this
    /// interpreter does not implement under it).
    pub const UTXO_AFTER_CHRONICLE: Self = Self(1 << 21);

    /// Every bit this crate knows, with the reference's name for it
    /// (`src/rpc/misc.cpp:1284-1305`, the same table as
    /// `src/test/scriptflags.cpp:17-38`).
    const NAMED: &'static [(Self, &'static str)] = &[
        (Self::P2SH, "P2SH"),
        (Self::STRICTENC, "STRICTENC"),
        (Self::DERSIG, "DERSIG"),
        (Self::LOW_S, "LOW_S"),
        (Self::NULLDUMMY, "NULLDUMMY"),
        (Self::SIGPUSHONLY, "SIGPUSHONLY"),
        (Self::MINIMALDATA, "MINIMALDATA"),
        (
            Self::DISCOURAGE_UPGRADABLE_NOPS,
            "DISCOURAGE_UPGRADABLE_NOPS",
        ),
        (Self::CLEANSTACK, "CLEANSTACK"),
        (Self::CHECKLOCKTIMEVERIFY, "CHECKLOCKTIMEVERIFY"),
        (Self::CHECKSEQUENCEVERIFY, "CHECKSEQUENCEVERIFY"),
        (Self::MINIMALIF, "MINIMALIF"),
        (Self::NULLFAIL, "NULLFAIL"),
        (Self::COMPRESSED_PUBKEYTYPE, "COMPRESSED_PUBKEYTYPE"),
        (Self::SIGHASH_FORKID, "SIGHASH_FORKID"),
        (Self::GENESIS, "GENESIS"),
        (Self::UTXO_AFTER_GENESIS, "UTXO_AFTER_GENESIS"),
        (Self::CHRONICLE, "CHRONICLE"),
        (Self::UTXO_AFTER_CHRONICLE, "UTXO_AFTER_CHRONICLE"),
    ];

    /// The union of every known bit.
    const KNOWN: u32 = {
        let mut acc = 0u32;
        let mut i = 0;
        while i < Self::NAMED.len() {
            acc |= Self::NAMED[i].0 .0;
            i += 1;
        }
        acc
    };

    /// The mandatory flags of a block in `era`
    /// (`MandatoryScriptVerifyFlags`, `src/script/standard.cpp:330-337`, over
    /// `src/script/standard.h:55-68`): `P2SH | STRICTENC | SIGHASH_FORKID |
    /// NULLFAIL | LOW_S`, plus `CHRONICLE` once Chronicle is active.
    fn mandatory(era: ProtocolEra) -> Self {
        let base =
            Self::P2SH | Self::STRICTENC | Self::SIGHASH_FORKID | Self::NULLFAIL | Self::LOW_S;
        if era.is_chronicle() {
            base | Self::CHRONICLE
        } else {
            base
        }
    }

    /// The standard-only flags (`STANDARD_SCRIPT_VERIFY_FLAGS`,
    /// `src/policy/policy.h:178-190`): `DERSIG | NULLDUMMY |
    /// DISCOURAGE_UPGRADABLE_NOPS | CHECKLOCKTIMEVERIFY | CHECKSEQUENCEVERIFY
    /// | CLEANSTACK | MINIMALDATA`. A block never carries them: "scripts
    /// violating these flags may still be present in valid blocks and we must
    /// accept those blocks."
    const STANDARD_ONLY: Self = Self(
        Self::DERSIG.0
            | Self::NULLDUMMY.0
            | Self::DISCOURAGE_UPGRADABLE_NOPS.0
            | Self::CHECKLOCKTIMEVERIFY.0
            | Self::CHECKSEQUENCEVERIFY.0
            | Self::CLEANSTACK.0
            | Self::MINIMALDATA.0,
    );

    /// The per-input flags of a coin created in `era`, spent in a block of
    /// the same era (`InputScriptVerifyFlags`, `src/policy/policy.h:226-245`):
    /// `SIGPUSHONLY` once Genesis is active for the block, `UTXO_AFTER_GENESIS`
    /// and `UTXO_AFTER_CHRONICLE` by the coin's era. A node ORs them into the
    /// block or mempool word for every input (`src/validation.cpp:2694-2702`).
    fn per_input(era: ProtocolEra) -> Self {
        let mut f = Self::SIGPUSHONLY | Self::UTXO_AFTER_GENESIS;
        if era.is_chronicle() {
            f |= Self::UTXO_AFTER_CHRONICLE;
        }
        f
    }

    /// The **block word** for a block in `era` spending a coin created in the
    /// same era: what a mining node applies when it connects the block
    /// (`GetBlockScriptFlags`, `src/verify_script_flags.cpp:32-81`, at any
    /// mainnet height past the DAA fork: `P2SH`, `DERSIG`,
    /// `CHECKLOCKTIMEVERIFY`, `CHECKSEQUENCEVERIFY`, `STRICTENC`,
    /// `SIGHASH_FORKID`, `LOW_S`, `NULLFAIL`, then `GENESIS | SIGPUSHONLY`
    /// and `CHRONICLE` by the era), unioned with the per-input flags
    /// (`src/validation.cpp:2697-2702`).
    ///
    /// This is the word a consensus oracle selects. For a post-Chronicle
    /// block the value is `0x3D462F`.
    pub fn block(era: ProtocolEra) -> Self {
        let mut f = Self::P2SH
            | Self::DERSIG
            | Self::CHECKLOCKTIMEVERIFY
            | Self::CHECKSEQUENCEVERIFY
            | Self::STRICTENC
            | Self::SIGHASH_FORKID
            | Self::LOW_S
            | Self::NULLFAIL
            | Self::GENESIS
            | Self::SIGPUSHONLY;
        if era.is_chronicle() {
            f |= Self::CHRONICLE;
        }
        f | Self::per_input(era)
    }

    /// The **standard word** for a block in `era`: what a node with default
    /// policy applies when it accepts a transaction into its mempool
    /// (`GetScriptVerifyFlags` with `require_standard`,
    /// `src/verify_script_flags.cpp:11-30`, = `StandardScriptVerifyFlags(era)`,
    /// `src/policy/policy.h:213-223`: the mandatory set, the standard-only
    /// set, `GENESIS`), unioned with the per-input flags.
    ///
    /// It is the block word plus exactly `NULLDUMMY | MINIMALDATA |
    /// DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK`; for a post-Chronicle block
    /// the value is `0x3D47FF`. A spend that fails under this word and passes
    /// under the block word is valid but non-standard: a miner may still
    /// include it.
    pub fn standard(era: ProtocolEra) -> Self {
        Self::mandatory(era) | Self::STANDARD_ONLY | Self::GENESIS | Self::per_input(era)
    }

    /// The four bits only the mempool word carries (`standard` sets them,
    /// `block` never does): `NULLDUMMY`, `MINIMALDATA`,
    /// `DISCOURAGE_UPGRADABLE_NOPS` and `CLEANSTACK`.
    const MEMPOOL_ONLY: Self = Self(
        Self::NULLDUMMY.0
            | Self::MINIMALDATA.0
            | Self::DISCOURAGE_UPGRADABLE_NOPS.0
            | Self::CLEANSTACK.0,
    );

    /// Whether the word carries the mempool word's four bits. Where the
    /// reference's rule depends on the path (`consensus` in
    /// `make_eval_script_params`, `interpreter.cpp:2283-2292`), this
    /// interpreter judges such a word on the mempool path and any other word
    /// on the block path.
    pub const fn is_mempool_word(self) -> bool {
        self.contains(Self::MEMPOOL_ONLY)
    }

    /// The script-number length limit under this word for a coin of the given
    /// era (`GetMaxScriptNumLength`, `src/configscriptpolicy.cpp:79-110`): on
    /// the block path the consensus limit of the coin's era
    /// ([`MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS`],
    /// [`MAX_SCRIPT_NUM_LENGTH_AFTER_CHRONICLE`]); on the mempool path
    /// `policy`, the node's `-maxscriptnumlengthpolicy`
    /// ([`DEFAULT_SCRIPT_NUM_LENGTH_POLICY`] by default), where 0 selects the
    /// consensus limit. A coin created before Genesis (4 bytes,
    /// `consensus.h:62`) is outside this interpreter's words
    /// ([`check`](Self::check)).
    pub const fn max_script_num_length(self, utxo_after_chronicle: bool, policy: usize) -> usize {
        let consensus = if utxo_after_chronicle {
            MAX_SCRIPT_NUM_LENGTH_AFTER_CHRONICLE
        } else {
            MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS
        };
        if self.is_mempool_word() && policy != 0 {
            policy
        } else {
            consensus
        }
    }

    /// The word as the reference's `uint32_t`.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// A word from the reference's `uint32_t`; a bit this crate does not know
    /// (11, 12, 17, 22 and above) is refused rather than ignored.
    pub fn from_bits(bits: u32) -> Result<Self, ScriptFlagsError> {
        let unknown = bits & !Self::KNOWN;
        if unknown != 0 {
            return Err(ScriptFlagsError::UnknownBits(unknown));
        }
        Ok(Self(bits))
    }

    /// A word from the reference's flag names (`P2SH`, `STRICTENC`, `DERSIG`,
    /// `LOW_S`, `NULLDUMMY`, `SIGPUSHONLY`, `MINIMALDATA`,
    /// `DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, `CHECKLOCKTIMEVERIFY`,
    /// `CHECKSEQUENCEVERIFY`, `MINIMALIF`, `NULLFAIL`, `COMPRESSED_PUBKEYTYPE`,
    /// `SIGHASH_FORKID`, `GENESIS`, `UTXO_AFTER_GENESIS`, `CHRONICLE`,
    /// `UTXO_AFTER_CHRONICLE`; `NONE` adds nothing), the vocabulary of the
    /// node's RPC and of the TypeScript SDK's `verifyFlags`. Whitespace around
    /// a name is ignored; an unknown name is refused.
    pub fn from_names<'a>(
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ScriptFlagsError> {
        let mut f = Self::NONE;
        for raw in names {
            let name = raw.trim();
            if name.is_empty() || name == "NONE" {
                continue;
            }
            match Self::NAMED.iter().find(|(_, n)| *n == name) {
                Some((bit, _)) => f |= *bit,
                None => return Err(ScriptFlagsError::UnknownName(name.to_string())),
            }
        }
        Ok(f)
    }

    /// The reference's names of the bits set, in bit order.
    pub fn names(self) -> Vec<&'static str> {
        Self::NAMED
            .iter()
            .filter(|(bit, _)| self.contains(*bit))
            .map(|(_, n)| *n)
            .collect()
    }

    /// Whether every bit of `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// This word with every bit of `other` cleared.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether this interpreter can honor the word. A word fails when it
    /// asks for rules this interpreter does not implement, or when the
    /// reference itself would refuse it:
    ///
    /// * without `SIGHASH_FORKID`: the legacy sighash is not computed here;
    /// * without `GENESIS` or without `UTXO_AFTER_GENESIS`: pre-Genesis block
    ///   or UTXO rules are not implemented here;
    /// * `CHRONICLE` without `GENESIS`: no node derives it (`IsProtocolActive`,
    ///   `src/protocol_era.cpp:89-103`);
    /// * `UTXO_AFTER_CHRONICLE` without `UTXO_AFTER_GENESIS`: the reference's
    ///   `valid_flags` refuses it with `SCRIPT_ERR_INVALID_FLAGS`
    ///   (`interpreter.cpp:2258-2266`, `2312-2313`);
    /// * `CLEANSTACK` without `P2SH`: refused the same way
    ///   (`interpreter.cpp:2436-2437`).
    ///
    /// [`Spend::validate`](super::Spend::validate) runs this check first and
    /// reports a failure as a script evaluation error, as the reference does.
    pub fn check(self) -> Result<(), ScriptFlagsError> {
        if !self.contains(Self::SIGHASH_FORKID) {
            return Err(ScriptFlagsError::NotApplicable(
                "SIGHASH_FORKID is not set: this interpreter computes the BIP-143 sighash only",
            ));
        }
        if !self.contains(Self::GENESIS) {
            return Err(ScriptFlagsError::NotApplicable(
                "GENESIS is not set: pre-Genesis block rules are not implemented by this interpreter",
            ));
        }
        if !self.contains(Self::UTXO_AFTER_GENESIS) {
            return Err(ScriptFlagsError::NotApplicable(
                "UTXO_AFTER_GENESIS is not set: pre-Genesis UTXO rules are not implemented by this interpreter",
            ));
        }
        if self.contains(Self::CHRONICLE) && !self.contains(Self::GENESIS) {
            return Err(ScriptFlagsError::NotApplicable(
                "CHRONICLE without GENESIS: no node derives this word",
            ));
        }
        if self.contains(Self::UTXO_AFTER_CHRONICLE) && !self.contains(Self::UTXO_AFTER_GENESIS) {
            return Err(ScriptFlagsError::NotApplicable(
                "UTXO_AFTER_CHRONICLE without UTXO_AFTER_GENESIS: the reference refuses this word (valid_flags)",
            ));
        }
        if self.contains(Self::CLEANSTACK) && !self.contains(Self::P2SH) {
            return Err(ScriptFlagsError::NotApplicable(
                "CLEANSTACK without P2SH: the reference refuses this word",
            ));
        }
        Ok(())
    }

    /// The reference's version gate `EnforceNonMalleability(flags, version)`
    /// (`interpreter.cpp:40-44`): a transaction of version 2 or above in a
    /// Chronicle-era block is malleable, and every malleability restriction
    /// is switched off for it, whatever the word says. Before Chronicle the
    /// gate is always on.
    pub const fn enforce_non_malleability(self, tx_version: i32) -> bool {
        !(self.contains(Self::CHRONICLE) && tx_version > 1)
    }

    /// The reference's push-only condition (`interpreter.cpp:2321-2334`):
    /// under `SIGPUSHONLY`, a push-only unlocking script is required when the
    /// block is post-Genesis but pre-Chronicle, or post-Chronicle and the
    /// transaction is non-malleable (version <= 1).
    pub const fn requires_push_only(self, tx_version: i32) -> bool {
        self.contains(Self::SIGPUSHONLY)
            && ((self.contains(Self::GENESIS) && !self.contains(Self::CHRONICLE))
                || (self.contains(Self::CHRONICLE) && tx_version <= 1))
    }

    /// The rules the interpreter derives from a word for a transaction
    /// version, one per gated site.
    pub(crate) fn gates(self, tx_version: i32) -> Gates {
        let enforce = self.enforce_non_malleability(tx_version);
        Gates {
            push_only: self.requires_push_only(tx_version),
            minimal: self.contains(Self::MINIMALDATA) && enforce,
            low_s: self.contains(Self::LOW_S) && enforce,
            clean_stack: self.contains(Self::CLEANSTACK) && enforce,
            null_dummy: self.contains(Self::NULLDUMMY) && enforce,
            null_fail: self.contains(Self::NULLFAIL) && enforce,
            minimal_if: self.contains(Self::MINIMALIF) && enforce,
            discourage_upgradable_nops: self.contains(Self::DISCOURAGE_UPGRADABLE_NOPS),
            compressed_pubkey: self.contains(Self::COMPRESSED_PUBKEYTYPE),
            utxo_after_chronicle: self.contains(Self::UTXO_AFTER_CHRONICLE),
        }
    }
}

/// The interpreter's rule switches, derived from a word and a version
/// ([`ScriptFlags::gates`]); the TypeScript default mode sets them directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Gates {
    pub push_only: bool,
    pub minimal: bool,
    pub low_s: bool,
    pub clean_stack: bool,
    pub null_dummy: bool,
    pub null_fail: bool,
    pub minimal_if: bool,
    pub discourage_upgradable_nops: bool,
    pub compressed_pubkey: bool,
    /// The UTXO was created after Chronicle: `OP_2MUL`, `OP_2DIV`, `OP_VER`,
    /// `OP_VERIF`, `OP_VERNOTIF` and the Chronicle meanings of `0xb3`-`0xb7`
    /// are live for it (`interpreter.cpp:360-375`, `598-812`).
    pub utxo_after_chronicle: bool,
}

impl std::ops::BitOr for ScriptFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for ScriptFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Debug for ScriptFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScriptFlags({:#x}: {})", self.0, self.names().join("|"))
    }
}

impl fmt::Display for ScriptFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("NONE");
        }
        f.write_str(&self.names().join(","))
    }
}

/// Why a flag word was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptFlagsError {
    /// Bits this crate does not know (the reference defines none there, or
    /// this crate does not model them).
    UnknownBits(u32),
    /// A name outside the reference's table.
    UnknownName(String),
    /// A word this interpreter cannot honor, or one the reference refuses
    /// (see [`ScriptFlags::check`]).
    NotApplicable(&'static str),
}

impl fmt::Display for ScriptFlagsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptFlagsError::UnknownBits(bits) => {
                write!(f, "unknown script verification flag bits {:#x}", bits)
            }
            ScriptFlagsError::UnknownName(name) => {
                write!(f, "unknown script verification flag name '{}'", name)
            }
            ScriptFlagsError::NotApplicable(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for ScriptFlagsError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words a post-Chronicle mainnet node derives today, as `uint32_t`:
    /// the block word `0x3D462F` and the standard word `0x3D47FF`. Bits:
    /// P2SH 0, STRICTENC 1, DERSIG 2, LOW_S 3, SIGPUSHONLY 5, CLTV 9, CSV 10,
    /// NULLFAIL 14, SIGHASH_FORKID 16, GENESIS 18, UTXO_AFTER_GENESIS 19,
    /// CHRONICLE 20, UTXO_AFTER_CHRONICLE 21; the standard word adds
    /// NULLDUMMY 4, MINIMALDATA 6, DISCOURAGE_UPGRADABLE_NOPS 7, CLEANSTACK 8.
    #[test]
    fn the_post_chronicle_block_and_standard_words_have_the_reference_values() {
        assert_eq!(
            ScriptFlags::block(ProtocolEra::PostChronicle).bits(),
            0x3D462F
        );
        assert_eq!(
            ScriptFlags::standard(ProtocolEra::PostChronicle).bits(),
            0x3D47FF
        );
    }

    #[test]
    fn the_post_genesis_words_drop_the_two_chronicle_bits_and_nothing_else() {
        let block = ScriptFlags::block(ProtocolEra::PostGenesis);
        let chronicle = ScriptFlags::block(ProtocolEra::PostChronicle);
        assert_eq!(
            chronicle.without(block),
            ScriptFlags::CHRONICLE | ScriptFlags::UTXO_AFTER_CHRONICLE
        );
        assert_eq!(block.without(chronicle), ScriptFlags::NONE);
        let standard = ScriptFlags::standard(ProtocolEra::PostGenesis);
        assert_eq!(
            ScriptFlags::standard(ProtocolEra::PostChronicle).without(standard),
            ScriptFlags::CHRONICLE | ScriptFlags::UTXO_AFTER_CHRONICLE
        );
    }

    /// `policy.h:178-190`: the block word never carries a standard-only flag
    /// (the reference's comment: blocks violating them must be accepted).
    #[test]
    fn the_block_word_never_carries_a_standard_only_flag() {
        for era in [ProtocolEra::PostGenesis, ProtocolEra::PostChronicle] {
            let block = ScriptFlags::block(era);
            for bit in [
                ScriptFlags::NULLDUMMY,
                ScriptFlags::MINIMALDATA,
                ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS,
                ScriptFlags::CLEANSTACK,
            ] {
                assert!(
                    !block.contains(bit),
                    "{era:?}: {bit:?} is in the block word"
                );
            }
            assert_eq!(
                ScriptFlags::standard(era).without(block),
                ScriptFlags::NULLDUMMY
                    | ScriptFlags::MINIMALDATA
                    | ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS
                    | ScriptFlags::CLEANSTACK
            );
        }
    }

    /// `interpreter.cpp:46-49`, the four `static_assert`s.
    #[test]
    fn the_version_gate_matches_the_references_static_asserts() {
        let none = ScriptFlags::NONE;
        let chronicle = ScriptFlags::CHRONICLE;
        assert!(none.enforce_non_malleability(1));
        assert!(none.enforce_non_malleability(2));
        assert!(chronicle.enforce_non_malleability(1));
        assert!(!chronicle.enforce_non_malleability(2));
        // A negative version is not malleable either (`version > 1`).
        assert!(chronicle.enforce_non_malleability(-1));
        assert!(chronicle.enforce_non_malleability(0));
    }

    /// `interpreter.cpp:2321-2334`.
    #[test]
    fn push_only_is_required_pre_chronicle_at_every_version_and_post_chronicle_at_version_1() {
        let genesis = ScriptFlags::block(ProtocolEra::PostGenesis);
        assert!(genesis.requires_push_only(1));
        assert!(genesis.requires_push_only(2));
        let chronicle = ScriptFlags::block(ProtocolEra::PostChronicle);
        assert!(chronicle.requires_push_only(1));
        assert!(!chronicle.requires_push_only(2));
        assert!(!chronicle
            .without(ScriptFlags::SIGPUSHONLY)
            .requires_push_only(1));
    }

    #[test]
    fn the_gates_of_the_block_word_follow_the_version_at_chronicle() {
        let word = ScriptFlags::block(ProtocolEra::PostChronicle);
        let v1 = word.gates(1);
        assert!(v1.low_s && v1.null_fail && v1.push_only);
        assert!(!v1.minimal && !v1.clean_stack && !v1.null_dummy && !v1.minimal_if);
        assert!(!v1.discourage_upgradable_nops && !v1.compressed_pubkey);
        let v2 = word.gates(2);
        assert_eq!(
            v2,
            Gates {
                push_only: false,
                minimal: false,
                low_s: false,
                clean_stack: false,
                null_dummy: false,
                null_fail: false,
                minimal_if: false,
                discourage_upgradable_nops: false,
                compressed_pubkey: false,
                utxo_after_chronicle: true,
            }
        );
        assert!(
            !ScriptFlags::block(ProtocolEra::PostGenesis)
                .gates(2)
                .utxo_after_chronicle
        );
        let standard_v1 = ScriptFlags::standard(ProtocolEra::PostChronicle).gates(1);
        assert!(standard_v1.minimal && standard_v1.clean_stack && standard_v1.null_dummy);
        assert!(standard_v1.discourage_upgradable_nops);
        let standard_v2 = ScriptFlags::standard(ProtocolEra::PostChronicle).gates(2);
        assert!(
            standard_v2.discourage_upgradable_nops,
            "not a malleability rule: no version gate"
        );
        assert!(!standard_v2.minimal && !standard_v2.clean_stack && !standard_v2.null_dummy);
    }

    #[test]
    fn the_gates_of_the_standard_word_before_chronicle_ignore_the_version() {
        let word = ScriptFlags::standard(ProtocolEra::PostGenesis);
        assert_eq!(word.gates(1), word.gates(2));
        assert!(word.gates(2).minimal && word.gates(2).null_fail && word.gates(2).push_only);
    }

    #[test]
    fn names_round_trip_through_the_references_table() {
        let word = ScriptFlags::standard(ProtocolEra::PostChronicle);
        let names = word.names();
        assert_eq!(
            ScriptFlags::from_names(names.iter().copied()).unwrap(),
            word
        );
        assert_eq!(
            ScriptFlags::from_names(" NULLFAIL , SIGHASH_FORKID,NONE".split(',')).unwrap(),
            ScriptFlags::NULLFAIL | ScriptFlags::SIGHASH_FORKID
        );
        assert_eq!(
            ScriptFlags::from_names(["NULLFAIL", "BIP16"]).unwrap_err(),
            ScriptFlagsError::UnknownName("BIP16".into())
        );
        assert_eq!(word.to_string(), names.join(","));
        assert_eq!(ScriptFlags::NONE.to_string(), "NONE");
    }

    #[test]
    fn from_bits_refuses_a_bit_the_crate_does_not_know() {
        assert_eq!(
            ScriptFlags::from_bits(0x3D462F).unwrap(),
            ScriptFlags::block(ProtocolEra::PostChronicle)
        );
        assert_eq!(
            ScriptFlags::from_bits(1 << 11).unwrap_err(),
            ScriptFlagsError::UnknownBits(1 << 11)
        );
        assert_eq!(
            ScriptFlags::from_bits(0x3D462F | (1 << 22)).unwrap_err(),
            ScriptFlagsError::UnknownBits(1 << 22)
        );
    }

    #[test]
    fn check_refuses_what_the_interpreter_cannot_honor_and_what_the_reference_refuses() {
        assert!(ScriptFlags::block(ProtocolEra::PostGenesis).check().is_ok());
        assert!(ScriptFlags::standard(ProtocolEra::PostChronicle)
            .check()
            .is_ok());
        let block = ScriptFlags::block(ProtocolEra::PostChronicle);
        assert!(block.without(ScriptFlags::SIGHASH_FORKID).check().is_err());
        assert!(block.without(ScriptFlags::GENESIS).check().is_err());
        assert!(block
            .without(ScriptFlags::UTXO_AFTER_GENESIS)
            .check()
            .is_err());
        assert!((ScriptFlags::SIGHASH_FORKID
            | ScriptFlags::GENESIS
            | ScriptFlags::UTXO_AFTER_CHRONICLE)
            .check()
            .is_err());
        assert!((block | ScriptFlags::CLEANSTACK)
            .without(ScriptFlags::P2SH)
            .check()
            .is_err());
        assert!((block | ScriptFlags::CLEANSTACK).check().is_ok());
    }

    #[test]
    fn the_mainnet_eras_switch_at_the_activation_heights() {
        assert_eq!(ProtocolEra::mainnet(620_537), None);
        assert_eq!(
            ProtocolEra::mainnet(620_538),
            Some(ProtocolEra::PostGenesis)
        );
        assert_eq!(
            ProtocolEra::mainnet(943_815),
            Some(ProtocolEra::PostGenesis)
        );
        assert_eq!(
            ProtocolEra::mainnet(943_816),
            Some(ProtocolEra::PostChronicle)
        );
        assert_eq!(
            ProtocolEra::at_height(20_000, 10_000, 15_000),
            Some(ProtocolEra::PostChronicle)
        );
        assert_eq!(
            ProtocolEra::at_height(12_000, 10_000, 15_000),
            Some(ProtocolEra::PostGenesis)
        );
    }
}

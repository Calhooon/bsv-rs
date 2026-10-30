//! #520: the public typed resolver owns the live door's no-tip rule.
#![cfg(all(feature = "script", feature = "block"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #520 regression witnesses.

use bsv_rs::block::{ActivationHeightsError, ChainParams};
use bsv_rs::script::{input_script_flags, NotJudgedCause, ScriptFlags, ScriptFlagsError, Word};

#[test]
fn a_public_typed_input_word_accepts_optional_heights_520() {
    type Resolver =
        fn(&ChainParams, Word, Option<u32>, Option<u32>) -> Result<ScriptFlags, NotJudgedCause>;
    let resolve: Resolver = ChainParams::word_for_input;
    assert_eq!(
        resolve(&ChainParams::mainnet(), Word::Standard, None, None).map(ScriptFlags::bits),
        Ok(0x3d47ff),
    );
}

#[derive(Clone, Debug)]
struct Case {
    chain: ChainParams,
    spend: Option<u32>,
    source: Option<u32>,
    // Exact (standard, block) words, independent of the composition under test.
    expected: Result<(u32, u32), NotJudgedCause>,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for chain in [
        ChainParams::mainnet(),
        ChainParams::testnet(),
        ChainParams::regtest(),
        ChainParams::regtest()
            .with_activation_heights(100, 200)
            .unwrap(),
        ChainParams::regtest()
            .with_activation_heights(1, 2)
            .unwrap(),
        ChainParams::regtest()
            .with_activation_heights(u32::MAX - 1, u32::MAX)
            .unwrap(),
    ] {
        let (g, c) = (chain.genesis_height, chain.chronicle_height);
        let before_spend = Err(NotJudgedCause::PreGenesisSpend {
            height: g - 1,
            genesis_height: g,
        });
        let before_coin = Err(NotJudgedCause::PreGenesisCoin {
            height: g - 1,
            genesis_height: g,
        });
        for (spend, source, expected) in [
            (Some(g - 1), Some(g - 1), before_spend),
            (Some(g - 1), Some(g), before_spend),
            (Some(g), Some(g - 1), before_coin),
            (Some(g), None, Ok((0x0d47ff, 0x0d462f))),
            (Some(c - 1), Some(g), Ok((0x0d47ff, 0x0d462f))),
            (Some(c), Some(c - 1), Ok((0x1d47ff, 0x1d462f))),
            (Some(c), Some(c), Ok((0x3d47ff, 0x3d462f))),
            (Some(c), None, Ok((0x3d47ff, 0x3d462f))),
            (Some(u32::MAX), Some(g), Ok((0x1d47ff, 0x1d462f))),
            (Some(g), Some(c), Ok((0x2d47ff, 0x2d462f))),
            (None, None, Ok((0x3d47ff, 0x3d462f))),
            (None, Some(g), Ok((0x1d47ff, 0x1d462f))),
            (None, Some(c), Ok((0x3d47ff, 0x3d462f))),
            (None, Some(g - 1), before_coin),
        ] {
            cases.push(Case {
                chain: chain.clone(),
                spend,
                source,
                expected,
            });
        }
    }
    // Public field overrides are checked even with no tip, and before either era.
    for (g, c, expected) in [
        (0, 0, ActivationHeightsError::ZeroGenesis),
        (0, 200, ActivationHeightsError::ZeroGenesis),
        (100, 0, ActivationHeightsError::ZeroChronicle),
    ] {
        let mut chain = ChainParams::regtest();
        chain.genesis_height = g;
        chain.chronicle_height = c;
        for spend in [None, Some(0), Some(99), Some(u32::MAX)] {
            cases.push(Case {
                chain: chain.clone(),
                spend,
                source: Some(0),
                expected: Err(NotJudgedCause::ZeroActivationHeight(expected)),
            });
        }
    }
    // The latest known era uses the maximum, including equal/reversed activations.
    for (g, c) in [(200, 100), (100, 100)] {
        let chain = ChainParams::regtest()
            .with_activation_heights(g, c)
            .unwrap();
        for spend in [None, Some(g), Some(u32::MAX)] {
            cases.push(Case {
                chain: chain.clone(),
                spend,
                source: None,
                expected: Ok((0x3d47ff, 0x3d462f)),
            });
        }
    }
    cases
}

#[test]
fn typed_input_words_pin_the_era_table_and_existing_refusal_order_520() {
    let cases = cases();
    assert_eq!(cases.len(), 102);
    for case in cases {
        for word in [Word::Standard, Word::Block] {
            let expected = case.expected.map(|(standard, block)| {
                if word == Word::Standard {
                    standard
                } else {
                    block
                }
            });
            let actual = case.chain.word_for_input(word, case.spend, case.source);
            assert_eq!(
                actual.map(ScriptFlags::bits),
                expected,
                "{word:?}: {case:?}"
            );
            let legacy = input_script_flags(
                &case.chain,
                case.spend
                    .unwrap_or_else(|| case.chain.genesis_height.max(case.chain.chronicle_height)),
                case.source,
                word == Word::Block,
            );
            match (actual, legacy) {
                (Ok(flags), Ok(old)) => assert_eq!(flags, old, "{case:?}"),
                (Err(cause), Err(ScriptFlagsError::NotApplicable(message))) => {
                    let expected = match cause {
                        NotJudgedCause::ZeroActivationHeight(ActivationHeightsError::ZeroGenesis) =>
                            "Genesis activation height cannot be configured with a zero or negative value.",
                        NotJudgedCause::ZeroActivationHeight(ActivationHeightsError::ZeroChronicle) =>
                            "Chronicle activation height cannot be configured with a zero or negative value.",
                        NotJudgedCause::PreGenesisSpend { .. } =>
                            "The spending transaction is before Genesis; its script era is unsupported.",
                        NotJudgedCause::PreGenesisCoin { .. } =>
                            "The source output was created before Genesis; its script era is unsupported.",
                        other => panic!("unexpected resolver cause: {other:?}"),
                    };
                    assert_eq!(message, expected, "{case:?}");
                }
                other => panic!("legacy disagreement for {case:?}: {other:?}"),
            }
        }
    }
}

#[cfg(feature = "transaction")]
mod streaming {
    use super::*;
    use bsv_rs::primitives::{PrivateKey, Reader, Writer};
    use bsv_rs::script::{LockingScript, Script, SigningContext, UnlockingScript};
    use bsv_rs::transaction::beef_stream::{ChainTip, Hash32, Headers};
    use bsv_rs::transaction::{
        verify_stream_two_pass_with_chain_params, Beef, BeefStream, Element, MerklePath,
        StreamVerifier, Transaction, TransactionInput, TransactionOutput, Verdict, BEEF_V1,
    };
    use std::io::Cursor;

    struct Facts {
        roots: Vec<(u64, Hash32)>,
        tip: Option<ChainTip>,
    }

    impl Headers for Facts {
        fn carries(&self, height: u64, root: &Hash32) -> bool {
            self.roots.contains(&(height, *root))
        }
        fn mining_tip(&self) -> Option<ChainTip> {
            self.tip
        }
    }

    #[allow(deprecated)] // The compatibility field is ignored under ChainParams (#451).
    fn tip(height: u32) -> ChainTip {
        ChainTip {
            height,
            median_time_past: 0,
            genesis_height: 1,
            csv_height: 0,
            next_block_time: None,
        }
    }

    fn parent(lock: LockingScript, proven: Option<u32>, genesis: u32) -> Transaction {
        let mut tx = Transaction::new();
        let mut input = match proven {
            Some(_) => TransactionInput::new("aa".repeat(32), 0),
            None => TransactionInput::with_source_transaction(
                parent(
                    LockingScript::from_hex("51").unwrap(),
                    Some(genesis.max(1)),
                    genesis,
                ),
                0,
            ),
        };
        input.set_unlocking_script(UnlockingScript::new());
        tx.add_input(input).unwrap();
        tx.add_output(TransactionOutput::new(1_000, lock)).unwrap();
        tx.merkle_path = proven.map(|height| MerklePath::from_coinbase_txid(&tx.id(), height));
        tx
    }

    fn spending(case: &Case, lock: LockingScript) -> Transaction {
        let mut tx = Transaction::new();
        let mut input = TransactionInput::with_source_transaction(
            parent(lock, case.source, case.chain.genesis_height),
            0,
        );
        input.set_unlocking_script(UnlockingScript::new());
        tx.add_input(input).unwrap();
        tx.add_output(TransactionOutput::new(
            900,
            LockingScript::from_hex("51").unwrap(),
        ))
        .unwrap();
        tx
    }

    fn verdicts(bytes: &[u8], tip_height: Option<u32>, chain: &ChainParams) -> [Verdict; 2] {
        let roots = BeefStream::new(bytes)
            .filter_map(|element| match element.unwrap() {
                Element::Bump(bump) => Some((bump.block_height, bump.root)),
                _ => None,
            })
            .collect();
        let facts = Facts {
            roots,
            tip: tip_height.map(tip),
        };
        [
            StreamVerifier::new(bytes, &facts, None)
                .with_chain_params(chain.clone())
                .run()
                .unwrap(),
            verify_stream_two_pass_with_chain_params(Cursor::new(bytes), &facts, None, chain)
                .unwrap(),
        ]
    }

    #[test]
    fn the_same_height_table_has_the_same_stream_verdicts_520() {
        let mut checked = 0;
        for case in cases() {
            // tip + 1 cannot express height zero; the public method pins it above.
            if case.spend == Some(0) {
                continue;
            }
            let tx = spending(&case, LockingScript::from_hex("51").unwrap());
            let bytes = tx.to_beef(false).unwrap();
            for verdict in verdicts(&bytes, case.spend.map(|h| h - 1), &case.chain) {
                match (case.expected, verdict) {
                    (Ok(_), Verdict::Valid { .. }) => {}
                    (Err(expected), Verdict::NotJudged { cause, .. }) => {
                        assert_eq!(cause, expected, "{case:?}")
                    }
                    other => panic!("stream disagreement for {case:?}: {other:?}"),
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 97);
    }

    fn with_wide_height(tx: &Transaction, height: u64) -> Vec<u8> {
        let beef = Beef::from_binary(&tx.to_beef(false).unwrap()).unwrap();
        assert_eq!(beef.bumps.len(), 1);
        let bump = beef.bumps[0].to_binary();
        let mut reader = Reader::new(&bump);
        reader.read_var_int().unwrap();
        let mut writer = Writer::new();
        writer.write_u32_le(BEEF_V1);
        writer.write_var_int(1);
        writer.write_var_int(height);
        writer.write_bytes(reader.read_remaining());
        writer.write_var_int(beef.txs.len() as u64);
        for tx in &beef.txs {
            tx.to_writer(&mut writer, BEEF_V1);
        }
        writer.into_bytes()
    }

    #[test]
    fn height_conversion_refusals_precede_activation_and_era_checks_520() {
        let wide = u64::from(u32::MAX) + 1;
        let mut chain = ChainParams::regtest();
        chain.genesis_height = 0;
        chain.chronicle_height = 0;
        let case = Case {
            chain,
            spend: None,
            source: Some(0),
            expected: Ok((0, 0)),
        };
        let tx = spending(&case, LockingScript::from_hex("51").unwrap());
        for (tip, height, expected) in [
            (
                Some(u32::MAX),
                0,
                NotJudgedCause::TipHeightOverflow { tip: u32::MAX },
            ),
            (
                Some(0),
                wide,
                NotJudgedCause::SourceHeightOverflow { height: wide },
            ),
            (
                None,
                u64::MAX,
                NotJudgedCause::SourceHeightOverflow { height: u64::MAX },
            ),
            // The existing stream converts its u64 source first, even if both overflow.
            (
                Some(u32::MAX),
                wide,
                NotJudgedCause::SourceHeightOverflow { height: wide },
            ),
        ] {
            let bytes = with_wide_height(&tx, height);
            for verdict in verdicts(&bytes, tip, &case.chain) {
                assert!(
                    matches!(verdict, Verdict::NotJudged { cause, .. } if cause == expected),
                    "{verdict:?}"
                );
            }
        }
    }

    #[test]
    fn stream_execution_observes_both_independent_era_bits_520() {
        let chain = ChainParams::regtest()
            .with_activation_heights(100, 200)
            .unwrap();
        for (spend, source, coin_chronicle, spend_chronicle) in [
            (Some(100), Some(100), false, false),
            (Some(199), None, false, false),
            (Some(200), Some(199), false, true),
            (Some(200), Some(200), true, true),
            (Some(200), None, true, true),
            (None, Some(100), false, true),
            (None, None, true, true),
        ] {
            let case = Case {
                chain: chain.clone(),
                spend,
                source,
                expected: Ok((0, 0)),
            };
            // OP_2MUL is enabled by the source coin's Chronicle bit.
            let tx = spending(&case, LockingScript::from_hex("518d5287").unwrap());
            for verdict in verdicts(&tx.to_beef(false).unwrap(), spend.map(|h| h - 1), &chain) {
                assert_eq!(
                    verdict.is_valid(),
                    coin_chronicle,
                    "coin era {case:?}: {verdict:?}"
                );
                if !coin_chronicle {
                    assert!(matches!(verdict, Verdict::SpendRefused { .. }));
                }
            }
            // A version-1 SIGHASH_CHRONICLE signature uses the spending era.
            let key = PrivateKey::from_hex(&format!("{:064x}", 42)).unwrap();
            let mut lock = Script::new();
            lock.write_bin(&key.public_key().to_compressed())
                .write_opcode(0xac);
            let mut tx = spending(&case, LockingScript::from_script(lock));
            tx.version = 1;
            let source = tx.inputs[0].source_transaction.as_ref().unwrap();
            let digest = SigningContext::new(
                &tx.to_binary(),
                0,
                1_000,
                source.outputs[0].locking_script.as_script(),
            )
            .compute_sighash(0x61)
            .unwrap();
            let mut signature = key.sign(&digest).unwrap().to_der();
            signature.push(0x61);
            let mut unlock = Script::new();
            unlock.write_bin(&signature);
            tx.inputs[0].set_unlocking_script(UnlockingScript::from_script(unlock));
            tx.invalidate_caches();
            for verdict in verdicts(&tx.to_beef(false).unwrap(), spend.map(|h| h - 1), &chain) {
                assert_eq!(
                    verdict.is_valid(),
                    spend_chronicle,
                    "spend era {case:?}: {verdict:?}"
                );
                if !spend_chronicle {
                    assert!(matches!(verdict, Verdict::SpendRefused { .. }));
                }
            }
        }
    }
}

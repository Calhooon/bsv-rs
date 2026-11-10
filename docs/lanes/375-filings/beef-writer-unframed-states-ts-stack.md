keeper's word first

# Beef.toBinary writes a version word its reader refuses, a txid-only txid of another length and a raw entry with bytes after its lock time as frames no reader reads back as written

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's three divergence rows on the BEEF writers (#817). Drafted by the fix-817-beef-writers lane on 2026-11-10. One draft, a section per state, as the MerklePath writer's draft (row 58) is.

## 1. A version word other than V1 or V2

`toWriter` writes `this.version` whatever it holds (`Beef.ts:1169-1170`), and `BeefTx.toWriter` uses the V1 layout for any word but V2 (`BeefTx.ts:270-285`). The same SDK's reader refuses the bytes (`Beef.ts:1251-1254`), so `mergeBeef` of such a BEEF throws from its snapshot while `toBinary` returns bytes no reader takes.

Steps (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0): read a V1 BEEF, set `version = 0xefbe0003`, call `toHex()`: it returns `0300beef01...`; `Beef.fromBinaryStrict` of it throws `Serialized BEEF must start with 4022206465 or 4022206466 but starts with 4022206467`. With `version = 0x01010101` the reader reads the word as an Atomic prefix and names `2958992019`, the bytes 32 on.

Expected: `toBinary` throws its reader's sentence. Actual: it writes the frame.

## 2. A txid-only txid that is not 64 hex digits

`writeTxid` writes `toArray(this._txid, 'hex')` (`BeefTx.ts:247-250`): 62 digits as 31 bytes (the strict reader then `ReaderUint8Array read exceeds available data`), 66 as 33 (the strict reader `Serialized BEEF contains trailing data`, the prefix reader the leading 32), and 63 padded with a leading zero (`utils.ts:128`) to 32 bytes that read back as `0` followed by the 63, another txid. `mergeTxidOnly` takes any text (`Beef.ts:919-929`).

Expected: `toBinary` throws for a txid of other than 64 hex digits. Actual: it writes it at its length, or pads it.

## 3. A raw entry with bytes after its lock time, or any bytes merged with a BUMP index

`mergeRawTx` scans only where no BUMP index is given (`BeefTx.ts:203,234-235`), and the scan reads a prefix while the entry keeps the whole buffer (`:24-48`); `toWriter` writes the buffer whole. A raw entry has no length prefix in a BEEF, so the next element is read from the extra bytes: `mergeRawTx(tx + [0x00])`, then `toHex`, then `fromBinaryStrict` throws `Serialized BEEF contains trailing data`; `mergeRawTx(tx.slice(0, 10), 0)` writes a frame its strict reader refuses with `ReaderUint8Array read exceeds available data`.

Expected: `mergeRawTx` refuses bytes that are not exactly one transaction, with or without an index. Actual: it keeps them and the writer misframes the BEEF.

bsv-rs refuses all three before any byte (the words in its rows); go-sdk at 2ca481c refuses the version word in `Bytes` (`transaction/beef.go:1533-1534`), holds a txid as a 32-byte hash, and parses `MergeRawTx`'s bytes (`:820-826`).

Witness (bsv-rs, the #817 landing; links to be pinned at filing): `tests/beef_writer_refusals_817.rs` (`each_writer_cell_is_the_reference_s_or_a_stated_refusal_817`, `the_raw_door_refuses_bytes_that_are_not_one_transaction_817`, `the_raw_bytes_the_reference_door_keeps_are_written_unreadably_there_817`) on `tests/vectors/beef_v1_txid_only_writer_817.json` (`writers`, `raw_door`), recorded by `tests/support/beef_v1_txid_only_writer_817.mjs`.

Pinned reference reading: [ts-stack@edf6e03da packages/sdk/src/transaction/Beef.ts:1169-1170,1251-1254](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L1169-L1170); [BeefTx.ts:16-48,203,234-235,247-285](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/BeefTx.ts#L16-L48); [go-sdk@2ca481c59 transaction/beef.go:1533-1534](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/beef.go#L1533-L1534).

BRC reading: [BRCs@5119a9b51 transactions/0062.md](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0062.md) and [transactions/0096.md](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0096.md) name the two version words and a txid-only entry's 32 bytes; a raw transaction is framed by its own fields (the lines to be cited by the keeper at filing).

Requested maintainer action: make `toBinary` throw for a version word other than V1 or V2 (its reader's sentence) and for a txid-only txid of other than 64 hex digits, and make `mergeRawTx` refuse bytes that are not exactly one transaction whether or not a BUMP index is given; add the cells above as regressions.

Evidence status: the reference was run (Node 22.18.0, two runs byte-identical) by the linked recorder; go-sdk source-read at the pin, not run. This draft contains no private-key literal.

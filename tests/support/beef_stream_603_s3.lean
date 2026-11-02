/-
The recorder of `tests/vectors/beef_stream_603_s3.json` (#603, shard S3): the sibling's definition
(bsv-stack-lean `lean/BeefOfAnySize.lean`, `readBytes`, `Index.size`, `finish`) read on one row its
scenarios do not carry, a BEEF of two BUMPs that both carry one txid, so that the index's
"(level-0 txid, BUMP) pairs" count a txid twice (`Index.size`, :860-861: each BUMP's own set, then the
proven set once). The shape uses the scenarios' encoders and stand-in hashing
(`lean/BeefOfAnySize/Scenarios.lean`); no count it records reads a digest's value, only the equalities
of the txids, so the same shape under SHA-256 (`tests/beef_stream_603_s3.rs`) has the same counts.

Run, from a scratch copy of the sibling's `lean/` at its pin (the sources compiled with `lean -o` into a
scratch output directory, the packages' prebuilt `.olean`s on `LEAN_PATH`; the sibling's clone is
never written):

  lean +leanprover/lean4:v4.34.0 --run tests/support/beef_stream_603_s3.lean \
    > tests/vectors/beef_stream_603_s3.json
-/
import BeefOfAnySize.Scenarios

open BeefOfAnySize BeefOfAnySize.Scenarios

namespace S3

/-- Two txids no transaction of the row carries, proven beside the anchor. -/
def provenOne : TxId := stubTxid [0x51]
def provenTwo : TxId := stubTxid [0x52]

/-- BUMP A: a block of four at 800,000 (tree height 2), level 0 the anchor at 0, the two at 1 and 2,
the duplicate marker at 3, nothing above. -/
def bumpA : Bytes :=
  bumpBytes 800000 2
    [[.hash 0 anchorTxid true, .hash 1 provenOne true, .hash 2 provenTwo true, .dup 3], []]

/-- BUMP B: the anchor again, a block of two at 800,006 (the chain's anchor BUMP at another height). -/
def bumpB : Bytes := bumpBytes 800006 1 [[.hash 0 anchorTxid true, .dup 1]]

/-- The subject: one output, spending the anchor's two outputs. -/
def subjectTx : Bytes := rawTx [(anchorTxid, 0), (anchorTxid, 1)] 1
def subjectTxid : TxId := stubTxid subjectTx

/-- The BEEF (V1): the two BUMPs, the anchor under BUMP A, the subject unproven. -/
def beefBytes : Bytes :=
  leBytes 4 BEEF_V1 ++ [2] ++ bumpA ++ bumpB ++ [2] ++ anchorTx ++ [1, 0] ++ subjectTx ++ [0]

/-- The same under the Atomic prefix, the subject named. -/
def atomicBytes : Bytes := leBytes 4 ATOMIC_BEEF ++ leBytes 32 subjectTxid ++ beefBytes

def headers : Tracker.Headers :=
  { tip := 800006,
    header := fun h =>
      if h = 800000 then some ⟨"block", Hash.hex (rootOf bumpA)⟩
      else if h = 800006 then some ⟨"block", Hash.hex (rootOf bumpB)⟩ else none }

def row (name : String) (bytes : Bytes) : String :=
  match readBytes stub headers bytes with
  | .ok s =>
    s!"    \{\"name\": \"{name}\", \"bytes\": {bytes.length}, \"verdict\": \"accepted\", " ++
    s!"\"steps\": {s.steps}, \"work\": {s.work}, \"index_size\": {s.index.size}}"
  | .error e =>
    s!"    \{\"name\": \"{name}\", \"bytes\": {bytes.length}, \"verdict\": \"refused\", " ++
    s!"\"offset\": {e.offset}, \"reason\": \"{reprStr e.reason}\"}"

end S3

def main : IO Unit := do
  IO.println "{"
  IO.println "  \"description\": \"#603 shard S3: the sibling's reader (bsv-stack-lean lean/BeefOfAnySize.lean readBytes) on a BEEF of two BUMPs carrying one txid (BUMP A at 800000: the anchor, two proven txids and the duplicate marker; BUMP B at 800006: the anchor again), the anchor under BUMP A and an unproven subject spending the anchor's two outputs; plain and under the Atomic prefix\","
  IO.println "  \"recorder\": \"tests/support/beef_stream_603_s3.lean, Lean 4.34.0, the stand-in hashing of lean/BeefOfAnySize/Scenarios.lean\","
  IO.println "  \"sibling\": \"bsv-stack-lean@9a69056314a0d7bebc84ed9b16af6fdf081fcca5\","
  IO.println "  \"rows\": ["
  IO.println (S3.row "two_bumps_one_txid" S3.beefBytes ++ ",")
  IO.println (S3.row "two_bumps_one_txid_atomic" S3.atomicBytes)
  IO.println "  ]"
  IO.println "}"

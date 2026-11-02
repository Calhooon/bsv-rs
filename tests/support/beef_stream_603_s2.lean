/-
The #603 shard S2 Lean recorder: bsv-stack-lean's `BeefOfAnySize` (the Lean the stream reader
`src/transaction/beef_stream.rs` states, `lean/BeefOfAnySize.lean`) reading the BEEFs of
`tests/vectors/beef_reference_603.json`'s `stream_s2_*` cases under SHA-256 (the sibling
bsv-script-lean's `BsvScript.Hash.sha256d`, a dependency of bsv-stack-lean), with headers that
carry the roots the reference checked; and bsv-script-lean's `BsvChain.isFinalTx`
(`lean/BsvChain/Finality.lean:116-120`) on the lock-time case's transaction.

Run against bsv-stack-lean at 88c37ac8, its packages built (bsvscript v1.1.1); its own three modules
compiled from the pin into a folder `$O` (a checkout's `.lake` build may predate the pin):
  cd ~/bsv/bsv-stack-lean && for f in Tracker BeefOfAnySize BeefOfAnySize/Scenarios; do
    git show 88c37ac8:lean/$f.lean > $S/$f.lean; done
  cd lean && for f in Tracker BeefOfAnySize BeefOfAnySize/Scenarios; do
    lake env sh -c "LEAN_PATH=$O:\$LEAN_PATH lean -R $S -o $O/$f.olean $S/$f.lean"; done
  lake env sh -c "LEAN_PATH=$O:\$LEAN_PATH BEEF_603_VECTORS=<this tree>/tests/vectors/beef_reference_603.json \
    lean <this tree>/tests/support/beef_stream_603_s2.lean" > <this tree>/tests/vectors/beef_stream_603_s2_lean.json

Each reading: the refusal (`repr`, or null) and, accepted, the state's `steps`, `work`
(`Parsed.cost` summed, `BeefOfAnySize.lean:913-926`) and `index.size` (`Index.size`, :860-861):
the Lean's `summary` (`BeefOfAnySize/Scenarios.lean:91-95`).
-/
import Lean.Data.Json
import BeefOfAnySize.Scenarios
import BsvScript.Hash.Sha256
import BsvChain.Finality

open Lean BeefOfAnySize

namespace Beef603S2

/-- The txid and the Merkle parent under SHA-256d, the digests read little-endian as the
reader reads every 32 bytes (`leNat`). -/
def sha256Hashing : Hashing :=
  ⟨fun bs => leNat ((BsvScript.Hash.sha256d (bs.map (·.toNat))).map UInt8.ofNat),
   fun a b => leNat ((BsvScript.Hash.sha256d
     ((Scenarios.leBytes 32 a ++ Scenarios.leBytes 32 b).map (·.toNat))).map UInt8.ofNat)⟩

def hexDigit (c : Char) : Nat :=
  if c.isDigit then c.toNat - '0'.toNat else c.toLower.toNat - 'a'.toNat + 10

def unhex : List Char → List Nat
  | a :: b :: rest => (16 * hexDigit a + hexDigit b) :: unhex rest
  | _ => []

/-- Headers carrying, at each height, the root the reference checked (display hex). -/
def headersOf (roots : List (Nat × String)) : Tracker.Headers :=
  { tip := 0, header := fun h => (roots.lookup h).map fun r => ⟨"", r⟩ }

def reading (hex : String) (roots : List (Nat × String)) : Json :=
  let bytes := (unhex hex.toList).map UInt8.ofNat
  match readBytes sha256Hashing (headersOf roots) bytes with
  | .ok s => Json.mkObj [("refusal", Json.null), ("steps", toJson s.steps),
      ("work", toJson s.work), ("size", toJson s.index.size)]
  | .error r => Json.mkObj [("refusal", toJson (toString (repr r)))]

def rootsOf (c : Json) : List (Nat × String) :=
  match c.getObjVal? "roots" with
  | .ok (.obj kvs) => kvs.toList.filterMap fun (k, v) =>
      match k.toNat?, v.getStr? with
      | some h, .ok r => some (h, r)
      | _, _ => none
  | _ => []

/-- `finality/threshold-500000000` (bsv-script-lean `corpus/chain/finality/finality.jsonl`): its
height and cutoff, and the same lock read at candidate height 800001 with a cutoff of 500000001. -/
def finality (raw : String) : Json :=
  match BsvScript.Tx.decodeTx (unhex raw.toList) with
  | none => Json.str "undecodable"
  | some tx => Json.mkObj [
      ("row_height_500000000_time_500000000", toJson (BsvChain.isFinalTx tx 500000000 500000000)),
      ("height_800001_time_500000001", toJson (BsvChain.isFinalTx tx 800001 500000001))]

def main : IO Unit := do
  let path ← IO.getEnv "BEEF_603_VECTORS"
  let text ← IO.FS.readFile (path.getD "tests/vectors/beef_reference_603.json")
  let json ← IO.ofExcept (Json.parse text)
  let cases ← IO.ofExcept (json.getObjVal? "cases")
  let .obj kvs := cases | throw (IO.userError "cases is not an object")
  let mut out : List (String × Json) := []
  for (name, c) in kvs.toList do
    if name.startsWith "stream_s2_" then
      if let .ok hex := c.getObjValAs? String "hex" then
        let mut fields := [("reading", reading hex (rootsOf c))]
        if let .ok raw := c.getObjValAs? String "child_raw" then
          fields := fields ++ [("is_final_tx", finality raw)]
        out := out ++ [(name, Json.mkObj fields)]
  IO.println (Json.mkObj [
    ("lean", Json.str "bsv-stack-lean@88c37ac8 lean/BeefOfAnySize.lean readBytes; bsv-script-lean@a478bf56 (v1.1.1) BsvScript.Hash.sha256d, BsvChain.isFinalTx"),
    ("cases", Json.mkObj out)]).pretty

end Beef603S2

#eval Beef603S2.main

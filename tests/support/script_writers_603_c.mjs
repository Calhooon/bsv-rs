// #603, shard C: src/script/script.rs's writers (`compute_serialized_length`,
// `serialize_chunks_to_bytes`, `write_bin`, `write_number`) against the
// sibling's corpus and the reference's writer.
//
// The inputs are entries of bsv-script-lean@5dc337e1's corpora (`bytes`,
// `arith`, `seed`, `gen`, `tx`), copied by id with their scripts and recorded
// verdicts; every expectation besides the corpus's own bytes is the
// reference's `Script.ts` at ts-stack@edf6e03 (`writeBin` :338-360, `writeBn`
// :309-329, `writeNumber` :368-372, `toBinary` :254-260 over
// `#computeSerializedLength` :450-471, whose total sizes the output buffer).
// A script longer than 4096 bytes is recorded as its length, its first 16
// bytes and its SHA-256; a shorter one as its hex.
//
// Recorded under Node v22.18.0 against the SDK bundled with bun (no node_modules):
//   R=<a clone of ts-stack at edf6e03>; W=<a scratch folder>
//   (cd "$R/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_writers_603_c.mjs \
//     "$W/sdk.mjs" ~/bsv/bsv-script-lean/corpus > tests/vectors/script_writers_603_c.json
// The tests are `tests/script_script_603_c.rs` and `tests/script_script_603_c_length.rs`.
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import { pathToFileURL } from 'url'

const [sdkPath, corpusDir] = process.argv.slice(2)
const { Script, Transaction, BigNumber } = await import(pathToFileURL(sdkPath).href)

const WANT = {
  'bytes/cases.jsonl': ['bytes-00076', 'bytes-00077', 'bytes-00078', 'bytes-00079'],
  'arith/cases.jsonl': [
    'arith-00005', 'arith-00011', 'arith-00013', 'arith-00101', 'arith-00117', 'arith-00119',
    'arith-00121', 'arith-00123', 'arith-00643', 'arith-00687'
  ],
  'seed/seed.jsonl': [
    'seed-000001', 'seed-000020', 'seed-000027', 'seed-000030', 'seed-000040', 'seed-000044',
    'seed-000050', 'seed-000092', 'seed-000101', 'seed-000126', 'seed-000133', 'seed-000159',
    'seed-000195', 'seed-000647', 'seed-000785', 'seed-000824', 'seed-005218'
  ],
  'gen/gen.jsonl': ['gen-00999'],
  'tx/tx.jsonl': ['tx-00040']
}
const entries = {}
for (const [file, ids] of Object.entries(WANT)) {
  for (const line of fs.readFileSync(path.join(corpusDir, file), 'utf8').split('\n')) {
    if (line.trim() === '') continue
    const e = JSON.parse(line)
    if (ids.includes(e.id)) entries[e.id] = { ...e, corpus: file }
  }
  for (const id of ids) if (entries[id] == null) throw new Error(`no ${id} in ${file}`)
}

const hex = bytes => Buffer.from(bytes).toString('hex')
const shape = bytes =>
  bytes.length <= 4096
    ? { hex: hex(bytes) }
    : {
        len: bytes.length,
        head: hex(bytes.slice(0, 16)),
        sha256: crypto.createHash('sha256').update(Uint8Array.from(bytes)).digest('hex')
      }
const verdicts = e => ({
  'bsv-rs@0.7.0': e.expect['bsv-rs@0.7.0'].verdict,
  'sv-node@v1.2.3': e.expect['sv-node@v1.2.3'].verdict
})
const tx = e => Transaction.fromHex(e.tx)
const source = (e, where) => {
  if (where === 'prevout 0') return Array.from(Buffer.from(e.prevouts[0].script, 'hex'))
  if (where === 'input 0') return tx(e).inputs[0].unlockingScript.toBinary()
  if (where === 'output 0') return tx(e).outputs[0].lockingScript.toBinary()
  throw new Error(where)
}
// (7i + 1) mod 256: the data of a push whose length no corpus entry carries.
const pattern = n => Array.from({ length: n }, (_, i) => (7 * i + 1) % 256)

// The length path and the serializer: a corpus script read into chunks and
// written back from them (`new Script(chunks).toBinary()`).
const SCRIPTS = [
  ['bytes-00076', 'prevout 0', 'a direct push of 75 bytes (0x4b), the last direct push'],
  ['bytes-00077', 'prevout 0', 'OP_PUSHDATA1 of one byte'],
  ['bytes-00078', 'prevout 0', 'OP_PUSHDATA2 of one byte'],
  ['bytes-00079', 'prevout 0', 'OP_PUSHDATA4 of one byte'],
  ['arith-00011', 'prevout 0', 'two OP_PUSHDATA1 pushes of 80 bytes around OP_AND, then OP_EQUAL'],
  ['arith-00013', 'prevout 0', 'two OP_PUSHDATA2 pushes of 520 bytes around OP_AND, then OP_EQUAL'],
  ['arith-00687', 'prevout 0', 'two OP_PUSHDATA1 pushes of 100 bytes around OP_ADD, then OP_EQUAL'],
  ['seed-000647', 'prevout 0', 'OP_9, then a top-level OP_RETURN and six bytes of data'],
  ['gen-00999', 'prevout 0', 'a 33-byte key push, OP_CHECKSIG, then a top-level OP_RETURN and four bytes'],
  ['seed-000785', 'input 0', 'OP_PUSHDATA2 of 65535 bytes, the last OP_PUSHDATA2 length'],
  ['tx-00040', 'output 0', 'OP_0, a top-level OP_RETURN and 10000034 bytes (an OP_PUSHDATA4 of 10000029 zeros)']
]
const scripts = SCRIPTS.map(([id, where, note]) => {
  const e = entries[id]
  const bytes = source(e, where)
  const rewritten = new Script(Script.fromBinary(bytes).chunks.map(c => ({ ...c }))).toBinary()
  const small = id !== 'tx-00040' && id !== 'seed-000785'
  return {
    id,
    corpus: e.corpus,
    family: e.family,
    where,
    note,
    verdicts: verdicts(e),
    params: e.params,
    ...(small ? { tx: e.tx, prevout_satoshis: e.prevouts[0].satoshis } : {}),
    script: shape(bytes),
    reference_rewritten: shape(rewritten)
  }
})

// The push writer (`writeBin`): the data of a corpus push at its length, or
// the pattern at a length the corpus lacks, written into an empty script.
const push = (len, data, from) => {
  const s = new Script()
  s.writeBin(data)
  return { len, from, op: s.chunks[0].op, reference: shape(s.toBinary()) }
}
const corpusPush = (id, where, index) => {
  const chunk = Script.fromBinary(source(entries[id], where)).chunks[index]
  return { data: chunk.data, fill: chunk.data.every(b => b === chunk.data[0]) ? chunk.data[0] : null }
}
const pushes = []
for (const [id, where, index] of [
  ['bytes-00076', 'prevout 0', 0],
  ['arith-00011', 'prevout 0', 0],
  ['arith-00687', 'prevout 0', 0],
  ['arith-00013', 'prevout 0', 0],
  ['arith-00643', 'prevout 0', 0],
  ['seed-000785', 'input 0', 0]
]) {
  const { data, fill } = corpusPush(id, where, index)
  pushes.push({
    ...push(data.length, data, `${id} ${where} chunk ${index}`),
    data: fill != null ? { fill } : { hex: hex(data) }
  })
}
for (const len of [1, 76, 255, 256, 65536, 16777216]) {
  pushes.push({ ...push(len, pattern(len), null), data: { pattern: '(7i + 1) mod 256' } })
}

// tx-00040's output script through the writers: OP_0, OP_RETURN (as opcodes),
// then the push of 10000029 zeros; the corpus bytes are `scripts`' tx-00040.
const opReturnPush = (() => {
  const s = new Script()
  s.writeOpCode(0x00).writeOpCode(0x6a).writeBin(new Array(10000029).fill(0))
  return { id: 'tx-00040', where: 'output 0', data_len: 10000029, fill: 0, reference: shape(s.toBinary()) }
})()

// The 4 GiB bound: `writeBin` reads only `bin.length` before it throws
// (:340-353), so an array-like of that length stands for the array a JS
// engine cannot build (its length is at most 2^32 - 1).
const bound = [4294967295, 4294967296].map(len => {
  try {
    const s = new Script()
    s.writeBin({ length: len })
    return { len, op: s.chunks[0].op }
  } catch (err) {
    return { len, throws: err.message }
  }
})

// The number writer (`writeBn` through `writeNumber`): the reference's script
// for each value, and the corpus entry whose script pushes that value's
// minimal encoding (the push's hex as the corpus carries it, in the input's
// script or else the previous output's).
const NUMBERS = [
  ['-2', 'seed-000040'],
  ['17', 'arith-00101'],
  ['127', 'seed-000126'],
  ['-127', 'seed-000092'],
  ['128', 'arith-00005'],
  ['-128', 'seed-000092'],
  ['-129', 'seed-000001'],
  ['255', 'seed-000101'],
  ['-255', 'seed-000824'],
  ['256', 'seed-000159'],
  ['-256', 'seed-005218'],
  ['32767', 'seed-000195'],
  ['-32767', 'seed-000050'],
  ['32768', 'seed-000020'],
  ['-32768', 'seed-000030'],
  ['65535', 'arith-00117'],
  ['65536', 'arith-00119'],
  ['2147483647', 'arith-00121'],
  ['2147483648', 'arith-00123'],
  ['-2147483648', 'seed-000027'],
  ['9223372036854775807', 'seed-000044'],
  ['-9223372036854775807', 'seed-000133'],
  ['-9223372036854775808', null]
]
const numbers = NUMBERS.map(([value, id]) => {
  const s = new Script()
  s.writeBn(new BigNumber(value))
  const written = s.toBinary()
  const record = { value, reference: hex(written) }
  if (id != null) {
    const e = entries[id]
    const want = s.chunks[0].data
    let chunk
    let where
    for (where of ['input 0', 'prevout 0']) {
      chunk = Script.fromBinary(source(e, where)).chunks.find(
        c => c.data != null && c.op < 0x4c && hex(c.data) === hex(want)
      )
      if (chunk != null) break
    }
    if (chunk == null) throw new Error(`${id}: no push of ${value}`)
    Object.assign(record, {
      id,
      corpus: e.corpus,
      family: e.family,
      where,
      corpus_push: hex([chunk.op, ...chunk.data]),
      verdicts: verdicts(e)
    })
  }
  return record
})

process.stdout.write(
  JSON.stringify(
    {
      source:
        'ts-stack@edf6e03 packages/sdk/src/script/Script.ts under Node ' +
        process.version +
        ', on bsv-script-lean@5dc337e1 corpus entries copied by id',
      scripts,
      pushes,
      op_return_push: opReturnPush,
      bound,
      numbers
    },
    null,
    2
  ) + '\n'
)

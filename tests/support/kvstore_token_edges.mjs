// #843's third fold: every refusal of the kvstore token reader at its edge,
// judged by the reference's `decodeAndVerifyKVStoreToken`
// (`packages/sdk/src/kvstore/kvStoreTokenValidation.ts`) at the pin
// `ts-stack@edf6e03` (`:85-119`) and at the head the fold read, `11faa7d1`
// (2026-11-16; `:84-118`), under Node v22.18.0. The tokens are this crate's (the
// ignored writer in `src/kvstore/token_edges_tests.rs`, PushDrop's script,
// KeyDeriver's lock, ProtoWallet's signature):
//   KVSTORE_EDGES_OUT=<tokens.json> cargo test --features "full,http" --lib \
//     kvstore::token_validation::edges::record_the_edge_tokens -- --ignored --exact
// Each SDK is bundled from an archive of its sha:
//   W=$TMPDIR/ref-<sha>; git -C ~/bsv/ts-stack archive <sha> packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
// Then:
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/kvstore_token_edges.mjs \
//     <pin sdk.mjs> <head sdk.mjs> <tokens.json> > tests/vectors/kvstore_token_edges.json
// The vector keeps each script's SHA-256, not its bytes (the 1 MiB cells);
// the replay rebuilds every script and checks the hash. No randomness is
// read: the reader signs nothing.
import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

const [pinPath, headPath, tokensPath] = process.argv.slice(2)
const pin = await import(pathToFileURL(pinPath).href)
const head = await import(pathToFileURL(headPath).href)
const tokens = JSON.parse(readFileSync(tokensPath, 'utf8'))
const sha256 = (bytes) => createHash('sha256').update(Buffer.from(bytes)).digest('hex')
const utf8 = (text) => Buffer.from(text, 'utf8')

// A tag no JSON reader of this crate holds (a lone surrogate, #843's fourth
// fold) is written as its UTF-16 code units.
const writable = (tag) =>
  tag.isWellFormed() ? tag : { utf16: [...Array(tag.length).keys()].map((i) => tag.charCodeAt(i)) }

const judge = async (sdk, hex) => {
  try {
    const token = await sdk.decodeAndVerifyKVStoreToken(sdk.LockingScript.fromHex(hex))
    return {
      accepted: true,
      protocol_id_text: token.protocolIDText,
      name_sha256: sha256(utf8(token.key)),
      value_sha256: sha256(utf8(token.value)),
      controller: token.controller,
      tags: token.tags?.map(writable) ?? null
    }
  } catch (e) {
    return { accepted: false, words: String(e.message) }
  }
}

const cells = []
for (const { row, name, hex } of tokens) {
  const cell = { row, name, sha256: sha256(Buffer.from(hex, 'hex')), pin: await judge(pin, hex) }
  const atHead = await judge(head, hex)
  if (JSON.stringify(atHead) !== JSON.stringify(cell.pin)) cell.head = atHead
  cells.push(cell)
}
process.stdout.write(JSON.stringify({
  reference: {
    pin: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9',
    head: 'ts-stack@11faa7d16dd2b9567006e7d82d125d634dee128e',
    node: process.version,
    reader: 'decodeAndVerifyKVStoreToken',
    head_note: 'a cell carries `head` only where the head answers otherwise than the pin'
  },
  cells
}, null, 1) + '\n')

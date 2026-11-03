// #616: the reference's words for PushDrop tokens at two sites, each read by
// `decodeCanonicalPushDrop` with the site's limits and by the site's own
// reader: the registry's `decodeAndVerifyRegistryToken('basket', ...)` and
// the overlay admin token's static `OverlayAdminTokenTemplate.decode`
// (`ts-stack@edf6e03` `PushDropValidation.ts:54-79`,
// `registryTokenValidation.ts:10-31`, `OverlayAdminTokenTemplate.ts:29-30,159-167,237-239`).
// Usage: node pushdrop_canonical_bounds_616.mjs <sdk.mjs> > vectors/pushdrop_canonical_bounds_616.json
// The tokens are described by shape (the site, the second opcode, the field
// lengths, every field byte 0x61 but a `last_field_byte` when given, written
// minimally as the PushDrop writer writes it) and pinned by the SHA-256 of
// their bytes, which the Rust test's own PushDrop writer must reproduce.
import { createHash } from 'node:crypto'

const sdk = await import(process.argv[2])
const { LockingScript, decodeCanonicalPushDrop, decodeAndVerifyRegistryToken, OverlayAdminTokenTemplate, OP } = sdk

const KEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const SITES = {
  registry: {
    limits: { fieldCount: 7, maximumFieldBytes: 16 * 1024, maximumPayloadBytes: 64 * 1024 },
    read: async (s) => decodeAndVerifyRegistryToken('basket', s)
  },
  overlay_admin_token: {
    limits: { fieldCount: 5, maximumFieldBytes: 4096, maximumPayloadBytes: 8192 },
    read: async (s) => OverlayAdminTokenTemplate.decode(s)
  }
}
const R = 'registry'
const A = 'overlay_admin_token'
const NOP = 0x61
const shapes = [
  { name: 'no_checksig_oversized_field', site: R, second_op: NOP, field_lengths: [16385, 2, 2, 2, 2, 2, 2] },
  { name: 'no_checksig_payload_too_large', site: R, second_op: NOP, field_lengths: [16384, 16384, 16384, 16384, 16384, 16384, 16384] },
  { name: 'no_checksig_in_bounds', site: R, second_op: NOP, field_lengths: [2, 2, 2, 2, 2, 2, 2] },
  { name: 'checksig_oversized_field', site: R, second_op: OP.OP_CHECKSIG, field_lengths: [16385, 2, 2, 2, 2, 2, 2] },
  // The strength fold: the count before the bounds, the payload's `>`, the
  // field's check before the payload's, the opcode field's one byte, and a
  // second site's two bounds.
  { name: 'no_checksig_wrong_count_oversized_field', site: R, second_op: NOP, field_lengths: [16385, 2, 2, 2, 2, 2] },
  { name: 'no_checksig_payload_at_bound', site: R, second_op: NOP, field_lengths: [16384, 16384, 16384, 16381, 1, 1, 1] },
  { name: 'no_checksig_oversized_field_crossing_payload', site: R, second_op: NOP, field_lengths: [16384, 16384, 16384, 16385, 2, 2, 2] },
  { name: 'no_checksig_op_1_field_crossing_payload', site: R, second_op: NOP, field_lengths: [16384, 16384, 16384, 16382, 1, 1, 1], last_field_byte: 1 },
  { name: 'admin_token_no_checksig_at_bounds', site: A, second_op: NOP, field_lengths: [4096, 4093, 1, 1, 1] },
  { name: 'admin_token_no_checksig_oversized_field', site: A, second_op: NOP, field_lengths: [4097, 1, 1, 1, 1] },
  { name: 'admin_token_no_checksig_payload_too_large', site: A, second_op: NOP, field_lengths: [4096, 4096, 1, 1, 1] }
]

function push (data) {
  if (data.length === 1 && data[0] >= 1 && data[0] <= 16) return { op: OP.OP_1 + data[0] - 1 }
  if (data.length <= 75) return { op: data.length, data }
  if (data.length <= 0xff) return { op: OP.OP_PUSHDATA1, data }
  return { op: OP.OP_PUSHDATA2, data }
}

function fields (shape) {
  const all = shape.field_lengths.map((length) => new Array(length).fill(0x61))
  if (shape.last_field_byte !== undefined) all[all.length - 1] = [shape.last_field_byte]
  return all
}

function script (shape) {
  const chunks = [{ op: 33, data: [...Buffer.from(KEY, 'hex')] }, { op: shape.second_op }]
  chunks.push(...fields(shape).map(push))
  for (let left = shape.field_lengths.length; left > 1; left -= 2) chunks.push({ op: OP.OP_2DROP })
  if (shape.field_lengths.length % 2 === 1) chunks.push({ op: OP.OP_DROP })
  return new LockingScript(chunks)
}

function words (f) {
  try { f(); return null } catch (e) { return e.message }
}

async function asyncWords (f) {
  try { await f(); return null } catch (e) { return e.message }
}

const cases = []
for (const shape of shapes) {
  const s = script(shape)
  const bytes = Buffer.from(s.toHex(), 'hex')
  const site = SITES[shape.site]
  cases.push({
    ...shape,
    script_bytes: bytes.length,
    script_sha256: createHash('sha256').update(bytes).digest('hex'),
    canonical_words: words(() => decodeCanonicalPushDrop(LockingScript.fromHex(s.toHex()), site.limits)),
    site_words: await asyncWords(() => site.read(LockingScript.fromHex(s.toHex())))
  })
}
console.log(JSON.stringify({
  reference: 'ts-stack@edf6e03 packages/sdk (bun build mod.ts), Node ' + process.version,
  key: KEY,
  field_byte: 0x61,
  limits: Object.fromEntries(Object.entries(SITES).map(([name, site]) => [name, site.limits])),
  cases
}, null, 2))

// #543: the registry's definition token as the reference writes and reads it
// (`ts-stack@edf6e03`, Node 22). The writer is `RegistryClient.registerDefinition`
// itself (`RegistryClient.ts:308-342`), run with a `ProtoWallet` on the scalar 9
// up to its createAction, whose output is the token: the data fields
// (`#buildPushDropFields`, `:688-722`), then `PushDrop.lock(fields, protocol,
// '1', 'anyone', true)` (`:320`; `PushDrop.ts:146-202`: the key the wallet's
// `getPublicKey` for counterparty `anyone` and `forSelf`, the signature its
// `createSignature` over the fields' bytes concatenated, counterparty `anyone`,
// appended as the last field). The reader is `decodeAndVerifyRegistryToken`
// (`registryTokenValidation.ts:13-64`: 6/6/7 data fields plus the signature,
// the canonical envelope, the operator-linked key, the signature verified by
// `ProtoWallet('anyone')`), and `RegistryClient.resolve` (`:370-397`) with
// `LookupResolver.prototype.query` answering the token.
//
// `base_tokens` are this crate's tokens before #543 (6/6/7 fields, no
// signature, locked with the operator's identity key, the protocol ID written
// `[1, "name"]`), built here from their fields; `refusals` are a reference
// token changed in one respect; `counterparties` a reference token whose
// operator text is another form, signed and locked for it; `operator_orders`
// a bad operator beside a non-DER signature and an operator in whitespace.
// Each records the validator's verdict and words.
//   W=$TMPDIR/ref-543
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/registry_token_fields_543.mjs \
//     "$W/sdk.mjs" > tests/vectors/registry_token_fields_543.json
const sdk = await import(process.argv[2])
const {
  PushDrop, LockingScript, Transaction, PrivateKey, PublicKey, KeyDeriver, ProtoWallet,
  LookupResolver, RegistryClient, decodeAndVerifyRegistryToken, Utils, OP
} = sdk

const utf8 = (text) => Utils.toArray(text, 'utf8')
const hex = (bytes) => Utils.toHex(bytes)
const operatorKey = PrivateKey.fromHex('09'.padStart(64, '0'))
const inner = new ProtoWallet(operatorKey)
const operator = (await inner.getPublicKey({ identityKey: true })).publicKey

const definitions = [
  {
    definitionType: 'basket',
    basketID: 'basket1',
    name: 'Basket',
    iconURL: 'https://icon.example/basket.png',
    description: 'A basket',
    documentationURL: 'https://doc.example/basket'
  },
  {
    definitionType: 'protocol',
    protocolID: [1, 'proto name'],
    name: 'Proto',
    iconURL: 'https://icon.example/proto.png',
    description: 'A protocol',
    documentationURL: 'https://doc.example/proto'
  },
  {
    definitionType: 'certificate',
    type: 'certtype',
    name: 'Cert',
    iconURL: 'https://icon.example/cert.png',
    description: 'A certificate',
    documentationURL: 'https://doc.example/cert',
    fields: {
      email: {
        friendlyName: 'Email',
        description: 'Email address',
        type: 'text',
        fieldIcon: 'https://icon.example/email.png'
      }
    }
  }
]

// The wallet the reference's client is given: the ProtoWallet's keys and
// signatures, its calls recorded, createAction keeping the outputs and
// stopping the action.
const calls = []
let created = null
const wallet = {
  async getPublicKey (args) { calls.push({ call: 'getPublicKey', args }); return await inner.getPublicKey(args) },
  async createSignature (args) {
    calls.push({ call: 'createSignature', args: { ...args, data: hex(args.data) } })
    return await inner.createSignature(args)
  },
  async createAction (args) { created = args; throw new Error('stop') }
}

const words = async (run) => {
  try { await run(); return null } catch (error) { return error.message }
}
const sourceOf = (script) => {
  const source = new Transaction()
  source.addInput({
    sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  source.addOutput({ satoshis: 1, lockingScript: script })
  return source
}
const resolved = async (type, script) => {
  const source = sourceOf(script)
  LookupResolver.prototype.query = async function () {
    return { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
  }
  return await new RegistryClient(inner, { networkPreset: 'mainnet' }).resolve(type, {})
}
const verdict = async (type, script) => {
  try {
    return { ok: true, fields: await decodeAndVerifyRegistryToken(type, script) }
  } catch (error) {
    return { ok: false, words: error.message }
  }
}
// The canonical lock-before envelope (`PushDropValidation.ts:40-51`) over a key.
const envelope = (key, fields) => {
  const chunks = [{ op: 33, data: key }, { op: OP.OP_CHECKSIG }]
  for (const field of fields) {
    if (field.length === 0 || (field.length === 1 && field[0] === 0)) chunks.push({ op: 0 })
    else if (field.length === 1 && field[0] >= 1 && field[0] <= 16) chunks.push({ op: 0x50 + field[0] })
    else if (field.length <= 75) chunks.push({ op: field.length, data: field })
    else if (field.length <= 0xff) chunks.push({ op: 0x4c, data: field })
    else chunks.push({ op: 0x4d, data: field })
  }
  for (let remaining = fields.length; remaining > 1; remaining -= 2) chunks.push({ op: OP.OP_2DROP })
  if (fields.length % 2 === 1) chunks.push({ op: OP.OP_DROP })
  return new LockingScript(chunks)
}

// The operator's text in the forms `PublicKey.fromString` (`:36`) reads as a
// key and `verifySignature`'s counterparty check (`validationHelpers.ts:185-196`,
// `:522-534`) judges as text: the same point written otherwise, and `02 || (p+1)`,
// which `Point.fromX` reduces to x = 1 (`Point.ts:365-367`).
const point = PublicKey.fromString(operator)
const uncompressed = hex(point.encode(false))
const fieldPrimePlusOne = (2n ** 256n - 2n ** 32n - 977n + 1n).toString(16)
const operatorForms = {
  operator_uncompressed: uncompressed,
  operator_odd_length: operator.slice(1),
  operator_hybrid: `${operator.startsWith('02') ? '06' : '07'}${uncompressed.slice(2)}`,
  operator_upper_case: operator.toUpperCase(),
  operator_reduced_x: `02${fieldPrimePlusOne}`
}

const tokens = []
const baseTokens = []
const refusals = []
const counterparties = []
for (const definition of definitions) {
  const type = definition.definitionType
  calls.length = 0
  created = null
  const stopped = await words(() =>
    new RegistryClient(wallet, { networkPreset: 'mainnet' }).registerDefinition(structuredClone(definition)))
  if (stopped !== 'stop' || created == null) throw new Error(`${type}: no createAction (${stopped})`)
  const output = created.outputs[0]
  const script = LockingScript.fromHex(output.lockingScript)
  const token = PushDrop.decode(script)
  const records = await resolved(type, script)
  tokens.push({
    definition_type: type,
    definition,
    wallet_calls: calls.map(c => c.call),
    public_key_args: calls.filter(c => c.call === 'getPublicKey').map(c => c.args),
    signature_args: calls.filter(c => c.call === 'createSignature').map(c => c.args),
    locking_point: token.lockingPublicKey.toString(),
    fields: token.fields.slice(0, -1).map(hex),
    signature: hex(token.fields.at(-1)),
    script: output.lockingScript,
    satoshis: output.satoshis,
    basket: output.basket,
    output_description: output.outputDescription,
    description: created.description,
    verdict: await verdict(type, script),
    resolved: records
  })

  // This crate's token before #543: the data fields alone, the identity key.
  const fields = token.fields.slice(0, -1)
  const baseFields = type === 'protocol'
    ? [utf8(`[${definition.protocolID[0]}, "${definition.protocolID[1]}"]`), ...fields.slice(1)]
    : fields
  const base = envelope(Utils.toArray(operator, 'hex'), baseFields)
  baseTokens.push({
    definition_type: type,
    field_count: baseFields.length,
    script: base.toHex(),
    verdict: await verdict(type, base),
    resolved: (await resolved(type, base)).length
  })

  // One change each to the reference's token.
  const signature = token.fields.at(-1)
  const key = token.lockingPublicKey.encode(true)
  const changed = {
    identity_key: envelope(Utils.toArray(operator, 'hex'), [...fields, signature]),
    signature_over_other_data: envelope(key, [...fields.slice(0, -1).map((f, i) => i === 1 ? utf8('Other') : f), fields.at(-1), signature]),
    signature_absent: envelope(key, fields),
    signature_doubled: envelope(key, [...fields, signature, signature]),
    field_not_utf8: envelope(key, [[0xff], ...fields.slice(1), signature]),
    // The operator's key text (`PublicKey.fromString`, `:36`) and the
    // signature's DER (`validateVerifySignatureArgs`, `:45`), each read
    // before the linkage or the verdict it would reach.
    operator_not_hex: envelope(key, [...fields.slice(0, -1), utf8('zz'.repeat(33)), signature]),
    operator_unknown_format: envelope(key, [...fields.slice(0, -1), utf8(`05${operator.slice(2)}`), signature]),
    operator_not_a_point: envelope(key, [...fields.slice(0, -1), utf8(`02${'00'.repeat(31)}05`), signature]),
    signature_not_der: envelope(key, [...fields, [0x30, 0x01]])
  }
  // `05` in place of the locking key's prefix (`decodeCanonicalPushDrop`'s
  // read of the key, `PushDropValidation.ts:40-51`).
  changed.locking_key_05 = envelope([0x05, ...key.slice(1)], [...fields, signature])
  for (const [kind, changedScript] of Object.entries(changed)) {
    refusals.push({
      name: `${type}_${kind}`,
      kind,
      definition_type: type,
      script: changedScript.toHex(),
      verdict: await verdict(type, changedScript),
      resolved: (await resolved(type, changedScript)).length
    })
  }
}

for (const definition of definitions) {
  const type = definition.definitionType
  const token = PushDrop.decode(LockingScript.fromHex(tokens.find(t => t.definition_type === type).script))
  const protocolID = [1, { basket: 'basketmap', protocol: 'protomap', certificate: 'certmap' }[type]]
  const fields = token.fields.slice(0, -1)
  for (const [kind, text] of Object.entries(operatorForms)) {
    // Signed by the operator's wallet over the changed text and locked with
    // the key the reference derives for that text, so the text is the one
    // difference the validator can find.
    const changedFields = [...fields.slice(0, -1), utf8(text)]
    const { signature } = await inner.createSignature({
      data: changedFields.flat(), protocolID, keyID: '1', counterparty: 'anyone'
    })
    const lockingKey = new KeyDeriver('anyone').derivePublicKey(protocolID, '1', text)
    const script = envelope(lockingKey.encode(true), [...changedFields, signature])
    counterparties.push({
      name: `${type}_${kind}`,
      kind,
      definition_type: type,
      operator: text,
      operator_point: PublicKey.fromString(text).toString(),
      script: script.toHex(),
      verdict: await verdict(type, script),
      resolved: (await resolved(type, script)).length
    })
  }
}

// The operator's text read before the counterparty check: a bad operator
// with a non-DER signature (`validateVerifySignatureArgs` judges the
// counterparty, `validationHelpers.ts:1797`, before the signature's DER,
// `:1799-1802`), and whitespace around a key (`validateHexString` trims,
// `:524`, but `PublicKey.fromString`, `registryTokenValidation.ts:36`, reads
// the text first). Locked with the key derived for the operator's point.
const operatorOrders = []
for (const definition of definitions) {
  const type = definition.definitionType
  const token = PushDrop.decode(LockingScript.fromHex(tokens.find(t => t.definition_type === type).script))
  const protocolID = [1, { basket: 'basketmap', protocol: 'protomap', certificate: 'certmap' }[type]]
  const fields = token.fields.slice(0, -1)
  const orders = {
    operator_uncompressed_signature_not_der: [operatorForms.operator_uncompressed, false],
    operator_reduced_x_signature_not_der: [operatorForms.operator_reduced_x, false],
    operator_spaced: [` ${operator} `, true],
    operator_newline: [`${operator}\n`, true]
  }
  for (const [kind, [text, signed]] of Object.entries(orders)) {
    const changedFields = [...fields.slice(0, -1), utf8(text)]
    const signature = signed
      ? (await inner.createSignature({ data: changedFields.flat(), protocolID, keyID: '1', counterparty: 'anyone' })).signature
      : [0x30, 0x01]
    const lockingKey = new KeyDeriver('anyone').derivePublicKey(protocolID, '1', text.trim())
    const script = envelope(lockingKey.encode(true), [...changedFields, signature])
    operatorOrders.push({
      name: `${type}_${kind}`,
      kind,
      definition_type: type,
      operator: text,
      script: script.toHex(),
      verdict: await verdict(type, script),
      resolved: (await resolved(type, script)).length
    })
  }
}

console.log(JSON.stringify({
  description: '#543: the registry definition token as ts-stack@edf6e03 writes and reads it; this crate\'s pre-#543 tokens, ten one-change tokens, five operator key texts and four operator orders under its validator',
  reference: 'ts-stack@edf6e03 packages/sdk/src/registry/RegistryClient.ts:308-342,688-722; registryTokenValidation.ts:13-64; script/templates/PushDrop.ts:146-202',
  node: process.version,
  recorder: 'tests/support/registry_token_fields_543.mjs',
  wallet_key: '09'.padStart(64, '0'),
  operator,
  tokens,
  base_tokens: baseTokens,
  refusals,
  counterparties,
  operator_orders: operatorOrders
}, null, 2))

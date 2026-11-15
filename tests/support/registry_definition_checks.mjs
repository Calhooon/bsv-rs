// The registry client's definition checks as the reference applies them to a
// resolved definition (`ts-stack@edf6e03`, Node 22): each case is a
// definition its operator signed (`PushDrop.lock(fields, protocol, '1',
// 'anyone', true)`, `RegistryClient.ts:320`, with a `ProtoWallet` on the
// scalar 9), answered by `LookupResolver.prototype.query` and read by
// `RegistryClient.resolve` (`:370-397`), which runs `validateDefinitionData`
// (`:153-198`, called at `:737-776`) on it. Each case records whether the
// reference returned it and, if it did, the fields it returned (the reference
// writes a URL back as its parser's `href`; this crate returns the field as
// signed).
//   W=$TMPDIR/ref-checks
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/registry_definition_checks.mjs \
//     "$W/sdk.mjs" > tests/vectors/registry_definition_checks.json
const sdk = await import(process.argv[2])
const { PushDrop, LockingScript, Transaction, PrivateKey, ProtoWallet, LookupResolver, RegistryClient, Utils } = sdk

const utf8 = (text) => Utils.toArray(text, 'utf8')
const operatorKey = PrivateKey.fromHex('09'.padStart(64, '0'))
const inner = new ProtoWallet(operatorKey)
const operator = (await inner.getPublicKey({ identityKey: true })).publicKey

const icon = 'https://icon.example/i.png'
const docs = 'https://docs.example/d'
const descriptor = (over = {}) => ({
  friendlyName: 'Name', description: 'The holder name', type: 'text', fieldIcon: 'https://icon.example/f.png', ...over
})
const fieldsOf = (value) => JSON.stringify(value)
const manyFields = Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`f${i}`, descriptor()]))
const sixtyFour = Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`f${i}`, descriptor()]))

const basket = (over = {}) => {
  const d = { id: 'payments', name: 'Payments', icon, description: 'Payments basket', docs, ...over }
  return [d.id, d.name, d.icon, d.description, d.docs]
}
const protocol = (over = {}) => {
  const d = { id: '[1,"payments"]', name: 'Payments', icon, description: 'Payments protocol', docs, ...over }
  return [d.id, d.name, d.icon, d.description, d.docs]
}
const certificate = (over = {}) => {
  const d = {
    type: 'dHlwZQ==', name: 'Identity', icon, description: 'An identity certificate', docs,
    fields: fieldsOf({ name: descriptor() }), ...over
  }
  return [d.type, d.name, d.icon, d.description, d.docs, d.fields]
}

const cases = [
  ['basket', 'honest', basket()],
  ['basket', 'http icon', basket({ icon: 'http://icon.example/i.png' })],
  ['basket', 'empty urls', basket({ icon: '', docs: '' })],
  ['basket', 'relative icon', basket({ icon: '//icon.example/i.png' })],
  ['basket', 'path icon', basket({ icon: 'icon.png' })],
  ['basket', 'upper-case scheme', basket({ icon: 'HTTPS://Icon.Example/i.png' })],
  ['basket', 'query in url', basket({ docs: 'https://docs.example/d?x=1&y=2' })],
  ['basket', 'empty userinfo', basket({ icon: 'https://@icon.example/i.png' })],
  ['basket', 'empty fragment', basket({ icon: 'https://icon.example/i.png#' })],
  ['basket', 'unicode name', basket({ name: 'Paiements été €' })],
  ['basket', 'tab and newline in description', basket({ description: 'line one\n\tline two\r\n' })],
  ['basket', 'name of 300 bytes', basket({ name: 'n'.repeat(300) })],
  ['basket', 'description of 4096 bytes', basket({ description: 'd'.repeat(4096) })],
  ['basket', 'empty description', basket({ description: '' })],
  ['basket', 'icon of another scheme', basket({ icon: 'ftp://icon.example/i.png' })],
  ['basket', 'uhrp icon', basket({ icon: 'uhrp://abcdef' })],
  ['basket', 'data icon', basket({ icon: 'data:,x' })],
  ['basket', 'documentation with a user', basket({ docs: 'https://user@docs.example/d' })],
  ['basket', 'documentation with a password', basket({ docs: 'https://u:p@docs.example/d' })],
  ['basket', 'icon with a fragment', basket({ icon: 'https://icon.example/i.png#top' })],
  ['basket', 'url of 2049 bytes', basket({ docs: 'https://docs.example/' + 'a'.repeat(2028) })],
  ['basket', 'empty name', basket({ name: '' })],
  ['basket', 'name of 301 bytes', basket({ name: 'n'.repeat(301) })],
  ['basket', 'empty basket id', basket({ id: '' })],
  ['basket', 'basket id of 301 bytes', basket({ id: 'b'.repeat(301) })],
  ['basket', 'description of 4097 bytes', basket({ description: 'd'.repeat(4097) })],
  ['basket', 'control byte in name', basket({ name: 'Pay\u0001ments' })],
  ['basket', 'delete byte in description', basket({ description: 'Payments\u007f' })],
  ['protocol', 'honest', protocol()],
  ['protocol', 'silent level', protocol({ id: '[0,"payments"]' })],
  ['protocol', 'counterparty level', protocol({ id: '[2,"payments protocol"]' })],
  ['protocol', 'protocol name of 4 bytes', protocol({ id: '[1,"paym"]' })],
  ['protocol', 'protocol name of 401 bytes', protocol({ id: `[1,"${'p'.repeat(401)}"]` })],
  ['protocol', 'control byte in protocol name', protocol({ id: '[1,"pay\\u0001ments"]' })],
  ['protocol', 'icon of another scheme', protocol({ icon: 'ftp://icon.example/i.png' })],
  ['protocol', 'empty name', protocol({ name: '' })],
  ['certificate', 'honest', certificate()],
  ['certificate', 'no fields', certificate({ fields: '{}' })],
  ['certificate', 'sixty-four fields', certificate({ fields: fieldsOf(sixtyFour) })],
  ['certificate', 'empty field icon and description', certificate({ fields: fieldsOf({ name: descriptor({ fieldIcon: '', description: '' }) }) })],
  ['certificate', 'image field', certificate({ fields: fieldsOf({ photo: descriptor({ type: 'imageURL' }) }) })],
  ['certificate', 'fields not json', certificate({ fields: '{"name":' })],
  ['certificate', 'fields an array', certificate({ fields: '[]' })],
  ['certificate', 'fields a string', certificate({ fields: '"name"' })],
  ['certificate', 'sixty-five fields', certificate({ fields: fieldsOf(manyFields) })],
  ['certificate', 'descriptor not an object', certificate({ fields: '{"name":"text"}' })],
  ['certificate', 'descriptor without its icon', certificate({ fields: '{"name":{"friendlyName":"Name","description":"d","type":"text"}}' })],
  ['certificate', 'descriptor with another key', certificate({ fields: fieldsOf({ name: descriptor({ extra: 'x' }) }) })],
  ['certificate', 'descriptor of another type', certificate({ fields: fieldsOf({ name: descriptor({ type: 'number' }) }) })],
  ['certificate', 'empty friendly name', certificate({ fields: fieldsOf({ name: descriptor({ friendlyName: '' }) }) })],
  ['certificate', 'field name of 51 bytes', certificate({ fields: fieldsOf({ ['f'.repeat(51)]: descriptor() }) })],
  ['certificate', 'empty field name', certificate({ fields: fieldsOf({ '': descriptor() }) })],
  ['certificate', 'unsafe field name', certificate({ fields: '{"__proto__":{"friendlyName":"Name","description":"d","type":"text","fieldIcon":""}}' })],
  ['certificate', 'constructor field name', certificate({ fields: fieldsOf({ constructor: descriptor() }) })],
  ['certificate', 'field icon of another scheme', certificate({ fields: fieldsOf({ name: descriptor({ fieldIcon: 'ftp://icon.example/f.png' }) }) })],
  ['certificate', 'empty certificate type', certificate({ type: '' })],
  ['certificate', 'documentation with a fragment', certificate({ docs: 'https://docs.example/d#x' })]
]

const sourceOf = (script) => {
  const source = new Transaction()
  source.addInput({
    sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  source.addOutput({ satoshis: 1, lockingScript: script })
  return source
}
const protocolOf = { basket: [1, 'basketmap'], protocol: [1, 'protomap'], certificate: [1, 'certmap'] }

const out = []
for (const [type, label, fields] of cases) {
  const data = [...fields, operator].map(utf8)
  const script = await new PushDrop(inner).lock(data, protocolOf[type], '1', 'anyone', true)
  const source = sourceOf(script)
  LookupResolver.prototype.query = async function () {
    return { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
  }
  let records
  try {
    records = await new RegistryClient(inner, { networkPreset: 'mainnet' }).resolve(type, {})
  } catch (error) {
    records = { error: error.message }
  }
  out.push({
    type,
    label,
    fields,
    returned: Array.isArray(records) && records.length === 1,
    returned_urls: Array.isArray(records) && records.length === 1
      ? [records[0].iconURL, records[0].documentationURL]
      : null
  })
}

console.log(JSON.stringify({
  description: 'The registry client definition checks on a resolved definition its operator signed: whether RegistryClient.resolve returned it.',
  reference: 'ts-stack@edf6e03 packages/sdk/src/registry/RegistryClient.ts:36-198,370-397,729-783',
  node: process.version,
  recorder: 'tests/support/registry_definition_checks.mjs',
  operator,
  cases: out
}, null, 2))

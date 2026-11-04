// #737: the reference's wallet discovery walks every output of an
// `ls_identity` lookup answer (`ts-stack@edf6e03`
// `packages/wallet/wallet-toolbox/src/Wallet.ts:950-1016`,
// `discoverOverlayCertificates` and `discoverByIdentityKey`, through
// `parseResults`, `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:671-707`):
// each output parsed in order by `IdentityEvidenceVerifier.parse`
// (`:596-634`), a skipped one dropped, a repeated outpoint read once
// (`:699-702`), a `limit` rethrown (`:630-634`); the certificates bound to
// the identity key asked (`filterCertificatesByIdentityKey`, `:247-255`) and
// returned as a list of every identity by `IdentityClient.resolveByIdentityKey`
// (`packages/sdk/src/identity/IdentityClient.ts:559-591`, `parseIdentities`,
// `:994-1011`). Each shape is an answer of one to three outputs, every BEEF
// built by the reference's writer as `tests/support/identity_evidence_730.mjs`
// builds them (its helpers copied; its vector untouched), the tokens the
// reference's own revelation tokens (#553's vector: `reference`, and
// `fields_at_bound`, a second certificate of the same subject and certifier
// under another serial number; and two issued here by #553's recipe and
// recorded under `tokens`: another subject's, the scalar 10, and a second of
// the asked subject named carol), judged under a chain tracker admitting
// every root. The trust step
// runs as the wallet runs it (`transformVerifiableCertificatesWithTrust`,
// `identityUtils.ts:313-382`, `Wallet.ts:1010-1013`) under settings trusting
// the tokens' certifier at the threshold (trust 1 of 1): it keeps one
// certificate per type, serial number and certifier (`:360-361`), so one
// certificate at two outpoints is one identity. The page (`discoveryPage`,
// `Wallet.ts:228-233`) is the caller's limit, 10 by default, and is not run.
//
// Recorded per shape: each output's builder, bytes' SHA-256 (the hex to 4096
// bytes) and the builder's size; `parseResults`' certificate count and the
// subjects and serial numbers in order; the identities `parseIdentities`
// returns over the subject-bound, trusted certificates (their count, keys and
// names, the first one's key and name), or `refused: <words>` when
// `parseResults` throws.
//
// The bundle (the recipe of tests/support/identity_certificate_record_553.mjs):
//   W=<lane folder>/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry737.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseResults, filterCertificatesByIdentityKey, transformVerifiableCertificatesWithTrust } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry737.ts --target node --format esm --outfile "$W/ref737.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_resolve_737.mjs \
//     "$W/ref737.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_resolve_737.json
import { readFileSync } from 'fs'
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

// The randomness of the two tokens issued here (the keyrings' symmetric
// keys) is a SHA-256 counter stream installed before the SDK loads, as
// #553's recorder installs it, so two runs print the same file.
let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#737 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, filterCertificatesByIdentityKey, transformVerifiableCertificatesWithTrust, IdentityClient, Beef, LockingScript,
  UnlockingScript, Transaction, MerklePath, Utils, ProtoWallet, PrivateKey, MasterCertificate
} = sdk
const record553 = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const token = record553.cases[0].locking_script
const caseScript = (name) => record553.cases.find(c => c.name === name).locking_script
const secondToken = caseScript('fields_at_bound')
const subjectHex = record553.subject
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }

// A revelation token the reference's own `publiclyRevealAttributes` writes
// (#553's `published`, its subject a parameter): a certificate of `fields`
// issued by the scalar `certifier` (7 unless named) to the scalar `scalar`
// under the serial number of 32 bytes of `serial`, revealing `email`, locked
// and signed by the subject.
const ANYONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const published = async (scalar, fields, serial, certifier = 7) => {
  const wallet = new ProtoWallet(new PrivateKey(scalar))
  const subject = new PrivateKey(scalar).toPublicKey().toString()
  const issued = await MasterCertificate.issueCertificateForSubject(
    new ProtoWallet(new PrivateKey(certifier)), subject, fields,
    Utils.toBase64(new Array(32).fill(1)), async () => '00'.repeat(32) + '.0',
    Utils.toBase64(new Array(32).fill(serial))
  )
  const certificate = {
    type: issued.type, subject: issued.subject, serialNumber: issued.serialNumber,
    certifier: issued.certifier, revocationOutpoint: issued.revocationOutpoint,
    signature: issued.signature, fields: { ...issued.fields }
  }
  const keyring = await MasterCertificate.createKeyringForVerifier(
    wallet, issued.certifier, ANYONE, certificate.fields, ['email'], issued.masterKeyring, issued.serialNumber
  )
  let lock
  await new IdentityClient({
    async proveCertificate () { return { keyringForVerifier: { ...keyring } } },
    async getPublicKey (args) { return wallet.getPublicKey(args) },
    async createSignature (args) { return wallet.createSignature(args) },
    async createAction (args) { lock = args.outputs[0].lockingScript; return {} }
  }, { networkPreset: 'mainnet' }).publiclyRevealAttributes(certificate, ['email']).catch(() => {})
  return lock
}
// Another subject's token (the scalar 10), and a second token of the
// asked subject under another serial number and name.
const tokens = {
  other_subject: await published(10, { email: 'bob@example.com', name: 'Bob' }, 4),
  second_name: await published(9, { email: 'carol@example.com', name: 'Carol' }, 5),
  // The list's fold (#737): the asked subject's certificate by another
  // certifier, the scalar 8, issued after the two above so their bytes stay.
  other_certifier: await published(9, { email: 'dave@example.com', name: 'Dave' }, 6, 8)
}

// One input spending `source` at 0 with `unlocking`, one 1-satoshi output
// locked by `lock` (#730's helper).
const spending = (source, unlocking, lock) => {
  const tx = new Transaction()
  tx.addInput({
    sourceTXID: source, sourceOutputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(unlocking), sequence: 0xffffffff
  })
  tx.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(lock) })
  return tx
}
const loneLeaf = (txid, height) => new MerklePath(height, [[{ offset: 0, hash: txid, txid: true }]])
const proven = (beef, tx, height) => beef.mergeRawTx(tx.toBinary(), beef.mergeBump(loneLeaf(tx.id('hex'), height)))
const atomic = (txid, beef) => {
  const w = new Utils.Writer()
  w.writeUInt32LE(0x01010101)
  w.write(Utils.toArray(txid, 'hex').reverse())
  w.write(beef.toBinary())
  return w.toArray()
}

// The builders, each one output's BEEF.
const builders = {
  // A proven transaction spending `<byte>`x32:0, its output 0 the token.
  reference_11: () => { const b = new Beef(); proven(b, spending('11'.repeat(32), '', token), 900); return b.toBinary() },
  reference_55: () => { const b = new Beef(); proven(b, spending('55'.repeat(32), '', token), 900); return b.toBinary() },
  // The same at `55`x32:0, its output 0 #553's `fields_at_bound` token: a second certificate.
  second_certificate_55: () => { const b = new Beef(); proven(b, spending('55'.repeat(32), '', secondToken), 900); return b.toBinary() },
  // A proven transaction spending `77`x32:0, its output 0 another subject's token.
  other_subject_77: () => { const b = new Beef(); proven(b, spending('77'.repeat(32), '', tokens.other_subject), 900); return b.toBinary() },
  // A proven transaction spending `11`x32:0, its output 0 the asked subject's second token.
  second_name_11: () => { const b = new Beef(); proven(b, spending('11'.repeat(32), '', tokens.second_name), 900); return b.toBinary() },
  // A proven transaction spending `33`x32:0, its output 0 the asked subject's
  // certificate by the second certifier.
  other_certifier_33: () => { const b = new Beef(); proven(b, spending('33'.repeat(32), '', tokens.other_certifier), 900); return b.toBinary() },
  // A proven transaction spending `66`x32:0 locked by OP_TRUE: no identity token.
  op_true_66: () => { const b = new Beef(); proven(b, spending('66'.repeat(32), '', '51'), 900); return b.toBinary() },
  // #730's `unproven_no_inputs`: invalid evidence (`TransactionEvidence.ts:174`).
  unproven_no_inputs: () => {
    const subject = new Transaction()
    subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
    const b = new Beef()
    b.mergeRawTx(subject.toBinary())
    return b.toBinary()
  },
  // #730's `transactions_over_bound` at 256: 257 transactions, a limit (`:117`).
  transactions_over_bound: (n) => overBound('11', n),
  // The same, its subject spending `88`x32:0: another txid than
  // `reference_11`'s, so no resolver drops it as a repeat of the token.
  transactions_over_bound_88: (n) => overBound('88', n)
}
const overBound = (byte, n) => {
  const subject = spending(byte.repeat(32), '', token)
  const b = new Beef()
  for (let i = 1; i <= n; i++) b.mergeTxidOnly(i.toString(16).padStart(64, '0'))
  proven(b, subject, 900)
  return atomic(subject.id('hex'), b)
}
const sizes = { transactions_over_bound: 256, transactions_over_bound_88: 256 }

// The wallet's trust settings: every certifier found trusted at the
// threshold, at 1, or at the level `levels` names for its key.
const trust = (certificates, levels = {}) => ({
  trustLevel: 1,
  trustedCertifiers: [...new Set(certificates.map(c => c.certifier))].map(identityKey => ({
    name: 'Certifier', description: 'The certifier of #553\'s tokens', identityKey, trust: levels[identityKey] ?? 1
  }))
})
const judged = async (outputs, levels) => {
  const lookup = { type: 'output-list', outputs: outputs.map(beef => ({ beef, outputIndex: 0 })) }
  let certificates
  try {
    certificates = await parseResults(lookup, tracker)
  } catch (e) {
    return { certificates: null, subjects: null, outcome: `refused: ${e.message}`, identities: null }
  }
  const bound = filterCertificatesByIdentityKey(certificates, subjectHex)
  const trusted = transformVerifiableCertificatesWithTrust(trust(certificates, levels), bound).certificates
  const identities = await IdentityClient.parseIdentities(trusted)
  return {
    certificates: certificates.length,
    subjects: certificates.map(c => c.subject),
    serial_numbers: certificates.map(c => c.serialNumber),
    outcome: `identities: ${identities.length}`,
    identities: identities.length,
    identity_subjects: identities.map(i => i.identityKey),
    identity_names: identities.map(i => i.name),
    first_subject: identities[0]?.identityKey ?? null,
    first_identity_name: identities[0]?.name ?? null
  }
}

const shapes = []
const add = async (name, shape, check, names, levels) => {
  const outputs = names.map(n => builders[n](sizes[n]))
  shapes.push({
    name, shape, check,
    outputs: names.map((n, i) => {
      const o = {
        builder: n, size: sizes[n] ?? null, output_index: 0, beef_bytes: outputs[i].length,
        beef_sha256: createHash('sha256').update(Buffer.from(outputs[i])).digest('hex')
      }
      if (outputs[i].length <= 4096) o.beef = Utils.toHex(outputs[i])
      return o
    }),
    ...(levels ? { trust_levels: levels } : {}),
    ...(await judged(outputs, levels))
  })
}

await add('refused_first_then_token', 'i',
  'the first output invalid evidence (TransactionEvidence.ts:174), skipped (identityUtils.ts:630-634); the second, ' +
  'another token of the subject (carol, another serial number), read',
  ['unproven_no_inputs', 'second_name_11'])
await add('non_identity_first_then_token', 'i',
  'the first output no identity token (decodeIdentityOutput null, identityUtils.ts:609-610), skipped; the second read',
  ['op_true_66', 'reference_11'])
await add('token_then_refused', 'control',
  'the token first, the invalid evidence second: read, skipped',
  ['reference_11', 'unproven_no_inputs'])
await add('two_certificates', 'ii',
  'two admitted outputs of one subject, two certificates: both read, both identities returned (IdentityClient.ts:568-571)',
  ['reference_11', 'second_certificate_55'])
await add('one_certificate_two_outpoints', 'ii',
  'one certificate at two outpoints: both read, one identity (identityUtils.ts:360-361)',
  ['reference_11', 'reference_55'])
await add('same_output_twice', 'ii',
  'one outpoint twice: read once (identityUtils.ts:699-702)',
  ['reference_11', 'reference_11'])
await add('other_subject_alone', 'iv',
  'another subject\'s certificate alone: read, then dropped by the subject filter (identityUtils.ts:247-255, ' +
  'Wallet.ts:1012): no identity',
  ['other_subject_77'])
await add('other_subject_then_asked', 'iv',
  'another subject\'s certificate, then the asked one\'s: both read, the other dropped by the subject filter ' +
  '(identityUtils.ts:247-255): the asked identity',
  ['other_subject_77', 'reference_11'])
await add('skipped_then_other_subject_then_asked', 'iv',
  'invalid evidence (skipped), another subject\'s certificate (filtered), the asked one\'s: the asked identity',
  ['unproven_no_inputs', 'other_subject_77', 'reference_11'])
await add('token_then_limit', 'iii',
  'the token, then an output over limits.transactions (TransactionEvidence.ts:117): every output parsed before ' +
  'the answer (identityUtils.ts:671-707), the limit rethrown (:630-634), the discovery refused (Wallet.ts:950-955)',
  ['reference_11', 'transactions_over_bound_88'])
await add('limit_first_then_token', 'iii',
  'the first output over limits.transactions (TransactionEvidence.ts:117): rethrown (identityUtils.ts:630-634), the discovery refused',
  ['transactions_over_bound', 'reference_11'])

// The list's fold (#737): the asked subject's certificates by two
// certifiers around a skipped output, both returned in the answer's order
// at equal trust; the same answer with the second certifier trusted at 2,
// the reference's trust sort putting its certificate ahead (the stated
// difference: this crate holds no trust settings); one output, one identity;
// no output, none.
const certifierOf = (lock) => {
  const field = LockingScript.fromHex(lock).chunks[2].data
  return JSON.parse(Utils.toUTF8(field)).certifier
}
await add('two_certifiers_around_a_skipped_output', 'v',
  'the asked subject\'s certificate by the certifier 7, invalid evidence (skipped), its certificate by the certifier 8: ' +
  'both identities at equal trust, in the answer\'s order (the stable sort, identityUtils.ts:378)',
  ['reference_11', 'unproven_no_inputs', 'other_certifier_33'])
await add('two_certifiers_trust_ordered', 'v',
  'the same answer with the certifier 8 trusted at 2: the reference returns its identity ahead (identityUtils.ts:378)',
  ['reference_11', 'unproven_no_inputs', 'other_certifier_33'],
  { [certifierOf(tokens.other_certifier)]: 2 })
await add('token_alone', 'v', 'one output, the token: one identity', ['reference_11'])
await add('no_outputs', 'v', 'an answer of no outputs: no identity, an empty list', [])

process.stdout.write(JSON.stringify({
  description: '#737: the reference wallet\'s discovery over an ls_identity answer (a refused or ' +
    'non-identity output before the token, the token before a refused one, two certificates, one certificate at two ' +
    'outpoints, one outpoint twice, another subject\'s certificate before the asked one\'s, a limit ' +
    'before and after the token; since the list\'s fold, two certifiers around a skipped output at equal and unequal ' +
    'trust, one output, none): parseResults\' certificates and the identities resolveByIdentityKey returns, in its order',
  reference: 'ts-stack@edf6e03 packages/wallet/wallet-toolbox/src/Wallet.ts:950-1016; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:247-255,313-382,596-634,671-707; ' +
    'packages/sdk/src/identity/IdentityClient.ts:559-591,994-1011',
  node: process.version,
  recorder: 'tests/support/identity_resolve_737.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  subject: subjectHex,
  tokens,
  shapes
}, null, 2) + '\n')

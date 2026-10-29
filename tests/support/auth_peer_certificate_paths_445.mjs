// #445: record the unmodified ts-stack@edf6e03 Peer's two certificate paths under Node 22.
// Build the clone's pinned source outside the checkout:
//   git archive edf6e03 packages/sdk | tar -x -C "$REFERENCE"
//   (cd "$REFERENCE/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$REFERENCE/sdk.mjs")
//   node tests/support/auth_peer_certificate_paths_445.mjs "$REFERENCE/sdk.mjs"
// "intake" rows enter through the transport callback (`snapshotAuthMessage`, Peer.ts:767);
// "handler" rows call processCertificateResponse, as the #362-364 recorder does, since the
// earlier handler rows are retained byte for byte. The fold adds intake rows for all
// nonce fields, certificate rejection order, policy matching and the sending bound.
// Two real Peers; no network or listening socket.
import { pathToFileURL } from 'node:url'
const sdk = await import(pathToFileURL(process.argv[2]).href)
const { Peer, ProtoWallet, PrivateKey, Certificate, MasterCertificate, VerifiableCertificate, Utils } = sdk
const key = n => new PrivateKey(n)
const hex = n => key(n).toPublicKey().toString()
const policy = { certifiers: [hex(42)], types: { [Utils.toBase64(Array(32).fill(1))]: ['name'] } }
class Wallet extends ProtoWallet {
  certificates = []
  async verifyHmac (args, o) { try { return await super.verifyHmac(args, o) } catch { return { valid: false } } }
  async verifySignature (args, o) { try { return await super.verifySignature(args, o) } catch { return { valid: false } } }
  async listCertificates (args) {
    const certificates = this.certificates.filter(({ certificate: c }) => args.certifiers.includes(c.certifier) && args.types.includes(c.type)).map(({ certificate }) => certificate)
    return { totalCertificates: certificates.length, certificates }
  }
  async proveCertificate (args) {
    const { certificate: c, masterKeyring } = this.certificates.find(({ certificate }) => certificate.serialNumber === args.certificate.serialNumber)
    return { keyringForVerifier: await MasterCertificate.createKeyringForVerifier(this, c.certifier, args.verifier, c.fields, args.fieldsToReveal, masterKeyring, c.serialNumber) }
  }
}
class Wire {
  sent = []
  waiters = []
  async send (m) { this.sent.push(m); this.waiters.shift()?.() }
  async onData (f) { this.callback = f }
  async next () { if (this.sent.length === 0) await new Promise(r => this.waiters.push(r)); return this.sent.shift() }
}
async function verdict (f) { try { await f(); return null } catch (e) { return e.message } }
async function held (subject, certifier = 42, type = 1, field = 'name', serial = 2) {
  const w = new Wallet(key(certifier))
  const { certificateFields, masterKeyring } = await MasterCertificate.createCertificateFields(w, hex(subject), { [field]: 'Alice' })
  const certificate = new Certificate(Utils.toBase64(Array(32).fill(type)), Utils.toBase64(Array(32).fill(serial)), hex(subject), hex(certifier), '0'.repeat(64) + '.0', certificateFields)
  await certificate.sign(w)
  return { certificate, masterKeyring }
}
// A certificate of `subject` shown to verifier 41, revealing its one field.
async function shown (subject = 42, certifier = 42, type = 1, field = 'name', serial = 2) {
  const { certificate: c, masterKeyring } = await held(subject, certifier, type, field, serial)
  const keyring = await MasterCertificate.createKeyringForVerifier(new Wallet(key(subject)), c.certifier, hex(41), c.fields, [field], masterKeyring, c.serialNumber)
  return new VerifiableCertificate(c.type, c.serialNumber, c.subject, c.certifier, c.revocationOutpoint, c.fields, keyring, c.signature)
}
async function pair ({ aPolicy = false, bHolds = false, listeners } = {}) {
  const a = new Wire(); const b = new Wire()
  const aw = new Wallet(key(41)); const bw = new Wallet(key(42))
  if (bHolds) bw.certificates.push(await held(42))
  a.peer = new Peer(aw, a, aPolicy ? policy : undefined, undefined, false)
  b.peer = new Peer(bw, b, undefined, undefined, false)
  await Promise.all([a.peer.ready, b.peer.ready])
  listeners?.(a.peer)
  const pending = a.peer.getAuthenticatedSession(hex(42)); pending.catch(() => {})
  const request = await a.next(); await b.callback(request)
  const response = await b.next()
  const error = await verdict(() => a.callback(response))
  if (error == null) await pending
  // A signed follow-up authenticates a's session on b (Peer.ts:818-820).
  if (error == null && !aPolicy) { await a.peer.toPeer([0], hex(42)); await b.callback(await a.next()) }
  return { a, b, aw, bw, request, response, error }
}
// a requires the handshake policy after the handshake, as the #362-364 recorder's requireCertificates.
function requireCertificates (p) {
  p.a.peer.certificatesToRequest = policy
  const session = p.a.peer.sessionManager.getSession(hex(42))
  session.certificatePolicy = policy; session.certificatesRequired = true; session.certificatesValidated = false
}
// b's certificateResponse to a, carrying `certificates`, signed as sendCertificateResponse signs.
async function certificateResponse (p, certificates) {
  requireCertificates(p)
  await p.b.peer.sendCertificateResponse(hex(41), [await shown()])
  const m = await p.b.next()
  m.certificates = certificates
  const { signature } = await p.bw.createSignature({
    data: Array.from(Buffer.from(JSON.stringify(certificates), 'utf8')),
    protocolID: [2, 'auth message signature'],
    keyID: `${m.nonce} ${m.yourNonce}`,
    counterparty: hex(41)
  })
  m.signature = signature
  return m
}
// Distinct objects: one object repeated is a cycle to the reference's snapshot.
const copies = (certificate, count) => Array.from({ length: count }, () => JSON.parse(JSON.stringify(certificate)))
const rows = []
// 1. The certificate-response path's words, one fault at a time, a's policy the handshake's.
{
  const other = await shown(42, 42, 1, 'name', 3)
  const faults = {
    subject: async () => await shown(43),
    signature: async () => { const c = await shown(); c.signature = other.signature; return c },
    certifier: async () => await shown(42, 43),
    type: async () => await shown(42, 42, 3),
    field: async () => await shown(42, 42, 1, 'email')
  }
  for (const [fault, make] of Object.entries(faults)) {
    const p = await pair()
    const m = await certificateResponse(p, [await make()])
    rows.push({ id: 'certificate_response_' + fault, path: 'handler', error: await verdict(() => p.a.peer.processCertificateResponse(m)) })
  }
}
// 2. The bound: 100 accepted, 101 refused, on each path and at the intake.
for (const count of [100, 101]) {
  const certificate = await shown()
  const p = await pair()
  const m = await certificateResponse(p, copies(certificate, count))
  rows.push({ id: `certificate_response_${count}_handler`, path: 'handler', error: await verdict(() => p.a.peer.processCertificateResponse(m)) })
  const q = await pair()
  const n = await certificateResponse(q, copies(certificate, count))
  rows.push({ id: `certificate_response_${count}_intake`, path: 'intake', error: await verdict(() => q.a.callback(n)) })
}
{
  const certificate = await shown()
  const a = new Wire(); const b = new Wire()
  a.peer = new Peer(new Wallet(key(41)), a, policy, undefined, false)
  b.peer = new Peer(new Wallet(key(42)), b, undefined, undefined, false)
  const pending = a.peer.getAuthenticatedSession(hex(42)); pending.catch(() => {})
  await b.callback(await a.next())
  const response = await b.next()
  response.certificates = copies(certificate, 101)
  rows.push({ id: 'initial_response_101_intake', path: 'intake', error: await verdict(() => a.callback(response)) })
  const session = { sessionNonce: response.yourNonce, certificatesRequired: true, certificatePolicy: policy }
  rows.push({ id: 'initial_response_101_validator', path: 'validateInitialResponseCertificates', error: await verdict(() => a.peer.validateInitialResponseCertificates(response, session)) })
  a.peer.stopListeningForInitialResponsesByNonce?.(response.yourNonce)
}
// 3. The empty certificates array: automatic selection ran and matched nothing.
{
  let received = 0
  const p = await pair({ aPolicy: true, listeners: a => a.listenForCertificatesReceived(() => { received++ }) })
  rows.push({
    id: 'initial_response_empty_certificates',
    error: p.error,
    response_fields: Object.keys(JSON.parse(JSON.stringify(p.response))),
    certificates: p.response.certificates,
    ready: p.a.peer.sessionManager.getSession(hex(42)).certificatesValidated,
    certificates_received_calls: received,
    automatic_answers: p.a.sent.length
  })
}
// 4. A nonce that is not canonical base64: what the signer's decoder yields, and the intake's verdict.
const decodings = []
for (const text of ['not base64!', 'AB==']) {
  let toArray; try { toArray = Utils.toArray(text, 'base64') } catch (e) { toArray = { threw: e.message } }
  decodings.push({ text, buffer_from: Array.from(Buffer.from(text, 'base64')), to_array: toArray })
}
for (const text of ['not base64!', 'AB==', Utils.toBase64(Array(32).fill(7))]) {
  const a = new Wire(); const b = new Wire()
  a.peer = new Peer(new Wallet(key(41)), a, undefined, undefined, false)
  b.peer = new Peer(new Wallet(key(42)), b, undefined, undefined, false)
  const pending = a.peer.getAuthenticatedSession(hex(42)); pending.catch(() => {})
  const request = await a.next()
  const forged = { ...request, initialNonce: text }
  const error = await verdict(() => b.callback(forged))
  rows.push({ id: 'initial_request_nonce', nonce: text, error, answered: b.sent.length })
  await b.callback(request)
  const response = { ...(await b.next()), initialNonce: text }
  rows.push({ id: 'initial_response_nonce', nonce: text, error: await verdict(() => a.callback(response)) })
  a.peer.stopListeningForInitialResponsesByNonce?.(request.initialNonce)
}

// Re-sign every changed envelope so the intake, not a stale signature, decides.
async function resign (wallet, message) {
  if (message.messageType === 'initialRequest') return
  const initial = message.messageType === 'initialResponse'
  const data = initial
    ? [...Buffer.from(message.yourNonce ?? '', 'base64'), ...Buffer.from(message.initialNonce ?? '', 'base64')]
    : message.messageType === 'general' ? message.payload
      : Array.from(Buffer.from(JSON.stringify(message.messageType === 'certificateRequest' ? message.requestedCertificates : message.certificates), 'utf8'))
  const keyID = initial ? `${message.yourNonce ?? ''} ${message.initialNonce ?? ''}` : `${message.nonce ?? ''} ${message.yourNonce ?? ''}`
  message.signature = (await wallet.createSignature({ data, protocolID: [2, 'auth message signature'], keyID, counterparty: message.identityKey === hex(42) ? hex(41) : hex(42) })).signature
}
// Every required nonce: absence, empty canonical text, malformed text and lengths
// on either side of the required one. Valid sends below exercise the exact lengths.
{
  const p = await pair()
  await p.b.peer.requestCertificates(policy, hex(41))
  const request = await p.b.next()
  await p.b.peer.sendCertificateResponse(hex(41), [await shown()])
  const response = await p.b.next()
  await p.b.peer.toPeer([1], hex(41))
  const general = await p.b.next()
  const messages = [p.request, p.response, request, response, general]
  for (const original of messages) {
    const type = original.messageType
    const fields = type === 'initialRequest' ? { initialNonce: 48 }
      : type === 'initialResponse' ? { initialNonce: 48, yourNonce: 48 }
        : type === 'general' ? { nonce: 32, yourNonce: 48 }
          : { nonce: 32, initialNonce: 48, yourNonce: 48 }
    for (const [field, length] of Object.entries(fields)) {
      const inputs = [['missing', undefined], ['empty', ''], ['noncanonical', 'AB=='],
        ...[31, 32, 33, 47, 48, 49].filter(n => n !== length).map(n => [`bytes_${n}`, Utils.toBase64(Array(n).fill(7))])]
      for (const [input, value] of inputs) {
        const message = { ...original }
        if (value === undefined) delete message[field]
        else message[field] = value
        await resign(type === 'initialRequest' ? p.aw : p.bw, message)
        const destination = type === 'initialRequest' ? p.b : p.a
        rows.push({ id: `nonce_intake_${type}_${field}_${input}`, message_type: type, field, value: value ?? null, error: await verdict(() => destination.callback(message)) })
      }
    }
  }
}
// No configured policy is the reference's empty policy, never permission to
// accept an unsolicited nonempty response. An empty response stays permitted.
for (const count of [0, 1]) {
  let called = 0
  const p = await pair({ listeners: a => a.listenForCertificatesReceived(() => { called++ }) })
  await p.b.peer.sendCertificateResponse(hex(41), count === 0 ? [] : [await shown()])
  rows.push({ id: `no_policy_response_${count}`, error: await verdict(() => p.a.callback(p.b.sent.shift())), certificates_received_calls: called })
}
async function shownFields (reveal) {
  const w = new Wallet(key(42))
  const { certificateFields, masterKeyring } = await MasterCertificate.createCertificateFields(w, hex(42), { name: 'Alice', email: 'alice@example.invalid' })
  const c = new Certificate(Utils.toBase64(Array(32).fill(1)), Utils.toBase64(Array(32).fill(2)), hex(42), hex(42), '0'.repeat(64) + '.0', certificateFields)
  await c.sign(w)
  const ring = reveal.length === 0 ? {} : await MasterCertificate.createKeyringForVerifier(w, c.certifier, hex(41), c.fields, reveal, masterKeyring, c.serialNumber)
  return new VerifiableCertificate(c.type, c.serialNumber, c.subject, c.certifier, c.revocationOutpoint, c.fields, ring, c.signature)
}
for (const [kind, requested, reveal] of [
  ['empty', ['name', 'email'], []],
  ['subset', ['name', 'email'], ['name']],
  ['extra', ['name'], ['name', 'email']]
]) {
  const prior = policy.types[Utils.toBase64(Array(32).fill(1))]
  policy.types[Utils.toBase64(Array(32).fill(1))] = requested
  const p = await pair()
  const message = await certificateResponse(p, [await shownFields(reveal)])
  rows.push({ id: `keyring_${kind}`, error: await verdict(() => p.a.callback(message)) })
  policy.types[Utils.toBase64(Array(32).fill(1))] = prior
}
async function initialCertificates (certificates) {
  const a = new Wire(); const b = new Wire()
  const aw = new Wallet(key(41)); const bw = new Wallet(key(42))
  a.peer = new Peer(aw, a, policy, undefined, false)
  b.peer = new Peer(bw, b, undefined, undefined, false)
  const pending = a.peer.getAuthenticatedSession(hex(42)); pending.catch(() => {})
  const request = await a.next(); await b.callback(request)
  const message = await b.next(); message.certificates = certificates
  await resign(bw, message)
  const error = await verdict(() => a.callback(message))
  a.peer.stopListeningForInitialResponsesByNonce?.(request.initialNonce)
  return error
}
// Repeat each pair in both orders. Subject failures precede the mandatory
// await of verify(); signature and policy failures share the next stage;
// decryption failures follow its await. Record both shared-validator paths.
const invalidSignature = async (serial = 2) => {
  const c = await shown(42, 42, 1, 'name', serial)
  c.signature = (await shown(42, 42, 1, 'name', 9)).signature
  return c
}
const badKeyring = async () => { const c = await shown(); c.keyring.name = 'AB=='; return c }
for (const [label, makeA, makeB, responsePath] of [
  ['signature_subject', () => invalidSignature(), () => shown(43), true],
  ['signature_certifier', () => invalidSignature(), () => shown(42, 43), false],
  ['signature_keyring', () => invalidSignature(), badKeyring, true],
  ['subject_subject', () => shown(43), () => shown(44), true],
  ['signature_signature', () => invalidSignature(2), () => invalidSignature(4), true]
]) {
  for (const reverse of [false, true]) {
    const certificates = [await makeA(), await makeB()]
    if (reverse) certificates.reverse()
    const suffix = reverse ? 'reverse' : 'forward'
    rows.push({ id: `order_initial_${label}_${suffix}`, error: await initialCertificates(certificates) })
    if (responsePath) {
      const p = await pair()
      const message = await certificateResponse(p, certificates)
      rows.push({ id: `order_response_${label}_${suffix}`, error: await verdict(() => p.a.callback(message)) })
    }
  }
}
for (const count of [0, 100, 101]) {
  const p = await pair()
  const certificates = copies(await shown(), count)
  const error = await verdict(() => p.b.peer.sendCertificateResponse(hex(41), certificates))
  rows.push({ id: `sender_bound_${count}`, error, sent: p.b.sent.length })
}
{
  const wire = new Wire()
  wire.peer = new Peer(new Wallet(key(42)), wire, undefined, undefined, false)
  await wire.peer.ready
  const certificates = copies(await shown(), 101)
  rows.push({ id: 'sender_bound_101_without_session', error: await verdict(() => wire.peer.sendCertificateResponse(hex(41), certificates)), sent: wire.sent.length })
}

// The required policy is checked after these nonces; the optional policy's
// contents, when present, remain checked before both bounds and nonces.
{
  const p = await pair()
  await p.b.peer.requestCertificates(policy, hex(41))
  const original = await p.b.next()
  for (const [id, missingNonce, overLimit] of [
    ['certificate_request_missing_nonce_and_policy', true, false],
    ['certificate_request_missing_policy', false, false],
    ['certificate_request_bound_before_missing_policy', true, true]
  ]) {
    const m = { ...original }; delete m.requestedCertificates
    if (missingNonce) delete m.nonce
    if (overLimit) m.certificates = copies(await shown(), 101)
    rows.push({ id, error: await verdict(() => p.a.callback(m)) })
  }
}

// A keyring failure before any wallet await wins over one after a wallet
// answer, even when the latter certificate is earlier in the array.
{
  const prior = policy.types[Utils.toBase64(Array(32).fill(1))]
  policy.types[Utils.toBase64(Array(32).fill(1))] = ['name', 'email']
  for (const reverse of [false, true]) {
    const afterWallet = await shownFields(['name', 'email']); afterWallet.keyring.email = 'AB=='
    const beforeWallet = await shown(); beforeWallet.keyring.name = 'AB=='
    const certificates = reverse ? [beforeWallet, afterWallet] : [afterWallet, beforeWallet]
    const suffix = reverse ? 'reverse' : 'forward'
    rows.push({ id: `order_initial_decryption_await_${suffix}`, error: await initialCertificates(certificates) })
    const p = await pair()
    const message = await certificateResponse(p, certificates)
    rows.push({ id: `order_response_decryption_await_${suffix}`, error: await verdict(() => p.a.callback(message)) })
  }
  policy.types[Utils.toBase64(Array(32).fill(1))] = prior
}

process.stdout.write(JSON.stringify({ reference: 'ts-stack@edf6e03', node: process.version, decodings, cases: rows }, null, 2) + '\n')

// #362-364: record the unmodified ts-stack@edf6e03 Peer under Node 22.
// Build the clone's pinned source outside the checkout:
//   git archive edf6e03 packages/sdk | tar -x -C "$REFERENCE"
//   (cd "$REFERENCE/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$REFERENCE/sdk.mjs")
//   node tests/support/auth_peer_nonces_362_364.mjs "$REFERENCE/sdk.mjs"
// Certificate messages use the reference's certificate handlers: its full
// intake requires initialNonce, which its own certificateRequest omits (#416).
// Two real Peers complete each handshake; no network or listening socket.
import { pathToFileURL } from 'node:url'
const sdk = await import(pathToFileURL(process.argv[2]).href)
const { Peer, ProtoWallet, PrivateKey, Certificate, MasterCertificate, VerifiableCertificate, SessionManager, createNonce, Utils } = sdk
const key = n => new PrivateKey(n)
const hex = n => key(n).toPublicKey().toString()
const policy = { certifiers: [hex(42)], types: { [Utils.toBase64(Array(32).fill(1))]: ['name'] } }
class Wallet extends ProtoWallet {
  async verifyHmac (args, o) { try { return await super.verifyHmac(args, o) } catch { return { valid: false } } }
  async verifySignature (args, o) { try { return await super.verifySignature(args, o) } catch { return { valid: false } } }
  async decrypt (args, o) { if (this.gate != null) { this.entered?.(); await this.gate }; return await super.decrypt(args, o) }
}
class Wire {
  sent = []
  waiters = []
  async send (m) { this.sent.push(m); this.waiters.shift()?.() }
  async onData (f) { this.callback = f }
  async next () { if (this.sent.length === 0) await new Promise(r => this.waiters.push(r)); return this.sent.shift() }
  async deliver (m) {
    if (m.messageType === 'certificateRequest') return await this.peer.processCertificateRequest(m)
    if (m.messageType === 'certificateResponse') return await this.peer.processCertificateResponse(m)
    return await this.callback(m)
  }
}
const tick = () => new Promise(r => setTimeout(r, 10))
async function pair () {
  const a = new Wire(); const b = new Wire()
  const wallet = new Wallet(key(41))
  a.peer = new Peer(wallet, a, undefined, undefined, false)
  b.peer = new Peer(new Wallet(key(42)), b, undefined, undefined, false)
  await Promise.all([a.peer.ready, b.peer.ready])
  const pending = a.peer.getAuthenticatedSession(hex(42)); pending.catch(() => {})
  const request = await a.next(); await b.deliver(request)
  const response = await b.next(); await a.deliver(response); await pending
  await a.peer.toPeer([0], hex(42)); await b.deliver(await a.next())
  return { a, b, wallet, request, response }
}
async function certificate () {
  const w = new Wallet(key(42)); const type = Object.keys(policy.types)[0]
  const serial = Utils.toBase64(Array(32).fill(2))
  const { certificateFields, masterKeyring } = await MasterCertificate.createCertificateFields(w, 'self', { name: 'Alice' })
  const cert = new Certificate(type, serial, hex(42), hex(42), '0'.repeat(64) + '.0', certificateFields)
  await cert.sign(w)
  const keyring = await MasterCertificate.createKeyringForVerifier(w, 'self', hex(41), certificateFields, ['name'], masterKeyring, serial)
  return new VerifiableCertificate(type, serial, hex(42), hex(42), cert.revocationOutpoint, certificateFields, keyring, cert.signature)
}
function requireCertificates (p) {
  p.a.peer.certificatesToRequest = policy
  const session = p.a.peer.sessionManager.getSession(hex(42))
  session.certificatePolicy = policy; session.certificatesRequired = true; session.certificatesValidated = false
  return session
}
async function message (p, kind) {
  if (kind === 'initialRequest') return p.request
  if (kind === 'initialResponse') return p.response
  if (kind === 'certificateRequest') await p.b.peer.requestCertificates(policy, hex(41))
  if (kind === 'certificateResponse') { requireCertificates(p); await p.b.peer.sendCertificateResponse(hex(41), [await certificate()]) }
  if (kind === 'general') await p.b.peer.toPeer([1, 2, 3], hex(41))
  return await p.b.next()
}
async function verdict (f) { try { await f(); return null } catch (e) { return e.message } }
const rows = []
for (const kind of ['initialRequest', 'initialResponse', 'certificateRequest', 'certificateResponse', 'general']) {
  const p = await pair(); const m = await message(p, kind); const target = kind === 'initialRequest' ? p.b : p.a
  if (!kind.startsWith('initial')) {
    if (kind === 'certificateRequest') await p.a.peer.listenForCertificatesRequested(() => {})
    const first = await verdict(() => target.deliver(m)); if (first !== null) throw new Error(first)
  }
  rows.push({ id: 'replay_' + kind, error: await verdict(() => target.deliver(m)) })
}
for (const kind of ['certificateRequest', 'certificateResponse']) {
  for (const fault of ['wrong_your_nonce', 'unknown_session', 'identity_mismatch', 'invalid_signature', 'missing_nonce', 'listener_error']) {
    const p = await pair(); const m = await message(p, kind)
    if (fault === 'wrong_your_nonce') m.yourNonce = Utils.toBase64(Array(48).fill(0))
    if (fault === 'unknown_session') m.yourNonce = await createNonce(p.wallet)
    if (fault === 'identity_mismatch') m.identityKey = hex(43)
    if (fault === 'invalid_signature') m.signature = [48, 6, 2, 1, 1, 2, 1, 1]
    if (fault === 'missing_nonce') { delete m.nonce; p.wallet.verifySignature = async () => ({ valid: true }) }
    if (fault === 'listener_error') {
      const fail = async () => { throw new Error('certificate listener failed') }
      if (kind === 'certificateRequest') await p.a.peer.listenForCertificatesRequested(fail)
      else await p.a.peer.listenForCertificatesReceived(fail)
    }
    const error = await verdict(() => p.a.deliver(m))
    rows.push({ id: kind + '_' + fault, error: error?.replace(m.yourNonce, '<nonce>') ?? null })
  }
}
{
  const p = await pair(); const response = await message(p, 'certificateResponse')
  const session = requireCertificates(p)
  let release; p.wallet.gate = new Promise(r => { release = r })
  let entered; const started = new Promise(r => { entered = r }); p.wallet.entered = entered
  const validation = p.a.deliver(response); await started
  let calls = 0; await p.a.peer.listenForGeneralMessages(() => { calls++ })
  const general = await message(p, 'general'); let settled = false
  const delivery = p.a.deliver(general).finally(() => { settled = true })
  await tick(); const before = { calls, settled }
  release(); await validation; await delivery
  rows.push({ id: 'pending_validation', before, after: { calls, ready: session.certificatesValidated } })
}
{
  const p = await pair(); requireCertificates(p)
  const general = await message(p, 'general')
  // Keep Node alive for the reference's unref'ed, unchanged 30-second timer.
  const keepalive = setInterval(() => {}, 1000)
  rows.push({ id: 'validation_timeout', error: await verdict(() => p.a.deliver(general)) })
  clearInterval(keepalive)
}
const manager = new SessionManager({ now: () => 1000 })
manager.addSession({ sessionNonce: 'session', lastUpdate: 1000, isAuthenticated: true })
for (let i = 0; i < 100000; i++) manager.claimMessageNonce('session', String(i))
const capacity = await verdict(() => manager.claimMessageNonce('session', 'overflow'))
const replayAtCapacity = manager.claimMessageNonce('session', '0')
manager.removeSession({ sessionNonce: 'session' })
manager.addSession({ sessionNonce: 'session', lastUpdate: 1000, isAuthenticated: true })
const afterRemoval = manager.claimMessageNonce('session', '0')
let now = 1000
const initial = new SessionManager({ now: () => now })
initial.claimInitialRequestNonce('alice', 'first')
const duplicate = initial.claimInitialRequestNonce('alice', 'first')
now += 30 * 60 * 1000 - 1
const beforeExpiry = initial.claimInitialRequestNonce('alice', 'first')
now++
const atExpiry = initial.claimInitialRequestNonce('alice', 'first')
for (let i = 0; i < 256; i++) initial.claimInitialRequestNonce('bob', String(i))
initial.claimInitialRequestNonce('bob', 'overflow')
const perIdentityEviction = initial.claimInitialRequestNonce('bob', '0')
const global = new SessionManager({ now: () => now })
for (let i = 0; i < 100000; i++) global.claimInitialRequestNonce('peer' + Math.floor(i / 256), String(i))
global.claimInitialRequestNonce('newPeer', 'newNonce')
const globalEviction = global.claimInitialRequestNonce('peer0', '0')
const store = { capacity, replayAtCapacity, afterRemoval, duplicate, beforeExpiry, atExpiry, perIdentityEviction, globalEviction }
process.stdout.write(JSON.stringify({ reference: 'ts-stack@edf6e03', node: process.version, certificate_entry: 'Peer.processCertificateRequest / processCertificateResponse', cases: rows, store }, null, 2) + '\n')

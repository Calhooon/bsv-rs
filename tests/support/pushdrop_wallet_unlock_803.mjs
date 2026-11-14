// #803: the reference's wallet-aware `PushDrop.unlock`,
// `new PushDrop(wallet, originator).unlock(protocolID, keyID, counterparty,
// signOutputs, anyoneCanPay, sourceSatoshis, lockingScript)` (`ts-stack@edf6e03`
// `packages/sdk/src/script/templates/PushDrop.ts:205-262`): its `sign(tx,
// inputIndex)` asks the wallet's createSignature for SHA-256 of the BIP143
// preimage under the scope `computeSignatureScope` gives
// (`SignatureUtils.ts:44-68`), reads the answer with `Signature.fromDER` and
// pushes it with the scope byte; its `estimateLength` answers 73.
// Recorded with the reference's own template over a ProtoWallet on the
// scalar 9, wrapped to record each call's arguments and originator; RFC 6979
// makes the signature, and so the whole script, deterministic.
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk803.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/pushdrop_wallet_unlock_803.mjs \
//     "$W/sdk803.mjs" > tests/vectors/pushdrop_wallet_unlock_803.json
//
// The spent output: 1000 satoshis under the reference's own wallet lock
// (`lock([[1, 2, 3]], protocolID, keyID, counterparty, true, true)`: `forSelf`
// true, the key the wallet itself signs for under that counterparty), one
// per counterparty, so the unlocking script recorded spends the locking
// script recorded. The spending transaction has three inputs (sequences
// 0xffffffff, 0xfffffffe and 5) and two outputs, so every scope signs other
// bytes and SIGHASH_SINGLE at input 2 names an output the transaction does
// not have. No source transaction is linked: the amount and the script are
// the two arguments, as a caller holding an outpoint alone passes them.
//
// `cases`: the three `signOutputs` with and without `anyoneCanPay` at each
// input (counterparty `self`), then `all` at input 0 for `anyone` and a
// compressed key's hex (the scalar 7's), with an originator, at version 2 and
// at an amount of exactly 21e14. `refusals`: an input index past the inputs,
// an amount past 21e14, a wallet that throws. `answers`: the wallet's
// signature rewritten (not DER, empty, a byte after the sequence, the high-S
// twin): the words thrown, or the script pushed.
// `fold`: both refusals at once, and an answer whose R is past 32 bytes.
// `fold2`: a high-S answer whose DER is as long as its low-S twin's.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const {
  ProtoWallet, PrivateKey, PushDrop, Transaction, UnlockingScript, LockingScript, Signature, Curve, Utils, Hash
} = await import(pathToFileURL(sdkPath).href)

const PROTOCOL = [2, 'pushdrop wallet unlock']
const KEY_ID = '1'
const OTHER = new PrivateKey(7).toPublicKey().toString()
const ORIGINATOR = 'pushdrop.example.com'
const SATOSHIS = 1000

const inner = new ProtoWallet(new PrivateKey(9))

function recording (rewrite) {
  const calls = []
  const wallet = {
    getPublicKey: async (args, originator) => await inner.getPublicKey(args, originator),
    createSignature: async (args, originator) => {
      calls.push({
        method: 'createSignature',
        args: { ...JSON.parse(JSON.stringify({ ...args, data: undefined })), data: Utils.toHex(args.data) },
        originator: originator ?? null
      })
      if (rewrite === 'throws') throw new Error('wallet refused')
      const answer = await inner.createSignature(args, originator)
      return rewrite == null ? answer : { signature: rewrite(answer.signature) }
    }
  }
  return { wallet, calls }
}

const locks = {}
for (const counterparty of ['self', 'anyone', OTHER]) {
  const script = await new PushDrop(inner).lock([[1, 2, 3]], PROTOCOL, KEY_ID, counterparty, true, true)
  locks[counterparty] = script.toHex()
}

const txid = (n) => Utils.toHex(Hash.sha256([n]))

function spending (version) {
  const tx = new Transaction()
  tx.version = version
  const sequences = [0xffffffff, 0xfffffffe, 5]
  for (let i = 0; i < 3; i++) {
    tx.addInput({
      sourceTXID: txid(i + 1),
      sourceOutputIndex: i,
      sequence: sequences[i],
      unlockingScript: new UnlockingScript()
    })
  }
  tx.addOutput({ satoshis: 600, lockingScript: LockingScript.fromHex('76a914' + '11'.repeat(20) + '88ac') })
  tx.addOutput({ satoshis: 300, lockingScript: LockingScript.fromHex('006a0568656c6c6f') })
  tx.lockTime = 7
  return tx
}

async function run (o) {
  const { wallet, calls } = recording(o.rewrite ?? null)
  const tx = spending(o.version ?? 1)
  const lock = locks[o.counterparty ?? 'self']
  const template = new PushDrop(wallet, o.originator ?? undefined).unlock(
    PROTOCOL, KEY_ID, o.counterparty ?? 'self', o.signOutputs ?? 'all', o.anyoneCanPay ?? false,
    o.satoshis ?? SATOSHIS, LockingScript.fromHex(lock)
  )
  const out = {
    name: o.name,
    originator: o.originator ?? null,
    protocol_id: PROTOCOL,
    key_id: KEY_ID,
    counterparty: o.counterparty ?? 'self',
    sign_outputs: o.signOutputs ?? 'all',
    anyone_can_pay: o.anyoneCanPay ?? false,
    transaction: tx.toHex(),
    input_index: o.inputIndex ?? 0,
    source_satoshis: o.satoshis ?? SATOSHIS,
    locking_script: lock,
    estimate_length: await template.estimateLength()
  }
  try {
    const script = await template.sign(tx, o.inputIndex ?? 0)
    out.accepted = true
    out.unlocking_script = script.toHex()
  } catch (e) {
    out.accepted = false
    out.refusal = e.message
    out.class = e.constructor.name
  }
  out.calls = calls
  return out
}

const cases = []
for (const inputIndex of [0, 1, 2]) {
  for (const signOutputs of ['all', 'none', 'single']) {
    for (const anyoneCanPay of [false, true]) {
      cases.push(await run({
        name: `input_${inputIndex}_${signOutputs}${anyoneCanPay ? '_anyone_can_pay' : ''}`,
        inputIndex,
        signOutputs,
        anyoneCanPay
      }))
    }
  }
}
cases.push(await run({ name: 'counterparty_anyone', counterparty: 'anyone' }))
cases.push(await run({ name: 'counterparty_other', counterparty: OTHER }))
cases.push(await run({ name: 'with_an_originator', originator: ORIGINATOR }))
cases.push(await run({ name: 'version_2', version: 2, signOutputs: 'single', anyoneCanPay: true, inputIndex: 1 }))
cases.push(await run({ name: 'amount_at_21e14', satoshis: 21e14 }))

const refusals = [
  await run({ name: 'input_index_past_the_inputs', inputIndex: 3 }),
  await run({ name: 'amount_past_21e14', satoshis: 21e14 + 1 }),
  await run({ name: 'wallet_throws', rewrite: 'throws' })
]

const n = new Curve().n
const answers = [
  await run({ name: 'answer_not_der', rewrite: () => [1, 2, 3] }),
  await run({ name: 'answer_empty', rewrite: () => [] }),
  await run({ name: 'answer_with_a_byte_after', rewrite: (sig) => [...sig, 0] }),
  await run({
    name: 'answer_high_s',
    rewrite: (sig) => {
      const parsed = Signature.fromDER([...sig])
      return new Signature(parsed.r, n.sub(parsed.s)).toDER()
    }
  })
]

// The fold of #803 (the parity read's two rows), a group of its own so the
// three groups above stay byte for byte: both faults at once (an input index
// past the inputs and an amount past 21e14: which refusal comes before the
// other), and a wallet answer whose R is 33 bytes past its sign rule (the
// value 2^256 + r, written by hand: a DER the reference's `fromDER` reads and
// its `toDER` writes back, so the script pushed carries it).
const fold = [
  await run({ name: 'input_index_past_the_inputs_and_amount_past_21e14', inputIndex: 3, satoshis: 21e14 + 1 }),
  await run({
    name: 'answer_r_past_32_bytes',
    rewrite: (sig) => {
      const parsed = Signature.fromDER([...sig])
      const integer = (bytes) => {
        const v = [...bytes]
        while (v.length > 1 && v[0] === 0) v.shift()
        if ((v[0] & 0x80) !== 0) v.unshift(0)
        return [0x02, v.length, ...v]
      }
      const body = [...integer([1, ...parsed.r.toArray('be', 32)]), ...integer(parsed.s.toArray('be', 32))]
      return [0x30, body.length, ...body]
    }
  })
]

// The second fold of #803 (the re-read's plant: a signer that pushes the
// answer as given only when its DER is as long as its low-S form's passed the
// one high-S sample above, whose DER is a byte longer than its twin's), a
// group of its own so the four groups above stay byte for byte: a high-S
// answer whose S is 2^255 - 1, the largest S of 32 DER bytes. It lies between
// n / 2 and 2^255, so it is high and its low-S twin, n - S, is 32 bytes too:
// the two DERs are of one length. No signer reaches that range by chance (it
// is 2^127 wide), so the S is written by hand over the wallet's R; the
// signature verifies under no key, which the template does not ask.
const fold2 = [
  await run({
    name: 'answer_high_s_of_equal_der_length',
    rewrite: (sig) => {
      const parsed = Signature.fromDER([...sig])
      const integer = (bytes) => {
        const v = [...bytes]
        while (v.length > 1 && v[0] === 0) v.shift()
        if ((v[0] & 0x80) !== 0) v.unshift(0)
        return [0x02, v.length, ...v]
      }
      const s = [0x7f, ...new Array(31).fill(0xff)]
      const body = [...integer(parsed.r.toArray('be', 32)), ...integer(s)]
      return [0x30, body.length, ...body]
    }
  })
]

console.log(JSON.stringify({
  issue: 803,
  source: 'ts-stack@edf6e03 packages/sdk/src/script/templates/PushDrop.ts:205-262, SignatureUtils.ts:44-68,74-184',
  recorder: 'tests/support/pushdrop_wallet_unlock_803.mjs',
  node: process.version,
  wallet_scalar: 9,
  other_scalar: 7,
  cases,
  refusals,
  answers,
  fold,
  fold2
}, null, 2))

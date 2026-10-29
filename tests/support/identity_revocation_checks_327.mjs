// The #327 witnesses, run by `identity_wallet_calls_318.mjs` with the mode
// `revocation-checks` (its header has the command): the reference's
// `revokeCertificateRevelation` (`ts-stack@edf6e03`
// `packages/sdk/src/identity/IdentityClient.ts:705-950`) on ten lookups,
// each run's verdict, wallet calls, createAction, signAction and abortAction
// arguments and broadcast txids. Bytes are hex text; the #318 witnesses are
// not repeated.

const ANYONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'

export async function record (ctx) {
  const {
    IdentityClient, LookupResolver, MasterCertificate, ProtoWallet, Script, TopicBroadcaster,
    Transaction, Utils, WERR_REVIEW_ACTIONS, key, pub, certificate, subjectWallet, tokenScript,
    reference
  } = ctx
  const hex = (bytes) => Utils.toHex(bytes)

  // Another certificate of the same subject and certifier (serial number of
  // 32 bytes of 3), revealed by the reference to get its token.
  ctx.resetCounter()
  const other = await MasterCertificate.issueCertificateForSubject(
    new ProtoWallet(key(7)), pub(9), { email: 'bob@example.com' },
    Utils.toBase64(new Array(32).fill(1)), async () => '00'.repeat(32) + '.0',
    Utils.toBase64(new Array(32).fill(3))
  )
  const otherCertificate = {
    type: other.type, subject: other.subject, serialNumber: other.serialNumber,
    certifier: other.certifier, revocationOutpoint: other.revocationOutpoint,
    signature: other.signature, fields: { ...other.fields }
  }
  const otherKeyring = await MasterCertificate.createKeyringForVerifier(
    subjectWallet, other.certifier, ANYONE, otherCertificate.fields, ['email'],
    other.masterKeyring, other.serialNumber
  )
  let otherScript
  await new IdentityClient({
    async proveCertificate () { return { keyringForVerifier: { ...otherKeyring } } },
    async getPublicKey (args) { return subjectWallet.getPublicKey(args) },
    async createSignature (args) { return subjectWallet.createSignature(args) },
    async createAction (args) { otherScript = args.outputs[0].lockingScript; return {} }
  }, { networkPreset: 'mainnet' }).publiclyRevealAttributes(otherCertificate, ['email']).catch(() => {})

  // A source transaction of one made-up input whose outputs are the scripts given.
  const sourceOf = (scripts) => {
    const source = new Transaction()
    source.addInput({
      sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
      unlockingScript: Script.fromHex('51'), sequence: 0xffffffff
    })
    for (const s of scripts) source.addOutput({ satoshis: 1, lockingScript: Script.fromHex(s) })
    return source
  }
  const single = sourceOf([tokenScript])
  const otherOnly = sourceOf([otherScript])
  const both = sourceOf([otherScript, tokenScript])

  // The competing spend of the single source's output 0.
  const competing = new Transaction()
  competing.addInput({
    sourceTransaction: single, sourceOutputIndex: 0,
    unlockingScript: Script.fromHex('51'), sequence: 0xffffffff
  })
  competing.addOutput({ satoshis: 0, lockingScript: Script.fromHex('006a02cccc') })
  const competingTxid = competing.id('hex')
  const competingBeef = competing.toBEEF(true)

  const run = async (name, outputs, signAnswers, serialNumber = certificate.serialNumber) => {
    const state = { calls: [], createAction: [], signAction: [], abortAction: [], broadcasts: [], createSignature: [] }
    const note = (n) => state.calls.push(n)
    let signable
    const wallet = {
      async getPublicKey (args) { note('getPublicKey'); return subjectWallet.getPublicKey(args) },
      async createSignature (args) { note('createSignature'); state.createSignature.push(JSON.stringify(args)); return subjectWallet.createSignature(args) },
      async verifySignature (args) { note('verifySignature'); return subjectWallet.verifySignature(args) },
      async createAction (args) {
        note('createAction')
        state.createAction.push({ ...structuredClone(args), inputBEEF: hex(args.inputBEEF) })
        const [txid, index] = args.inputs[0].outpoint.split('.')
        const partial = new Transaction()
        partial.addInput({
          sourceTransaction: Transaction.fromBEEF(args.inputBEEF, txid),
          sourceOutputIndex: Number(index), unlockingScript: new Script(), sequence: 0xffffffff
        })
        partial.addOutput({ satoshis: 0, lockingScript: Script.fromHex('006a') })
        signable = partial.toAtomicBEEF(true)
        state.signable_tx = hex(signable)
        return { signableTransaction: { tx: signable, reference } }
      },
      async signAction (args) {
        note('signAction')
        state.signAction.push(structuredClone(args))
        const answer = signAnswers.shift() ?? 'none'
        if (answer === 'none') return {}
        if (answer === 'signed') {
          const signed = Transaction.fromAtomicBEEF(signable)
          for (const [i, spend] of Object.entries(args.spends)) {
            signed.inputs[Number(i)].unlockingScript = Script.fromHex(spend.unlockingScript)
          }
          const tx = signed.toAtomicBEEF(true)
          state.signed_tx = hex(tx)
          return { tx }
        }
        throw answer()
      },
      async abortAction (args) {
        note('abortAction')
        state.abortAction.push(structuredClone(args))
        return { aborted: true }
      }
    }
    LookupResolver.prototype.query = async function () { return outputs }
    TopicBroadcaster.prototype.broadcast = async function (tx) {
      state.broadcasts.push(tx.id('hex'))
      return { status: 'success', txid: tx.id('hex'), message: 'sent' }
    }
    let verdict = null
    try {
      await new IdentityClient(wallet, { networkPreset: 'mainnet' })
        .revokeCertificateRevelation(serialNumber)
    } catch (e) {
      verdict = e.message
    }
    return { name, verdict, ...state }
  }

  const lookupOf = (source, indexes) => ({
    type: 'output-list',
    outputs: indexes.map((outputIndex) => ({ beef: source.toBEEF(true), outputIndex }))
  })
  const review = (evidence) => () => new WERR_REVIEW_ACTIONS(
    [{ txid: '22'.repeat(32), status: 'doubleSpend', ...evidence }], [], undefined, undefined, []
  )
  const runs = [
    await run('lookup_empty', { type: 'output-list', outputs: [] }, []),
    await run('lookup_freeform', { type: 'freeform', result: {} }, []),
    await run('too_many_results', {
      type: 'output-list',
      outputs: new Array(10001).fill(0).map(() => ({ beef: single.toBEEF(true), outputIndex: 0 }))
    }, []),
    await run('another_certificate', lookupOf(otherOnly, [0]), []),
    await run('second_output_matches', lookupOf(both, [0, 1]), ['signed']),
    await run('sign_action_fails', lookupOf(single, [0]), [() => new Error('signAction refused')]),
    await run('double_spend_then_accepted', lookupOf(single, [0]), [
      review({ competingTxs: [competingTxid], competingBeef }), 'signed'
    ]),
    await run('review_without_evidence', lookupOf(single, [0]), [review({})]),
    await run('beef_bytes_bound', {
      type: 'output-list',
      outputs: new Array(17).fill(0).map(() => ({ beef: new Array(1 << 20).fill(0), outputIndex: 0 }))
    }, []),
    await run('serial_number_short', lookupOf(single, [0]), [], 'AAAA')
  ]
  for (const r of runs) {
    // the lookup's BEEF for the runs the Rust side answers itself
    if (r.name === 'too_many_results') r.lookup = { outputs: 10001, beef: 'single' }
    if (r.name === 'beef_bytes_bound') r.lookup = { outputs: 17, beef_bytes_each: 1 << 20 }
    if (r.name === 'serial_number_short') r.serial_number = 'AAAA'
  }

  return {
    description: 'revokeCertificateRevelation on lookups the script answers: the verdict, the wallet calls in order with the createAction, signAction and abortAction arguments, and the txids broadcast (the double-spend retry broadcasting the competing transaction first) (#327)',
    reference: '@bsv/sdk at ts-stack@edf6e03 (bundled with bun build), run under Node ' + process.version + ' by tests/support/identity_wallet_calls_318.mjs revocation-checks',
    site: 'ts-stack@edf6e03 packages/sdk/src/identity/IdentityClient.ts:123-200,705-950; packages/sdk/src/overlay-tools/withDoubleSpendRetry.ts:8-165',
    serial_number: certificate.serialNumber,
    other_serial_number: otherCertificate.serialNumber,
    lookups: {
      single: hex(single.toBEEF(true)),
      other_only: hex(otherOnly.toBEEF(true)),
      both: hex(both.toBEEF(true))
    },
    competing: { txid: competingTxid, beef: hex(competingBeef) },
    runs
  }
}

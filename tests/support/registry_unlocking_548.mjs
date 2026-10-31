// #548: the unlocking script the reference's registry client sends for a
// definition token on revoke and update (`ts-stack@edf6e03`, Node 22).
// `RegistryClient.removeDefinition` (`RegistryClient.ts:540-548`) and
// `updateDefinition` (`:630-639`) unlock the token with
// `PushDrop.unlock(protocol, '1', 'anyone', 'all', false, satoshis,
// lockingScript)` (`PushDrop.ts:217-262`: the BIP-143 preimage under
// SIGHASH_ALL | FORKID over the record's satoshis and locking script, its
// SHA-256 signed by the wallet's `createSignature` for counterparty `anyone`,
// one push of the checksig signature) inside `completeBoundAction`.
//
// The wallet is the `ProtoWallet` of the scalar 9 (its RFC 6979 signatures
// are deterministic: the recorded bytes are compared, not only verified).
// Each definition type's token is the reference's own `registerDefinition`
// output (createAction stopped), carried by a made-up source transaction;
// createAction answers a signable transaction whose input 0 is a made-up
// funding input and input 1 the token (so the spend's index is not the
// token's output index), the requested outputs in order; signAction is
// recorded and answers no transaction, so the client aborts and stops before
// any broadcast. Each case also records the reference interpreter's verdict
// (`Spend.validate`) on the token's spend with the recorded script.
//   W=$TMPDIR/ref-548
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/registry_unlocking_548.mjs \
//     "$W/sdk.mjs" > tests/vectors/registry_unlocking_548.json
const sdk = await import(process.argv[2])
const { LockingScript, UnlockingScript, Transaction, PrivateKey, ProtoWallet, RegistryClient, Spend, Utils } = sdk

const hex = (bytes) => Utils.toHex(bytes)
const REFERENCE = Utils.toBase64(new Array(8).fill(0x52))
const inner = new ProtoWallet(PrivateKey.fromHex('09'.padStart(64, '0')))
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
const updated = (definition) => ({ ...definition, name: `${definition.name} v2`, description: `${definition.description}, updated` })

const sourceOf = (txid, outputs) => {
  const tx = new Transaction()
  tx.addInput({
    sourceTXID: txid, sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  for (const o of outputs) tx.addOutput(o)
  return tx
}
const funding = sourceOf('33'.repeat(32), [{ satoshis: 1000, lockingScript: LockingScript.fromHex('51') }])

const recording = (state) => ({
  async getPublicKey (args) { return await inner.getPublicKey(args) },
  async createSignature (args) {
    state.createSignature.push({ ...args, data: hex(args.data) })
    return await inner.createSignature(args)
  },
  async verifySignature (args) { return await inner.verifySignature(args) },
  async createAction (args) {
    state.createAction.push(args)
    if (state.source === null) throw new Error('stop')
    const partial = new Transaction()
    partial.addInput({
      sourceTransaction: funding, sourceOutputIndex: 0,
      unlockingScript: new UnlockingScript(), sequence: 0xffffffff
    })
    for (const input of args.inputs) {
      const [, vout] = input.outpoint.split('.')
      partial.addInput({
        sourceTransaction: state.source, sourceOutputIndex: Number(vout),
        unlockingScript: new UnlockingScript(), sequence: 0xffffffff
      })
    }
    for (const o of args.outputs ?? []) {
      partial.addOutput({ satoshis: o.satoshis, lockingScript: LockingScript.fromHex(o.lockingScript) })
    }
    state.partial = partial
    return { signableTransaction: { tx: partial.toAtomicBEEF(), reference: REFERENCE } }
  },
  async signAction (args) { state.signAction.push(structuredClone(args)); return {} },
  async abortAction (args) { state.abortAction.push(args); return { aborted: true } }
})

const stopped = async (run) => {
  try { await run() } catch (error) { return error.message }
  throw new Error('the client did not stop')
}

// The reference interpreter's verdict on the token's spend at `index`.
const verdict = (partial, index, source, script) => {
  const input = partial.inputs[index]
  const spend = new Spend({
    sourceTXID: source.id('hex'),
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: source.outputs[input.sourceOutputIndex].satoshis,
    lockingScript: source.outputs[input.sourceOutputIndex].lockingScript,
    transactionVersion: partial.version,
    otherInputs: partial.inputs.filter((_, i) => i !== index),
    outputs: partial.outputs,
    inputIndex: index,
    unlockingScript: UnlockingScript.fromHex(script),
    inputSequence: input.sequence,
    lockTime: partial.lockTime
  })
  try { return { valid: spend.validate() } } catch (error) { return { valid: false, words: error.message } }
}

const cases = []
for (const definition of definitions) {
  const type = definition.definitionType
  const state = { createAction: [], createSignature: [], signAction: [], abortAction: [], source: null }
  const client = new RegistryClient(recording(state), { networkPreset: 'mainnet' })
  await stopped(() => client.registerDefinition(definition))
  const tokenScript = LockingScript.fromHex(state.createAction[0].outputs[0].lockingScript)
  const source = sourceOf('11'.repeat(32), [{ satoshis: 1, lockingScript: tokenScript }])
  state.source = source
  const record = {
    ...definition,
    registryOperator: operator,
    txid: source.id('hex'),
    outputIndex: 0,
    satoshis: 1,
    lockingScript: tokenScript.toHex(),
    beef: source.toBEEF()
  }
  for (const [operation, run] of [
    ['revoke', () => client.removeDefinition(record)],
    ['update', () => client.updateDefinition(record, updated(definition))]
  ]) {
    state.createAction.length = 0
    state.createSignature.length = 0
    state.signAction.length = 0
    state.abortAction.length = 0
    const words = await stopped(run)
    if (state.signAction.length !== 1) throw new Error(`${type} ${operation}: ${words}`)
    const create = state.createAction.at(-1)
    const spends = state.signAction[0].spends
    const [index, spend] = Object.entries(spends)[0]
    cases.push({
      definition_type: type,
      operation,
      definition,
      updated: operation === 'update' ? updated(definition) : null,
      locking_script: tokenScript.toHex(),
      source_tx: source.toHex(),
      txid: source.id('hex'),
      signable_tx: hex(state.partial.toAtomicBEEF()),
      create_inputs: create.inputs,
      create_outputs: (create.outputs ?? []).map((o) => ({ satoshis: o.satoshis, lockingScript: o.lockingScript })),
      // The unlocker's createSignature: the last call, after any lock's.
      create_signature: state.createSignature.at(-1),
      spend_indexes: Object.keys(spends),
      spend_index: Number(index),
      unlocking_script: spend.unlockingScript,
      reference_verdict: verdict(state.partial, Number(index), source, spend.unlockingScript),
      stopped: words,
      aborted: state.abortAction.length
    })
  }
}

process.stdout.write(JSON.stringify({
  description: 'the unlocking script the reference registry client sends signAction for a definition token on removeDefinition (revoke) and updateDefinition (update): PushDrop.unlock(protocol, "1", "anyone", "all", false, satoshis, lockingScript) under completeBoundAction (#548)',
  reference: 'ts-stack@edf6e03 packages/sdk (bun build mod.ts), Node ' + process.version + ', tests/support/registry_unlocking_548.mjs',
  wallet: 'ProtoWallet of the scalar 9 (deterministic RFC 6979 signatures)',
  operator,
  signable_reference: REFERENCE,
  cases
}, null, 2) + '\n')

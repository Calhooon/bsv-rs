// Extension of #326's fake-wallet recorder. No network; Node v22.18.0,
// ts-stack@edf6e03. Run signaction_reference_326.mjs <bundle> --bound-actions.
async function stores(c, enabled) {
  const result = {}
  for (const kind of ['global', 'local']) {
    const state = c.fresh()
    let answer = { type: 'output-list', outputs: [] }
    c.LookupResolver.prototype.query = async () => answer
    const wallet = c.recording(state)
    const store = kind === 'global'
      ? new c.GlobalKVStore({ wallet, acceptDelayedBroadcast: enabled, overlayBroadcast: enabled })
      : new c.LocalKVStore(wallet, 'kvstore default', true, undefined, enabled)
    const runs = {}
    runs.set_new = c.record(state, await c.stop(() => store.set('alpha', 'one')))
    const source = c.tokenOf(state, runs.set_new)
    answer = { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
    state.listed = {
      totalOutputs: 1, BEEF: source.toBEEF(),
      outputs: [{ outpoint: `${source.id('hex')}.0`, satoshis: source.outputs[0].satoshis,
        spendable: true, lockingScript: source.outputs[0].lockingScript.toHex(), tags: ['alpha'] }]
    }
    runs.set_update = c.record(state, await c.stop(() => store.set('alpha', 'two')))
    runs.remove = c.record(state, await c.stop(() => store.remove('alpha')))
    result[kind] = runs
  }
  return result
}

function alter(tx, mode, c) {
  if (mode === 'version' || mode === 'version_before_input') tx.version = 2
  if (mode === 'lock_time') tx.lockTime = 1
  if (mode === 'missing_input' || mode === 'version_before_input') tx.inputs[0].sourceOutputIndex = 1
  if (mode === 'duplicate_input') tx.inputs.push(tx.inputs[0])
  if (mode === 'sequence') tx.inputs[0].sequence = 0
  if (mode === 'output') tx.outputs[0].satoshis = 0
  if (mode === 'inflation') tx.outputs.push({ satoshis: 2, lockingScript: c.Script.fromHex('51') })
  if (mode === 'unrequested_output') tx.outputs.push({ satoshis: 1, lockingScript: c.Script.fromHex('51') })
}

async function probe(c, mode) {
  const state = c.fresh()
  const source = c.sourceOf([{ satoshis: 2, lockingScript: '51' }])
  const outpoint = `${source.id('hex')}.0`
  state.sources[source.id('hex')] = source
  const args = {
    description: 'Bound action probe',
    inputs: [{ outpoint, unlockingScriptLength: 74, inputDescription: 'Requested token' }],
    outputs: [{ satoshis: 1, lockingScript: '51', outputDescription: 'Requested output' }],
    options: { randomizeOutputs: false }
  }
  const wallet = c.recording(state)
  const create = wallet.createAction
  let partial
  const savedPush = Array.prototype.push
  wallet.createAction = async (request) => {
    const result = await create(request)
    partial = c.Transaction.fromAtomicBEEF(result.signableTransaction.tx)
    alter(partial, mode, c)
    result.signableTransaction.tx = partial.toAtomicBEEF()
    if (mode === 'empty_reference') result.signableTransaction.reference = ''
    if (mode === 'shared_intrinsics') Array.prototype.push = function (...items) {
      return Reflect.apply(savedPush, this, items)
    }
    return result
  }
  wallet.signAction = async (request) => {
    state.signAction.push(structuredClone(request))
    for (const [index, spend] of Object.entries(request.spends)) {
      partial.inputs[Number(index)].unlockingScript = c.Script.fromHex(spend.unlockingScript)
    }
    if (mode === 'signed_version') partial.version = 2
    if (mode === 'signed_output') partial.outputs[0].satoshis = 0
    if (mode === 'signed_script') partial.inputs[0].unlockingScript = c.Script.fromHex('00')
    return mode === 'missing_signed_tx' ? {} : { tx: partial.toAtomicBEEF() }
  }
  const inputSigners = { [outpoint]: async () => '51' }
  if (mode === 'unused_signer') inputSigners[`${'22'.repeat(32)}.0`] = async () => '51'
  let error
  try {
    await c.completeBoundAction(wallet, args, { inputSigners })
  } catch (e) {
    error = e.message
  } finally {
    Array.prototype.push = savedPush
  }
  return { error: error ?? null, sign_calls: state.signAction.length, abort_calls: state.abortAction.length }
}

export async function recordBoundActions(c) {
  const defaults = await stores(c, false)
  const enabled = await stores(c, true)
  const refusals = {}
  for (const mode of ['version', 'lock_time', 'missing_input', 'version_before_input',
    'duplicate_input', 'sequence', 'output', 'inflation', 'unrequested_output',
    'empty_reference', 'unused_signer', 'shared_intrinsics', 'signed_version',
    'signed_output', 'signed_script', 'missing_signed_tx']) {
    refusals[mode] = await probe(c, mode)
  }
  return { reference: 'ts-stack@edf6e03', node: process.version,
    recorder: 'tests/support/signaction_reference_326.mjs --bound-actions',
    defaults, enabled, refusals }
}

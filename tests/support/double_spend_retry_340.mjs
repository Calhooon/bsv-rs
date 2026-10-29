// Called only by signaction_reference_326.mjs --double-spend-retry under Node 22.
// All wallet, lookup and broadcast calls stay in process. The local runs record
// the absence of retries at edf6e03, an explicit difference from the #340 ruling.
export async function recordDoubleSpendRetry (ctx) {
  const {
    recording, fresh, record, stop, sourceOf, LookupResolver, TopicBroadcaster,
    GlobalKVStore, LocalKVStore, Transaction, Script, Utils, WERR_REVIEW_ACTIONS
  } = ctx
  const runs = []
  for (const kind of ['global', 'local']) {
    for (const operation of ['set', 'remove']) {
      for (const mode of ['once', 'always']) {
        ctx.resetCounter()
        const state = fresh()
        const wallet = recording(state)
        let stage = 0
        let seeded = false
        let completed = false
        const events = []
        const tokens = [[], []]
        const lookup = async () => {
          if (!seeded) return { type: 'output-list', outputs: [] }
          events.push('lookup')
          return {
            type: 'output-list',
            outputs: (completed ? [] : tokens[stage]).map(({ tx, index }) => ({
              beef: tx.toBEEF(), outputIndex: index
            }))
          }
        }
        LookupResolver.prototype.query = lookup
        const store = kind === 'global'
          ? new GlobalKVStore({ wallet })
          : new LocalKVStore(wallet, 'kvstore', false)
        const seed = record(state, await stop(() => store.set('alpha', 'one')))
        const lock = seed.create_action_outputs[0].lockingScript
        const makeToken = (amount, index) => {
          const tx = sourceOf([
            ...Array.from({ length: index }, () => ({ satoshis: 0, lockingScript: '006a' })),
            { satoshis: amount, lockingScript: lock }
          ])
          state.sources[tx.id('hex')] = tx
          return { tx, index }
        }
        tokens[0] = [makeToken(3, 0)]
        tokens[1] = [makeToken(4, 1), makeToken(5, 2)]
        const competing = tokens[1][0].tx
        const review = () => new WERR_REVIEW_ACTIONS([{
          txid: '22'.repeat(32), status: 'doubleSpend',
          competingTxs: [competing.id('hex')], competingBeef: competing.toBEEF()
        }], [], undefined, undefined, [])
        // No invented BEEF: merge through the SDK's Beef writer supplied below.
        wallet.listOutputs = async () => {
          events.push('lookup')
          const current = completed ? [] : tokens[stage]
          const beef = new ctx.Beef()
          for (const { tx } of current) beef.mergeBeef(tx.toBEEF())
          return {
            totalOutputs: current.length,
            BEEF: beef.toBinary(),
            outputs: current.map(({ tx, index }) => ({
              outpoint: `${tx.id('hex')}.${index}`,
              satoshis: tx.outputs[index].satoshis,
              lockingScript: tx.outputs[index].lockingScript.toHex(),
              spendable: true, tags: ['alpha']
            }))
          }
        }
        const create = wallet.createAction
        wallet.createAction = async args => {
          events.push('createAction')
          const result = await create(args)
          result.signableTransaction.reference = Utils.toBase64(new Array(8).fill(0x52 + state.createAction.length - 1))
          state.pending = result.signableTransaction
          return result
        }
        wallet.signAction = async args => {
          events.push('signAction')
          state.signAction.push(structuredClone(args))
          if (mode === 'always' || state.signAction.length === 1) throw review()
          const signed = Transaction.fromAtomicBEEF(state.pending.tx)
          for (const [index, spend] of Object.entries(args.spends)) {
            signed.inputs[Number(index)].unlockingScript = Script.fromHex(spend.unlockingScript)
          }
          completed = true
          return { txid: signed.id('hex'), tx: signed.toAtomicBEEF() }
        }
        const abort = wallet.abortAction
        wallet.abortAction = async args => {
          events.push('abortAction')
          return await abort(args)
        }
        const broadcasts = []
        TopicBroadcaster.prototype.broadcast = async tx => {
          events.push('broadcast')
          broadcasts.push(tx.id('hex'))
          if (tx.id('hex') === competing.id('hex')) stage = 1
          return { status: 'success', txid: tx.id('hex'), message: 'accepted' }
        }
        seeded = true
        let result = null
        let error = null
        try {
          result = operation === 'set' ? await store.set('alpha', 'two') : await store.remove('alpha')
        } catch (e) {
          error = { name: e.name, message: e.message }
        }
        const encodeTokens = entries => entries.map(({ tx, index }) => ({
          beef: Utils.toHex(tx.toBEEF()), output_index: index, outpoint: `${tx.id('hex')}.${index}`
        }))
        runs.push({
          name: `${kind}_${operation}_${mode}`, kind, operation, mode,
          initial_tokens: encodeTokens(tokens[0]), fresh_tokens: encodeTokens(tokens[1]),
          review_error: { name: review().name, message: review().message, code: review().code },
          competing: { txid: competing.id('hex'), beef: Utils.toHex(competing.toBEEF()) },
          result, error, events, broadcasts,
          create_actions: state.createAction.map(args => ({
            ...args, inputBEEF: args.inputBEEF === undefined ? undefined : Utils.toHex(args.inputBEEF)
          })),
          sign_actions: state.signAction, abort_actions: state.abortAction
        })
      }
    }
  }
  return {
    description: '#340: actual global retry and local non-retry sequences; local retries in Rust are the owner-requested extension',
    reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9; Node ' + process.version,
    runs
  }
}

// #477: Error.message at both lookup catches and both bound-action catches.
// Every token and BEEF starts with the SDK's writer; corruption happens here.
export async function recordOriginalErrors477 (c) {
  const { recording, fresh, record, stop, sourceOf, LocalKVStore,
    Transaction, Beef, Utils, WalletError } = c
  const prepare = async () => {
    c.resetCounter()
    const state = fresh()
    const wallet = recording(state)
    const store = new LocalKVStore(wallet, 'kvstore', false)
    const seed = record(state, await stop(() => store.set('alpha', 'one')))
    const source = sourceOf(seed.create_action_outputs)
    state.sources[source.id('hex')] = source
    state.listed = {
      totalOutputs: 1, BEEF: source.toBEEF(),
      outputs: [{ outpoint: `${source.id('hex')}.0`, satoshis: 1,
        spendable: true, lockingScript: source.outputs[0].lockingScript.toHex(),
        tags: ['alpha'] }]
    }
    return { state, wallet, store, source }
  }
  const call = (store, operation) => operation === 'get'
    ? store.get('alpha')
    : operation === 'set' ? store.set('alpha', 'two') : store.remove('alpha')
  const sample = await prepare()
  const badBeef = Array.from(new Beef().toBinary())
  badBeef.fill(0, 0, 4)
  const nonAtomic = sample.source.toBEEF()
  const messages = {
    wallet_fault: 'backend: café\nretry',
    beef_error: await stop(() => Beef.fromBinaryStrict(badBeef)),
    transaction_error: await stop(() => Transaction.fromAtomicBEEF(nonAtomic)),
    wallet_error: 'wallet error: preserve this payload',
    kvstore_error: 'kvstore error: preserve this payload',
    kvstore_local_error: 'local: preserve this payload'
  }
  const injected = []
  for (const [kind, message] of Object.entries(messages)) {
    for (const stage of ['listOutputs', 'getPublicKey', 'verifySignature', 'createAction', 'signAction']) {
      const operations = ['createAction', 'signAction'].includes(stage)
        ? ['set', 'remove'] : ['get', 'set']
      for (const operation of operations) {
        const { wallet, store } = await prepare()
        wallet[stage] = async () => {
          throw kind.startsWith('wallet_') ? new WalletError(message) : new Error(message)
        }
        injected.push({ kind, operation, stage, message,
          error: await stop(() => call(store, operation)) })
      }
    }
  }
  const malformed = []
  for (const operation of ['get', 'set']) {
    const { state, store } = await prepare()
    state.listed.BEEF = badBeef
    malformed.push({ kind: 'beef_error', operation, stage: 'listOutputs',
      bytes: Utils.toHex(badBeef),
      error: await stop(() => call(store, operation)) })
  }
  for (const operation of ['set', 'remove']) {
    for (const [kind, bytes] of [['beef_error', badBeef], ['transaction_error', nonAtomic]]) {
      const { wallet, store } = await prepare()
      const create = wallet.createAction
      wallet.createAction = async args => {
        const result = await create(args)
        result.signableTransaction.tx = bytes
        return result
      }
      malformed.push({ kind, operation, stage: 'createAction', bytes: Utils.toHex(bytes),
        error: await stop(() => call(store, operation)) })
    }
  }
  return { source_beef: Utils.toHex(nonAtomic), messages, injected, malformed }
}

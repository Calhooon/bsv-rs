// #454: actual SDK-written tokens, complete action inputs/BEEF, request text
// and unlocking scripts, plus pagination/authentication verdicts. No network.
import { recordOriginalErrors477 } from './kvstore_original_error_477.mjs'
import { recordTokenSearch478 } from './kvstore_local_divergences_478.mjs'
import { recordLocalParserWords489 } from './kvstore_local_parser_words_489.mjs'

export async function recordLocal454 (c) {
  const { recording, fresh, record, stop, sourceOf, LocalKVStore, GlobalKVStore,
    LookupResolver, Beef, Script, Utils } = c
  const runs = []
  for (const kind of ['local', 'global']) {
    for (const operation of ['set', 'remove']) {
      c.resetCounter()
      const state = fresh()
      const wallet = recording(state)
      const publicKeys = []
      const getPublicKey = wallet.getPublicKey
      wallet.getPublicKey = async args => {
        publicKeys.push(JSON.stringify(args))
        return getPublicKey(args)
      }
      let answer = { type: 'output-list', outputs: [] }
      LookupResolver.prototype.query = async () => answer
      const store = kind === 'local'
        ? new LocalKVStore(wallet, 'kvstore', false)
        : new GlobalKVStore({ wallet })
      const seed = record(state, await stop(() => store.set('alpha', 'one')))
      publicKeys.length = 0
      const lock = seed.create_action_outputs[0].lockingScript
      const sources = [2, 3].map(satoshis => sourceOf([{ satoshis, lockingScript: lock }]))
      const beef = new Beef()
      for (const tx of sources) {
        state.sources[tx.id('hex')] = tx
        beef.mergeBeef(tx.toBEEF())
      }
      state.listed = {
        totalOutputs: 2, BEEF: beef.toBinary(),
        outputs: sources.map(tx => ({ outpoint: `${tx.id('hex')}.0`,
          satoshis: tx.outputs[0].satoshis, spendable: true,
          lockingScript: tx.outputs[0].lockingScript.toHex(), tags: ['alpha'] }))
      }
      answer = { type: 'output-list', outputs: sources.map(tx => ({ beef: tx.toBEEF(), outputIndex: 0 })) }
      // Funding outputs are part of the wallet's answer, not the store request.
      // Keep the same zero-valued data output as the Rust recording wallet.
      const create = wallet.createAction
      wallet.createAction = async args => {
        const result = await create(args)
        if ((args.outputs ?? []).length === 0) {
          const tx = c.Transaction.fromAtomicBEEF(result.signableTransaction.tx)
          tx.addOutput({ satoshis: 0, lockingScript: Script.fromHex('006a') })
          result.signableTransaction.tx = tx.toAtomicBEEF()
        }
        return result
      }
      const stopped = await stop(() => operation === 'set' ? store.set('alpha', 'two') : store.remove('alpha'))
      const args = state.createAction.at(-1)
      runs.push({ kind, operation, sources: sources.map(tx => Utils.toHex(tx.toBEEF())),
        create_action_inputs: args.inputs,
        input_beef: Utils.toHex(args.inputBEEF), ...record(state, stopped),
        get_public_key_json: publicKeys,
        create_action_description: args.description,
        create_action_output_descriptions: (args.outputs ?? []).map(o => o.outputDescription) })
    }
  }
  return { reference: 'ts-stack@edf6e03; Node ' + process.version,
    description: '#454: two live tokens, exact merged BEEF, requests and unlocking scripts',
    signable_reference: 'UlJSUlJSUlI=', runs,
    original_errors_477: await recordOriginalErrors477(c),
    token_search: await recordTokenSearch478(c),
    parser_words_489: await recordLocalParserWords489(c) }
}

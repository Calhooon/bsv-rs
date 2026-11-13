// #904: the reference's ContactsManager (`ts-stack@edf6e03`
// `packages/sdk/src/identity/ContactsManager.ts`) updating and removing a
// contact listed in a BEEF of more than one transaction, its token at an
// output other than 0, its input at an index other than 0, and failing where
// its wallet fails, recorded as the wallet received each call. A mode of the
// #326 recorder (`signaction_reference_326.mjs --contacts-listed`, the same
// bundle and the same SHA-256 counter stream), so two runs print the same
// file and the #326 recording is untouched:
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/signaction_reference_326.mjs \
//     "$W/sdk326.mjs" --contacts-listed > tests/vectors/contacts_listed_spend.json
//
// The wallet is the ProtoWallet of the scalar 9 under a recorder, as #326's:
// createAction with inputs answers a signable transaction spending the
// requested outpoints of the sources it was given (a funding input of its own
// ahead of them when the case asks), the requested outputs in order (one
// zero-satoshi `OP_FALSE OP_RETURN` when none, as this crate's counting wallet
// writes it, so both doubles hand out one transaction); without inputs it
// answers the finished transaction; signAction answers the signable
// transaction with the spends applied (`signed`) or nothing (`none`); a method
// named in `fail` throws `<name> failed`, and `create_no_tx` answers `{}`.
const hex = (bytes) => Buffer.from(bytes).toString('hex')

export async function recordContactsListed ({
  ContactsManager, ProtoWallet, PrivateKey, Transaction, Script, Utils, sourceOf, resetCounter
}) {
  const REFERENCE = Utils.toBase64(new Array(8).fill(0x52))
  const recorder = (state) => {
    const inner = new ProtoWallet(new PrivateKey(9))
    const wallet = {}
    const call = (name, args) => {
      state.calls.push(name)
      if (state.fail.includes(name)) throw new Error(`${name} failed`)
      return args
    }
    for (const name of ['getPublicKey', 'createSignature', 'verifySignature', 'createHmac',
      'verifyHmac', 'encrypt', 'decrypt']) {
      wallet[name] = async (args) => { call(name); return inner[name](args) }
    }
    wallet.listOutputs = async (args) => {
      call('listOutputs')
      state.listOutputs.push({ ...args })
      return state.listed ?? { totalOutputs: 0, outputs: [] }
    }
    wallet.createAction = async (args) => {
      call('createAction')
      const copy = structuredClone(args)
      if (copy.inputBEEF !== undefined) copy.inputBEEF = hex(copy.inputBEEF)
      state.createAction.push(copy)
      if (state.createNoTx) return {}
      const outputs = args.outputs ?? []
      if (args.inputs === undefined) {
        const finished = sourceOf(outputs)
        state.created = finished
        return { txid: finished.id('hex'), tx: finished.toAtomicBEEF() }
      }
      const partial = new Transaction()
      if (state.funding !== undefined) {
        partial.addInput({
          sourceTransaction: state.funding,
          sourceOutputIndex: 0,
          unlockingScript: new Script(),
          sequence: 0xffffffff
        })
      }
      for (const input of args.inputs) {
        const [txid, vout] = input.outpoint.split('.')
        partial.addInput({
          sourceTransaction: state.sources[txid],
          sourceOutputIndex: Number(vout),
          unlockingScript: new Script(),
          sequence: 0xffffffff
        })
      }
      if (outputs.length === 0) {
        partial.addOutput({ satoshis: 0, lockingScript: Script.fromHex('006a') })
      }
      for (const o of outputs) {
        partial.addOutput({ satoshis: o.satoshis, lockingScript: Script.fromHex(o.lockingScript) })
      }
      // #904's fold: the signable transaction not the one asked, as this
      // crate's counting wallet's `create_mode` writes it: the contact's
      // input twice, or its output index moved to 1.
      // #904's fourth fold: `bind` may name two faults at once (an array).
      const binds = [].concat(state.bind ?? [])
      if (binds.includes('duplicate_input')) {
        const first = partial.inputs[0]
        partial.addInput({
          sourceTransaction: first.sourceTransaction,
          sourceOutputIndex: first.sourceOutputIndex,
          unlockingScript: new Script(),
          sequence: 0xffffffff
        })
      }
      if (binds.includes('missing_input')) partial.inputs[0].sourceOutputIndex = 1
      if (binds.includes('output')) partial.outputs[0].satoshis = 0
      state.partial = partial
      const tx = partial.toAtomicBEEF()
      state.signable.push(hex(tx))
      return { signableTransaction: { tx, reference: REFERENCE } }
    }
    wallet.signAction = async (args) => {
      call('signAction')
      state.signAction.push(structuredClone(args))
      if (state.sign !== 'signed') return {}
      const signed = Transaction.fromAtomicBEEF(state.partial.toAtomicBEEF())
      for (const [index, spend] of Object.entries(args.spends)) {
        signed.inputs[Number(index)].unlockingScript = Script.fromHex(spend.unlockingScript)
      }
      // #904's fourth fold: the signed transaction moved as this crate's
      // counting wallet's `sign_mode` moves it, one fault or two.
      const faults = state.signFaults ?? []
      if (faults.includes('signed_version')) signed.version = 2
      if (faults.includes('signed_output')) signed.outputs[0].satoshis = 0
      if (faults.includes('signed_script')) signed.inputs[0].unlockingScript = Script.fromHex('00')
      return { txid: signed.id('hex'), tx: signed.toAtomicBEEF() }
    }
    wallet.abortAction = async (args) => {
      call('abortAction')
      state.abortAction.push(structuredClone(args))
      return { aborted: true }
    }
    return wallet
  }
  const fresh = (over = {}) => ({
    calls: [], listOutputs: [], createAction: [], signAction: [], abortAction: [], signable: [],
    sources: {}, fail: [], sign: 'signed', ...over
  })
  const contact = {
    name: 'Bob Example',
    identityKey: new PrivateKey(3).toPublicKey().toString(),
    avatarURL: 'https://example.com/bob.png',
    abbreviatedKey: '',
    badgeIconURL: '',
    badgeLabel: '',
    badgeClickURL: ''
  }
  const outcome = async (f) => {
    try {
      await f()
      return { ok: true }
    } catch (e) {
      return { error: e.message, cause: e.cause?.message ?? null }
    }
  }
  const caseOf = (state, result) => ({
    calls: state.calls,
    list_outputs: state.listOutputs,
    create_action: state.createAction,
    signable: state.signable,
    sign_action: state.signAction,
    abort_action: state.abortAction,
    outcome: result
  })

  // The token: the create path's own output, its key ID drawn by the stream.
  resetCounter()
  const created = fresh()
  const creating = new ContactsManager(recorder(created))
  const createOutcome = await outcome(() => creating.saveContact(contact))
  const createCase = caseOf(created, createOutcome)
  const token = created.createAction[0].outputs[0]

  // A parent P carrying the token's lock at 1000 satoshis, the token's
  // transaction C spending P:0: written `C.toBEEF()`, P ahead of C.
  const parent = sourceOf([{ satoshis: 1000, lockingScript: token.lockingScript }])
  const childOf = (outputs) => {
    const tx = new Transaction()
    tx.addInput({
      sourceTransaction: parent,
      sourceOutputIndex: 0,
      unlockingScript: Script.fromHex('51'),
      sequence: 0xffffffff
    })
    for (const o of outputs) {
      tx.addOutput({ satoshis: o.satoshis, lockingScript: Script.fromHex(o.lockingScript) })
    }
    return tx
  }
  const shapes = {
    token_at_0: { child: childOf([{ satoshis: 1, lockingScript: token.lockingScript }]), vout: 0 },
    token_at_1: {
      child: childOf([{ satoshis: 5, lockingScript: '51' }, { satoshis: 1, lockingScript: token.lockingScript }]),
      vout: 1
    },
    input_at_1: { child: sourceOf([{ satoshis: 1, lockingScript: token.lockingScript }]), vout: 0, funding: true }
  }
  const funding = sourceOf([{ satoshis: 1, lockingScript: '51' }])
  const listing = (child, vout) => ({
    totalOutputs: 1,
    BEEF: child.toBEEF(),
    outputs: [{
      outpoint: `${child.id('hex')}.${vout}`,
      satoshis: 1,
      spendable: true,
      customInstructions: token.customInstructions
    }]
  })
  const run = async (over, act) => {
    const state = fresh(over)
    const manager = new ContactsManager(recorder(state))
    const result = await outcome(() => act(manager))
    return caseOf(state, result)
  }
  const update = (manager) => manager.saveContact({ ...contact, name: 'Bob Updated' })
  const remove = (manager) => manager.removeContact(contact.identityKey)

  const cases = {}
  for (const [name, shape] of Object.entries(shapes)) {
    const over = () => ({
      listed: listing(shape.child, shape.vout),
      sources: { [shape.child.id('hex')]: shape.child },
      funding: shape.funding ? funding : undefined
    })
    resetCounter()
    cases[`${name}_update`] = await run(over(), update)
    resetCounter()
    cases[`${name}_remove`] = await run(over(), remove)
  }
  const single = () => ({
    listed: listing(shapes.token_at_0.child, 0),
    sources: { [shapes.token_at_0.child.id('hex')]: shapes.token_at_0.child }
  })
  // Item 3's cells: each failure as the reference answers it.
  resetCounter()
  cases.update_sign_no_tx = await run({ ...single(), sign: 'none' }, update)
  resetCounter()
  cases.remove_sign_no_tx = await run({ ...single(), sign: 'none' }, remove)
  resetCounter()
  cases.add_hmac_fails = await run({ fail: ['createHmac'] }, (m) => m.saveContact(contact))
  resetCounter()
  cases.add_list_fails = await run({ fail: ['listOutputs'] }, (m) => m.saveContact(contact))
  resetCounter()
  cases.add_create_fails = await run({ fail: ['createAction'] }, (m) => m.saveContact(contact))
  resetCounter()
  cases.add_create_no_tx = await run({ createNoTx: true }, (m) => m.saveContact(contact))
  resetCounter()
  cases.update_create_fails = await run({ ...single(), fail: ['createAction'] }, update)
  resetCounter()
  cases.remove_hmac_fails = await run({ fail: ['createHmac'] }, remove)
  resetCounter()
  cases.remove_list_fails = await run({ fail: ['listOutputs'] }, remove)
  resetCounter()
  cases.remove_nothing_listed = await run({}, remove)
  resetCounter()
  cases.list_fails = await run({ fail: ['listOutputs'] }, (m) => m.getContacts(undefined, true))
  // #904's fold: the removal refuses a signable transaction that does not
  // spend the contact's outpoint exactly once before any signAction
  // (`ContactsManager.ts:987`, `#findBoundInput` `:689-697`), and aborts it
  // (`:1018`). The calls, signAction, the aborts and the outcome alone are
  // kept, so the vector holds no BEEF the census of the seeds would count.
  for (const bind of ['duplicate_input', 'missing_input']) {
    resetCounter()
    const full = await run({ ...single(), bind }, remove)
    cases[`remove_${bind}`] = {
      calls: full.calls,
      sign_action: full.sign_action,
      abort_action: full.abort_action,
      outcome: full.outcome
    }
  }
  // #904's third fold: the update refuses the same signable transactions,
  // and one whose contact output is not the one asked, before it asks any
  // signature (`#findBoundInput` and `#requireContactOutput` at `:819-820`,
  // `createSignature` at `:821-830`), and aborts it (`:853`). The same four
  // members are kept.
  for (const bind of ['duplicate_input', 'missing_input', 'output']) {
    resetCounter()
    const full = await run({ ...single(), bind }, update)
    cases[`update_${bind}`] = {
      calls: full.calls,
      sign_action: full.sign_action,
      abort_action: full.abort_action,
      outcome: full.outcome
    }
  }
  // #904's third fold, the sweep's: the lookups' bounds and the other
  // identity's refusal (`#findExistingOutput` `:591-592`, `:620-625`;
  // `removeContact` `:904-905`), the token listed 100 and 101 times, and a
  // save of another identity over the listed token. The number of wallet
  // calls, of signActions and the outcome alone are kept (a listing of 100
  // authenticates 100 outputs).
  const repeated = (count) => {
    const one = listing(shapes.token_at_0.child, 0)
    return { ...one, totalOutputs: count, outputs: Array.from({ length: count }, () => one.outputs[0]) }
  }
  const other = {
    ...contact,
    name: 'Carol Example',
    identityKey: new PrivateKey(4).toPublicKey().toString()
  }
  const sweep = [
    ['update_other_identity', single(), (m) => m.saveContact(other)],
    ['update_listing_100', { ...single(), listed: repeated(100) }, update],
    ['update_listing_101', { ...single(), listed: repeated(101) }, update],
    ['remove_listing_100', { ...single(), listed: repeated(100) }, remove],
    ['remove_listing_101', { ...single(), listed: repeated(101) }, remove]
  ]
  for (const [name, over, act] of sweep) {
    resetCounter()
    const full = await run(over, act)
    cases[name] = { call_count: full.calls.length, sign_action_count: full.sign_action.length, outcome: full.outcome }
  }
  // #904's fourth fold: two faults at once, the refusal the reference
  // names. The update's two checks of the signable transaction
  // (`#findBoundInput` then `#requireContactOutput`, `:819-820`); a fault of
  // the signable transaction beside one of the signed transaction (the
  // signed fault lives in signAction's answer, which a signable fault never
  // reaches, so one signed fault stands for the three); and two faults of the
  // signed transaction (`#assertTransactionTemplate`'s header before its
  // outputs, `:700-725`, both before the signature, `:847-850`). The
  // removal's one output is the zero-satoshi `OP_FALSE OP_RETURN` both
  // doubles write, so `signed_output` moves nothing there and its removal
  // pairs are version and script alone. The same four members are kept, no
  // BEEF.
  const pairs = [
    ['update_duplicate_input_and_output', { bind: ['duplicate_input', 'output'] }, update],
    ['update_missing_input_and_output', { bind: ['missing_input', 'output'] }, update],
    ['update_duplicate_input_and_signed_version', { bind: 'duplicate_input', signFaults: ['signed_version'] }, update],
    ['update_missing_input_and_signed_version', { bind: 'missing_input', signFaults: ['signed_version'] }, update],
    ['update_output_and_signed_version', { bind: 'output', signFaults: ['signed_version'] }, update],
    ['update_signed_version_and_output', { signFaults: ['signed_version', 'signed_output'] }, update],
    ['update_signed_version_and_script', { signFaults: ['signed_version', 'signed_script'] }, update],
    ['update_signed_output_and_script', { signFaults: ['signed_output', 'signed_script'] }, update],
    ['remove_duplicate_input_and_signed_version', { bind: 'duplicate_input', signFaults: ['signed_version'] }, remove],
    ['remove_missing_input_and_signed_version', { bind: 'missing_input', signFaults: ['signed_version'] }, remove],
    ['remove_signed_version_and_script', { signFaults: ['signed_version', 'signed_script'] }, remove]
  ]
  for (const [name, over, act] of pairs) {
    resetCounter()
    const full = await run({ ...single(), ...over }, act)
    cases[name] = {
      calls: full.calls,
      sign_action: full.sign_action,
      abort_action: full.abort_action,
      outcome: full.outcome
    }
  }
  // #904's fourth fold: two contacts saved (the cache warm), then a forced
  // refresh whose listing fails, then a plain read: the calls after the
  // failure, the read's outcome and its count. The reference's forced
  // refresh drops the cache before it loads (`:321`, `#invalidate`
  // `:343-347`), so the plain read asks the wallet again.
  {
    resetCounter()
    const state = fresh()
    const manager = new ContactsManager(recorder(state))
    const carol = { ...contact, name: 'Carol Example', identityKey: new PrivateKey(4).toPublicKey().toString() }
    const saved = [await outcome(() => manager.saveContact(contact)), await outcome(() => manager.saveContact(carol))]
    const before = state.calls.length
    state.fail.push('listOutputs')
    const refresh = await outcome(() => manager.getContacts(undefined, true))
    state.fail.length = 0
    let read
    const plain = await outcome(async () => { read = await manager.getContacts() })
    cases.refresh_fails_after_two_saves = {
      saved,
      refresh,
      read: plain,
      read_count: read?.length ?? null,
      calls_after_saves: state.calls.slice(before)
    }
  }

  return {
    description: '#904: the reference ContactsManager updating and removing a contact whose BEEF holds the token transaction after its parent, the token at output 1, the contact input at index 1, and each wallet failure of the update, the removal, the save and the listing; the wallet calls in order, the createAction and signAction arguments, the signable transactions, the aborts and the outcome',
    reference: '@bsv/sdk at ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 (bundled with bun build, the #326 entry), run under Node ' + process.version + ' by tests/support/signaction_reference_326.mjs --contacts-listed',
    site: 'ts-stack@edf6e03 packages/sdk/src/identity/ContactsManager.ts:350-378,527-570,633-697,699-745,776-856,859-885,891-1021',
    wallet_key: 9,
    signable_reference: REFERENCE,
    contact,
    token: { locking_script: token.lockingScript, custom_instructions: token.customInstructions },
    shapes: Object.fromEntries(Object.entries(shapes).map(([name, shape]) => [name, {
      beef: hex(shape.child.toBEEF()),
      txid: shape.child.id('hex'),
      vout: shape.vout,
      parent_txid: shape.child === shapes.input_at_1.child ? null : parent.id('hex'),
      funding: shape.funding ? hex(funding.toBinary()) : null
    }])),
    create: createCase,
    cases
  }
}

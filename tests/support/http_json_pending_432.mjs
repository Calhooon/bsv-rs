// #432 extends #408's recorder. Every verdict below is obtained by the caller
// from the pinned SDK, including request-only witnesses and typed residues.
export function extend432(cases, seeds, sdk) {
  const clone = structuredClone
  const names = new Set(cases.map(c => c.name))
  const add = (row, call, name, result, args = seeds.get(call).args, extra = {}) => {
    const base = `row_${row}_${call}_${name}`
    let unique = base
    for (let occurrence = 2; names.has(unique); occurrence++) unique = `${base}_case_${occurrence}`
    names.add(unique)
    cases.push({ name: unique, group: `row_${row}`, call,
      args: clone(args), bodyText: JSON.stringify(result), ...extra })
  }
  const edit = (call, path, value) => {
    const result = clone(seeds.get(call).result)
    const keys = path.split('.')
    let at = result
    for (const key of keys.slice(0, -1)) at = at[key]
    if (value === undefined) delete at[keys.at(-1)]
    else at[keys.at(-1)] = value
    return result
  }
  const variations = (row, call, path, values, args) => values.forEach((v, i) => add(row, call, `${path}_${i}`, edit(call, path, v), args))
  const wrong = [undefined, null, false, 1, 'true']
  const range = (low, high) => [null, '1', low - 1, low, low + 0.5, high, high + 1]
  const key = seeds.get('getPublicKey').result.publicKey
  const other = seeds.get('revealCounterpartyKeyLinkage').result.prover
  const point = '33'.repeat(32) + '.0'
  const badKeys = [null, 3, '', 'aa', 'f'.repeat(66), '02' + 'ff'.repeat(32), key.toUpperCase()]
  const output = { satoshis: 1, spendable: true, outputIndex: 0, outputDescription: '', basket: '' }
  const input = { sourceOutpoint: point, sourceSatoshis: 1, inputDescription: '', sequenceNumber: 0xffffffff }
  const history = clone(seeds.get('listActions').result)
  history.actions[0].inputs = [input]
  history.actions[0].outputs = [output]
  const historyEdit = (row, path, values, args) => {
    const prior = seeds.get('listActions').result
    seeds.get('listActions').result = history
    variations(row, 'listActions', path, values, args)
    seeds.get('listActions').result = prior
  }
  for (const call of seeds.keys()) {
    const result = clone(seeds.get(call).result)
    for (const unsafe of ['__proto__', 'constructor', 'prototype']) {
      const text = JSON.stringify(result).replace('{', `{"${unsafe}":{},`)
      add(3, call, unsafe, result, undefined, { bodyText: text })
    }
  }
  for (const [name, item, count] of [['array_edge', 'x', 999997], ['array_over', 'x', 1000001], ['graph_edge', {}, 499997], ['graph_over', {}, 500001]]) {
    add(3, 'getHeight', name, { height: 1, extra: 'EXPAND_432' }, {},
      { expansion: { marker: '"EXPAND_432"', length: count, array: true, item } })
  }
  add(3, 'getHeight', 'response_cap', { height: 1 }, {}, { headers: { 'content-length': '268435457' } })
  for (const height of ['1', '1.0']) {
    for (const [name, pad] of [['nonfinite', '1e400'], ['depth_129', '['.repeat(129) + '0' + ']'.repeat(129)]]) {
      add(3, 'getHeight', `${name}_${height}`, { height: 1 }, {},
        { bodyText: `{"height":${height},"pad":${pad}}` })
    }
  }
  add(3, 'getVersion', 'lone_surrogate', {}, {}, {
    bodyText: '{"version":"123456\\ud800"}',
    residue: 'Rust strings cannot represent a lone UTF-16 surrogate'
  })
  for (const [name, pad] of [['nonfinite', '1e400'], ['depth_129', '['.repeat(129) + '0' + ']'.repeat(129)]]) {
    add(3, 'getVersion', `error_${name}`, {}, {}, {
      status: 400,
      bodyText: `{"isError":true,"code":5.0,"reviewActionResults":[],"pad":${pad}}`
    })
  }
  for (const [row, calls, field] of [[6, ['abortAction'], 'aborted'], [7, ['internalizeAction'], 'accepted'],
    [8, ['relinquishOutput', 'relinquishCertificate'], 'relinquished'], [9, ['verifyHmac', 'verifySignature'], 'valid'],
    [10, ['isAuthenticated', 'waitForAuthentication'], 'authenticated']]) {
    for (const call of calls) variations(row, call, field, [...wrong, true])
  }
  variations(11, 'getPublicKey', 'publicKey', badKeys)
  for (const call of ['revealCounterpartyKeyLinkage', 'revealSpecificKeyLinkage']) {
    for (const field of ['prover', 'verifier', 'counterparty']) variations(15, call, field, badKeys)
    add(15, call, 'key_precedes_bytes', { ...seeds.get(call).result, prover: 'bad', encryptedLinkage: null })
  }
  variations(17, 'revealCounterpartyKeyLinkage', 'revelationTime', [null, '', '2026-01-01', '2026-01-01T25:00:00Z', '2026-13-01T00:00:00Z', '2026-02-31T00:00:00Z', '2026-01-01T24:00:00.000Z', '2026-01-01T00:00Z', '2026-01-01T00:00:00+01:30', 'x'.repeat(65), '2026-01-01T00:00:00Z\n', '2026-01-01T00:00:00\rZ', '2026-01-01T00:00:00\u2028Z', '2026-01-01T00:00:00\u2029Z'])
  for (const field of ['verifier', 'counterparty']) variations(18, 'revealCounterpartyKeyLinkage', field, [other, seeds.get('revealCounterpartyKeyLinkage').result[field].toUpperCase()])
  variations(19, 'revealSpecificKeyLinkage', 'protocolID', [[-1, 'abcde'], [3, 'abcde'], [1, 'abcd'], [1, 'é'.repeat(201)], [1.5, 'abcde'], [1, null]])
  variations(19, 'revealSpecificKeyLinkage', 'keyID', [null, '', 'é'.repeat(401)])
  variations(19, 'revealSpecificKeyLinkage', 'proofType', range(0, 255))
  for (const counterparty of ['self', 'anyone', key]) {
    const args = { ...seeds.get('revealSpecificKeyLinkage').args, counterparty }
    variations(20, 'revealSpecificKeyLinkage', 'counterparty', [key, other], args)
  }
  variations(20, 'revealSpecificKeyLinkage', 'verifier', [key, other])
  variations(21, 'revealSpecificKeyLinkage', 'protocolID', [[0, 'fixture keys'], [1, 'other protocol']])
  variations(21, 'revealSpecificKeyLinkage', 'keyID', ['other key'])
  add(21, 'revealSpecificKeyLinkage', 'integral_tuple', seeds.get('revealSpecificKeyLinkage').result, undefined, { bodyText: JSON.stringify(seeds.get('revealSpecificKeyLinkage').result).replace('[1,', '[1.0,') })
  variations(22, 'getHeight', 'height', range(1, 0xffffffff))
  add(22, 'getHeight', 'integral_float', { height: 1 }, {}, { bodyText: '{"height":1.0}' })
  variations(23, 'getHeaderForHeight', 'header', [null, '', 'a'.repeat(159), 'a'.repeat(160), 'gg'.repeat(80)])
  variations(24, 'getNetwork', 'network', [null, 1, 'regtest', 'testnet'])
  variations(25, 'getVersion', 'version', [null, '', '123456', '1234567', 'é'.repeat(15), 'é'.repeat(16)])

  const signed = clone(seeds.get('signAction'))
  const { Transaction, LockingScript, UnlockingScript, Beef } = sdk
  const source = Transaction.fromBEEF(seeds.get('listOutputs').result.BEEF)
  const sourceId = source.id('hex')
  const build = (changes = {}) => new Transaction(changes.version ?? 1,
    changes.inputs ?? [{ sourceTransaction: source, sourceTXID: sourceId, sourceOutputIndex: 0,
      unlockingScript: UnlockingScript.fromHex('51'), sequence: 0xffffffff }],
    changes.outputs ?? [{ satoshis: 900, lockingScript: LockingScript.fromHex('51') }], changes.lockTime ?? 0)
  const action = (row, name, tx, args, signable = true, extra = {}) => {
    const body = signable ? { signableTransaction: { tx: tx.toAtomicBEEF(), reference: 'Zml4dHVyZQ==' }, ...extra }
      : { txid: tx.id('hex'), tx: tx.toAtomicBEEF(), ...extra }
    add(row, signable ? 'createAction' : 'signAction', name, body, args)
  }
  const deferred = { description: 'fixture action', outputs: [{ satoshis: 900, lockingScript: '51', outputDescription: 'fixture output' }], options: { signAndProcess: false } }
  variations(26, 'signAction', 'txid', [null, 1, 'a', 'gg'.repeat(32), '11'.repeat(31)])
  variations(28, 'signAction', 'tx', [[], [1, 2, 3], [...signed.result.tx, 0]])
  variations(28, 'signAction', 'txid', ['11'.repeat(32)])
  const tx = build()
  add(28, 'signAction', 'ordinary_beef', { txid: tx.id('hex'), tx: tx.toBEEF() }, signed.args)
  add(28, 'createAction', 'partial_atomic', { signableTransaction: { tx: tx.toAtomicBEEF(true), reference: 'Zml4dHVyZQ==' } }, deferred)
  variations(29, 'createAction', 'noSendChange', [[point.replace('.0', '.01')], [point.replace('.0', '.+1')], [point.replace('.0', '.4294967296')], [null]])
  variations(30, 'signAction', 'sendWithResults', [[{ txid: null, status: 'sending' }], [{ txid: signed.result.txid, status: 'other' }]])
  add(30, 'signAction', 'send_count', { ...signed.result, sendWithResults: 'EXPAND_432' }, undefined,
    { expansion: { marker: '"EXPAND_432"', length: 1002, array: true, item: { txid: signed.result.txid, status: 'sending' } } })
  variations(32, 'createAction', 'signableTransaction.reference', [null, '', 'abc', 'AA==', 'AB==', 'a_=='])
  add(33, 'createAction', 'deferred_missing', { txid: signed.result.txid }, deferred)
  add(33, 'createAction', 'completed_missing', {}, { description: 'fixture action', options: { returnTXIDOnly: true } })
  add(33, 'createAction', 'unsigned_deferred_missing', { txid: signed.result.txid }, seeds.get('createAction').args)
  add(34, 'signAction', 'completed_missing', {})
  const badSource = { ...seeds.get('createAction').args, inputBEEF: [1, 2, 3] }
  add(35, 'createAction', 'bad_source', seeds.get('createAction').result, badSource, { mode: 'snapshot' })
  // Match the source-less partial transaction with a request-supplied source envelope.
  const bare = new Transaction(1, [{ sourceTXID: sourceId, sourceOutputIndex: 0,
    unlockingScript: UnlockingScript.fromHex('51'), sequence: 0xffffffff }],
    [{ satoshis: 900, lockingScript: LockingScript.fromHex('51') }], 0)
  const ordinary = new Beef(); ordinary.mergeRawTx(bare.toBinary())
  const completedArgs = { ...deferred, inputBEEF: seeds.get('listOutputs').result.BEEF,
    inputs: [{ outpoint: sourceId + '.0', unlockingScript: '51', inputDescription: 'fixture input' }], options: {} }
  add(35, 'createAction', 'request_source_evidence', { txid: bare.id('hex'), tx: ordinary.toBinary() }, completedArgs)
  for (const [name, changes] of [['version', { version: 2 }], ['lock_time', { lockTime: 1 }]]) action(36, name, build(changes), deferred)
  action(37, 'duplicate_input', build({ inputs: [...build().inputs, ...build().inputs] }), deferred)
  const requestInput = { ...deferred, inputs: [{ outpoint: sourceId + '.0', unlockingScriptLength: 1, inputDescription: 'fixture input' }] }
  action(38, 'missing_input', build({ inputs: [] }), requestInput)
  action(38, 'duplicate_request', build(), { ...requestInput, inputs: [...requestInput.inputs, ...requestInput.inputs] })
  cases.at(-1).mode = 'result'
  action(38, 'sequence', build({ inputs: [{ ...build().inputs[0], sequence: 1 }] }), requestInput)
  action(38, 'script', build(), { ...requestInput, inputs: [{ outpoint: sourceId + '.0', unlockingScript: '52', inputDescription: 'fixture input' }] })
  action(39, 'amount', build({ outputs: [{ satoshis: 899, lockingScript: LockingScript.fromHex('51') }] }), deferred)
  action(39, 'multiplicity', build(), { ...deferred, outputs: [...deferred.outputs, ...deferred.outputs] })
  action(39, 'position', build({ outputs: [{ satoshis: 0, lockingScript: LockingScript.fromHex('52') }, ...build().outputs] }), { ...deferred, options: { signAndProcess: false, randomizeOutputs: false } })
  add(40, 'signAction', 'unknown_source', { txid: bare.id('hex'), tx: ordinary.toBinary() }, signed.args)
  action(40, 'deferred_unknown_source', bare, deferred, true)
  const hugeSource = new Transaction(1, [], [{ satoshis: 2100000000000001, lockingScript: LockingScript.fromHex('51') }], 0)
  action(40, 'source_bound', build({ inputs: [{ sourceTransaction: hugeSource, sourceOutputIndex: 0, unlockingScript: UnlockingScript.fromHex('51') }] }), deferred)
  const summedSource = new Transaction(1, [], [0, 1].map(() => ({ satoshis: 2100000000000000, lockingScript: LockingScript.fromHex('51') })), 0)
  action(40, 'input_sum', build({ inputs: [0, 1].map(sourceOutputIndex => ({ sourceTransaction: summedSource, sourceOutputIndex, unlockingScript: UnlockingScript.fromHex('51') })) }), deferred)
  action(41, 'inflation', build({ outputs: [{ satoshis: 1001, lockingScript: LockingScript.fromHex('51') }] }), { ...deferred, outputs: [] })
  action(41, 'output_bound', build({ outputs: [{ satoshis: 2100000000000001, lockingScript: LockingScript.fromHex('51') }] }), { ...deferred, outputs: [] })
  action(41, 'output_sum', build({ outputs: [0, 1].map(() => ({ satoshis: 2100000000000000, lockingScript: LockingScript.fromHex('51') })) }), { ...deferred, outputs: [] })
  for (const [name, spends] of [['index', { 1: { unlockingScript: '51' } }], ['script', { 0: { unlockingScript: '52' } }], ['sequence', { 0: { unlockingScript: '51', sequenceNumber: 1 } }]]) action(42, name, build(), { ...signed.args, spends }, false)
  action(42, 'spend_key_order', build(), { ...signed.args, spends: { 10: { unlockingScript: '51' }, 2: { unlockingScript: '51' } } }, false)
  add(43, 'createAction', 'wrong_change', { ...seeds.get('createAction').result, noSendChange: [point] })
  add(43, 'createAction', 'unassociated_change', { noSendChange: [] }, { description: 'fixture action', options: { sendWith: ['11'.repeat(32)] } })
  variations(44, 'signAction', 'sendWithResults', [[{ txid: signed.result.txid, status: 'sending' }, { txid: signed.result.txid.toUpperCase(), status: 'sending' }], [{ txid: '11'.repeat(32), status: 'sending' }]])
  add(45, 'createAction', 'tx_without_txid', { tx: build().toAtomicBEEF() }, { description: 'fixture action', options: { sendWith: ['11'.repeat(32)] } })
  add(45, 'signAction', 'missing_evidence', { txid: signed.result.txid })
  add(45, 'signAction', 'explicit_txid_only', { txid: signed.result.txid }, { ...signed.args, options: { returnTXIDOnly: true } })
  add(46, 'signAction', 'change_not_allowed', { ...signed.result, noSendChange: [] })
  add(46, 'createAction', 'empty_outcome', {}, { description: 'fixture action', options: { sendWith: ['11'.repeat(32)] } })

  for (const [call, total, entries] of [['listActions', 'totalActions', 'actions'], ['listOutputs', 'totalOutputs', 'outputs'], ['listCertificates', 'totalCertificates', 'certificates'], ['discoverByIdentityKey', 'totalCertificates', 'certificates'], ['discoverByAttributes', 'totalCertificates', 'certificates']]) {
    variations(47, call, total, [-1, null, 1.5, 9007199254740992])
    add(47, call, 'wide_total', edit(call, total, 4294967296), undefined, { residue: 'public u32 total cannot represent the reference safe-integer range' })
    add(47, call, 'integral_total', edit(call, total, 1), undefined, { bodyText: JSON.stringify(edit(call, total, 1)).replace(`"${total}":1`, `"${total}":1.0`) })
    add(49, call, 'total_below_page', edit(call, total, 0))
    const page = clone(seeds.get(call).result)
    page[total] = 11
    page[entries] = Array(11).fill(page[entries][0])
    add(49, call, 'default_limit', page)
    add(49, call, 'explicit_limit', page, { ...seeds.get(call).args, limit: 1 })
  }
  variations(50, 'listActions', 'actions.0.txid', [null, 'a', 'gg'.repeat(32)])
  variations(50, 'listActions', 'actions.0.satoshis', range(-2100000000000000, 2100000000000000))
  variations(50, 'listActions', 'actions.0.status', [null, 'other', 'failed'])
  variations(50, 'listActions', 'actions.0.isOutgoing', [null, 1, false])
  for (const path of ['actions.0.description', 'actions.0.inputs.0.inputDescription', 'actions.0.outputs.0.outputDescription']) historyEdit(51, path, [null, '', 'four', '12345', 'é'.repeat(1000), 'é'.repeat(1001)])
  variations(52, 'listActions', 'actions.0.labels', [[''], ['é'.repeat(151)], ['a']], { labels: ['b'] })
  add(52, 'listActions', 'required_labels', seeds.get('listActions').result, { labels: [], includeLabels: true })
  for (const mode of ['any', 'all']) variations(52, 'listActions', 'actions.0.labels', [['a'], ['a', 'b']], { labels: ['a', 'b'], labelQueryMode: mode })
  for (const field of ['version', 'lockTime']) variations(53, 'listActions', `actions.0.${field}`, range(0, 0xffffffff))
  for (const flag of ['includeInputs', 'includeInputSourceLockingScripts', 'includeInputUnlockingScripts']) add(54, 'listActions', flag, seeds.get('listActions').result, { labels: [], [flag]: true })
  historyEdit(55, 'actions.0.inputs.0.sourceOutpoint', [point.replace('.0', '.01'), null])
  historyEdit(55, 'actions.0.inputs.0.sourceSatoshis', range(0, 2100000000000000))
  for (const field of ['sourceLockingScript', 'unlockingScript']) historyEdit(56, `actions.0.inputs.0.${field}`, [null, 'a', '', '51'])
  for (const flag of ['includeInputSourceLockingScripts', 'includeInputUnlockingScripts']) add(56, 'listActions', flag, history, { labels: [], [flag]: true })
  historyEdit(57, 'actions.0.inputs.0.sequenceNumber', range(0, 0xffffffff))
  for (const flag of ['includeOutputs', 'includeOutputLockingScripts']) add(58, 'listActions', flag, seeds.get('listActions').result, { labels: [], [flag]: true })
  historyEdit(59, 'actions.0.outputs.0.satoshis', range(0, 2100000000000000))
  historyEdit(59, 'actions.0.outputs.0.lockingScript', [null, 'a', ''])
  add(59, 'listActions', 'required_script', history, { labels: [], includeOutputLockingScripts: true })
  historyEdit(60, 'actions.0.outputs.0.spendable', [null, 1, false])
  historyEdit(60, 'actions.0.outputs.0.customInstructions', [null, 1, ''])
  add(61, 'listActions', 'absent_tags', history)
  historyEdit(61, 'actions.0.outputs.0.tags', [[''], ['é'.repeat(151)], ['a']])
  historyEdit(61, 'actions.0.outputs.0.outputIndex', range(0, 0xffffffff))
  historyEdit(61, 'actions.0.outputs.0.basket', [null, '', 'é'.repeat(150), 'é'.repeat(151)])
  variations(62, 'listOutputs', 'BEEF', [[], [1, 2], [...seeds.get('listOutputs').result.BEEF, 0]])
  variations(63, 'listOutputs', 'BEEF', [undefined])
  variations(64, 'listOutputs', 'outputs.0.outpoint', [point.replace('.0', '.01'), point.replace('.0', '.4294967296')])
  const duplicates = clone(seeds.get('listOutputs').result)
  duplicates.totalOutputs = 2; duplicates.outputs.push({ ...duplicates.outputs[0], outpoint: duplicates.outputs[0].outpoint.toUpperCase() })
  add(64, 'listOutputs', 'duplicate', duplicates)
  variations(65, 'listOutputs', 'outputs.0.satoshis', [-1, 1.5, 2100000000000001])
  variations(65, 'listOutputs', 'outputs.0.spendable', [null, 1, false])
  variations(65, 'listOutputs', 'outputs.0.lockingScript', [null, 'a', 'gg'])
  variations(66, 'listOutputs', 'outputs.0.satoshis', [999])
  variations(66, 'listOutputs', 'outputs.0.lockingScript', ['52'])
  variations(66, 'listOutputs', 'outputs.0.outpoint', [point])
  variations(66, 'listOutputs', 'outputs.0.lockingScript', [undefined], { basket: 'default', include: 'locking scripts' })
  for (const field of ['tags', 'labels']) variations(67, 'listOutputs', `outputs.0.${field}`, [[''], ['é'.repeat(151)]])
  variations(67, 'listOutputs', 'outputs.0.customInstructions', [null, 1, ''])
  for (const field of ['tags', 'labels']) variations(68, 'listOutputs', `outputs.0.${field}`, [undefined], { basket: 'default', [field === 'tags' ? 'includeTags' : 'includeLabels']: true })
  for (const mode of ['any', 'all']) variations(68, 'listOutputs', 'outputs.0.tags', [['a'], ['a', 'b'], ['c']], { basket: 'default', tags: ['a', 'b'], tagQueryMode: mode })

  const cert = clone(seeds.get('acquireCertificate').result)
  const unsafeFields = JSON.parse('{"__proto__":"x"}')
  variations(73, 'acquireCertificate', 'fields', [unsafeFields])
  variations(76, 'listCertificates', 'certificates.0.certifier', [key])
  variations(76, 'listCertificates', 'certificates.0.type', [Buffer.alloc(32, 1).toString('base64')])
  variations(76, 'discoverByIdentityKey', 'certificates.0.subject', [other])
  const maps = [{ '': 'AA==' }, { ['é'.repeat(26)]: 'AA==' }, { name: '' }, { name: 'a_' }, { name: 1 }, { name: 'AB==' }]
  variations(77, 'listCertificates', 'certificates.0.keyring', maps)
  const numericKeyring = edit('listCertificates', 'certificates.0.keyring', { 2: '', 10: '' })
  add(77, 'listCertificates', 'numeric_key_order', numericKeyring, undefined, { bodyText: JSON.stringify(numericKeyring).replace('"2":"","10":""', '"10":"","2":""') })
  variations(78, 'listCertificates', 'certificates.0.verifier', badKeys)
  variations(79, 'discoverByIdentityKey', 'certificates.0.certifierInfo.name', [null, '', 'é'.repeat(51)])
  variations(79, 'discoverByIdentityKey', 'certificates.0.certifierInfo.iconUrl', ['', 'file:///x', 'relative', 'https://example.com/' + 'x'.repeat(500), 'https://example.com'])
  variations(79, 'discoverByIdentityKey', 'certificates.0.certifierInfo.description', [null, 'four', '12345', 'x'.repeat(51)])
  variations(79, 'discoverByIdentityKey', 'certificates.0.certifierInfo.trust', range(1, 10))
  variations(80, 'discoverByIdentityKey', 'certificates.0.publiclyRevealedKeyring', maps)
  variations(80, 'discoverByIdentityKey', 'certificates.0.decryptedFields', [{ '': '' }, { name: 1 }])
  const searches = [
    ['john', { name: 'John Smith' }], ['jo', { name: 'John Smith' }], ['j', { name: 'John Smith' }],
    ['smi', { name: 'John Smith' }], ['smith', { name: 'John Smith' }], ['the', { name: 'the' }],
    ['cafe', { name: 'Café' }], ['"john smith"', { name: 'John Smith' }], ['"smith john"', { name: 'John Smith' }],
    ['john -smith', { name: 'John Smith' }], ['john -jones', { name: 'John Smith' }], ['john', { profilePhoto: 'John' }],
    ['john', { icon: 'John' }], ["o'neil", { name: "O'Neil" }], ['JO', { name: 'John' }],
    ['john', { name: 'Johnny' }], ['john smith', { name: 'Other Smith' }], ['john -"other name"', { name: 'John' }],
    ['john', { name: 'John\nSmith' }]
  ]
  searches.forEach(([search, fields], i) => add(81, 'discoverByAttributes', `any_${i}`, edit('discoverByAttributes', 'certificates.0.decryptedFields', fields), { attributes: { any: search } }))
  for (const [i, [attrs, fields]] of [
    [{ name: 'John Smith' }, { name: 'John A Smith' }], [{ name: 'Smith John' }, { name: 'John Smith' }],
    [{ name: 'John Smith' }, { name: 'John\nSmith' }], [{ name: '  \t' }, { name: 'John' }],
    [{ userName: '  John  ' }, { userName: 'John' }], [{ userName: 'john' }, { userName: 'John' }],
    [{ name: 'a+b' }, { name: 'a+b' }], [{ name: 'a.b' }, { name: 'axb' }],
    [{ name: 'John', ignored: '' }, { name: 'John' }]
  ].entries()) add(82, 'discoverByAttributes', `named_${i}`, edit('discoverByAttributes', 'certificates.0.decryptedFields', fields), { attributes: attrs }, { mode: 'result' })
  const orderedAttributes = { attributes: { z: 'Wanted', a: 'Wanted' } }
  add(82, 'discoverByAttributes', 'attribute_order', edit('discoverByAttributes', 'certificates.0.decryptedFields', {}), orderedAttributes, { argsText: JSON.stringify(orderedAttributes) })
  variations(83, 'acquireCertificate', 'type', [Buffer.alloc(32, 1).toString('base64')])
  variations(83, 'acquireCertificate', 'certifier', [key])
  for (const [field, value] of Object.entries({ serialNumber: Buffer.alloc(32, 1).toString('base64'), subject: other, signature: '3006020102020102', revocationOutpoint: '33'.repeat(32) + '.2', fields: { other: 'eA==' } })) {
    const result = { keyringForVerifier: { name: 'a2V5cmluZw==' }, certificate: { ...cert, [field]: value } }
    add(84, 'proveCertificate', field, result)
  }
  add(84, 'acquireCertificate', 'issuance_values_may_change', { ...cert, fields: { name: 'eA==' } })
  add(84, 'acquireCertificate', 'direct_values_must_match', { ...cert, fields: { name: 'eA==' } }, { ...seeds.get('acquireCertificate').args, acquisitionProtocol: 'direct', ...cert, keyringRevealer: 'certifier', keyringForSubject: { name: 'a2V5' } })
  variations(85, 'proveCertificate', 'keyringForVerifier', maps.slice(0, -1))
  variations(86, 'proveCertificate', 'keyringForVerifier', [{}, { extra: 'AA==' }, { name: 'AA==', extra: 'AA==' }])
  add(86, 'proveCertificate', 'deduplicated_fields', { keyringForVerifier: { name: 'AA==' } }, { ...seeds.get('proveCertificate').args, fieldsToReveal: ['name', 'name'] }, { mode: 'result' })
  variations(87, 'proveCertificate', 'verifier', [...badKeys, other])
  for (const unsafe of ['__proto__', 'constructor', 'prototype']) add(88, 'discoverByAttributes', unsafe, seeds.get('discoverByAttributes').result, { attributes: JSON.parse(`{"${unsafe}":"x"}`) }, { mode: 'snapshot' })
}

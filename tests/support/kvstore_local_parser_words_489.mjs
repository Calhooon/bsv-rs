// #489: actual local authentication failures at ts-stack@edf6e03, Node 22;
// #499 adds the lock-after tokens.
// Mutate the wallet key or an SDK-written token; serialize with the SDK only.
export async function recordLocalParserWords489 (c) {
  const { recording, fresh, record, stop, sourceOf, LocalKVStore, Script,
    PublicKey, PushDrop, Utils } = c
  const gx = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  const gy = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
  const hybrid = '06' + gx + gy
  const reducedX = '02' + ((1n << 256n) - (1n << 32n) - 977n + 1n).toString(16)
  const definitions = [
    { name: 'key_non_hex', kind: 'invalid_hex', publicKey: 'zz' },
    { name: 'key_non_hex_odd', kind: 'invalid_hex', publicKey: 'not-hex' },
    { name: 'key_wrong_length', kind: 'unknown_point', publicKey: '02' },
    { name: 'key_wrong_prefix', kind: 'unknown_point', publicKey: '05' + '00'.repeat(32) },
    { name: 'key_empty', kind: 'unknown_point', publicKey: '' },
    { name: 'key_odd_hex', kind: 'unknown_point', publicKey: '2' },
    { name: 'key_off_curve', kind: 'invalid_point', publicKey: '02' + '00'.repeat(32) },
    { name: 'key_uncompressed_off_curve', kind: 'invalid_point', publicKey: '04' + '00'.repeat(64) },
    { name: 'key_hybrid_odd_y', kind: 'hybrid_length', publicKey: '06' + '00'.repeat(63) + '01' },
    { name: 'key_hybrid_even_y', kind: 'hybrid_length', publicKey: '07' + '00'.repeat(64) },
    { name: 'token_hybrid_even_y', kind: 'hybrid_length', keyBytes: [7, ...new Array(64).fill(0)] },
    { name: 'token_off_curve', kind: 'invalid_point', keyBytes: [2, ...new Array(32).fill(0)] },
    { name: 'token_wrong_length', kind: 'unknown_point', keyBytes: [2] },
    { name: 'token_wrong_prefix', kind: 'unknown_point', keyBytes: [5, ...new Array(32).fill(0)] },
    { name: 'token_not_pushdrop', kind: 'token', asm: 'OP_TRUE' },
    { name: 'token_empty', kind: 'token', empty: true },
    { name: 'token_no_checksig', kind: 'token', noChecksig: true },
    { name: 'token_key_only', kind: 'token', keyOnly: true },
    { name: 'key_odd_valid', kind: 'key_odd_valid', publicKey: '2' + gx, divergence: true },
    { name: 'key_hybrid_valid', kind: 'key_hybrid_valid', publicKey: hybrid, divergence: true },
    { name: 'key_odd_hybrid_valid', kind: 'key_odd_hybrid_valid', publicKey: hybrid.slice(1), divergence: true },
    { name: 'key_reduced_x', kind: 'key_reduced_x', publicKey: reducedX, divergence: true },
    { name: 'token_hybrid_valid', kind: 'token_hybrid_valid', keyBytes: Utils.toArray(hybrid, 'hex'), divergence: true },
    { name: 'token_reduced_x', kind: 'token_reduced_x', keyBytes: Utils.toArray(reducedX, 'hex'), divergence: true },
    // #499: the local decode is lock-before alone (PushDropValidation.ts:59,
    // PushDrop.ts:74-75), so a lock-after token meets the first-chunk read.
    { name: 'token_lock_after_one_field', kind: 'token_lock_after',
      asm: `OP_1 OP_DROP 02${gx} OP_CHECKSIG` },
    { name: 'token_lock_after_two_fields', kind: 'token_lock_after',
      asm: `OP_1 OP_2 OP_2DROP 02${gx} OP_CHECKSIG` },
    { name: 'token_lock_after_op0_one_field', kind: 'token_lock_after',
      asm: `OP_0 OP_DROP 02${gx} OP_CHECKSIG` },
    { name: 'token_lock_after_data_one_field', kind: 'token_lock_after',
      asm: `07 OP_DROP 02${gx} OP_CHECKSIG` },
    { name: 'token_lock_after_data_two_fields', kind: 'token_lock_after',
      asm: `0708 09 OP_2DROP 02${gx} OP_CHECKSIG` },
    { name: 'token_lock_after_uncompressed', kind: 'token_lock_after',
      asm: `OP_1 OP_2 OP_2DROP 04${gx}${gy} OP_CHECKSIG` }
  ]
  const cases = []
  for (const definition of definitions) {
    for (const operation of ['get', 'set']) {
      c.resetCounter()
      const state = fresh()
      const wallet = recording(state)
      const store = new LocalKVStore(wallet, 'kvstore', false)
      const seed = record(state, await stop(() => store.set('alpha', 'one')))
      let script = Script.fromHex(seed.create_action_outputs[0].lockingScript)
      if (definition.asm !== undefined) script = Script.fromASM(definition.asm)
      if (definition.empty) script = new Script()
      if (definition.keyBytes !== undefined) {
        script = new Script([{ op: definition.keyBytes.length, data: definition.keyBytes },
          ...script.chunks.slice(1)])
      }
      if (definition.noChecksig) {
        script = new Script([script.chunks[0], { op: 0x51 }, ...script.chunks.slice(2)])
      }
      if (definition.keyOnly) script = new Script([script.chunks[0]])
      const source = sourceOf([{ satoshis: 1, lockingScript: script.toHex() }])
      script = source.outputs[0].lockingScript
      state.listed = { totalOutputs: 1, BEEF: source.toBEEF(),
        outputs: [{ outpoint: `${source.id('hex')}.0`, satoshis: 1, spendable: true,
          lockingScript: script.toHex(), tags: ['alpha'] }] }
      let parserError = null
      try {
        if (definition.publicKey !== undefined) PublicKey.fromString(definition.publicKey)
        else PushDrop.decode(script)
      } catch (error) { parserError = error.message }
      if (definition.publicKey !== undefined) {
        // Only the authentication request is corrupt; set's replacement-token
        // derivation still succeeds, so this reaches the lookup catch.
        const getPublicKey = wallet.getPublicKey
        wallet.getPublicKey = async args => args.forSelf === undefined
          ? { publicKey: definition.publicKey } : getPublicKey(args)
      }
      cases.push({ name: definition.name, kind: definition.kind, operation,
        public_key: definition.publicKey ?? null,
        locking_script: script.toHex(), source_beef: Utils.toHex(source.toBEEF()),
        parser_error: parserError,
        ...(definition.divergence ? { parser_accepted: parserError === null } : {}),
        error: await stop(() => operation === 'get'
          ? store.get('alpha') : store.set('alpha', 'two')) })
    }
  }
  return cases
}

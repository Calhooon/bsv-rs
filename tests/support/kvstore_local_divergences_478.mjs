// #478: run the pinned reference's token search verbatim on SDK-written BEEF.
// The boundary normally binds the one-satoshi output at index zero. Isolate
// its subsequent search so zero/multiple matches and a nonzero index are
// recorded independently of the boundary's earlier refusal rules.
import { readFile } from 'node:fs/promises'

export async function recordTokenSearch478 (c) {
  if (c.localSource == null || !c.localSource.endsWith('/LocalKVStore.ts')) {
    throw new Error('--kvstore-local-454 requires --local-source <archived LocalKVStore.ts>')
  }
  const source = await readFile(c.localSource, 'utf8')
  const start = source.indexOf('        const indexes = transaction.outputs.flatMap(')
  const catchStart = source.indexOf('      } catch (error) {', start)
  const catchEnd = source.indexOf('\n      }\n    } finally', catchStart)
  if (start < 0 || catchStart < 0 || catchEnd < 0) throw new Error('reference token search not found')
  const search = new Function('transaction', 'lockingScript',
    source.slice(start, catchStart).replace(' as OutpointString', ''))
  const wrap = new Function('error', 'current', 'key',
    source.slice(catchStart + '      } catch (error) {'.length, catchEnd))
  const wallet = c.recording(c.fresh())
  const lockingScript = await new c.PushDrop(wallet).lock(
    [c.Utils.toArray('two', 'utf8')], [2, 'kvstore'], 'alpha', 'self')
  const cases = []
  for (const [name, matches] of [['nonzero', 1], ['none', 0], ['two', 2]]) {
    // A two-satoshi requested output exercises the Rust amount option; only
    // subsequent one-satoshi outputs can satisfy the reference's search.
    const outputs = [
      { satoshis: 2, lockingScript: lockingScript.toHex() },
      ...Array.from({ length: matches }, () => ({ satoshis: 1, lockingScript: lockingScript.toHex() })),
      { satoshis: 1, lockingScript: '51' }
    ]
    const funding = c.sourceOf([{ satoshis: 10, lockingScript: '51' }])
    const tx = new c.Transaction()
    tx.addInput({ sourceTransaction: funding, sourceOutputIndex: 0,
      unlockingScript: new c.Script(), sequence: 0xffffffff })
    for (const output of outputs) {
      tx.addOutput({ satoshis: output.satoshis, lockingScript: c.Script.fromHex(output.lockingScript) })
    }
    let outpoint = null
    let error = null
    try {
      outpoint = search(tx, lockingScript)
    } catch (cause) {
      try { wrap(cause, { authenticated: [] }, 'alpha') } catch (wrapped) { error = wrapped.message }
    }
    cases.push({ name, transaction: c.Utils.toHex(tx.toAtomicBEEF()),
      locking_script: lockingScript.toHex(), outpoint, error })
  }
  return { site: 'LocalKVStore.ts:538-551 (verbatim search and error wrapper)', cases }
}

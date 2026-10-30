// Apply the Rust fixture recorder's changed byte strings while retaining
// existing JSON property order. Usage: node fixtures_order_400.mjs OLD NEW OUT
// OUT defaults to OLD; NEW is a BSV_FIXTURES_RECORD=1 scratch recording.
import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert/strict'

const [oldRoot, newRoot, outputRoot = oldRoot] = process.argv.slice(2)
const changes = []
const writes = []
function merge (old, fresh, pointer) {
  if (Array.isArray(old)) {
    assert.equal(fresh.length, old.length, pointer)
    return old.map((value, index) => merge(value, fresh[index], `${pointer}/${index}`))
  }
  if (old !== null && typeof old === 'object') {
    assert.deepEqual(Object.keys(old).sort(), Object.keys(fresh).sort(), pointer)
    return Object.fromEntries(Object.entries(old).map(([key, value]) =>
      [key, merge(value, fresh[key], `${pointer}/${key}`)]))
  }
  if (!Object.is(old, fresh)) {
    assert.equal(typeof old, 'string', pointer)
    assert.equal(typeof fresh, 'string', pointer)
    if (!pointer.endsWith('_hex')) {
      // This fixture echoes its JSON error body in Display and Debug. Only
      // that body's property order may move; diagnostic words stay fixed.
      assert.match(pointer, /^http_json\/errors\.json\/cases\/7\/expected\/client_result\/(display|error)$/)
      const split = text => [text.slice(0, text.indexOf('{')),
        JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1).replaceAll('\\"', '"')),
        text.slice(text.lastIndexOf('}') + 1)]
      assert.deepEqual(split(old), split(fresh), pointer)
    }
    changes.push(pointer)
  }
  return fresh
}
function walk (relative = '') {
  for (const entry of fs.readdirSync(path.join(oldRoot, relative), { withFileTypes: true })) {
    const name = path.join(relative, entry.name)
    if (entry.isDirectory()) { walk(name); continue }
    if (!name.endsWith('.json')) continue
    const before = changes.length
    const old = JSON.parse(fs.readFileSync(path.join(oldRoot, name), 'utf8'))
    const fresh = JSON.parse(fs.readFileSync(path.join(newRoot, name), 'utf8'))
    const updated = merge(old, fresh, name)
    if (changes.length !== before) {
      writes.push([path.join(outputRoot, name), JSON.stringify(updated, null, 2) + '\n'])
    }
  }
}
walk()
for (const [name, text] of writes) fs.writeFileSync(name, text)
process.stdout.write(JSON.stringify(changes, null, 2) + '\n')

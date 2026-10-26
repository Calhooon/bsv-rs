// The pair check of `src/wallet/collation.rs` (#249).
//
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_collation_pairs_249.mjs \
//     src/wallet/collation_latin1.txt \
//     tests/vectors/auth_certificate_field_order_249.json
//
// Builds the sort key `collation.rs` builds from the same table (every
// primary weight, then every secondary, then every tertiary; the `l` and `L`
// before U+00B7 contractions) and compares each pair of names by it and by
// this Node's `a.localeCompare(b)`, the reference's comparison
// (`ts-stack@edf6e03` `Certificate.ts:282`), the sign of each; equal keys
// are 0 here (the byte fallback of `collation.rs` decides only what
// `localeCompare` calls equal). The pairs, every one ordered (a, b):
//   - the 256 one-character names U+0000..U+00FF, with each other;
//   - the 1,402 names of the vector's `collation_corpus`, with each other;
//   - the 65,536 two-character names over U+0000..U+00FF, each with the 256
//     one-character names.
// It prints the Node, ICU, CLDR and Unicode versions, the count of pairs and
// the disagreements (at most 20 shown), and exits 1 on any.
//
// Recorded 2026-10-26 at the tree of #249's fold, the same under Node
// v22.18.0, v20.19.5 and v24.11.1 (each ICU 77.1, CLDR 47.0, Unicode 16.0):
//   pairs 18,808,356, disagreements 0
import fs from 'fs'

const [tablePath, vectorPath] = process.argv.slice(2)

const rows = []
const contraction = {}
for (const line of fs.readFileSync(tablePath, 'utf8').split('\n')) {
  if (line === '' || line.startsWith('#')) continue
  const parts = line.split(' ')
  const elements = (xs) => xs.map((e) => e.split('.').map(Number))
  if (parts[1].includes('.')) rows[parseInt(parts[0], 16)] = elements(parts.slice(1))
  else contraction[String.fromCharCode(parseInt(parts[0], 16))] = elements(parts.slice(2))
}
if (rows.length !== 256 || Object.keys(contraction).length !== 2) throw new Error('table shape')

const key = (name) => {
  const levels = [[], [], []]
  const cs = [...name]
  for (let i = 0; i < cs.length; i++) {
    let es
    if ((cs[i] === 'l' || cs[i] === 'L') && cs[i + 1] === '·') {
      es = contraction[cs[i]]
      i++
    } else {
      es = rows[cs[i].codePointAt(0)]
      if (es === undefined) throw new Error(`past the table: ${JSON.stringify(name)}`)
    }
    for (const e of es) e.forEach((w, l) => w && levels[l].push(w))
  }
  return levels
}
const cmpList = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1
  return Math.sign(a.length - b.length)
}
const cmpKey = (a, b) => cmpList(a[0], b[0]) || cmpList(a[1], b[1]) || cmpList(a[2], b[2])

const singles = Array.from({ length: 256 }, (_, c) => String.fromCharCode(c))
const corpus = JSON.parse(fs.readFileSync(vectorPath, 'utf8')).collation_corpus
const doubles = singles.flatMap((a) => singles.map((b) => a + b))

let pairs = 0
const bad = []
const check = (as, bs) => {
  const ka = as.map(key)
  const kb = bs.map(key)
  for (let i = 0; i < as.length; i++) {
    for (let j = 0; j < bs.length; j++) {
      pairs++
      const want = Math.sign(as[i].localeCompare(bs[j]))
      const got = cmpKey(ka[i], kb[j])
      if (want !== got) bad.push([as[i], bs[j], want, got])
    }
  }
}
check(singles, singles)
check(corpus, corpus)
check(doubles, singles)

const v = process.versions
console.log(`node ${process.version}, ICU ${v.icu}, CLDR ${v.cldr}, Unicode ${v.unicode}`)
console.log(`pairs ${pairs.toLocaleString('en-US')}, disagreements ${bad.length}`)
for (const [a, b, want, got] of bad.slice(0, 20)) {
  console.log(`  ${JSON.stringify(a)} vs ${JSON.stringify(b)}: localeCompare ${want}, table ${got}`)
}
process.exit(bad.length ? 1 : 0)

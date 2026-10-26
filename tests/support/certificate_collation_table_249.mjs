// The collation table of `src/wallet/collation.rs` (#249).
//
//   node tests/support/certificate_collation_table_249.mjs \
//     /System/Library/Perl/5.34/Unicode/Collate/allkeys.txt \
//     > src/wallet/collation_latin1.txt
//
// Reads the DUCET (`allkeys.txt`, 13.0.0 in the system Perl's
// Unicode::Collate) for U+0000..U+00FF and the two contractions inside that
// range (`l` and `L` before U+00B7), ranks each level's nonzero weights
// densely from 1 (only their order matters to a comparison) and writes one
// line per code point, `00B7 18.1.1` (the code point, then each collation
// element as primary.secondary.tertiary), then the two contraction lines,
// `006C 00B7 85.1.1 0.10.1`. The header names the DUCET version and the
// Node, ICU, CLDR and Unicode versions of the run; the rows are checked
// against that Node's `localeCompare` by
// `tests/auth_certificate_field_order_249.rs` on the corpus
// `certificate_field_order_249.mjs` writes, and pair by pair by
// `certificate_collation_pairs_249.mjs`.
import fs from 'fs'

const [allkeys] = process.argv.slice(2)
const lines = fs.readFileSync(allkeys, 'utf8').split('\n')
const version = lines.find((l) => l.startsWith('@version')).slice('@version '.length)
const ce = (s) =>
  [...s.matchAll(/\[[.*]([0-9A-F]{4})\.([0-9A-F]{4})\.([0-9A-F]{4})\]/g)].map((x) =>
    x.slice(1, 4).map((w) => parseInt(w, 16))
  )

const single = {}
const contraction = {}
for (const l of lines) {
  let m = /^([0-9A-F]{4})\s*;\s*((?:\[[.*][0-9A-F.]+\])+)/.exec(l)
  if (m && parseInt(m[1], 16) <= 0xff) single[parseInt(m[1], 16)] = ce(m[2])
  m = /^(00[0-9A-F]{2}) (00[0-9A-F]{2})\s*;\s*((?:\[[.*][0-9A-F.]+\])+)/.exec(l)
  if (m) contraction[`${m[1]} ${m[2]}`] = ce(m[3])
}
const all = [...Object.values(single), ...Object.values(contraction)].flat()
const rank = (i) => {
  const ws = [...new Set(all.map((e) => e[i]).filter((w) => w))].sort((a, b) => a - b)
  return new Map(ws.map((w, k) => [w, k + 1]))
}
const R = [rank(0), rank(1), rank(2)]
const row = (es) => es.map((e) => e.map((w, i) => (w ? R[i].get(w) : 0)).join('.')).join(' ')

const v = process.versions
console.log(`# The collation table of src/wallet/collation.rs (#249), written by`)
console.log(`# tests/support/certificate_collation_table_249.mjs from the DUCET ${version}`)
console.log(`# (allkeys.txt), under Node ${process.version} (ICU ${v.icu}, CLDR ${v.cldr}, Unicode`)
console.log(`# ${v.unicode}), whose localeCompare the rows are checked against. Weights ranked`)
console.log(`# densely per level: primaries ${R[0].size}, secondaries ${R[1].size}, tertiaries ${R[2].size}.`)
console.log(`# A line: the code point, then each collation element as primary.secondary.tertiary.`)
for (let c = 0; c <= 0xff; c++) {
  console.log(`${c.toString(16).toUpperCase().padStart(4, '0')} ${row(single[c])}`)
}
for (const k of Object.keys(contraction).sort().reverse()) console.log(`${k} ${row(contraction[k])}`)

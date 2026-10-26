// The collation table of `src/auth/certificates/collation.rs` (#249).
//
//   node tests/support/certificate_collation_table_249.mjs \
//     /System/Library/Perl/5.34/Unicode/Collate/allkeys.txt
//
// Reads the DUCET (`allkeys.txt`, 13.0.0 in the system Perl's
// Unicode::Collate) for U+0000..U+00FF and the two contractions inside that
// range (`l` and `L` before U+00B7), ranks each level's nonzero weights
// densely from 1 (only their order matters to a comparison) and prints the
// table's rows, each led by its code point. The rows are checked against Node's `localeCompare` (ICU
// root under the default locale) by `tests/auth_certificate_field_order_249.rs`
// on the corpus `certificate_field_order_249.mjs` writes.
import fs from 'fs'

const [allkeys] = process.argv.slice(2)
const lines = fs.readFileSync(allkeys, 'utf8').split('\n')
const version = lines.find((l) => l.startsWith('@version'))
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
const row = (es) => '&[' + es.map((e) => `(${e.map((w, i) => (w ? R[i].get(w) : 0)).join(', ')})`).join(', ') + ']'

console.log(`// ${version}; primaries ${R[0].size}, secondaries ${R[1].size}, tertiaries ${R[2].size}`)
for (let c = 0; c <= 0xff; c++) {
  const name = c < 0x20 || (c >= 0x7f && c < 0xa0) ? 'control' : JSON.stringify(String.fromCharCode(c))
  const hex = c.toString(16).toUpperCase().padStart(2, '0')
  console.log(`    (0x${hex}, ${row(single[c])}), // ${name}`)
}
for (const [k, es] of Object.entries(contraction)) console.log(`contraction ${k} ${row(es)}`)

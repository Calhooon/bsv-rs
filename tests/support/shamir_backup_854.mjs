// #854's recorder: what the reference's Shamir backup writes and reads
// (`ts-stack@edf6e03` `packages/sdk/src/primitives/PrivateKey.ts`:
// `KeyShares.fromBackupFormat` `:55-102`, `toBackupFormat` `:104-118`,
// `toKeyShares` `:478-538`, `fromKeyShares` `:575-623`; `Polynomial.ts`
// `PointInFiniteField.fromString` `:32-49`), BRC-140 at BRCs@f7f1520.
//
// Three fixed keys (1, n - 1, sha256 of a label) at 2 of 3 and 3 of 5: the
// reference's shares are random, so the shares themselves are recorded, with
// the key the reference recovers from every threshold-sized subset. Then the
// reader's refusals, one cell per row, with the thrown words. Then this
// crate's shares (written by `split_private_key_with` with fixed draws, the
// file `tests/shamir_backup_854.rs`'s ignored recorder writes) as the
// reference reads them. Only the unmodified SDK answers. Build the bundle at
// the pin and run under Node 22.18.0:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   SHAMIR_854_OUT="$W/rust_written.json" cargo test --test shamir_backup_854 -- --ignored records_this_crates_shares
//   node tests/support/shamir_backup_854.mjs "$W/sdk.mjs" "$W/rust_written.json" tests/vectors/shamir_backup_854.json
//
// The fold's mode (#854's fold) adds the deterministic cells to a recorded
// vector without re-rolling the reference's random shares: every member
// already there is kept as read and `fold_854` and `fold2_854` (#854's second
// fold) are written before `rust_written`, so the diff is additions alone:
//   node tests/support/shamir_backup_854.mjs --fold "$W/sdk.mjs" tests/vectors/shamir_backup_854.json
//
// `fold_854.coordinates` is the reference's `toKeyShares` (`PrivateKey.ts:478-538`)
// drawing from fixed bytes. The one thing stubbed is the platform's random
// source: `globalThis.crypto.getRandomValues`, which the bundle's `Random`
// (`Random.ts`, `Rand.getRandomValues`) reads on every call, is replaced by a
// queue of the fixed bytes for the duration of the split and restored after.
// `Random`, `Polynomial.fromPrivateKey`, `toKeyShares` and `toBackupFormat`
// run as shipped. The queue is the reference's draws in its order: per
// random point of `fromPrivateKey` (`Polynomial.ts`) its x then its y (32
// bytes each), the 64-byte seed, then 32 bytes per coordinate attempt. The
// reference's polynomial is the one through (0, key) and those points; its
// coefficients a_1..a_{t-1} (what `split_private_key_with` takes) are
// computed here by Lagrange over F_p, the recorder's own arithmetic, and
// checked against the reference's shares before they are written.
import { readFileSync, writeFileSync } from 'node:fs'

const FOLD = process.argv[2] === '--fold'
const [bundle, rustWritten, out] = FOLD
  ? [process.argv[3], null, process.argv[4]]
  : process.argv.slice(2, 5)
const { PrivateKey, KeyShares, BigNumber, Utils, Hash, PointInFiniteField } = await import(bundle)

const N_MINUS_1 = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'
const P_HEX = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'
const LABEL = 'bsv-rs #854 shamir vector'
const KEYS = {
  one: '0000000000000000000000000000000000000000000000000000000000000001',
  n_minus_1: N_MINUS_1,
  sha_label: Utils.toHex(Hash.sha256(Utils.toArray(LABEL, 'utf8')))
}
const SPLITS = [[2, 3], [3, 5]]

const answer = (f) => {
  try {
    return { ok: true, scalar_hex: f().toHex() }
  } catch (e) {
    return { ok: false, error: String(e && e.message) }
  }
}
const recover = (shares) => answer(() => PrivateKey.fromBackupShares(shares))
// #854's fold: the deterministic cells (`fold_854`).
const P_BN = new BigNumber(P_HEX, 16)
const N_BN = new BigNumber(N_MINUS_1, 16).addn(1)
const TAG_ONE = '751e76e8' // key one's BRC-140 tag
const hex32 = (bn) => bn.toString(16).padStart(64, '0')
const pointOf = ([x, y]) => new PointInFiniteField(new BigNumber(x, 16), new BigNumber(y, 16))
const keySharesAnswer = (points, threshold, integrity) =>
  answer(() => PrivateKey.fromKeyShares(new KeyShares(points, threshold, integrity)))

// Shares whose secret is read from f(0): each through `fromBackupShares` (the
// texts the reference's writer gives the points) and `fromKeyShares`.
const secretCell = (name, points, threshold, integrity) => {
  const shares = points.map((p) => `${pointOf(p).toString()}.${threshold}.${integrity}`)
  return {
    name,
    points: points.map(([x, y]) => ({ x, y })),
    threshold,
    integrity,
    shares,
    backup: recover(shares),
    key_shares: keySharesAnswer(points.map(pointOf), threshold, integrity)
  }
}
const n = hex32(N_BN)
const nPlus = (k) => hex32(N_BN.addn(k))
const small = (k) => hex32(new BigNumber(k))
// f(0) = 0: the zero line, y = x, and y = n at two x (f(0) = n, 0 mod n).
const zero_secret = [
  secretCell('zero_line', [[small(1), small(0)], [small(2), small(0)]], 2, TAG_ONE),
  secretCell('line_y_equals_x', [[small(1), small(1)], [small(2), small(2)]], 2, TAG_ONE),
  secretCell('constant_n', [[small(1), n], [small(2), n]], 2, TAG_ONE),
  secretCell('zero_line_three_of_three', [[small(3), small(0)], [small(5), small(0)], [small(9), small(0)]], 3, TAG_ONE)
]
// f(0) in [n, p): read modulo n (`new PrivateKey(..)`, modN 'apply').
const reduction = [
  secretCell('constant_n_plus_1', [[small(1), nPlus(1)], [small(2), nPlus(1)]], 2, TAG_ONE),
  secretCell('line_to_n_plus_1', [[small(1), nPlus(2)], [small(2), nPlus(3)]], 2, TAG_ONE)
]

// `fromKeyShares` on hand-built collections the fold adds.
const withY = (points, i, y) => {
  points[i].y = y
  return points
}
const fold_key_shares = {
  y_at_p: keySharesAnswer(withY([pointOf([small(1), small(1)]), pointOf([small(2), small(2)])], 0, P_BN.clone()), 2, TAG_ONE),
  y_at_p_in_share_1: keySharesAnswer(withY([pointOf([small(1), small(1)]), pointOf([small(2), small(2)])], 1, P_BN.clone()), 2, TAG_ONE),
  y_at_p_past_the_threshold: keySharesAnswer(
    withY([pointOf([small(1), small(1)]), pointOf([small(2), small(1)]), pointOf([small(3), small(1)])], 2, P_BN.clone()),
    2,
    TAG_ONE
  ),
  points_256: keySharesAnswer(
    Array.from({ length: 256 }, (_, i) => pointOf([small(i + 1), small(1)])),
    2,
    TAG_ONE
  ),
  points_255: keySharesAnswer(
    Array.from({ length: 255 }, (_, i) => pointOf([small(i + 1), small(1)])),
    2,
    TAG_ONE
  )
}

// The reference's split from fixed bytes (the header's seam).
const fill = (b, len) => Array(len).fill(b)
const withDraws = (queue, f) => {
  const crypto = globalThis.crypto
  const original = crypto.getRandomValues
  let calls = 0
  crypto.getRandomValues = (arr) => {
    const next = queue.shift()
    if (next === undefined || next.length !== arr.length) {
      throw new Error(`the stub's queue does not hold ${arr.length} bytes at call ${calls}`)
    }
    arr.set(next)
    calls++
    return arr
  }
  try {
    const result = f()
    if (queue.length !== 0) throw new Error('the stub queue was not drained')
    return { result, calls }
  } finally {
    crypto.getRandomValues = original
  }
}
// The monomial coefficients of the polynomial through `points` over F_p.
const coefficientsThrough = (points) => {
  let total = points.map(() => new BigNumber(0))
  points.forEach(([xj, yj], j) => {
    let basis = [new BigNumber(1)]
    let denom = new BigNumber(1)
    points.forEach(([xm], m) => {
      if (m === j) return
      const next = basis.map(() => new BigNumber(0)).concat([new BigNumber(0)])
      basis.forEach((c, d) => {
        next[d + 1] = next[d + 1].add(c).umod(P_BN)
        next[d] = next[d].sub(c.mul(xm)).umod(P_BN)
      })
      basis = next
      denom = denom.mul(xj.sub(xm)).umod(P_BN)
    })
    const scale = yj.mul(denom.invm(P_BN)).umod(P_BN)
    total = total.map((t, d) => t.add(basis[d].mul(scale)).umod(P_BN))
  })
  return total
}
const evaluate = (coeffs, x) => coeffs.reduceRight((acc, c) => acc.mul(x).add(c).umod(P_BN), new BigNumber(0))
// The bytes of a case: `fill`'s repeated byte (the fold's four), or since
// #854's second fold counting bytes, so a reversal inside the seed or a draw
// changes the shares (`count(start, len)`: start, start + 1, ... mod 256).
const count = (start, len) => Array.from({ length: len }, (_, j) => (start + j) & 0xff)
const REPEATED = {
  point: (i) => [fill(0x30 + i, 32), fill(0x40 + i, 32)],
  seed: () => fill(0x5e, 64),
  draw: (i) => fill(0xa0 + i, 32)
}
const COUNTING = {
  point: (i) => [count(0x40 + 64 * i, 32), count(0x60 + 64 * i, 32)],
  seed: () => count(0, 64),
  draw: (i) => count(0x80 + 32 * i, 32)
}
const coordinateCase = (keyName, threshold, total, bytes = REPEATED) => {
  const keyHex = KEYS[keyName]
  const randomPoints = Array.from({ length: threshold - 1 }, (_, i) => bytes.point(i))
  const seed = bytes.seed()
  const draws = Array.from({ length: total }, (_, i) => bytes.draw(i))
  const queue = [...randomPoints.flat(), seed, ...draws].map((b) => Uint8Array.from(b))
  const { result: shares, calls } = withDraws(queue, () => PrivateKey.fromHex(keyHex).toBackupShares(threshold, total))
  const through = [[new BigNumber(0), new BigNumber(keyHex, 16)], ...randomPoints.map(([x, y]) => [new BigNumber(x), new BigNumber(y)])]
  const coeffs = coefficientsThrough(through)
  for (const share of shares) {
    const [x, y] = share.split('.').slice(0, 2).map((f) => new BigNumber(Utils.fromBase58(f)))
    if (!evaluate(coeffs, x).eq(y)) throw new Error('the derived coefficients miss a reference share')
  }
  if (!coeffs[0].eq(new BigNumber(keyHex, 16))) throw new Error('the constant term is not the key')
  return {
    key: keyName,
    scalar_hex: keyHex,
    threshold,
    total,
    random_points: randomPoints.map(([x, y]) => ({ x: Utils.toHex(x), y: Utils.toHex(y) })),
    seed: Utils.toHex(seed),
    draws: draws.map((d) => Utils.toHex(d)),
    random_calls: calls,
    coefficients: coeffs.slice(1).map(hex32),
    shares
  }
}

// Reader cells on the count, from the vector's key-one 2 of 3 split.
const foldReads = (doc) => {
  const [s0, s1] = doc.splits.find((x) => x.key === 'one' && x.threshold === 2).shares
  const cells = {
    shares_255_leading_distinct: [s0, s1, ...Array(253).fill(s0)],
    shares_300_malformed_at_256: [s0, s1, ...Array(254).fill(s0), 'malformed', ...Array(43).fill(s0)]
  }
  return Object.entries(cells).map(([name, shares]) => ({
    name,
    shares,
    parse: (() => {
      try {
        KeyShares.fromBackupFormat(shares)
        return { ok: true }
      } catch (e) {
        return { ok: false, error: String(e && e.message) }
      }
    })(),
    answer: recover(shares)
  }))
}

const foldCells = (doc) => ({
  note: "#854's fold: the deterministic cells, recorded by the --fold mode",
  zero_secret,
  reduction,
  key_shares: fold_key_shares,
  reads: foldReads(doc),
  coordinates: [
    coordinateCase('sha_label', 2, 3),
    coordinateCase('sha_label', 3, 5),
    coordinateCase('one', 3, 5),
    coordinateCase('one', 2, 2)
  ]
})

// #854's second fold (the strength re-read of PR #876): one coordinates case
// whose seed is the bytes 0 to 63 and whose draws and random points count,
// a member of its own so every member before it stays byte for byte.
const fold2Cells = () => ({
  note: "#854's second fold: a coordinates case of counting bytes, recorded by the --fold mode",
  coordinates: [coordinateCase('sha_label', 3, 5, COUNTING)]
})

// The vector with `fold_854` and `fold2_854` placed before `rust_written`,
// every other member as given.
const withFold = (doc) => {
  const outDoc = {}
  for (const [k, v] of Object.entries(doc)) {
    if (k === 'fold_854' || k === 'fold2_854') continue
    if (k === 'rust_written') {
      outDoc.fold_854 = foldCells(doc)
      outDoc.fold2_854 = fold2Cells()
    }
    outDoc[k] = v
  }
  return outDoc
}

if (FOLD) {
  const doc = JSON.parse(readFileSync(out, 'utf8'))
  writeFileSync(out, JSON.stringify(withFold(doc), null, 2) + '\n')
} else {
  const subsets = (n, k) => {
    const all = []
    const walk = (start, picked) => {
      if (picked.length === k) return all.push(picked.slice())
      for (let i = start; i < n; i++) walk(i + 1, [...picked, i])
    }
    walk(0, [])
    return all
  }

  // The reference's splits, each recovered from every threshold-sized subset
  // (in index order and reversed) and from every share.
  const splits = []
  for (const [name, hex] of Object.entries(KEYS)) {
    const key = PrivateKey.fromHex(hex)
    for (const [t, n] of SPLITS) {
      const shares = key.toBackupShares(t, n)
      const recoveries = subsets(n, t).map((indices) => ({
        indices,
        answer: recover(indices.map((i) => shares[i])),
        reversed: recover(indices.slice().reverse().map((i) => shares[i]))
      }))
      splits.push({
        key: name,
        scalar_hex: hex,
        threshold: t,
        total: n,
        integrity: key.toPublicKey().toHash('hex').slice(0, 8),
        shares,
        recoveries,
        all: recover(shares)
      })
    }
  }

  // The reader's cells, from key one's 2 of 3 (its tag `751e76e8` carries
  // letters) and a second split of it; each cell the shares given and the
  // reference's answer.
  const base = splits.find((s) => s.key === 'one' && s.threshold === 2)
  const [s0, s1, s2] = base.shares
  const other = PrivateKey.fromHex(KEYS.one).toBackupShares(2, 3)
  const fields = (s) => s.split('.')
  const join = (f) => f.join('.')
  const withField = (s, i, v) => {
    const f = fields(s)
    f[i] = v
    return join(f)
  }
  const b58 = (hex) => Utils.toBase58(Utils.toArray(hex, 'hex'))
  const P = new BigNumber(P_HEX, 16)
  const xOf = (s) => new BigNumber(Utils.fromBase58(fields(s)[0]))
  const yPlusP = (s) => b58(new BigNumber(Utils.fromBase58(fields(s)[1])).add(P).toString(16).padStart(66, '0'))
  const legacy = JSON.parse(readFileSync(rustWritten, 'utf8')).legacy_085
  const BRC140_EXAMPLE = [
    '45s4vLL2hFvqmxrarvbRT2vZoQYGZGocsmaEksZ64o5M.A7nZrGux15nEsQGNZ1mbfnMKugNnS6SYYEQwfhfbDZG8.3.2f804d43',
    '7aPzkiGZgvU4Jira5PN9Qf9o7FEg6uwy1zcxd17NBhh3.CCt7NH1sPFgceb6phTRkfviim2WvmUycJCQd2BxauxP9.3.2f804d43',
    '9GaS2Tw5sXqqbuigdjwGPwPsQuEFqzqUXo5MAQhdK3es.8MLh2wyE3huyq6hiBXjSkJRucgyKh4jVY6ESq5jNtXRE.3.2f804d43'
  ]
  const both = (f) => [f(s0), f(s1)]

  const READS = {
    own_threshold: [s0, s1],
    all_shares: [s0, s1, s2],
    fewer_than_threshold: [s0],
    no_shares: [],
    shares_256: Array(256).fill(s0),
    two_splits_mixed: [s0, other[1]],
    same_share_twice: [s0, s0],
    duplicate_past_the_threshold: [s0, s1, s1],
    share_over_256_characters: both((s) => '1'.repeat(257 - s.length) + s),
    share_of_256_characters: both((s) => '1'.repeat(256 - s.length) + s),
    share_200_non_ascii_units: ['é'.repeat(200), s1],
    share_130_astral_characters: ['😀'.repeat(130), s1],
    x_with_one_leading_1: both((s) => '1' + s),
    y_with_one_leading_1: both((s) => withField(s, 1, '1' + fields(s)[1])),
    x_zero: ['1.' + fields(s0)[1] + '.2.' + base.integrity, s1],
    x_at_p: both((s) => withField(s, 0, b58(P_HEX))),
    y_at_or_above_p: both((s) => withField(s, 1, yPlusP(s))),
    empty_x: both((s) => withField(s, 0, '')),
    empty_y: both((s) => withField(s, 1, '')),
    x_65_characters: both((s) => withField(s, 0, 'z'.repeat(65))),
    x_with_a_zero_character: both((s) => withField(s, 0, '0' + fields(s)[0].slice(1))),
    threshold_plus_2: both((s) => withField(s, 2, '+2')),
    threshold_02: both((s) => withField(s, 2, '02')),
    threshold_0: both((s) => withField(s, 2, '0')),
    threshold_1: both((s) => withField(s, 2, '1')),
    threshold_255: both((s) => withField(s, 2, '255')),
    threshold_256: both((s) => withField(s, 2, '256')),
    threshold_empty: both((s) => withField(s, 2, '')),
    threshold_space_2: both((s) => withField(s, 2, ' 2')),
    threshold_2_point_0: both((s) => withField(s, 2, '2.0')),
    threshold_arabic_indic_2: both((s) => withField(s, 2, '٢')),
    integrity_uppercase: both((s) => withField(s, 3, base.integrity.toUpperCase())),
    integrity_wrong_same_shape: both((s) => withField(s, 3, '00000000')),
    integrity_7_digits: both((s) => withField(s, 3, base.integrity.slice(0, 7))),
    integrity_9_digits: both((s) => withField(s, 3, base.integrity + '0')),
    integrity_differs_in_share_1: [s0, withField(s1, 3, '00000000')],
    threshold_differs_in_share_1: [s0, withField(s1, 2, '3')],
    threshold_and_integrity_differ_in_share_1: [s0, withField(withField(s1, 2, '3'), 3, '00000000')],
    integrity_differs_and_x_leading_1_in_share_1: [s0, '1' + withField(s1, 3, '00000000')],
    bad_point_in_share_1: [s0, '1' + s1],
    five_fields: both((s) => s + '.extra'),
    three_fields: both((s) => fields(s).slice(0, 3).join('.')),
    trailing_newline: both((s) => s + '\n'),
    legacy_085_2_of_3: legacy.shares.slice(0, 2),
    brc140_example_three: BRC140_EXAMPLE,
    brc140_example_two: BRC140_EXAMPLE.slice(0, 2)
  }
  if (xOf(s0).eq(xOf(s1))) throw new Error('the reference drew one x twice')
  const reads = Object.entries(READS).map(([name, shares]) => ({
    name,
    shares,
    parse: (() => {
      try {
        KeyShares.fromBackupFormat(shares)
        return { ok: true }
      } catch (e) {
        return { ok: false, error: String(e && e.message) }
      }
    })(),
    answer: recover(shares)
  }))

  // The writer's refusals of a hand-built collection (`toBackupFormat`).
  const writerCase = (f) => {
    try {
      return { ok: true, lines: f().toBackupFormat() }
    } catch (e) {
      return { ok: false, error: String(e && e.message) }
    }
  }
  const parsed = () => KeyShares.fromBackupFormat([s0, s1])
  const writer = {
    as_read: writerCase(() => parsed()),
    no_points: writerCase(() => new KeyShares([], 2, base.integrity)),
    threshold_1: writerCase(() => new KeyShares(parsed().points, 1, base.integrity)),
    threshold_256: writerCase(() => new KeyShares(parsed().points, 256, base.integrity)),
    integrity_legacy: writerCase(() => new KeyShares(parsed().points, 2, 'GuMr')),
    y_at_p: writerCase(() => {
      const k = parsed()
      k.points[0].y = P.clone()
      return k
    })
  }
  // `fromKeyShares` on a hand-built collection.
  const keySharesCase = (f) => answer(() => PrivateKey.fromKeyShares(f()))
  const key_shares = {
    threshold_above_points: keySharesCase(() => new KeyShares(parsed().points, 3, base.integrity)),
    integrity_legacy: keySharesCase(() => new KeyShares(parsed().points, 2, 'GuMr')),
    x_at_p: keySharesCase(() => {
      const k = parsed()
      k.points[0].x = P.clone()
      return k
    })
  }

  // This crate's shares, as the reference reads them.
  const rust = JSON.parse(readFileSync(rustWritten, 'utf8'))
  const rust_written = rust.splits.map((s) => ({
    ...s,
    recoveries: subsets(s.total, s.threshold).map((indices) => ({
      indices,
      answer: recover(indices.map((i) => s.shares[i]))
    }))
  }))
  writeFileSync(
    out,
    JSON.stringify(
      withFold({
        issue: 854,
        reference: 'ts-stack@edf6e03 packages/sdk (@bsv/sdk), Node 22.18.0',
        standard: 'BRC-140, bsv-blockchain/BRCs@f7f1520 key-derivation/0140.md',
        recorder: 'tests/support/shamir_backup_854.mjs',
        label: LABEL,
        splits,
        reads,
        writer,
        key_shares,
        legacy_085: legacy,
        rust_written
      }),
      null,
      2
    ) + '\n'
  )
}

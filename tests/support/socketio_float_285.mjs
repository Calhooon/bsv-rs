// The #285 verdicts: the reference's Socket.IO parser on a frame's numbers.
//
// `@bsv/sdk` carries no Socket.IO codec; the reference's is the one
// `@bsv/authsocket-client` reaches through `socket.io-client`, which
// `ts-stack@edf6e03`'s `pnpm-lock.yaml` resolves to `socket.io-parser`
// 4.2.7 (its Encoder writes a packet's data with `JSON.stringify`, its
// Decoder reads it with `JSON.parse`). This script decodes each frame of
// the vector with that parser, encodes the packet again, and records the
// number it read (the text `JSON.stringify` writes and the double's bits)
// and whether the encoding is a fixed point:
//   npm install --prefix "$W" socket.io-parser@4.2.7
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/socketio_float_285.mjs \
//     "$W/node_modules/socket.io-parser" tests/vectors/socketio_float_round_trip_285.json
import fs from 'fs'
import { createRequire } from 'module'
import path from 'path'

const [parserDir, vectorPath] = process.argv.slice(2)
const require = createRequire(import.meta.url)
const { Decoder, Encoder } = require(path.resolve(parserDir))
const parserVersion = JSON.parse(fs.readFileSync(path.join(parserDir, 'package.json'), 'utf8')).version
const v = JSON.parse(fs.readFileSync(vectorPath, 'utf8'))

const decode = (frame) => {
  const d = new Decoder()
  let packet
  d.on('decoded', (p) => { packet = p })
  d.add(frame)
  return packet
}
const bits = (n) => Buffer.from(new Float64Array([n]).buffer).reverse().toString('hex')
const at = (data, where) => where.reduce((x, k) => x[k], data)

v.reference = `socket.io-parser ${parserVersion} under Node ${process.version}`
for (const c of v.cases) {
  const packet = decode(c.frame)
  const [encoded] = new Encoder().encode(packet)
  const [again] = new Encoder().encode(decode(encoded))
  const n = at(packet.data, c.number_at)
  c.reference_text = JSON.stringify(n)
  c.reference_bits = bits(n)
  c.reference_encoding = encoded
  c.reference_fixed_point = encoded === again
}
fs.writeFileSync(vectorPath, JSON.stringify(v, null, 2) + '\n')

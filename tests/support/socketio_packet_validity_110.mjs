// The #110 verdicts: the reference's Socket.IO parser on a packet's id and payload.
//
// The reference is `socket.io-parser` 4.2.7, the parser `socket.io` ^4.8.3
// ships and `@bsv/authsocket` reaches (`ts-stack@edf6e03`
// `packages/messaging/authsocket/package.json`). This script decodes each
// frame below with that parser's `Decoder` (`decodeString`,
// `build/cjs/index.js:178-247`, its payload rule `isPayloadValid`,
// `:256-275`), records the verdict (the packet, or the error's words), encodes
// an accepted packet again with its `Encoder` (`encodeAsString`, `:77-100`)
// and records that encoding and whether it decodes and re-encodes to itself.
// It also records the UTF-16 code units the decoder's id loop takes as part of
// the digit run (`Number(c) == c`, `:222`, `:226`): the ASCII digits and every
// character `Number` trims as white space.
//
// Run with the copy of the parser on this host (Node v22.18.0 under nvm):
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/socketio_packet_validity_110.mjs \
//     ~/bsv/bsv-stack-lean/tools/n1-paid-send/node_modules/socket.io-parser \
//     > tests/vectors/socketio_packet_validity_110.json
import fs from 'fs'
import { createRequire } from 'module'
import path from 'path'

const [parserDir] = process.argv.slice(2)
const require = createRequire(import.meta.url)
const { Decoder, Encoder } = require(path.resolve(parserDir))
const parserVersion = JSON.parse(fs.readFileSync(path.join(parserDir, 'package.json'), 'utf8')).version

// The two inputs of the issue, base64 as filed
const fuzz1 = Buffer.from('MAowCg==', 'base64').toString('utf8')
const fuzz2 = Buffer.from('MDAwMDAwMCAgIDgxNDc0MTk3MTQxODE0NzQxOTcxNDEwMzQxOTIzMDM0MTkyMzIKCgo=', 'base64').toString('utf8')

const FRAMES = [
  ['the issue\'s first fuzz input', fuzz1],
  ['the issue\'s second fuzz input', fuzz2],
  ['CONNECT with an id', '00'],
  ['CONNECT, an object', '0{"a":1}'],
  ['CONNECT, an array', '0[1]'],
  ['CONNECT, a string', '0"x"'],
  ['CONNECT, null', '0null'],
  ['CONNECT, a number after the id', '012'],
  ['CONNECT, not JSON', '0{'],
  ['CONNECT, no payload', '0'],
  ['CONNECT, an id and an object', '07{"a":1}'],
  ['DISCONNECT', '1'],
  ['DISCONNECT, a payload', '1{}'],
  ['DISCONNECT, an id', '13'],
  ['CONNECT_ERROR, a string', '4"msg"'],
  ['CONNECT_ERROR, an object', '4{"message":"x"}'],
  ['CONNECT_ERROR, an array', '4[1]'],
  ['CONNECT_ERROR, a number after the id', '45'],
  ['CONNECT_ERROR, no payload', '4'],
  ['EVENT, a reserved name', '2["connect"]'],
  ['EVENT, each reserved name', '2["newListener",1]'],
  ['EVENT, a number head', '2[1]'],
  ['EVENT, an empty array', '2[]'],
  ['EVENT, an object', '2{}'],
  ['EVENT, a null head', '2[null]'],
  ['EVENT, an object head', '2[{}]'],
  ['EVENT, no payload', '2'],
  ['EVENT, an id and no payload', '25'],
  ['EVENT, a name', '2["ev",1]'],
  ['ACK with no id', '3[]'],
  ['ACK, an object', '3{}'],
  ['ACK with an id', '30[]'],
  ['ACK with an id and no payload', '30'],
  ['ACK with no id and no payload', '3'],
  ['a namespace and no payload', '0/nsp,'],
  ['a namespace and an object', '0/nsp,{"a":1}'],
  ['a namespace without its comma', '0/nsp'],
  ['the default namespace written', '0/,'],
  ['an EVENT on a namespace with an id', '2/nsp,5["ev"]'],
  ['a 20-digit id within u64', '218446744073709551615["ev"]'],
  ['a 20-digit id past u64', '218446744073709551616["ev"]'],
  ['a 21-digit id', '2123456789012345678901["ev"]'],
  ['an id past 2^53 within u64', '29007199254740993["ev"]'],
  ['an id with leading zeros', '2007["ev"]'],
  ['a space before the payload', '2 ["ev"]'],
  ['a space inside the digit run', '21 2["ev"]'],
  ['spaces around the id', '2 12 ["ev"]'],
  ['a tab before the id', '0\t5'],
  ['a no-break space before the payload', '0 {}'],
  ['a BOM before the payload', '0﻿{}'],
  ['an ideographic space before the payload', '2　["ev"]'],
  ['white space after the payload', '0{} '],
  ['a BINARY_EVENT', '51-["ev",{"_placeholder":true,"num":0}]'],
  ['a BINARY_ACK', '61-0[{"_placeholder":true,"num":0}]'],
  ['an unknown type', '7'],
  ['a letter type', 'x'],
  ['an empty frame', ''],
  ['a space as the type', ' {"a":1}'],
  ['a lone surrogate escape', '2["ev","\\ud800"]']
]

const decode = (frame) => {
  const d = new Decoder()
  let packet
  d.on('decoded', (p) => { packet = p })
  d.add(frame)
  return packet
}

const cases = FRAMES.map(([name, frame]) => {
  let packet
  try {
    packet = new Decoder().decodeString(frame)
  } catch (e) {
    return { name, frame, accepted: false, error: e.message }
  }
  const out = { name, frame, accepted: true, type: packet.type, nsp: packet.nsp }
  if (packet.id !== undefined) out.id = String(packet.id)
  if (packet.attachments !== undefined) out.attachments = packet.attachments
  if (packet.data !== undefined) out.data_text = JSON.stringify(packet.data)
  const encoded = new Encoder().encodeAsString(packet)
  out.encoding = encoded
  try {
    out.encoding_fixed_point = new Encoder().encodeAsString(new Decoder().decodeString(encoded)) === encoded
  } catch (e) {
    out.encoding_fixed_point = false
    out.encoding_error = e.message
  }
  // A non-binary frame also goes through the Decoder's `add`, the path a socket takes
  if (packet.type !== 5 && packet.type !== 6) decode(frame)
  return out
})

const idRunUnits = []
for (let u = 0; u <= 0xffff; u++) {
  const c = String.fromCharCode(u)
  // eslint-disable-next-line eqeqeq
  if (c !== '' && Number(c) == c) idRunUnits.push(u)
}

process.stdout.write(JSON.stringify({
  issue: 'Calhooon/bsv-rs#110',
  description: 'Socket.IO frames and the reference decoder\'s verdict on each (the packet, or the error\'s words), the reference encoder\'s writing of an accepted packet and whether it is a fixed point, and the UTF-16 code units its id loop reads as part of the digit run; written by tests/support/socketio_packet_validity_110.mjs',
  reference: `socket.io-parser ${parserVersion} under Node ${process.version}`,
  id_run_units: idRunUnits,
  cases
}, null, 2) + '\n')

// #914: an unknown wallet wire call code, recorded from two unmodified
// ts-stack bundles under Node 22 (the pin edf6e03 and the head 5226d0c7).
//
//   node wire_call_code_callcode.mjs <pin sdk.mjs> <head sdk.mjs> \
//        <base frames json> [<tip test binary>] > call_code_callcode.json
//
// Every frame, verdict and word below is observed, never supplied, save two
// answers the client rows are given: the reference's sentence under code 6
// (a frame built here) and this crate's base frame, read from <base frames
// json> (written by `this_crates_answers_callcode` on the scratch base). With
// a tip test binary the recorder drives this crate's processor live through
// that ignored test, one child process per request.
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const [pinPath, headPath, basePath, tipBinary] = process.argv.slice(2)
const pin = await import(pinPath)
const head = await import(headPath)
const baseFrames = JSON.parse(readFileSync(basePath, 'utf8'))
const hex = (bytes) => Buffer.from(bytes).toString('hex')
const unhex = (text) => Uint8Array.from(Buffer.from(text, 'hex'))

const CODES = [0, 29, 30, 99, 255]
const shapes = (n) => [[n], [n, 0], [n, 0, 0, 1], [n, 251], [n, 3, 0x61, 0x2e, 0x62, 1]]
const PAGE = { totalCertificates: 0, certificates: [] }

// A wallet that records any call by name and answers an empty page.
function recordingWallet (called) {
  return new Proxy({}, {
    get (_target, name) {
      if (typeof name !== 'string' || name === 'then') return undefined
      return async () => { called.push(name); return PAGE }
    }
  })
}

const thrownOf = (error) => ({ name: error?.name ?? null, code: error?.code ?? null, message: error?.message ?? String(error) })

async function processorCells () {
  const cells = []
  for (const [side, sdk] of [['pin', pin], ['head', head]]) {
    for (const code of CODES) {
      for (const request of shapes(code)) {
        const called = []
        const processor = new sdk.WalletWireProcessor(recordingWallet(called))
        const response = await processor.transmitToWallet(request)
        cells.push({ side, request_hex: hex(request), response_hex: hex(response), called })
      }
    }
  }
  return cells
}

async function httpCells () {
  const cells = []
  for (const [side, sdk] of [['pin', pin], ['head', head]]) {
    for (const request of [[29, 0, 0, 1], [99, 0]]) {
      const urls = []
      const httpClient = async (url) => {
        urls.push(url)
        return new Response(Uint8Array.from([0, 1]), { status: 200, headers: { 'content-type': 'application/octet-stream' } })
      }
      const wire = new sdk.HTTPWalletWire(undefined, 'http://localhost:1', httpClient)
      let result = null
      let thrown = null
      try {
        result = hex(await wire.transmitToWallet(request))
      } catch (error) {
        thrown = thrownOf(error)
      }
      cells.push({ side, request_hex: hex(request), requests_sent: urls.length, urls, result, thrown })
    }
  }
  return cells
}

function errorFrame (code, words) {
  const bytes = Buffer.from(words, 'utf8')
  return Uint8Array.from([code, bytes.length, ...bytes, 0])
}

function tipAnswer (request) {
  const dir = mkdtempSync(join(tmpdir(), 'callcode-'))
  const out = join(dir, 'out.json')
  try {
    execFileSync(tipBinary, ['--ignored', '--exact', 'this_crates_answers_callcode', '--quiet'], {
      env: { ...process.env, CALLCODE_REQUESTS: hex(request), CALLCODE_OUT: out },
      stdio: ['ignore', 'ignore', 'inherit']
    })
    return unhex(JSON.parse(readFileSync(out, 'utf8'))[hex(request)])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

async function clientRows () {
  const pinProcessor = new pin.WalletWireProcessor(recordingWallet([]))
  const headProcessor = new head.WalletWireProcessor(recordingWallet([]))
  const probeAnswers = {
    pin_processor: (frame) => pinProcessor.transmitToWallet(Array.from(frame)),
    head_processor: (frame) => headProcessor.transmitToWallet(Array.from(frame)),
    code6_sentence: () => errorFrame(6, 'Invalid call code: 29'),
    base_frame: (frame) => {
      const answer = baseFrames[hex(frame)]
      if (answer === undefined) throw new Error(`no base frame for ${hex(frame)}`)
      return unhex(answer)
    }
  }
  if (tipBinary) probeAnswers.tip_live = (frame) => tipAnswer(frame)
  const calls = {
    discoverByIdentityKey: (client) => client.discoverByIdentityKey({ identityKey: '02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' }),
    listCertificates: (client) => client.listCertificates({ certifiers: [], types: [] })
  }
  const rows = []
  for (const [call, invoke] of Object.entries(calls)) {
    for (const [wireName, answerProbe] of Object.entries(probeAnswers)) {
      const requests = []
      let probeResponse = null
      const plain = wireName === 'head_processor' ? headProcessor : pinProcessor
      const client = new head.WalletWireTransceiver({
        async transmitToWallet (frame) {
          const bytes = Uint8Array.from(frame)
          requests.push(hex(bytes))
          if (requests.length === 1) {
            probeResponse = Uint8Array.from(await answerProbe(bytes))
            return Array.from(probeResponse)
          }
          if (wireName === 'tip_live') return Array.from(tipAnswer(bytes))
          return Array.from(await plain.transmitToWallet(Array.from(bytes)))
        }
      })
      let result = null
      let thrown = null
      try {
        result = await invoke(client)
      } catch (error) {
        thrown = thrownOf(error)
      }
      rows.push({
        call,
        wire: wireName,
        requests,
        probe_response_hex: probeResponse === null ? null : hex(probeResponse),
        fell_back: requests.length >= 2 && requests[1].slice(0, 2) !== '1d',
        result,
        thrown
      })
    }
  }
  return rows
}

const vector = {
  description: 'An unknown wallet wire call code (#914): the pin processor\'s and the head\'s frames, HTTPWalletWire\'s refusal, and the head client\'s probe fallback over five answers.',
  references: {
    pin: 'ts-stack@edf6e03 packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:276-283, HTTPWalletWire.ts:33-40',
    head: 'ts-stack@5226d0c7 packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:287-294, WalletWireTransceiver.ts:126-154, HTTPWalletWire.ts:41-48'
  },
  node: process.version,
  processor: await processorCells(),
  http: await httpCells(),
  client: await clientRows()
}
process.stdout.write(JSON.stringify(vector, null, 2) + '\n')

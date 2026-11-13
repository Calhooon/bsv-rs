// #815's second fold: a lookup answer's `Content-Type` and `Content-Length`
// padded with one character, read by the reference's own
// `HTTPSOverlayLookupFacilitator.lookup` (`ts-stack@edf6e03`
// `packages/sdk/src/overlay-tools/LookupResolver.ts:512-516`, `isOctetStream`,
// `split(';', 1)[0].trim().toLowerCase()`; `:845`;
// `LookupResponseReader.ts:23-35`, `contentLength.trim()` then `/^\d+$/`),
// with a stub `fetch` whose `headers.get` hands the text over as given (no
// host dialled). The pads: every character of ECMAScript's `trim` set
// (WhiteSpace and LineTerminator), U+0085 (which Rust's `str::trim` takes
// and ECMAScript's does not) and two controls neither takes. Each cell also
// records whether a WHATWG `Headers` (Node's fetch) holds the text and what
// it hands back, so the cells a peer reaches through fetch are named.
//
// The bundle:
//   W=/Volumes/Lanes/out/bsv-rs/fix-815-fold2/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   printf "export * from './packages/sdk/mod.js'\n" > "$W/entry815.ts"
//   (cd "$W" && bun build entry815.ts --target node --format esm --outfile "$W/ref815.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/lookup_header_trim_815.mjs \
//     "$W/ref815.mjs" > tests/vectors/lookup_header_trim_815.json
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const { HTTPSOverlayLookupFacilitator } = sdk

// ECMAScript's trim set (ECMA-262 WhiteSpace and LineTerminator)
const JS_TRIM = [
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
  0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff
]
// Rust's `char::is_whitespace` (Unicode White_Space) takes U+0085 beside them
// and not U+FEFF; U+001F and U+0080 neither
const PADS = [...JS_TRIM, 0x85, 0x1f, 0x80]
const hex = (cp) => cp.toString(16).padStart(4, '0')
const BODY = new TextEncoder().encode('{"type":"output-list","outputs":[]}')

const throughHeaders = (name, text) => {
  try {
    return { held: new Headers([[name, text]]).get(name) }
  } catch (e) {
    return { refused: e.constructor.name }
  }
}

const read = async (headers, maxResponseBytes) => {
  const fetchClient = async () => ({
    ok: true,
    status: 200,
    headers: { get: (name) => (name in headers ? headers[name] : null) },
    body: new ReadableStream({
      start(c) {
        c.enqueue(BODY)
        c.close()
      }
    })
  })
  const facilitator = new HTTPSOverlayLookupFacilitator(fetchClient)
  try {
    const answer = await facilitator.lookup(
      'https://host-815.invalid',
      { service: 'ls_trim_815', query: {} },
      1000,
      undefined,
      { maxResponseBytes }
    )
    return { answer: answer.type }
  } catch (e) {
    return { error: e.message }
  }
}

const contentType = []
for (const cp of PADS) {
  const pad = String.fromCodePoint(cp)
  for (const [position, text] of [
    ['after', `application/octet-stream${pad}`],
    ['before', `${pad}application/octet-stream`],
    ['before_parameter', `application/octet-stream${pad}; x=1`]
  ]) {
    const got = await read({ 'content-type': text }, 1024)
    contentType.push({
      pad: hex(cp),
      position,
      // the binary path refuses this JSON body; the JSON path answers it
      path: got.answer === 'output-list' ? 'json' : 'binary',
      result: got,
      fetch_headers: throughHeaders('content-type', text)
    })
  }
}

const contentLength = []
for (const cp of PADS) {
  const pad = String.fromCodePoint(cp)
  for (const [position, text] of [
    ['after', `100${pad}`],
    ['before', `${pad}100`]
  ]) {
    // past the bound of 64 when read as a length; no length otherwise, and
    // the 35-byte body is read
    const got = await read({ 'content-type': 'application/json', 'content-length': text }, 64)
    contentLength.push({
      pad: hex(cp),
      position,
      length: got.error === 'Lookup resource limit reached: maxResponseBytes' ? 'read' : 'none',
      result: got,
      fetch_headers: throughHeaders('content-length', text)
    })
  }
}

process.stdout.write(
  JSON.stringify(
    {
      reference:
        'ts-stack@edf6e03 packages/sdk HTTPSOverlayLookupFacilitator.lookup (isOctetStream, assertDeclaredLengthIsWithinLimit)',
      node: process.version,
      body: new TextDecoder().decode(BODY),
      content_type: contentType,
      content_length: contentLength
    },
    null,
    1
  ) + '\n'
)

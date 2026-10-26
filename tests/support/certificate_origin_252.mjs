// The #252 provenance: what signed tests/vectors/auth_certificate.json vector 0.
//
// Vector 0 is the reference's `fromObject` fixture (@bsv/sdk
// `Certificate.test.ts`, added at ts-sdk@27a93752, 2025-11-19) with its type
// and serial changed. This script reads the original and the copy under a
// given SDK bundle, each with the original or the copy's type and serial,
// and prints the reference's `verify()` verdict and the raw-key verdict:
//   git -C ~/bsv/ts-sdk archive 27a93752 | tar -x -C "$W"
//   (cd "$W" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_origin_252.mjs \
//     "$W/sdk.mjs" tests/vectors/auth_certificate_origin_252.json
// and the same against ts-stack@edf6e03 (`git -C ~/bsv/ts-stack archive
// edf6e03 packages/sdk`, built in `packages/sdk`).
import fs from 'fs'
import { pathToFileURL } from 'url'

const [sdkPath, vectorPath] = process.argv.slice(2)
const { Certificate, PublicKey, Signature, Utils } = await import(pathToFileURL(sdkPath).href)
const v = JSON.parse(fs.readFileSync(vectorPath, 'utf8'))
const o = v.original

console.log('node', process.version)
for (const type of [o.type, v.vector_0.type]) {
  for (const serial of [o.serialNumber, v.vector_0.serialNumber]) {
    const c = new Certificate(type, serial, o.subject, o.certifier, o.revocationOutpoint, { ...o.fields }, o.signature)
    let derived, raw
    try { derived = await c.verify() } catch (e) { derived = 'throws: ' + e.message }
    try {
      raw = PublicKey.fromString(o.certifier).verify(c.toBinary(false), Signature.fromDER(Utils.toArray(o.signature, 'hex')))
    } catch (e) { raw = 'throws: ' + e.message }
    const name = `type=${type === o.type ? 'original' : 'vector_0'} serial=${serial === o.serialNumber ? 'original' : 'vector_0'}`
    console.log(name, 'verify', derived, 'raw', raw)
  }
}

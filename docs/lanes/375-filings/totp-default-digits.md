# Resolve the two-digit legacy TOTP default versus the secure six-digit entry point

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 22: TS TOTP defaults to 2 digits; this crate uses 6…

The no-options generate/validate path retains the historical two-digit default; generateSecure chooses six. Compare generate(secret, { timestamp: fixed }) with generate(secret, { timestamp: fixed, digits: 6 }) and the Rust default, using the public RFC test vector through the linked tests. Please document/migrate the default deliberately; the secure alternative already exists. No secret literal is included here.

Witness:

- [src/totp/core.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/src/totp/core.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/totp/totp.ts:49-65,140-158](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/totp/totp.ts#L49)

BRC reading: No BRC defines this compatibility format or its limits; this is an SDK parity request.

Additional standard: [RFC 4226 section 5.3, minimum six digits](https://www.rfc-editor.org/rfc/rfc4226.html#section-5.3), used by [RFC 6238 section 3](https://www.rfc-editor.org/rfc/rfc6238.html#section-3).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

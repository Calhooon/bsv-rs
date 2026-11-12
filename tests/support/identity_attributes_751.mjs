// #751: the reference wallet re-binds an attribute lookup's answer to the
// question it asked (`ts-stack@edf6e03`
// `packages/wallet/wallet-toolbox/src/Wallet.ts:1069-1082`,
// `discoverByAttributes`), through `filterCertificatesByAttributes`
// (`packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:140-293`):
// `userName` exact after `normalizeIdentitySearch`, every other named field
// by `identityFuzzyMatches` (the tokens found in order on one line, under a
// `gi` literal), `any` across every string field but `profilePhoto` and
// `icon` (two UTF-16 units fuzzily, three or more by `identityTextMatches`:
// NFD, `\p{Mn}` removed, lower case, stop words, `-term`, a phrase), and
// nothing kept when nothing is usable. The matcher reads only each
// certificate's `decryptedFields`, so each case hands it records of that one
// member, in the order given (integer-like names ahead, as a JavaScript
// object holds them).
//
// Recorded per case: the attributes and each record as `[name, value]` pairs
// in the order built, and `kept`, the indices of the records the reference
// keeps, in order.
//
// The bundle:
//   W=<lane folder>/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src packages/overlays/topics/src | tar -x -C "$W"
//   cat > "$W/tsconfig.json" <<'EOF'
//   { "compilerOptions": { "baseUrl": ".", "paths": {
//     "@bsv/sdk": ["packages/sdk/mod.ts"],
//     "@bsv/sdk/primitives/utils": ["packages/sdk/src/primitives/utils.ts"],
//     "@bsv/sdk/wallet/validationHelpers": ["packages/sdk/src/wallet/validationHelpers.ts"]
//   } } }
//   EOF
//   cat > "$W/entry751.ts" <<'EOF'
//   export { filterCertificatesByAttributes } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   export { IdentityLookupService } from './packages/overlays/topics/src/identity/IdentityLookupService.js'
//   EOF
//   (cd "$W" && bun build entry751.ts --target node --format esm --external mongodb --external @bsv/overlay --outfile "$W/ref751.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_attributes_751.mjs \
//     "$W/ref751.mjs" > tests/vectors/identity_attributes_751.json
import { pathToFileURL } from 'url'

const { filterCertificatesByAttributes } = await import(pathToFileURL(process.argv[2]).href)

const cases = []
const add = (name, attributes, records) => {
  const certificates = records.map(pairs => ({ decryptedFields: Object.fromEntries(pairs) }))
  const kept = filterCertificatesByAttributes(certificates, Object.fromEntries(attributes))
    .map(certificate => certificates.indexOf(certificate))
  cases.push({ name, attributes, records, kept })
}

const names = [[['userName', 'alice']], [['userName', 'Alice']], [['userName', 'alice2']],
  [['userName', ' alice']], [['userName', 'alice smith']], [['name', 'alice']]]
add('username_exact', [['userName', 'alice']], names)
add('username_padded', [['userName', '  alice\t']], names)
add('username_other_case', [['userName', 'ALICE']], names)
add('username_inner_space', [['userName', 'alice   smith']], names)
const emails = [[['email', 'bob@example.com']], [['email', 'example bob']], [['email', 'BOB@EXAMPLE.COM']],
  [['email', 'bo b example']], [['email', 'bobexample']], [['email', 'xbobx and exampley']]]
add('fuzzy_in_order', [['email', 'bob example']], emails)
add('fuzzy_out_of_order', [['email', 'example bob']], emails)
add('fuzzy_other_case', [['email', 'BoB  EXAMPLE ']], emails)
add('fuzzy_metacharacter', [['email', 'a.b (c']], [[['email', 'a.b (c']], [['email', 'axb (c']],
  [['email', 'a.b c']], [['email', 'A.B (C)']]])
add('fuzzy_two_lines', [['name', 'alice smith']], [[['name', 'alice\nsmith']], [['name', 'bob\nalice smith']],
  [['name', 'x\r\nalice smith']], [['name', 'alice smith']], [['name', 'alice\rsmith']], [['name', 'alice\tsmith']]])
add('fuzzy_case_folding', [['city', 'straße']], [[['city', 'STRASSE']], [['city', 'Straße']], [['city', 'STRAẞE']]])
add('fuzzy_long_s_and_kelvin', [['city', 'sk']], [[['city', 'ſk']], [['city', 'SK']], [['city', 'sK']], [['city', 'Sk']]])
add('fuzzy_dotless_i', [['city', 'istanbul']], [[['city', 'ıstanbul']], [['city', 'ISTANBUL']], [['city', 'İstanbul']]])
add('missing_field', [['email', 'bob']], [[['name', 'bob']], [['email', 'bob']], []])
add('blank_beside_usable', [['email', 'bob'], ['phone', '   ']], [[['email', 'bob']], [['email', 'bob'], ['phone', '1']], [['phone', '1']]])
add('all_blank', [['email', '  '], ['phone', '']], [[['email', 'x']], []])
add('empty_map', [], [[['email', 'x']], []])
add('two_named_fields', [['email', 'bob'], ['name', 'smith']], [[['email', 'bob'], ['name', 'smith']], [['email', 'bob'], ['name', 'jones']]])
const people = [[['firstName', 'Alice'], ['lastName', 'Smith']], [['firstName', 'Alicent']],
  [['email', 'alice@x.com']], [['firstName', 'bob'], ['lastName', 'Hall']], [['profilePhoto', 'alice']],
  [['icon', 'alice']], [['firstName', 'Bob'], ['lastName', 'Smith']], []]
add('any_one_unit', [['any', 'a']], people)
add('any_blank', [['any', '   ']], people)
add('any_two_units', [['any', 'al']], people)
add('any_two_units_padded', [['any', ' AL ']], people)
add('any_two_units_across_fields', [['any', 'ab']], [[['first', 'a'], ['last', 'b']], [['first', 'ab']]])
add('any_three_units', [['any', 'alice']], people)
add('any_stop_word', [['any', 'the']], [[['name', 'the']], [['name', 'alice the']]])
add('any_stop_word_beside_term', [['any', 'the alice']], people)
add('any_negated_term', [['any', 'alice -smith']], [[['firstName', 'alice'], ['lastName', 'smith']],
  [['firstName', 'alice'], ['lastName', 'jones']], [['firstName', 'bob'], ['lastName', 'smith']]])
add('any_negated_alone', [['any', '-smith']], [[['name', 'alice']], [['name', 'smith']]])
add('any_dash_alone', [['any', 'alice -']], [[['name', 'alice']], [['name', 'bob']]])
add('any_phrase', [['any', '"alice smith"']], [[['name', 'alice smith']], [['name', 'smith alice']],
  [['first', 'alice'], ['last', 'smith']], [['name', 'Alice  Smith']]])
add('any_negated_phrase', [['any', 'bob -"alice smith"']], [[['name', 'bob alice smith']], [['name', 'bob smith alice']]])
add('any_unclosed_quote', [['any', '"alice']], [[['name', 'alice']], [['name', 'bob']]])
add('any_phrase_of_stop_words', [['any', '"the a"']], [[['name', 'the a']], [['name', 'alice']]])
add('any_diacritic', [['any', 'jose']], [[['name', 'José']], [['name', 'JOSE']], [['name', 'josé-maria']]])
add('any_diacritic_asked', [['any', 'JOSÉ']], [[['name', 'jose']], [['name', 'José']]])
add('any_apostrophe', [['any', "o'neil"]], [[['name', "Mary O'Neil"]], [['name', 'oneil']], [['name', 'o neil']]])
add('any_punctuation_token', [['any', 'alice.smith']], [[['email', 'alice.smith@x']], [['email', 'smith']]])
add('any_only_in_photo', [['any', 'photo']], [[['profilePhoto', 'photo']], [['icon', 'photo']], [['name', 'photo']]])
add('any_beside_failing_named_field', [['email', 'zzz'], ['any', 'alice']], [[['firstName', 'alice'], ['email', 'bob']]])
add('any_beside_failing_named_field_after', [['any', 'alice'], ['email', 'zzz']], [[['firstName', 'alice'], ['email', 'bob']]])
add('any_integer_like_field_order', [['any', '"x y"']], [[['b', 'x'], ['1', 'y']], [['b', 'y'], ['1', 'x']]])
add('any_final_sigma', [['any', 'ΟΔΟΣ']], [[['name', 'οδος']], [['name', 'οδος']]])
add('any_two_units_two_lines', [['any', 'ab']], [[['name', 'a\nb']], [['name', 'xab\ny']]])
// #818: four rules of the port no case above held (a mutation of each
// survived). A repeated token is searched from where the last match ended
// (`identityUtils.ts:154-158`, `cursor = found.index + found[0].length`);
// U+2029 ends a line as U+2028 does (`:147`); and `Object.entries` walks only
// a canonical array index ahead (`4294967295`, `01` and `+1` are none), the
// u32 bound beside a third field, since two fields alone read the same
// either way.
add('fuzzy_repeated_token', [['email', 'a a']], [[['email', 'a']], [['email', 'a a']], [['email', 'aa']], [['email', 'ba']]])
add('fuzzy_paragraph_separator', [['name', 'alice smith']], [[['name', 'alice smith']], [['name', 'x alice smith']]])
add('any_index_name_u32_max', [['any', '"x y"']], [[['b', 'x'], ['4294967295', 'y'], ['1', 'w']],
  [['1', 'w'], ['4294967295', 'y'], ['b', 'x']]])
add('any_index_name_leading_zero', [['any', '"x y"']], [[['01', 'y'], ['1', 'x']], [['1', 'x'], ['01', 'y']]])
add('any_index_name_plus_sign', [['any', '"x y"']], [[['+1', 'y'], ['1', 'x']], [['1', 'x'], ['+1', 'y']]])
// #818's fold: five steps of the same walk no case above held (the strength
// read's S1 to S5). The cursor moves by the token's length, not by one unit
// (`:156`); a lone CR ends a line and takes nothing after it (`:147`,
// `\r\n?`); each line is searched from its start (`:152`, `let cursor = 0`
// inside the line's loop); `4294967294` is the largest array index; and two
// index names are walked in ascending numeric order, whatever order they were
// inserted in (`10` after `9`).
add('fuzzy_token_longer_than_one_unit', [['email', 'ab bc']], [[['email', 'abc']], [['email', 'abbc']], [['email', 'ab bc']]])
add('fuzzy_lone_carriage_return', [['name', 'alice smith']], [[['name', 'x\ralice smith']], [['name', 'alice\rsmith']]])
add('fuzzy_second_line_from_its_start', [['name', 'alice smith']], [[['name', 'alice\nalice smith']], [['name', 'alice\nsmith']]])
add('any_index_name_below_u32_max', [['any', '"x y"']], [[['b', 'y'], ['4294967294', 'x']], [['b', 'x'], ['4294967294', 'y']]])
add('any_two_index_names', [['any', '"x y"']], [[['2', 'y'], ['1', 'x']], [['10', 'y'], ['9', 'x']], [['1', 'y'], ['2', 'x']]])

process.stdout.write(JSON.stringify({
  description: '#751: the reference wallet\'s filterCertificatesByAttributes over records of decryptedFields alone: ' +
    'userName exact, the other named fields fuzzy, any by its length, nothing kept when nothing is usable; ' +
    'kept the indices of the records the reference keeps',
  reference: 'ts-stack@edf6e03 packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:140-293; ' +
    'packages/wallet/wallet-toolbox/src/Wallet.ts:1069-1082',
  node: process.version,
  recorder: 'tests/support/identity_attributes_751.mjs',
  cases
}, null, 2) + '\n')

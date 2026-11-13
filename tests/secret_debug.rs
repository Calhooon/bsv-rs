//! No secret leaves through `Debug` or an error's text (the API read of
//! 2026-11-10, C-DEBUG, and the fold of PR #851): a `{:?}` of a value that
//! holds secret material, or of a struct that holds one, in a dependent's log
//! line or a panic message, writes the secret to the log, and so does an
//! error that echoes its input. Each type that holds a secret names itself
//! and redacts; the public half (a public key, a share's index, a count, a
//! URL) may be shown. Each door that parses secret material is run on
//! malformed forms of a real secret, and its error may carry no more than
//! `WINDOW_BOUND` characters of it. The ECDH shared secret is one such
//! value since #843d6: every door that derives it returns `SharedSecret`,
//! never a `PublicKey`, whose `Debug` printed the point.
//!
//! Every secret here is derived at run time from a fixed test vector (the
//! BIP-39 and BIP-32 specifications' entropy and seed, the scalar 2, a
//! SHA-256 of a label), never a literal secret text, and compared against the
//! formatted output in every encoding the crate writes it in.
#![cfg(all(feature = "compat", feature = "wallet"))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use bsv_rs::compat::bip32::{ExtendedKey, Network};
use bsv_rs::compat::bip39::Mnemonic;
use bsv_rs::primitives::bsv::shamir::split_private_key_with;

/// The coordinate draws of a fixed split (BRC-140's procedure, #854).
const DRAWS: [[u8; 32]; 3] = [[0xa1; 32], [0xa2; 32], [0xa3; 32]];
use bsv_rs::primitives::bsv::{PointInFiniteField, Polynomial};
use bsv_rs::primitives::encoding::to_base58;
use bsv_rs::primitives::p256::P256PrivateKey;
use bsv_rs::primitives::{to_hex, PrivateKey, SymmetricKey};
use bsv_rs::wallet::{CachedKeyDeriver, KeyDeriver, ProtoWallet};
use bsv_rs::Error;

/// BIP-39's test vector entropy `7f` x 16 (`bip-0039` vectors, English).
fn mnemonic() -> Mnemonic {
    Mnemonic::from_entropy(&[0x7f; 16]).expect("BIP-39 vector")
}

/// The scalar 2 (a fixed, public test key; 1 is the wallet's "anyone").
fn private_key() -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = 2;
    PrivateKey::from_bytes(&bytes).expect("scalar 2")
}

/// BIP-32 test vector 1's seed, `000102...0f`.
fn master() -> ExtendedKey {
    let seed: Vec<u8> = (0u8..16).collect();
    ExtendedKey::new_master(&seed, Network::Mainnet).expect("BIP-32 vector 1")
}

/// Both `{:?}` and `{:#?}` of `value`.
fn both<T: std::fmt::Debug>(value: &T) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

/// Every secret in `out` replaced by `x`s, longest first, so a failure's
/// message never carries one.
fn masked(out: &str, secrets: &[String]) -> String {
    let mut sorted: Vec<&String> = secrets.iter().collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    sorted.into_iter().fold(out.to_owned(), |acc, s| {
        acc.replace(s.as_str(), &"x".repeat(s.len()))
    })
}

fn assert_hides(what: &str, outputs: &[String], secrets: &[String]) {
    for out in outputs {
        for secret in secrets {
            assert!(
                !secret.is_empty() && !out.contains(secret.as_str()),
                "{what}: Debug output carries secret text ({} chars): {}",
                secret.len(),
                masked(out, secrets)
            );
        }
    }
}

fn mnemonic_secrets(m: &Mnemonic) -> Vec<String> {
    let mut s: Vec<String> = m.words().to_vec();
    s.push(m.phrase());
    s.push(to_hex(&m.entropy()));
    s
}

fn private_key_secrets(k: &PrivateKey) -> Vec<String> {
    vec![k.to_hex(), k.to_hex().to_uppercase(), k.to_wif()]
}

fn extended_key_secrets(k: &ExtendedKey) -> Vec<String> {
    let mut s = vec![k.to_string(), to_hex(k.chain_code())];
    s.extend(private_key_secrets(&k.private_key().expect("private form")));
    s
}

#[test]
fn a_mnemonic_debug_prints_no_word_of_the_phrase() {
    let m = mnemonic();
    let outputs = both(&m);
    assert_hides("Mnemonic", &outputs, &mnemonic_secrets(&m));
    assert!(outputs[0].starts_with("Mnemonic("), "{}", outputs[0]);
    assert!(outputs[0].contains("12 words"), "{}", outputs[0]);
}

#[test]
fn a_private_key_debug_prints_no_scalar_or_wif() {
    let k = private_key();
    assert_hides("PrivateKey", &both(&k), &private_key_secrets(&k));
}

#[test]
fn an_extended_private_key_debug_prints_no_xprv_chain_code_or_key() {
    let k = master();
    assert_hides("ExtendedKey", &both(&k), &extended_key_secrets(&k));
    let child = k.derive_path("m/0'/1").expect("path");
    assert_hides(
        "ExtendedKey child",
        &both(&child),
        &extended_key_secrets(&child),
    );
}

#[test]
fn a_symmetric_key_debug_prints_no_key_bytes() {
    let key = SymmetricKey::from_bytes(&[0x5a; 32]).expect("32 bytes");
    assert_hides("SymmetricKey", &both(&key), &[to_hex(key.as_bytes())]);
}

#[test]
fn a_p256_private_key_debug_prints_no_scalar() {
    let key = P256PrivateKey::from_bytes(&[0x11; 32]).expect("scalar");
    assert_hides("P256PrivateKey", &both(&key), &[key.to_hex()]);
}

#[test]
fn the_key_derivers_and_proto_wallet_print_no_root_key() {
    let k = private_key();
    let secrets = private_key_secrets(&k);
    assert_hides(
        "KeyDeriver",
        &both(&KeyDeriver::new(Some(k.clone()))),
        &secrets,
    );
    assert_hides(
        "CachedKeyDeriver",
        &both(&CachedKeyDeriver::new(Some(k.clone()), None)),
        &secrets,
    );
    assert_hides("ProtoWallet", &both(&ProtoWallet::new(Some(k))), &secrets);
}

/// The y coordinate of a share in every text the crate writes a `BigNumber`
/// in, and the share's own backup string.
fn share_secrets(p: &PointInFiniteField) -> Vec<String> {
    let y_bytes = p.y.to_bytes_be(32);
    vec![
        p.y.to_hex(),
        p.y.to_dec_string(),
        to_base58(&p.y.to_bytes_be_min()),
        to_hex(&y_bytes),
        p.to_point_string(),
    ]
}

#[test]
fn shamir_shares_debug_prints_no_share_value() {
    let key = private_key();
    let shares = split_private_key_with(&key, 2, 3, &[[0x42; 32]], &[0x5e; 64], &DRAWS)
        .expect("fixed coefficient split");
    let mut secrets: Vec<String> = shares.points.iter().flat_map(share_secrets).collect();
    secrets.extend(shares.to_backup_format().expect("written"));
    secrets.extend(private_key_secrets(&key));

    assert_hides("KeyShares", &both(&shares), &secrets);
    for point in &shares.points {
        assert_hides("PointInFiniteField", &both(point), &share_secrets(point));
    }
    let polynomial = Polynomial::new(shares.points.clone(), shares.threshold);
    assert_hides("Polynomial", &both(&polynomial), &secrets);
}

/// A dependent's struct that derives `Debug` over the secrets.
#[derive(Debug)]
#[allow(dead_code)] // Read only through Debug.
struct Holder {
    mnemonic: Mnemonic,
    key: PrivateKey,
    xprv: ExtendedKey,
    shares: bsv_rs::primitives::bsv::KeyShares,
    wallet: ProtoWallet,
}

#[test]
fn a_struct_holding_the_secrets_prints_none_of_them() {
    let m = mnemonic();
    let key = private_key();
    let xprv = master();
    let shares =
        split_private_key_with(&key, 2, 3, &[[0x42; 32]], &[0x5e; 64], &DRAWS).expect("split");
    let mut secrets = mnemonic_secrets(&m);
    secrets.extend(private_key_secrets(&key));
    secrets.extend(extended_key_secrets(&xprv));
    secrets.extend(shares.points.iter().flat_map(share_secrets));
    let holder = Holder {
        mnemonic: m,
        key: key.clone(),
        xprv,
        shares,
        wallet: ProtoWallet::new(Some(key)),
    };
    assert_hides("Holder", &both(&holder), &secrets);
}

#[test]
fn an_unknown_mnemonic_word_is_named_by_its_position_not_echoed() {
    let m = mnemonic();
    let mut words = m.words().to_vec();
    // A mistyped word of the phrase is still most of the word.
    words[2] = format!("{}q", words[2]);
    let typo = words[2].clone();
    let err = Mnemonic::from_phrase(&words.join(" ")).expect_err("unknown word");
    assert!(matches!(err, Error::InvalidMnemonicWord(_)), "{err:?}");
    let outputs = [err.to_string(), format!("{err:?}"), format!("{err:#?}")];
    let mut secrets = mnemonic_secrets(&m);
    secrets.push(typo);
    assert_hides("InvalidMnemonicWord", &outputs, &secrets);
    assert_eq!(
        err.to_string(),
        "invalid word in mnemonic: word 3 of 12 is not in the English wordlist"
    );
}

// ---------------------------------------------------------------------------
// The doors that parse secret material: no error text carries the input.
// ---------------------------------------------------------------------------

/// The longest run of input characters an error's `Display` or `Debug` may
/// carry. Three: the one character and its position the cold read of #851
/// saw (`Invalid character 'z' at position 31`), and short coincidences of
/// an error's own words with the input (`er `, a length's digits), while no
/// four characters of a secret's text are allowed through, so no BIP-39 word
/// (each fixed by its first four letters), no base58 or hex run longer than
/// 18 bits, and no echo of the input as a whole.
const WINDOW_BOUND: usize = 3;

/// A fixed, public test scalar of full entropy (no literal secret text in
/// the tree): SHA-256 of the file's name.
fn door_key() -> PrivateKey {
    let bytes = bsv_rs::primitives::sha256(b"tests/secret_debug.rs doors");
    PrivateKey::from_bytes(&bytes).expect("a scalar below the order")
}

/// The malformed forms of a secret text: one character changed, one
/// dropped, one added (an out-of-alphabet and an in-alphabet one), a
/// separator moved (or two characters swapped where none is), the text
/// truncated and doubled.
fn text_mutants(s: &str, sep: Option<char>) -> Vec<(&'static str, String)> {
    let chars: Vec<char> = s.chars().collect();
    let mut mid = chars.len() / 2;
    while sep.is_some_and(|c| chars[mid] == c) {
        mid += 1;
    }
    let with = |f: &dyn Fn(&mut Vec<char>)| {
        let mut c = chars.clone();
        f(&mut c);
        c.into_iter().collect::<String>()
    };
    let changed = with(&|c| c[mid] = if c[mid] == '2' { '3' } else { '2' });
    let moved = match sep.and_then(|c| chars.iter().position(|x| *x == c)) {
        Some(p) if p + 1 < chars.len() => with(&|c| c.swap(p, p + 1)),
        _ => with(&|c| c.swap(mid, mid + 1)),
    };
    vec![
        ("changed", changed),
        (
            "dropped",
            with(&|c| {
                c.remove(mid);
            }),
        ),
        ("added out of alphabet", with(&|c| c.insert(mid, '~'))),
        ("added in alphabet", with(&|c| c.insert(mid, '2'))),
        ("separator moved", moved),
        ("truncated", chars[..chars.len() / 2].iter().collect()),
        ("doubled", format!("{s}{s}")),
    ]
}

/// The malformed forms of secret bytes.
fn byte_mutants(b: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mid = b.len() / 2;
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut c = b.to_vec();
        f(&mut c);
        c
    };
    vec![
        ("changed", with(&|c| c[mid] ^= 0xff)),
        (
            "dropped",
            with(&|c| {
                c.remove(mid);
            }),
        ),
        ("added", with(&|c| c.insert(mid, 0x5a))),
        ("swapped", with(&|c| c.swap(mid, mid + 1))),
        ("truncated", b[..mid].to_vec()),
        ("doubled", [b, b].concat()),
        ("all ones", vec![0xff; b.len()]),
    ]
}

/// The first run of more than `WINDOW_BOUND` characters of `secret` found in
/// `out`, as a count and an offset (never the run itself).
fn shared_window(out: &str, secret: &str) -> Option<(usize, usize)> {
    if let Some(run) = secret.strip_prefix(DECIMAL) {
        return out.contains(run).then_some((run.len(), 0));
    }
    let s: Vec<char> = secret.chars().collect();
    let n = WINDOW_BOUND + 1;
    (0..s.len().saturating_sub(n - 1))
        .find(|&i| out.contains(&s[i..i + n].iter().collect::<String>()))
        .map(|i| (n, i))
}

/// The texts a byte secret is printed in: hex either case, and `{:?}`'s
/// decimal list as runs of three elements (`167, 24, 192`), since a window of
/// four characters of a decimal list (`192,`) is any error's length.
fn byte_texts(b: &[u8]) -> Vec<String> {
    let mut texts = vec![to_hex(b), to_hex(b).to_uppercase()];
    texts.extend(
        b.windows(3)
            .map(|w| format!("{DECIMAL}{}, {}, {}", w[0], w[1], w[2])),
    );
    texts
}

/// Marks a secret text matched whole, never by its windows: a run of a
/// decimal byte list.
const DECIMAL: char = '\u{1}';

/// One door's verdict on one input: the error's texts, or `None` when the
/// input parsed.
fn error_texts<T>(r: bsv_rs::Result<T>) -> Option<[String; 3]> {
    r.err()
        .map(|e| [e.to_string(), format!("{e:?}"), format!("{e:#?}")])
}

/// One door on one input: the door, the case, the error's texts (`None` when
/// the input parsed), the secret texts they must not carry.
type Row = (String, &'static str, Option<[String; 3]>, Vec<String>);

#[test]
fn no_door_that_parses_secret_material_echoes_its_input_in_an_error() {
    use bsv_rs::compat::bip39::Language;
    use bsv_rs::primitives::bsv::KeyShares;

    let key = door_key();
    let key_bytes = key.to_bytes();
    let wif = key.to_wif();
    let xprv = ExtendedKey::new_master(&key_bytes, Network::Mainnet)
        .expect("seed")
        .to_string();
    let shares =
        split_private_key_with(&key, 2, 3, &[[0x42; 32]], &[0x5e; 64], &DRAWS).expect("split");
    let backup = shares.to_backup_format().expect("written");
    let entropy = bsv_rs::primitives::sha256(b"tests/secret_debug.rs entropy");

    // (door, case, the error's texts, the secret texts it must not carry)
    let mut rows: Vec<Row> = Vec::new();
    let mut texts_of_key = byte_texts(&key_bytes);
    texts_of_key.push(wif.clone());

    for (case, m) in text_mutants(&to_hex(&key_bytes), None) {
        let mut secret = texts_of_key.clone();
        secret.push(m.clone());
        rows.push((
            "PrivateKey::from_hex".into(),
            case,
            error_texts(PrivateKey::from_hex(&m)),
            secret.clone(),
        ));
        rows.push((
            "P256PrivateKey::from_hex".into(),
            case,
            error_texts(P256PrivateKey::from_hex(&m)),
            secret,
        ));
    }
    for (case, m) in text_mutants(&wif, None) {
        let mut secret = texts_of_key.clone();
        secret.push(m.clone());
        rows.push((
            "PrivateKey::from_wif".into(),
            case,
            error_texts(PrivateKey::from_wif(&m)),
            secret,
        ));
    }
    for (case, m) in byte_mutants(&key_bytes) {
        let mut secret = texts_of_key.clone();
        secret.extend(byte_texts(&m));
        rows.push((
            "PrivateKey::from_bytes".into(),
            case,
            error_texts(PrivateKey::from_bytes(&m)),
            secret.clone(),
        ));
        rows.push((
            "P256PrivateKey::from_bytes".into(),
            case,
            error_texts(P256PrivateKey::from_bytes(&m)),
            secret.clone(),
        ));
        rows.push((
            "SymmetricKey::from_bytes".into(),
            case,
            error_texts(SymmetricKey::from_bytes(&m)),
            secret,
        ));
    }
    let mut texts_of_xprv = texts_of_key.clone();
    texts_of_xprv.push(xprv.clone());
    for (case, m) in text_mutants(&xprv, None) {
        let mut secret = texts_of_xprv.clone();
        secret.push(m.clone());
        rows.push((
            "ExtendedKey::from_string".into(),
            case,
            error_texts(ExtendedKey::from_string(&m)),
            secret,
        ));
    }
    for language in [
        Language::ChineseSimplified,
        Language::ChineseTraditional,
        Language::Czech,
        Language::English,
        Language::French,
        Language::Italian,
        Language::Japanese,
        Language::Korean,
        Language::Spanish,
    ] {
        let m = Mnemonic::from_entropy_with_language(&entropy[..16], language).expect("entropy");
        let phrase = m.phrase();
        let sep = phrase.chars().find(|c| c.is_whitespace());
        let mut secret = mnemonic_secrets(&m);
        secret.push(phrase.clone());
        for (case, t) in text_mutants(&phrase, sep) {
            let mut s = secret.clone();
            s.push(t.clone());
            let door = format!("Mnemonic::from_phrase_with_language({language:?})");
            rows.push((
                door,
                case,
                error_texts(Mnemonic::from_phrase_with_language(&t, language)),
                s.clone(),
            ));
            if language == Language::English {
                rows.push((
                    "Mnemonic::from_phrase".into(),
                    case,
                    error_texts(Mnemonic::from_phrase(&t)),
                    s.clone(),
                ));
                rows.push((
                    "Mnemonic::from_binary".into(),
                    case,
                    error_texts(Mnemonic::from_binary(t.as_bytes())),
                    s,
                ));
            }
        }
    }
    let mut texts_of_entropy = byte_texts(&entropy);
    texts_of_entropy.extend(byte_texts(&entropy[..16]));
    for (case, m) in byte_mutants(&entropy[..16]) {
        let mut secret = texts_of_entropy.clone();
        secret.extend(byte_texts(&m));
        rows.push((
            "Mnemonic::from_entropy".into(),
            case,
            error_texts(Mnemonic::from_entropy(&m)),
            secret.clone(),
        ));
        rows.push((
            "Mnemonic::from_entropy_with_language".into(),
            case,
            error_texts(Mnemonic::from_entropy_with_language(&m, Language::Japanese)),
            secret,
        ));
    }
    // A share's secret is its y; x, the threshold and the integrity are public.
    for point in &shares.points {
        let y = point
            .to_point_string()
            .split('.')
            .nth(1)
            .expect("y")
            .to_owned();
        let mut secret = share_secrets(point);
        secret.push(y);
        secret.extend(texts_of_key.clone());
        for (case, m) in text_mutants(&backup[0], Some('.')) {
            let all = [m.clone(), backup[1].clone()];
            rows.push((
                "KeyShares::from_backup_format".into(),
                case,
                error_texts(
                    KeyShares::from_backup_format(&all).and_then(|s| s.recover_private_key()),
                ),
                secret.clone(),
            ));
        }
        for (case, m) in text_mutants(&point.to_point_string(), Some('.')) {
            rows.push((
                "PointInFiniteField::from_string".into(),
                case,
                error_texts(PointInFiniteField::from_string(&m)),
                secret.clone(),
            ));
        }
    }
    // The legacy reader (#854) on a backup bsv-rs 0.8.5 wrote of the key 1
    // (`tests/shamir_backup_854.rs`' constant): a share's y is its secret.
    let legacy = [
        "2.GUibg2QL6Zip4QDpTAiPhM5zaMAxoXJBWFxVszov1Wch.2.GuMr",
        "4.CyX42Vhnhbgu336cu9nahbewE4EEv9kMYfxqv9oJ4JDj.2.GuMr",
    ];
    for share in legacy {
        let y = share.split('.').nth(1).expect("y").to_owned();
        let other = legacy.iter().find(|s| **s != share).expect("the other");
        for (case, m) in text_mutants(share, Some('.')) {
            let all = [m, other.to_string()];
            rows.push((
                "recover_private_key_from_legacy_backup".into(),
                case,
                error_texts(
                    bsv_rs::primitives::bsv::shamir::recover_private_key_from_legacy_backup(&all),
                ),
                vec![y.clone(), share.to_owned()],
            ));
        }
    }

    let mut bad = Vec::new();
    let mut refused = 0;
    for (door, case, errors, secrets) in &rows {
        let Some(errors) = errors else { continue };
        refused += 1;
        for text in errors {
            for secret in secrets {
                if let Some((n, at)) = shared_window(text, secret) {
                    bad.push(format!(
                        "{door} ({case}): its error carries {n} characters of the input (from offset {at} of a secret text of {} chars): {}",
                        secret.chars().count(),
                        masked(text, secrets)
                    ));
                }
            }
        }
    }
    bad.sort();
    bad.dedup();
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(
        refused * 2 > rows.len(),
        "most malformed inputs are refused: {refused} of {}",
        rows.len()
    );
}

// ---------------------------------------------------------------------------
// The service credentials: present or absent, never the value or its length.
// ---------------------------------------------------------------------------

/// A credential derived at run time (no literal in the tree), its length 64.
fn credential(label: &str) -> String {
    to_hex(&bsv_rs::primitives::sha256(label.as_bytes()))
}

/// `{:?}` and `{:#?}` of `value` carry no run of more than `WINDOW_BOUND`
/// characters of `secret`, nor its length, and say it is there.
fn assert_credential_hidden<T: std::fmt::Debug>(what: &str, value: &T, secret: &str) {
    for out in both(value) {
        assert!(
            shared_window(&out, secret).is_none(),
            "{what}: Debug carries the credential: {}",
            out.replace(secret, "xxxx")
        );
        assert!(!out.contains("64"), "{what}: Debug carries a length: {out}");
        assert!(out.contains("<redacted>"), "{what}: {out}");
        assert!(out.starts_with(what), "{what}: {out}");
    }
}

#[test]
#[allow(deprecated)] // ArcConfig, deprecated since 0.9.0 (#350)
fn an_arc_config_debug_prints_no_api_key() {
    use bsv_rs::transaction::ArcConfig;
    let key = credential("arc api key");
    let config = ArcConfig {
        api_key: Some(key.clone()),
        ..ArcConfig::default()
    };
    assert_credential_hidden("ArcConfig", &config, &key);
    assert!(format!("{config:?}").contains("https://arc.taal.com"));
    let none = format!("{:?}", ArcConfig::default());
    assert!(none.contains("api_key: None"), "{none}");
}

#[test]
fn a_teranode_config_debug_prints_no_api_key() {
    use bsv_rs::transaction::TeranodeConfig;
    let key = credential("teranode api key");
    let config = TeranodeConfig {
        url: "https://teranode.invalid".into(),
        api_key: Some(key.clone()),
        timeout_ms: 7,
    };
    assert_credential_hidden("TeranodeConfig", &config, &key);
    assert_eq!(
        format!("{config:?}"),
        "TeranodeConfig { url: \"https://teranode.invalid\", api_key: Some(<redacted>), timeout_ms: 7 }"
    );
}

#[test]
fn a_whatsonchain_config_debug_prints_no_api_key() {
    use bsv_rs::transaction::WocBroadcastConfig;
    let key = credential("woc api key");
    let config = WocBroadcastConfig {
        api_key: Some(key.clone()),
        base_url: Some("https://woc.invalid".into()),
        ..WocBroadcastConfig::default()
    };
    assert_credential_hidden("WocBroadcastConfig", &config, &key);
    assert!(format!("{config:?}").contains("https://woc.invalid"));
}

#[test]
fn a_live_policy_config_debug_prints_no_api_key() {
    use bsv_rs::transaction::LivePolicyConfig;
    let key = credential("live policy api key");
    let config = LivePolicyConfig {
        policy_url: "https://policy.invalid/v1/policy".into(),
        api_key: Some(key.clone()),
        ..LivePolicyConfig::default()
    };
    assert_credential_hidden("LivePolicyConfig", &config, &key);
    assert!(format!("{config:?}").contains("cache_ttl: 300s"));
}

#[test]
fn a_block_headers_service_config_debug_prints_no_auth_token() {
    use bsv_rs::transaction::BlockHeadersServiceConfig;
    let token = credential("headers auth token");
    let config = BlockHeadersServiceConfig {
        auth_token: Some(token.clone()),
        ..BlockHeadersServiceConfig::default()
    };
    assert_credential_hidden("BlockHeadersServiceConfig", &config, &token);
    let none = format!("{:#?}", BlockHeadersServiceConfig::default());
    assert!(none.contains("auth_token: None"), "{none}");
}

/// The header names whose values are credentials by use, not by any list a
/// redaction could keep: the first fold's `Authorization` and the six the
/// second fold's class names (an invented one among them), each with a value
/// of its own, in three letter cases (`credential` of the name and the case).
#[cfg(feature = "auth")]
const SECRET_HEADERS: &[&str] = &[
    "Authorization",
    "Cookie",
    "Set-Cookie",
    "Proxy-Authorization",
    "X-API-Key",
    "X-Auth-Token",
    "X-Whatever-Secret",
    "X-Bsv-Topic",
];

/// Names whose values are public by their protocol, with a value each must
/// still print (`debug_redact::PUBLIC_HEADERS`).
#[cfg(feature = "auth")]
const PUBLIC_HEADERS: &[(&str, &str)] = &[
    ("Content-Type", "application/json"),
    ("content-length", "1234"),
    ("ACCEPT", "text/plain"),
    ("x-bsv-auth-identity-key", "visible-identity"),
    ("X-BSV-AUTH-NONCE", "visible-nonce"),
];

/// Every secret header in three cases (`(name, value)`), then the public.
#[cfg(feature = "auth")]
fn headers() -> (Vec<(String, String)>, Vec<String>) {
    let mut list = Vec::new();
    let mut values = Vec::new();
    for name in SECRET_HEADERS {
        for case in [name.to_string(), name.to_lowercase(), name.to_uppercase()] {
            let value = credential(&format!("header {case}"));
            list.push((case, value.clone()));
            values.push(value);
        }
    }
    for (name, value) in PUBLIC_HEADERS {
        list.push(((*name).into(), (*value).into()));
    }
    (list, values)
}

#[cfg(feature = "auth")]
#[test]
fn the_http_shapes_holding_headers_print_no_header_value_but_the_public_ones() {
    use bsv_rs::auth::transports::http::{HttpRequest, HttpResponse};
    use bsv_rs::auth::{AuthFetchOptions, Response};
    let (list, values) = headers();
    let query = credential("request search");
    let request = HttpRequest {
        request_id: [0; 32],
        method: "POST".into(),
        path: "/a".into(),
        search: format!("?api_key={query}"),
        headers: list.clone(),
        body: vec![],
    };
    let response = HttpResponse {
        request_id: [0; 32],
        status: 200,
        headers: list.clone(),
        body: vec![],
    };
    let options = AuthFetchOptions::default().with_headers(list.clone().into_iter().collect());
    let answer = Response {
        status: 200,
        headers: list.clone().into_iter().collect(),
        body: vec![],
    };
    let redacted = SECRET_HEADERS.len() * 3;
    let mut secrets = values.clone();
    secrets.push(query.clone());
    for (what, outs) in [
        ("HttpRequest", both(&request)),
        ("HttpResponse", both(&response)),
        ("AuthFetchOptions", both(&options)),
        ("Response", both(&answer)),
    ] {
        for out in outs {
            for value in &secrets {
                assert!(
                    shared_window(&out, value).is_none(),
                    "{what}: Debug carries a header value: {}",
                    masked(&out, &secrets)
                );
            }
            assert!(out.starts_with(what), "{what}: {out}");
            for (name, _) in &list {
                assert!(
                    out.contains(&format!("\"{name}\"")),
                    "{what}: {name}: {out}"
                );
            }
            for (_, value) in PUBLIC_HEADERS {
                assert!(
                    out.contains(&format!("\"{value}\"")),
                    "{what}: {value}: {out}"
                );
            }
            let search = usize::from(what == "HttpRequest");
            assert_eq!(
                out.matches("<redacted>").count(),
                redacted + search,
                "{what}: {out}"
            );
        }
    }
}

/// A URL carrying a credential as user info and in its query and fragment,
/// each part a credential of its own, and the parts that must still print.
fn credential_url(label: &str) -> (String, Vec<String>) {
    let user = credential(&format!("{label} user"));
    let pass = credential(&format!("{label} pass"));
    let key = credential(&format!("{label} query"));
    let frag = credential(&format!("{label} fragment"));
    (
        format!("https://{user}:{pass}@host.invalid:8443/v1/path?api_key={key}#{frag}"),
        vec![user, pass, key, frag],
    )
}

/// `{:?}` and `{:#?}` of `value` carry none of the URL's credentials and
/// still carry its scheme, host, port and path.
fn assert_url_hidden<T: std::fmt::Debug>(what: &str, value: &T, secrets: &[String]) {
    for out in both(value) {
        for secret in secrets {
            assert!(
                shared_window(&out, secret).is_none(),
                "{what}: Debug carries the URL's credential: {}",
                masked(&out, secrets)
            );
        }
        assert!(!out.contains("api_key="), "{what}: {out}");
        assert!(
            out.contains("\"https://<redacted>@host.invalid:8443/v1/path?<redacted>#<redacted>\""),
            "{what}: {out}"
        );
        assert!(out.starts_with(what), "{what}: {out}");
    }
}

#[test]
#[allow(deprecated)] // ArcConfig, deprecated since 0.9.0 (#350)
fn the_service_configurations_print_no_credential_in_their_url() {
    use bsv_rs::transaction::{
        ArcConfig, BlockHeadersServiceConfig, LivePolicyConfig, TeranodeConfig, WocBroadcastConfig,
    };
    let (url, secrets) = credential_url("arc");
    let arc = ArcConfig {
        url,
        ..ArcConfig::default()
    };
    assert_url_hidden("ArcConfig", &arc, &secrets);
    let (url, secrets) = credential_url("teranode");
    let teranode = TeranodeConfig {
        url,
        api_key: None,
        timeout_ms: 7,
    };
    assert_url_hidden("TeranodeConfig", &teranode, &secrets);
    let (url, secrets) = credential_url("woc");
    let woc = WocBroadcastConfig {
        base_url: Some(url),
        ..WocBroadcastConfig::default()
    };
    assert_url_hidden("WocBroadcastConfig", &woc, &secrets);
    let (url, secrets) = credential_url("policy");
    let policy = LivePolicyConfig {
        policy_url: url,
        ..LivePolicyConfig::default()
    };
    assert_url_hidden("LivePolicyConfig", &policy, &secrets);
    let (url, secrets) = credential_url("headers");
    let headers = BlockHeadersServiceConfig {
        base_url: url,
        ..BlockHeadersServiceConfig::default()
    };
    assert_url_hidden("BlockHeadersServiceConfig", &headers, &secrets);
    // Text that is no URL prints nothing of itself.
    let junk = credential("not a url");
    let teranode = TeranodeConfig {
        url: format!("{junk}@host"),
        api_key: None,
        timeout_ms: 7,
    };
    let out = format!("{teranode:?}");
    assert!(shared_window(&out, &junk).is_none(), "{out}");
    assert!(out.contains("url: <unparsed url>"), "{out}");
}

#[test]
fn an_acquire_certificate_args_prints_no_credential_in_its_certifier_url() {
    use bsv_rs::wallet::{AcquireCertificateArgs, AcquisitionProtocol};
    let (url, secrets) = credential_url("certifier");
    let args = AcquireCertificateArgs {
        certificate_type: "dHlwZQ==".into(),
        certifier: "02aa".into(),
        acquisition_protocol: AcquisitionProtocol::Issuance,
        fields: Default::default(),
        serial_number: None,
        revocation_outpoint: None,
        signature: None,
        certifier_url: Some(url),
        keyring_revealer: None,
        keyring_for_subject: None,
        privileged: None,
        privileged_reason: None,
    };
    assert_url_hidden("AcquireCertificateArgs", &args, &secrets);
    assert!(format!("{args:?}").contains("certifier: \"02aa\""));
}

#[cfg(feature = "websocket")]
#[test]
fn the_websocket_options_print_no_credential_in_their_url() {
    use bsv_rs::auth::transports::WebSocketTransportOptions;
    let (url, secrets) = credential_url("websocket");
    let options = WebSocketTransportOptions::new(url).with_read_deadline_secs(Some(5));
    assert_url_hidden("WebSocketTransportOptions", &options, &secrets);
}

#[test]
fn a_malformed_share_is_named_by_its_index_not_echoed() {
    use bsv_rs::primitives::bsv::KeyShares;
    let key = door_key();
    let shares =
        split_private_key_with(&key, 2, 3, &[[0x42; 32]], &[0x5e; 64], &DRAWS).expect("split");
    let backup = shares.to_backup_format().expect("written");
    let point = shares.points[1].to_point_string();
    // A share with a fifth part and a point with a third: the text carries y.
    let bad = [backup[0].clone(), format!("{}.{}", backup[1], backup[1])];
    let err = KeyShares::from_backup_format(&bad).expect_err("five parts");
    let mut secrets = share_secrets(&shares.points[1]);
    secrets.push(bad[1].clone());
    let outputs = [err.to_string(), format!("{err:?}"), format!("{err:#?}")];
    assert_hides("KeyShares::from_backup_format", &outputs, &secrets);
    // The reference's words (`ts-stack@edf6e03` `PrivateKey.ts:69-75`).
    assert_eq!(
        err.to_string(),
        "cryptographic operation failed: Invalid share format in share 1. Expected format: \"x.y.t.i\""
    );
    let err =
        PointInFiniteField::from_string(&format!("{point}.{point}")).expect_err("three parts");
    let outputs = [err.to_string(), format!("{err:?}"), format!("{err:#?}")];
    assert_hides(
        "PointInFiniteField::from_string",
        &outputs,
        &share_secrets(&shares.points[1]),
    );
    // The reference's words (`Polynomial.ts:32-45`).
    assert_eq!(
        err.to_string(),
        "invalid base58 string: Finite-field point must use a bounded canonical Base58 representation"
    );
}

// ---------------------------------------------------------------------------
// The ECDH shared secret (#843d6): every door that derives it returns a type
// whose `Debug` prints no secret.
// ---------------------------------------------------------------------------

/// A dependent's struct that derives `Debug` over a shared secret (generic,
/// so the test reads the same before and after the type changed).
#[derive(Debug)]
#[allow(dead_code)] // Read only through Debug.
struct HeldSecret<T> {
    shared: T,
}

/// The texts the shared secret is written in: its compressed hex and x's hex
/// (either case), and `byte_texts` of the 33 bytes.
fn shared_secret_texts(compressed: &[u8; 33], x: &[u8; 32]) -> Vec<String> {
    let mut texts = byte_texts(compressed);
    texts.push(to_hex(x));
    texts.push(to_hex(x).to_uppercase());
    texts
}

fn assert_no_shared_window(what: &str, outputs: &[String], secrets: &[String]) {
    for out in outputs {
        for secret in secrets {
            assert!(
                shared_window(out, secret).is_none(),
                "{what}: Debug carries a run of the shared secret {:?}",
                shared_window(out, secret)
            );
        }
    }
}

#[test]
fn the_ecdh_shared_secret_is_not_printed_by_debug_843d6() {
    use bsv_rs::wallet::{Counterparty, KeyDeriverApi};

    let alice = door_key();
    let bob = PrivateKey::from_bytes(&bsv_rs::primitives::sha256(b"tests/secret_debug.rs ecdh"))
        .expect("a scalar below the order");
    let deriver = KeyDeriver::new(Some(alice.clone()));
    let cached = CachedKeyDeriver::new(Some(alice.clone()), None);
    let other = Counterparty::Other(bob.public_key());

    let doors = [
        (
            "PrivateKey::derive_shared_secret",
            alice.derive_shared_secret(&bob.public_key()).expect("ecdh"),
        ),
        (
            "PublicKey::derive_shared_secret",
            bob.public_key().derive_shared_secret(&alice).expect("ecdh"),
        ),
        (
            "KeyDeriver::reveal_counterparty_secret",
            deriver.reveal_counterparty_secret(&other).expect("reveal"),
        ),
        (
            "KeyDeriverApi::reveal_counterparty_secret (KeyDeriver)",
            KeyDeriverApi::reveal_counterparty_secret(&deriver, &other).expect("reveal"),
        ),
        (
            "KeyDeriverApi::reveal_counterparty_secret (CachedKeyDeriver)",
            KeyDeriverApi::reveal_counterparty_secret(&cached, &other).expect("reveal"),
        ),
    ];
    let compressed = doors[0].1.to_compressed();
    let secrets = shared_secret_texts(&compressed, &doors[0].1.x());
    for (door, shared) in &doors {
        assert_eq!(shared.to_compressed(), compressed, "{door}: the same point");
        assert_no_shared_window(door, &both(shared), &secrets);
        let held = HeldSecret {
            shared: shared.clone(),
        };
        assert_no_shared_window(&format!("a struct holding {door}"), &both(&held), &secrets);
        // The exact text (#843d6's fold, the strength read's S7): a `Debug`
        // that wrote the point in a form the windows above do not read
        // (base64, y) is refused here.
        assert_eq!(format!("{shared:?}"), "SharedSecret { .. }", "{door}");
        assert_eq!(format!("{shared:#?}"), "SharedSecret { .. }", "{door}");
        assert_eq!(
            format!("{held:?}"),
            "HeldSecret { shared: SharedSecret { .. } }",
            "{door}"
        );
        assert_eq!(
            format!("{held:#?}"),
            "HeldSecret {\n    shared: SharedSecret { .. },\n}",
            "{door}"
        );
    }
}

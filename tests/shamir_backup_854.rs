//! #854: backup shares are BRC-140's (`key-derivation/0140.md` at
//! BRCs@f7f1520), written and read as the reference writes and reads them
//! (`ts-stack@edf6e03` `PrivateKey.ts:12-118,478-623`, `Polynomial.ts:32-49`),
//! against `vectors/shamir_backup_854.json` (`support/shamir_backup_854.mjs`,
//! Node v22.18.0): the reference's shares for three keys at 2 of 3 and 3 of 5
//! recovered from every threshold-sized subset; the reader's refusals cell for
//! cell in its words; the writer's and `fromKeyShares`' refusals of hand-built
//! collections; this crate's shares, written by `split_private_key_with` with
//! fixed draws, recovered by the reference. And the legacy reader,
//! `recover_private_key_from_legacy_backup`, on share sets the published
//! bsv-rs 0.8.5 wrote.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::polynomial::PointInFiniteField;
use bsv_rs::primitives::bsv::shamir::{
    recover_private_key_from_legacy_backup, split_private_key, split_private_key_with, KeyShares,
};
use bsv_rs::primitives::encoding::to_base58;
use bsv_rs::primitives::{BigNumber, PrivateKey};
use bsv_rs::Error;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/shamir_backup_854.json");

/// Share sets written by the published crate: a scratch cargo project
/// against `bsv-rs = "=0.8.5"` from crates.io (`Cargo.lock`: `bsv-rs`
/// 0.8.5, `registry+https://github.com/rust-lang/crates.io-index`), its
/// `split_private_key(&key, t, n).to_backup_format()` for the keys 1,
/// n - 1 and sha256 of the vector's label, at 2 of 3 and 3 of 5, run once on
/// 2026-11-10 (`/Volumes/Lanes/out/bsv-rs/fix-854-shamir-interop/legacy-085/`).
const LEGACY_085: &str = r#"[
 {
  "key": "one",
  "scalar_hex": "0000000000000000000000000000000000000000000000000000000000000001",
  "threshold": 2,
  "total": 3,
  "shares": [
   "2.GUibg2QL6Zip4QDpTAiPhM5zaMAxoXJBWFxVszov1Wch.2.GuMr",
   "3.Ej7prG44Q5hrYifDgAFVCUNTuChbrqXGXTxfu5Jc2uRD.2.GuMr",
   "4.CyX42Vhnhbgu336cu9nahbewE4EEv9kMYfxqv9oJ4JDj.2.GuMr"
  ]
 },
 {
  "key": "one",
  "scalar_hex": "0000000000000000000000000000000000000000000000000000000000000001",
  "threshold": 3,
  "total": 5,
  "shares": [
   "2.9TBYVS5UiRYU8Gc6qWDb6yjT6zP7cJfBmt4qtzeLskLK.3.GuMr",
   "3.DsBRGAZy3b6pTu1iNgnYQMpyCz5TFafdvYLYLnJDnCd9.3.GuMr",
   "4.EEzdKCUTzVg41tDqcYhru9HZJz61vq2MSyp6LMxdiMsW.3.GuMr",
   "5.AadAeXnyZ9GAnEEUZ5yYbL7DQzQoe3jLMCVVsjdagE5Q.3.GuMr",
   "6.2t53GAXVjXsAkw3dCJbbUvHwX13pPEnadCNkxuK4foEq.3.GuMr"
  ]
 },
 {
  "key": "n_minus_1",
  "scalar_hex": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
  "threshold": 2,
  "total": 3,
  "shares": [
   "2.HmRE69k7X36GA5WAPZxPgSgaAhf4v2PJFnaA9uHwuyP4.2.4pjT",
   "3.HJX5gWjdF2Skk5DuYxjVAgFo2uqkfNh9EPCvv9rexgcD.2.4pjT",
   "4.GqcwGsj8y1oFL4weiMWaeuq1u82SQizzCyqhgQRN1PqN.2.4pjT"
  ]
 },
 {
  "key": "n_minus_1",
  "scalar_hex": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
  "threshold": 3,
  "total": 5,
  "shares": [
   "2.EuBs1ak1HFpHJsREwaG6suG9m5naKYMvq12cPvJBQYty.3.4pjT",
   "3.4NNQ9HmMDK8ZR8MuDCMLWLco1LTmnxQ6GgMjjviz2jsc.3.4pjT",
   "4.3sBMPhaEPGRNTwPpGDdJGjyoHk9JL8G36Gt6HbKsiwty.3.4pjT",
   "5.DPcikpAeo7giTJWz6e5zB7MAcJq9w3wmHnbg2v6rVAy4.3.4pjT",
   "6.FiN8jqo1epBpp8wzVHZ72DvNiXt1rXPBPAZA7yjhLJGi.3.4pjT"
  ]
 },
 {
  "key": "sha_label",
  "scalar_hex": "f5df2dff4a4302977648902ae113f499a4295600582c75d85ceb84873d597e44",
  "threshold": 2,
  "total": 3,
  "shares": [
   "2.2kYgG8sG3ojhQcMzvBteJZ6Jp6UNdHVBaNpUzrUhk6rk.2.4VTm",
   "3.5BdTXEidGogeNpFUPN2gh7PjeMr5JpATPS438db22Hnc.2.4VTm",
   "4.7ciEnLZzVodbM28wrYAj5fhAUdDmzLqjCVHbGQhLJUiU.2.4VTm"
  ]
 },
 {
  "key": "sha_label",
  "scalar_hex": "f5df2dff4a4302977648902ae113f499a4295600582c75d85ceb84873d597e44",
  "threshold": 3,
  "total": 5,
  "shares": [
   "2.6qDtGR5UFJiPG43TLosYPmPzjKiimTBF3be74MjBnsbV.3.4VTm",
   "3.3EpwXYLXjNWMZUBu6ieixnhYhR5wAuKu88NgBZCdC6Zj.3.4VTm",
   "4.6mbSHCYg53uRujhGwvGSpHW48bqduKKyUxjy6b6vehem.3.4VTm",
   "5.HRXNXPhuGLucJrZatQihxFoX2sypxhBU86jyoTS6Agrb.3.4VTm",
   "6.HyJNmL4cXCn8Bk1Qh1qDBUoR9ksBbppHZVRPSEstkwN4.3.4VTm"
  ]
 }
]"#;

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("the vector")
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|s| s.as_str().expect("a string").to_string())
        .collect()
}

/// An error's words: the message the reference throws, without this crate's
/// variant prefix.
fn words(e: &Error) -> String {
    match e {
        Error::CryptoError(s) | Error::InvalidBase58(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A recorded answer, `{ ok, scalar_hex }` or `{ ok: false, error }`, as this
/// crate's result is written.
fn answer_of(r: &bsv_rs::Result<PrivateKey>) -> Value {
    match r {
        Ok(k) => serde_json::json!({ "ok": true, "scalar_hex": k.to_hex() }),
        Err(e) => serde_json::json!({ "ok": false, "error": words(e) }),
    }
}

fn recover(shares: &[String]) -> bsv_rs::Result<PrivateKey> {
    KeyShares::from_backup_format(shares)?.recover_private_key()
}

/// The canonical base58 text of a coordinate: its minimal bytes, `1` for zero.
fn field_text(value: &BigNumber) -> String {
    let bytes = value.to_bytes_be_min();
    if bytes.is_empty() {
        "1".to_string()
    } else {
        to_base58(&bytes)
    }
}

/// This crate's fixed draws for a split: the coefficients, the HMAC seed and
/// one 32-byte draw per share.
fn draws(threshold: usize, total: usize) -> (Vec<[u8; 32]>, [u8; 64], Vec<[u8; 32]>) {
    let coefficients = (1..threshold).map(|i| [0x10 + i as u8; 32]).collect();
    let fresh = (0..total).map(|i| [0xa0 + i as u8; 32]).collect();
    (coefficients, [0x5e; 64], fresh)
}

fn rust_split(scalar_hex: &str, threshold: usize, total: usize) -> Vec<String> {
    let key = PrivateKey::from_hex(scalar_hex).unwrap();
    let (c, seed, d) = draws(threshold, total);
    split_private_key_with(&key, threshold, total, &c, &seed, &d)
        .unwrap()
        .to_backup_format()
        .unwrap()
}

#[test]
fn the_references_shares_recover_their_keys_from_every_threshold_subset_854() {
    let v = vector();
    let splits = v["splits"].as_array().unwrap();
    assert_eq!(splits.len(), 6);
    let mut cells = 0;
    for s in splits {
        let shares = strings(&s["shares"]);
        for r in s["recoveries"].as_array().unwrap() {
            let picked: Vec<String> = r["indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| shares[i.as_u64().unwrap() as usize].clone())
                .collect();
            assert_eq!(
                answer_of(&recover(&picked)),
                r["answer"],
                "{} {:?}",
                s["key"],
                r["indices"]
            );
            let reversed: Vec<String> = picked.iter().rev().cloned().collect();
            assert_eq!(answer_of(&recover(&reversed)), r["reversed"]);
            assert_eq!(r["answer"]["scalar_hex"], s["scalar_hex"]);
            cells += 2;
        }
        assert_eq!(answer_of(&recover(&shares)), s["all"]);
    }
    assert_eq!(cells, 2 * 3 * (3 + 10));
}

/// #854's fix: the read cells whose sets carry a share at x = 0 or a
/// repeated x, refused at the door where the recording reads them. The vector
/// keeps the recording's verdicts (it is read, never edited); this crate's
/// words for those cells are named here.
fn carved_854(name: &str) -> Option<&'static str> {
    match name {
        "same_share_twice" | "duplicate_past_the_threshold" | "shares_255_leading_distinct" => {
            Some("Duplicate share detected, each must be unique.")
        }
        "x_zero" => Some("Zero x coordinate in share 0"),
        _ => None,
    }
}

#[test]
fn the_readers_refusals_are_the_references_in_its_words_854() {
    let v = vector();
    let reads = v["reads"].as_array().unwrap();
    let mut differ = Vec::new();
    let mut carved = 0;
    for cell in reads {
        let shares = strings(&cell["shares"]);
        let name = cell["name"].as_str().unwrap();
        let parse = match KeyShares::from_backup_format(&shares) {
            Ok(_) => serde_json::json!({ "ok": true }),
            Err(e) => serde_json::json!({ "ok": false, "error": words(&e) }),
        };
        let answer = answer_of(&recover(&shares));
        if let Some(ours) = carved_854(name) {
            let refusal = serde_json::json!({ "ok": false, "error": ours });
            assert_eq!(parse, refusal, "{name}");
            assert_eq!(answer, refusal, "{name}");
            carved += 1;
            continue;
        }
        if parse != cell["parse"] || answer != cell["answer"] {
            differ.push((cell["name"].clone(), parse, answer));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
    assert_eq!(carved, 3);
    assert_eq!(reads.len(), 46);
}

#[test]
fn a_backup_written_by_bsv_rs_0_8_5_is_refused_by_the_standard_reader_854() {
    let legacy: Value = serde_json::from_str(LEGACY_085).unwrap();
    for s in legacy.as_array().unwrap() {
        let e = KeyShares::from_backup_format(&strings(&s["shares"])).unwrap_err();
        assert_eq!(words(&e), "Invalid canonical share data in share 0");
    }
}

#[test]
fn the_writer_refuses_what_the_reader_refuses_in_the_references_words_854() {
    let v = vector();
    let w = &v["writer"];
    let base = v["splits"].as_array().unwrap()[0].clone();
    let shares = strings(&base["shares"]);
    let read = || KeyShares::from_backup_format(&shares[..2]).unwrap();
    let integrity = base["integrity"].as_str().unwrap().to_string();
    let written = |k: KeyShares| match k.to_backup_format() {
        Ok(lines) => serde_json::json!({ "ok": true, "lines": lines }),
        Err(e) => serde_json::json!({ "ok": false, "error": words(&e) }),
    };
    assert_eq!(written(read()), w["as_read"]);
    assert_eq!(
        written(KeyShares::new(vec![], 2, integrity.clone())),
        w["no_points"]
    );
    assert_eq!(
        written(KeyShares::new(read().points, 1, integrity.clone())),
        w["threshold_1"]
    );
    assert_eq!(
        written(KeyShares::new(read().points, 256, integrity.clone())),
        w["threshold_256"]
    );
    assert_eq!(
        written(KeyShares::new(read().points, 2, "GuMr".into())),
        w["integrity_legacy"]
    );
    let mut at_p = read();
    at_p.points[0].y = BigNumber::secp256k1_prime();
    assert_eq!(written(at_p), w["y_at_p"]);

    let k = &v["key_shares"];
    let recovered = |ks: KeyShares| answer_of(&ks.recover_private_key());
    assert_eq!(
        recovered(KeyShares::new(read().points, 3, integrity.clone())),
        k["threshold_above_points"]
    );
    assert_eq!(
        recovered(KeyShares::new(read().points, 2, "GuMr".into())),
        k["integrity_legacy"]
    );
    let mut x_at_p = read();
    x_at_p.points[0].x = BigNumber::secp256k1_prime();
    assert_eq!(recovered(x_at_p), k["x_at_p"]);
}

#[test]
fn this_crates_shares_are_read_by_the_reference_854() {
    let v = vector();
    let rust = v["rust_written"].as_array().unwrap();
    assert_eq!(rust.len(), 6);
    for s in rust {
        let (t, n) = (
            s["threshold"].as_u64().unwrap() as usize,
            s["total"].as_u64().unwrap() as usize,
        );
        let shares = rust_split(s["scalar_hex"].as_str().unwrap(), t, n);
        assert_eq!(
            shares,
            strings(&s["shares"]),
            "the writer moved from the recorded bytes"
        );
        for r in s["recoveries"].as_array().unwrap() {
            assert_eq!(
                r["answer"]["ok"], true,
                "the reference refused {:?}",
                r["indices"]
            );
            assert_eq!(r["answer"]["scalar_hex"], s["scalar_hex"]);
            let picked: Vec<String> = r["indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| shares[i.as_u64().unwrap() as usize].clone())
                .collect();
            assert_eq!(answer_of(&recover(&picked)), r["answer"]);
        }
    }
}

#[test]
fn the_writer_writes_brc_140s_tag_and_drawn_coordinates_854() {
    let v = vector();
    for s in v["splits"].as_array().unwrap() {
        let key = PrivateKey::from_hex(s["scalar_hex"].as_str().unwrap()).unwrap();
        let (t, n) = (
            s["threshold"].as_u64().unwrap() as usize,
            s["total"].as_u64().unwrap() as usize,
        );
        let a = split_private_key(&key, t, n).unwrap();
        let b = split_private_key(&key, t, n).unwrap();
        // The reference's tag for the same key.
        assert_eq!(a.integrity, s["integrity"].as_str().unwrap());
        // Coordinates drawn, never 1..n, and no two splits sharing one.
        for p in &a.points {
            assert!(p.x.compare(&BigNumber::from_u64(256)).is_gt());
            assert!(b.points.iter().all(|q| q.x != p.x));
        }
        let lines = a.to_backup_format().unwrap();
        assert_eq!(
            KeyShares::from_backup_format(&lines)
                .unwrap()
                .to_backup_format()
                .unwrap(),
            lines
        );
        assert_eq!(recover(&lines[n - t..]).unwrap().to_bytes(), key.to_bytes());
    }
}

#[test]
fn the_split_refuses_its_parameters_in_the_references_words_854() {
    let key = PrivateKey::from_bytes(&[5; 32]).unwrap();
    let cases: [(usize, usize, &str); 5] = [
        (1, 3, "threshold must be at least 2"),
        (2, 1, "totalShares must be at least 2"),
        (
            4,
            3,
            "threshold should be less than or equal to totalShares",
        ),
        (2, 256, "threshold and totalShares cannot exceed 255"),
        (256, 256, "threshold and totalShares cannot exceed 255"),
    ];
    for (t, n, w) in cases {
        assert_eq!(
            words(&split_private_key(&key, t, n).unwrap_err()),
            w,
            "{t} of {n}"
        );
    }
    assert_eq!(split_private_key(&key, 255, 255).unwrap().points.len(), 255);
}

#[test]
fn split_private_key_with_runs_out_of_draws_as_an_error_854() {
    let key = PrivateKey::from_bytes(&[5; 32]).unwrap();
    let (c, seed, d) = draws(2, 3);
    let e = split_private_key_with(&key, 2, 3, &c, &seed, &d[..2]).unwrap_err();
    assert_eq!(words(&e), "Shamir coordinate draws exhausted");
    // The same draws again: the same shares; a seed differing: none shared.
    let a = split_private_key_with(&key, 2, 3, &c, &seed, &d).unwrap();
    let b = split_private_key_with(&key, 2, 3, &c, &seed, &d).unwrap();
    assert_eq!(a.to_backup_format().unwrap(), b.to_backup_format().unwrap());
    let other = split_private_key_with(&key, 2, 3, &c, &[0x5f; 64], &d).unwrap();
    assert!(a
        .points
        .iter()
        .all(|p| other.points.iter().all(|q| q.x != p.x)));
}

#[test]
fn a_backup_written_by_bsv_rs_0_8_5_is_recovered_by_the_legacy_reader_854() {
    let legacy: Value = serde_json::from_str(LEGACY_085).unwrap();
    let mut cells = 0;
    for s in legacy.as_array().unwrap() {
        let shares = strings(&s["shares"]);
        let t = s["threshold"].as_u64().unwrap() as usize;
        let want = s["scalar_hex"].as_str().unwrap();
        // Every threshold-sized window, every share and the set reversed.
        for start in 0..=shares.len() - t {
            let key = recover_private_key_from_legacy_backup(&shares[start..start + t]).unwrap();
            assert_eq!(key.to_hex(), want);
            cells += 1;
        }
        let reversed: Vec<String> = shares.iter().rev().cloned().collect();
        assert_eq!(
            recover_private_key_from_legacy_backup(&reversed)
                .unwrap()
                .to_hex(),
            want
        );
        assert_eq!(
            recover_private_key_from_legacy_backup(&shares)
                .unwrap()
                .to_hex(),
            want
        );
    }
    assert_eq!(cells, 3 * 2 + 3 * 3);
}

#[test]
fn the_legacy_reader_reads_only_what_the_old_writer_wrote_854() {
    let legacy: Value = serde_json::from_str(LEGACY_085).unwrap();
    let s = strings(&legacy[0]["shares"]);
    let field = |share: &str, i: usize, v: &str| {
        let mut f: Vec<&str> = share.split('.').collect();
        f[i] = v;
        f.join(".")
    };
    let refused =
        |shares: Vec<String>| words(&recover_private_key_from_legacy_backup(&shares).unwrap_err());
    let v = vector();
    let reference = strings(&v["splits"][0]["shares"]);
    // The reference's shares are longer than any the old writer wrote (#854's
    // fold): refused on their length, before they are split.
    assert_eq!(
        refused(reference[..2].to_vec()),
        "Share 0 is longer than any legacy share (65 bytes): check it for spaces or a line break around or inside it; a share with an 8-hex-digit tag is BRC-140's, read with KeyShares::from_backup_format"
    );
    // A short text in BRC-140's form, at each index.
    let brc140_form = "2.2.2.751e76e8".to_string();
    for at in 0..3 {
        let mut set = vec![s[0].clone(), s[1].clone(), s[2].clone()];
        set[at] = brc140_form.clone();
        assert_eq!(
            refused(set),
            format!(
                "Share {at} is in the BRC-140 backup form; read it with KeyShares::from_backup_format"
            )
        );
    }
    assert_eq!(
        refused(vec![]),
        "legacy backup must contain from 1 to 255 shares"
    );
    assert_eq!(
        refused(vec![s[0].clone(); 256]),
        "legacy backup must contain from 1 to 255 shares"
    );
    assert_eq!(
        refused(vec![s[0].clone()]),
        "At least 2 legacy shares are required to recover the private key"
    );
    assert_eq!(
        refused(vec![s[0].clone(), s[0].clone()]),
        "Duplicate legacy share detected, each must be unique."
    );
    assert_eq!(
        refused(vec![s[0].clone(), s[1].clone() + ".x"]),
        "Invalid legacy share format in share 1. Expected format: \"x.y.t.i\""
    );
    for bad in [
        field(&s[0], 2, "02"),
        field(&s[0], 2, "+2"),
        field(&s[0], 2, "1"),
        field(&s[0], 2, "256"),
        field(&s[0], 3, "GuM"),
        field(&s[0], 3, "GuMrr"),
        field(&s[0], 3, "Gu0r"),
        field(&s[0], 1, ""),
        format!("1{}", s[0]),
    ] {
        assert_eq!(
            refused(vec![bad.clone(), s[1].clone()]),
            "Invalid legacy share data in share 0"
        );
        // The same share at index 1 and 2: the words name its index (#854's fold).
        assert_eq!(
            refused(vec![s[0].clone(), bad.clone(), s[2].clone()]),
            "Invalid legacy share data in share 1"
        );
        assert_eq!(
            refused(vec![s[0].clone(), s[1].clone(), bad]),
            "Invalid legacy share data in share 2"
        );
    }
    assert_eq!(
        refused(vec![s[0].clone(), field(&s[1], 2, "3")]),
        "Threshold mismatch in legacy share 1"
    );
    assert_eq!(
        refused(vec![s[0].clone(), field(&s[1], 3, "GuMs")]),
        "Integrity mismatch in legacy share 1"
    );
    assert_eq!(
        refused(vec![field(&s[0], 3, "GuMs"), field(&s[1], 3, "GuMs")]),
        "Legacy integrity check failed"
    );
    // Two 0.8.5 splits of one key mixed: the old tag fails, as the new one does.
    let other = strings(&legacy[1]["shares"]);
    assert_eq!(
        refused(vec![s[0].clone(), field(&other[1], 2, "2")]),
        "Legacy integrity check failed"
    );
    // A point the old writer never wrote: y at p.
    let y_at_p = PointInFiniteField::new(BigNumber::one(), BigNumber::one()).to_point_string();
    let p_text = bsv_rs::primitives::to_base58(&BigNumber::secp256k1_prime().to_bytes_be(32));
    let bad = format!("{}.{}.2.GuMr", &y_at_p[..1], p_text);
    assert_eq!(
        refused(vec![bad, s[1].clone()]),
        "Invalid legacy share data in share 0"
    );
}

/// #854's fold, the legacy reader's length bound: a share longer than the
/// 65 bytes the old writer could write is refused on its length, at any
/// index, before it is split; a share of exactly 65 bytes is read on (and
/// refused here by its point, which no writer gave); 255 shares of the
/// bound are the most it reads, 256 refused on the count.
#[test]
fn the_legacy_reader_refuses_a_share_longer_than_the_old_writer_wrote_854() {
    let legacy: Value = serde_json::from_str(LEGACY_085).unwrap();
    let s = strings(&legacy[0]["shares"]);
    let refused =
        |shares: Vec<String>| words(&recover_private_key_from_legacy_backup(&shares).unwrap_err());
    let long = |n: usize| "1".repeat(n);
    for at in 0..3 {
        let mut set = s.clone();
        set[at] = long(66);
        assert_eq!(
            refused(set),
            format!("Share {at} is longer than any legacy share (65 bytes): check it for spaces or a line break around or inside it; a share with an 8-hex-digit tag is BRC-140's, read with KeyShares::from_backup_format")
        );
    }
    // A million characters with no dot, and one of dots: the same refusal.
    assert!(refused(vec![long(1_000_000), s[1].clone()]).starts_with("Share 0 is longer"));
    assert!(refused(vec![".".repeat(1_000_000), s[1].clone()]).starts_with("Share 0 is longer"));
    // The longest the old writer could write: x of 11 characters (2^64 - 1),
    // y of 44 (a 32-byte value), a 3-digit threshold, a 4-character tag.
    let x = bsv_rs::primitives::to_base58(&u64::MAX.to_be_bytes());
    let y = bsv_rs::primitives::to_base58(
        &BigNumber::secp256k1_prime()
            .sub(&BigNumber::one())
            .to_bytes_be(32),
    );
    assert_eq!((x.len(), y.len()), (11, 44));
    let at_bound = format!("{x}.{y}.255.GuMr");
    assert_eq!(at_bound.len(), 65);
    assert_eq!(
        refused(vec![at_bound.clone(), s[1].clone()]),
        "Threshold mismatch in legacy share 1"
    );
    assert_eq!(
        refused(vec![format!("{at_bound}1"), s[1].clone()]),
        "Share 0 is longer than any legacy share (65 bytes): check it for spaces or a line break around or inside it; a share with an 8-hex-digit tag is BRC-140's, read with KeyShares::from_backup_format"
    );
    // A multi-byte character counts by its bytes: 33 two-byte characters
    // are 66 bytes, and the words say bytes (#854's second fold).
    assert_eq!("é".repeat(33).chars().count(), 33);
    assert_eq!(
        refused(vec!["é".repeat(33), s[1].clone()]),
        "Share 0 is longer than any legacy share (65 bytes): check it for spaces or a line break around or inside it; a share with an 8-hex-digit tag is BRC-140's, read with KeyShares::from_backup_format"
    );
    // A share the published 0.8.5 wrote (53 bytes) copied with whitespace:
    // over 65 bytes the words say what to check before the other reader;
    // within them, and with one trailing newline, the share's data words, as
    // before the fold.
    assert_eq!(s[0].len(), 53);
    for pad in [
        format!("{}{}", s[0], " ".repeat(13)),
        format!("{}{}", " ".repeat(13), s[0]),
        format!("{}{}{}", " ".repeat(6), s[0], " ".repeat(7)),
    ] {
        assert_eq!(
            refused(vec![pad, s[1].clone()]),
            "Share 0 is longer than any legacy share (65 bytes): check it for spaces or a line break around or inside it; a share with an 8-hex-digit tag is BRC-140's, read with KeyShares::from_backup_format"
        );
    }
    for pad in [format!("{}{}", s[0], " ".repeat(12)), format!("{}\n", s[0])] {
        assert_eq!(
            refused(vec![pad, s[1].clone()]),
            "Invalid legacy share data in share 0"
        );
    }
    assert_eq!(
        refused(vec![long(66); 256]),
        "legacy backup must contain from 1 to 255 shares"
    );
}

/// #854's second fold: old-form shares whose f(0) is 0 modulo n (the line
/// y = 5x at 2 and at 3 shares, the line y = n + x through f(0) = n) are
/// refused by the legacy reader in its own words, `Legacy integrity check
/// failed`, before any tag is computed: it never returns a key of 0.
#[test]
fn the_legacy_reader_refuses_a_secret_of_zero_in_its_own_words_854() {
    let n = BigNumber::secp256k1_order();
    let u = BigNumber::from_u64;
    let shares = |points: &[(BigNumber, BigNumber)], t: usize| -> Vec<String> {
        points
            .iter()
            .map(|(x, y)| format!("{}.{t}.GuMr", PointInFiniteField::new(x.clone(), y.clone())))
            .collect()
    };
    let cells = [
        (shares(&[(u(1), u(5)), (u(2), u(10))], 2), "y = 5x, 2 of 2"),
        (
            shares(&[(u(1), u(5)), (u(2), u(10)), (u(3), u(15))], 3),
            "y = 5x, 3 of 3",
        ),
        (
            shares(&[(u(1), n.add(&u(1))), (u(2), n.add(&u(2)))], 2),
            "y = n + x, 2 of 2",
        ),
    ];
    for (set, name) in cells {
        assert_eq!(
            words(&recover_private_key_from_legacy_backup(&set).unwrap_err()),
            "Legacy integrity check failed",
            "{name}"
        );
    }
}

/// #854's fold: shares whose secret is 0 mod n (the zero line, y = x, y = n
/// at two x, the zero line at 3 of 3) refused in the reference's words, and
/// shares whose f(0) lies in [n, p) read modulo n, through
/// `from_backup_format` and through `KeyShares::new`, each the reference's
/// answer (`fold_854.zero_secret`, `fold_854.reduction`). This crate never
/// returns a key of 0.
#[test]
fn a_secret_of_zero_is_refused_and_one_past_n_read_modulo_n_as_the_reference_reads_them_854() {
    let v = vector();
    let fold = &v["fold_854"];
    let mut cells = 0;
    for cell in fold["zero_secret"]
        .as_array()
        .unwrap()
        .iter()
        .chain(fold["reduction"].as_array().unwrap())
    {
        let t = cell["threshold"].as_u64().unwrap() as usize;
        let integrity = cell["integrity"].as_str().unwrap().to_string();
        let points: Vec<PointInFiniteField> = cell["points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                PointInFiniteField::new(
                    BigNumber::from_hex(p["x"].as_str().unwrap()).unwrap(),
                    BigNumber::from_hex(p["y"].as_str().unwrap()).unwrap(),
                )
            })
            .collect();
        let texts: Vec<String> = points
            .iter()
            .map(|p| format!("{}.{t}.{integrity}", p.to_point_string()))
            .collect();
        assert_eq!(texts, strings(&cell["shares"]), "{}", cell["name"]);
        assert_eq!(
            answer_of(&recover(&texts)),
            cell["backup"],
            "{}",
            cell["name"]
        );
        let held = KeyShares::new(points, t, integrity);
        assert_eq!(
            answer_of(&held.recover_private_key()),
            cell["key_shares"],
            "{}",
            cell["name"]
        );
        cells += 1;
    }
    assert_eq!(cells, 6);
    assert_eq!(
        fold["zero_secret"][0]["backup"]["error"],
        "Integrity hash mismatch"
    );
    assert_eq!(
        fold["reduction"][0]["backup"]["scalar_hex"],
        format!("{:064x}", 1)
    );
}

/// #854's fold: `recover_private_key` on hand-built collections: a y at p at
/// index 0 and 1 refused, one past the threshold not read, 256 points
/// refused on the count and 255 read (`fold_854.key_shares`); both readers'
/// share counts at 255 and past it.
#[test]
fn recovery_judges_y_and_the_point_count_as_the_reference_does_854() {
    let v = vector();
    let k = &v["fold_854"]["key_shares"];
    let n = |i: u64| BigNumber::from_u64(i);
    let pt = |x: u64, y: u64| PointInFiniteField { x: n(x), y: n(y) };
    let p = BigNumber::secp256k1_prime();
    let tag = || "751e76e8".to_string();
    let recovered = |points: Vec<PointInFiniteField>| {
        answer_of(&KeyShares::new(points, 2, tag()).recover_private_key())
    };
    let mut at0 = vec![pt(1, 1), pt(2, 2)];
    at0[0].y = p.clone();
    assert_eq!(recovered(at0), k["y_at_p"]);
    let mut at1 = vec![pt(1, 1), pt(2, 2)];
    at1[1].y = p.clone();
    assert_eq!(recovered(at1), k["y_at_p_in_share_1"]);
    let mut past = vec![pt(1, 1), pt(2, 1), pt(3, 1)];
    past[2].y = p;
    assert_eq!(recovered(past), k["y_at_p_past_the_threshold"]);
    assert_eq!(
        recovered((1..=256).map(|x| pt(x, 1)).collect()),
        k["points_256"]
    );
    assert_eq!(
        recovered((1..=255).map(|x| pt(x, 1)).collect()),
        k["points_255"]
    );
    // The reader's count is judged before any share is read: 255 read, and
    // 300 refused on the count, not at the malformed share 256 (`fold_854.reads`).
    // The 255 cell repeats share 0's x past the threshold window, where the
    // recording reads it (#854's fix reads the whole set; `carved_854`).
    let mut carved = 0;
    for cell in v["fold_854"]["reads"].as_array().unwrap() {
        let shares = strings(&cell["shares"]);
        let name = cell["name"].as_str().unwrap();
        let parse = match KeyShares::from_backup_format(&shares) {
            Ok(_) => serde_json::json!({ "ok": true }),
            Err(e) => serde_json::json!({ "ok": false, "error": words(&e) }),
        };
        if let Some(ours) = carved_854(name) {
            let refusal = serde_json::json!({ "ok": false, "error": ours });
            assert_eq!(parse, refusal, "{name}");
            assert_eq!(answer_of(&recover(&shares)), refusal, "{name}");
            carved += 1;
            continue;
        }
        assert_eq!(parse, cell["parse"], "{name}");
        assert_eq!(answer_of(&recover(&shares)), cell["answer"], "{name}");
    }
    assert_eq!(carved, 1);
    // The legacy reader's count the same: 255 shares read, every x distinct
    // (#854's fix reads the whole set, where 0.8.5 read the leading two
    // only). The line f(x) = 1 through the points (1..=255, 1), the tag
    // of key 1.
    let legacy: Value = serde_json::from_str(LEGACY_085).unwrap();
    let tag = legacy[0]["shares"][0]
        .as_str()
        .unwrap()
        .rsplit('.')
        .next()
        .unwrap()
        .to_string();
    let many: Vec<String> = (1u64..=255)
        .map(|i| format!("{}.2.2.{}", field_text(&BigNumber::from_u64(i)), tag))
        .collect();
    assert_eq!(many.len(), 255);
    assert_eq!(
        recover_private_key_from_legacy_backup(&many)
            .unwrap()
            .to_hex(),
        format!("{:064x}", 1)
    );
}

/// #854's fold, BRC-140's coordinate procedure cross-recorded: the
/// reference's `toKeyShares` drawing from fixed bytes (the recorder's
/// `--fold` mode stubs `globalThis.crypto.getRandomValues` alone) and
/// `split_private_key_with` given the same key, the coefficients of the
/// reference's polynomial, the same seed and the same draws write the same
/// shares byte for byte (`fold_854.coordinates`), and since #854's second
/// fold on one case of counting bytes (`fold2_854.coordinates`: the seed the
/// bytes 0 to 63, each draw and random point counting), where the fold's
/// four repeat one byte, so the bytes inside the seed or a draw reversed
/// write other shares.
#[test]
fn brc_140s_coordinates_are_the_references_under_the_same_draws_854() {
    let v = vector();
    let hex32 =
        |s: &str| -> [u8; 32] { bsv_rs::primitives::from_hex(s).unwrap().try_into().unwrap() };
    let repeated = v["fold_854"]["coordinates"].as_array().unwrap();
    assert_eq!(repeated.len(), 4); // a total of 2 among them, the least the split takes
    let counting = v["fold2_854"]["coordinates"].as_array().unwrap();
    assert_eq!(counting.len(), 1);
    let seed0 = counting[0]["seed"].as_str().unwrap();
    assert_eq!(
        seed0,
        (0u8..64).map(|b| format!("{b:02x}")).collect::<String>()
    );
    for c in repeated.iter().chain(counting) {
        let (t, n) = (
            c["threshold"].as_u64().unwrap() as usize,
            c["total"].as_u64().unwrap() as usize,
        );
        let key = PrivateKey::from_hex(c["scalar_hex"].as_str().unwrap()).unwrap();
        let coefficients: Vec<[u8; 32]> = c["coefficients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex32(h.as_str().unwrap()))
            .collect();
        let seed: [u8; 64] = bsv_rs::primitives::from_hex(c["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let draws: Vec<[u8; 32]> = c["draws"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex32(h.as_str().unwrap()))
            .collect();
        // One draw per share: no attempt was drawn again.
        assert_eq!(
            c["random_calls"].as_u64().unwrap() as usize,
            2 * (t - 1) + 1 + n
        );
        let shares = split_private_key_with(&key, t, n, &coefficients, &seed, &draws)
            .unwrap()
            .to_backup_format()
            .unwrap();
        assert_eq!(
            shares,
            strings(&c["shares"]),
            "{} {t} of {n}, seed {}..",
            c["key"],
            &c["seed"].as_str().unwrap()[..8]
        );
    }
}

/// #854's fold (the mutation pass): `Display` of a point is its share text
/// (the explicit conversion), and the three `Debug`s print what their
/// rustdoc says (the counts, the threshold, the tag, x) and redact the rest;
/// `tests/secret_debug.rs` holds that no secret is printed, this holds that
/// the fields are.
#[test]
fn the_share_types_print_what_their_documentation_says_854() {
    let key = PrivateKey::from_hex(&format!("{:064x}", 1)).unwrap();
    let (c, seed, d) = draws(2, 3);
    let shares = split_private_key_with(&key, 2, 3, &c, &seed, &d).unwrap();
    let point = &shares.points[0];
    assert_eq!(format!("{point}"), point.to_point_string());
    assert_eq!(
        format!("{point:?}"),
        format!("PointInFiniteField {{ x: {:?}, y: <redacted> }}", point.x)
    );
    assert_eq!(
        format!("{shares:?}"),
        "KeyShares { shares: 3, threshold: 2, integrity: \"751e76e8\", .. }"
    );
    let poly = bsv_rs::primitives::bsv::polynomial::Polynomial::new(shares.points.clone(), 2);
    assert_eq!(
        format!("{poly:?}"),
        "Polynomial { points: 3, threshold: 2, .. }"
    );
}

/// Writes this crate's deterministic shares and the 0.8.5 constant for the
/// recorder (`SHAMIR_854_OUT`, the path).
#[test]
#[ignore]
fn records_this_crates_shares_for_the_recorder_854() {
    let out = std::env::var("SHAMIR_854_OUT").expect("SHAMIR_854_OUT");
    let legacy: Value = serde_json::from_str(LEGACY_085).unwrap();
    let keys = [
        ("one", format!("{:064x}", 1)),
        (
            "n_minus_1",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140".to_string(),
        ),
        (
            "sha_label",
            bsv_rs::primitives::to_hex(&bsv_rs::primitives::sha256(b"bsv-rs #854 shamir vector")),
        ),
    ];
    let mut splits = Vec::new();
    for (name, hex) in &keys {
        for (t, n) in [(2usize, 3usize), (3, 5)] {
            splits.push(serde_json::json!({
                "key": name, "scalar_hex": hex, "threshold": t, "total": n,
                "shares": rust_split(hex, t, n),
            }));
        }
    }
    let doc = serde_json::json!({ "legacy_085": legacy[0], "splits": splits });
    std::fs::write(out, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
}

//! The cells of `token_edges_tests.rs`, one table row after another
//! (#843's third fold; a file of their own for the 800-line ceiling).

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

/// Every cell: (row, name, spec). The rows are the table's.
pub(super) fn cells() -> Vec<(&'static str, String, Spec)> {
    let mut cells: Vec<(&'static str, String, Spec)> = Vec::new();
    let mut add = |row: &'static str, name: &str, spec: Spec| cells.push((row, name.into(), spec));
    let x = controller().public_key().to_compressed()[1..].to_vec();
    let uncompressed = controller().public_key().to_uncompressed().to_vec();
    let tagged = |tag: u8, body: &[u8]| [vec![tag], body.to_vec()].concat();
    let dummy = Sig::Bytes(vec![0x30; 8]);
    let bom = |rest: &[u8]| [b"\xef\xbb\xbf".as_slice(), rest].concat();

    // R01: the envelope's read of the lock key (`PushDrop.decode`).
    add(
        "R01",
        "lock_key_tag_05",
        base().shape(Shape::KeyBytes(tagged(5, &x))),
    );
    add(
        "R01",
        "lock_key_uncompressed",
        base().shape(Shape::KeyBytes(uncompressed.clone())),
    );
    add(
        "R01",
        "lock_key_hybrid_06",
        base().shape(Shape::KeyBytes(tagged(6, &uncompressed[1..]))),
    );
    add(
        "R01",
        "lock_key_hybrid_07",
        base().shape(Shape::KeyBytes(tagged(7, &uncompressed[1..]))),
    );
    add(
        "R01",
        "lock_key_x_5",
        base().shape(Shape::KeyBytes(tagged(2, &[vec![0; 31], vec![5]].concat()))),
    );
    add(
        "R01",
        "lock_key_x_p_plus_2",
        base().shape(Shape::KeyBytes(tagged(3, &p_plus(2)))),
    );
    add(
        "R01",
        "lock_key_x_all_ff",
        base().shape(Shape::KeyBytes(tagged(2, &[0xff; 32]))),
    );

    // R02: the field count, 5 or 6.
    let mut four = base();
    four.data.truncate(3);
    add("R02", "fields_4", four);
    add("R02", "fields_5", base());
    add("R02", "fields_6", base().tags(br#"["t"]"#.to_vec()));
    add(
        "R02",
        "fields_7",
        base().tags(br#"["t"]"#.to_vec()).tags(b"x".to_vec()),
    );

    // R03: each field at most 1 MiB.
    for (name, len) in [
        ("value_1mib_less_1", MIB - 1),
        ("value_1mib", MIB),
        ("value_1mib_plus_1", MIB + 1),
    ] {
        add("R03", name, base().field(2, vec![b'v'; len]));
    }
    add(
        "R03",
        "key_1mib_plus_1",
        base().key(vec![b'k'; MIB + 1], "k").sig(dummy.clone()),
    );
    // #843's fourth fold: the field bound is one helper over every field,
    // so each field has its own cells at 1 MiB and one past it.
    let padded = |text: &[u8], len: usize| {
        let mut bytes = text.to_vec();
        bytes.resize(len, b' ');
        bytes
    };
    for (suffix, len) in [("1mib", MIB), ("1mib_plus_1", MIB + 1)] {
        add(
            "R03",
            &format!("protocol_{suffix}"),
            base().protocol(padded(br#"[1,"kvstore"]"#, len)),
        );
        add(
            "R03",
            &format!("controller_{suffix}"),
            base().field(3, vec![2; len]),
        );
        add(
            "R03",
            &format!("tags_{suffix}"),
            base().tags(padded(br#"["t"]"#, len)),
        );
        add(
            "R03",
            &format!("signature_{suffix}"),
            base().sig(Sig::Bytes(vec![0x30; len])),
        );
    }
    add(
        "R03",
        "key_1mib",
        base().key(vec![b'k'; MIB], "k").sig(dummy.clone()),
    );

    // R04: the running payload at most 1 MiB and 64 KiB, at 5 and 6 fields;
    // an 8-byte signature, so the exact key is the bound less the rest.
    for six in [false, true] {
        let rest = 13 + MIB + 33 + 8 + if six { 5 } else { 0 };
        let exact = PAYLOAD - rest;
        for (suffix, len) in [
            ("less_1", exact - 1),
            ("exact", exact),
            ("plus_1", exact + 1),
        ] {
            let mut spec = base()
                .key(vec![b'k'; len], "k")
                .field(2, vec![b'v'; MIB])
                .sig(dummy.clone());
            if six {
                spec = spec.tags(br#"["t"]"#.to_vec());
            }
            let fields = if six { 6 } else { 5 };
            add("R04", &format!("payload_{suffix}_{fields}_fields"), spec);
        }
    }

    // R05: the canonical envelope.
    add("R05", "all_drops_5_fields", base().shape(Shape::AllDrops));
    add(
        "R05",
        "all_drops_6_fields",
        base().tags(br#"["t"]"#.to_vec()).shape(Shape::AllDrops),
    );
    add(
        "R05",
        "trailing_op_1",
        base().shape(Shape::TrailingOp(OP_1)),
    );
    add(
        "R05",
        "trailing_op_drop",
        base().shape(Shape::TrailingOp(OP_DROP)),
    );
    add(
        "R05",
        "trailing_op_checksig",
        base().shape(Shape::TrailingOp(OP_CHECKSIG)),
    );
    add("R05", "key_pushdata1", base().shape(Shape::PushData1(1)));
    add(
        "R05",
        "value_0x81_direct_push",
        base().field(2, vec![0x81]).shape(Shape::DirectPush(2)),
    );
    add(
        "R05",
        "value_0x05_direct_push",
        base().field(2, vec![0x05]).shape(Shape::DirectPush(2)),
    );
    add(
        "R05",
        "value_0x81_as_op_1negate",
        base().field(2, vec![0x81]),
    );
    add("R05", "value_0x05_as_op_5", base().field(2, vec![0x05]));
    add("R05", "key_0x00_as_op_0", base().key(vec![0], "\0"));
    add("R05", "key_0x01_as_op_1", base().key(vec![1], "\u{1}"));

    // R06: the protocol text strict UTF-8, one leading BOM dropped.
    add(
        "R06",
        "protocol_byte_ff",
        base().protocol(b"[1,\"kvst\xffre\"]".to_vec()),
    );
    add(
        "R06",
        "protocol_overlong_nul",
        base().protocol(b"[1,\"kvst\xc0\x80re\"]".to_vec()),
    );
    add(
        "R06",
        "protocol_surrogate_bytes",
        base().protocol(b"[1,\"kvst\xed\xa0\x80re\"]".to_vec()),
    );
    add(
        "R06",
        "protocol_bom",
        base().protocol(bom(br#"[1,"kvstore"]"#)),
    );
    add(
        "R06",
        "protocol_bom_twice",
        base().protocol(bom(&bom(br#"[1,"kvstore"]"#))),
    );
    add(
        "R06",
        "protocol_truncated_sequence",
        base().protocol(b"[1,\"kvstore\"]\xe2\x82".to_vec()),
    );
    add(
        "R06",
        "protocol_past_10ffff",
        base().protocol(b"[1,\"kvst\xf4\x90\x80\x80re\"]".to_vec()),
    );

    // R07: the protocol text JSON.
    add(
        "R07",
        "protocol_no_json",
        base().protocol(b"kvstore".to_vec()),
    );
    add(
        "R07",
        "protocol_truncated",
        base().protocol(br#"[1,"kvstore""#.to_vec()),
    );
    add(
        "R07",
        "protocol_trailing_comma",
        base().protocol(br#"[1,"kvstore",]"#.to_vec()),
    );
    add(
        "R07",
        "protocol_level_1e400",
        base().protocol(spelled("1e400")),
    );

    // R08: an array of exactly two members.
    for (name, text) in [
        ("empty_array", "[]"),
        ("one_member", "[1]"),
        ("three_members", r#"[1,"kvstore",1]"#),
        ("object", r#"{"a":1}"#),
        ("string", r#""kvstore""#),
        ("null", "null"),
        ("number", "1"),
    ] {
        add("R08", name, base().protocol(text.as_bytes().to_vec()));
    }

    // R09: the level 0, 1 or 2 and the name a string.
    for (name, spelling) in [
        ("level_minus_1", "-1"),
        ("level_3", "3"),
        ("level_1_5", "1.5"),
        ("level_text_1", "\"1\""),
        ("level_true", "true"),
        ("level_null", "null"),
        ("level_0_0", "0.0"),
        ("level_1_0", "1.0"),
        ("level_2_0", "2.0"),
        ("level_minus_0", "-0"),
        ("level_minus_0_0", "-0.0"),
        ("level_1e0", "1e0"),
        ("level_1E0", "1E0"),
        ("level_10e_minus_1", "10e-1"),
        ("level_1_plus_tiny", "1.0000000000000001"),
        ("level_2_pow_64_plus_1", "18446744073709551617"),
        // #843's fourth fold: the nearest doubles on each side of 0, 1 and
        // 2 (the type `JSON.parse` reads and `!==` compares), the nearest
        // f32s, the spellings that read as exactly a level, and 1.05.
        ("level_f64_after_0", "5e-324"),
        ("level_f64_before_0", "-5e-324"),
        ("level_f64_before_1", "0.9999999999999999"),
        ("level_f64_after_1", "1.0000000000000002"),
        ("level_f64_before_2", "1.9999999999999998"),
        ("level_f64_after_2", "2.0000000000000004"),
        ("level_f32_after_0", "1.401298464324817e-45"),
        ("level_f32_before_0", "-1.401298464324817e-45"),
        ("level_f32_before_1", "0.99999994039535522"),
        ("level_f32_after_1", "1.00000011920928955"),
        ("level_f32_before_2", "1.99999988079071045"),
        ("level_f32_after_2", "2.0000002384185791"),
        ("level_1e_minus_400", "1e-400"),
        ("level_minus_1e_minus_400", "-1e-400"),
        ("level_0e5", "0e5"),
        ("level_0_99999999999999999", "0.99999999999999999"),
        ("level_0_1e1", "0.1e1"),
        ("level_1_9999999999999999", "1.9999999999999999"),
        ("level_2_0000000000000001", "2.0000000000000001"),
        ("level_200e_minus_2", "200e-2"),
        ("level_1_05", "1.05"),
    ] {
        add("R09", name, base().protocol(spelled(spelling)));
    }
    for (name, text) in [
        ("name_number", "[1,7]"),
        ("name_null", "[1,null]"),
        ("name_array", r#"[1,["kvstore"]]"#),
        ("name_object", "[1,{}]"),
    ] {
        add("R09", name, base().protocol(text.as_bytes().to_vec()));
    }

    // R10: the name 5 to 400 bytes, at each level.
    for level in 0..=2u8 {
        add(
            "R10",
            &format!("name_4_bytes_level_{level}"),
            base().at(level, "kvst"),
        );
        add(
            "R10",
            &format!("name_5_bytes_level_{level}"),
            base().at(level, "kvsto"),
        );
        add(
            "R10",
            &format!("name_400_bytes_level_{level}"),
            base().at(level, &"n".repeat(400)),
        );
        add(
            "R10",
            &format!("name_401_bytes_level_{level}"),
            base().at(level, &"n".repeat(401)),
        );
        add(
            "R10",
            &format!("name_6_bytes_level_{level}"),
            base().at(level, "kvstor"),
        );
        add(
            "R10",
            &format!("name_399_bytes_level_{level}"),
            base().at(level, &"n".repeat(399)),
        );
        add(
            "R10",
            &format!("name_4_bytes_two_chars_level_{level}"),
            base().at(level, "éé"),
        );
    }

    // R11: the protocol text its canonical JSON, at each level.
    for level in 0..=2u8 {
        let l = level.to_string();
        add(
            "R11",
            &format!("canonical_level_{level}"),
            base().at(level, "kvstore"),
        );
        for (name, text) in [
            ("space_after_comma", format!("[{l}, \"kvstore\"]")),
            ("space_after_bracket", format!("[ {l},\"kvstore\"]")),
            ("space_before_comma", format!("[{l} ,\"kvstore\"]")),
            ("space_at_end", format!("[{l},\"kvstore\"] ")),
            ("space_at_start", format!(" [{l},\"kvstore\"]")),
            ("newline_at_end", format!("[{l},\"kvstore\"]\n")),
            ("crlf_at_end", format!("[{l},\"kvstore\"]\r\n")),
            ("tab_at_start", format!("\t[{l},\"kvstore\"]")),
            ("escaped_o", format!("[{l},\"kvst\\u006fre\"]")),
            ("escaped_solidus", format!("[{l},\"kv\\/store\"]")),
            ("level_point_0", format!("[{l}.0,\"kvstore\"]")),
            ("level_e0", format!("[{l}e0,\"kvstore\"]")),
        ] {
            let mut spec = base().at(level, "kvstore");
            spec.data[0] = text.into_bytes();
            add("R11", &format!("{name}_level_{level}"), spec);
        }
    }
    let mut minus_zero = base().at(0, "kvstore");
    minus_zero.data[0] = spelled("-0");
    add("R11", "level_minus_0_signed_level_0", minus_zero);
    let mut point_zero = base();
    point_zero.data[0] = spelled("1.0");
    add("R11", "level_1_0_signed_level_1", point_zero);
    add(
        "R11",
        "control_escape_long_form",
        base().protocol(br#"[1,"kvst\u0008re"]"#.to_vec()),
    );
    add(
        "R11",
        "lone_surrogate_escape",
        base().protocol(br#"[1,"kvst\ud800re"]"#.to_vec()),
    );
    let deep = |depth: usize, inner: &str| {
        format!("{}{inner}{}", "[".repeat(depth), "]".repeat(depth)).into_bytes()
    };
    for depth in [127, 128, 129] {
        add(
            "R11",
            &format!("protocol_depth_{depth}"),
            base().protocol(deep(depth, "")),
        );
    }

    // R12: the key strict UTF-8, 1 to 800 bytes.
    add(
        "R12",
        "key_bom_only",
        base().key(bom(b""), "k").sig(dummy.clone()),
    );
    add("R12", "key_bom_then_k", base().key(bom(b"k"), "k"));
    add("R12", "key_1_byte", base().key(b"q".to_vec(), "q"));
    let k800 = "k".repeat(800);
    add(
        "R12",
        "key_800_bytes",
        base().key(k800.clone().into_bytes(), &k800),
    );
    add(
        "R12",
        "key_801_bytes",
        base().key(vec![b'k'; 801], "k").sig(dummy.clone()),
    );
    add(
        "R12",
        "key_bom_then_800_bytes",
        base().key(bom(k800.as_bytes()), &k800),
    );
    let e400 = "é".repeat(400);
    add(
        "R12",
        "key_800_bytes_400_chars",
        base().key(e400.clone().into_bytes(), &e400),
    );
    let e401 = "é".repeat(401);
    add(
        "R12",
        "key_802_bytes_401_chars",
        base()
            .key(e401.clone().into_bytes(), "k")
            .sig(dummy.clone()),
    );
    // #843's fourth fold: strict UTF-8's edges at the key, zero, one and two
    // marks and one not leading, and the length's other neighbours.
    for (name, bytes) in [
        ("key_byte_ff", b"k\xff".to_vec()),
        ("key_overlong_nul", b"k\xc0\x80".to_vec()),
        ("key_surrogate_bytes", b"k\xed\xa0\x80".to_vec()),
        ("key_truncated_sequence", b"k\xe2\x82".to_vec()),
        ("key_past_10ffff", b"k\xf4\x90\x80\x80".to_vec()),
    ] {
        add("R12", name, base().key(bytes, "k").sig(dummy.clone()));
    }
    for id in [
        "k\u{10ffff}",
        "\u{feff}k",
        "k\u{feff}",
        "kq",
        &"k".repeat(799),
        &"😀".repeat(200),
    ] {
        let name = match id {
            "k\u{10ffff}" => "key_max_code_point".to_string(),
            "\u{feff}k" => "key_bom_twice_then_k".to_string(),
            "k\u{feff}" => "key_k_then_bom".to_string(),
            _ => format!("key_{}_bytes_{}_chars", id.len(), id.chars().count()),
        };
        let bytes = if id == "\u{feff}k" {
            bom(id.as_bytes())
        } else {
            id.as_bytes().to_vec()
        };
        add("R12", &name, base().key(bytes, id));
    }
    add(
        "R12",
        "key_804_bytes_201_chars",
        base()
            .key("😀".repeat(201).into_bytes(), "k")
            .sig(dummy.clone()),
    );

    // R13: the value strict UTF-8, 1 byte to 1 MiB.
    add(
        "R13",
        "value_bom_only",
        base().field(2, bom(b"")).sig(dummy.clone()),
    );
    add("R13", "value_bom_then_v", base().field(2, bom(b"v")));
    add(
        "R13",
        "value_bom_then_1mib_less_3",
        base().field(2, bom(&vec![b'v'; MIB - 3])),
    );
    for (name, bytes) in [
        ("value_byte_ff", b"v\xff".to_vec()),
        ("value_overlong_nul", b"v\xc0\x80".to_vec()),
        ("value_surrogate_bytes", b"v\xed\xa0\x80".to_vec()),
        ("value_truncated_sequence", b"v\xe2\x82".to_vec()),
        ("value_past_10ffff", b"v\xf4\x90\x80\x80".to_vec()),
        ("value_max_code_point", "v\u{10ffff}".as_bytes().to_vec()),
        ("value_bom_twice_then_v", bom(&bom(b"v"))),
        ("value_v_then_bom", "v\u{feff}".as_bytes().to_vec()),
        ("value_2_bytes", b"vw".to_vec()),
        (
            "value_1mib_two_byte_chars",
            "é".repeat(MIB / 2).into_bytes(),
        ),
    ] {
        add("R13", name, base().field(2, bytes));
    }

    // R14: the controller field 33 bytes.
    let c = controller().public_key().to_compressed().to_vec();
    add(
        "R14",
        "controller_32_bytes",
        base().field(3, c[..32].to_vec()),
    );
    add(
        "R14",
        "controller_34_bytes",
        base().field(3, [c.clone(), vec![0]].concat()),
    );

    // R15: the controller a point (`PublicKey.fromString`).
    let flipped = tagged(c[0] ^ 1, &x);
    add("R15", "controller_other_parity", base().field(3, flipped));
    for tag in [0u8, 1, 4, 5, 6, 7, 8] {
        add(
            "R15",
            &format!("controller_tag_{tag:02x}"),
            base().field(3, tagged(tag, &x)),
        );
    }
    add(
        "R15",
        "controller_x_5",
        base().field(3, tagged(2, &[vec![0; 31], vec![5]].concat())),
    );
    add(
        "R15",
        "controller_x_0",
        base().field(3, tagged(2, &[0; 32])),
    );
    add(
        "R15",
        "controller_x_p",
        base().field(3, tagged(2, &p_plus(0))),
    );
    add(
        "R15",
        "controller_x_p_plus_1",
        base().field(3, tagged(2, &p_plus(1))),
    );
    add(
        "R15",
        "controller_x_p_plus_2",
        base().field(3, tagged(3, &p_plus(2))),
    );
    add(
        "R15",
        "controller_x_all_ff",
        base().field(3, tagged(2, &[0xff; 32])),
    );

    // R16: the tags, when a sixth field is present.
    let tag_list = |tags: Vec<String>| serde_json::to_vec(&tags).unwrap();
    let many = |n: usize| tag_list((0..n).map(|i| format!("t{i}")).collect());
    for (name, bytes) in [
        ("tags_empty_array", b"[]".to_vec()),
        ("tags_null", b"null".to_vec()),
        ("tags_object", b"{}".to_vec()),
        ("tags_string", br#""t""#.to_vec()),
        ("tags_number", b"7".to_vec()),
        ("tags_32", many(32)),
        ("tags_33", many(33)),
        ("tag_empty", br#"[""]"#.to_vec()),
        ("tag_1_byte", br#"["t"]"#.to_vec()),
        ("tag_256_bytes", tag_list(vec!["t".repeat(256)])),
        ("tag_257_bytes", tag_list(vec!["t".repeat(257)])),
        ("tag_256_bytes_64_chars", tag_list(vec!["😀".repeat(64)])),
        (
            "tag_257_bytes_65_chars",
            tag_list(vec![format!("a{}", "😀".repeat(64))]),
        ),
        ("tag_number", b"[1]".to_vec()),
        ("tag_null", b"[null]".to_vec()),
        ("tag_array", br#"[["t"]]"#.to_vec()),
        ("tags_twice", br#"["t","t"]"#.to_vec()),
        ("tags_differ_in_case", br#"["t","T"]"#.to_vec()),
        ("tags_bom", bom(br#"["t"]"#)),
        ("tags_not_utf8", b"[\"\xff\"]".to_vec()),
        ("tags_no_json", b"t".to_vec()),
        ("tags_spaced", br#"[ "t" ]"#.to_vec()),
        // #843's fourth fold.
        ("tags_31", many(31)),
        ("tag_2_bytes", br#"["tu"]"#.to_vec()),
        ("tag_255_bytes", tag_list(vec!["t".repeat(255)])),
        ("tag_256_bytes_128_chars", tag_list(vec!["é".repeat(128)])),
        (
            "tag_257_bytes_129_chars",
            tag_list(vec![format!("a{}", "é".repeat(128))]),
        ),
        ("tags_overlong_nul", b"[\"\xc0\x80\"]".to_vec()),
        ("tags_surrogate_bytes", b"[\"\xed\xa0\x80\"]".to_vec()),
        ("tags_truncated_sequence", b"[\"t\"]\xe2\x82".to_vec()),
        ("tags_past_10ffff", b"[\"\xf4\x90\x80\x80\"]".to_vec()),
        (
            "tags_max_code_point",
            "[\"\u{10ffff}\"]".as_bytes().to_vec(),
        ),
        ("tags_bom_twice", bom(&bom(br#"["t"]"#))),
        ("tag_bom_inside", "[\"\u{feff}t\"]".as_bytes().to_vec()),
        ("tag_escaped_t", br#"["\u0074"]"#.to_vec()),
        ("tags_escaped_twice", br#"["t","\u0074"]"#.to_vec()),
        ("tag_surrogate_pair_escape", br#"["\ud83d\ude00"]"#.to_vec()),
        ("tag_lone_surrogate_escape", br#"["\ud800"]"#.to_vec()),
        ("tag_number_1e400", b"[1e400]".to_vec()),
        ("tags_depth_127", deep(127, "")),
        ("tags_depth_128", deep(128, "")),
        ("tags_depth_129", deep(129, "")),
    ] {
        add("R16", name, base().tags(bytes));
    }

    // R17: the derivation's rules on the protocol name and key ID
    // (`KeyDeriver.computeInvoiceNumber`), reached through the text.
    for (name, protocol) in [
        ("name_hyphen", "kv-store"),
        ("name_double_space", "kv  store"),
        ("name_ends_protocol", "kvstore protocol"),
        ("name_three_chars_six_bytes", "ééé"),
        ("name_short_after_trim", " kvst"),
    ] {
        add(
            "R17",
            name,
            base().protocol(format!("[1,\"{protocol}\"]").into_bytes()),
        );
    }
    for (name, protocol) in [
        ("name_upper_case", "KVSTORE"),
        ("name_leading_space", " kvstore"),
        ("name_trailing_space", "kvstore "),
        ("name_kelvin_sign", "\u{212a}vstore"),
    ] {
        add("R17", name, base().at(1, protocol));
    }

    // R18: the lock the controller's derived key, at each level.
    for level in 0..=2u8 {
        add(
            "R18",
            &format!("honest_level_{level}"),
            base().at(level, "kvstore"),
        );
        add(
            "R18",
            &format!("honest_6_fields_level_{level}"),
            base().at(level, "kvstore").tags(br#"["t"]"#.to_vec()),
        );
        for (name, lock) in [
            ("other_key_id", Lock::OtherKeyId),
            ("other_level", Lock::OtherLevel),
            ("not_for_self", Lock::NotForSelf),
            ("other_controller", Lock::OtherController),
        ] {
            add(
                "R18",
                &format!("{name}_level_{level}"),
                base().at(level, "kvstore").lock(lock),
            );
        }
    }

    // R19: the signature the controller's over the data fields.
    for (name, sig) in [
        ("other_signer", Sig::OtherSigner),
        ("other_data", Sig::OtherData),
        ("high_s", Sig::HighS),
        ("trailing_byte", Sig::Trailing),
        ("eight_bytes_0x30", Sig::Bytes(vec![0x30; 8])),
        ("one_byte_0x01", Sig::Bytes(vec![0x01])),
        ("ascii_text", Sig::Bytes(b"signature".to_vec())),
    ] {
        add("R19", name, base().sig(sig.clone()));
        add(
            "R19",
            &format!("{name}_6_fields"),
            base().tags(br#"["t"]"#.to_vec()).sig(sig),
        );
    }
    cells
}

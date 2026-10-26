//! The Socket.IO codec carries every finite `f64` through a frame's JSON
//! exactly (Calhooon/bsv-rs#285). The reference's `socket.io-parser` writes a
//! packet's payload with `JSON.stringify` and reads it with `JSON.parse`, both
//! exact for a double; this crate's codec reads and writes the payload with
//! `serde_json`, whose number reader was not correctly rounded until the crate
//! turned on its `float_roundtrip` feature: a long decimal read one bit off,
//! and the re-read of its own encoding another bit off (the fuzz crash of
//! #280's lane on `fuzz_auth_messages`).
//!
//! Run with: `cargo test --features socketio --test socketio_float_round_trip`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "socketio")]

use bsv_rs::auth::transports::socketio::codec::SocketIoPacket;
use serde_json::Value;

/// The crash input of #280's fuzz run, byte for byte
/// (`fuzz/corpus/fuzz_auth_messages/socketio-event-long-float`).
const CRASH: &str = include_str!("../fuzz/corpus/fuzz_auth_messages/socketio-event-long-float");

/// The 107-digit integer in the crash input's `payload` array.
const LONG_NUMBER: &str = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444111";

/// The reference's verdict on [`LONG_NUMBER`]: `socket.io-parser` 4.2.7 (the
/// version `ts-stack@edf6e03`'s `pnpm-lock.yaml` resolves for
/// `@bsv/authsocket-client`'s `socket.io-client`) decoding the crash input and
/// encoding it again under Node v22.18.0 reads `4.444444444444445e+106`,
/// bits `0x561360e1fd8531d4`, and its encoding is a fixed point.
const REFERENCE_TEXT: &str = "4.444444444444445e+106";
const REFERENCE_BITS: u64 = 0x5613_60e1_fd85_31d4;

fn event_args(frame: &str) -> Vec<Value> {
    match SocketIoPacket::decode(frame).expect("the frame decodes") {
        SocketIoPacket::Event { data, .. } => data,
        other => panic!("expected an EVENT, got {other:?}"),
    }
}

fn number_at(args: &[Value], path: &[&str], index: usize) -> f64 {
    let mut value = &args[1];
    for key in path {
        value = &value[*key];
    }
    value[index].as_f64().expect("a number")
}

#[test]
fn a_long_decimal_in_a_socketio_frame_reads_and_re_reads_to_the_same_double() {
    let packet = SocketIoPacket::decode(CRASH).expect("the crash input decodes");
    let encoded = packet.encode();
    let again = SocketIoPacket::decode(&encoded).expect("a frame's encoding decodes");
    assert_eq!(
        again.encode(),
        encoded,
        "the frame's encoding is a fixed point"
    );
    assert_eq!(again, packet);

    let read = number_at(&event_args(CRASH), &["payload"], 4);
    let correctly_rounded: f64 = LONG_NUMBER.parse().unwrap();
    assert_eq!(read.to_bits(), correctly_rounded.to_bits());
    let reference: f64 = REFERENCE_TEXT.parse().unwrap();
    assert_eq!(
        read.to_bits(),
        reference.to_bits(),
        "the reference's double"
    );
    assert_eq!(read.to_bits(), REFERENCE_BITS);
    assert_eq!(
        number_at(&event_args(&encoded), &["payload"], 4).to_bits(),
        read.to_bits()
    );
}

#[test]
fn every_awkward_double_round_trips_through_a_socketio_frame() {
    let awkward = [
        0.0,
        -0.0,
        0.1,
        0.2 + 0.1,
        1.0 / 3.0,
        48.6,
        1e308,
        -1e308,
        f64::MAX,
        f64::MIN,
        f64::MIN_POSITIVE,
        f64::EPSILON,
        f64::from_bits(1),                     // the smallest subnormal
        f64::from_bits(0x000f_ffff_ffff_ffff), // the largest subnormal
        5e-324,
        "2.2250738585072011e-308".parse().unwrap(),
        9007199254740992.0,     // 2^53
        9007199254740994.0,     // 2^53 + 2
        18446744073709551616.0, // 2^64, past u64
        1.8446744073709552e19,
        123456789012345680000.0,
        4.444444444444445e106,
        LONG_NUMBER.parse().unwrap(),
        "2.47032822920623272088e-324".parse().unwrap(),
        "1.7976931348623157e308".parse().unwrap(),
        "0.30000000000000004".parse().unwrap(),
    ];
    for x in awkward {
        let text = serde_json::to_string(&x).unwrap();
        // serde_json's own round trip, the oracle: the shortest text back to the bits.
        let oracle: f64 = serde_json::from_str(&text).unwrap();
        assert_eq!(oracle.to_bits(), x.to_bits(), "serde_json on {text}");

        let frame = format!("2[\"n\",[{text}]]");
        let args = event_args(&frame);
        let read = args[1][0].as_f64().expect("a number");
        assert_eq!(read.to_bits(), x.to_bits(), "the codec on {text}");
        let encoded = SocketIoPacket::decode(&frame).unwrap().encode();
        assert_eq!(encoded, frame, "the codec writes {text} back as read");
    }
}

#[test]
fn a_long_decimal_text_reads_as_the_correctly_rounded_double() {
    // Decimal texts that are not a double's shortest form: the codec reads
    // each to the double Rust's correctly rounded parser gives, as
    // `JSON.parse` does, and writes it back as a fixed point.
    let texts = [
        LONG_NUMBER,
        "0.1000000000000000055511151231257827021181583404541015625",
        "2.4703282292062327208828439643411068618252990130716238221279284125033775364e-324",
        "1.00000000000000011102230246251565404236316680908203125",
        "9007199254740993.0",
        "7.2057594037927933e16",
        "179769313486231580793728971405301e276",
    ];
    for text in texts {
        let frame = format!("2[\"n\",[{text}]]");
        let read = event_args(&frame)[1][0].as_f64().expect("a number");
        let correctly_rounded: f64 = text.parse().unwrap();
        assert_eq!(read.to_bits(), correctly_rounded.to_bits(), "{text}");
        let encoded = SocketIoPacket::decode(&frame).unwrap().encode();
        let again = SocketIoPacket::decode(&encoded).unwrap();
        assert_eq!(again.encode(), encoded, "{text}");
    }
}

#[test]
fn a_number_past_the_double_range_is_refused_with_a_reason() {
    // The reference's `JSON.parse` reads it as `Infinity` and `JSON.stringify`
    // writes `null` back, the frame's data changed; the codec refuses the frame
    // instead (rule 5: the exact value back or a refusal), a stated divergence.
    let err = SocketIoPacket::decode("2[\"n\",[1e400]]").unwrap_err();
    assert!(err.to_string().contains("invalid JSON"), "{err}");
}

/// The cases of `socketio_float_round_trip_285.json` whose number this
/// crate writes back in other text than `JSON.stringify` does; the double is
/// the reference's in every case (the bits are checked for each). serde_json
/// writes an integral float with a fraction or an exponent where JavaScript
/// writes an integral double below 1e21 as an integer, keeps the sign of
/// negative zero where JavaScript writes `0`, and keeps an integer within
/// `u64` exact where JavaScript reads it as a double (the number this crate
/// hands on is `9007199254740993`, the reference's `9007199254740992`).
const TEXT_DIFFERS: &[(&str, &str)] = &[
    (
        "1.00000000000000011102230246251565404236316680908203125",
        "1.0",
    ),
    ("7.2057594037927933e16", "7.205759403792794e+16"),
    ("-0.0", "-0.0"),
    ("123456789012345680000", "1.2345678901234568e+20"),
    ("9007199254740993", "9007199254740993"),
    ("18446744073709551616", "1.8446744073709552e+19"),
    ("100.0", "100.0"),
    ("1E2", "100.0"),
];

#[test]
fn every_frame_of_the_vector_reads_the_reference_s_double() {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/socketio_float_round_trip_285.json")).unwrap();
    let mut differs = Vec::new();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let frame = case["frame"].as_str().unwrap();
        let at = |args: Vec<Value>| {
            let mut slot = Value::Array(args);
            for step in case["number_at"].as_array().unwrap() {
                slot = match step {
                    Value::Number(i) => slot[i.as_u64().unwrap() as usize].take(),
                    Value::String(k) => slot[k.as_str()].take(),
                    _ => panic!("a path step"),
                };
            }
            slot
        };
        let read = at(event_args(frame));
        let bits = u64::from_str_radix(case["reference_bits"].as_str().unwrap(), 16).unwrap();
        assert_eq!(read.as_f64().unwrap().to_bits(), bits, "{name}");

        let encoded = SocketIoPacket::decode(frame).unwrap().encode();
        let again = SocketIoPacket::decode(&encoded).unwrap();
        assert_eq!(again.encode(), encoded, "{name}: a fixed point");
        let reread = at(event_args(&encoded));
        assert_eq!(reread.as_f64().unwrap().to_bits(), bits, "{name}: re-read");

        let text = serde_json::to_string(&read).unwrap();
        if text != case["reference_text"].as_str().unwrap() {
            differs.push((name.to_string(), text));
        }
    }
    let expected: Vec<(String, String)> = TEXT_DIFFERS
        .iter()
        .map(|(n, t)| (n.to_string(), t.to_string()))
        .collect();
    assert_eq!(differs, expected, "the enumerated text differences");
}

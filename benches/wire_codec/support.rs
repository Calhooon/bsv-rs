//! The wire_codec bench's frames and layouts, shared with `tests/wire_codec_bench_bytes.rs`.
//!
//! The bytes are #76's recordings (`tests/fixtures/wire/<method>.json`, the `full`
//! case): `request_hex`, the frame the transceiver wrote, and `response_hex`, the
//! result frame the wallet side wrote (the processor, or `WireWriter`'s type
//! writers for the 13 calls the processor does not answer). A layout names the
//! reader and writer call of each field in order and carries no value: decoding a
//! recorded frame through it yields the values the encode op writes back, so both
//! ops run on the recorded bytes. `tests/wire_codec_bench_bytes.rs` pins every
//! layout to both recorded cases: the frame consumed exactly, re-encoded byte for
//! byte. A fixture that moves (a re-recording) turns that test red, never the bench
//! silently.
#![allow(dead_code)] // the bench and the test each use a part

use std::collections::HashMap;
use std::path::Path;

use bsv_rs::wallet::wire::{WalletCall, WireReader, WireWriter};
use bsv_rs::wallet::{
    Counterparty, Outpoint, Protocol, SendWithResult, SignActionSpend, WalletAction, WalletOutput,
};
use bsv_rs::{Error, Result};

/// The recorded case the bench measures; the test checks both.
pub const CASE: &str = "full";
pub const CASES: [&str; 2] = ["minimal", "full"];

/// One field's codec, in frame order.
#[derive(Clone, Debug)]
pub enum Layout {
    U8,
    I8,
    Var,
    /// `read_optional_var_int` / `write_optional_var_int`.
    OptVar,
    OptBool,
    Str,
    OptStr,
    Raw(usize),
    /// The bytes left in the frame (a certificate's unprefixed signature).
    Rest,
    /// A var length then that many bytes.
    Blob,
    OptBlob,
    Strs,
    /// A string array whose absent form is the nil count.
    OptStrs,
    Map,
    OptMap,
    Protocol,
    OptProtocol,
    Counterparty,
    Outpoint,
    Spends,
    SendResults,
    Action,
    Output,
    /// A var count (the nil count is absent), then each row.
    Array(Vec<Layout>),
    /// An `i8` flag; the fields follow when it is 1.
    Flag(Vec<Layout>),
    /// A var length, then a frame of its own.
    Framed(Vec<Layout>),
    /// A `u8` tag choosing an arm; `other` reads on after a tag no arm names.
    Branch(Vec<(u8, Vec<Layout>)>, Vec<Layout>),
    /// An `i8` length then that many bytes (-1 absent): a privileged reason.
    Reason,
    /// createAction's unlocking script: a blob, or the nil length then its length.
    Unlock,
    /// The request's originator: a `u8` length then its bytes.
    Originator,
    /// listOutputs' result: the total, the optional BEEF, then that many outputs.
    Outputs,
}

/// A decoded field, written back by `encode`.
#[derive(Clone, Debug)]
pub enum Value {
    U8(u8),
    I8(i8),
    Var(u64),
    OptVar(Option<u64>),
    OptBool(Option<bool>),
    Str(String),
    OptStr(Option<String>),
    Raw(Vec<u8>),
    Blob(Vec<u8>),
    OptBlob(Option<Vec<u8>>),
    Strs(Vec<String>),
    OptStrs(Option<Vec<String>>),
    Map(HashMap<String, String>),
    OptMap(Option<HashMap<String, String>>),
    Protocol(Protocol),
    OptProtocol(Option<Protocol>),
    Counterparty(Option<Counterparty>),
    Outpoint(Outpoint),
    Spends(HashMap<u32, SignActionSpend>),
    SendResults(Option<Vec<SendWithResult>>),
    Action(Box<WalletAction>),
    Output(Box<WalletOutput>),
    Rows(Option<Vec<Vec<Value>>>),
    Flag(i8, Vec<Value>),
    Framed(Vec<Value>),
    Branch(u8, Vec<Value>),
    Reason(Option<Vec<u8>>),
    Unlock(Option<Vec<u8>>, u64),
    Originator(Vec<u8>),
    Outputs(u64, Option<Vec<u8>>, Vec<WalletOutput>),
}

const NIL: u64 = u64::MAX;

fn malformed(what: &str) -> Error {
    Error::WalletError(format!("wire_codec layout: {what}"))
}

fn read_all(layout: &[Layout], r: &mut WireReader<'_>) -> Result<Vec<Value>> {
    layout.iter().map(|field| read(field, r)).collect()
}

fn read(field: &Layout, r: &mut WireReader<'_>) -> Result<Value> {
    use Layout as L;
    Ok(match field {
        L::U8 => Value::U8(r.read_u8()?),
        L::I8 => Value::I8(r.read_i8()?),
        L::Var => Value::Var(r.read_var_int()?),
        L::OptVar => Value::OptVar(r.read_optional_var_int()?),
        L::OptBool => Value::OptBool(r.read_optional_bool()?),
        L::Str => Value::Str(r.read_string()?),
        L::OptStr => Value::OptStr(r.read_optional_string()?),
        L::Raw(len) => Value::Raw(r.read_bytes(*len)?.to_vec()),
        L::Rest => Value::Raw(r.read_remaining().to_vec()),
        L::Blob => {
            let len = r.read_var_int()? as usize;
            Value::Blob(r.read_bytes(len)?.to_vec())
        }
        L::OptBlob => Value::OptBlob(r.read_optional_bytes()?),
        L::Strs => Value::Strs(r.read_string_array()?),
        L::OptStrs => {
            let count = r.read_var_int()?;
            if count == NIL {
                Value::OptStrs(None)
            } else {
                let strings = (0..count)
                    .map(|_| Ok(r.read_optional_string()?.unwrap_or_default()))
                    .collect::<Result<_>>()?;
                Value::OptStrs(Some(strings))
            }
        }
        L::Map => Value::Map(r.read_string_map()?),
        L::OptMap => Value::OptMap(r.read_optional_string_map()?),
        L::Protocol => Value::Protocol(r.read_protocol_id()?),
        L::OptProtocol => Value::OptProtocol(r.read_optional_protocol_id()?),
        L::Counterparty => Value::Counterparty(r.read_counterparty()?),
        L::Outpoint => Value::Outpoint(r.read_outpoint()?),
        L::Spends => Value::Spends(r.read_sign_action_spends()?),
        L::SendResults => Value::SendResults(r.read_send_with_result_array()?),
        L::Action => Value::Action(Box::new(r.read_wallet_action()?)),
        L::Output => Value::Output(Box::new(r.read_wallet_output()?)),
        L::Array(row) => {
            let count = r.read_var_int()?;
            if count == NIL {
                Value::Rows(None)
            } else {
                if count > r.remaining() as u64 {
                    return Err(malformed("array count past the frame"));
                }
                let rows = (0..count)
                    .map(|_| read_all(row, r))
                    .collect::<Result<_>>()?;
                Value::Rows(Some(rows))
            }
        }
        L::Flag(fields) => {
            let flag = r.read_i8()?;
            let values = if flag == 1 {
                read_all(fields, r)?
            } else {
                Vec::new()
            };
            Value::Flag(flag, values)
        }
        L::Framed(fields) => {
            let len = r.read_var_int()? as usize;
            Value::Framed(decode(fields, r.read_bytes(len)?)?)
        }
        L::Branch(arms, other) => {
            let tag = r.read_u8()?;
            let fields = arms
                .iter()
                .find(|(arm, _)| *arm == tag)
                .map_or(other, |(_, fields)| fields);
            Value::Branch(tag, read_all(fields, r)?)
        }
        L::Reason => {
            let len = r.read_i8()?;
            if len < 0 {
                Value::Reason(None)
            } else {
                Value::Reason(Some(r.read_bytes(len as usize)?.to_vec()))
            }
        }
        L::Unlock => {
            let len = r.read_var_int()?;
            if len == NIL {
                Value::Unlock(None, r.read_var_int()?)
            } else {
                Value::Unlock(Some(r.read_bytes(len as usize)?.to_vec()), 0)
            }
        }
        L::Originator => {
            let len = r.read_u8()? as usize;
            Value::Originator(r.read_bytes(len)?.to_vec())
        }
        L::Outputs => {
            let total = r.read_var_int()?;
            let beef = r.read_optional_bytes()?;
            if total > r.remaining() as u64 {
                return Err(malformed("output count past the frame"));
            }
            let outputs = (0..total)
                .map(|_| r.read_wallet_output())
                .collect::<Result<_>>()?;
            Value::Outputs(total, beef, outputs)
        }
    })
}

/// Reads `bytes` through `layout`; a byte left over is an error.
pub fn decode(layout: &[Layout], bytes: &[u8]) -> Result<Vec<Value>> {
    let mut r = WireReader::new(bytes);
    let values = read_all(layout, &mut r)?;
    if !r.is_empty() {
        return Err(malformed(&format!(
            "{} bytes left at offset {}",
            r.remaining(),
            r.position()
        )));
    }
    Ok(values)
}

fn write_all(values: &[Value], w: &mut WireWriter) {
    for value in values {
        write(value, w);
    }
}

fn write(value: &Value, w: &mut WireWriter) {
    match value {
        Value::U8(v) => {
            w.write_u8(*v);
        }
        Value::I8(v) => {
            w.write_i8(*v);
        }
        Value::Var(v) => {
            w.write_var_int(*v);
        }
        Value::OptVar(v) => {
            w.write_optional_var_int(*v);
        }
        Value::OptBool(v) => {
            w.write_optional_bool(*v);
        }
        Value::Str(v) => {
            w.write_string(v);
        }
        Value::OptStr(v) => {
            w.write_optional_string(v.as_deref());
        }
        Value::Raw(v) => {
            w.write_bytes(v);
        }
        Value::Blob(v) => {
            w.write_var_int(v.len() as u64).write_bytes(v);
        }
        Value::OptBlob(v) => {
            w.write_optional_bytes(v.as_deref());
        }
        Value::Strs(v) => {
            w.write_string_array(v);
        }
        Value::OptStrs(v) => {
            w.write_optional_string_array(v.as_deref());
        }
        Value::Map(v) => {
            w.write_string_map(v);
        }
        Value::OptMap(v) => {
            w.write_optional_string_map(v.as_ref());
        }
        Value::Protocol(v) => {
            w.write_protocol_id(v);
        }
        Value::OptProtocol(v) => {
            w.write_optional_protocol_id(v.as_ref());
        }
        Value::Counterparty(v) => {
            w.write_counterparty(v.as_ref());
        }
        Value::Outpoint(v) => {
            w.write_outpoint(v);
        }
        Value::Spends(v) => {
            w.write_sign_action_spends(v);
        }
        Value::SendResults(v) => {
            w.write_send_with_result_array(v.as_deref());
        }
        Value::Action(v) => {
            w.write_wallet_action(v);
        }
        Value::Output(v) => {
            w.write_wallet_output(v);
        }
        Value::Rows(None) => {
            w.write_var_int(NIL);
        }
        Value::Rows(Some(rows)) => {
            w.write_var_int(rows.len() as u64);
            for row in rows {
                write_all(row, w);
            }
        }
        Value::Flag(flag, values) => {
            w.write_i8(*flag);
            write_all(values, w);
        }
        Value::Framed(values) => {
            let bytes = encode(values);
            w.write_var_int(bytes.len() as u64).write_bytes(&bytes);
        }
        Value::Branch(tag, values) => {
            w.write_u8(*tag);
            write_all(values, w);
        }
        Value::Reason(None) => {
            w.write_i8(-1);
        }
        Value::Reason(Some(v)) => {
            w.write_i8(v.len() as i8).write_bytes(v);
        }
        Value::Unlock(Some(script), _) => {
            w.write_var_int(script.len() as u64).write_bytes(script);
        }
        Value::Unlock(None, len) => {
            w.write_var_int(NIL).write_var_int(*len);
        }
        Value::Originator(v) => {
            w.write_u8(v.len() as u8).write_bytes(v);
        }
        Value::Outputs(total, beef, outputs) => {
            w.write_var_int(*total)
                .write_optional_bytes(beef.as_deref());
            for output in outputs {
                w.write_wallet_output(output);
            }
        }
    }
}

/// Writes `values` back with the same writer calls `decode` read them with.
pub fn encode(values: &[Value]) -> Vec<u8> {
    let mut w = WireWriter::new();
    write_all(values, &mut w);
    w.into_bytes()
}

/// One call's recorded frames: the request and the result, each with its envelope.
pub struct Frames {
    pub request: Vec<u8>,
    pub result: Vec<u8>,
}

/// The recording `tests/fixtures/wire/<method>.json`, case `case`.
pub fn frames(call: WalletCall, case: &str) -> Frames {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wire")
        .join(format!("{}.json", call.method_name()));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("recording JSON");
    let entry = fixture["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|c| c["name"] == case))
        .unwrap_or_else(|| panic!("{}: no case {case}", path.display()));
    let bytes =
        |key: &str| hex::decode(entry["expected"][key].as_str().expect(key)).expect("recorded hex");
    Frames {
        request: bytes("request_hex"),
        result: bytes("response_hex"),
    }
}

/// The 28 calls by code.
pub fn calls() -> Vec<WalletCall> {
    (1..=28)
        .map(|code| WalletCall::try_from(code).expect("call code"))
        .collect()
}

/// The request frame: the call code, the originator, the arguments.
pub fn request_layout(call: WalletCall) -> Vec<Layout> {
    let mut out = vec![Layout::U8, Layout::Originator];
    out.extend(request_args(call));
    out
}

/// The result frame: the success byte, then the result's fields.
pub fn result_layout(call: WalletCall) -> Vec<Layout> {
    let mut out = vec![Layout::U8];
    out.extend(result_fields(call));
    out
}

fn common() -> Vec<Layout> {
    vec![Layout::Protocol, Layout::Str, Layout::Counterparty]
}

/// The transceiver's certificate order (`prove_certificate`, `parse_certificate_from_binary`):
/// type, subject, serial, certifier, outpoint, a prefixed signature, the fields.
fn transceiver_certificate() -> Vec<Layout> {
    use Layout::*;
    vec![Raw(32), Raw(33), Raw(32), Raw(33), Outpoint, Blob, Map]
}

/// `WireWriter::write_wallet_certificate`'s order, the one the recorded results carry:
/// type, serial, subject, certifier, outpoint, the fields, the signature unprefixed.
fn writer_certificate() -> Vec<Layout> {
    use Layout::*;
    vec![Raw(32), Raw(32), Raw(33), Raw(33), Outpoint, Map, Rest]
}

fn keyring() -> Layout {
    Layout::Array(vec![Layout::Str, Layout::Blob])
}

fn request_args(call: WalletCall) -> Vec<Layout> {
    use Layout::*;
    use WalletCall as C;
    let txids = || Array(vec![Raw(32)]);
    match call {
        C::CreateAction => vec![
            Str,
            OptBlob,
            Array(vec![Outpoint, Unlock, Str, OptVar]),
            Array(vec![Blob, Var, Str, OptStr, OptStr, OptStrs]),
            OptVar,
            OptVar,
            OptStrs,
            Flag(vec![
                OptBool,
                OptBool,
                I8,
                txids(),
                OptBool,
                OptBool,
                Array(vec![Outpoint]),
                txids(),
                OptBool,
            ]),
        ],
        C::SignAction => vec![Spends, Blob, Flag(vec![OptBool, OptBool, OptBool, txids()])],
        C::AbortAction => vec![Rest],
        C::ListActions => vec![
            Strs, I8, OptBool, OptBool, OptBool, OptBool, OptBool, OptBool, OptVar, OptVar, OptBool,
        ],
        C::InternalizeAction => vec![
            Blob,
            Array(vec![
                Var,
                Branch(
                    vec![(1, vec![Raw(33), Blob, Blob]), (2, vec![Str, OptStr, Strs])],
                    Vec::new(),
                ),
            ]),
            OptStrs,
            Str,
            OptBool,
        ],
        C::ListOutputs => vec![
            Str, Strs, I8, I8, OptBool, OptBool, OptBool, OptVar, OptVar, OptBool,
        ],
        C::RelinquishOutput => vec![Str, Outpoint],
        C::GetPublicKey => vec![OptBool, OptProtocol, OptStr, Counterparty, OptBool],
        C::RevealCounterpartyKeyLinkage => vec![Raw(33), Raw(33)],
        C::RevealSpecificKeyLinkage => vec![Counterparty, Raw(33), Protocol, Str],
        C::Encrypt | C::Decrypt | C::CreateHmac => {
            let mut fields = common();
            fields.push(Blob);
            fields
        }
        C::VerifyHmac => {
            let mut fields = common();
            fields.extend([Blob, Blob]);
            fields
        }
        C::CreateSignature => {
            let mut fields = common();
            fields.extend([OptBlob, OptBlob]);
            fields
        }
        C::VerifySignature => {
            let mut fields = common();
            fields.extend([OptBool, OptBlob, OptBlob, Blob]);
            fields
        }
        C::AcquireCertificate => vec![
            Raw(32),
            Raw(33),
            Map,
            OptBool,
            Reason,
            Branch(
                vec![
                    (
                        1,
                        vec![
                            Raw(32),
                            Outpoint,
                            Blob,
                            // The keyring revealer: 11 for the certifier, else a key.
                            Branch(vec![(11, Vec::new())], vec![Raw(32)]),
                            keyring(),
                        ],
                    ),
                    (2, vec![Str]),
                ],
                Vec::new(),
            ),
        ],
        C::ListCertificates => vec![
            Array(vec![Raw(33)]),
            Array(vec![Raw(32)]),
            OptVar,
            OptVar,
            OptBool,
            Reason,
        ],
        C::ProveCertificate => {
            let mut fields = transceiver_certificate();
            fields.extend([Strs, Raw(33), OptBool, Reason]);
            fields
        }
        C::RelinquishCertificate => vec![Raw(32), Raw(32), Raw(33)],
        C::DiscoverByIdentityKey => vec![Raw(33), OptVar, OptVar, OptBool],
        C::DiscoverByAttributes => vec![Array(vec![Str, Str]), OptVar, OptVar, OptBool],
        C::GetHeaderForHeight => vec![Var],
        C::IsAuthenticated
        | C::WaitForAuthentication
        | C::GetHeight
        | C::GetNetwork
        | C::GetVersion => Vec::new(),
    }
}

fn result_fields(call: WalletCall) -> Vec<Layout> {
    use Layout::*;
    use WalletCall as C;
    let linkage = || vec![Blob, Blob, Raw(33), Raw(33), Raw(33)];
    match call {
        C::CreateAction => vec![
            Flag(vec![Raw(32)]),
            Flag(vec![Blob]),
            Array(vec![Outpoint]),
            SendResults,
            Flag(vec![Blob, Blob]),
        ],
        C::SignAction => vec![Flag(vec![Raw(32)]), Flag(vec![Blob]), SendResults],
        C::ListActions => vec![Array(vec![Action])],
        C::ListOutputs => vec![Outputs],
        C::GetPublicKey => vec![Raw(33)],
        C::RevealCounterpartyKeyLinkage => {
            let mut fields = linkage();
            fields.push(Str);
            fields
        }
        C::RevealSpecificKeyLinkage => {
            let mut fields = linkage();
            fields.extend([Protocol, Str, U8]);
            fields
        }
        C::Encrypt | C::Decrypt | C::CreateHmac | C::CreateSignature => vec![Blob],
        C::VerifyHmac | C::VerifySignature | C::IsAuthenticated | C::WaitForAuthentication => {
            vec![OptBool]
        }
        C::AcquireCertificate => writer_certificate(),
        C::ListCertificates => vec![Array(vec![
            Framed(writer_certificate()),
            Flag(vec![keyring()]),
            Str,
        ])],
        C::ProveCertificate => vec![keyring()],
        C::DiscoverByIdentityKey | C::DiscoverByAttributes => vec![Array(vec![
            Framed(writer_certificate()),
            Flag(vec![Str, OptStr, OptStr, U8]),
            OptMap,
            OptMap,
        ])],
        C::GetHeight => vec![Var],
        // The processor prefixes the header with its length; the transceiver keeps
        // the prefix as the header's first byte (recorded as such by #76).
        C::GetHeaderForHeight => vec![Blob],
        C::GetNetwork => vec![U8],
        C::GetVersion => vec![Rest],
        C::AbortAction | C::InternalizeAction | C::RelinquishOutput | C::RelinquishCertificate => {
            Vec::new()
        }
    }
}

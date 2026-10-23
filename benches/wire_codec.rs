//! Field codecs for all 28 request/result shapes, without a wallet or transport.
//!
//! Layouts follow this checkout's transceiver (the two linkage layouts follow
//! the processor). This measures the public WireReader/WireWriter helpers.
//! It includes a small schema walk, not async dispatch or cryptography.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: benchmark fixtures
#![allow(missing_docs)] // #135: Criterion entry point

use std::collections::HashMap;

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::wire::{WalletCall, WireReader, WireWriter};
use bsv_rs::wallet::{
    ActionStatus, Counterparty, Outpoint, Protocol, SecurityLevel, SendWithResult,
    SendWithResultStatus, SignActionSpend, WalletAction, WalletActionInput, WalletActionOutput,
    WalletOutput,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

#[derive(Clone)]
enum Field {
    Byte(u8),
    Var(u64),
    OptionalVar(Option<u64>),
    Bool(Option<bool>),
    Text(String),
    OptionalText(Option<String>),
    Raw(Vec<u8>),
    Blob(Vec<u8>),
    OptionalBlob(Option<Vec<u8>>),
    Strings(Vec<String>),
    Map(HashMap<String, String>),
    Protocol(Protocol),
    OptionalProtocol(Option<Protocol>),
    Counterparty(Counterparty),
    Outpoint(Outpoint),
    Spends(HashMap<u32, SignActionSpend>),
    SendResults(Vec<SendWithResult>),
    Action(WalletAction),
    Output(WalletOutput),
    Array(Vec<Vec<Field>>),
    Flagged(Vec<Field>),
    Framed(Vec<Field>),
}

fn encode(fields: &[Field]) -> Vec<u8> {
    let mut w = WireWriter::new();
    for field in fields {
        field.write(&mut w);
    }
    w.into_bytes()
}

fn read_fields(fields: &[Field], r: &mut WireReader<'_>) -> bsv_rs::Result<()> {
    for field in fields {
        field.read(r)?;
    }
    Ok(())
}

fn decode(fields: &[Field], bytes: &[u8]) -> bsv_rs::Result<()> {
    let mut r = WireReader::new(bytes);
    read_fields(fields, &mut r)?;
    if !r.is_empty() {
        return Err(bsv_rs::Error::WalletError(
            "fixture has trailing bytes".into(),
        ));
    }
    Ok(())
}

impl Field {
    fn write(&self, w: &mut WireWriter) {
        match self {
            Self::Byte(v) => {
                w.write_u8(*v);
            }
            Self::Var(v) => {
                w.write_var_int(*v);
            }
            Self::OptionalVar(v) => {
                w.write_optional_var_int(*v);
            }
            Self::Bool(v) => {
                w.write_optional_bool(*v);
            }
            Self::Text(v) => {
                w.write_string(v);
            }
            Self::OptionalText(v) => {
                w.write_optional_string(v.as_deref());
            }
            Self::Raw(v) => {
                w.write_bytes(v);
            }
            Self::Blob(v) => {
                w.write_var_int(v.len() as u64).write_bytes(v);
            }
            Self::OptionalBlob(v) => {
                w.write_optional_bytes(v.as_deref());
            }
            Self::Strings(v) => {
                w.write_string_array(v);
            }
            Self::Map(v) => {
                w.write_string_map(v);
            }
            Self::Protocol(v) => {
                w.write_protocol_id(v);
            }
            Self::OptionalProtocol(v) => {
                w.write_optional_protocol_id(v.as_ref());
            }
            Self::Counterparty(v) => {
                w.write_counterparty(Some(v));
            }
            Self::Outpoint(v) => {
                w.write_outpoint(v);
            }
            Self::Spends(v) => {
                w.write_sign_action_spends(v);
            }
            Self::SendResults(v) => {
                w.write_send_with_result_array(Some(v));
            }
            Self::Action(v) => {
                w.write_wallet_action(v);
            }
            Self::Output(v) => {
                w.write_wallet_output(v);
            }
            Self::Array(rows) => {
                w.write_var_int(rows.len() as u64);
                for row in rows {
                    for field in row {
                        field.write(w);
                    }
                }
            }
            Self::Flagged(fields) => {
                w.write_i8(1);
                for field in fields {
                    field.write(w);
                }
            }
            Self::Framed(fields) => {
                let bytes = encode(fields);
                w.write_var_int(bytes.len() as u64).write_bytes(&bytes);
            }
        }
    }

    fn read(&self, r: &mut WireReader<'_>) -> bsv_rs::Result<()> {
        match self {
            Self::Byte(_) => {
                black_box(r.read_u8()?);
            }
            Self::Var(_) => {
                black_box(r.read_var_int()?);
            }
            Self::OptionalVar(_) => {
                black_box(r.read_optional_var_int()?);
            }
            Self::Bool(_) => {
                black_box(r.read_optional_bool()?);
            }
            Self::Text(_) => {
                black_box(r.read_string()?);
            }
            Self::OptionalText(_) => {
                black_box(r.read_optional_string()?);
            }
            Self::Raw(v) => {
                black_box(r.read_bytes(v.len())?.to_vec());
            }
            Self::Blob(_) => {
                let len = r.read_var_int()? as usize;
                black_box(r.read_bytes(len)?.to_vec());
            }
            Self::OptionalBlob(_) => {
                black_box(r.read_optional_bytes()?);
            }
            Self::Strings(_) => {
                black_box(r.read_string_array()?);
            }
            Self::Map(_) => {
                black_box(r.read_string_map()?);
            }
            Self::Protocol(_) => {
                black_box(r.read_protocol_id()?);
            }
            Self::OptionalProtocol(_) => {
                black_box(r.read_optional_protocol_id()?);
            }
            Self::Counterparty(_) => {
                black_box(r.read_counterparty()?);
            }
            Self::Outpoint(_) => {
                black_box(r.read_outpoint()?);
            }
            Self::Spends(_) => {
                black_box(r.read_sign_action_spends()?);
            }
            Self::SendResults(_) => {
                black_box(r.read_send_with_result_array()?);
            }
            Self::Action(_) => {
                black_box(r.read_wallet_action()?);
            }
            Self::Output(_) => {
                black_box(r.read_wallet_output()?);
            }
            Self::Array(rows) => {
                if r.read_var_int()? != rows.len() as u64 {
                    return Err(bsv_rs::Error::WalletError("fixture count changed".into()));
                }
                for row in rows {
                    read_fields(row, r)?;
                }
            }
            Self::Flagged(fields) => {
                if r.read_i8()? != 1 {
                    return Err(bsv_rs::Error::WalletError("fixture flag changed".into()));
                }
                read_fields(fields, r)?;
            }
            Self::Framed(fields) => {
                let len = r.read_var_int()? as usize;
                decode(fields, r.read_bytes(len)?)?;
            }
        }
        Ok(())
    }
}

struct Fixtures {
    public_key: Vec<u8>,
    protocol: Protocol,
    outpoint: Outpoint,
    action: WalletAction,
    output: WalletOutput,
}

impl Fixtures {
    fn new() -> Self {
        let public_key = PrivateKey::random().public_key().to_compressed().to_vec();
        let outpoint = Outpoint {
            txid: [0x42; 32],
            vout: 3,
        };
        let action = WalletAction {
            txid: outpoint.txid,
            satoshis: 1_000,
            status: ActionStatus::Completed,
            is_outgoing: true,
            description: "codec action".into(),
            labels: Some(vec!["bench".into()]),
            version: 2,
            lock_time: 0,
            inputs: Some(vec![WalletActionInput {
                source_outpoint: outpoint.clone(),
                source_satoshis: 1_001,
                source_locking_script: Some(vec![0x51]),
                unlocking_script: Some(vec![0x00]),
                input_description: "codec input".into(),
                sequence_number: u32::MAX,
            }]),
            outputs: Some(vec![WalletActionOutput {
                satoshis: 1_000,
                locking_script: Some(vec![0x51]),
                spendable: true,
                custom_instructions: Some("codec".into()),
                tags: vec!["bench".into()],
                output_index: 0,
                output_description: "codec output".into(),
                basket: "bench".into(),
            }]),
        };
        let output = WalletOutput {
            satoshis: 1_000,
            locking_script: Some(vec![0x51]),
            spendable: true,
            custom_instructions: Some("codec".into()),
            tags: Some(vec!["bench".into()]),
            outpoint: outpoint.clone(),
            labels: Some(vec!["bench".into()]),
        };
        Self {
            public_key,
            protocol: Protocol::new(SecurityLevel::App, "codec bench"),
            outpoint,
            action,
            output,
        }
    }

    fn common(&self) -> Vec<Field> {
        vec![
            Field::Protocol(self.protocol.clone()),
            Field::Text("codec".into()),
            Field::Counterparty(Counterparty::Self_),
        ]
    }

    fn certificate(&self) -> Vec<Field> {
        // The transceiver's certificate order (type, subject, serial, certifier).
        // These are synthetic identifiers and opaque signature bytes, no key material.
        vec![
            Field::Raw(vec![0x41; 32]),
            Field::Raw(self.public_key.clone()),
            Field::Raw(vec![0x42; 32]),
            Field::Raw(self.public_key.clone()),
            Field::Outpoint(self.outpoint.clone()),
            Field::Blob(vec![0; 72]),
            Field::Map(attributes()),
        ]
    }

    fn send_results(&self) -> Field {
        Field::SendResults(vec![SendWithResult {
            txid: self.outpoint.txid,
            status: SendWithResultStatus::Unproven,
        }])
    }

    fn request(&self, call: WalletCall) -> Vec<Field> {
        use Field::*;
        use WalletCall::*;
        match call {
            CreateAction => vec![
                Text("codec action".into()),
                OptionalBlob(Some(vec![0; 128])),
                Array(vec![vec![
                    Outpoint(self.outpoint.clone()),
                    Blob(vec![0; 72]),
                    Text("codec input".into()),
                    OptionalVar(Some(u32::MAX as u64)),
                ]]),
                Array(vec![vec![
                    Blob(vec![0x51]),
                    Var(1_000),
                    Text("codec output".into()),
                    OptionalText(Some("bench".into())),
                    OptionalText(Some("codec".into())),
                    Strings(vec!["bench".into()]),
                ]]),
                OptionalVar(Some(0)),
                OptionalVar(Some(2)),
                Strings(vec!["bench".into()]),
                Flagged(vec![
                    Bool(Some(false)),
                    Bool(Some(false)),
                    Byte(255),
                    Array(vec![vec![Raw(vec![0x42; 32])]]),
                    Bool(Some(false)),
                    Bool(Some(true)),
                    Array(vec![vec![Outpoint(self.outpoint.clone())]]),
                    Array(vec![vec![Raw(vec![0x42; 32])]]),
                    Bool(Some(false)),
                ]),
            ],
            SignAction => vec![
                Spends(HashMap::from([(
                    0,
                    SignActionSpend {
                        unlocking_script: vec![0; 72],
                        sequence_number: Some(u32::MAX),
                    },
                )])),
                Blob(vec![0; 16]),
                Flagged(vec![
                    Bool(Some(false)),
                    Bool(Some(false)),
                    Bool(Some(true)),
                    Array(vec![vec![Raw(vec![0x42; 32])]]),
                ]),
            ],
            AbortAction => vec![Raw(vec![0; 16])],
            ListActions => {
                let mut fields = vec![Strings(vec!["bench".into()]), Byte(1)];
                fields.extend((0..6).map(|_| Bool(Some(true))));
                fields.extend([
                    OptionalVar(Some(10)),
                    OptionalVar(Some(0)),
                    Bool(Some(false)),
                ]);
                fields
            }
            InternalizeAction => vec![
                Blob(vec![0; 128]),
                Array(vec![vec![
                    Var(0),
                    Byte(2),
                    Text("bench".into()),
                    OptionalText(Some("codec".into())),
                    Strings(vec!["bench".into()]),
                ]]),
                Strings(vec!["bench".into()]),
                Text("codec action".into()),
                Bool(Some(false)),
            ],
            ListOutputs => vec![
                Text("bench".into()),
                Strings(vec!["bench".into()]),
                Byte(1),
                Byte(1),
                Bool(Some(true)),
                Bool(Some(true)),
                Bool(Some(true)),
                OptionalVar(Some(10)),
                OptionalVar(Some(0)),
                Bool(Some(false)),
            ],
            RelinquishOutput => vec![Text("bench".into()), Outpoint(self.outpoint.clone())],
            GetPublicKey => vec![
                Bool(Some(false)),
                OptionalProtocol(Some(self.protocol.clone())),
                OptionalText(Some("codec".into())),
                Counterparty(bsv_rs::wallet::Counterparty::Self_),
                Bool(Some(true)),
            ],
            RevealCounterpartyKeyLinkage => {
                vec![Raw(self.public_key.clone()), Raw(self.public_key.clone())]
            }
            RevealSpecificKeyLinkage => vec![
                Counterparty(bsv_rs::wallet::Counterparty::Self_),
                Raw(self.public_key.clone()),
                Protocol(self.protocol.clone()),
                Text("codec".into()),
            ],
            Encrypt | Decrypt | CreateHmac => {
                let mut fields = self.common();
                fields.push(Blob(vec![0; 256]));
                fields
            }
            VerifyHmac => {
                let mut fields = self.common();
                fields.extend([Blob(vec![0; 256]), Blob(vec![0; 32])]);
                fields
            }
            CreateSignature => {
                let mut fields = self.common();
                fields.extend([OptionalBlob(Some(vec![0; 256])), OptionalBlob(None)]);
                fields
            }
            VerifySignature => {
                let mut fields = self.common();
                fields.extend([
                    Bool(Some(true)),
                    OptionalBlob(Some(vec![0; 256])),
                    OptionalBlob(None),
                    Blob(vec![0; 72]),
                ]);
                fields
            }
            AcquireCertificate => vec![
                Raw(vec![0x41; 32]),
                Raw(self.public_key.clone()),
                Map(attributes()),
                Bool(Some(false)),
                Byte(255),
                Byte(1),
                Raw(vec![0x42; 32]),
                Outpoint(self.outpoint.clone()),
                Blob(vec![0; 72]),
                Byte(11),
                Array(vec![vec![Text("bench".into()), Blob(vec![0; 32])]]),
            ],
            ListCertificates => vec![
                Array(vec![vec![Raw(self.public_key.clone())]]),
                Array(vec![vec![Raw(vec![0x41; 32])]]),
                OptionalVar(Some(10)),
                OptionalVar(Some(0)),
                Bool(Some(false)),
                Byte(255),
            ],
            ProveCertificate => {
                let mut fields = self.certificate();
                fields.extend([
                    Strings(vec!["bench".into()]),
                    Raw(self.public_key.clone()),
                    Bool(Some(false)),
                    Byte(255),
                ]);
                fields
            }
            RelinquishCertificate => vec![
                Raw(vec![0x41; 32]),
                Raw(vec![0x42; 32]),
                Raw(self.public_key.clone()),
            ],
            DiscoverByIdentityKey => vec![
                Raw(self.public_key.clone()),
                OptionalVar(Some(10)),
                OptionalVar(Some(0)),
                Bool(Some(false)),
            ],
            DiscoverByAttributes => vec![
                Map(attributes()),
                OptionalVar(Some(10)),
                OptionalVar(Some(0)),
                Bool(Some(false)),
            ],
            GetHeaderForHeight => vec![Var(800_000)],
            IsAuthenticated | WaitForAuthentication | GetHeight | GetNetwork | GetVersion => vec![],
        }
    }

    fn result(&self, call: WalletCall) -> Vec<Field> {
        use Field::*;
        use WalletCall::*;
        match call {
            CreateAction => vec![
                Flagged(vec![Raw(vec![0x42; 32])]),
                Flagged(vec![Blob(vec![0; 128])]),
                Array(vec![vec![Outpoint(self.outpoint.clone())]]),
                self.send_results(),
                Flagged(vec![Blob(vec![0; 128]), Blob(vec![0; 16])]),
            ],
            SignAction => vec![
                Flagged(vec![Raw(vec![0x42; 32])]),
                Flagged(vec![Blob(vec![0; 128])]),
                self.send_results(),
            ],
            ListActions => vec![Var(1), Action(self.action.clone())],
            ListOutputs => vec![
                Var(1),
                OptionalBlob(Some(vec![0; 128])),
                Output(self.output.clone()),
            ],
            GetPublicKey => vec![Raw(self.public_key.clone())],
            RevealCounterpartyKeyLinkage | RevealSpecificKeyLinkage => {
                let mut fields = vec![
                    Blob(vec![0; 32]),
                    Blob(vec![0; 72]),
                    Raw(self.public_key.clone()),
                    Raw(self.public_key.clone()),
                    Raw(self.public_key.clone()),
                ];
                if call == RevealCounterpartyKeyLinkage {
                    fields.push(Text("2026-01-01T00:00:00Z".into()));
                } else {
                    fields.extend([
                        Protocol(self.protocol.clone()),
                        Text("codec".into()),
                        Byte(1),
                    ]);
                }
                fields
            }
            Encrypt | Decrypt => vec![Blob(vec![0; 256])],
            CreateHmac => vec![Blob(vec![0; 32])],
            CreateSignature => vec![Blob(vec![0; 72])],
            VerifyHmac | VerifySignature | IsAuthenticated => vec![Bool(Some(true))],
            AcquireCertificate => self.certificate(),
            ListCertificates => vec![Array(vec![vec![
                Framed(self.certificate()),
                Flagged(vec![Array(vec![vec![
                    Text("bench".into()),
                    Blob(vec![0; 32]),
                ]])]),
                Var(0),
            ]])],
            ProveCertificate => vec![Array(vec![vec![Text("bench".into()), Blob(vec![0; 32])]])],
            DiscoverByIdentityKey | DiscoverByAttributes => vec![Array(vec![vec![
                Framed(self.certificate()),
                Text("codec certifier".into()),
                OptionalText(None),
                OptionalText(Some("codec".into())),
                Byte(1),
                Array(vec![vec![Text("bench".into()), Blob(vec![0; 32])]]),
                Map(attributes()),
            ]])],
            GetHeight => vec![Var(800_000)],
            GetHeaderForHeight => vec![Raw(vec![0; 80])],
            GetNetwork => vec![Byte(0)],
            GetVersion => vec![Raw(b"0.8.2".to_vec())],
            AbortAction
            | InternalizeAction
            | RelinquishOutput
            | RelinquishCertificate
            | WaitForAuthentication => vec![],
        }
    }
}

fn attributes() -> HashMap<String, String> {
    HashMap::from([
        ("bench".into(), "codec".into()),
        ("purpose".into(), "measurement".into()),
    ])
}

fn bench(c: &mut Criterion) {
    let fixtures = Fixtures::new();
    for code in 1..=28 {
        let call = WalletCall::try_from(code).expect("call code");
        let mut request = vec![
            Field::Byte(code),
            Field::Byte(5),
            Field::Raw(b"bench".to_vec()),
        ];
        request.extend(fixtures.request(call));
        let mut result = vec![Field::Byte(0)]; // success envelope, not a verdict
        result.extend(fixtures.result(call));
        let mut group = c.benchmark_group(format!("wire_codec/{}", call.method_name()));
        for (name, fields) in [("request", request), ("result", result)] {
            let bytes = encode(&fields);
            decode(&fields, &bytes).expect("fixture round trip consumes the frame");
            group.throughput(Throughput::Bytes(bytes.len() as u64));
            group.bench_function(format!("{name}_encode"), |b| {
                b.iter(|| black_box(encode(black_box(&fields))))
            });
            group.bench_function(format!("{name}_decode"), |b| {
                b.iter(|| decode(black_box(&fields), black_box(&bytes)))
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);

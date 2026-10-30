#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "support/wire_bounds_473.rs"]
mod bounds_473;
mod support;
#[path = "support/result_totals_467.rs"]
mod totals_467;

fuzz_target!(|data: &[u8]| {
    bounds_473::exercise(data);
    totals_467::exercise(data);
    // The JSON intake must also return on malformed or null remittances (#393).
    let _ = serde_json::from_slice::<bsv_rs::wallet::InternalizeOutput>(data);

    // Fuzz wire protocol deserialization - should never panic
    let mut reader = bsv_rs::wallet::wire::WireReader::new(data);

    // Try reading various types (each may fail gracefully)
    let _ = reader.read_var_int();

    let mut reader = bsv_rs::wallet::wire::WireReader::new(data);
    let _ = reader.read_string();

    let mut reader = bsv_rs::wallet::wire::WireReader::new(data);
    let _ = reader.read_optional_string();

    let mut reader = bsv_rs::wallet::wire::WireReader::new(data);
    let _ = reader.read_counterparty();

    let mut reader = bsv_rs::wallet::wire::WireReader::new(data);
    let _ = reader.read_protocol_id();

    let mut reader = bsv_rs::wallet::wire::WireReader::new(data);
    let _ = reader.read_optional_protocol_id();

    let mut reader = bsv_rs::wallet::wire::WireReader::new(data);
    let _ = reader.read_bytes(data.len().min(1024));

    // Encoded counterparties must be validated before their encoding is lost.
    if let Ok(encoded) = std::str::from_utf8(data) {
        let _ = bsv_rs::wallet::Counterparty::from_hex(encoded);
    }
});

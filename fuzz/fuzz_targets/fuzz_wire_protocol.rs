#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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
});

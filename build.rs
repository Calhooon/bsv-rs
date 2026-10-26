//! The one build-time bound (#152): `http` is reqwest's native client. On
//! wasm32 its futures are not `Send` (the `async_trait` methods of the
//! broadcasters, chain trackers, HTTP substrate and transports await them) and
//! its wasm backend has no `ClientBuilder::timeout`, so the crate built there
//! with `http` fails at every await: 8 errors for `transaction,http,wasm`, 69
//! for rule 6's slice with `http`. No Worker asks for it (`docs/DEPENDENTS.md`:
//! every `http` row is native); a Worker's HTTP is the host's `fetch`. A
//! `compile_error!` in the library is not enough: rustc reports it and then the
//! awaits too. The build script stops the crate before rustc reads it, with one
//! message.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let wasm32 = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    if wasm32 && std::env::var_os("CARGO_FEATURE_HTTP").is_some() {
        eprintln!(
            "bsv-rs: the `http` feature is native-only and does not build for wasm32 \
             (reqwest's futures are not `Send` there; bsv-rs#152). Drop `http` from the \
             wasm32 build and reach HTTP through the host's `fetch`."
        );
        std::process::exit(1);
    }
}

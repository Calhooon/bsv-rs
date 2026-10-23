//! Network clients live at transport boundaries. See docs/ARCH-RULES.md.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

const HOMES: &[&str] = &[
    "src/wallet/substrates/",
    "src/auth/transports/",
    "src/transaction/broadcasters/",
    "src/transaction/chain_trackers/",
];

// The overlay's concrete SHIP/SLAP adapters are a fifth home. Resolver,
// reputation, retry and historian code do not gain permission to hold clients.
const OVERLAY_HOME: &str = "src/overlay/facilitators.rs";

// These existing adapters predate the boundary. Each line has its own ceiling;
// the exception does not permit another client in the same file (#87).
const ALLOWED: &[(&str, &str, usize)] = &[
    (
        "src/storage/downloader.rs",
        "let client = reqwest::Client::builder()",
        1,
    ),
    ("src/storage/downloader.rs", "client: &reqwest::Client,", 1),
    ("src/storage/uploader.rs", "client: reqwest::Client,", 1),
    (
        "src/storage/uploader.rs",
        "client: reqwest::Client::new(),",
        1,
    ),
    (
        "src/transaction/fee_models/live_policy.rs",
        "client: reqwest::Client,",
        1,
    ),
    (
        "src/transaction/fee_models/live_policy.rs",
        "client: reqwest::Client::new(),",
        1,
    ),
];

fn is_client_name(name: &str) -> bool {
    matches!(
        name,
        "reqwest"
            | "tokio_tungstenite"
            | "tungstenite"
            | "hyper"
            | "hyper_util"
            | "ureq"
            | "surf"
            | "isahc"
            | "awc"
            | "attohttpc"
            | "curl"
            | "reqwless"
            | "wreq"
            | "gloo_net"
            | "reqwasm"
            | "web_sys"
            | "TcpStream"
            | "TcpSocket"
            | "UdpSocket"
            | "WebSocket"
            | "WebSocketStream"
            | "Fetch"
            | "HttpClient"
            | "SocketClient"
    )
}

#[test]
fn network_clients_stay_in_their_homes() {
    let mut sites = Vec::new();
    for source in arch_support::sources() {
        if source.path == OVERLAY_HOME || HOMES.iter().any(|home| source.path.starts_with(home)) {
            continue;
        }
        for token in source.tokens() {
            if !token.literal && is_client_name(token.text) {
                sites.push((
                    source.path.clone(),
                    token.line,
                    source.line(token.line).to_owned(),
                ));
            }
        }
    }
    arch_support::check_sites("network client outside a transport home", &sites, ALLOWED);
    println!("network exceptions: {} sites in 3 files", sites.len());
}

#[test]
fn imports_aliases_and_socket_types_are_client_sites() {
    for text in [
        "use reqwest as wire;",
        "use reqwest::{Client as Wire};",
        "use std::net::TcpStream;",
        "web_sys::window().fetch_with_str(path);",
    ] {
        assert!(arch_support::code_tokens(text, false)
            .iter()
            .any(|token| !token.literal && is_client_name(token.text)));
    }
}

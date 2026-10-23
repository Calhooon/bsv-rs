use super::cases;
use super::wallet::{calls, invoke, outcome};
use super::Suite;
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::wire::WalletCall;
use bsv_rs::Error;
use serde_json::{json, Value};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn request_value(request: &Request) -> Value {
    json!({"method": request.method.as_str(), "path": request.url.path(),
        "headers": {"content-type": request.headers.get("content-type").unwrap().to_str().unwrap(),
            "originator": request.headers.get("originator").unwrap().to_str().unwrap()},
        "json": serde_json::from_slice::<Value>(&request.body).unwrap()})
}

async fn captured(server: &MockServer) -> (Value, String) {
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "one request per fixture");
    (request_value(&requests[0]), hex::encode(&requests[0].body))
}

fn client(server: &MockServer, timeout: Duration) -> HttpWalletJson {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .build()
        .unwrap();
    HttpWalletJson::with_client(client, None, Some(server.uri()))
}

pub async fn record(suite: &mut Suite) {
    let server = MockServer::start().await;
    for call in calls() {
        let mut entries = Vec::new();
        for case in cases::cases(call) {
            server.reset().await;
            let response_body = serde_json::to_vec(&case.result).unwrap();
            Mock::given(method("POST"))
                .and(path(format!("/{}", call.method_name())))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(response_body.clone())
                        .insert_header("Content-Type", "application/json"),
                )
                .expect(1)
                .mount(&server)
                .await;
            let result = invoke(
                &client(&server, Duration::from_secs(10)),
                call,
                case.input.clone(),
            )
            .await;
            let (request, request_body_hex) = captured(&server).await;
            entries.push(json!({"name": case.name, "seed": cases::SEED,
                "input": {"args": case.input, "response_status": 200, "response_body": case.result},
                "expected": {"request": request, "request_body_hex": request_body_hex,
                    "response_body_hex": hex::encode(response_body), "client_result": outcome(result)}}));
        }
        assert_eq!(entries.len(), 2, "{call}: case count");
        suite.add(
            &format!("http_json/{}.json", call.method_name()),
            &[(
                "wallet/0100.md",
                &format!("The Wallet Interface / {}", call.method_name()),
            )],
            entries,
        );
    }
    suite.add(
        "http_json/errors.json",
        &[("wallet/0100.md", "Error Handling and Validation")],
        errors(&server).await,
    );
}

async fn errors(server: &MockServer) -> Vec<Value> {
    use WalletCall::*;
    let mut entries = Vec::new();
    let fault_cases = [
        (
            "busy_with_retry",
            CreateAction,
            503,
            Some("2"),
            json!({"code": "STORE_BUSY", "message": "fixture store busy"}),
        ),
        (
            "busy_without_retry",
            CreateAction,
            500,
            None,
            json!({"code": "STORE_BUSY", "message": "fixture store busy"}),
        ),
        (
            "toolbox_busy_with_retry",
            CreateAction,
            503,
            Some("1"),
            json!({"status": "error", "code": "ERR_SERVER_BUSY", "description": "fixture capacity busy"}),
        ),
        (
            "toolbox_busy_without_retry",
            CreateAction,
            429,
            None,
            json!({"code": "ERR_SERVER_BUSY", "description": "fixture capacity busy"}),
        ),
        (
            "busy_code_fallback",
            CreateAction,
            503,
            None,
            json!({"code": "STORE_BUSY"}),
        ),
        (
            "numeric_refusal",
            CreateAction,
            400,
            None,
            json!({"code": 6, "description": "fixture refused"}),
        ),
        (
            "numeric_refusal_on_503",
            CreateAction,
            503,
            None,
            json!({"code": 6, "description": "fixture refused"}),
        ),
        (
            "brc_string_refusal",
            CreateAction,
            403,
            None,
            json!({"status": "error", "code": "ERR_PERMISSION_DENIED", "description": "fixture permission refused"}),
        ),
        (
            "invalid_hmac_length",
            CreateHmac,
            200,
            None,
            json!({"hmac": [1,2,3]}),
        ),
        (
            "unknown_network",
            GetNetwork,
            200,
            None,
            json!({"network": "fixture-unknown"}),
        ),
    ];
    for (name, call, status, retry_after, body) in fault_cases {
        let mut template = ResponseTemplate::new(status).set_body_json(&body);
        if let Some(retry) = retry_after {
            template = template.insert_header("Retry-After", retry);
        }
        entries.push(
            error_case(
                server,
                name,
                call,
                template,
                json!({"status": status, "retry_after": retry_after, "body": body}),
            )
            .await,
        );
    }
    for status in [502, 503, 504] {
        entries.push(
            error_case(
                server,
                &format!("bare_{status}"),
                CreateAction,
                ResponseTemplate::new(status),
                json!({"status": status, "body_text": ""}),
            )
            .await,
        );
    }
    entries.push(
        error_case(
            server,
            "malformed_json",
            GetVersion,
            ResponseTemplate::new(200).set_body_string("not JSON"),
            json!({"status": 200, "body_text": "not JSON"}),
        )
        .await,
    );

    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/createAction"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .expect(1)
        .mount(server)
        .await;
    let args = cases::cases(CreateAction).remove(0).input;
    let error = invoke(
        &client(server, Duration::from_millis(250)),
        CreateAction,
        args.clone(),
    )
    .await
    .unwrap_err();
    let (request, request_body_hex) = captured(server).await;
    entries.push(json!({"name": "timeout", "input": {"call": "createAction", "args": args,
        "fault": {"client_timeout_ms": 250, "server_delay_ms": 5000}},
        "expected": {"request": request, "request_body_hex": request_body_hex, "client_error": transport_contract(error)}}));

    // Hold the listener until the client connects, then close with the request
    // unread. This produces a connection fault without relying on a port
    // remaining unused. Both futures are joined; no detached peer remains.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let wallet = HttpWalletJson::with_client(client, None, Some(format!("http://{address}")));
    let peer = async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.readable().await.unwrap();
        let _ = stream.try_read(&mut [0u8; 1]);
        drop(stream);
    };
    let (result, ()) = futures::join!(invoke(&wallet, CreateAction, args.clone()), peer);
    let error = result.unwrap_err();
    entries.push(
        json!({"name": "connection_error", "input": {"call": "createAction", "args": args,
        "fault": "accepted loopback connection closed before an HTTP response"},
        "expected": {"client_error": transport_contract(error)}}),
    );
    entries
}

async fn error_case(
    server: &MockServer,
    name: &str,
    call: WalletCall,
    template: ResponseTemplate,
    response: Value,
) -> Value {
    server.reset().await;
    Mock::given(method("POST"))
        .and(path(format!("/{}", call.method_name())))
        .respond_with(template)
        .expect(1)
        .mount(server)
        .await;
    let args = cases::cases(call).remove(0).input;
    let result = invoke(&client(server, Duration::from_secs(10)), call, args.clone()).await;
    assert!(result.is_err(), "{name}: fault must produce an error");
    let (request, request_body_hex) = captured(server).await;
    json!({"name": name, "input": {"call": call.method_name(), "args": args, "response": response},
        "expected": {"request": request, "request_body_hex": request_body_hex, "client_result": outcome(result)}})
}

fn transport_contract(error: Error) -> Value {
    match error {
        Error::WalletTransport { status, detail } => {
            assert_eq!(status, None);
            // The dependency's URL includes a dynamically allocated port and
            // its diagnostic is OS-specific. Pin the crate's contract, and
            // explicitly assert the invariant prefix instead of normalizing it.
            assert!(detail.starts_with("HTTP request failed: "), "{detail}");
            json!({"variant": "WalletTransport", "status": status, "detail_starts_with": "HTTP request failed: "})
        }
        error => panic!("expected WalletTransport, got {error:?}"),
    }
}

//! WebSocket transport for auth messages.
//!
//! This module provides a WebSocket-based transport for authentication messages,
//! matching the Go SDK's `WebSocketTransport` implementation. Connection is
//! established lazily on the first `send()` call, and a background task handles
//! receiving incoming messages.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use bsv_sdk::auth::transports::websocket_transport::{WebSocketTransport, WebSocketTransportOptions};
//!
//! let transport = WebSocketTransport::new(WebSocketTransportOptions {
//!     base_url: "ws://localhost:8080".to_string(),
//!     read_deadline_secs: Some(30),
//! })?;
//! ```

use crate::auth::types::AuthMessage;
use crate::{Error, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;

use super::http::{Transport, TransportCallback};

/// Configuration options for [`WebSocketTransport`].
#[derive(Debug, Clone)]
pub struct WebSocketTransportOptions {
    /// WebSocket URL to connect to (must start with `ws://` or `wss://`).
    pub base_url: String,
    /// Read deadline in seconds. Defaults to 30 if `None` or 0.
    pub read_deadline_secs: Option<u64>,
}

/// The write half of a tokio-tungstenite WebSocket connection.
type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;

/// WebSocket-based transport for BRC-31 authentication messages.
///
/// Implements the [`Transport`] trait for full-duplex WebSocket communication.
/// Connection is established lazily on the first [`send`](Transport::send) call,
/// and a background tokio task handles receiving incoming messages and dispatching
/// them to registered callbacks.
///
/// This implementation matches the Go SDK's `WebSocketTransport` behavior:
/// - Lazy connection on first send
/// - Background receive loop
/// - JSON-serialized `AuthMessage` payloads
/// - Connection dropped on send/receive errors
pub struct WebSocketTransport {
    /// WebSocket URL.
    base_url: String,
    /// Write half of the WebSocket connection (established lazily).
    sink: Arc<Mutex<Option<WsSink>>>,
    /// Callbacks for incoming messages.
    on_data_callbacks: Arc<RwLock<Vec<Box<TransportCallback>>>>,
    /// Read deadline in seconds.
    read_deadline_secs: u64,
}

impl std::fmt::Debug for WebSocketTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketTransport")
            .field("base_url", &self.base_url)
            .field("read_deadline_secs", &self.read_deadline_secs)
            .finish()
    }
}

impl WebSocketTransport {
    /// Creates a new WebSocket transport with the given options.
    ///
    /// # Arguments
    /// * `options` - Configuration including the WebSocket URL and optional read deadline
    ///
    /// # Errors
    /// Returns an error if `base_url` is empty or does not start with `ws://` or `wss://`.
    pub fn new(options: WebSocketTransportOptions) -> Result<Self> {
        if options.base_url.is_empty() {
            return Err(Error::TransportError(
                "base_url is required for WebSocket transport".into(),
            ));
        }

        // Validate WebSocket URL scheme
        if !options.base_url.starts_with("ws://") && !options.base_url.starts_with("wss://") {
            return Err(Error::TransportError(
                "WebSocket URL must start with ws:// or wss://".into(),
            ));
        }

        // Validate the URL is parseable
        url_parse_check(&options.base_url)?;

        let read_deadline_secs = match options.read_deadline_secs {
            Some(s) if s > 0 => s,
            _ => 30,
        };

        Ok(Self {
            base_url: options.base_url,
            sink: Arc::new(Mutex::new(None)),
            on_data_callbacks: Arc::new(RwLock::new(Vec::new())),
            read_deadline_secs,
        })
    }

    /// Returns the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the read deadline in seconds.
    pub fn read_deadline_secs(&self) -> u64 {
        self.read_deadline_secs
    }

    /// Establishes the WebSocket connection and starts the background receive loop.
    ///
    /// Returns the write-half sink for sending messages. The read-half stream is
    /// consumed by a spawned tokio task that dispatches incoming messages to callbacks.
    async fn connect(&self) -> Result<()> {
        let (ws_stream, _response) = tokio_tungstenite::connect_async(&self.base_url)
            .await
            .map_err(|e| Error::TransportError(format!("failed to connect to WebSocket: {}", e)))?;

        let (sink, stream) = ws_stream.split();

        // Store the write half
        {
            let mut sink_guard = self.sink.lock().await;
            *sink_guard = Some(sink);
        }

        // Spawn background receive loop
        let callbacks = self.on_data_callbacks.clone();
        let sink_ref = self.sink.clone();
        let deadline = self.read_deadline_secs;

        tokio::spawn(async move {
            receive_loop(stream, callbacks, sink_ref, deadline).await;
        });

        Ok(())
    }
}

/// Background receive loop that reads messages from the WebSocket stream
/// and dispatches them to registered callbacks.
async fn receive_loop(
    mut stream: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    callbacks: Arc<RwLock<Vec<Box<TransportCallback>>>>,
    sink: Arc<Mutex<Option<WsSink>>>,
    _deadline: u64,
) {
    loop {
        match stream.next().await {
            Some(Ok(msg)) => {
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Binary(b) => match String::from_utf8(b.to_vec()) {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                    Message::Close(_) => {
                        // Connection closed by server
                        let mut sink_guard = sink.lock().await;
                        *sink_guard = None;
                        return;
                    }
                    // Ping/Pong handled automatically by tungstenite
                    _ => continue,
                };

                // Deserialize incoming JSON as AuthMessage
                let auth_message: AuthMessage = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(_) => continue, // Skip malformed messages (matches Go behavior)
                };

                // Dispatch to all registered callbacks
                let cbs = callbacks.read().await;
                for cb in cbs.iter() {
                    let _ = cb(auth_message.clone()).await;
                }
            }
            Some(Err(_)) => {
                // Connection error - drop connection and exit
                let mut sink_guard = sink.lock().await;
                *sink_guard = None;
                return;
            }
            None => {
                // Stream ended
                let mut sink_guard = sink.lock().await;
                *sink_guard = None;
                return;
            }
        }
    }
}

/// Validates that a string is a parseable URL.
fn url_parse_check(url: &str) -> Result<()> {
    // Basic validation: try to parse as a URL by checking structure
    // We already validated the scheme above, so check for a host component
    let after_scheme = if let Some(rest) = url.strip_prefix("wss://") {
        rest
    } else if let Some(rest) = url.strip_prefix("ws://") {
        rest
    } else {
        return Err(Error::TransportError("invalid WebSocket URL".into()));
    };

    if after_scheme.is_empty() {
        return Err(Error::TransportError(
            "WebSocket URL must include a host".into(),
        ));
    }

    Ok(())
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        // Check that at least one callback is registered (matches Go behavior)
        {
            let cbs = self.on_data_callbacks.read().await;
            if cbs.is_empty() {
                return Err(Error::TransportError("no handler registered".into()));
            }
        }

        // Lazy connection: connect on first send
        {
            let sink_guard = self.sink.lock().await;
            if sink_guard.is_none() {
                drop(sink_guard);
                self.connect().await?;
            }
        }

        // Serialize the message to JSON
        let json_data = serde_json::to_string(message)
            .map_err(|e| Error::TransportError(format!("failed to marshal auth message: {}", e)))?;

        // Send the message
        let mut sink_guard = self.sink.lock().await;
        if let Some(ref mut sink) = *sink_guard {
            if let Err(e) = sink.send(Message::Text(json_data)).await {
                // Drop connection on error (matches Go behavior)
                *sink_guard = None;
                return Err(Error::TransportError(format!(
                    "failed to send WebSocket message: {}",
                    e
                )));
            }
            Ok(())
        } else {
            Err(Error::TransportError(
                "WebSocket connection not available".into(),
            ))
        }
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        let callbacks = self.on_data_callbacks.clone();
        tokio::spawn(async move {
            let mut cbs = callbacks.write().await;
            cbs.push(callback);
        });
    }

    fn clear_callback(&self) {
        let callbacks = self.on_data_callbacks.clone();
        tokio::spawn(async move {
            let mut cbs = callbacks.write().await;
            cbs.clear();
        });
    }
}

#[cfg(all(test, feature = "websocket"))]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_valid_ws_url() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://localhost:8080".to_string(),
            read_deadline_secs: None,
        });
        assert!(transport.is_ok());
        let t = transport.unwrap();
        assert_eq!(t.base_url(), "ws://localhost:8080");
    }

    #[test]
    fn test_new_with_valid_wss_url() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "wss://example.com/ws".to_string(),
            read_deadline_secs: Some(60),
        });
        assert!(transport.is_ok());
        let t = transport.unwrap();
        assert_eq!(t.base_url(), "wss://example.com/ws");
        assert_eq!(t.read_deadline_secs(), 60);
    }

    #[test]
    fn test_new_with_empty_url_returns_error() {
        let result = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: String::new(),
            read_deadline_secs: None,
        });
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::TransportError(msg) => {
                assert!(msg.contains("base_url is required"));
            }
            other => panic!("expected TransportError, got: {:?}", other),
        }
    }

    #[test]
    fn test_new_with_http_url_returns_error() {
        let result = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "http://example.com".to_string(),
            read_deadline_secs: None,
        });
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::TransportError(msg) => {
                assert!(msg.contains("ws://") || msg.contains("wss://"));
            }
            other => panic!("expected TransportError, got: {:?}", other),
        }
    }

    #[test]
    fn test_new_with_https_url_returns_error() {
        let result = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "https://example.com".to_string(),
            read_deadline_secs: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_new_with_invalid_scheme_returns_error() {
        let result = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ftp://example.com".to_string(),
            read_deadline_secs: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_default_read_deadline() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://localhost:8080".to_string(),
            read_deadline_secs: None,
        })
        .unwrap();
        assert_eq!(transport.read_deadline_secs(), 30);
    }

    #[test]
    fn test_zero_read_deadline_defaults_to_30() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://localhost:8080".to_string(),
            read_deadline_secs: Some(0),
        })
        .unwrap();
        assert_eq!(transport.read_deadline_secs(), 30);
    }

    #[test]
    fn test_custom_read_deadline() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://localhost:8080".to_string(),
            read_deadline_secs: Some(120),
        })
        .unwrap();
        assert_eq!(transport.read_deadline_secs(), 120);
    }

    #[test]
    fn test_ws_url_without_host_returns_error() {
        let result = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://".to_string(),
            read_deadline_secs: None,
        });
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_on_data_callback_registration() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://localhost:9999".to_string(),
            read_deadline_secs: None,
        })
        .unwrap();

        // Register a callback via set_callback
        transport.set_callback(Box::new(|_msg| Box::pin(async move { Ok(()) })));

        // Wait for the spawned task to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Verify callback was registered
        let cbs = transport.on_data_callbacks.read().await;
        assert_eq!(cbs.len(), 1);
    }

    #[tokio::test]
    async fn test_clear_callback() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://localhost:9999".to_string(),
            read_deadline_secs: None,
        })
        .unwrap();

        // Register a callback
        transport.set_callback(Box::new(|_msg| Box::pin(async move { Ok(()) })));
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Clear callbacks
        transport.clear_callback();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let cbs = transport.on_data_callbacks.read().await;
        assert_eq!(cbs.len(), 0);
    }

    #[tokio::test]
    async fn test_send_without_callback_returns_error() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://localhost:9999".to_string(),
            read_deadline_secs: None,
        })
        .unwrap();

        let msg = AuthMessage::new(
            crate::auth::types::MessageType::InitialRequest,
            crate::primitives::PrivateKey::random().public_key(),
        );

        let result = transport.send(&msg).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::TransportError(msg) => {
                assert!(msg.contains("no handler registered"));
            }
            other => panic!("expected TransportError, got: {:?}", other),
        }
    }

    #[test]
    fn test_debug_format() {
        let transport = WebSocketTransport::new(WebSocketTransportOptions {
            base_url: "ws://localhost:8080".to_string(),
            read_deadline_secs: Some(45),
        })
        .unwrap();

        let debug = format!("{:?}", transport);
        assert!(debug.contains("WebSocketTransport"));
        assert!(debug.contains("ws://localhost:8080"));
        assert!(debug.contains("45"));
    }

    #[test]
    fn test_url_parse_check_valid() {
        assert!(url_parse_check("ws://localhost:8080").is_ok());
        assert!(url_parse_check("wss://example.com/path").is_ok());
        assert!(url_parse_check("ws://192.168.1.1:3000/ws").is_ok());
    }

    #[test]
    fn test_url_parse_check_empty_host() {
        assert!(url_parse_check("ws://").is_err());
        assert!(url_parse_check("wss://").is_err());
    }

    #[test]
    fn test_url_parse_check_invalid_scheme() {
        assert!(url_parse_check("http://example.com").is_err());
    }
}

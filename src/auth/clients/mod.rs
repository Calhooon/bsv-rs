//! Authenticated fetch clients over the BRC-104 transport.

mod fallback;
mod labels;
mod payment;
mod request;
mod response;
mod retry;
mod shared_wallet;
mod state;
mod transport;

pub mod auth_fetch;
pub use auth_fetch::{AuthFetch, AuthFetchOptions};
pub use payment::parse_known_txids_header;
pub use response::Response;

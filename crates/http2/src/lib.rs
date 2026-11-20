//! HTTP/2 client fingerprinting as tls.peet.ws does it.
//!
//! [`Parser`] turns the client's bytes after the TLS handshake into tls.peet.ws's frame list,
//! [`akamai_fingerprint`] reduces it to the Akamai fingerprint, and [`serve`] runs the whole
//! one-request exchange, with the body supplied by the caller.

mod akamai;
mod frame;
mod parser;
mod request;
mod serve;

pub use akamai::{akamai_fingerprint, akamai_fingerprint_hash};
pub use frame::{GoAway, ParsedFrame, Priority};
pub use parser::{DEFAULT_MAX_INPUT, Error, MAX_FRAMES, MAX_HEADER_BYTES, PREFACE, Parser, Status};
pub use request::{Http2Details, Http2Request};
pub use serve::{Response, ServeError, serve, serve_with_prefix};

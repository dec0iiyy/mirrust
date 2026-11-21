//! TLS client fingerprints: JA3, JA4 (FoxIO spec) and, as tls.peet.ws reports them,
//! PeetPrint and its JA4 variant.
//!
//! Parse the ClientHello handshake message once with [`ClientHello::parse`] (or
//! [`ClientHello::parse_peet`] for the tls.peet.ws fields), then compute any fingerprint from
//! it. The tls.peet.ws fields match that service byte for byte, quirks included, so reports
//! from both compare directly.
//!
//! [`known`] tells which known client a JA4 belongs to and what a `User-Agent` claims.

mod client_hello;
mod details;
mod grease;
mod ja3;
mod ja4;
mod ja4_peet;
pub mod known;
mod names;
mod peetprint;
mod text;
mod transport_parameters;

pub use client_hello::{ClientHello, Extension};
pub use grease::is_grease;
pub use ja3::Ja3;
pub use ja4::{Ja4, Transport};
pub use ja4_peet::Ja4Peet;
pub use peetprint::PeetPrint;

/// The IANA name of a TLS cipher suite, as reports print it; `None` for a code point
/// without one, GREASE included.
#[must_use]
pub fn cipher_suite_name(id: u16) -> Option<&'static str> {
    names::cipher_suite(id)
}

/// The IANA name of a TLS extension type, as reports print it; `None` for a code point
/// without one, GREASE included.
#[must_use]
pub fn extension_name(id: u16) -> Option<&'static str> {
    names::extension(id)
}

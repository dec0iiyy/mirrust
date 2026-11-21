//! TLS client fingerprints: JA3, JA4 (FoxIO spec) and, as tls.peet.ws reports them,
//! PeetPrint and its JA4 variant.
//!
//! Parse the ClientHello handshake message once with [`ClientHello::parse`] (or
//! [`ClientHello::parse_peet`] for the tls.peet.ws fields), then compute any fingerprint from
//! it. The tls.peet.ws fields match that service byte for byte, quirks included, so reports
//! from both compare directly.
//!
//! [`known`] tells which known client a JA4 belongs to and what a `User-Agent` claims.
//!
//! # Examples
//!
//! The input is the handshake message, starting at its type byte (`01`), without the TLS
//! record header. This one is Android 11's ClientHello for `example.com`:
//!
//! ```
//! use fingerprint::{ClientHello, Ja3, Ja4, Transport};
//!
//! let hex = "010000b1030390d5e21bb5fe0d40948cde614e1a2e300e26a4a78a82109e314ee37aa1cb7cc0205d4e\
//!            4053f861c83df9d9587ea1ae0e565a5d221ebc1ad10b34b751dec5cdb9750018c02bc02ccca9c02fc0\
//!            30cca8c013c014009c009d002f00350100005000000010000e00000b6578616d706c652e636f6d0017\
//!            0000ff01000100000a00080006001d00170018000b00020100000500050100000000000d0014001204\
//!            0308040401050308050501080606010201";
//! let message = (0..hex.len())
//!     .step_by(2)
//!     .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
//!     .collect::<Result<Vec<u8>, _>>()?;
//!
//! let hello = ClientHello::parse(&message);
//! let ja4 = Ja4::new(&hello, Transport::Tcp);
//! let ja3 = Ja3::new(&hello);
//! println!("JA4 {}\nJA3 {}", ja4.hashed(), ja3.hash());
//! assert_eq!(ja4.hashed(), "t12d120700_d34a8e72043a_036209cd1ead");
//! assert_eq!(ja3.hash(), "6c0f0a346dcd84cb4b97a0d9382c53fd");
//! # Ok::<(), std::num::ParseIntError>(())
//! ```

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

/// Compiles and runs the example of `README.md`.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
struct ReadmeDoctests;

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

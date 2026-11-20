//! Semantic diff of two client fingerprints: does a client's TLS ClientHello (and HTTP/2
//! fingerprint) look like a reference browser's?
//!
//! Read each side with [`Profile::parse`] (tls.peet.ws JSON or a ClientHello in hex), then
//! [`compare`] them. What varies per connection (GREASE, randoms, session id, key share bytes,
//! padding length, SNI value, and by default extension order) is not compared.

mod compare;
mod http2;
mod profile;

pub use compare::{
    Change, Ja4Comparison, Options, ParseSectionError, Report, Section, SectionDiff, compare,
};
pub use http2::Akamai;
pub use profile::{InputError, Profile, peet_tls};

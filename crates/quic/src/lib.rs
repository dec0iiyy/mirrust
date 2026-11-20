//! Extracts the TLS ClientHello from a client's QUIC Initial packets.
//!
//! QUIC (RFC 9000) carries the ClientHello in CRYPTO frames inside Initial packets, encrypted
//! with keys anyone can derive from the client's Destination Connection ID (RFC 9001 §5.2).
//! [`InitialAssembler`] takes the client's datagrams, removes header protection, decrypts the
//! payloads, and reassembles the CRYPTO stream until the whole ClientHello is there, which may
//! take several packets and datagrams (post-quantum key shares make it larger than one packet).
//! QUIC v1 and v2 (RFC 9369) are supported.
//!
//! # Examples
//!
//! ```
//! # fn run(datagrams: &[Vec<u8>]) -> Result<(), quic::Error> {
//! let mut assembler = quic::InitialAssembler::new();
//! for datagram in datagrams {
//!     if let Some(initial) = assembler.push(datagram)? {
//!         println!("{:?}: {} bytes", initial.version(), initial.client_hello().len());
//!     }
//! }
//! # Ok(())
//! # }
//! ```

mod assembler;
mod error;
mod frame;
mod packet;
mod reader;

pub use assembler::{ClientInitial, InitialAssembler, MAX_CRYPTO_LEN, MAX_DATAGRAM_SIZES};
pub use error::Error;
pub use packet::Version;

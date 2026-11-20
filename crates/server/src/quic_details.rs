//! The `quic` object of a report: what the client's Initial packets show besides the
//! ClientHello.

use quic::ClientInitial;
use serde_json::{Value, json};

/// Header fields and datagram sizes of a client's first flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuicDetails {
    /// The version field of the Initial packets.
    version: u32,
    dcid_len: usize,
    scid_len: usize,
    token_len: usize,
    /// Sizes of the datagrams that carried the ClientHello, in arrival order.
    datagram_sizes: Vec<usize>,
}

impl QuicDetails {
    pub(crate) fn new(initial: &ClientInitial) -> Self {
        Self {
            version: initial.version().to_wire(),
            dcid_len: initial.dcid().len(),
            scid_len: initial.scid().len(),
            token_len: initial.token_len(),
            datagram_sizes: initial.datagram_sizes().to_vec(),
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "version": format!("0x{:08x}", self.version),
            "dcid_length": self.dcid_len,
            "scid_length": self.scid_len,
            "token_length": self.token_len,
            "initial_datagrams": self.datagram_sizes.len(),
            "initial_datagram_sizes": self.datagram_sizes,
        })
    }
}

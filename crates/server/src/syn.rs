//! The TCP SYN of an accepted connection, as the kernel kept it.
//!
//! Linux saves the SYN of every connection of a listening socket that has `TCP_SAVE_SYN`
//! set, from the IP header to the end of the TCP header, and hands it out once through
//! `TCP_SAVED_SYN` on the accepted socket. Both are plain socket options: no packet capture,
//! no privilege, and no table that pairs packets with connections.
//!
//! The two system calls are made by the `tcp-save-syn` crate, because this workspace
//! forbids `unsafe` code and `getsockopt` cannot be called without it. Its functions exist on
//! every system and do nothing where the options do not, so nothing here is conditional:
//! off Linux, on a kernel before 4.2, and in a sandbox that refuses the options (gVisor), no
//! SYN is found and the report says so.

use tokio::net::{TcpListener, TcpStream};

/// Asks the kernel to keep the SYN of each connection `listener` accepts from now on.
///
/// A refusal is not reported: the server works without, and says "not measured".
pub(crate) fn keep(listener: &TcpListener) {
    // Whatever the reason, the answer is the same: no SYN in the reports.
    let _ = tcp_save_syn::enable_save_syn(listener);
}

/// The SYN that opened `stream`, if the kernel kept it and it is one that can be read.
///
/// The kernel gives it out once, so this is called once, right after `accept`.
pub(crate) fn saved(stream: &TcpStream) -> Option<tcpip::Syn> {
    tcpip::Syn::parse(&tcp_save_syn::get_saved_syn(stream)?)
}

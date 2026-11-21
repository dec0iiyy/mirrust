//! A captured packet, from the IP header on, into `tcpip::Syn::parse`: IPv4/IPv6 headers, the
//! TCP header and SYN options, then the p0f signature and the serialized `tcpip` object.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tcpip::{Syn, TcpIp};

/// TCP options take at most 40 bytes (data offset 15 words minus the 20-byte header).
const MAX_OPTION_BYTES: usize = 40;
/// `SynDetails::options` holds at most this many names.
const MAX_OPTION_NAMES: usize = 24;

fuzz_target!(|data: &[u8]| {
    let syn = Syn::parse(data);
    if let Some(syn) = &syn {
        let details = &syn.details;
        assert!(matches!(details.ip_version, 4 | 6));
        let is_v4 = details.ip_version == 4;
        assert_eq!(details.ip_id.is_some(), is_v4);
        assert_eq!(details.df.is_some(), is_v4);
        assert!(
            details.options.len() <= MAX_OPTION_NAMES,
            "{:?}",
            details.options
        );
        assert_eq!(details.option_order, details.options.join(","));
        let raw = &details.options_raw;
        assert!(
            raw.len() % 2 == 0 && raw.len() <= 2 * MAX_OPTION_BYTES,
            "{raw}"
        );
        assert!(
            raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{raw}"
        );
        assert!(details.payload_len < data.len());
        // `ver:ttl+?:olen:mss:wsize,scale:olayout:quirks:pclass`: eight fields.
        assert_eq!(syn.p0f.matches(':').count(), 7, "{}", syn.p0f);
        assert!(
            syn.p0f
                .starts_with(&format!("{}:{}+?:", details.ip_version, details.ttl))
        );
    }
    let tcpip = TcpIp::new(syn);
    serde_json::to_string(&tcpip).expect("tcpip serializes");
});

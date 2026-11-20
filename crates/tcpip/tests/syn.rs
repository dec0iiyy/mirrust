//! Two reference SYN packets, plus truncation and JSON shape.

use tcpip::Syn;

/// IPv4 SYN: IPv4, TTL 47, id 12345, DF, MSS 1460, SACK,
/// timestamps (1020304, 0), NOP, window scale 8.
const SAMPLE_V4: &str = "4500003c303940002f060000c000020ac6336414\
                          d43101bb0001e24000000000a002faf000000000\
                          020405b40402080a010203040000000001030308";

/// IPv6 SYN, no IPv4-only fields: traffic class 2, flow 123,
/// hop limit 55, window 65535, no options.
const SAMPLE_V6: &str = "6020007b0014063720010db80000000000000000\
                          0000001020010db8000000000000000000000020\
                          d43101bb0001e240000000005002ffff00000000";

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("test hex is valid"))
        .collect()
}

#[test]
fn parses_ipv4_syn() {
    let syn = Syn::parse(&decode_hex(SAMPLE_V4)).expect("SYN was parsed");
    assert_eq!(syn.p0f, "4:47+?:0:1460:64240,8:mss,sok,ts,nop,ws:df,id+:0");
    let details = &syn.details;
    assert_eq!(
        (
            details.ip_version,
            details.src_ip.as_str(),
            details.dst_ip.as_str()
        ),
        (4, "192.0.2.10", "198.51.100.20")
    );
    assert_eq!(
        (
            details.src_port,
            details.dst_port,
            details.ttl,
            details.ip_id
        ),
        (54321, 443, 47, Some(12345))
    );
    assert_eq!(details.df, Some(true));
    assert!(!details.ecn);
    assert_eq!((details.window, details.mss), (64240, 1460));
    assert_eq!(details.window_scale, Some(8));
    assert!(details.sack_permitted && details.timestamps);
    assert_eq!(
        details.options,
        ["mss", "sackOK", "timestamp", "nop", "wscale"]
    );
    assert_eq!(
        details.options_raw,
        "020405b40402080a010203040000000001030308"
    );
    assert_eq!(details.option_order, "mss,sackOK,timestamp,nop,wscale");
    assert_eq!((details.payload_len, details.packet_len), (0, 60));
}

#[test]
fn ipv6_omits_ipv4_only_fields() {
    let syn = Syn::parse(&decode_hex(SAMPLE_V6)).expect("SYN was parsed");
    assert_eq!(syn.p0f, "6:55+?:0:0:65535,0::ecn,flow:0");
    assert_eq!((syn.details.ip_id, syn.details.df), (None, None));
    assert!(syn.details.ecn);
    assert_eq!(syn.details.packet_len, 60);

    let json = serde_json::to_string(&syn.details).expect("serialize");
    assert_eq!(
        json,
        r#"{"ip_version":6,"src_ip":"2001:db8::10","dst_ip":"2001:db8::20","src_port":54321,"dst_port":443,"ttl":55,"ecn":true,"window":65535,"mss":0,"sack_permitted":false,"timestamps":false,"options":null,"options_raw":"","option_order":"","payload_len":0,"packet_len":60}"#
    );
}

#[test]
fn truncated_packets_never_panic() {
    for packet in [SAMPLE_V4, SAMPLE_V6].map(decode_hex) {
        for end in 0..packet.len() {
            let syn = Syn::parse(&packet[..end]);
            // Without the full fixed headers there is nothing to fingerprint.
            let headers = if packet[0] >> 4 == 4 { 40 } else { 60 };
            if end < headers {
                assert!(syn.is_none(), "prefix of {end} bytes gave {syn:?}");
            }
        }
    }
}

#[test]
fn rejects_syn_ack() {
    let mut packet = decode_hex(SAMPLE_V4);
    packet[33] |= 0x10;
    assert!(Syn::parse(&packet).is_none());
}

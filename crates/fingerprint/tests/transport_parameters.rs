//! The `quic_transport_parameters` details of the ClientHello Chrome Canary 160 sent over QUIC
//! (the capture `crates/quic` replays).

use fingerprint::ClientHello;
use serde_json::json;

fn unhex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn chrome_transport_parameters_keep_their_order() {
    let message = unhex(include_str!(
        "../../quic/tests/data/chrome160_client_hello.hex"
    ));
    let details = ClientHello::parse_peet(&message).extension_details();
    let extension = details
        .as_array()
        .expect("extensions")
        .iter()
        .find(|extension| extension["name"] == "quic_transport_parameters (57)")
        .expect("a QUIC ClientHello carries extension 57");
    assert_eq!(
        extension["parameters"],
        json!([
            { "id": 8, "name": "initial_max_streams_bidi", "value": 100 },
            { "id": 9, "name": "initial_max_streams_uni", "value": 103 },
            { "id": 1, "name": "max_idle_timeout", "value": 30000 },
            { "id": 17, "name": "version_information", "value": "00000001000000018a0afaea" },
            { "id": 7, "name": "initial_max_stream_data_uni", "value": 6_291_456 },
            {
                "id": 12584,
                "name": "google_connection_options",
                "value": "4231414c354146464f524947",
            },
            { "id": 6, "name": "initial_max_stream_data_bidi_remote", "value": 6_291_456 },
            { "id": 32, "name": "max_datagram_frame_size", "value": 65536 },
            { "id": 5, "name": "initial_max_stream_data_bidi_local", "value": 6_291_456 },
            { "id": 4, "name": "initial_max_data", "value": 15_728_640 },
            { "id": 3, "name": "max_udp_payload_size", "value": 1472 },
            // 31 * N + 27 with an eight-byte N: Chrome's GREASE parameter.
            { "id": 3_585_582_852_614_701_089_u64, "name": "GREASE", "value": "aaf5448545" },
            { "id": 15, "name": "initial_source_connection_id", "value": "" },
        ])
    );
    // The field tls.peet.ws reports stays as it was.
    let data = extension["data"].as_str().expect("data");
    assert!(data.starts_with("080240640902"), "{data}");
}

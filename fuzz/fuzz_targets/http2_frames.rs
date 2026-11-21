//! A client byte stream into `http2::Parser`: preface, frame headers, every frame type and HPACK
//! header block decoding, then the Akamai fingerprint and request summary built from the frames.
//!
//! Input: one byte that sets a chunk size (1 to 256), then the stream. The stream is fed once
//! whole and once in chunks; both must end the same way.

#![no_main]

use http2::{Http2Request, MAX_FRAMES, MAX_HEADER_BYTES, Parser, Status};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, stream)) = data.split_first() else {
        return;
    };
    let mut whole = Parser::new();
    let whole_result = whole.feed(stream);

    let mut chunked = Parser::new();
    let mut chunked_result = Ok(Status::Incomplete);
    for piece in stream.chunks(usize::from(chunk) + 1) {
        chunked_result = chunked.feed(piece);
        if chunked_result != Ok(Status::Incomplete) {
            break;
        }
    }
    assert_eq!(
        whole_result,
        chunked_result,
        "chunks of {}",
        usize::from(chunk) + 1
    );
    assert_eq!(whole.frames(), chunked.frames());
    assert_eq!(whole.last_stream(), chunked.last_stream());
    assert_eq!(whole.request_stream(), chunked.request_stream());
    if let Err(error) = &whole_result {
        assert_eq!(
            whole.feed(b"more"),
            Err(error.clone()),
            "the first error is final"
        );
    }

    let frames = whole.frames();
    assert!(frames.len() <= MAX_FRAMES, "{} frames", frames.len());
    // Each decoded byte of a header line is kept as one char, or as U+FFFD (3 bytes) when it
    // is not UTF-8.
    let header_bytes: usize = frames
        .iter()
        .flat_map(|f| &f.headers)
        .map(String::len)
        .sum();
    assert!(
        header_bytes <= 3 * MAX_HEADER_BYTES,
        "{header_bytes} header bytes"
    );

    let request = Http2Request::new(whole);
    let details = &request.details;
    let fingerprint = &details.akamai_fingerprint;
    // The pseudo-header part is raw header bytes and may hold `|` itself.
    assert_eq!(fingerprint.splitn(4, '|').count(), 4, "{fingerprint}");
    assert_eq!(details.akamai_fingerprint_hash.len(), 32);
    serde_json::to_string(details).expect("details serialize");
    let _ = request.headers();
});

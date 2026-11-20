use crate::Error;
use crate::reader::Reader;

const PADDING: u64 = 0x00;
const PING: u64 = 0x01;
const ACK: u64 = 0x02;
const ACK_ECN: u64 = 0x03;
const CRYPTO: u64 = 0x06;
const CONNECTION_CLOSE: u64 = 0x1c;

/// The data of one CRYPTO frame and its offset in the crypto stream.
pub(crate) struct CryptoFrame<'pkt> {
    pub(crate) offset: u64,
    pub(crate) data: &'pkt [u8],
}

/// Reads the frames of a decrypted Initial payload and returns its CRYPTO frames in packet order.
///
/// Initial packets may carry only PADDING, PING, ACK, CRYPTO and `CONNECTION_CLOSE`
/// (RFC 9000 §12.4, table 3); anything else is an error.
pub(crate) fn crypto_frames(payload: &[u8]) -> Result<Vec<CryptoFrame<'_>>, Error> {
    let mut reader = Reader::new(payload);
    let mut frames = Vec::new();
    while !reader.is_empty() {
        match reader.varint()? {
            PADDING | PING => {}
            kind @ (ACK | ACK_ECN) => skip_ack(&mut reader, kind == ACK_ECN)?,
            CRYPTO => {
                let offset = reader.varint()?;
                let data = reader.varint_bytes()?;
                frames.push(CryptoFrame { offset, data });
            }
            CONNECTION_CLOSE => {
                reader.varint()?; // error code
                reader.varint()?; // frame type
                reader.varint_bytes()?; // reason phrase
            }
            other => return Err(Error::UnexpectedFrame(other)),
        }
    }
    Ok(frames)
}

fn skip_ack(reader: &mut Reader<'_>, ecn: bool) -> Result<(), Error> {
    reader.varint()?; // largest acknowledged
    reader.varint()?; // ack delay
    let ranges = reader.varint()?;
    reader.varint()?; // first ack range
    // Each range takes at least two bytes, so a bogus count runs out of input quickly.
    for _ in 0..ranges {
        reader.varint()?; // gap
        reader.varint()?; // ack range length
    }
    if ecn {
        for _ in 0..3 {
            reader.varint()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_crypto_between_padding_ping_and_ack() {
        let payload = [
            0x00, 0x01, // PADDING, PING
            0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x01, // ACK with one extra range
            0x06, 0x40, 0x10, 0x02, 0xaa, 0xbb, // CRYPTO offset 16, 2 bytes
            0x00, 0x00,
        ];
        let frames = crypto_frames(&payload).expect("valid frames");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].offset, 16);
        assert_eq!(frames[0].data, [0xaa, 0xbb]);
    }

    #[test]
    fn rejects_stream_frames_and_truncation() {
        assert_eq!(
            crypto_frames(&[0x08, 0x00]).err(),
            Some(Error::UnexpectedFrame(0x08))
        );
        assert_eq!(
            crypto_frames(&[0x06, 0x00, 0x05, 0xaa]).err(),
            Some(Error::Truncated)
        );
        assert_eq!(
            crypto_frames(&[0x02, 0x00, 0x00, 0x3f, 0x00]).err(),
            Some(Error::Truncated)
        );
    }
}

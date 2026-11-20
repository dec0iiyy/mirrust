use crate::Error;

/// A cursor over untrusted bytes whose reads fail with [`Error::Truncated`] instead of panicking.
pub(crate) struct Reader<'buf> {
    buf: &'buf [u8],
    pos: usize,
}

impl<'buf> Reader<'buf> {
    pub(crate) fn new(buf: &'buf [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'buf [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::Truncated)?;
        let bytes = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        let byte = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(byte)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let bytes = self.bytes(4)?;
        Ok(bytes.iter().fold(0, |acc, &b| acc << 8 | u32::from(b)))
    }

    /// Reads a variable-length integer (RFC 9000 §16).
    pub(crate) fn varint(&mut self) -> Result<u64, Error> {
        let first = self.u8()?;
        let rest = self.bytes((1 << (first >> 6)) - 1)?;
        Ok(rest
            .iter()
            .fold(u64::from(first & 0x3f), |acc, &b| acc << 8 | u64::from(b)))
    }

    /// Reads a varint length prefix followed by that many bytes.
    pub(crate) fn varint_bytes(&mut self) -> Result<&'buf [u8], Error> {
        let len = self.varint()?;
        self.bytes(usize::try_from(len).map_err(|_| Error::Truncated)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_examples_from_rfc9000_appendix_a1() {
        let cases: [(&[u8], u64); 4] = [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (bytes, want) in cases {
            assert_eq!(Reader::new(bytes).varint(), Ok(want), "input {bytes:02x?}");
        }
        assert_eq!(Reader::new(&[0x7b]).varint(), Err(Error::Truncated));
    }
}

//! TCP options of a SYN, read the way p0f v3 (and tls.peet.ws) reads them.

const KIND_EOL: u8 = 0;
const KIND_NOP: u8 = 1;
const KIND_MSS: u8 = 2;
const KIND_WINDOW_SCALE: u8 = 3;
const KIND_SACK_PERMITTED: u8 = 4;
const KIND_SACK: u8 = 5;
const KIND_TIMESTAMPS: u8 = 8;

/// p0f reads at most this many options and marks any remainder as bad.
const MAX_OPTIONS: usize = 24;

/// Largest window scale RFC 7323 allows; p0f flags anything above as `exws`.
const MAX_WINDOW_SCALE: u8 = 14;

/// What the options of one SYN say, including the p0f quirks they carry.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent option flags and p0f quirks, one per field of tls.peet.ws's `tcp_syn` object"
)]
pub(crate) struct SynOptions {
    /// tls.peet.ws's option names in wire order (`mss`, `sackOK`, `unknown-30`, ...).
    pub(crate) names: Vec<String>,
    /// p0f's option layout in wire order (`mss`, `sok`, `eol+2`, `?30`, ...).
    pub(crate) layout: Vec<String>,
    pub(crate) mss: u16,
    pub(crate) window_scale: Option<u8>,
    pub(crate) sack_permitted: bool,
    pub(crate) timestamps: bool,
    pub(crate) zero_timestamp: bool,
    pub(crate) nonzero_timestamp2: bool,
    pub(crate) nonzero_eol_padding: bool,
    pub(crate) excessive_window_scale: bool,
    pub(crate) bad: bool,
}

impl SynOptions {
    /// Reads the raw option bytes (the TCP header past its first 20 bytes).
    pub(crate) fn parse(raw: &[u8]) -> Self {
        let mut parsed = Self::default();
        if parsed.read(raw).is_none() {
            parsed.bad = true;
        }
        parsed
    }

    /// Returns `None` where p0f gives up: a truncated option, an impossible length, more than
    /// [`MAX_OPTIONS`] options, or bytes left over.
    fn read(&mut self, raw: &[u8]) -> Option<()> {
        let mut offset = 0;
        while let Some(&kind) = raw.get(offset)
            && self.layout.len() < MAX_OPTIONS
        {
            offset += 1;
            match kind {
                KIND_EOL => {
                    let padding = raw.get(offset..).unwrap_or_default();
                    self.push("eol", format!("eol+{}", padding.len()));
                    if padding.iter().any(|&byte| byte != 0) {
                        self.nonzero_eol_padding = true;
                    }
                    offset = raw.len();
                }
                KIND_NOP => self.push("nop", "nop".into()),
                KIND_MSS => {
                    self.push("mss", "mss".into());
                    let [length, high, low] = take(raw, offset)?;
                    // The declared length is checked but not followed, as p0f does.
                    self.bad |= length != 4;
                    self.mss = u16::from_be_bytes([high, low]);
                    offset += 3;
                }
                KIND_WINDOW_SCALE => {
                    self.push("wscale", "ws".into());
                    let [length, scale] = take(raw, offset)?;
                    self.bad |= length != 3;
                    self.window_scale = Some(scale);
                    self.excessive_window_scale = scale > MAX_WINDOW_SCALE;
                    offset += 2;
                }
                KIND_SACK_PERMITTED => {
                    self.push("sackOK", "sok".into());
                    self.sack_permitted = true;
                    let [length] = take(raw, offset)?;
                    self.bad |= length != 2;
                    offset += 1;
                }
                KIND_SACK => {
                    self.push("sack", "sack".into());
                    offset = skip(raw, offset, 10..=34)?;
                }
                KIND_TIMESTAMPS => {
                    self.push("timestamp", "ts".into());
                    self.timestamps = true;
                    let [length, body @ ..] = take::<9>(raw, offset)?;
                    self.bad |= length != 10;
                    let [ts1, ts2] = [&body[..4], &body[4..]];
                    self.zero_timestamp = ts1 == [0; 4];
                    self.nonzero_timestamp2 = ts2 != [0; 4];
                    offset += 9;
                }
                other => {
                    self.push(&format!("unknown-{other}"), format!("?{other}"));
                    offset = skip(raw, offset, 2..=40)?;
                }
            }
        }
        (offset == raw.len()).then_some(())
    }

    fn push(&mut self, name: &str, layout: String) {
        self.names.push(name.to_owned());
        self.layout.push(layout);
    }
}

/// The `N` bytes at `offset`, or `None` if the options end first.
fn take<const N: usize>(raw: &[u8], offset: usize) -> Option<[u8; N]> {
    raw.get(offset..)?.first_chunk::<N>().copied()
}

/// Skips a variable-length option whose length byte is at `offset` (one past the kind) and
/// must lie in `allowed`; returns the offset after it.
fn skip(raw: &[u8], offset: usize, allowed: std::ops::RangeInclusive<usize>) -> Option<usize> {
    let length = usize::from(*raw.get(offset)?);
    let end = offset - 1 + length;
    (allowed.contains(&length) && end <= raw.len()).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_p0f_quirks() {
        let parsed = SynOptions::parse(&[8, 10, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 15, 0, 0, 1]);
        assert!(
            parsed.zero_timestamp && parsed.nonzero_timestamp2,
            "{parsed:?}"
        );
        assert!(
            parsed.excessive_window_scale && parsed.nonzero_eol_padding,
            "{parsed:?}"
        );
        assert_eq!(parsed.layout, ["ts", "ws", "eol+2"]);
    }

    #[test]
    fn marks_malformed_option() {
        let parsed = SynOptions::parse(&[2, 4, 0x05]);
        assert!(parsed.bad, "truncated MSS option was not marked bad");
        assert_eq!(parsed.layout, ["mss"]);
    }

    #[test]
    fn stops_after_24_options() {
        let parsed = SynOptions::parse(&[KIND_NOP; 30]);
        assert_eq!(parsed.layout.len(), MAX_OPTIONS);
        assert!(parsed.bad);
    }

    #[test]
    fn wrong_declared_length_is_bad_but_read() {
        let parsed = SynOptions::parse(&[2, 3, 0x05, 0xb4]);
        assert!(parsed.bad);
        assert_eq!(parsed.mss, 1460);
    }

    #[test]
    fn unknown_option_needs_sane_length() {
        assert!(!SynOptions::parse(&[30, 4, 0, 0]).bad);
        assert!(SynOptions::parse(&[30, 1, 0, 0]).bad);
        assert!(SynOptions::parse(&[30, 6, 0, 0]).bad);
        assert_eq!(SynOptions::parse(&[30]).names, ["unknown-30"]);
    }
}

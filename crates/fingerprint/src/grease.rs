/// Whether `value` is a GREASE value from RFC 8701: `0x0A0A`, `0x1A1A`, … `0xFAFA`.
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

/// tls.peet.ws stores GREASE groups as 6969 and later treats 6969 itself as GREASE, so a real
/// group with that id (unassigned today) is reported as GREASE too.
const GREASE_GROUP_MARKER: u16 = 6969;

/// Whether a supported group counts as GREASE in tls.peet.ws's output.
pub(crate) const fn is_grease_group(group: u16) -> bool {
    is_grease(group) || group == GREASE_GROUP_MARKER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_sixteen_rfc_8701_values() {
        let grease: Vec<u16> = (0..=u16::MAX).filter(|&v| is_grease(v)).collect();
        let expected: Vec<u16> = (0..16).map(|i| 0x0a0a + i * 0x1010).collect();
        assert_eq!(grease, expected);
    }
}

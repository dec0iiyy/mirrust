//! The Akamai HTTP/2 fingerprint: `SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order`.

use crate::InputError;

/// The four parts of an Akamai HTTP/2 fingerprint such as
/// `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Akamai {
    /// SETTINGS as `(id, value)` in the order sent.
    pub settings: Vec<(u16, u64)>,
    /// The connection `WINDOW_UPDATE` increment, `00` when none was sent.
    pub window_update: String,
    /// PRIORITY frames as tls.peet.ws writes them, `0` when none were sent.
    pub priority: String,
    /// Pseudo-header order: `m`, `a`, `s`, `p` for method, authority, scheme, path.
    pub pseudo_headers: Vec<String>,
}

impl Akamai {
    /// Parses the fingerprint text.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::Malformed`] when the text does not have four parts or a setting
    /// is not `id:value`.
    pub fn parse(text: &str) -> Result<Self, InputError> {
        let malformed = || InputError::Malformed {
            field: "akamai_fingerprint",
            value: text.to_owned(),
        };
        let parts: Vec<&str> = text.split('|').collect();
        let [settings, window_update, priority, pseudo_headers] = parts[..] else {
            return Err(malformed());
        };
        let settings = settings
            .split([';', ','])
            .filter(|setting| !setting.is_empty())
            .map(|setting| {
                let (id, value) = setting.split_once(':')?;
                Some((id.parse().ok()?, value.parse().ok()?))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(malformed)?;
        Ok(Self {
            settings,
            window_update: window_update.to_owned(),
            priority: priority.to_owned(),
            pseudo_headers: pseudo_headers
                .split(',')
                .filter(|header| !header.is_empty())
                .map(str::to_owned)
                .collect(),
        })
    }
}

/// The RFC 9113 name of a SETTINGS id.
pub(crate) fn setting_name(id: u16) -> String {
    let name = match id {
        1 => "HEADER_TABLE_SIZE",
        2 => "ENABLE_PUSH",
        3 => "MAX_CONCURRENT_STREAMS",
        4 => "INITIAL_WINDOW_SIZE",
        5 => "MAX_FRAME_SIZE",
        6 => "MAX_HEADER_LIST_SIZE",
        8 => "ENABLE_CONNECT_PROTOCOL",
        9 => "NO_RFC7540_PRIORITIES",
        _ => "UNKNOWN",
    };
    format!("{name} ({id})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chrome() -> Result<(), InputError> {
        let akamai = Akamai::parse("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")?;
        assert_eq!(
            akamai.settings,
            [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)]
        );
        assert_eq!(akamai.window_update, "15663105");
        assert_eq!(akamai.pseudo_headers, ["m", "a", "s", "p"]);
        Ok(())
    }

    #[test]
    fn rejects_three_parts() {
        assert!(Akamai::parse("1:1|0|m,a,s,p").is_err());
    }
}

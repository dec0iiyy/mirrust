//! Which names to certify: validation of `--domain` values, and `--domain auto`, which turns
//! the machine's own public IPv4 address into an `A-B-C-D.sslip.io` name.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use anyhow::{Context as _, bail};

/// Names one certificate may cover. Let's Encrypt allows 100; a mirror needs one or two.
pub const MAX_DOMAINS: usize = 4;

/// The `--domain` value that asks for a name derived from the machine's address.
pub const AUTO: &str = "auto";

/// The DNS suffix of the free third-party service that resolves `A-B-C-D.sslip.io` to
/// `A.B.C.D`.
const SSLIP_SUFFIX: &str = "sslip.io";

/// An address that is only used to ask the operating system which local address a packet to
/// it would leave from. It is in TEST-NET-1 (RFC 5737), which no host owns. Nothing is sent.
const ROUTE_PROBE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// Why an IPv4 address cannot be reached from the public internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// `0.0.0.0/8`, "this network".
    Unspecified,
    /// `127.0.0.0/8`.
    Loopback,
    /// RFC 1918: `10/8`, `172.16/12`, `192.168/16`.
    Private,
    /// `169.254.0.0/16`.
    LinkLocal,
    /// Carrier-grade NAT, `100.64.0.0/10` (RFC 6598).
    Cgnat,
    /// The documentation ranges of RFC 5737.
    Documentation,
    /// `224.0.0.0/4`.
    Multicast,
    /// Other ranges that are never routed on the internet: `240.0.0.0/4` (which holds the
    /// broadcast address), `192.0.0.0/24` and the benchmarking range `198.18.0.0/15`.
    Reserved,
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unspecified => "in 0.0.0.0/8 (this network)",
            Self::Loopback => "a loopback address",
            Self::Private => "a private (RFC 1918) address",
            Self::LinkLocal => "a link-local address",
            Self::Cgnat => "in the carrier-grade NAT range 100.64.0.0/10",
            Self::Documentation => "in a documentation range",
            Self::Multicast => "a multicast address",
            Self::Reserved => "in a reserved range",
        })
    }
}

/// Classifies `ip`; `None` means it can be a public address.
#[must_use]
pub fn classify(ip: Ipv4Addr) -> Option<AddressClass> {
    let [a, b, c, _] = ip.octets();
    if a == 0 {
        Some(AddressClass::Unspecified)
    } else if ip.is_loopback() {
        Some(AddressClass::Loopback)
    } else if ip.is_private() {
        Some(AddressClass::Private)
    } else if ip.is_link_local() {
        Some(AddressClass::LinkLocal)
    } else if a == 100 && b & 0xc0 == 0x40 {
        Some(AddressClass::Cgnat)
    } else if ip.is_documentation() {
        Some(AddressClass::Documentation)
    } else if ip.is_multicast() {
        Some(AddressClass::Multicast)
    } else if a >= 240 || (a == 192 && b == 0 && c == 0) || (a == 198 && b & 0xfe == 18) {
        Some(AddressClass::Reserved)
    } else {
        None
    }
}

/// The sslip.io name of `ip`: `203.0.113.7` becomes `203-0-113-7.sslip.io`.
#[must_use]
pub fn sslip_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{a}-{b}-{c}-{d}.{SSLIP_SUFFIX}")
}

/// The sslip.io name for `ip` if it can be a public address.
///
/// # Errors
///
/// Fails when `ip` is loopback, private, link-local, CGNAT or otherwise not routable; the
/// message says to pass an explicit `--domain`.
pub fn auto_name(ip: Ipv4Addr) -> anyhow::Result<String> {
    if let Some(class) = classify(ip) {
        bail!(
            "--domain auto needs a public IPv4 address, but this machine's address {ip} is \
             {class} (a router or cloud NAT may map a public address to it); \
             pass an explicit --domain NAME that resolves to this server"
        );
    }
    Ok(sslip_name(ip))
}

/// The local IPv4 address of the default route, found without sending anything: connecting a
/// UDP socket only makes the operating system pick the route and the source address.
///
/// # Errors
///
/// Fails when there is no default route, or the route's address is not IPv4.
pub fn default_route_ipv4() -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((ROUTE_PROBE, 9))?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(ip) => Err(io::Error::other(format!("local address {ip} is not IPv4"))),
    }
}

/// Checks one host name and returns it in lowercase.
///
/// # Errors
///
/// Fails for anything that is not a plain ASCII DNS name with at least two labels: wildcards,
/// IP addresses, underscores, non-ASCII text (give the punycode form) and names with an empty,
/// over-long or hyphen-edged label.
pub fn validate(name: &str) -> anyhow::Result<String> {
    let name = name.to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        bail!("bad --domain {name:?}: a host name has 1 to 253 characters");
    }
    if name.starts_with('*') {
        bail!("bad --domain {name}: wildcard names need DNS validation, which is not supported");
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        bail!("bad --domain {name}: not a fully qualified host name (no dot)");
    }
    for label in &labels {
        let edges_ok = !label.starts_with('-') && !label.ends_with('-');
        let chars_ok = label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if label.is_empty() || label.len() > 63 || !edges_ok || !chars_ok {
            bail!(
                "bad --domain {name}: label {label:?} must be 1 to 63 letters, digits or \
                 hyphens, not starting or ending with a hyphen (use punycode for non-ASCII)"
            );
        }
    }
    let tld = labels[labels.len() - 1];
    if tld.bytes().all(|b| b.is_ascii_digit()) {
        bail!("bad --domain {name}: IP addresses cannot be certified, give a host name");
    }
    Ok(name)
}

/// The names to certify: each `--domain` value validated, `auto` replaced by the sslip.io name
/// of the address `detect` returns, duplicates dropped, first-given order kept.
///
/// # Errors
///
/// Fails when a name is invalid, when there are more than [`MAX_DOMAINS`], when `auto` is
/// combined with another name, or when `auto` finds no usable public address.
pub fn resolve(
    given: &[String],
    detect: impl FnOnce() -> io::Result<Ipv4Addr>,
) -> anyhow::Result<Vec<String>> {
    if given.len() > MAX_DOMAINS {
        bail!("at most {MAX_DOMAINS} --domain names, got {}", given.len());
    }
    if given.len() > 1 && given.iter().any(|name| name == AUTO) {
        bail!("--domain {AUTO} stands for the whole certificate; do not combine it with names");
    }
    if given == [AUTO] {
        let ip = detect().context(
            "--domain auto could not find the machine's address (is there a default route?); \
             pass an explicit --domain NAME",
        )?;
        return Ok(vec![auto_name(ip)?]);
    }
    let mut names: Vec<String> = Vec::with_capacity(given.len());
    for name in given {
        let name = validate(name)?;
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("test address")
    }

    #[test]
    fn classifies_every_refused_class() {
        let table = [
            ("0.0.0.0", Some(AddressClass::Unspecified)),
            ("0.1.2.3", Some(AddressClass::Unspecified)),
            ("127.0.0.1", Some(AddressClass::Loopback)),
            ("127.255.255.254", Some(AddressClass::Loopback)),
            ("10.0.0.1", Some(AddressClass::Private)),
            ("172.16.0.1", Some(AddressClass::Private)),
            ("172.31.255.255", Some(AddressClass::Private)),
            ("192.168.1.10", Some(AddressClass::Private)),
            ("169.254.1.1", Some(AddressClass::LinkLocal)),
            ("100.64.0.1", Some(AddressClass::Cgnat)),
            ("100.127.255.255", Some(AddressClass::Cgnat)),
            ("192.0.2.1", Some(AddressClass::Documentation)),
            ("198.51.100.1", Some(AddressClass::Documentation)),
            ("203.0.113.9", Some(AddressClass::Documentation)),
            ("224.0.0.1", Some(AddressClass::Multicast)),
            ("240.0.0.1", Some(AddressClass::Reserved)),
            ("255.255.255.255", Some(AddressClass::Reserved)),
            ("192.0.0.5", Some(AddressClass::Reserved)),
            ("198.18.0.1", Some(AddressClass::Reserved)),
            ("198.19.255.255", Some(AddressClass::Reserved)),
        ];
        for (text, want) in table {
            assert_eq!(classify(ip(text)), want, "{text}");
        }
    }

    #[test]
    fn neighbours_of_the_refused_ranges_are_public() {
        for text in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "169.253.0.1",
            "198.17.255.255",
            "198.20.0.0",
            "192.0.1.1",
            "223.255.255.255",
            "93.184.216.34",
        ] {
            assert_eq!(classify(ip(text)), None, "{text}");
        }
    }

    #[test]
    fn auto_builds_the_sslip_name_and_refuses_the_rest() {
        assert_eq!(
            auto_name(ip("93.184.216.34")).expect("public"),
            "93-184-216-34.sslip.io"
        );
        for refused in ["127.0.0.1", "10.1.2.3", "169.254.9.9", "100.100.100.100"] {
            let message = auto_name(ip(refused)).expect_err(refused).to_string();
            assert!(message.contains("explicit --domain"), "{message}");
            assert!(message.contains(refused), "{message}");
        }
    }

    #[test]
    fn validates_names() {
        assert_eq!(
            validate("Mirror.Example.COM").expect("ok"),
            "mirror.example.com"
        );
        assert_eq!(validate("a-b.c1.io").expect("ok"), "a-b.c1.io");
        for bad in [
            "",
            "localhost",
            "*.example.com",
            "-a.example.com",
            "a-.example.com",
            "a..example.com",
            "a_b.example.com",
            "пример.example.com",
            "1.2.3.4",
            "example.com.",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}com", "a.".repeat(130)),
        ] {
            assert!(validate(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn resolve_replaces_auto_dedupes_and_limits() {
        fn never() -> io::Result<Ipv4Addr> {
            panic!("no detection needed")
        }
        let names = |values: &[&str]| -> Vec<String> {
            values.iter().map(|&value| value.to_owned()).collect()
        };
        assert_eq!(
            resolve(
                &names(&["B.example.com", "a.example.com", "b.example.com"]),
                never
            )
            .expect("ok"),
            ["b.example.com", "a.example.com"]
        );
        assert_eq!(
            resolve(&names(&["auto"]), || Ok(ip("93.184.216.34"))).expect("ok"),
            ["93-184-216-34.sslip.io"]
        );
        assert!(resolve(&names(&["auto"]), || Ok(ip("192.168.0.2"))).is_err());
        assert!(
            resolve(&names(&["auto"]), || Err(
                io::ErrorKind::NetworkUnreachable.into()
            ))
            .is_err()
        );
        assert!(resolve(&names(&["auto", "a.example.com"]), never).is_err());
        assert!(
            resolve(
                &names(&["a.com", "b.com", "c.com", "d.com", "e.com"]),
                never
            )
            .is_err()
        );
    }
}

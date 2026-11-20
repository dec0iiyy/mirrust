//! The `client` object of a report: which known client the TLS fingerprint matches and
//! whether the `User-Agent` claims the same one.

use fingerprint::known::{Client, Match, UserAgent};
use serde_json::{Value, json};

/// Builds the `client` object from the JA4 lookup and the `User-Agent` value.
///
/// `consistent` is a verdict only for an exact match with a recognized `User-Agent`; a shared
/// cipher list alone does not say which client it is.
pub(crate) fn to_json(known: Match, user_agent: &str) -> Value {
    let agent = UserAgent::parse(user_agent);
    let kind = match known {
        Match::Exact(_) => "exact",
        Match::Ciphers(_) => "ciphers",
        Match::Unknown => "none",
    };
    let consistent = match (known, agent) {
        (Match::Exact(client), Some(agent)) => Some(client.agrees_with(agent.family)),
        _ => None,
    };
    let client = known.client();
    json!({
        "match": kind,
        "family": client.map(Client::family),
        "version": client.map(Client::version),
        "library": client.and_then(Client::library),
        "source": client.map(Client::source),
        "user_agent_family": agent.map_or("unknown", |agent| agent.family.name()),
        "consistent": consistent,
    })
}

#[cfg(test)]
mod tests {
    use fingerprint::known;

    use super::*;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, \
        like Gecko) Chrome/133.0.0.0 Safari/537.36";
    const EDGE: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, \
        like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0";

    fn client(family: &str) -> &'static Client {
        known::clients()
            .iter()
            .find(|client| client.family() == family)
            .unwrap_or_else(|| panic!("no {family} entry in the dataset"))
    }

    #[test]
    fn exact_match_reports_the_entry_and_a_verdict() {
        let go = client("Go net/http");
        assert_eq!(
            to_json(Match::Exact(go), CHROME),
            json!({
                "match": "exact",
                "family": "Go net/http",
                "version": go.version(),
                "library": "crypto/tls",
                "source": go.source(),
                "user_agent_family": "Chrome",
                "consistent": false,
            })
        );
        assert_eq!(
            to_json(Match::Exact(go), "Go-http-client/2.0")["consistent"],
            true
        );
    }

    #[test]
    fn key_order_is_fixed() {
        let value = to_json(Match::Unknown, "");
        let keys: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "match",
                "family",
                "version",
                "library",
                "source",
                "user_agent_family",
                "consistent"
            ]
        );
    }

    #[test]
    fn chromium_user_agents_are_consistent_with_a_chrome_match() {
        let chrome = Match::Exact(client("Chrome"));
        assert_eq!(to_json(chrome, CHROME)["consistent"], true);
        let edge = to_json(chrome, EDGE);
        assert_eq!(edge["user_agent_family"], "Edge");
        assert_eq!(edge["consistent"], true);
        assert_eq!(to_json(chrome, "curl/8.7.1")["consistent"], false);
    }

    #[test]
    fn unknown_user_agent_gives_no_verdict() {
        for user_agent in ["", "Wget/1.21.4"] {
            let value = to_json(Match::Exact(client("Chrome")), user_agent);
            assert_eq!(value["user_agent_family"], "unknown", "{user_agent:?}");
            assert_eq!(value["consistent"], Value::Null, "{user_agent:?}");
            assert_eq!(value["family"], "Chrome", "{user_agent:?}");
        }
    }

    #[test]
    fn cipher_match_names_the_entry_without_a_verdict() {
        let value = to_json(Match::Ciphers(client("curl")), CHROME);
        assert_eq!(value["match"], "ciphers");
        assert_eq!(value["family"], "curl");
        assert_eq!(value["user_agent_family"], "Chrome");
        assert_eq!(value["consistent"], Value::Null);
    }

    #[test]
    fn no_match_leaves_the_entry_fields_null() {
        assert_eq!(
            to_json(Match::Unknown, "curl/8.7.1"),
            json!({
                "match": "none",
                "family": null,
                "version": null,
                "library": null,
                "source": null,
                "user_agent_family": "curl",
                "consistent": null,
            })
        );
    }
}

//! The request router: `/` as the page or the text report, `/text`, the JSON API under `/api/`,
//! and a 404 page.

use crate::Config;
use crate::printable::{MAX_PRINTED, printable};
use crate::report::{Report, base64, hex, to_go_json, to_go_json_pretty};
use crate::text::{self, Colour};

/// Headers every response carries, on HTTP/1.1, HTTP/2 and HTTP/3, whatever the route or
/// status. Names are in HTTP/1.1 capitalization; HTTP/2 and HTTP/3 send them in lowercase.
pub(crate) const RESPONSE_HEADERS: [(&str, &str); 4] = [
    // A report describes one connection; a cached copy would describe someone else's.
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    // `/` answers with the page or the text report by `Accept`. Every response says so, because
    // HTTP/2 sends these headers from one fixed list and a cache must not mix the two up.
    ("Vary", "Accept"),
];

/// Content type (before `; charset=utf-8`) of the empty answer to `OPTIONS`.
pub(crate) const OPTIONS_CONTENT_TYPE: &str = "text/plain";

/// A routed response: status, body and content type (sent with `; charset=utf-8`).
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    pub(crate) content_type: &'static str,
}

impl Reply {
    fn text(body: String) -> Self {
        Self {
            status: 200,
            body: body.into_bytes(),
            content_type: "text/plain",
        }
    }

    fn json(body: String) -> Self {
        Self {
            status: 200,
            body: body.into_bytes(),
            content_type: "application/json",
        }
    }
}

/// Routes `report.path`. `/` is the text report for a request that does not accept `text/html`
/// and the page for one that does (see [`wants_page`]); `/text` is always the text report. An
/// unknown path gets the 404 page with status 404; a route that
/// cannot answer, such as `/api/raw` without a captured ClientHello, gets
/// `{"error": "..."}` with status 500.
pub(crate) fn route(report: &Report, config: &Config) -> Reply {
    log(report);
    if let Some(log) = &config.log {
        log.record(report);
    }
    let result = match url_path(&report.path).as_deref() {
        Some("/") => Ok(root(report)),
        Some("/text") => Ok(text_report(report)),
        Some("/api/all") => Ok(Reply::json(to_go_json_pretty(&report.to_json()))),
        Some("/api/tls") => Ok(api_tls(report)),
        Some("/api/clean") => Ok(Reply::json(to_go_json_pretty(&report.clean_json()))),
        Some("/api/raw") => api_raw(report),
        _ => Ok(not_found()),
    };
    result.unwrap_or_else(|error| Reply {
        status: 500,
        ..Reply::json(format!(r#"{{"error": "{error}"}}"#))
    })
}

/// Whether a request asks for CORS headers: one of its `Name: value` header lines starts with
/// `key`, compared without regard to ASCII case, since header names are case-insensitive and
/// HTTP/2 and HTTP/3 send them in lowercase. An empty key turns CORS off.
pub(crate) fn wants_cors<'line>(lines: impl IntoIterator<Item = &'line str>, key: &str) -> bool {
    !key.is_empty()
        && lines.into_iter().any(|line| {
            line.as_bytes()
                .get(..key.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(key.as_bytes()))
        })
}

/// The value of `name` in the request's `Name: value` header lines, compared without regard to
/// ASCII case. Several lines of the same name are joined with `, `; no such line gives an empty
/// string.
pub(crate) fn header_value<'line>(
    lines: impl IntoIterator<Item = &'line str>,
    name: &str,
) -> String {
    let values: Vec<&str> = lines
        .into_iter()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
        .collect();
    values.join(", ")
}

/// The value of `key` in the query of a request target, as sent (not percent-decoded); the
/// first `key=` wins.
fn query_value<'target>(target: &'target str, key: &str) -> Option<&'target str> {
    let (_, query) = target.split_once('?')?;
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(name, value)| (name == key).then_some(value))
}

/// Whether `/` answers with the HTML page. `?format=html` says yes and `?format=text` says no;
/// otherwise the page goes to a request whose `Accept` contains `text/html` (browsers) and the
/// text report to every other, including one with no `Accept` (curl, wget, scripts).
fn wants_page(report: &Report) -> bool {
    match query_value(&report.path, "format") {
        Some(format) if format.eq_ignore_ascii_case("html") => true,
        Some(format) if format.eq_ignore_ascii_case("text") => false,
        _ => report.accept.to_ascii_lowercase().contains("text/html"),
    }
}

fn root(report: &Report) -> Reply {
    if wants_page(report) {
        index(report)
    } else {
        text_report(report)
    }
}

/// The text report, with ANSI colour for `?color=1` and plain otherwise.
fn text_report(report: &Report) -> Reply {
    let colour = if query_value(&report.path, "color") == Some("1") {
        Colour::Ansi
    } else {
        Colour::Plain
    };
    Reply::text(text::render(report, colour))
}

fn log(report: &Report) {
    println!("{}", log_line(report));
}

/// The stdout summary of a request. The method and path are the client's own text, so they
/// are printed escaped and cut at [`MAX_PRINTED`]: a newline or ESC in them cannot forge a log
/// line or drive the operator's terminal.
fn log_line(report: &Report) -> String {
    let ip = report.ip.replace(['[', ']'], "");
    let ja3_hash = report.tls.as_ref().map_or("-", |tls| tls.ja3_hash.as_str());
    let method = printable(&report.method, MAX_PRINTED);
    let path = printable(&report.path, MAX_PRINTED);
    format!("{ip} {method} {} {path} {ja3_hash}", report.http_version)
}

/// The path Go's `url.Parse("https://tls.peet.ws" + target)` yields, or `None` where that
/// fails or the target does not start a path (Go then reads it as part of the host).
fn url_path(target: &str) -> Option<String> {
    let path = target.strip_prefix('/')?;
    let path = &path[..path.find(['?', '#']).unwrap_or(path.len())];
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let mut out = vec![b'/'];
    let mut bytes = path.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let high = char::from(bytes.next()?).to_digit(16)?;
            let low = char::from(bytes.next()?).to_digit(16)?;
            out.push(u8::try_from(high << 4 | low).expect("two hex digits fit a byte"));
        } else {
            out.push(b);
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn api_tls(report: &Report) -> Reply {
    let tls_only = Report {
        tls: report.tls.clone(),
        ..Report::default()
    };
    let mut json = tls_only.to_json();
    // `/api/tls` keeps tls.peet.ws's layout; the client match and the audit belong to the
    // full report.
    if let Some(fields) = json.as_object_mut() {
        fields.shift_remove("client");
        fields.shift_remove("audit");
    }
    Reply::json(to_go_json_pretty(&json))
}

fn api_raw(report: &Report) -> Result<Reply, String> {
    let tls = report
        .tls
        .as_ref()
        .ok_or_else(|| "TLS details not available".to_owned())?;
    Ok(Reply::json(format!(
        r#"{{"raw": "{}", "raw_b64": "{}"}}"#,
        hex(&tls.raw),
        base64(&tls.raw)
    )))
}

/// mirrust's own page, built into the binary; the report is inlined so the page shows
/// the very connection that loaded it.
const INDEX: &str = include_str!("../static/index.html");

/// Where [`INDEX`] takes the report. Go-style JSON escapes `<`, `>` and `&`, so the report
/// cannot close the `<script>` element it lands in.
const INDEX_DATA: &str = "null/*DATA*/";

fn index(report: &Report) -> Reply {
    Reply {
        status: 200,
        body: INDEX
            .replacen(INDEX_DATA, &to_go_json(&report.to_json()), 1)
            .into_bytes(),
        content_type: "text/html",
    }
}

/// The page for any other path, built into the binary. It shows the requested path from the
/// address bar, so the server needs to put nothing into it.
const NOT_FOUND: &str = include_str!("../static/404.html");

fn not_found() -> Reply {
    Reply {
        status: 404,
        body: NOT_FOUND.as_bytes().to_vec(),
        content_type: "text/html",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_key_ignores_case() {
        assert!(wants_cors(["x-cors-test: 1"], "X-CORS"));
        assert!(wants_cors(["X-CORS: 1"], "X-CORS"));
        assert!(!wants_cors(["accept: */*", "x-c"], "X-CORS"));
        assert!(!wants_cors(["x-cors: 1"], ""));
        assert!(!wants_cors(["\u{e9}t\u{e9}"], "X"));
    }

    fn asking(path: &str, accept: &str) -> Report {
        Report {
            path: path.into(),
            accept: accept.into(),
            ..Report::default()
        }
    }

    #[test]
    fn accept_and_format_choose_the_page_or_the_text() {
        let browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        for (path, accept, page) in [
            ("/", "", false),
            ("/", "*/*", false),
            ("/", "application/json", false),
            ("/", browser, true),
            ("/", "TEXT/HTML", true),
            ("/?format=text", browser, false),
            ("/?format=html", "*/*", true),
            ("/?format=HTML", "", true),
            ("/?x=1&format=text", browser, false),
            ("/?format=json", browser, true),
            ("/?format=json", "*/*", false),
            ("/?format=", "", false),
            ("/?color=1#format=html", "", false),
            ("/?xformat=html", "", false),
        ] {
            assert_eq!(wants_page(&asking(path, accept)), page, "{path} {accept}");
        }
    }

    #[test]
    fn colour_is_off_unless_asked_for() {
        let colour = |path: &str| text_report(&asking(path, "")).body.contains(&0x1b);
        assert!(!colour("/text"));
        assert!(!colour("/text?color=0"));
        assert!(!colour("/text?color=true"));
        // Without a ClientHello the text has nothing to colour but the hint line.
        assert!(colour("/text?color=1"));
        assert!(colour("/?color=1&format=text"));
    }

    #[test]
    fn header_values_are_found_by_name_and_joined() {
        let lines = [
            "Host: x",
            "accept: text/html",
            "ACCEPT:*/*",
            "Accept:",
            "Accepts: no",
        ];
        assert_eq!(header_value(lines, "accept"), "text/html, */*");
        assert_eq!(header_value(["GET /a:b HTTP/1.1"], "accept"), "");
        assert_eq!(header_value(Vec::<&str>::new(), "accept"), "");
    }

    #[test]
    fn the_stdout_line_cannot_be_forged_or_flood_the_terminal() {
        let report = Report {
            ip: "[::1]:5".into(),
            http_version: "h2".into(),
            method: "GE\nT".into(),
            path: "/x\n127.0.0.1 GET /forged h2 -\x1b[2J".into(),
            ..Report::default()
        };
        let line = log_line(&report);
        assert!(!line.contains(['\n', '\r', '\x1b']), "{line:?}");
        assert_eq!(
            line,
            r"::1:5 GE\nT h2 /x\n127.0.0.1 GET /forged h2 -\u{1b}[2J -"
        );

        let long = Report {
            path: format!("/{}", "a".repeat(10_000)),
            ..Report::default()
        };
        assert!(log_line(&long).chars().count() < 300);
        assert!(log_line(&long).contains('…'));
    }

    #[test]
    fn url_path_follows_go_url_parse() {
        assert_eq!(url_path("/api/all?x=1#f").as_deref(), Some("/api/all"));
        assert_eq!(url_path("/api/%61ll").as_deref(), Some("/api/all"));
        assert_eq!(url_path("/api/%zz"), None);
        assert_eq!(url_path("--"), None);
        assert_eq!(url_path("*"), None);
        assert_eq!(url_path("/").as_deref(), Some("/"));
    }
}

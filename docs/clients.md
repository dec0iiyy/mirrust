# How common clients look

What mirrust 0.1.4 reports for clients you can run yourself, and what the `audit` says when a
client lies about being a browser. Every row was measured on 2026-11-20 against a local server
(`mirrust --listen 127.0.0.1:8443`, then `GET /api/all`) on macOS 27.2.1.

Two limits of these numbers:

- **It was a loopback connection on macOS, so the TCP checks did not run.** `tcp_os` shows
  `skip` in every row, and the scores below are those of the TLS, User-Agent, HTTP/2 and header
  checks only. On a Linux server on the internet the score can also drop because of the TCP
  SYN (see [reference.md](reference.md)).
- **The built-in dataset has an entry for each of these builds**, captured on the same Mac
  (`corpus/clients.jsonl`; for `reqwest` the entry is rustls 0.23.46 with its default
  configuration). So "mirrust names it correctly" in the first table is expected. What the tables show is how the named client, its `User-Agent` and its
  HTTP/2 settings fit together.

## Clients with their own User-Agent

| Client | HTTP | JA4 | Audit | mirrust names it |
| --- | --- | --- | --- | --- |
| curl 8.7.1 (macOS system curl) | HTTP/2 | `t13i4906h2_0d8feac7bc37_7395dae3b2f3` | 100, consistent | curl 8.7.1 |
| curl 8.7.1, `--http1.1` | HTTP/1.1 | `t13i4906h1_0d8feac7bc37_7395dae3b2f3` | 100, consistent | curl 8.7.1 |
| Python 3.9.6 `urllib` | HTTP/1.1 | `t12i380400_10ed599f3404_67a080e8974e` | 100, consistent | Python 3.9.6 (urllib) |
| Python `httpx` 0.28.1 | HTTP/1.1 | `t12i3805h1_10ed599f3404_67a080e8974e` | 100, consistent | Python 3.9.6 (urllib) |
| Node.js 26.13.1 `fetch` | HTTP/2 | `t13i5211h1_b262b3658495_e44827223d20` | 100, consistent | Node.js 26.13.1 |
| Go 1.27.4 `net/http` | HTTP/2 | `t13i1311h2_f57a46bbacb6_f50d94e863eb` | 100, consistent | Go net/http 1.27.4 |
| Chrome Canary 160 (headless) | HTTP/2 | `t13i1516h2_8daaf6152771_cb7bf5808d99` | 100, consistent | Chrome 160 (Canary) |
| Rust `reqwest` 0.12.28 (rustls), no `User-Agent` | HTTP/2 | `t13i1010h2_61a7ad8aa9b6_3a8073edd8ef` | 85, suspicious | rustls 0.23.46 |

Things worth knowing:

- `httpx` and `urllib` have the same cipher and extension hashes in their JA4 (the second
  and third parts): both use the Python `ssl` module, so the handshake is the interpreter's,
  not the library's. That is why mirrust names `httpx` as `urllib`, which is also in the
  dataset, when it matches on the cipher list.
- `reqwest` sends no `User-Agent` by default. The `audit` says so (`ua_tls`: "No User-Agent
  header") and also notes that the extensions differ from the dataset's rustls entry
  (`tls_known`: "a modified, older or newer build"), hence 85.
- Headless Chrome keeps `HeadlessChrome` in its `User-Agent` and still scores 100. The `audit`
  compares the layers with each other; it does not look for automation flags.

## The same clients with a Chrome User-Agent

This is what the `audit` is for: the TLS stack, the HTTP/2 settings and the headers say one
thing, the `User-Agent` another (`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36`).

| Client | Audit | Checks that failed | mirrust names it |
| --- | --- | --- | --- |
| curl | 30, inconsistent | `ua_tls`, `headers` | curl 8.7.1 |
| Python `httpx` | 30, inconsistent | `ua_tls`, `headers` | Python 3.9.6 (urllib) |
| Node.js `fetch` | 20, inconsistent | `ua_tls`, `http2`, `headers` | Node.js 26.13.1 |
| Rust `reqwest` (rustls) | 10, inconsistent | `tls_known`, `ua_tls`, `http2`, `headers` | rustls 0.23.46 |

Changing the `User-Agent` fixes one layer of four. A client that wants to pass has to change
the TLS handshake, the HTTP/2 settings and the header order as well, and keep the TCP stack
in line with the operating system it claims.

## Reproduce

```
mirrust --listen 127.0.0.1:8443 &
curl -sk https://127.0.0.1:8443/api/all | jq '{audit, client}'
curl -sk -A 'Mozilla/5.0 ... Chrome/160.0.0.0 Safari/537.36' https://127.0.0.1:8443/api/all | jq '.audit'
```

Use `/` with `Accept: text/plain`, or `curl https://127.0.0.1:8443/`, for the plain-text report.

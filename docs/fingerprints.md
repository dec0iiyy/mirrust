# Fingerprints: how each value is computed

This document specifies every value mirrust reports. Where a value is defined by a public
specification (JA4), mirrust follows that specification. Where the value is defined by what
tls.peet.ws reports (JA3 as it computes it, PeetPrint, its JA4 variant, the extension details,
the Akamai HTTP/2 string), mirrust is written to reproduce tls.peet.ws, including the
irregularities listed below. These irregularities are intentional: changing them would make
mirrust's values differ from values recorded from tls.peet.ws for the same client.

The golden snapshots in `corpus/` pin what this code outputs for each test input; see the
README's Testing section. They are not an automated comparison with the live service.

Notation: numbers in fingerprint strings are decimal unless stated; "hex" means lowercase hex;
`sha256_12(s)` is the first 12 hex characters of SHA-256 of the UTF-8 string `s`; `md5(s)` is the
32-character lowercase hex MD5.

## 1. Reading the ClientHello

The input is the ClientHello handshake message, from the handshake type byte (`0x01`) on,
without TLS record headers. Over TCP the server reassembles it from as many handshake records
as it spans (up to 64 KiB). Over QUIC it comes from the CRYPTO frames of the Initial packets
(section 9).

There are two parsing modes:

- `ClientHello::parse` reads any `legacy_version`. It feeds the FoxIO JA4 values (`ja4`,
  `ja4_r`, `ja4_o`, `ja4_ro`).
- `ClientHello::parse_peet` stops after the 4-byte header and `legacy_version` when
  `legacy_version` is not `0x0303` or `0x0304`. Everything tls.peet.ws reports is computed from
  this mode: `ja3`, `peetprint`, `ja4_peet`, `ciphers`, `extensions`, `client_random`,
  `session_id`. A TLS 1.0 or 1.1 ClientHello therefore has empty lists everywhere and a JA3 of
  `769,,,,` or `770,,,,`.

Both modes never fail and never panic. The reading rules:

- A message that does not start with `0x01` gives an empty ClientHello.
- A fixed-size field that does not fit (the 32-byte random) is left empty.
- A vector whose declared length runs past the end of the message is left empty, and parsing
  continues right after its length field (the length is consumed, the body is not).
- The extension list is read until fewer than 4 bytes remain or an extension declares more data
  than is left; the extensions before that point are kept.
- GREASE values (RFC 8701: `0x0A0A`, `0x1A1A`, ... `0xFAFA`) are kept as sent; each fingerprint
  decides how to treat them.

Lists taken from extensions, used by several fingerprints:

| List | Source | Rule |
| --- | --- | --- |
| supported groups | ext 10 | 2-byte length `n`, then at most `n / 2` entries, cut at the data. |
| point formats | ext 11 | Every byte after the first (length) byte; the length is not checked. |
| signature algorithms | ext 13 **and ext 53** | Each: 2-byte length `n`, at most `n / 2` entries. Entries of ext 53 are appended (see 4.3). |
| ALPN names | ext 16 | 2-byte list length `L`; a new name starts only while its offset is at most `L`, so an empty name at the very end is dropped; a name cut short ends the list. |
| cert compression | ext 27 | 1-byte length `n`, then `ceil(n / 2)` 2-byte entries, cut at the data. |
| supported versions | ext 43 | As cert compression. |
| PSK mode | ext 45 | The second byte (the first mode) of the last ext 45 that has one. |

## 2. GREASE

A value `v` is GREASE when `v & 0x0F0F == 0x0A0A` and both bytes are equal.

In the tls.peet.ws-compatible values (JA3, PeetPrint, `ja4_peet`, extension details), a
supported group with id `6969` (`0x1B39`, unassigned) also counts as GREASE. This mirrors how
tls.peet.ws marks GREASE groups internally.

## 3. JA3

```
legacy_version,ciphers,extensions,groups,point_formats
```

- From `parse_peet`.
- `legacy_version`: decimal (`771`).
- `ciphers`, `extensions`: non-GREASE values in the client's order, decimal, joined with `-`.
- `groups`: supported groups without GREASE or 6969, decimal, joined with `-`.
- `point_formats`: decimal, joined with `-`.
- `ja3_hash` = `md5(ja3)`.

## 4. JA4

### 4.1 JA4 per the FoxIO specification (`ja4`, `ja4_r`, `ja4_o`, `ja4_ro`)

Follows FoxIO's `technical_details/JA4.md` and its reference implementations. Input: `parse`
(all legacy versions). GREASE is removed from every list.

**Part a** (10 characters): transport, version, SNI, cipher count, extension count, ALPN.

| Piece | Rule |
| --- | --- |
| transport | `t` TCP, `q` QUIC, `d` DTLS. |
| version | Highest non-GREASE entry of `supported_versions` (ext 43); without that extension, `legacy_version`. `0x0304` → `13`, `0x0303` → `12`, `0x0302` → `11`, `0x0301` → `10`, `0x0300` → `s3`, `0x0002` → `s2`, `0xFEFF` → `d1`, `0xFEFD` → `d2`, `0xFEFC` → `d3`, anything else (including an empty ext 43) → `00`. |
| SNI | `d` when ext 0 is present, else `i`. |
| counts | Non-GREASE cipher suites, then non-GREASE extensions (SNI and ALPN included), each two digits, capped at `99`. |
| ALPN | From the first ALPN name: its first and last byte when both are ASCII letters or digits; otherwise the high nibble of the first byte and the low nibble of the last byte, in hex. `00` with no ALPN or an empty first name. A GREASE name (RFC 8701: `0x0A 0x0A` to `0xFA 0xFA`) is not skipped, so it gives `0a` to `fa`. |

The specification says to "ignore GREASE values anywhere", and a GREASE ALPN name is the one
place where mirrust does not, on purpose. FoxIO's own implementations remove GREASE from
cipher suites, extensions, versions and signature algorithms and leave ALPN alone: the
Wireshark plugin (`wireshark/source/packet-ja4.c`) tests `IS_GREASE_TLS` for those lists and
takes the first `tls.handshake.extensions_alpn_str` as it is, and the Zeek script
(`zeek/scripts/fingerprints/ja4/helpers.zeek`) keeps every ALPN string where its other lists
are commented "GREASE removed". Both were read on 2026-11-20; the repository no longer has
its Rust and Python implementations. A value that differs from what those tools print for the
same ClientHello would be of no use, so mirrust follows them. No client in the corpus sends a
GREASE ALPN name.

**Part b**: the cipher suites, sorted, 4-digit hex, joined with `,`.

**Part c**: the extensions sorted, without SNI (0) and ALPN (16), 4-digit hex, joined with `,`;
then, only if there are any, `_` and the signature algorithms of ext 13 in the client's order,
4-digit hex, joined with `,`. Ext 53 is not used here.

Forms:

| Field | Value |
| --- | --- |
| `ja4` | `a_sha256_12(b)_sha256_12(c)` |
| `ja4_r` | `a_b_c` |
| `ja4_o` | As `ja4`, but b and c keep the client's order and c keeps SNI and ALPN. |
| `ja4_ro` | As `ja4_r`, with the same order rule as `ja4_o`. |

An empty part b or c hashes to `000000000000`.

Example (the specification's worked example):

```
ja4    t13d1516h2_8daaf6152771_e5627efa2ab1
ja4_o  t13d1516h2_acb858a92679_18f69afefd3d
```

### 4.2 The tls.peet.ws variant (`ja4_peet`, `ja4_peet_r`)

Same three-part layout, computed from `parse_peet`, with these differences:

| Aspect | `ja4_peet` | FoxIO `ja4` |
| --- | --- | --- |
| Version | The version the server negotiated (`13` for TLS 1.3, always `13` over QUIC), not the highest one offered. A value outside TLS 1.0–1.3 prints as its decimal number. | Highest offered. |
| SNI flag | Always `d`. A Chrome hello without SNI gives `t13d1515h2`. | `i` without SNI (`t13i1515h2`). |
| Counts | Not zero-padded, not capped. An empty list counts as `1`. Firefox 55 gives `t12d159h2`. | `t12d1509h2`. |
| ALPN | The first ALPN name that is `h2`, `http/1.1` or `http/1.0` (ASCII case-insensitive), other names skipped: `h2` → `h2`, `http/1.x` → `h1`; none of these → empty. ALPN `h3` alone gives `t13d1510`. A QUIC hello with ALPN `h3` gives `q13d311_...`. | First name's first and last character (`h3`). |
| No cipher suites | Part b is `0000`, then hashed. | `000000000000`. |
| Signature algorithms | Ext 13 and ext 53 entries (section 4.3), GREASE removed. None → `0000`. The `_` is always present. | Ext 13 only; none → no `_`. |
| Empty part c | Hashed like any string. | `000000000000`. |
| Legacy versions | A TLS 1.0/1.1 `legacy_version` empties all lists (section 1). | Read normally. |
| Original-order forms | None. | `ja4_o`, `ja4_ro`. |

Example: the same Chrome QUIC Initial gives `ja4` = `q13d0312h3_55b375c5d22e_178839b6cec1` and
`ja4_peet` = `q13d312_55b375c5d22e_178839b6cec1`.

### 4.3 Extension 53

tls.peet.ws reads extension 53 as `signature_algorithms_cert` (whose real id is 50) and appends
its entries to the signature algorithm list. This affects `ja4_peet`, PeetPrint, and the
extension details, where extension 53 is named `signature_algorithms_cert (50)`. Extension 50
itself is reported as `signature_algorithms_cert (50)` with its raw `data` and does not feed the
signature algorithm list. The FoxIO `ja4` is not affected.

## 5. PeetPrint

Eight sections joined with `|`, each a list joined with `-`:

```
versions|protocols|groups|signature_algorithms|psk_mode|cert_compression|ciphers|extensions
```

| Section | Content |
| --- | --- |
| versions | `supported_versions` entries, decimal; GREASE as `GREASE`. |
| protocols | ALPN names that are `h2`, `http/1.1`, `http/1.0` (ASCII case-insensitive) as `2`, `1.1`, `1.0`, in the client's order; other names dropped. |
| groups | Supported groups, decimal; GREASE and 6969 as `GREASE`. |
| signature_algorithms | Ext 13 and ext 53 entries, decimal; GREASE as `GREASE`. |
| psk_mode | The PSK mode, decimal; `0` when absent. |
| cert_compression | Ext 27 algorithms, decimal. |
| ciphers | Cipher suites in the client's order, decimal; GREASE as `GREASE`. |
| extensions | Extension ids, decimal, GREASE as `GREASE`, **sorted as strings** (so `10` < `13` < `17513` < `18` < `23`, and `GREASE` last). |

`peetprint_hash` = `md5(peetprint)`.

## 6. Readable ciphers and extension details

Both come from `parse_peet` and match tls.peet.ws's JSON.

`ciphers`: one name per suite in the client's order. Known suites by name
(`TLS_AES_128_GCM_SHA256`); GREASE as `TLS_GREASE (0x0A0A)` (uppercase hex); others as `0xFF02`.

**Names.** The names of cipher suites, extensions, groups and signature schemes are display
text. Every fingerprint (`ja3`, `ja4`, `ja4_peet`, `peetprint`) is computed from the numbers,
so no name can change one. The tables (`crates/fingerprint/src/names.rs`) began as
tls.peet.ws's and follow three rules, checked against the IANA registries on 2026-11-20:

- A name that tls.peet.ws gives the right code point stays as that service spells it, so that
  reports compare directly. That covers nearly everything a client sends, including where
  IANA spells it differently: `P-256 (23)`, `P-384 (24)`, `X25519 (29)` (IANA: `secp256r1`,
  `secp384r1`, `x25519`), `extended_master_secret (23)` and `delegated_credentials (34)`
  (IANA now: `extended_main_secret`, `delegated_credential`), `TLS_EMPTY_RENEGOTIATION_INFO`
  for `0x00ff` (IANA: with `_SCSV`), `X25519Kyber768 (25497)`, and the BoringSSL constant
  names such as `extensionRenegotiationInfo (boringssl) (65281)`.
- A name that belongs to another code point is corrected. These differ from tls.peet.ws:

  | Code point | tls.peet.ws | mirrust |
  | --- | --- | --- |
  | cipher suite `0x5600` | `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` | `TLS_FALLBACK_SCSV` |
  | cipher suites `0xff02`, `0xff03` | `256` | `0xFF02`, `0xFF03` (they have no name) |
  | group 2 | `sect163k1 (2)` | `sect163r1 (2)` |
  | groups 31, 32, 33 | `P256r1tls13`, `P384r1tls13`, `P521r1tls13` | `brainpoolP256r1tls13`, `brainpoolP384r1tls13`, `brainpoolP512r1tls13` |
  | signature scheme `0x0808` | `ed25519` | `ed448` |

- Every code point that the registries assign and tls.peet.ws does not know has its registry
  name, where tls.peet.ws prints a number (`Unknown curve 4587`, `0x905`, `Unknown extension
  51764`, `0x1307`). There are 93 of them: 51 cipher suites (PSK with GCM and SHA-2, Camellia
  with SHA-256, SM4, AEGIS, ECCPWD, GOST 2012, Ascon and others), 5 extensions (60 to 63 and
  `trust_anchors (51764)`), 19 groups (among them `secp256k1 (22)`, the Brainpool curves 26 to
  28, `MLKEM512 (512)` to `MLKEM1024 (514)`, `SecP256r1MLKEM768 (4587)` and
  `SecP384r1MLKEM1024 (4589)`) and 18 signature schemes (`mldsa44`, `mldsa65`, `mldsa87`,
  the twelve `slhdsa_*` and three `bign-*`).

No JSON key changed, and none of the 127 ClientHellos in `corpus/hellos.jsonl` or the 700 in
`corpus/malformed.jsonl` has one of these code points, so no snapshot changed either.

`extensions`: one object per extension in the client's order, `null` when there are none. Every
object has `name`; most names are `<name> (<id>)`. Contents by extension:

| Extension | Fields |
| --- | --- |
| 0 `server_name` | `server_name`: every byte after the fifth, not cut to the declared name length. |
| 5, 17 `status_request`, `status_request_v2` | `status_request`: `certificate_status_type` as `OSCP (n)` (spelled so), `responder_id_list_length`, `request_extensions_length` (single bytes 1–3 of the data). Absent when the data is shorter than 3 bytes. |
| 10 `supported_groups` | `supported_groups`: names; GREASE as `TLS_GREASE (0x0a0a)` (lowercase hex here); unknown as `Unknown curve N`. |
| 11 `ec_point_formats` | `elliptic_curves_point_formats`: `0x00` style. |
| 13 `signature_algorithms`, 53 (named `signature_algorithms_cert (50)`) | `signature_algorithms`: names; unknown as `0x...` without padding. |
| 16 ALPN | `protocols`. |
| 18 `signed_certificate_timestamp` | name only. |
| 21 `padding` | `padding_data_length`: **twice** the byte length (it counts hex digits). |
| 23 `extended_master_secret` | `master_secret_data`: hex of the data past its first two bytes; `extended_master_secret_data`: always `""`. |
| 27 `compress_certificate` | `algorithms`: `zlib (1)`, `brotli (2)`, `zstd (3)`, others as 4-digit hex (`0004`). |
| 34 `delegated_credentials` | `signature_hash_algorithms`: `ceil(n / 2)` entries for a 2-byte length `n` (ext 13 reads `floor(n / 2)`). |
| 43 `supported_versions` | `versions`: `TLS 1.0` … `TLS 1.3`, GREASE as `TLS_GREASE (0x....)`, others as 4-digit hex (`0305`). |
| 45 `psk_key_exchange_modes` | `PSK_Key_Exchange_Mode`: the text for mode 0 or 1, else `""`. |
| 51 `key_share` | `shared_keys`: `{group name: key hex}` objects. Needs only `length + 1` bytes of data and reads entries while their offset is below `length`. |
| 57 `quic_transport_parameters`, 65445 (its draft codepoint, named `extensionQUICTransportParamsLegacy (boringssl) (65445)`) | `data` (hex, as on tls.peet.ws) and `parameters`, mirrust's own field: see [6.1](#61-quic-transport-parameters). |
| 17513 `application_settings_old`, 17613 `application_settings` | `protocols`. Names are read while their offset is below the list length, so a final name of at most one byte is skipped. |
| GREASE | `name`: `TLS_GREASE (0x0a0a)`, nothing else. |
| any other | `name` (`Unknown extension N` when unnamed) and `data` (hex). |

Common rules:

- Empty lists are `null`, not `[]`.
- Invalid UTF-8 in SNI, ALPN and ALPS names becomes one U+FFFD per invalid byte.
- Malformed `key_share` and `application_settings` data: the list stops at the first entry that
  does not fit and keeps the entries before it. (tls.peet.ws itself fails on such input; this is
  the one place where mirrust's output is defined where tls.peet.ws has none.)

Other `tls` fields: `tls_version_record` is `legacy_version` in decimal; `client_random` and
`session_id` are hex; `tls_version_negotiated` is the server's negotiated version in decimal.

### 6.1 QUIC transport parameters

A QUIC client puts its transport parameters (RFC 9000 section 18) in extension 57; QUIC drafts
used 65445 (`0xffa5`) with the same encoding. tls.peet.ws does not decode them, so this format is
defined here. `parameters` is a list with one object per parameter, in the client's order:

```json
{ "id": 4, "name": "initial_max_data", "value": 15728640 }
```

The extension data is a sequence of `id` (varint), `length` (varint), `length` bytes of value.

- `id`: the parameter id as a number.
- `name`: the name from the table below when the id is in it; otherwise `GREASE` when the id has
  the reserved form `31 * N + 27` (RFC 9000 section 18.1); otherwise `UNKNOWN_<id>` with the id in
  decimal. The table is consulted first because `0xff02de1a` is of the reserved form.
- `value`: a number when the table says the parameter is an integer and the value is exactly one
  varint; in every other case the value bytes as hex. A parameter without a value (a flag) has
  `""`.

| Id | Name | Value |
| --- | --- | --- |
| `0x00` | `original_destination_connection_id` | hex |
| `0x01` | `max_idle_timeout` | integer |
| `0x02` | `stateless_reset_token` | hex |
| `0x03` | `max_udp_payload_size` | integer |
| `0x04` | `initial_max_data` | integer |
| `0x05` | `initial_max_stream_data_bidi_local` | integer |
| `0x06` | `initial_max_stream_data_bidi_remote` | integer |
| `0x07` | `initial_max_stream_data_uni` | integer |
| `0x08` | `initial_max_streams_bidi` | integer |
| `0x09` | `initial_max_streams_uni` | integer |
| `0x0a` | `ack_delay_exponent` | integer |
| `0x0b` | `max_ack_delay` | integer |
| `0x0c` | `disable_active_migration` | flag |
| `0x0d` | `preferred_address` | hex |
| `0x0e` | `active_connection_id_limit` | integer |
| `0x0f` | `initial_source_connection_id` | hex |
| `0x10` | `retry_source_connection_id` | hex |
| `0x11` | `version_information` (RFC 9368) | hex: the chosen version, then the available versions, four bytes each |
| `0x1d` | `reset_stream_at` (draft-ietf-quic-reliable-stream-reset) | flag |
| `0x20` | `max_datagram_frame_size` (RFC 9221) | integer |
| `0x3e` | `initial_max_path_id` (RFC 10069) | integer |
| `0x173e` | `discard` (IANA, provisional) | hex |
| `0x219e` | `scone_supported` (IANA, provisional) | hex |
| `0x26ab` | `google_handshake_message` (Google QUIC) | hex |
| `0x2ab2` | `grease_quic_bit` (RFC 9287) | flag |
| `0x3127` | `initial_rtt` (Google QUIC) | integer, microseconds |
| `0x3128` | `google_connection_options` (Google QUIC) | hex: four-character tags |
| `0x3129` | `user_agent` (Google QUIC, deprecated) | hex |
| `0x4752` | `google_version` (Google QUIC) | hex |
| `0xff73db` | `version_information_draft` (draft-ietf-quic-version-negotiation) | hex |
| `0xde1a`, `0xff02de1a`, `0xff03de1a`, `0xff04de1a`, `0xff04de1b` | `min_ack_delay` (draft-iyengar-quic-delayed-ack, draft-ietf-quic-ack-frequency; the id changed with the drafts and IANA registers `0xff04de1b`) | integer, microseconds |

Names come from RFC 9000 section 18.2 and the IANA "QUIC Transport Parameters" registry; an id
that is in neither (the multipath drafts' `enable_multipath`, for one) is `UNKNOWN_<id>`.

Rules:

- The list stops at the first parameter that does not fit in the data (a cut id, length or
  value) and keeps the parameters before it. No parameters gives `null`.
- Nothing is sorted, merged or dropped: a repeated id appears twice, and GREASE entries keep
  their position, id and value. The order is not stable for every client: Chrome Canary 160
  sent the same parameters in a different order on two connections.
- Ids and integer values go up to 2^62 - 1. They are written as JSON numbers in full; a reader
  that stores numbers as doubles loses the low bits above 2^53 (Chrome's GREASE id is that large).

## 7. HTTP/1

`http1.headers` holds the header lines of the request head, in order and as sent: every line
after the request line and before the first empty line that contains a `:`. The request is
read until that empty line or until 16 KiB have arrived, whichever is first; anything later is
not seen, so the last header of a longer head is cut and the rest are missing. A line ends
with CRLF or with a bare LF. Invalid UTF-8 becomes one U+FFFD per byte.

tls.peet.ws reads 1024 bytes and lists every line in them that contains a `:`, so its list
also has the request line when that contains one (`GET /a:b HTTP/1.1`) and lines of the
request body, and lacks the headers past 1024 bytes. mirrust does not copy that.

If the request line is not exactly three space-separated parts, `method`, `path` and
`http_version` are `--` and `http1` is absent. `user_agent` is the last non-empty value of a line
whose name starts with `user-agent` (ASCII case-insensitive), trimmed.

## 8. HTTP/2

### 8.1 Frame capture (`http2.sent_frames`)

After the 24-byte connection preface, frames are read until the first HEADERS or DATA frame that
carries the `END_STREAM` flag (bit `0x1`); nothing after it is read. The server refuses more
than 64 KiB of input (preface included), more than 256 frames before that point, and more than
64 KiB of decoded header lines over all HEADERS frames; the client then gets a GOAWAY frame
with `ENHANCE_YOUR_CALM` and no report. These caps are mirrust's own. A malformed frame gets
GOAWAY with the error code RFC 9113 gives it, where tls.peet.ws closes the connection without
a word.

Each frame is recorded with `frame_type` (`DATA`, `HEADERS`, `PRIORITY`, `RST_STREAM`,
`SETTINGS`, `PUSH_PROMISE`, `PING`, `GOAWAY`, `WINDOW_UPDATE`, `CONTINUATION`, or
`UNKNOWN_FRAME_TYPE_n`), `stream_id`, `length`, `flags` (names such as `EndStream (0x1)`), and:

- `HEADERS`: `headers` as `name: value` lines, decoded with a fresh HPACK decoder for each HEADERS
  frame; `priority` when the priority flag is set. `CONTINUATION` frames are recorded but not
  decoded, so a header block split mid-field fails to decode and the request gets no answer.
- `SETTINGS`: `settings` as `NAME = value` lines in wire order. Setting 8 is
  `ENABLE_CONNECT_PROTOCOL` (RFC 8441) and setting 9 is `NO_RFC7540_PRIORITIES` (RFC 9218);
  unknown ids are `UNKNOWN_SETTING_n`.
- `WINDOW_UPDATE`: `increment`.
- `PRIORITY`: `priority` `{weight, depends_on, exclusive}`, weight as wire value + 1 (1–256).
- `DATA`: `payload` (base64, padding removed).
- `GOAWAY`: `goaway` `{LastStreamID, ErrCode, DebugData}` (debug data base64).

Zero numbers, empty lists and absent objects are left out of each frame's JSON.

`method`, `path` and `user_agent` of the report come from the last HEADERS frame: a line counts
when it starts with `:method`, `:path` or `user-agent` (so `user-agent-x: ...` also counts) and
has a non-empty value after `: `.

### 8.2 Akamai fingerprint

```
S|WU|P|PS
```

| Part | Rule |
| --- | --- |
| `S` | The first SETTINGS frame only, even if it is an ACK or empty (then `S` is empty): `id:value` pairs joined with `;` in wire order. Unknown ids keep their number. |
| `WU` | The increment of the first WINDOW_UPDATE on any stream (not only stream 0); `00` when there is none. |
| `P` | Each PRIORITY frame as `stream:exclusive:depends_on:weight`, joined with `,`; `0` when there are none. Priority carried inside HEADERS frames is not included. |
| `PS` | Pseudo-header order of the first HEADERS frame: the character after `:` of each pseudo-header, with a `,` after it only when that header is among the first three lines of the block, regular headers included. Chrome's order gives `m,a,s,p`; a regular header first, then `:method`, `:path`, `:scheme`, `:authority`, gives `m,p,sa`. |

`akamai_fingerprint_hash` = `md5(akamai_fingerprint)`.

## 9. QUIC Initial

The `quic` crate extracts the ClientHello from a client's first flight without a QUIC stack:

- QUIC v1 (RFC 9000) and v2 (RFC 9369) long-header packets; several packets coalesced in one
  datagram (0-RTT and Handshake packets are skipped, a short-header packet ends the datagram).
- Initial keys derived from the client's Destination Connection ID (RFC 9001 section 5.2);
  header protection removed and the payload decrypted with AES-128-GCM.
- Frames allowed in the Initial payload: PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE. Any other
  frame is an error.
- CRYPTO data is reassembled by offset, in any order, across packets and datagrams, until the
  whole ClientHello is present. At most 16 KiB of CRYPTO data per connection
  (`quic::MAX_CRYPTO_LEN`); a CRYPTO frame may end at most 4 KiB beyond the bytes received
  without a gap, and the data may be in at most 64 separate ranges. Past any of these the
  packet is rejected; if the ClientHello never completes, the server's report has `"tls": null`.
- A CRYPTO frame may repeat bytes that were already received (a retransmission). If it has
  other bytes for them, the assembly ends for good and the report has `"tls": null`: RFC 9000
  section 2.2 forbids a sender to change the data at an offset, a receiver may keep either
  copy, and the ClientHello reported must be the one the server's QUIC stack read.
- A packet that cannot be read ends the datagram. The Initial packets in front of it count.
- In the server, a datagram under 1200 bytes does not start a connection's assembly, because
  quinn ignores such a datagram (RFC 9000 section 14.1); the `quic` crate itself has no
  such rule, so that captures can be read offline whatever their size.

Limits: packet numbers are decoded as if nothing had been acknowledged, which holds for a
client's first flight. Retry and Version Negotiation packets are ignored, and only the length of
the token is kept. QUIC draft versions are not supported.

### 9.1 The `quic` object

An HTTP/3 report whose Initial packets were read has a `quic` object, placed after `tls` and
before `tcpip`. It is absent on TCP and whenever `tls` is `null` on HTTP/3. The format is
mirrust's own:

```json
"quic": {
  "version": "0x00000001",
  "dcid_length": 8,
  "scid_length": 0,
  "token_length": 0,
  "initial_datagrams": 2,
  "initial_datagram_sizes": [1250, 1250]
}
```

| Field | Rule |
| --- | --- |
| `version` | The version field of the client's first Initial packet, `0x` and eight hex digits: `0x00000001` (v1) or `0x6b3343cf` (v2). Later Initial packets must carry the same version. |
| `dcid_length` | Byte length of the Destination Connection ID the client chose for its first Initial packet (0–20). |
| `scid_length` | Byte length of the client's Source Connection ID in that packet (0–20). |
| `token_length` | Byte length of the Token field of that packet; 0 when the client sent no token. A client sends one after it received a NEW_TOKEN frame on an earlier connection to the same server. |
| `initial_datagram_sizes` | UDP payload size of each datagram that contributed to the ClientHello, in arrival order: every datagram that held at least one Initial packet of the connection and was read without error, from the first one up to and including the one that completed the ClientHello. The size is that of the whole datagram, with coalesced 0-RTT packets and padding. At most 32 sizes are kept. |
| `initial_datagrams` | The number of entries in `initial_datagram_sizes`. |

The values describe the first flight as it arrived: a datagram lost on the way and sent again
appears once, and datagrams that arrive after the ClientHello is complete are not counted.

### 9.2 The `http3` object

Every HTTP/3 report has an `http3` object, placed after `quic`. It describes what the client
sent on its unidirectional streams (RFC 9114 section 6.2) before its first request was answered.
The format is mirrust's own:

```json
"http3": {
  "fingerprint": "1:65536;6:262144;7:100;51:1;GREASE|0",
  "fingerprint_hash": "bfdcd3f328f2d701438ba11f5b8ce1ac",
  "settings": [
    { "id": 1, "name": "SETTINGS_QPACK_MAX_TABLE_CAPACITY", "value": 65536 },
    { "id": 6, "name": "SETTINGS_MAX_FIELD_SECTION_SIZE", "value": 262144 },
    { "id": 7, "name": "SETTINGS_QPACK_BLOCKED_STREAMS", "value": 100 },
    { "id": 51, "name": "SETTINGS_H3_DATAGRAM", "value": 1 },
    { "id": 65941885509, "name": "GREASE", "value": 3915636215 }
  ],
  "streams": [
    { "id": 2, "type": 0, "name": "control" }
  ]
}
```

(Chrome Canary 160. It creates its QPACK streams but writes their type only when it first has
data for them, which did not happen before the first request here.)

**Capture.** The server keeps the first 1024 bytes of each unidirectional stream the client
opens, for at most 16 streams per connection. Requests are held back until the SETTINGS frame
has been read or 250 ms have passed since the handshake, whichever is first. The object is
built when the first request of the connection is answered and repeated unchanged on later
requests.

**`streams`.** One object per stream whose type (the varint the stream starts with) had been read
at that moment, ordered by QUIC stream id, which is the order the client opened them in:

- `id`: the QUIC stream id (2, 6, 10, … for client-opened unidirectional streams).
- `type`: the stream type as a number.
- `name`: `control` (0), `push` (1), `qpack_encoder` (2), `qpack_decoder` (3); `GREASE` for a
  type of the reserved form `0x1f * N + 0x21`; otherwise `UNKNOWN_<type>` in decimal.

**`settings`.** The settings of the SETTINGS frame, in wire order, when the control stream (the
lowest-numbered stream of type 0) starts with one: after the type come the frame type `0x04`,
the payload length, and `id`, `value` pairs, all varints. `null` when no control stream was read,
its first frame is not SETTINGS, or the frame had not arrived in full; `[]` for an empty frame.
A payload that ends inside a pair keeps the pairs before it. Repeated ids are kept.

- `id`, `value`: numbers.
- `name`: `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (`0x01`), `SETTINGS_MAX_FIELD_SECTION_SIZE`
  (`0x06`), `SETTINGS_QPACK_BLOCKED_STREAMS` (`0x07`), `SETTINGS_ENABLE_CONNECT_PROTOCOL`
  (`0x08`), `SETTINGS_H3_DATAGRAM` (`0x33`), `SETTINGS_H3_DATAGRAM_DRAFT04` (`0xffd277`),
  `SETTINGS_ENABLE_WEBTRANSPORT` (`0x2b603742`), `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`
  (`0xc671706a`); `GREASE` for an id of the reserved form `0x1f * N + 0x21`; otherwise
  `UNKNOWN_<id>` in decimal.

**`fingerprint`.**

```
S|U
```

| Part | Rule |
| --- | --- |
| `S` | Each entry of `settings` as `id:value`, joined with `;`, in wire order. An entry named `GREASE` is written as the word `GREASE`, without id or value, in its position. Empty when `settings` is `null` or `[]`. |
| `U` | Each entry of `streams` as its `type`, joined with `,`, in order. A type named `GREASE` is written as `GREASE`. Empty when there are no streams. |

`fingerprint_hash` = `md5(fingerprint)`. With nothing read the fingerprint is `|`.

Limits:

- `U` holds the streams whose type had arrived when the first request was answered. A client
  that sends a stream type in the same flight as its request is listed in full when the packets
  arrive in order; under loss or reordering a stream can be missing, and a stream opened later
  in the connection is never listed. The SETTINGS frame does not have this limit because requests
  wait for it.
- Which streams a client opens early can depend on the server: this server offers no QPACK
  dynamic table, so a client that opens its QPACK streams on first use may never open them here.
- The pseudo-header order of the request is not part of the fingerprint; `h3` does not expose
  the field section before decoding it.

## 10. TCP SYN and p0f

The `tcpip` crate parses one packet from the IP header on. It returns nothing unless the packet
is IPv4 or IPv6 carrying TCP with SYN set and ACK, FIN and RST clear.

Packets that give nothing: a zero IPv4 total length is read as "the whole buffer", but bad IPv4
options, IHL below 5, a total length below 20 or below IHL, an IPv6 payload length of 0, a TCP
data offset below 5, IPv6 extension headers, fragments, and IP-in-IP (protocol 4 or 41) give
nothing. A TCP data offset that points past the segment still parses, with the options running
to the end of the data.

`tcp_syn` fields: `ip_version`, `src_ip`, `dst_ip` (an IPv4-mapped IPv6 address prints as IPv4),
`src_port`, `dst_port`, `ttl`, `ip_id` and `df` (IPv4 only), `ecn`, `window`, `mss`,
`window_scale` (only when the option is present), `sack_permitted`, `timestamps`, `options`
(names in wire order: `mss`, `nop`, `wscale`, `sackOK`, `timestamp`, `sack`, `eol`,
`unknown-N`; `null` when empty), `options_raw` (hex), `option_order` (`options` joined with
`,`), `payload_len`, `packet_len`.

TCP options: at most 24 are read; more set `bad`. A wrong declared length on MSS, window scale,
SACK-permitted or timestamp sets `bad`, but the option is still read at its standard size. A
repeated option overwrites the earlier value.

`p0f` is a p0f v3 TCP signature:

```
ver:ttl+?:olen:mss:wsize,scale:olayout:quirks:pclass
```

The TTL is the observed value followed by `+?`, and `wsize` is the literal window: the
signature records observations, not p0f's guesses of the initial TTL or the MSS multiple.
`olayout` uses p0f's names (`mss`, `nop`, `ws`, `sok`, `sack`, `ts`, `eol+N`, `?N`). `quirks`
are p0f's: `df`, `id+`, `id-`, `ecn`, `0+`, `flow`, `seq-`, `ack+`, `ack-`, `uptr+`, `urgf+`,
`pushf+`, `ts1-`, `ts2+`, `opt+`, `exws`, `bad`. `pclass` is `+` when the SYN carries payload,
else `0`.

The server has a SYN on Linux only, for TCP connections: the one the kernel saved for the
listening socket (`TCP_SAVE_SYN`), which is the packet from the IP header to the end of the
TCP header, so `payload_len` is always 0 there. That path has not run on Linux yet; see
[architecture.md](architecture.md#known-gaps).

## 11. JSON encoding

Responses are encoded as tls.peet.ws encodes them:

- Indented responses use two spaces.
- `<`, `>`, `&`, U+2028 and U+2029 inside strings are written as `\u003c`, `\u003e`, `\u0026`,
  `\u2028`, `\u2029`.
- Empty lists produced by the details code are `null`.
- `tcpip` is always present.

## 12. Known clients (`client`)

`client` is mirrust's own field, not part of tls.peet.ws's layout. It answers two questions:
which known client sends this TLS fingerprint, and does the `User-Agent` claim the same client.
It is the last field of `/api/all` and `/api/clean`; `/api/tls` does not carry it.

```json
"client": {
  "match": "exact",
  "family": "Go net/http",
  "version": "1.27.4",
  "library": "crypto/tls",
  "source": "captured locally, go1.27.4 darwin/arm64 net/http with ForceAttemptHTTP2, HTTP/2",
  "user_agent_family": "Chrome",
  "consistent": false
}
```

| Field | Content |
| --- | --- |
| `match` | `exact`, `ciphers` or `none`; see below. |
| `family`, `version`, `library`, `source` | The matched dataset entry. `null` when `match` is `none`; `library` is also `null` when the entry does not state one. |
| `user_agent_family` | What the `User-Agent` claims: `Chrome`, `Edge`, `Firefox`, `Safari`, `curl`, `Go`, `Python`, `Node`, `okhttp`, or `unknown`. |
| `consistent` | `true` or `false` when `match` is `exact` and `user_agent_family` is not `unknown`; otherwise `null`. |

All seven keys are always present.

### 12.1 Matching

The lookup uses the FoxIO `ja4` (section 4.1), which has three parts `a_b_c`: `b` is the hash of
the sorted cipher list, `c` the hash of the sorted extensions and the signature algorithms.

1. `exact`: an entry has the same `ja4`.
2. `ciphers`: no entry has the same `ja4`, but at least one has the same part `b`. The entry
   reported is the first in file order whose part `c` is equal too, otherwise the first with
   that part `b`. Read it as "same cipher list as this client": `version` describes that entry,
   not the visitor.
3. `none`: no entry has this cipher list, or there is no ClientHello (an HTTP/3 request whose
   Initial was not captured).

Nothing is inferred beyond these comparisons.

One client produces several JA4 values, because part `a` holds the transport, the TLS version,
whether SNI is present, the cipher and extension counts and the first ALPN value. A browser
opened by IP address sends no SNI, `curl --http1.1` offers a different ALPN, and HTTP/3 uses
`q`; each of these is a `ciphers` match unless the dataset holds that variant. Part `c` can
change as well: the Chrome-120 profile of `corpus/hellos.jsonl` carries the padding extension in
its hello with SNI and not in the one without, and a resumed TLS 1.3 connection carries
`pre_shared_key`.

### 12.2 User-Agent

The header is read minimally. A value that starts with `curl/`, `Go-http-client/`,
`Python-urllib/`, `python-requests/`, `python-httpx/`, `okhttp/`, `undici`, `node-fetch/`, or
that is exactly `node`, names that tool (compared without regard to ASCII case). Otherwise the
first of these tokens found anywhere in the value decides: `Edg/` or `EdgA/` is Edge, `Firefox/`
is Firefox, `Chrome/` or `Chromium/` is Chrome, `Safari/` is Safari. Brave and Opera therefore
read as Chrome, and a value with `Safari/` but none of the other tokens (Chrome and Firefox on
iOS send `CriOS/` and `FxiOS/`) reads as Safari. Everything else is `unknown`.

`fingerprint::known::UserAgent` also reads a major version where the header states the
client's own: after `Edg/`, `Firefox/`, `Chrome/`, `Version/` (Safari), `curl/`, `okhttp/` and
`Python-urllib/`. `Go-http-client/` states the HTTP version, `python-requests/` and
`python-httpx/` the library's version, and `node` none, so those have no major version. The
report does not use the version.

`consistent` compares families only, never versions:

| Dataset `family` | Consistent with `user_agent_family` |
| --- | --- |
| `Chrome` | `Chrome`, `Edge` (Chromium-based browsers share Chrome's TLS stack) |
| `360 Browser` | `Chrome` |
| `Firefox` | `Firefox` |
| `Safari` | `Safari` |
| `curl` | `curl` |
| `Go net/http` | `Go` |
| `Python` | `Python` |
| `Node.js` | `Node` |
| `okhttp` | `okhttp` |
| `rustls` and any other | none: a library is not a client that a `User-Agent` family stands for |

### 12.3 The dataset

`corpus/clients.jsonl` is built into the `fingerprint` crate (`fingerprint::known`). One JSON
object per line, one line per JA4:

| Key | Content |
| --- | --- |
| `family` | Stable label: `Chrome`, `Firefox`, `Safari`, `curl`, `Go net/http`, `Python`, `Node.js`, `okhttp`, `rustls`, `360 Browser`. |
| `version` | The version or version range the fingerprint was observed with, as text. |
| `version_min`, `version_max` | The lowest and highest observed major version as integers, or both `null`. For the `Safari` entries taken from iOS profiles this is the iOS version. |
| `library` | The TLS library, or `null` when not known. |
| `source` | Where the sample came from. |
| `ja4`, `ja4_r` | The FoxIO JA4 and JA4_r. `ja4` must be unique in the file. |
| `akamai` | The Akamai HTTP/2 fingerprint (section 8.2) of the same connection, or `null` when the sample did not use HTTP/2 or has no HTTP/2 capture. |

Sources:

- The browser profiles of `corpus/hellos.jsonl` with SNI (the randomized ones are left out).
  Profiles with one JA4 are merged into one line whose range spans them; the versions between
  the listed profiles were not observed. These are uTLS's reproductions of the browsers, not
  captures of them, and have no `akamai`.
- Signatures of the test suite of curl-impersonate (MIT, lexiforest/curl-impersonate), which
  were captured from real browsers: Chrome 150, Firefox 133 and 135 to 144, Safari 18 and 26 on
  macOS and iOS. The ClientHello was rebuilt from the signature (ciphers, extension order and
  types, versions, ALPN, signature algorithms, groups) and fed to the code of this repository for
  the hashes. Only signatures that were captured are used, not the ones curl-impersonate derives
  from profile options.
- Clients captured through mirrust itself with a server name, with their exact versions in
  `source`: curl, Python (`urllib`, httpx, requests), Go `net/http`, Node.js (`https`, `http2`,
  `fetch`), Ruby `Net::HTTP`, Java (`HttpClient`, `HttpsURLConnection`), `reqwest` and `ureq`
  with rustls or with the system TLS (Secure Transport on macOS), rustls
  (`crates/server/examples/rustls_get.rs`) and headless Chrome. Clients whose JA4 equals one
  already in the file (aiohttp, axios, got) have no line of their own.

To add a client, request `/api/all` with it, copy `tls.ja4`, `tls.ja4_r` and
`http2.akamai_fingerprint` into a new line, and run `cargo test -p fingerprint`: the tests check
that every line parses, that `ja4` is unique and is the hash of `ja4_r`, and that every
SNI-carrying browser profile of `corpus/hellos.jsonl` has its line. A new `family` also needs a
row in `Client::agrees_with`.

### 12.4 Limits

- A match means "identical to a client we have seen", not proof of identity. Any client can
  send another's ClientHello; uTLS exists to do that. `consistent: true` says the two claims
  agree, not that either is true.
- JA4 sorts ciphers and extensions by design, so their order plays no part in the match. Two
  clients that differ only in order have one JA4; `ja4_o` and `ja4_ro` (section 4.1) keep the
  order but are not matched.
- `none` and `ciphers` are common for real clients: the dataset is small, and a new version,
  build option or TLS library release can change the fingerprint.
- Versions are not compared. A Chrome 133 `User-Agent` with the JA4 of Chrome 100 is
  `consistent: true`.
- The version ranges are what was looked at, not when a fingerprint began or ended. For the
  browser entries they are the names of uTLS profiles or curl-impersonate signatures, and a
  range spans the ones that share a JA4; nobody captured the versions between them. Three consequences:
  - **Chrome 134 to 149 are not in the dataset.** The entries around the gap are the profile
    of 133, one entry for a signature of 150 and a capture of Brave Beta 158 (the same hello;
    151 to 157 were not looked at), and one entry for the profile of 155 and a capture of
    Canary 160, which share a JA4. The profile of 133 and Canary 160 differ by one
    extension (51764, `trust_anchors`). A real Chrome of a version between is an `exact` match
    with whichever of the two it sends like, and the report then names that version, not the browser's. If it sends something
    else it is a `ciphers` match or `none`, which costs 5 or 10 points in the `audit`
    (`tls_known`) and leaves the verdict `consistent`; the `tls_traits` check then judges it
    by the extensions Chromium always sends.
  - **The entry "Chrome 120 (hello with the padding extension)" is not about version 120.**
    It is the hello of the entry "120-131" plus padding, which BoringSSL adds when a hello
    would be between 256 and 511 bytes long: a matter of the server name's length and of the
    key shares, not of the version. uTLS names the profile after 120; nothing in the dataset
    says which version first sent this hello. (Both entries have the `encrypted_client_hello`
    extension, which Chrome's release notes put in version 117; that was not checked here.)
  - Because of this the `audit` check `ua_version` does not compare the `User-Agent` with an
    entry's first version. It warns only when the claimed version is one the dataset has
    with another fingerprint: at or below the last version of the newest older entry of the
    family (115 for both entries that start at 120).
- The HTTP/2 fingerprint is stored in the dataset but not matched.

## Audit

The `audit` object of `/api/all` says whether the layers the server observed agree with each
other and with what the `User-Agent` claims. `/api/clean` carries its `score` and `verdict`
only; `/api/tls` has no `audit`. It is `null` when no ClientHello was captured (and then
`/api/clean` has `null` for both).

This is the `audit` for curl 8.7.1 over HTTP/2 with a Chrome `User-Agent` header, as the server
returned it:

```json
"audit": {
  "score": 30,
  "verdict": "inconsistent",
  "checks": [
    {
      "id": "tls_known",
      "status": "pass",
      "title": "TLS fingerprint against known clients",
      "detail": "Identical to curl 8.7.1"
    },
    {
      "id": "ua_tls",
      "status": "fail",
      "title": "User-Agent against the TLS stack",
      "detail": "The User-Agent says Chrome, but the TLS stack is curl 8.7.1"
    },
    {
      "id": "http2",
      "status": "pass",
      "title": "HTTP/2 fingerprint against the client",
      "detail": "Settings, window and header order are those of curl"
    },
    {
      "id": "headers",
      "status": "fail",
      "title": "Request headers of the claimed browser",
      "detail": "Chrome sends these with every request; missing here: sec-ch-ua, sec-fetch-*, accept-language, accept-encoding"
    },
    {
      "id": "tcp_os",
      "status": "skip",
      "title": "TCP stack against the User-Agent",
      "detail": "Not measured: this server did not capture the TCP SYN. ..."
    }
  ]
}
```

(The `detail` of `tcp_os` is shortened here.) The penalties are 40 and 30, so the score is 30.
Each check has `id`, `status`, `title` and `detail`, in that order; the penalty is not in the
JSON.

`score` is 100 minus the penalties of the checks, not below 0. `verdict` is `consistent` from
90, `suspicious` from 60, `inconsistent` below. `status` is `pass`, `warn` (unusual, but real
clients do it), `fail` (a real client of the claimed kind does not do this) or `skip` (not
measured). A check that does not apply to the connection is left out. The checks, in the order
they are reported:

| `id` | Compares | Penalty |
| --- | --- | --- |
| `tls_known` | The JA4 with the known-client dataset. A hello whose cipher and extension hashes equal an entry's, differing only in the first JA4 part (SNI, ALPN), counts as that client. | 5 for a cipher-list match only, 10 for no match |
| `ua_tls` | The family the `User-Agent` names with the family of the matched client. Also reports a missing `User-Agent`. | 40; 25 when only the cipher list matched; 10 for no `User-Agent` |
| `tls_traits` | Only without a dataset match and with a browser `User-Agent`: the extensions that engine always sends (Chromium: GREASE, `compress_certificate`, `application_settings` when `h2` is offered, no `record_size_limit`; Firefox: no GREASE, `record_size_limit`, `delegated_credentials`, no `application_settings`; Safari on an Apple platform: GREASE, no `application_settings`; WebKitGTK also says Safari and is not checked). | 30 |
| `ua_version` | The major version in the `User-Agent` with the dataset: a warning when the dataset has that version, or a newer one that is still older than the matched entry, with another fingerprint. A version between two entries was not observed and is not judged, and neither is one older than the only entry of its family. | 10 |
| `alps_alpn` | Every protocol named in `application_settings` (17513 or 17613) must also be in ALPN. | 30 |
| `grease` | A hello that uses GREASE has it in cipher suites, extensions, groups and versions alike. | 20 |
| `http2` | The Akamai fingerprint with the one recorded for the matched client; without one, the pseudo-header order with the claimed engine's (Chromium `m,a,s,p`, Firefox `m,p,a,s`). | 30 |
| `headers` | Only with a browser `User-Agent` and when the server saw the headers (HTTP/1.1, HTTP/2): `sec-ch-ua` (Chromium from 89; Chromium leaves it out when JavaScript is blocked for the site or the `User-Agent` was overridden, so it counts less), `sec-fetch-*` (Chromium from 76, Firefox from 90, Safari from 16.4, the versions in MDN's browser-compat-data; a Safari `Version/16` without a minor number is not asked for them), `accept-language`, `accept-encoding`. | 10, 20, 10, 10; at most 30 |
| `tcp_os` | The system whose default SYN has these TCP options with the system the `User-Agent` names. `skip`, with no penalty, when the server has no SYN: on macOS and Windows, over HTTP/3, and where the Linux kernel kept none. | 30 |
| `tcp_mss` | The MSS with the Ethernet value (1460, or 1440 over IPv6), allowing 8 bytes for `PPPoE`. Left out when there is no SYN. | 10 when more than 8 lower |

The score describes consistency as far as this server can observe it and for the clients in
its dataset. It is not proof that a client is, or is not, what it claims to be.

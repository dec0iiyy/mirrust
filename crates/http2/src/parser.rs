//! Incremental parser for the client side of an HTTP/2 connection, as tls.peet.ws reads it.

use std::fmt;
use std::ops::Range;

use loona_hpack::Decoder;

use crate::frame::{GoAway, ParsedFrame, Priority};

/// The client connection preface (RFC 9113 section 3.4).
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default cap on the bytes a [`Parser`] accepts, preface included.
///
/// A client sends its preface, SETTINGS, a few `WINDOW_UPDATE` or PRIORITY frames and the first
/// request: a few hundred bytes, a few KiB with large cookies. The header block alone is held
/// to [`MAX_HEADER_BYTES`] once decoded, so 64 KiB leaves room for any real client and no more.
/// tls.peet.ws has no cap: it buffers any frame up to 16 MiB and reads until the request ends.
pub const DEFAULT_MAX_INPUT: usize = 64 * 1024;

/// Most frames a [`Parser`] accepts before the first request ends.
///
/// Every frame becomes a [`ParsedFrame`] record that is later serialized, so without this cap
/// 9-byte empty frames turn each input byte into far more output. Real clients send under 20
/// frames (preface SETTINGS, `WINDOW_UPDATE`, up to five PRIORITY frames, HEADERS, DATA).
pub const MAX_FRAMES: usize = 256;

/// Most bytes of decoded header lines (`name: value`) a [`Parser`] keeps, over all the HEADERS
/// frames it reads; the header list size the server allows in its SETTINGS.
///
/// HPACK lets one byte of input repeat a whole dynamic table entry, so without this cap the
/// input limit does not bound what the decoded headers take: 1 MiB of input can decode to
/// gigabytes. tls.peet.ws has no such cap.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

const FRAME_HEADER_LEN: usize = 9;
/// The default `SETTINGS_MAX_FRAME_SIZE` (RFC 9113 section 6.5.2), which the server keeps.
const MAX_FRAME_SIZE: u32 = 16_384;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

const FRAME_NAMES: [&str; 10] = [
    "DATA",
    "HEADERS",
    "PRIORITY",
    "RST_STREAM",
    "SETTINGS",
    "PUSH_PROMISE",
    "PING",
    "GOAWAY",
    "WINDOW_UPDATE",
    "CONTINUATION",
];

/// Why the parser stopped without a complete request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The first 24 bytes are not the HTTP/2 connection preface.
    BadPreface,
    /// A frame broke a rule `x/net/http2`'s `Framer` enforces; tls.peet.ws closes the connection.
    Frame(&'static str),
    /// A frame whose length is wrong for its type (RFC 9113 section 4.2); tls.peet.ws closes
    /// the connection for these too.
    FrameSize(&'static str),
    /// A SETTINGS frame asks for a flow-control window over 2^31 - 1 (RFC 9113 section 6.5.2).
    FlowControl(&'static str),
    /// A HEADERS block failed to decode. tls.peet.ws then stops reading without a word
    /// and the connection hangs until the client gives up.
    HeaderDecode,
    /// The input grew past the parser's limit.
    TooLarge,
    /// The header lines decoded so far take more than [`MAX_HEADER_BYTES`].
    HeadersTooLarge,
    /// More than [`MAX_FRAMES`] frames arrived before the request ended.
    TooManyFrames,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPreface => f.write_str("missing http/2 connection preface"),
            Self::Frame(reason) | Self::FrameSize(reason) | Self::FlowControl(reason) => {
                write!(f, "invalid frame: {reason}")
            }
            Self::HeaderDecode => f.write_str("hpack decoding failed"),
            Self::TooLarge => f.write_str("input exceeds the size limit"),
            Self::HeadersTooLarge => f.write_str("decoded headers exceed the size limit"),
            Self::TooManyFrames => write!(f, "more than {MAX_FRAMES} frames before the request"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// The error code (RFC 9113 section 7) of the GOAWAY frame that tells the client about
    /// this error: `PROTOCOL_ERROR`, `FLOW_CONTROL_ERROR`, `FRAME_SIZE_ERROR`,
    /// `COMPRESSION_ERROR`, or `ENHANCE_YOUR_CALM` for input over one of the parser's limits.
    #[must_use]
    pub fn code(&self) -> u32 {
        match self {
            Self::BadPreface | Self::Frame(_) => 0x1,
            Self::FlowControl(_) => 0x3,
            Self::FrameSize(_) => 0x6,
            Self::HeaderDecode => 0x9,
            Self::TooLarge | Self::HeadersTooLarge | Self::TooManyFrames => 0xb,
        }
    }
}

/// Whether the parser has seen the end of the first request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// More bytes are needed.
    Incomplete,
    /// A frame with `END_STREAM` arrived; tls.peet.ws stops reading here and responds.
    Complete,
}

/// Turns the client's bytes (preface and frames) into tls.peet.ws's frame list.
///
/// Feed bytes as they arrive with [`Parser::feed`]; it returns [`Status::Complete`] at the
/// first HEADERS or DATA frame with `END_STREAM`, the point where tls.peet.ws stops reading.
/// Bytes after that are ignored.
#[derive(Debug)]
pub struct Parser {
    buf: Vec<u8>,
    pos: usize,
    received: usize,
    max_input: usize,
    preface_seen: bool,
    last_header_stream: u32,
    /// The highest stream identifier in the frames read so far.
    last_stream: u32,
    /// The stream of the last HEADERS frame read, decoded or not.
    request_stream: u32,
    frames: Vec<ParsedFrame>,
    header_frame: Option<usize>,
    /// What is left of [`MAX_HEADER_BYTES`].
    header_budget: usize,
    complete: bool,
    /// The first error `feed` returned; every later call returns it again.
    failed: Option<Error>,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// A parser that expects the connection preface first and caps input at
    /// [`DEFAULT_MAX_INPUT`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_input(DEFAULT_MAX_INPUT)
    }

    /// A parser that accepts at most `max_input` bytes in total.
    #[must_use]
    pub fn with_max_input(max_input: usize) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            received: 0,
            max_input,
            preface_seen: false,
            last_header_stream: 0,
            last_stream: 0,
            request_stream: 0,
            frames: Vec::new(),
            header_frame: None,
            header_budget: MAX_HEADER_BYTES,
            complete: false,
            failed: None,
        }
    }

    /// Adds bytes and parses every frame they complete.
    ///
    /// # Errors
    ///
    /// Returns the reason tls.peet.ws would drop the connection: a bad preface, a malformed frame,
    /// an undecodable header block, or more input than the limit; and, unlike tls.peet.ws,
    /// [`Error::HeadersTooLarge`] when the decoded headers pass [`MAX_HEADER_BYTES`] and
    /// [`Error::TooManyFrames`] when more than [`MAX_FRAMES`] frames arrive. Frames
    /// parsed before the error stay available through [`Parser::frames`].
    ///
    /// The first error is final: later calls return the same error and ignore their bytes.
    pub fn feed(&mut self, data: &[u8]) -> Result<Status, Error> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        let result = self.feed_bytes(data);
        if let Err(error) = &result {
            self.failed = Some(error.clone());
        }
        result
    }

    fn feed_bytes(&mut self, data: &[u8]) -> Result<Status, Error> {
        if self.complete {
            return Ok(Status::Complete);
        }
        self.received = self.received.saturating_add(data.len());
        if self.received > self.max_input {
            return Err(Error::TooLarge);
        }
        self.buf.drain(..self.pos);
        self.pos = 0;
        self.buf.extend_from_slice(data);

        if !self.preface_seen {
            let n = self.buf.len().min(PREFACE.len());
            if self.buf[..n] != PREFACE[..n] {
                return Err(Error::BadPreface);
            }
            if n < PREFACE.len() {
                return Ok(Status::Incomplete);
            }
            self.preface_seen = true;
            self.pos = PREFACE.len();
        }

        while let Some((header, payload_end)) = self.next_frame() {
            if self.frames.len() >= MAX_FRAMES {
                return Err(Error::TooManyFrames);
            }
            self.last_stream = self.last_stream.max(header.stream_id);
            if header.kind == HEADERS {
                self.request_stream = header.stream_id;
            }
            let payload_start = self.pos + FRAME_HEADER_LEN;
            let (mut frame, fragment) =
                parse_frame(&header, &self.buf[payload_start..payload_end])?;
            // Framer checks frame order before tls.peet.ws decodes the header block.
            self.check_order(&header)?;
            if let Some(range) = fragment {
                let start = payload_start + range.start;
                let fragment = &self.buf[start..payload_start + range.end];
                (frame.headers, frame.second_bytes) =
                    decode_headers(fragment, &mut self.header_budget)?;
            }
            self.pos = payload_end;
            let ends_stream = frame.flags.first() == Some(&"EndStream (0x1)");
            if header.kind == HEADERS {
                self.header_frame = Some(self.frames.len());
            }
            self.frames.push(frame);
            if ends_stream {
                self.complete = true;
                return Ok(Status::Complete);
            }
        }
        Ok(Status::Incomplete)
    }

    /// Frames parsed so far, in arrival order.
    #[must_use]
    pub fn frames(&self) -> &[ParsedFrame] {
        &self.frames
    }

    /// The last HEADERS frame parsed so far, whose stream tls.peet.ws answers on.
    #[must_use]
    pub fn header_frame(&self) -> Option<&ParsedFrame> {
        self.header_frame.and_then(|i| self.frames.get(i))
    }

    /// The highest stream identifier the client used in the frames read so far, the frame
    /// that caused an error included; 0 before any frame on a stream.
    ///
    /// It is the last stream of a GOAWAY frame sent for an error (RFC 9113 section 5.4.1). A
    /// client sends a request again on a new connection when GOAWAY names a lower stream than
    /// the request's (section 6.8), and a request the parser refused would be refused again.
    #[must_use]
    pub fn last_stream(&self) -> u32 {
        self.last_stream
    }

    /// The stream of the last HEADERS frame read, whether or not its header block could be
    /// decoded: the request the client waits on. 0 before any HEADERS frame.
    #[must_use]
    pub fn request_stream(&self) -> u32 {
        self.request_stream
    }

    /// Whether the full connection preface has arrived.
    #[must_use]
    pub fn preface_seen(&self) -> bool {
        self.preface_seen
    }

    /// The bytes received after the last frame parsed: what the client sent behind the frame
    /// that ended its request, or the start of a frame that is not whole yet.
    #[must_use]
    pub fn unparsed(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Consumes the parser and returns its frames.
    #[must_use]
    pub fn into_frames(self) -> Vec<ParsedFrame> {
        self.frames
    }

    fn next_frame(&self) -> Option<(FrameHeader, usize)> {
        let rest = &self.buf[self.pos..];
        let raw: &[u8; FRAME_HEADER_LEN] = rest.get(..FRAME_HEADER_LEN)?.try_into().ok()?;
        let header = FrameHeader::parse(raw);
        let end = self.pos + FRAME_HEADER_LEN + header.length as usize;
        (end <= self.buf.len()).then_some((header, end))
    }

    /// `Framer.checkFrameOrder`: a header block must continue with CONTINUATION frames on
    /// its own stream, and CONTINUATION may not appear anywhere else.
    fn check_order(&mut self, header: &FrameHeader) -> Result<(), Error> {
        if self.last_header_stream != 0 {
            if header.kind != CONTINUATION {
                return Err(Error::Frame("expected CONTINUATION"));
            }
            if header.stream_id != self.last_header_stream {
                return Err(Error::Frame("CONTINUATION on another stream"));
            }
        } else if header.kind == CONTINUATION {
            return Err(Error::Frame("unexpected CONTINUATION"));
        }
        if matches!(header.kind, HEADERS | CONTINUATION) {
            self.last_header_stream = if header.flags & FLAG_END_HEADERS == 0 {
                header.stream_id
            } else {
                0
            };
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct FrameHeader {
    length: u32,
    kind: u8,
    flags: u8,
    stream_id: u32,
}

impl FrameHeader {
    fn parse(raw: &[u8; FRAME_HEADER_LEN]) -> Self {
        Self {
            length: u32::from_be_bytes([0, raw[0], raw[1], raw[2]]),
            kind: raw[3],
            flags: raw[4],
            stream_id: u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) & 0x7fff_ffff,
        }
    }

    fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// The frame at the start of `buf` and its length in bytes, header included; `None` while
/// `buf` holds only part of a frame.
///
/// For the frames a client sends while the response is written: header blocks are not
/// decoded, frame order is not checked, and a frame over the default `SETTINGS_MAX_FRAME_SIZE`
/// is an error, because the server never raises it (RFC 9113 section 4.2).
pub(crate) fn frame_at(buf: &[u8]) -> Result<Option<(ParsedFrame, usize)>, Error> {
    let Some(raw) = buf.first_chunk::<FRAME_HEADER_LEN>() else {
        return Ok(None);
    };
    let header = FrameHeader::parse(raw);
    if header.length > MAX_FRAME_SIZE {
        return Err(Error::FrameSize("frame over SETTINGS_MAX_FRAME_SIZE"));
    }
    let end = FRAME_HEADER_LEN + header.length as usize;
    let Some(payload) = buf.get(FRAME_HEADER_LEN..end) else {
        return Ok(None);
    };
    let (frame, _) = parse_frame(&header, payload)?;
    Ok(Some((frame, end)))
}

/// Reads one frame and records it as tls.peet.ws does, except header block
/// decoding: a HEADERS frame returns its fragment's range within `payload` instead.
fn parse_frame(
    header: &FrameHeader,
    payload: &[u8],
) -> Result<(ParsedFrame, Option<Range<usize>>), Error> {
    let mut frame = ParsedFrame {
        frame_type: FRAME_NAMES.get(usize::from(header.kind)).map_or_else(
            || format!("UNKNOWN_FRAME_TYPE_{}", header.kind),
            |name| (*name).to_owned(),
        ),
        stream_id: header.stream_id,
        length: header.length,
        flags: flag_names(header),
        ..ParsedFrame::default()
    };
    let stream_zero = header.stream_id == 0;
    let mut fragment = None;
    match header.kind {
        DATA => {
            if stream_zero {
                return Err(Error::Frame("DATA frame with stream ID 0"));
            }
            frame.payload = unpad(header, payload)?.to_vec();
        }
        HEADERS => {
            if stream_zero {
                return Err(Error::Frame("HEADERS frame with stream ID 0"));
            }
            let (prio, range) = headers_layout(header, payload)?;
            frame.priority = prio;
            fragment = Some(range);
        }
        PRIORITY => {
            if stream_zero {
                return Err(Error::Frame("PRIORITY frame with stream ID 0"));
            }
            let param: &[u8; 5] = payload
                .try_into()
                .map_err(|_| Error::FrameSize("PRIORITY payload is not 5 bytes"))?;
            frame.priority = Some(priority(*param));
        }
        RST_STREAM => {
            if payload.len() != 4 {
                return Err(Error::FrameSize("bad RST_STREAM"));
            }
            if stream_zero {
                return Err(Error::Frame("bad RST_STREAM"));
            }
        }
        SETTINGS => {
            frame.settings = settings(header, payload)?;
            frame.initial_window = initial_window(payload);
        }
        PUSH_PROMISE => check_push_promise(header, payload)?,
        PING => {
            frame.ping_data = payload.try_into().ok();
            if frame.ping_data.is_none() {
                return Err(Error::FrameSize("bad PING"));
            }
            if !stream_zero {
                return Err(Error::Frame("bad PING"));
            }
        }
        GOAWAY => {
            if !stream_zero {
                return Err(Error::Frame("GOAWAY on a stream"));
            }
            let (ids, debug) = payload
                .split_first_chunk::<8>()
                .ok_or(Error::FrameSize("short GOAWAY"))?;
            frame.go_away = Some(GoAway {
                last_stream_id: u32::from_be_bytes([ids[0], ids[1], ids[2], ids[3]]) & 0x7fff_ffff,
                err_code: u32::from_be_bytes([ids[4], ids[5], ids[6], ids[7]]),
                debug_data: debug.to_vec(),
            });
        }
        WINDOW_UPDATE => {
            let raw: [u8; 4] = payload
                .try_into()
                .map_err(|_| Error::FrameSize("WINDOW_UPDATE payload is not 4 bytes"))?;
            frame.increment = u32::from_be_bytes(raw) & 0x7fff_ffff;
            if frame.increment == 0 {
                return Err(Error::Frame("WINDOW_UPDATE with zero increment"));
            }
        }
        CONTINUATION if stream_zero => {
            return Err(Error::Frame("CONTINUATION frame with stream ID 0"));
        }
        _ => {}
    }
    Ok((frame, fragment))
}

/// `Framer`'s checks of a `PUSH_PROMISE` frame, which tls.peet.ws records like any other.
fn check_push_promise(header: &FrameHeader, payload: &[u8]) -> Result<(), Error> {
    if header.stream_id == 0 {
        return Err(Error::Frame("PUSH_PROMISE frame with stream ID 0"));
    }
    let mut rest = payload;
    let mut pad = 0;
    if header.has(FLAG_PADDED) {
        let (&first, tail) = rest
            .split_first()
            .ok_or(Error::Frame("short PUSH_PROMISE"))?;
        pad = usize::from(first);
        rest = tail;
    }
    if rest.len() < 4 + pad {
        return Err(Error::Frame("short PUSH_PROMISE"));
    }
    Ok(())
}

/// Where the priority and the header block fragment sit in a HEADERS payload.
fn headers_layout(
    header: &FrameHeader,
    payload: &[u8],
) -> Result<(Option<Priority>, Range<usize>), Error> {
    let mut rest = payload;
    let mut pad = 0;
    if header.has(FLAG_PADDED) {
        let (&first, tail) = rest.split_first().ok_or(Error::Frame("short HEADERS"))?;
        pad = usize::from(first);
        rest = tail;
    }
    let mut prio = None;
    if header.has(FLAG_PRIORITY) {
        let (param, tail) = rest
            .split_first_chunk::<5>()
            .ok_or(Error::Frame("short HEADERS priority"))?;
        prio = Some(priority(*param));
        rest = tail;
    }
    let len = rest
        .len()
        .checked_sub(pad)
        .ok_or(Error::Frame("HEADERS padding too long"))?;
    let start = payload.len() - rest.len();
    Ok((prio, start..start + len))
}

fn unpad<'p>(header: &FrameHeader, payload: &'p [u8]) -> Result<&'p [u8], Error> {
    if !header.has(FLAG_PADDED) {
        return Ok(payload);
    }
    let (&pad, rest) = payload
        .split_first()
        .ok_or(Error::Frame("short padded frame"))?;
    rest.len()
        .checked_sub(usize::from(pad))
        .map(|end| &rest[..end])
        .ok_or(Error::Frame("padding longer than payload"))
}

fn priority(param: [u8; 5]) -> Priority {
    let raw = u32::from_be_bytes([param[0], param[1], param[2], param[3]]);
    Priority {
        weight: u16::from(param[4]) + 1,
        depends_on: raw & 0x7fff_ffff,
        exclusive: u8::from(raw & 0x8000_0000 != 0),
    }
}

/// Only the flags tls.peet.ws has names for, lowest bit first.
fn flag_names(header: &FrameHeader) -> Vec<&'static str> {
    let known: &[(u8, &'static str)] = match header.kind {
        SETTINGS | PING => &[(FLAG_ACK, "Ack (0x1)")],
        HEADERS => &[
            (FLAG_END_STREAM, "EndStream (0x1)"),
            (FLAG_END_HEADERS, "EndHeaders (0x4)"),
            (FLAG_PADDED, "Padded (0x8)"),
            (FLAG_PRIORITY, "Priority (0x20)"),
        ],
        DATA => &[
            (FLAG_END_STREAM, "EndStream (0x1)"),
            (FLAG_PADDED, "Padded (0x8)"),
        ],
        CONTINUATION => &[(FLAG_END_HEADERS, "EndHeaders (0x4)")],
        PUSH_PROMISE => &[
            (FLAG_END_HEADERS, "EndHeaders (0x4)"),
            (FLAG_PADDED, "Padded (0x8)"),
        ],
        _ => &[],
    };
    known
        .iter()
        .filter(|(bit, _)| header.has(*bit))
        .map(|&(_, name)| name)
        .collect()
}

/// Settings as tls.peet.ws prints them: `fmt.Sprintf("%q", setting)` with quotes and brackets
/// stripped, and id 9 renamed because `x/net/http2` does not know it.
fn settings(header: &FrameHeader, payload: &[u8]) -> Result<Vec<String>, Error> {
    if header.has(FLAG_ACK) && !payload.is_empty() {
        return Err(Error::FrameSize("SETTINGS ack with a payload"));
    }
    if header.stream_id != 0 {
        return Err(Error::Frame("SETTINGS on a stream"));
    }
    if !payload.len().is_multiple_of(6) {
        return Err(Error::FrameSize("SETTINGS length is not a multiple of 6"));
    }
    let pairs: Vec<(u16, u32)> = payload
        .as_chunks::<6>()
        .0
        .iter()
        .map(|c| {
            (
                u16::from_be_bytes([c[0], c[1]]),
                u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
            )
        })
        .collect();
    // Framer checks only the first INITIAL_WINDOW_SIZE (`SettingsFrame.Value`).
    if let Some(&(_, value)) = pairs.iter().find(|(id, _)| *id == 4)
        && value > 0x7fff_ffff
    {
        return Err(Error::FlowControl("INITIAL_WINDOW_SIZE too large"));
    }
    Ok(pairs
        .into_iter()
        .map(|(id, value)| format!("{} = {value}", setting_name(id)))
        .collect())
}

/// The last `INITIAL_WINDOW_SIZE` (id 4) of a SETTINGS payload: the one that takes effect
/// (RFC 9113 section 6.5.3 applies the settings in order).
fn initial_window(payload: &[u8]) -> Option<u32> {
    payload
        .as_chunks::<6>()
        .0
        .iter()
        .rev()
        .find(|c| c[..2] == [0, 4])
        .map(|c| u32::from_be_bytes([c[2], c[3], c[4], c[5]]))
}

fn setting_name(id: u16) -> String {
    let name = match id {
        1 => "HEADER_TABLE_SIZE",
        2 => "ENABLE_PUSH",
        3 => "MAX_CONCURRENT_STREAMS",
        4 => "INITIAL_WINDOW_SIZE",
        5 => "MAX_FRAME_SIZE",
        6 => "MAX_HEADER_LIST_SIZE",
        8 => "ENABLE_CONNECT_PROTOCOL",
        9 => "NO_RFC7540_PRIORITIES",
        _ => return format!("UNKNOWN_SETTING_{id}"),
    };
    name.to_owned()
}

/// Decodes one HEADERS fragment with a fresh decoder, as tls.peet.ws does for every frame.
///
/// Each line's bytes come out of `budget`; a block that needs more is not kept. The second
/// value is the second byte of each line before invalid UTF-8 was replaced.
fn decode_headers(fragment: &[u8], budget: &mut usize) -> Result<(Vec<String>, Vec<u8>), Error> {
    let mut decoder = Decoder::new();
    let mut lines = Vec::new();
    let mut second_bytes = Vec::new();
    let mut too_large = false;
    decoder
        .decode_with_cb(fragment, |name, value| {
            let len = name.len() + value.len() + 2;
            // The decoder cannot be stopped from here; past the budget its output is dropped,
            // which costs no more than reading the fragment.
            if too_large || len > *budget {
                too_large = true;
                return;
            }
            *budget -= len;
            let mut line = Vec::with_capacity(len);
            line.extend_from_slice(&name);
            line.extend_from_slice(b": ");
            line.extend_from_slice(&value);
            // A line is at least `: `, so it has a second byte.
            second_bytes.push(line[1]);
            lines.push(go_json_string(&line));
        })
        .map_err(|_| Error::HeaderDecode)?;
    if too_large {
        return Err(Error::HeadersTooLarge);
    }
    Ok((lines, second_bytes))
}

/// Bytes as Go's `encoding/json` shows them: every invalid UTF-8 byte becomes U+FFFD.
pub(crate) fn go_json_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(chunk.invalid().iter().map(|_| char::REPLACEMENT_CHARACTER));
    }
    out
}

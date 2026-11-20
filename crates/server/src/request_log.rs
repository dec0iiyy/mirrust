//! The request log: one compact JSON object per line for every routed request and every TLS
//! handshake that failed after its ClientHello was read.
//!
//! Connection tasks never wait on the file. They serialize the entry and hand it to a bounded
//! channel; one task owns the file and writes. When the channel is full the entry is dropped and
//! counted, and the writer reports the count on stderr.

use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::report::{Report, TlsDetails};

/// Entries that may wait for the writer before new ones are dropped.
const QUEUE_CAPACITY: usize = 4096;
/// Lines written between flushes when requests come faster than [`FLUSH_INTERVAL`].
const FLUSH_LINES: usize = 256;
/// The longest a written line waits in the buffer before it reaches the file.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// The sending side of the request log; cheap to clone, one per connection is fine.
#[derive(Debug, Clone)]
pub struct RequestLog {
    lines: mpsc::Sender<String>,
    dropped: Arc<AtomicU64>,
}

/// The task that owns the log file. Call [`LogWriter::finish`] on shutdown to flush it.
#[derive(Debug)]
pub struct LogWriter {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
    dropped: Arc<AtomicU64>,
}

impl RequestLog {
    /// Opens `path` for appending, creating it if needed, and starts the writer task on the
    /// current tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be opened.
    pub async fn open(path: &Path) -> io::Result<(Self, LogWriter)> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        let (lines, queue) = mpsc::channel(QUEUE_CAPACITY);
        let (stop, stopped) = oneshot::channel();
        let dropped = Arc::new(AtomicU64::new(0));
        let writer = Writer {
            path: path.to_owned(),
            out: BufWriter::new(file),
            dropped: Arc::clone(&dropped),
            reported: 0,
        };
        let task = tokio::spawn(writer.run(queue, stopped));
        let log = Self {
            lines,
            dropped: Arc::clone(&dropped),
        };
        Ok((
            log,
            LogWriter {
                stop,
                task,
                dropped,
            },
        ))
    }

    /// Queues the entry for `report`, or counts it as dropped when the queue is full or the
    /// writer has stopped.
    pub(crate) fn record(&self, report: &Report) {
        self.queue(entry(report, SystemTime::now()));
    }

    /// Queues the entry for a connection whose ClientHello was read but whose TLS handshake
    /// then failed with `error`: the fingerprints, empty request fields and `handshake_error`.
    pub(crate) fn record_failed_handshake(
        &self,
        peer: SocketAddr,
        tls: TlsDetails,
        error: &dyn Display,
    ) {
        let report = Report {
            ip: peer.to_string(),
            tls: Some(tls),
            ..Report::default()
        };
        self.queue(failed_handshake_entry(&report, error, SystemTime::now()));
    }

    fn queue(&self, entry: Map<String, Value>) {
        let mut line = Value::Object(entry).to_string();
        line.push('\n');
        if self.lines.try_send(line).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl LogWriter {
    /// Writes what is queued, flushes the file and stops the writer.
    ///
    /// Returns how many entries were dropped since the log was opened.
    pub async fn finish(self) -> u64 {
        // The writer may already have stopped on a write error, which it reported.
        let _ = self.stop.send(());
        if let Err(error) = self.task.await {
            eprintln!("request log writer failed: {error}");
        }
        self.dropped.load(Ordering::Relaxed)
    }
}

struct Writer {
    path: PathBuf,
    out: BufWriter<tokio::fs::File>,
    dropped: Arc<AtomicU64>,
    /// The drop count last printed, so each report says something new.
    reported: u64,
}

impl Writer {
    async fn run(mut self, queue: mpsc::Receiver<String>, stopped: oneshot::Receiver<()>) {
        if let Err(error) = self.write_until_stopped(queue, stopped).await {
            eprintln!(
                "request log {}: {error}; logging stopped",
                self.path.display()
            );
        }
        self.report_drops();
    }

    async fn write_until_stopped(
        &mut self,
        mut queue: mpsc::Receiver<String>,
        mut stopped: oneshot::Receiver<()>,
    ) -> io::Result<()> {
        let mut tick = tokio::time::interval(FLUSH_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut unflushed = 0;
        loop {
            tokio::select! {
                line = queue.recv() => {
                    let Some(line) = line else { break };
                    self.out.write_all(line.as_bytes()).await?;
                    unflushed += 1;
                    if unflushed >= FLUSH_LINES {
                        self.out.flush().await?;
                        unflushed = 0;
                    }
                }
                _ = tick.tick() => {
                    if unflushed > 0 {
                        self.out.flush().await?;
                        unflushed = 0;
                    }
                    self.report_drops();
                }
                _ = &mut stopped => {
                    queue.close();
                    while let Some(line) = queue.recv().await {
                        self.out.write_all(line.as_bytes()).await?;
                    }
                    break;
                }
            }
        }
        self.out.flush().await
    }

    fn report_drops(&mut self) {
        let dropped = self.dropped.load(Ordering::Relaxed);
        if dropped > self.reported {
            eprintln!(
                "request log {}: {dropped} entries dropped so far (queue full)",
                self.path.display()
            );
            self.reported = dropped;
        }
    }
}

/// The log entry: who asked for what, and the fingerprints. Client random, session id and
/// key shares are left out; they identify a connection, not a client.
fn entry(report: &Report, now: SystemTime) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("time".into(), rfc3339(now).into());
    fields.insert("ip".into(), report.ip.as_str().into());
    fields.insert("http_version".into(), report.http_version.as_str().into());
    fields.insert("method".into(), report.method.as_str().into());
    fields.insert("path".into(), report.path.as_str().into());
    fields.insert("user_agent".into(), report.user_agent.as_str().into());
    if let Some(tls) = &report.tls {
        let fingerprints = [
            ("ja3_hash", &tls.ja3_hash),
            ("ja4", &tls.ja4),
            ("ja4_r", &tls.ja4_r),
            ("ja4_peet", &tls.ja4_peet),
            ("peetprint_hash", &tls.peetprint_hash),
        ];
        for (key, value) in fingerprints {
            fields.insert(key.into(), value.as_str().into());
        }
    }
    if let Some(h2) = &report.http2 {
        let akamai = [
            ("akamai_fingerprint", &h2.akamai_fingerprint),
            ("akamai_fingerprint_hash", &h2.akamai_fingerprint_hash),
        ];
        for (key, value) in akamai {
            fields.insert(key.into(), value.as_str().into());
        }
    }
    fields
}

/// The entry for a handshake that failed: [`entry`] for a report without a request, so the
/// request fields are empty strings, followed by `handshake_error`, which no request entry has.
fn failed_handshake_entry(
    report: &Report,
    error: &dyn Display,
    now: SystemTime,
) -> Map<String, Value> {
    let mut fields = entry(report, now);
    fields.insert("handshake_error".into(), error.to_string().into());
    fields
}

/// `2024-02-29T12:34:56.789Z`: RFC 3339 in UTC with milliseconds. Times before 1970 print as
/// the epoch.
fn rfc3339(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since_epoch.as_secs();
    let (year, month, day) = civil_from_days(secs / 86_400);
    let (hour, minute, second) = (secs / 3600 % 24, secs / 60 % 60, secs % 60);
    let millis = since_epoch.subsec_millis();
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Year, month and day of the date `days` after 1970-01-01, by Howard Hinnant's
/// `civil_from_days` (proleptic Gregorian calendar).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // Months counted from March, so the leap day is the last day of the year.
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys of an entry with TLS details and no HTTP/2 details, in order.
    const REQUEST_KEYS: [&str; 11] = [
        "time",
        "ip",
        "http_version",
        "method",
        "path",
        "user_agent",
        "ja3_hash",
        "ja4",
        "ja4_r",
        "ja4_peet",
        "peetprint_hash",
    ];

    #[test]
    fn rfc3339_matches_known_instants() {
        let cases = [
            (0, 0, "1970-01-01T00:00:00.000Z"),
            (951_782_400, 0, "2000-02-29T00:00:00.000Z"),
            (1_700_000_000, 0, "2023-11-14T22:13:20.000Z"),
            (1_709_210_096, 789, "2024-02-29T12:34:56.789Z"),
            (4_102_444_799, 999, "2099-12-31T23:59:59.999Z"),
        ];
        for (secs, millis, want) in cases {
            let time = UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(millis);
            assert_eq!(rfc3339(time), want, "{secs}s + {millis}ms");
        }
    }

    #[test]
    fn entry_leaves_out_connection_secrets() {
        let report = Report {
            ip: "127.0.0.1:1".into(),
            http_version: "HTTP/1.1".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: Some(crate::report::TlsDetails {
                client_random: "aa".into(),
                session_id: "bb".into(),
                ..Default::default()
            }),
            ..Report::default()
        };
        let keys: Vec<String> = entry(&report, UNIX_EPOCH).keys().cloned().collect();
        assert_eq!(keys, REQUEST_KEYS);
    }

    /// A client's path may hold a newline and ESC; the JSON Lines file must still get one line
    /// per request, and the path must come back unchanged.
    #[test]
    fn a_path_with_a_newline_and_escape_stays_on_one_line() {
        let (lines, mut queue) = mpsc::channel(4);
        let log = RequestLog {
            lines,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let path = "/a\nb\x1b[31m\r\u{2028}";
        log.record(&Report {
            path: path.into(),
            method: "G\nT".into(),
            ..Report::default()
        });

        let line = queue.try_recv().expect("one queued line");
        assert!(line.ends_with('\n'));
        let body = line.trim_end_matches('\n');
        assert!(!body.contains(['\n', '\r', '\x1b']), "{body:?}");
        let parsed: Value = serde_json::from_str(body).expect("JSON line");
        assert_eq!(parsed["path"], path);
        assert_eq!(parsed["method"], "G\nT");
        assert!(queue.try_recv().is_err(), "exactly one line");
    }

    #[test]
    fn failed_handshake_entry_is_a_request_entry_with_empty_request_fields() {
        let report = Report {
            ip: "127.0.0.1:1".into(),
            tls: Some(crate::report::TlsDetails {
                ja3_hash: "cc".into(),
                ..Default::default()
            }),
            ..Report::default()
        };
        let entry = failed_handshake_entry(&report, &"peer hung up", UNIX_EPOCH);
        let keys: Vec<&str> = entry.keys().map(String::as_str).collect();
        let mut want = REQUEST_KEYS.to_vec();
        want.push("handshake_error");
        assert_eq!(keys, want);
        for key in ["http_version", "method", "path", "user_agent"] {
            assert_eq!(entry[key], "", "{key}");
        }
        assert_eq!(entry["ja3_hash"], "cc");
        assert_eq!(entry["handshake_error"], "peer hung up");
    }
}

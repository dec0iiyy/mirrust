//! Failed connections, counted by kind and reported as one summary line per interval.
//!
//! On the public internet scanners, port probes and half-open clients fail connections all day.
//! A line for each would run through a blocking `eprintln!` on a runtime thread, so
//! [`FailureLog`] only counts and prints a summary, the way [`crate::ConnectionLimit`] reports
//! refusals.

use std::error::Error;
use std::fmt::{self, Write as _};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::capture::NotTls;
use crate::error_chain::error_chain;
use crate::printable::printable;

/// Failures are summed up and printed on stderr this long after the first unreported one, so
/// a scan costs one line per interval, not one per connection.
const REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// Longest error text of the `other` kind a summary carries, in printed characters. Error
/// texts are short; the cap only bounds a line that holds text a client influenced.
const MAX_OTHER_TEXT: usize = 1024;

/// Why a connection failed, as far as the summary tells apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureKind {
    /// The first bytes were not a TLS ClientHello: a port scan, plain HTTP, garbage.
    NotTls,
    /// The connection's 15 seconds ran out, or QUIC's idle timeout.
    Timeout,
    /// The client closed or reset the connection before it finished.
    Eof,
    /// Anything else; the summary keeps the text of the last one.
    Other,
}

impl FailureKind {
    const ALL: [Self; 4] = [Self::NotTls, Self::Timeout, Self::Eof, Self::Other];

    fn label(self) -> &'static str {
        match self {
            Self::NotTls => "not TLS",
            Self::Timeout => "timeout",
            Self::Eof => "eof",
            Self::Other => "other",
        }
    }

    fn of_io(error: &io::Error) -> Self {
        use io::ErrorKind::{
            BrokenPipe, ConnectionAborted, ConnectionReset, TimedOut, UnexpectedEof,
        };
        match error.kind() {
            TimedOut => Self::Timeout,
            UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe => Self::Eof,
            _ if error
                .get_ref()
                .is_some_and(<dyn Error + Send + Sync>::is::<NotTls>) =>
            {
                Self::NotTls
            }
            _ => Self::Other,
        }
    }

    /// The first cause in the chain that is a timeout or an `io::Error` with a known kind.
    fn of_chain(error: &anyhow::Error) -> Self {
        error
            .chain()
            .map(Self::of_cause)
            .find(|kind| *kind != Self::Other)
            .unwrap_or(Self::Other)
    }

    fn of_cause(cause: &(dyn Error + 'static)) -> Self {
        if let Some(error) = cause.downcast_ref::<io::Error>() {
            Self::of_io(error)
        } else if matches!(
            cause.downcast_ref::<quinn::ConnectionError>(),
            Some(quinn::ConnectionError::TimedOut)
        ) || matches!(
            cause.downcast_ref::<h3::error::ConnectionError>(),
            Some(h3::error::ConnectionError::Timeout { .. })
        ) {
            Self::Timeout
        } else {
            Self::Other
        }
    }
}

/// Counts failed connections, TCP and QUIC alike, and prints a summary on stderr at most once
/// per 30 seconds while there are new failures.
///
/// Clones share the same counts, so give [`serve`](crate::serve) and
/// [`serve_h3`](crate::serve_h3) the same [`Config`](crate::Config) to get one summary line.
#[derive(Clone)]
pub struct FailureLog {
    inner: Arc<Inner>,
}

struct Inner {
    interval: Duration,
    /// Where a summary goes; stderr unless a test says otherwise.
    sink: Box<dyn Fn(&str) + Send + Sync>,
    /// Failures not yet reported, indexed like [`FailureKind::ALL`].
    counts: [AtomicU64; 4],
    /// The `peer: text` of the last `other` failure not yet reported.
    last_other: Mutex<Option<String>>,
    /// Whether a task is waiting to print the counts.
    reporting: AtomicBool,
}

impl FailureLog {
    /// A log that prints its summaries on stderr.
    #[must_use]
    pub fn new() -> Self {
        Self::with_sink(REPORT_INTERVAL, |line| eprintln!("{line}"))
    }

    pub(crate) fn with_sink(
        interval: Duration,
        sink: impl Fn(&str) + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                interval,
                sink: Box::new(sink),
                counts: Default::default(),
                last_other: Mutex::new(None),
                reporting: AtomicBool::new(false),
            }),
        }
    }

    /// Counts a TCP connection that failed with `error`.
    ///
    /// Must be called on a tokio runtime.
    pub(crate) fn record_io(&self, peer: SocketAddr, error: &io::Error) {
        self.record(FailureKind::of_io(error), peer, || error_chain(error));
    }

    /// Counts an HTTP/3 connection that failed with `error`.
    ///
    /// Must be called on a tokio runtime.
    pub(crate) fn record_h3(&self, peer: SocketAddr, error: &anyhow::Error) {
        self.record(FailureKind::of_chain(error), peer, || format!("{error:#}"));
    }

    /// Counts a connection that ran past its deadline.
    ///
    /// Must be called on a tokio runtime.
    pub(crate) fn record_timeout(&self, peer: SocketAddr) {
        self.record(FailureKind::Timeout, peer, String::new);
    }

    /// `text` is only built for the `other` kind, whose last text is kept.
    fn record(&self, kind: FailureKind, peer: SocketAddr, text: impl FnOnce() -> String) {
        if kind == FailureKind::Other {
            let text = printable(&text(), MAX_OTHER_TEXT);
            *self.inner.last_other.lock().expect("lock poisoned") = Some(format!("{peer}: {text}"));
        }
        self.inner.counts[kind as usize].fetch_add(1, Ordering::Relaxed);
        if self.inner.reporting.swap(true, Ordering::AcqRel) {
            return;
        }
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            tokio::time::sleep(inner.interval).await;
            // Cleared before the counts are taken: a failure that comes in between starts the
            // next report instead of being left uncounted.
            inner.reporting.store(false, Ordering::Release);
            if let Some(summary) = inner.take_summary() {
                (inner.sink)(&summary);
            }
        });
    }
}

impl Inner {
    /// The summary of the failures counted since the last call, which resets the counts;
    /// `None` when there are none.
    fn take_summary(&self) -> Option<String> {
        let counts =
            FailureKind::ALL.map(|kind| self.counts[kind as usize].swap(0, Ordering::AcqRel));
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return None;
        }
        let kinds: Vec<String> = FailureKind::ALL
            .iter()
            .zip(counts)
            .filter(|(_, count)| *count > 0)
            .map(|(kind, count)| format!("{count} {}", kind.label()))
            .collect();
        let mut summary = format!(
            "{total} connections failed in {} s: {}",
            self.interval.as_secs(),
            kinds.join(", ")
        );
        if counts[FailureKind::Other as usize] > 0
            && let Some(last) = self.last_other.lock().expect("lock poisoned").take()
        {
            write!(summary, "; last other: {last}").expect("writing to a String cannot fail");
        }
        Some(summary)
    }
}

impl Default for FailureLog {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FailureLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailureLog").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    const PEER: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9);

    fn collecting(interval: Duration) -> (FailureLog, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let log = FailureLog::with_sink(interval, move |line| {
            sink.lock().expect("lock poisoned").push(line.to_owned());
        });
        (log, lines)
    }

    async fn wait_for_lines(lines: &Mutex<Vec<String>>, count: usize) -> Vec<String> {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            let now = lines.lock().expect("lock poisoned").clone();
            if now.len() >= count {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("no {count} summary lines in 5 s");
    }

    #[test]
    fn kinds_follow_the_error() {
        let kind = |error: io::Error| FailureKind::of_io(&error);
        assert_eq!(kind(io::ErrorKind::TimedOut.into()), FailureKind::Timeout);
        assert_eq!(kind(io::ErrorKind::UnexpectedEof.into()), FailureKind::Eof);
        assert_eq!(
            kind(io::ErrorKind::ConnectionReset.into()),
            FailureKind::Eof
        );
        assert_eq!(
            kind(io::Error::new(io::ErrorKind::InvalidData, NotTls("x"))),
            FailureKind::NotTls
        );
        // A rustls failure is also `InvalidData`, but it is not "not TLS".
        assert_eq!(
            kind(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer is incompatible"
            )),
            FailureKind::Other
        );
    }

    #[test]
    fn h3_kinds_come_from_the_chain() {
        use anyhow::Context as _;
        let timed_out = Err::<(), _>(quinn::ConnectionError::TimedOut)
            .context("QUIC handshake")
            .expect_err("error");
        assert_eq!(FailureKind::of_chain(&timed_out), FailureKind::Timeout);
        let reset = Err::<(), _>(io::Error::from(io::ErrorKind::UnexpectedEof))
            .context("reading a request")
            .expect_err("error");
        assert_eq!(FailureKind::of_chain(&reset), FailureKind::Eof);
        assert_eq!(
            FailureKind::of_chain(&anyhow::anyhow!("something else")),
            FailureKind::Other
        );
    }

    #[tokio::test]
    async fn failures_are_summed_into_one_line_per_interval() {
        let (log, lines) = collecting(Duration::from_millis(50));
        for _ in 0..40 {
            log.record_io(PEER, &io::ErrorKind::UnexpectedEof.into());
        }
        log.record_timeout(PEER);
        log.record_io(
            PEER,
            &io::Error::new(io::ErrorKind::InvalidData, NotTls("x")),
        );
        log.record_io(PEER, &io::Error::other("first\nsecond"));
        log.record_io(PEER, &io::Error::other("bad certificate\x1b[31m"));

        let got = wait_for_lines(&lines, 1).await;
        assert_eq!(
            got,
            [
                r"44 connections failed in 0 s: 1 not TLS, 1 timeout, 40 eof, 2 other; last other: 127.0.0.1:9: bad certificate\u{1b}[31m"
            ]
        );

        // Nothing new, nothing printed; a later failure starts the next interval.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(lines.lock().expect("lock poisoned").len(), 1);
        log.record_timeout(PEER);
        let got = wait_for_lines(&lines, 2).await;
        assert_eq!(got[1], "1 connections failed in 0 s: 1 timeout");
    }

    #[test]
    fn the_summary_of_nothing_is_nothing() {
        let (log, _) = collecting(Duration::from_secs(30));
        assert_eq!(log.inner.take_summary(), None);
    }
}

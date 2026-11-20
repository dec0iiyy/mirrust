//! The cap on simultaneous connections, shared by the TCP and QUIC listeners.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How many connections may be open at once unless the caller picks another number. The
/// binary's usage text and the README state this value.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Refusals are summed up and printed on stderr this long after the first unreported one, so
/// a flood of connections costs one line per interval, not one per connection.
const REFUSAL_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Admits connections up to a fixed number at a time; TCP and QUIC connections count alike.
///
/// Clones share the same slots, so one limit can be given to every listener.
#[derive(Debug, Clone)]
pub struct ConnectionLimit {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    slots: Arc<Semaphore>,
    max: usize,
    /// Refusals not yet printed.
    refused: AtomicU64,
    /// Whether a task is waiting to print `refused`.
    reporting: AtomicBool,
}

impl ConnectionLimit {
    /// A limit of `max` simultaneous connections. Zero refuses every connection.
    ///
    /// Values above [`Semaphore::MAX_PERMITS`] are lowered to it.
    #[must_use]
    pub fn new(max: usize) -> Self {
        let max = max.min(Semaphore::MAX_PERMITS);
        Self {
            inner: Arc::new(Inner {
                slots: Arc::new(Semaphore::new(max)),
                max,
                refused: AtomicU64::new(0),
                reporting: AtomicBool::new(false),
            }),
        }
    }

    /// Takes a slot for one connection; the slot is free again when the permit is dropped.
    ///
    /// `None` means every slot is taken and the connection must be refused. The refusal is
    /// counted here and reported on stderr later; this must be called on a tokio runtime.
    pub(crate) fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        let admitted = Arc::clone(&self.inner.slots).try_acquire_owned().ok();
        if admitted.is_none() {
            self.count_refusal();
        }
        admitted
    }

    fn count_refusal(&self) {
        self.inner.refused.fetch_add(1, Ordering::Relaxed);
        if self.inner.reporting.swap(true, Ordering::AcqRel) {
            return;
        }
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            tokio::time::sleep(REFUSAL_REPORT_INTERVAL).await;
            // Cleared before the count is taken: a refusal that comes in between starts the
            // next report instead of being left uncounted.
            inner.reporting.store(false, Ordering::Release);
            let refused = inner.refused.swap(0, Ordering::AcqRel);
            if refused > 0 {
                eprintln!(
                    "{refused} connections refused: the limit of {} simultaneous connections was reached",
                    inner.max
                );
            }
        });
    }
}

impl Default for ConnectionLimit {
    /// A limit of 1024 connections.
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONNECTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_slot_is_free_again_when_its_permit_is_dropped() {
        let limit = ConnectionLimit::new(2);
        let first = limit.try_admit().expect("first slot");
        let _second = limit.clone().try_admit().expect("clones share the slots");
        assert!(limit.try_admit().is_none(), "both slots are taken");
        assert_eq!(limit.inner.refused.load(Ordering::Relaxed), 1);

        drop(first);
        assert!(limit.try_admit().is_some(), "the dropped slot is free");
    }
}

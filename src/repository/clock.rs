//! Virtualizable clock for repositories and schedulers.
//!
//! Production code uses [`SystemClock`]; tests (and later the renewal
//! controller's virtual-clock scenarios, roadmap T09) use [`FakeClock`].

use std::sync::{Arc, Mutex};

use jiff::Timestamp;

/// Source of "now".
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Timestamp;
}

/// Real system time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// Manually advanced clock for tests.
#[derive(Debug, Clone, Default)]
pub struct FakeClock {
    inner: Arc<Mutex<Option<Timestamp>>>,
}

impl FakeClock {
    /// A fake clock starting at the given instant.
    pub fn at(start: Timestamp) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(start))),
        }
    }

    /// Advances the clock by whole seconds.
    pub fn advance_secs(&self, secs: i64) {
        let mut guard = self.inner.lock().expect("fake clock poisoned");
        let base = guard.unwrap_or_else(Timestamp::now);
        *guard = Some(
            base.checked_add(jiff::Span::new().seconds(secs))
                .expect("overflow"),
        );
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        let guard = self.inner.lock().expect("fake clock poisoned");
        guard.unwrap_or_else(Timestamp::now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn fake_clock_advances() {
        let clock = FakeClock::at(Timestamp::from_str("2026-01-01T00:00:00Z").unwrap());
        assert_eq!(clock.now().to_string(), "2026-01-01T00:00:00Z");
        clock.advance_secs(90);
        assert_eq!(clock.now().to_string(), "2026-01-01T00:01:30Z");
    }
}

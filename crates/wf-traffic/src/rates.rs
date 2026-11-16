//! Turning counter samples into rates (pure, unit-tested).

use crate::types::*;

/// A single-sample jump larger than this is treated as a counter glitch
/// (driver reset to a random value), not as traffic: 1 TiB in one sample.
const MAX_PLAUSIBLE_DELTA: u64 = 1 << 40;

/// Tracks one pair of monotonically growing counters.
#[derive(Clone, Debug, Default)]
pub struct RateTracker {
    last: Option<(f64, u64, u64)>,
}

impl RateTracker {
    /// Feeds a sample taken at `seconds` (any monotonic clock). Returns the
    /// rate since the previous sample and the bytes added since then. A
    /// counter that went backwards (adapter reset) counts as zero.
    pub fn update(&mut self, seconds: f64, rx: u64, tx: u64) -> (Rate, Totals) {
        let Some((last_t, last_rx, last_tx)) = self.last else {
            self.last = Some((seconds, rx, tx));
            return (Rate::default(), Totals::default());
        };
        let added = Totals {
            rx: delta(last_rx, rx),
            tx: delta(last_tx, tx),
        };
        let dt = seconds - last_t;
        if !dt.is_finite() || dt <= 0.0 {
            // The clock did not advance (or is broken): the bytes are real,
            // but no rate can be derived from them. Keep the old time stamp
            // when the new one is unusable so the next sample still works.
            let t = if seconds.is_finite() { seconds } else { last_t };
            self.last = Some((t, rx, tx));
            return (Rate::default(), added);
        }
        self.last = Some((seconds, rx, tx));
        let rate = Rate {
            down: added.rx as f64 / dt,
            up: added.tx as f64 / dt,
        };
        (rate, added)
    }

    /// Forgets the previous sample (the next one starts a new baseline).
    pub fn reset(&mut self) {
        self.last = None;
    }
}

fn delta(old: u64, new: u64) -> u64 {
    match new.checked_sub(old) {
        Some(d) if d <= MAX_PLAUSIBLE_DELTA => d,
        // Went backwards (reset / wrap) or jumped implausibly: new baseline.
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_is_a_baseline() {
        let mut t = RateTracker::default();
        let (r, d) = t.update(10.0, 5_000_000, 1_000_000);
        assert_eq!(r, Rate::default());
        assert_eq!(d, Totals::default());
    }

    #[test]
    fn steady_rate() {
        let mut t = RateTracker::default();
        t.update(0.0, 1000, 500);
        let (r, d) = t.update(1.0, 3000, 1500);
        assert_eq!(d, Totals { rx: 2000, tx: 1000 });
        assert_eq!(r.down, 2000.0);
        assert_eq!(r.up, 1000.0);
        let (r, d) = t.update(3.0, 4000, 1500);
        assert_eq!(d, Totals { rx: 1000, tx: 0 });
        assert_eq!(r.down, 500.0);
        assert_eq!(r.up, 0.0);
    }

    #[test]
    fn zero_and_negative_dt_give_no_rate_but_keep_bytes() {
        let mut t = RateTracker::default();
        t.update(5.0, 100, 100);
        let (r, d) = t.update(5.0, 300, 150);
        assert_eq!(r, Rate::default());
        assert_eq!(d, Totals { rx: 200, tx: 50 });
        let (r, d) = t.update(4.0, 400, 150);
        assert_eq!(r, Rate::default());
        assert_eq!(d, Totals { rx: 100, tx: 0 });
        // Works again once the clock advances from the new time stamp.
        let (r, d) = t.update(6.0, 600, 350);
        assert_eq!(d, Totals { rx: 200, tx: 200 });
        assert_eq!(r.down, 100.0);
        assert_eq!(r.up, 100.0);
    }

    #[test]
    fn nan_time_is_ignored() {
        let mut t = RateTracker::default();
        t.update(1.0, 0, 0);
        let (r, d) = t.update(f64::NAN, 10, 10);
        assert_eq!(r, Rate::default());
        assert_eq!(d, Totals { rx: 10, tx: 10 });
        let (r, _) = t.update(2.0, 20, 10);
        assert_eq!(r.down, 10.0);
    }

    #[test]
    fn counter_reset_counts_as_zero_then_recovers() {
        let mut t = RateTracker::default();
        t.update(0.0, 9_000_000, 9_000_000);
        let (r, d) = t.update(1.0, 1_000, 9_000_500);
        assert_eq!(d, Totals { rx: 0, tx: 500 });
        assert_eq!(r.down, 0.0);
        assert_eq!(r.up, 500.0);
        let (_, d) = t.update(2.0, 3_000, 9_000_500);
        assert_eq!(d, Totals { rx: 2_000, tx: 0 });
    }

    #[test]
    fn wrap_of_a_32_bit_counter_is_not_a_huge_spike() {
        let mut t = RateTracker::default();
        t.update(0.0, u32::MAX as u64 - 10, 0);
        let (r, d) = t.update(1.0, 20, 0);
        assert_eq!(d.rx, 0);
        assert_eq!(r.down, 0.0);
    }

    #[test]
    fn implausible_jump_is_dropped() {
        let mut t = RateTracker::default();
        t.update(0.0, 0, 0);
        let (r, d) = t.update(1.0, u64::MAX / 2, 100);
        assert_eq!(d, Totals { rx: 0, tx: 100 });
        assert_eq!(r.down, 0.0);
    }

    #[test]
    fn reset_starts_over() {
        let mut t = RateTracker::default();
        t.update(0.0, 100, 100);
        t.reset();
        let (r, d) = t.update(1.0, 900, 900);
        assert_eq!(r, Rate::default());
        assert_eq!(d, Totals::default());
    }
}

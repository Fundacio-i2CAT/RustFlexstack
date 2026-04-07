//! ITS time utilities.
//!
//! The ITS epoch is 2004-01-01 00:00:00 UTC (TAI), which corresponds to
//! Unix timestamp 1072915200.  A leap-second offset of 5 s is added to
//! convert from UTC to TAI.

use std::time::{SystemTime, UNIX_EPOCH};

/// Unix timestamp of the ITS epoch (2004-01-01T00:00:00 UTC).
const ITS_EPOCH: u64 = 1_072_915_200;

/// Leap-second offset UTC → TAI at the ITS epoch.
const ELAPSED_SECONDS: u64 = 5;

/// Return the current UTC timestamp in seconds (as `f64`).
pub fn unix_time_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs_f64()
}

/// Return the current ITS timestamp in **microseconds** (TAI, ITS epoch).
///
/// This matches the `Time64` type used in `generationTime` fields inside
/// IEEE 1609.2 headers.
pub fn timestamp_its_microseconds() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch");
    let its_secs = now.as_secs() - ITS_EPOCH + ELAPSED_SECONDS;
    its_secs * 1_000_000 + u64::from(now.subsec_micros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_time_secs_positive() {
        let t = unix_time_secs();
        // Should be well past the ITS epoch
        assert!(t > ITS_EPOCH as f64);
    }

    #[test]
    fn timestamp_its_microseconds_positive() {
        let t = timestamp_its_microseconds();
        assert!(t > 0);
    }

    #[test]
    fn timestamp_its_microseconds_monotonic() {
        let t1 = timestamp_its_microseconds();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let t2 = timestamp_its_microseconds();
        assert!(t2 > t1);
    }

    #[test]
    fn its_epoch_constant() {
        assert_eq!(ITS_EPOCH, 1_072_915_200);
    }

    #[test]
    fn elapsed_seconds_constant() {
        assert_eq!(ELAPSED_SECONDS, 5);
    }
}

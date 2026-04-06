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

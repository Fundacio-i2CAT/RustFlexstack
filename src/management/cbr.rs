// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Channel Busy Ratio (CBR) sources for the DCC entity.
//!
//! The DCC algorithms of ETSI TS 102 687 V1.2.1 (2018-04) are access-technology
//! independent, but the CBR they consume is measured by the access layer
//! (clause 5.2). This module decouples the two through the [`CbrProvider`]
//! trait, which the [`DccEntity`](super::DccEntity) polls once per evaluation.
//!
//! Provided implementations:
//! - [`SharedCbr`]: a thread-safe cell for access layers that *push* CBR
//!   measurements (e.g. a radio SDK callback or an external process).
//! - [`Nl80211SurveyCbr`]: derives CBR on Linux IEEE 802.11p (ITS-G5) interfaces
//!   from the nl80211 channel survey counters (`iw dev <iface> survey dump`).
//!
//! Mirrors `flexstack/management/cbr.py`.

use std::process::Command;
use std::sync::{Arc, Mutex};

/// A source of Channel Busy Ratio measurements.
///
/// Implementations return the most recent CBR in `[0.0, 1.0]`, or `None` when
/// no (new) measurement is available. The DCC entity keeps its previous output
/// when `None` is returned.
pub trait CbrProvider: Send {
    /// Return the current CBR measurement, if any.
    fn measure_cbr(&mut self) -> Option<f64>;
}

/// Thread-safe CBR cell for push-based access layers.
///
/// Clones share the same underlying value: the access layer keeps one clone
/// and calls [`report`](Self::report); the DCC entity owns another clone as
/// its [`CbrProvider`]. The latest reported value is returned on every poll.
#[derive(Debug, Clone, Default)]
pub struct SharedCbr {
    latest: Arc<Mutex<Option<f64>>>,
}

impl SharedCbr {
    /// Create an empty cell (no measurement yet).
    pub fn new() -> Self {
        Self::default()
    }

    /// Report a new CBR measurement. Values outside `[0.0, 1.0]` (or NaN) are ignored.
    pub fn report(&self, cbr: f64) {
        if !(0.0..=1.0).contains(&cbr) {
            return;
        }
        if let Ok(mut v) = self.latest.lock() {
            *v = Some(cbr);
        }
    }

    /// Latest reported CBR, if any.
    pub fn latest(&self) -> Option<f64> {
        self.latest.lock().ok().and_then(|v| *v)
    }
}

impl CbrProvider for SharedCbr {
    fn measure_cbr(&mut self) -> Option<f64> {
        self.latest()
    }
}

/// Cumulative channel-time counters of the in-use channel, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurveySample {
    /// `channel active time` (time the radio was on the channel).
    pub active_ms: u64,
    /// `channel busy time` (time the channel was sensed busy, own TX included).
    pub busy_ms: u64,
}

/// Parse the output of `iw dev <iface> survey dump` and return the counters of
/// the channel marked `[in use]`.
///
/// Returns `None` if no in-use channel with both counters is present (some
/// drivers do not report survey data).
pub fn parse_survey_dump(text: &str) -> Option<SurveySample> {
    let mut in_use = false;
    let mut active = None;
    let mut busy = None;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("Survey data from") {
            if in_use {
                break;
            }
            active = None;
            busy = None;
            continue;
        }
        if line.starts_with("frequency:") {
            if in_use {
                break; // next channel block of the same dump
            }
            in_use = line.contains("[in use]");
            continue;
        }
        if !in_use {
            continue;
        }
        if let Some(v) = line.strip_prefix("channel active time:") {
            active = parse_ms(v);
        } else if let Some(v) = line.strip_prefix("channel busy time:") {
            busy = parse_ms(v);
        }
    }

    match (in_use, active, busy) {
        (true, Some(active_ms), Some(busy_ms)) => Some(SurveySample { active_ms, busy_ms }),
        _ => None,
    }
}

fn parse_ms(v: &str) -> Option<u64> {
    v.trim().trim_end_matches("ms").trim().parse().ok()
}

/// CBR between two consecutive survey samples: `Δbusy / Δactive`, clamped to `[0, 1]`.
///
/// Returns `None` if the active-time counter did not advance (or was reset).
pub fn cbr_from_samples(previous: SurveySample, current: SurveySample) -> Option<f64> {
    if current.active_ms <= previous.active_ms || current.busy_ms < previous.busy_ms {
        return None;
    }
    let d_active = (current.active_ms - previous.active_ms) as f64;
    let d_busy = (current.busy_ms - previous.busy_ms) as f64;
    Some((d_busy / d_active).clamp(0.0, 1.0))
}

/// CBR provider for Linux IEEE 802.11p (ITS-G5) interfaces based on nl80211
/// channel survey counters, as exposed by e.g. the `ath9k` driver.
///
/// Each poll runs `iw dev <iface> survey dump` and returns the busy fraction of
/// the in-use channel since the previous poll, so the measurement window equals
/// the DCC evaluation period. The first poll only records a reference sample and
/// returns `None`.
///
/// **Approximation**: the driver's busy time is based on the radio's CCA
/// threshold, not the −85 dBm threshold that ETSI TS 102 687 §5.2 (via ETSI
/// TS 102 917) uses to define CBR. The `iw` binary must be installed.
#[derive(Debug, Clone)]
pub struct Nl80211SurveyCbr {
    iface: String,
    previous: Option<SurveySample>,
}

impl Nl80211SurveyCbr {
    /// Create a provider for the given wireless interface (e.g. `"wlan0"`).
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            previous: None,
        }
    }

    /// Interface name this provider reads from.
    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// Feed one survey sample and return the CBR since the previous one.
    ///
    /// Exposed so the delta logic can be driven without running `iw`.
    pub fn ingest(&mut self, sample: SurveySample) -> Option<f64> {
        let cbr = self
            .previous
            .and_then(|prev| cbr_from_samples(prev, sample));
        self.previous = Some(sample);
        cbr
    }

    fn read_survey(&self) -> Option<SurveySample> {
        let out = Command::new("iw")
            .args(["dev", &self.iface, "survey", "dump"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_survey_dump(&String::from_utf8_lossy(&out.stdout))
    }
}

impl CbrProvider for Nl80211SurveyCbr {
    fn measure_cbr(&mut self) -> Option<f64> {
        let sample = self.read_survey()?;
        self.ingest(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "Survey data from wlan0\n\
        \tfrequency:\t\t\t5880 MHz\n\
        \tnoise:\t\t\t\t-95 dBm\n\
        \tchannel active time:\t\t999 ms\n\
        \tchannel busy time:\t\t111 ms\n\
        Survey data from wlan0\n\
        \tfrequency:\t\t\t5900 MHz [in use]\n\
        \tnoise:\t\t\t\t-92 dBm\n\
        \tchannel active time:\t\t20000 ms\n\
        \tchannel busy time:\t\t5000 ms\n\
        \tchannel receive time:\t\t4000 ms\n\
        \tchannel transmit time:\t\t500 ms\n\
        Survey data from wlan0\n\
        \tfrequency:\t\t\t5910 MHz\n\
        \tchannel active time:\t\t7 ms\n\
        \tchannel busy time:\t\t7 ms\n";

    #[test]
    fn test_shared_cbr_empty_then_reported() {
        let cell = SharedCbr::new();
        let mut provider = cell.clone();
        assert_eq!(provider.measure_cbr(), None);
        cell.report(0.42);
        assert_eq!(provider.measure_cbr(), Some(0.42));
        // Latest value is returned on every poll.
        assert_eq!(provider.measure_cbr(), Some(0.42));
    }

    #[test]
    fn test_shared_cbr_ignores_invalid_values() {
        let cell = SharedCbr::new();
        cell.report(0.3);
        cell.report(1.5);
        cell.report(-0.1);
        cell.report(f64::NAN);
        assert_eq!(cell.latest(), Some(0.3));
    }

    #[test]
    fn test_parse_survey_dump_selects_in_use_channel() {
        let s = parse_survey_dump(DUMP).unwrap();
        assert_eq!(
            s,
            SurveySample {
                active_ms: 20000,
                busy_ms: 5000
            }
        );
    }

    #[test]
    fn test_parse_survey_dump_without_in_use_channel() {
        let text = "Survey data from wlan0\n\tfrequency:\t5880 MHz\n\tchannel active time:\t10 ms\n\tchannel busy time:\t1 ms\n";
        assert_eq!(parse_survey_dump(text), None);
        assert_eq!(parse_survey_dump(""), None);
    }

    #[test]
    fn test_parse_survey_dump_missing_busy_counter() {
        let text = "Survey data from wlan0\n\tfrequency:\t5900 MHz [in use]\n\tchannel active time:\t10 ms\n";
        assert_eq!(parse_survey_dump(text), None);
    }

    #[test]
    fn test_cbr_from_samples() {
        let a = SurveySample {
            active_ms: 1000,
            busy_ms: 100,
        };
        let b = SurveySample {
            active_ms: 1200,
            busy_ms: 160,
        };
        let cbr = cbr_from_samples(a, b).unwrap();
        assert!((cbr - 0.3).abs() < 1e-12);
    }

    #[test]
    fn test_cbr_from_samples_rejects_stalled_or_reset_counters() {
        let a = SurveySample {
            active_ms: 1000,
            busy_ms: 100,
        };
        assert_eq!(cbr_from_samples(a, a), None);
        let reset = SurveySample {
            active_ms: 10,
            busy_ms: 1,
        };
        assert_eq!(cbr_from_samples(a, reset), None);
    }

    #[test]
    fn test_cbr_from_samples_clamps_to_one() {
        let a = SurveySample {
            active_ms: 1000,
            busy_ms: 100,
        };
        let b = SurveySample {
            active_ms: 1100,
            busy_ms: 300,
        };
        assert_eq!(cbr_from_samples(a, b), Some(1.0));
    }

    #[test]
    fn test_nl80211_ingest_first_sample_is_reference() {
        let mut p = Nl80211SurveyCbr::new("wlan0");
        assert_eq!(p.iface(), "wlan0");
        assert_eq!(
            p.ingest(SurveySample {
                active_ms: 0,
                busy_ms: 0
            }),
            None
        );
        let cbr = p
            .ingest(SurveySample {
                active_ms: 200,
                busy_ms: 50,
            })
            .unwrap();
        assert!((cbr - 0.25).abs() < 1e-12);
        let cbr = p
            .ingest(SurveySample {
                active_ms: 400,
                busy_ms: 150,
            })
            .unwrap();
        assert!((cbr - 0.5).abs() < 1e-12);
    }
}

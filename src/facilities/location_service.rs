// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Location Service — GPS fix publisher.
//!
//! Mirrors `FlexStack/src/flexstack/utils/location_service.py`.
//!
//! [`LocationService`] acts as a fan-out hub: a GPS driver (GPSD thread,
//! simulated sensor, hardware UART, …) calls [`LocationService::publish`]
//! whenever a new fix arrives.  Any number of subscribers may listen by
//! calling [`LocationService::subscribe`], which returns a
//! `Receiver<GpsFix>` that delivers every subsequent fix.  Dead receivers
//! (subscriber dropped) are pruned automatically on the next publish.
//!
//! # Example
//! ```no_run
//! use rustflexstack::facilities::location_service::{LocationService, GpsFix};
//! use std::thread;
//! use std::time::Duration;
//!
//! let mut svc = LocationService::new();
//! let rx = svc.subscribe();
//!
//! // Simulate a GPS driver publishing fixes at 1 Hz
//! thread::spawn(move || loop {
//!     thread::sleep(Duration::from_secs(1));
//!     svc.publish(GpsFix {
//!         latitude:    41.552,
//!         longitude:   2.134,
//!         altitude_m:  120.0,
//!         speed_mps:   0.0,
//!         heading_deg: 0.0,
//!         pai:         true,
//!     });
//! });
//!
//! while let Ok(fix) = rx.recv() {
//!     println!("lat={} lon={}", fix.latitude, fix.longitude);
//! }
//! ```

use std::sync::mpsc::{self, Receiver, Sender};

/// A single GPS position fix with the fields needed by the CA Basic Service
/// and GeoNetworking position vector.
///
/// Field units match ETSI EN 302 636-4-1 and EN 302 637-2:
///
/// | Field | Unit |
/// |---|---|
/// | `latitude` / `longitude` | decimal degrees (WGS-84) |
/// | `altitude_m` | metres above WGS-84 ellipsoid |
/// | `speed_mps` | metres per second |
/// | `heading_deg` | degrees clockwise from North (0–360) |
/// | `pai` | Position Accuracy Indicator flag |
#[derive(Debug, Clone, Copy)]
pub struct GpsFix {
    /// WGS-84 latitude in decimal degrees (positive = North).
    pub latitude: f64,
    /// WGS-84 longitude in decimal degrees (positive = East).
    pub longitude: f64,
    /// Altitude above the WGS-84 ellipsoid in metres.
    pub altitude_m: f64,
    /// Ground speed in m/s.
    pub speed_mps: f64,
    /// Track / heading in decimal degrees (0 = North, clockwise).
    pub heading_deg: f64,
    /// Position Accuracy Indicator — `true` when the position fix is
    /// considered accurate (≤ 4 m, ETSI EN 302 636-4-1 §9.2.2.2).
    pub pai: bool,
}

impl Default for GpsFix {
    fn default() -> Self {
        GpsFix {
            latitude: 0.0,
            longitude: 0.0,
            altitude_m: 0.0,
            speed_mps: 0.0,
            heading_deg: 0.0,
            pai: false,
        }
    }
}

/// Fan-out GPS fix publisher.
///
/// Call [`subscribe`](LocationService::subscribe) to obtain a
/// `Receiver<GpsFix>`.  Call [`publish`](LocationService::publish) from the
/// GPS driver thread to deliver the fix to every active subscriber.
pub struct LocationService {
    /// One sender per active subscriber.  Entries whose receivers have been
    /// dropped are pruned lazily inside [`publish`].
    senders: Vec<Sender<GpsFix>>,
}

impl LocationService {
    /// Create a new, empty `LocationService` with no subscribers.
    pub fn new() -> Self {
        LocationService {
            senders: Vec::new(),
        }
    }

    /// Register a new subscriber.
    ///
    /// Returns a `Receiver<GpsFix>` that will receive every fix published
    /// after this call.  When the receiver is dropped the corresponding
    /// internal sender is pruned on the next [`publish`] call.
    pub fn subscribe(&mut self) -> Receiver<GpsFix> {
        let (tx, rx) = mpsc::channel();
        self.senders.push(tx);
        rx
    }

    /// Publish `fix` to every active subscriber.
    ///
    /// Subscribers whose `Receiver` has been dropped are silently removed.
    pub fn publish(&mut self, fix: GpsFix) {
        // `retain` sends and keeps only the senders that are still connected.
        self.senders.retain(|tx| tx.send(fix).is_ok());
    }

    /// Return the number of active (non-dropped) subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.senders.len()
    }
}

impl Default for LocationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_no_subscribers() {
        let svc = LocationService::new();
        assert_eq!(svc.subscriber_count(), 0);
    }

    #[test]
    fn default_same_as_new() {
        let svc = LocationService::default();
        assert_eq!(svc.subscriber_count(), 0);
    }

    #[test]
    fn subscribe_increases_count() {
        let mut svc = LocationService::new();
        let _rx1 = svc.subscribe();
        assert_eq!(svc.subscriber_count(), 1);
        let _rx2 = svc.subscribe();
        assert_eq!(svc.subscriber_count(), 2);
    }

    #[test]
    fn publish_delivers_to_subscribers() {
        let mut svc = LocationService::new();
        let rx = svc.subscribe();
        let fix = GpsFix {
            latitude: 41.552,
            longitude: 2.134,
            altitude_m: 120.0,
            speed_mps: 10.0,
            heading_deg: 90.0,
            pai: true,
        };
        svc.publish(fix);
        let received = rx.recv().unwrap();
        assert!((received.latitude - 41.552).abs() < 1e-6);
        assert!((received.longitude - 2.134).abs() < 1e-6);
        assert!(received.pai);
    }

    #[test]
    fn publish_to_multiple_subscribers() {
        let mut svc = LocationService::new();
        let rx1 = svc.subscribe();
        let rx2 = svc.subscribe();
        let fix = GpsFix::default();
        svc.publish(fix);
        assert!(rx1.recv().is_ok());
        assert!(rx2.recv().is_ok());
    }

    #[test]
    fn dead_receiver_pruned_on_publish() {
        let mut svc = LocationService::new();
        let rx = svc.subscribe();
        assert_eq!(svc.subscriber_count(), 1);
        drop(rx);
        svc.publish(GpsFix::default());
        assert_eq!(svc.subscriber_count(), 0);
    }

    #[test]
    fn gps_fix_default() {
        let fix = GpsFix::default();
        assert_eq!(fix.latitude, 0.0);
        assert_eq!(fix.longitude, 0.0);
        assert_eq!(fix.speed_mps, 0.0);
        assert!(!fix.pai);
    }
}

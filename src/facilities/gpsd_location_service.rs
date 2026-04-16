// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! GPSD-backed Location Service.
//!
//! [`GpsdLocationService`] connects to a running
//! [gpsd](https://gpsd.io/) daemon over its JSON TCP protocol and publishes
//! real GPS fixes to every subscriber, exactly like
//! [`super::location_service::LocationService`] but sourcing data from a
//! real GNSS receiver instead of software-injected fixes.
//!
//! # Usage
//!
//! ```no_run
//! use rustflexstack::facilities::gpsd_location_service::GpsdLocationService;
//!
//! let mut svc = GpsdLocationService::new("127.0.0.1:2947");
//! let rx = svc.subscribe();
//!
//! svc.start();  // spawns background thread
//!
//! while let Ok(fix) = rx.recv() {
//!     println!("lat={:.6} lon={:.6} speed={:.1} m/s",
//!              fix.latitude, fix.longitude, fix.speed_mps);
//! }
//! ```
//!
//! # gpsd JSON protocol (subset used)
//!
//! After connecting we send `?WATCH={"enable":true,"json":true}\n` and then
//! read newline-delimited JSON objects.  We only care about objects whose
//! `"class"` field is `"TPV"` (Time-Position-Velocity).

use super::location_service::{GpsFix, LocationService};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::Duration;

/// A location service that reads real positions from a gpsd daemon.
///
/// Internally it wraps a [`LocationService`] and adds a background thread
/// that connects to gpsd, parses TPV sentences, and calls
/// [`LocationService::publish`] for each valid fix.
pub struct GpsdLocationService {
    inner: LocationService,
    addr: String,
}

impl GpsdLocationService {
    /// Create a new `GpsdLocationService` targeting the given gpsd address.
    ///
    /// The address is typically `"127.0.0.1:2947"` or `"localhost:2947"`.
    /// No connection is made until [`start`](Self::start) is called.
    pub fn new(addr: &str) -> Self {
        GpsdLocationService {
            inner: LocationService::new(),
            addr: addr.to_string(),
        }
    }

    /// Register a new subscriber (delegates to [`LocationService::subscribe`]).
    pub fn subscribe(&mut self) -> Receiver<GpsFix> {
        self.inner.subscribe()
    }

    /// Return the number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.inner.subscriber_count()
    }

    /// Start the gpsd reader thread.
    ///
    /// This **consumes** `self` because the inner `LocationService` (which
    /// owns the `Sender` halves) must be moved into the background thread.
    /// Subscribers obtained before this call remain valid.
    ///
    /// The thread reconnects automatically if the connection to gpsd drops.
    pub fn start(self) {
        let addr = self.addr;
        let mut inner = self.inner;

        thread::spawn(move || {
            loop {
                eprintln!("[GPSD] Connecting to {} ...", addr);

                match connect_and_watch(&addr) {
                    Ok(reader) => {
                        eprintln!("[GPSD] Connected — reading TPV fixes");
                        for line in reader.lines() {
                            match line {
                                Ok(line) => {
                                    if let Some(fix) = parse_tpv(&line) {
                                        inner.publish(fix);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[GPSD] Read error: {} — reconnecting", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[GPSD] Connection failed: {}", e);
                    }
                }

                // Back-off before reconnecting
                thread::sleep(Duration::from_secs(2));
            }
        });
    }
}

/// Open a TCP connection to gpsd and send the WATCH command.
///
/// Returns a `BufReader` over the stream ready for line-by-line reading.
fn connect_and_watch(addr: &str) -> Result<BufReader<TcpStream>, std::io::Error> {
    let sock_addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad address"))?;

    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5))?;

    // gpsd expects the WATCH command to start streaming
    stream.write_all(b"?WATCH={\"enable\":true,\"json\":true}\n")?;
    stream.flush()?;

    // Set a read timeout so we can detect a dead connection
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    Ok(BufReader::new(stream))
}

/// Try to parse a gpsd JSON line as a TPV object.
///
/// Returns `Some(GpsFix)` if the line is a valid TPV with at least lat/lon,
/// otherwise `None`.
///
/// We do minimal JSON parsing with string matching to avoid pulling in
/// serde_json as a dependency.  The TPV object has a well-known, stable
/// format:
///
/// ```json
/// {"class":"TPV","mode":3,"lat":41.552,"lon":2.134,"alt":120.0,
///  "speed":0.0,"track":0.0,"epx":15.0,"epy":15.0,...}
/// ```
fn parse_tpv(line: &str) -> Option<GpsFix> {
    // Quick reject: must be a TPV class
    if !line.contains("\"class\":\"TPV\"") {
        return None;
    }

    // mode >= 2 means at least a 2D fix
    let mode = extract_f64(line, "mode").unwrap_or(0.0) as u8;
    if mode < 2 {
        return None;
    }

    let lat = extract_f64(line, "lat")?;
    let lon = extract_f64(line, "lon")?;
    let alt = extract_f64(line, "alt").unwrap_or(0.0);
    // gpsd uses "speed" in m/s and "track" in degrees
    let speed = extract_f64(line, "speed").unwrap_or(0.0);
    let track = extract_f64(line, "track").unwrap_or(0.0);

    // PAI: consider the fix accurate if EPX and EPY are both ≤ 4 m
    let epx = extract_f64(line, "epx").unwrap_or(f64::MAX);
    let epy = extract_f64(line, "epy").unwrap_or(f64::MAX);
    let pai = epx <= 4.0 && epy <= 4.0;

    Some(GpsFix {
        latitude: lat,
        longitude: lon,
        altitude_m: alt,
        speed_mps: speed,
        heading_deg: track,
        pai,
    })
}

/// Extract a numeric value for `"key":value` from a JSON line.
///
/// This is intentionally simple — it handles the subset of gpsd TPV output
/// where values are bare numbers (no quoting, no nesting).
fn extract_f64(json: &str, key: &str) -> Option<f64> {
    // Build the search pattern: "key":
    let pattern = format!("\"{}\":", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];

    // Skip optional whitespace
    let rest = rest.trim_start();

    // Find the end of the number: next comma, closing brace, or end of string
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace())
        .unwrap_or(rest.len());

    let num_str = &rest[..end];
    num_str.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tpv_valid_3d_fix() {
        let line = r#"{"class":"TPV","mode":3,"time":"2024-01-01T00:00:00.000Z","lat":41.552000,"lon":2.134000,"alt":120.5,"speed":10.2,"track":90.0,"epx":2.0,"epy":1.5}"#;
        let fix = parse_tpv(line).unwrap();
        assert!((fix.latitude - 41.552).abs() < 1e-6);
        assert!((fix.longitude - 2.134).abs() < 1e-6);
        assert!((fix.altitude_m - 120.5).abs() < 1e-1);
        assert!((fix.speed_mps - 10.2).abs() < 1e-1);
        assert!((fix.heading_deg - 90.0).abs() < 1e-1);
        assert!(fix.pai);
    }

    #[test]
    fn parse_tpv_2d_fix_no_alt() {
        let line = r#"{"class":"TPV","mode":2,"lat":41.0,"lon":2.0,"speed":5.0,"track":180.0}"#;
        let fix = parse_tpv(line).unwrap();
        assert!((fix.latitude - 41.0).abs() < 1e-6);
        assert!((fix.altitude_m).abs() < 1e-6); // defaults to 0
        assert!(!fix.pai); // no epx/epy → not accurate
    }

    #[test]
    fn parse_tpv_mode_1_rejected() {
        let line = r#"{"class":"TPV","mode":1}"#;
        assert!(parse_tpv(line).is_none());
    }

    #[test]
    fn parse_tpv_non_tpv_rejected() {
        let line = r#"{"class":"SKY","satellites":[]}"#;
        assert!(parse_tpv(line).is_none());
    }

    #[test]
    fn extract_f64_works() {
        let json = r#"{"lat":41.552,"lon":2.134,"speed":10.5}"#;
        assert!((extract_f64(json, "lat").unwrap() - 41.552).abs() < 1e-6);
        assert!((extract_f64(json, "lon").unwrap() - 2.134).abs() < 1e-6);
        assert!((extract_f64(json, "speed").unwrap() - 10.5).abs() < 1e-1);
        assert!(extract_f64(json, "missing").is_none());
    }

    #[test]
    fn extract_f64_negative() {
        let json = r#"{"lat":-33.86,"lon":151.21}"#;
        assert!((extract_f64(json, "lat").unwrap() - (-33.86)).abs() < 1e-6);
    }

    #[test]
    fn parse_tpv_inaccurate_position() {
        let line = r#"{"class":"TPV","mode":3,"lat":41.0,"lon":2.0,"epx":20.0,"epy":15.0}"#;
        let fix = parse_tpv(line).unwrap();
        assert!(!fix.pai);
    }
}

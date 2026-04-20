// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! C-V2X link layer for GeoNetworking.
//!
//! [`Cv2xLinkLayer`] uses the Qualcomm Telematics SDK (via
//! [`super::cv2x_ffi`]) to send and receive GeoNetworking packets over C-V2X
//! hardware (Cohda MKx, or any Qualcomm 9150 C-V2X chipset).
//!
//! # Two TX flows
//!
//! The C-V2X radio exposes two kinds of transmit flow:
//!
//! | Flow | Scheduling | Typical use |
//! |------|-----------|-------------|
//! | **SPS** (Semi-Persistent Scheduling) | Reserved periodic bandwidth | CAMs — predictable latency |
//! | **Event** | Contention-based, best-effort | DENMs, VAMs, LS — sporadic |
//!
//! The link layer inspects the **`tc_id`** field in the GeoNet Common Header
//! of each outbound packet (byte offset 6 from the start of the GN payload)
//! to decide which TX flow to use.  The default classifier sends packets
//! with `tc_id == 0` (the CAM default) via SPS and everything else via the
//! event flow.  A custom classifier can be supplied at construction time.
//!
//! # Protocol byte
//!
//! The Qualcomm non-IP C-V2X interface prepends a single 0x03 byte to every
//! frame (matching the Python `PythonCV2XLinkLayer` behaviour).  This byte is
//! added on TX and stripped on RX automatically.
//!
//! # Concurrency design
//!
//! Mirrors [`super::raw_link_layer::RawLinkLayer`]:
//!
//! ```text
//!   C-V2X Radio ──RX──► rx_thread ──Sender<Vec<u8>>──► GeoNetworking router
//!   C-V2X Radio ◄─TX──  tx_thread ◄──Receiver<Vec<u8>>── GeoNetworking router
//! ```
//!
//! Both threads communicate exclusively through `std::sync::mpsc` channels.

use super::cv2x_ffi::Cv2xHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// Protocol byte prepended to every C-V2X non-IP frame.
const CV2X_PROTOCOL_BYTE: u8 = 0x03;

/// Maximum receive buffer size (matches the C wrapper `BUF_LEN`).
const RX_BUF_LEN: usize = 3000;

/// Byte offset of the `tc_id` field within a GeoNet payload.
///
/// Layout:  BasicHeader (4 bytes) | CommonHeader (8 bytes) | …
/// Within CommonHeader: `[nh|reserved][ht|hst][tc][flags][pl_hi][pl_lo][mhl][reserved2]`
/// So `tc` is at CommonHeader byte index 2  →  absolute offset 4 + 2 = 6.
const TC_BYTE_OFFSET: usize = 6;

/// Default SPS classifier: returns `true` (use SPS flow) when `tc_id == 0`.
///
/// `tc_id == 0` is the default TrafficClass used by the CA Basic Service for
/// CAM packets in this codebase.
fn default_sps_classifier(tc_id: u8) -> bool {
    tc_id == 0
}

/// Extract the 6-bit `tc_id` from a GeoNet payload.
///
/// Returns `None` if the packet is too short to contain the Common Header.
fn extract_tc_id(gn_payload: &[u8]) -> Option<u8> {
    if gn_payload.len() > TC_BYTE_OFFSET {
        // tc_id is the lower 6 bits of the TrafficClass byte
        Some(gn_payload[TC_BYTE_OFFSET] & 0b0011_1111)
    } else {
        None
    }
}

// ------------------------------------------------------------------
// Cv2xLinkLayer
// ------------------------------------------------------------------

/// C-V2X link-layer driver for GeoNetworking.
///
/// Construct with [`Cv2xLinkLayer::new`], then call [`Cv2xLinkLayer::start`]
/// to spawn the RX and TX threads.  The struct is consumed by `start` so
/// ownership is clear.
pub struct Cv2xLinkLayer {
    gn_tx: Sender<Vec<u8>>,
    gn_rx: Receiver<Vec<u8>>,
    handle: Cv2xHandle,
    stop_flag: Arc<AtomicBool>,
    sps_classifier: fn(u8) -> bool,
}

impl Cv2xLinkLayer {
    /// Create a new `Cv2xLinkLayer`.
    ///
    /// * `gn_tx` — sender into the GeoNetworking router (radio → GN direction).
    /// * `gn_rx` — receiver from the GeoNetworking router (GN → radio direction).
    ///
    /// Panics if the C-V2X radio stack fails to initialise.
    pub fn new(gn_tx: Sender<Vec<u8>>, gn_rx: Receiver<Vec<u8>>) -> Self {
        let handle = Cv2xHandle::new().expect("Failed to initialise C-V2X radio stack");
        Cv2xLinkLayer {
            gn_tx,
            gn_rx,
            handle,
            stop_flag: Arc::new(AtomicBool::new(false)),
            sps_classifier: default_sps_classifier,
        }
    }

    /// Create a new `Cv2xLinkLayer` with a custom SPS classifier.
    ///
    /// The classifier receives the 6-bit `tc_id` from the GeoNet Common Header
    /// and returns `true` if the packet should be sent via the SPS flow.
    pub fn with_classifier(
        gn_tx: Sender<Vec<u8>>,
        gn_rx: Receiver<Vec<u8>>,
        sps_classifier: fn(u8) -> bool,
    ) -> Self {
        let handle = Cv2xHandle::new().expect("Failed to initialise C-V2X radio stack");
        Cv2xLinkLayer {
            gn_tx,
            gn_rx,
            handle,
            stop_flag: Arc::new(AtomicBool::new(false)),
            sps_classifier,
        }
    }

    /// Return a clone of the stop flag so the caller can signal shutdown.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    /// Consume `self` and start the RX and TX background threads.
    ///
    /// Returns `(stop_flag, rx_join, tx_join)`.  To shut down gracefully:
    ///
    /// 1. Set `stop_flag` to `true`.
    /// 2. Drop the `gn_to_ll_rx` sender so the TX channel closes.
    /// 3. Join both handles — this ensures `Cv2xHandle::drop()` runs and
    ///    the SDK closes all flows / QCMAP resources.
    pub fn start(self) -> (Arc<AtomicBool>, JoinHandle<()>, JoinHandle<()>) {
        let Cv2xLinkLayer {
            gn_tx,
            gn_rx,
            handle,
            stop_flag,
            sps_classifier,
        } = self;

        // We need the handle accessible from both threads.  Since the C
        // handle's SPS-send, event-send, and receive operate on independent
        // socket FDs, sharing through an Arc is safe.
        let handle = Arc::new(handle);
        let handle_rx = Arc::clone(&handle);
        let handle_tx = Arc::clone(&handle);
        let stop_flag_rx = Arc::clone(&stop_flag);
        let stop_flag_tx = Arc::clone(&stop_flag);
        let stop_ret = Arc::clone(&stop_flag);

        // ── RX thread: C-V2X radio ──► GeoNetworking ─────────────────────
        let rx_join = thread::spawn(move || {
            // Get the RX socket fd for poll().
            let rx_fd = match handle_rx.rx_sock_fd() {
                Some(fd) => fd,
                None => {
                    eprintln!("[CV2X RX] Failed to get RX socket fd");
                    return;
                }
            };

            let mut buf = vec![0u8; RX_BUF_LEN];

            loop {
                if stop_flag_rx.load(Ordering::Relaxed) {
                    break;
                }

                // poll() with 100 ms timeout so we can check the stop flag.
                let mut pfd = libc::pollfd {
                    fd: rx_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ret = unsafe { libc::poll(&mut pfd, 1, 100) };

                if ret < 0 {
                    // Interrupted or error — just retry after checking stop_flag
                    continue;
                }
                if ret == 0 {
                    // Timeout — loop to check stop_flag
                    continue;
                }

                // Data available
                match handle_rx.receive(&mut buf) {
                    Ok(n) if n > 1 => {
                        // Strip the leading 0x03 protocol byte
                        let payload = buf[1..n].to_vec();
                        let _ = gn_tx.send(payload);
                    }
                    Ok(_) => {
                        // Empty or single-byte frame — skip
                    }
                    Err(()) => {
                        eprintln!("[CV2X RX] receive error");
                    }
                }
            }

            eprintln!("[CV2X RX] Thread exiting");
        });

        // ── TX thread: GeoNetworking ──► C-V2X radio ─────────────────────
        let tx_join = thread::spawn(move || {
            while let Ok(gn_payload) = gn_rx.recv() {
                if stop_flag_tx.load(Ordering::Relaxed) {
                    break;
                }

                // Build the CV2X frame: [0x03] [GN payload]
                let mut frame = Vec::with_capacity(1 + gn_payload.len());
                frame.push(CV2X_PROTOCOL_BYTE);
                frame.extend_from_slice(&gn_payload);

                // Decide SPS vs event based on tc_id
                let use_sps = extract_tc_id(&gn_payload)
                    .map(sps_classifier)
                    .unwrap_or(true); // Default to SPS for malformed packets

                let result = if use_sps {
                    handle_tx.send_sps(&frame)
                } else {
                    handle_tx.send_event(&frame)
                };

                if result.is_err() {
                    eprintln!("[CV2X TX] Send error (sps={})", use_sps);
                }
            }
            eprintln!("[CV2X TX] Channel closed, thread exiting");
        });

        (stop_ret, rx_join, tx_join)
    }
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tc_id_from_valid_packet() {
        // Construct a minimal GN packet: 4-byte BasicHeader + 8-byte CommonHeader
        let mut packet = vec![0u8; 12];
        // Set tc byte at offset 6 to 0b1100_0101 → tc_id = 0b00_0101 = 5
        packet[6] = 0b1100_0101;
        assert_eq!(extract_tc_id(&packet), Some(5));
    }

    #[test]
    fn extract_tc_id_cam_default() {
        // CAM default: tc_id = 0
        let mut packet = vec![0u8; 12];
        packet[6] = 0b0000_0000;
        assert_eq!(extract_tc_id(&packet), Some(0));
    }

    #[test]
    fn extract_tc_id_too_short() {
        // Packet shorter than TC_BYTE_OFFSET + 1
        let packet = vec![0u8; 6];
        assert_eq!(extract_tc_id(&packet), None);
    }

    #[test]
    fn default_classifier_sps_for_tc0() {
        assert!(default_sps_classifier(0));
    }

    #[test]
    fn default_classifier_event_for_nonzero() {
        assert!(!default_sps_classifier(1));
        assert!(!default_sps_classifier(5));
        assert!(!default_sps_classifier(63));
    }
}

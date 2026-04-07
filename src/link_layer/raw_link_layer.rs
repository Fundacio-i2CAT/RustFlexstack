// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Raw Ethernet link layer for GeoNetworking.
//!
//! [`RawLinkLayer`] opens two `pnet` datalink channels on the same interface
//! (one for RX, one for TX) and runs each in a dedicated thread.
//!
//! # Concurrency design
//! ```text
//!   NIC ──RX──► rx_thread ──Sender<Vec<u8>>──► GeoNetworking router
//!   NIC ◄─TX──  tx_thread ◄──Receiver<Vec<u8>>── GeoNetworking router
//! ```
//!
//! Both threads communicate exclusively through `std::sync::mpsc` channels —
//! no `Arc`/`Mutex` is needed.  The `pnet` library handles all low-level
//! socket access; two separate channel objects are opened because `pnet`
//! requires a distinct handle per thread.
//!
//! # Graceful shutdown
//! Dropping the `tx` side of the GN→NIC channel causes the TX thread to exit
//! its `while let Ok(...)` loop naturally.  The RX thread polls a
//! `stop_flag` `AtomicBool` shared via `Arc` so it can also be stopped.
//!
//! # Concurrency correctness
//! On Linux, `AF_PACKET` sockets used by `pnet` are per-open-socket — two
//! sockets on the same interface do *not* conflict; the kernel delivers
//! received packets to all matching sockets independently.

use crate::link_layer::packet_consts::ETH_P_GEONET;
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/// Build a minimal 14-byte Ethernet II frame with the GeoNet EtherType.
fn build_eth_frame(dest_mac: [u8; 6], src_mac: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dest_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETH_P_GEONET.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Return `true` if the frame carries the GeoNetworking EtherType (0x8947).
fn is_geonet_frame(frame: &[u8]) -> bool {
    frame.len() >= 14 && u16::from_be_bytes([frame[12], frame[13]]) == ETH_P_GEONET
}

// ------------------------------------------------------------------
// RawLinkLayer
// ------------------------------------------------------------------

/// Ethernet link-layer driver for GeoNetworking.
///
/// Construct with [`RawLinkLayer::new`], then call [`RawLinkLayer::start`]
/// to spawn the RX and TX threads.  The struct is consumed by `start` so
/// ownership is clear.
pub struct RawLinkLayer {
    /// Channel endpoint for sending received GN payloads *up* to the GN router.
    gn_tx: Sender<Vec<u8>>,
    /// Channel endpoint for receiving GN payloads *from* the GN router for TX.
    gn_rx: Receiver<Vec<u8>>,
    /// Network interface name (e.g. `"eth0"`, `"enp0s31f6"`).
    iface_name: String,
    /// Local MAC address used as the source address in transmitted frames.
    mac_address: [u8; 6],
    /// Shared stop flag.  Setting this to `true` causes the RX thread to exit.
    stop_flag: Arc<AtomicBool>,
}

impl RawLinkLayer {
    /// Create a new `RawLinkLayer`.
    ///
    /// * `gn_tx`      — sender into the GeoNetworking router (NIC → GN direction).
    /// * `gn_rx`      — receiver from the GeoNetworking router (GN → NIC direction).
    /// * `iface_name` — OS network interface name.
    /// * `mac_address` — MAC address to use as the Ethernet source address.
    pub fn new(
        gn_tx: Sender<Vec<u8>>,
        gn_rx: Receiver<Vec<u8>>,
        iface_name: &str,
        mac_address: [u8; 6],
    ) -> Self {
        RawLinkLayer {
            gn_tx,
            gn_rx,
            iface_name: iface_name.to_string(),
            mac_address,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Return a clone of the stop flag so the caller can signal shutdown.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    /// Consume `self` and start the RX and TX background threads.
    ///
    /// The threads run until:
    /// - **RX**: `stop_flag` is set to `true`.
    /// - **TX**: the `gn_rx` sender is dropped (channel closed).
    pub fn start(self) {
        let RawLinkLayer {
            gn_tx,
            gn_rx,
            iface_name,
            mac_address,
            stop_flag,
        } = self;

        let iface_name_rx = iface_name.clone();
        let iface_name_tx = iface_name;
        let stop_flag_rx = Arc::clone(&stop_flag);

        // ── RX thread: NIC ──► GeoNetworking ─────────────────────────────────
        //
        // We open our own AF_PACKET / SOCK_RAW socket instead of using a pnet
        // channel for RX.  This lets us call setsockopt(PACKET_IGNORE_OUTGOING)
        // immediately after creation so the kernel never echoes our own TX
        // frames back to us — the only reliable fix for self-reception.
        thread::spawn(move || {
            // Resolve the interface index
            let if_index = match find_interface(&iface_name_rx) {
                Some(i) => i.index,
                None => {
                    eprintln!("[LL RX] Interface '{}' not found", iface_name_rx);
                    return;
                }
            };

            // Open AF_PACKET / SOCK_RAW socket filtered to GeoNet EtherType.
            // htons(ETH_P_GEONET) selects only 0x8947 frames at kernel level.
            let sock = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW,
                    ETH_P_GEONET.to_be() as libc::c_int,
                )
            };
            if sock < 0 {
                eprintln!("[LL RX] Failed to open AF_PACKET socket");
                return;
            }

            // PACKET_IGNORE_OUTGOING (value 23, added in Linux 4.20):
            // tells the kernel to never deliver frames that this host
            // transmitted to this socket — eliminates self-echo entirely.
            unsafe {
                let val: libc::c_int = 1;
                let ret = libc::setsockopt(
                    sock,
                    libc::SOL_PACKET,
                    23, // PACKET_IGNORE_OUTGOING
                    &val as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                if ret < 0 {
                    eprintln!(
                        "[LL RX] PACKET_IGNORE_OUTGOING not supported, falling back to MAC filter"
                    );
                }
            }

            // Bind to the specific interface so we don't receive from all NICs.
            let sll = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: ETH_P_GEONET.to_be(),
                sll_ifindex: if_index as i32,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0u8; 8],
            };
            let ret = unsafe {
                libc::bind(
                    sock,
                    &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                eprintln!("[LL RX] Failed to bind socket");
                unsafe {
                    libc::close(sock);
                }
                return;
            }

            // Set a 100 ms receive timeout so we can check the stop flag.
            let tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 100_000,
            };
            unsafe {
                libc::setsockopt(
                    sock,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const libc::timeval as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }

            let mut buf = vec![0u8; 2048];
            loop {
                if stop_flag_rx.load(Ordering::Relaxed) {
                    break;
                }
                let n = unsafe {
                    libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if n < 0 {
                    // EAGAIN / EWOULDBLOCK = timeout, just loop
                    continue;
                }
                let frame = &buf[..n as usize];
                // Ethernet frame: [0..6] dst, [6..12] src, [12..14] ethertype, [14..] payload
                if frame.len() < 14 {
                    continue;
                }
                // Fallback MAC filter — catches any self-echo if the kernel
                // doesn't support PACKET_IGNORE_OUTGOING.
                if frame[6..12] == mac_address {
                    continue;
                }
                // EtherType is already filtered by the socket, but double-check.
                if !is_geonet_frame(frame) {
                    continue;
                }
                let _ = gn_tx.send(frame[14..].to_vec());
            }

            unsafe {
                libc::close(sock);
            }
            eprintln!("[LL RX] Thread exiting");
        });

        // ── TX thread: GeoNetworking ──► NIC ─────────────────────────────────
        thread::spawn(move || {
            let interface = match find_interface(&iface_name_tx) {
                Some(i) => i,
                None => {
                    eprintln!("[LL TX] Interface '{}' not found", iface_name_tx);
                    return;
                }
            };
            let config = Config {
                write_timeout: None,
                ..Config::default()
            };
            let (mut tx, _rx) = match datalink::channel(&interface, config) {
                Ok(Channel::Ethernet(t, r)) => (t, r),
                Ok(_) => {
                    eprintln!("[LL TX] Unexpected channel type");
                    return;
                }
                Err(e) => {
                    eprintln!("[LL TX] Failed to open channel: {}", e);
                    return;
                }
            };

            // Loop until the GN router drops the sender side of the channel
            while let Ok(gn_payload) = gn_rx.recv() {
                // GeoNetworking always broadcasts at L2; unicast forwarding
                // requires a neighbour table lookup (not yet implemented).
                let dest_mac: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
                let frame = build_eth_frame(dest_mac, mac_address, &gn_payload);
                // send_to returns Option<io::Result<()>>; None means no-op.
                if let Some(Err(e)) = tx.send_to(&frame, None) {
                    eprintln!("[LL TX] Send error: {}", e);
                }
            }
            eprintln!("[LL TX] Channel closed, thread exiting");
        });
    }
}

// ------------------------------------------------------------------
// Helper
// ------------------------------------------------------------------

fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().find(|i| i.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn build_eth_frame_basic() {
        let dest = [0xFF; 6];
        let src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let payload = [0xAA, 0xBB];
        let frame = build_eth_frame(dest, src, &payload);
        // 6 dest + 6 src + 2 ethertype + 2 payload = 16
        assert_eq!(frame.len(), 16);
        assert_eq!(&frame[0..6], &dest);
        assert_eq!(&frame[6..12], &src);
        assert_eq!(&frame[12..14], &ETH_P_GEONET.to_be_bytes());
        assert_eq!(&frame[14..16], &payload);
    }

    #[test]
    fn build_eth_frame_empty_payload() {
        let frame = build_eth_frame([0; 6], [0; 6], &[]);
        assert_eq!(frame.len(), 14);
    }

    #[test]
    fn is_geonet_frame_valid() {
        let frame = build_eth_frame([0xFF; 6], [0; 6], &[0xCA, 0xFE]);
        assert!(is_geonet_frame(&frame));
    }

    #[test]
    fn is_geonet_frame_too_short() {
        assert!(!is_geonet_frame(&[0u8; 13]));
    }

    #[test]
    fn is_geonet_frame_wrong_ethertype() {
        let mut frame = build_eth_frame([0xFF; 6], [0; 6], &[0xCA]);
        // Overwrite ethertype
        frame[12] = 0x08;
        frame[13] = 0x00;
        assert!(!is_geonet_frame(&frame));
    }

    #[test]
    fn raw_link_layer_new() {
        let (gn_tx, _) = mpsc::channel();
        let (_, gn_rx) = mpsc::channel();
        let rll = RawLinkLayer::new(gn_tx, gn_rx, "lo", [0x00; 6]);
        assert_eq!(rll.iface_name, "lo");
        assert_eq!(rll.mac_address, [0x00; 6]);
        assert!(!rll.stop_flag.load(Ordering::Relaxed));
    }

    #[test]
    fn raw_link_layer_stop_flag_clone() {
        let (gn_tx, _) = mpsc::channel();
        let (_, gn_rx) = mpsc::channel();
        let rll = RawLinkLayer::new(gn_tx, gn_rx, "eth0", [0xAA; 6]);
        let flag = rll.stop_flag();
        flag.store(true, Ordering::Relaxed);
        assert!(rll.stop_flag.load(Ordering::Relaxed));
    }
}

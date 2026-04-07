// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Benchmark: Maximum CAM RX throughput.
//!
//! Listens on BTP port 2001, decodes every packet with `CamCoder::decode()`,
//! and reports packets/s plus UPER decode latency in µs.
//!
//! Pair with `bench_cam_tx` (possibly on another machine or loopback) to load
//! the receiver.
//!
//! # Usage
//! ```text
//! sudo cargo run --release --example bench_cam_rx -- [interface] [duration_s]
//! # defaults: lo, 30 s
//! ```

use rustflexstack::btp::router::{BTPRouterHandle, Router as BTPRouter};
use rustflexstack::btp::service_access_point::BTPDataIndication;
use rustflexstack::facilities::ca_basic_service::cam_coder::CamCoder;
use rustflexstack::geonet::gn_address::{GNAddress, M, MID, ST};
use rustflexstack::geonet::mib::Mib;
use rustflexstack::geonet::position_vector::LongPositionVector;
use rustflexstack::geonet::router::{Router as GNRouter, RouterHandle};
use rustflexstack::geonet::service_access_point::{GNDataIndication, GNDataRequest};
use rustflexstack::link_layer::raw_link_layer::RawLinkLayer;

use std::env;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    let duration_s = env::args()
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);

    println!("=== Benchmark: Maximum CAM RX throughput ===");
    println!("Interface : {iface}");
    println!("Duration  : {duration_s} s\n");

    // ── MAC / MIB ─────────────────────────────────────────────────────────────
    let mac = random_mac();
    let mut mib = Mib::new();
    mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(mac));
    mib.itsGnBeaconServiceRetransmitTimer = 0;

    // ── Routers + link layer ──────────────────────────────────────────────────
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();
    RawLinkLayer::new(ll_to_gn_tx, gn_to_ll_rx, &iface, mac).start();
    wire_routers(
        &gn_handle,
        &btp_handle,
        ll_to_gn_rx,
        gn_to_btp_rx,
        btp_to_gn_rx,
    );

    // Seed position vector.
    let mut epv = LongPositionVector::decode([0u8; 24]);
    epv.update_from_gps(41.552, 2.134, 0.0, 0.0, true);
    gn_handle.update_position_vector(epv);
    thread::sleep(Duration::from_millis(50));

    // ── Register on BTP port 2001 ─────────────────────────────────────────────
    let (ind_tx, ind_rx) = mpsc::channel::<BTPDataIndication>();
    btp_handle.register_port(2001, ind_tx);

    // ── Benchmark loop ────────────────────────────────────────────────────────
    println!("Waiting for CAMs on port 2001…\n");
    println!(
        "{:>7}  {:>10}  {:>12}  {:>12}  {:>10}",
        "time(s)", "total_recv", "rate(pkt/s)", "avg_dec(µs)", "errors"
    );

    let coder = CamCoder::new();
    let mut total_recv: u64 = 0;
    let mut total_errors: u64 = 0;
    let mut total_dec_us: u128 = 0;
    let bench_start = Instant::now();
    let bench_end = bench_start + Duration::from_secs(duration_s);
    let mut win_start = Instant::now();
    let mut win_recv: u64 = 0;

    loop {
        let now = Instant::now();
        if now >= bench_end {
            break;
        }

        let timeout = (bench_end - now).min(Duration::from_millis(500));
        match ind_rx.recv_timeout(timeout) {
            Ok(ind) => {
                let t0 = Instant::now();
                match coder.decode(&ind.data) {
                    Ok(_) => {}
                    Err(e) => {
                        total_errors += 1;
                        eprintln!("[RX] Decode error: {e}");
                    }
                }
                let dec_us = t0.elapsed().as_micros();
                total_recv += 1;
                total_dec_us += dec_us;
                win_recv += 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        let win_elapsed = win_start.elapsed();
        if win_elapsed >= Duration::from_secs(1) {
            let pps = win_recv as f64 / win_elapsed.as_secs_f64();
            let avg_dec = if total_recv > 0 {
                total_dec_us / total_recv as u128
            } else {
                0
            };
            println!(
                "{:>7.1}  {:>10}  {:>12.1}  {:>12}  {:>10}",
                bench_start.elapsed().as_secs_f64(),
                total_recv,
                pps,
                avg_dec,
                total_errors
            );
            win_start = Instant::now();
            win_recv = 0;
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    let elapsed = bench_start.elapsed().as_secs_f64();
    let avg_rate = total_recv as f64 / elapsed;
    let avg_decode = if total_recv > 0 {
        total_dec_us / total_recv as u128
    } else {
        0
    };

    println!();
    println!("=== CAM RX Results ===");
    println!("  Total received  : {total_recv}");
    println!("  Decode errors   : {total_errors}");
    println!("  Elapsed         : {elapsed:.3} s");
    println!("  Average rate    : {avg_rate:.1} pkt/s");
    println!("  Avg decode time : {avg_decode} µs");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn random_mac() -> [u8; 6] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    [
        0x02,
        (s >> 24) as u8,
        (s >> 16) as u8,
        (s >> 8) as u8,
        s as u8,
        0xCC,
    ]
}

fn wire_routers(
    gn: &RouterHandle,
    btp: &BTPRouterHandle,
    ll_rx: mpsc::Receiver<Vec<u8>>,
    gn_btp_rx: mpsc::Receiver<GNDataIndication>,
    btp_gn_rx: mpsc::Receiver<GNDataRequest>,
) {
    let g1 = gn.clone();
    thread::spawn(move || {
        while let Ok(p) = ll_rx.recv() {
            g1.send_incoming_packet(p);
        }
    });
    let b1 = btp.clone();
    thread::spawn(move || {
        while let Ok(i) = gn_btp_rx.recv() {
            b1.send_gn_data_indication(i);
        }
    });
    let g2 = gn.clone();
    thread::spawn(move || {
        while let Ok(r) = btp_gn_rx.recv() {
            g2.send_gn_data_request(r);
        }
    });
}

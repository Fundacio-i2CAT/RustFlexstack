// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! C-V2X DENM Sender and Receiver Example
//!
//! Identical to `denm_sender_receiver` but uses the C-V2X link layer
//! ([`Cv2xLinkLayer`]) instead of the raw Ethernet link layer.  DENM packets
//! are transmitted via the **event-driven** TX flow (contention-based), which
//! is appropriate for sporadic safety messages.
//!
//! The SPS vs event routing is automatic: the link layer inspects the `tc_id`
//! in the GeoNet Common Header.  DENMs use a non-zero `tc_id`, so they are
//! routed to the event flow.
//!
//! # Building
//! ```text
//! # First build the C wrapper on the target:
//! cd cv2xlinklayerlibrary && mkdir -p build && cd build && cmake .. && make cv2x_wrapper_c
//!
//! # Then build the Rust example with the cv2x feature:
//! cargo build --example cv2x_denm_sender_receiver --features cv2x
//! ```
//!
//! # Running
//! ```text
//! ./target/debug/examples/cv2x_denm_sender_receiver
//! ```

use rustflexstack::btp::router::Router as BTPRouter;
use rustflexstack::facilities::decentralized_environmental_notification_service::{
    denm_coder::{AccidentSubCauseCode, CauseCodeChoice},
    DENRequest, DecentralizedEnvironmentalNotificationService, VehicleData,
};
use rustflexstack::facilities::location_service::{GpsFix, LocationService};
use rustflexstack::geonet::gn_address::{GNAddress, M, MID, ST};
use rustflexstack::geonet::mib::Mib;
use rustflexstack::geonet::position_vector::LongPositionVector;
use rustflexstack::geonet::router::Router as GNRouter;
use rustflexstack::link_layer::cv2x_link_layer::Cv2xLinkLayer;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== C-V2X DENM Sender/Receiver Example (event flow) ===");

    // ── Generate a random locally-administered MAC ────────────────────────────
    let mac = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        [
            0x02u8,
            (seed >> 24) as u8,
            (seed >> 16) as u8,
            (seed >> 8) as u8,
            seed as u8,
            0xCC,
        ]
    };
    println!(
        "MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // ── MIB ───────────────────────────────────────────────────────────────────
    let mut mib = Mib::new();
    mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(mac));
    mib.itsGnBeaconServiceRetransmitTimer = 0;

    // ── Location Service ──────────────────────────────────────────────────────
    let mut loc_svc = LocationService::new();
    let gn_gps_rx = loc_svc.subscribe();

    // ── Spawn GeoNetworking router ────────────────────────────────────────────
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);

    // ── Spawn BTP router ──────────────────────────────────────────────────────
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    // ── Wire Cv2xLinkLayer ────────────────────────────────────────────────────
    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();
    let cv2x_ll = Cv2xLinkLayer::new(ll_to_gn_tx, gn_to_ll_rx);
    cv2x_ll.start();

    // ── Wire threads ──────────────────────────────────────────────────────────

    // LL → GN
    let gn_h1 = gn_handle.clone();
    thread::spawn(move || {
        while let Ok(pkt) = ll_to_gn_rx.recv() {
            gn_h1.send_incoming_packet(pkt);
        }
    });

    // GN → BTP
    let btp_h1 = btp_handle.clone();
    thread::spawn(move || {
        while let Ok(ind) = gn_to_btp_rx.recv() {
            btp_h1.send_gn_data_indication(ind);
        }
    });

    // BTP → GN
    let gn_h2 = gn_handle.clone();
    thread::spawn(move || {
        while let Ok(req) = btp_to_gn_rx.recv() {
            gn_h2.send_gn_data_request(req);
        }
    });

    // ── Bridge: LocationService → GN router position vector ───────────────────
    let gn_h3 = gn_handle.clone();
    thread::spawn(move || {
        while let Ok(fix) = gn_gps_rx.recv() {
            let mut epv = LongPositionVector::decode([0u8; 24]);
            epv.update_from_gps(
                fix.latitude,
                fix.longitude,
                fix.speed_mps,
                fix.heading_deg,
                fix.pai,
            );
            gn_h3.update_position_vector(epv);
        }
    });

    // ── DEN Service ───────────────────────────────────────────────────────────
    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let vehicle_data = VehicleData {
        station_id,
        station_type: 5, // passengerCar
    };

    let (den_svc, denm_rx) =
        DecentralizedEnvironmentalNotificationService::new(btp_handle.clone(), vehicle_data);

    // ── Decoded DENM printer ──────────────────────────────────────────────────
    thread::spawn(move || {
        while let Ok(denm) = denm_rx.recv() {
            let lat = denm.denm.management.event_position.latitude.0 as f64 / 1e7;
            let lon = denm.denm.management.event_position.longitude.0 as f64 / 1e7;
            let seq = denm.denm.management.action_id.sequence_number.0;
            println!(
                "[DENM RX] station={:>10}  seq={:>5}  event_lat={:.5}  event_lon={:.5}",
                denm.header.station_id.0, seq, lat, lon,
            );
        }
    });

    // ── Publish initial GPS fix ───────────────────────────────────────────────
    thread::sleep(Duration::from_millis(100));

    let gps_fix = GpsFix {
        latitude: 41.552,
        longitude: 2.134,
        altitude_m: 120.0,
        speed_mps: 14.0,
        heading_deg: 90.0,
        pai: true,
    };
    loc_svc.publish(gps_fix);

    // ── Trigger DENM: Road Hazard (accident) at current position ──────────────
    println!("Triggering road-hazard DENM (accident) for 30 s @ 1 Hz");
    den_svc.trigger_denm(DENRequest {
        event_latitude: gps_fix.latitude,
        event_longitude: gps_fix.longitude,
        event_altitude_m: gps_fix.altitude_m,
        cause_code: CauseCodeChoice::accident2(AccidentSubCauseCode(0)),
        information_quality: 4,
        event_speed_raw: (gps_fix.speed_mps * 100.0) as u16,
        event_heading_raw: (gps_fix.heading_deg * 10.0) as u16,
        denm_interval_ms: 1_000,
        time_period_ms: 30_000,
        relevance_radius_m: 1_000,
    });

    // ── GPS publisher loop ────────────────────────────────────────────────────
    println!("Publishing GPS fixes @ 1 Hz — Ctrl+C to stop\n");
    loop {
        thread::sleep(Duration::from_secs(1));
        loc_svc.publish(gps_fix);
    }
}

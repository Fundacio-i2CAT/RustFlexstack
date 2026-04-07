// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DENM Sender and Receiver Example
//!
//! This example mirrors `FlexStack/examples/cam_sender_and_receiver.py` but
//! uses the Decentralized Environmental Notification (DEN) Service (DENM)
//! instead of the CA Basic Service (CAM).
//!
//! It shows how to use the `rustflexstack` library to build a minimal V2X node
//! that:
//!
//! 1. Initialises a GeoNetworking router and a BTP router.
//! 2. Connects them to a raw Ethernet link layer.
//! 3. Uses `DecentralizedEnvironmentalNotificationService` to send UPER-encoded
//!    DENMs via GeoBroadcast-Circle on BTP port 2002 and receive + decode any
//!    incoming DENMs on the same port.
//! 4. Triggers a Road-Hazard Signalling DENM (accident cause code) once the
//!    stack is initialised, and repeats it for 30 seconds.
//!
//! # Running
//! ```text
//! # The raw socket requires CAP_NET_RAW or root:
//! sudo cargo run --example denm_sender_receiver -- <interface>
//! # e.g.:
//! sudo cargo run --example denm_sender_receiver -- eth0
//! ```
//!
//! If no interface is given the example falls back to `lo` (loopback), which
//! is sufficient to test encode/decode on a single machine.

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
use rustflexstack::link_layer::raw_link_layer::RawLinkLayer;
use std::env;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    // ── Parse optional interface argument ─────────────────────────────────────
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());

    println!("=== DENM Sender/Receiver Example (DEN Service) ===");
    println!("Interface: {}", iface);

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
    //
    // A single LocationService publishes GPS fixes.  We subscribe once for the
    // GN router's position vector updates.
    let mut loc_svc = LocationService::new();
    let gn_gps_rx = loc_svc.subscribe();

    // ── Spawn GeoNetworking router ────────────────────────────────────────────
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);

    // ── Spawn BTP router ──────────────────────────────────────────────────────
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    // ── Wire RawLinkLayer ─────────────────────────────────────────────────────
    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();
    let raw_ll = RawLinkLayer::new(ll_to_gn_tx, gn_to_ll_rx, &iface, mac);
    raw_ll.start();

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

    // DecentralizedEnvironmentalNotificationService::new returns the service
    // handle plus a Receiver<Denm> on which decoded incoming DENMs arrive.
    // The reception thread is started immediately (registers BTP port 2002).
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

    // ── Publish initial GPS fix to initialise the GN router ───────────────────
    thread::sleep(Duration::from_millis(100));

    // Publish position fixes to keep the GN position vector up to date.
    let gps_fix = GpsFix {
        latitude: 41.552,
        longitude: 2.134,
        altitude_m: 120.0,
        speed_mps: 14.0, // ~50 km/h
        heading_deg: 90.0,
        pai: true,
    };
    loc_svc.publish(gps_fix);

    // ── Trigger DENM: Road Hazard (accident) at current position ──────────────
    //
    // Send 1 DENM/s for 30 s, 1 000 m geo-broadcast circle.
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

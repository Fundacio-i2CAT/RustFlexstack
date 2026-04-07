// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CAM Sender and Receiver Example
//!
//! This example mirrors `FlexStack/examples/cam_sender_and_receiver.py` and
//! shows how to use the `rustflexstack` library to build a minimal V2X node
//! that:
//!
//! 1. Initialises a GeoNetworking router and a BTP router.
//! 2. Connects them to a raw Ethernet link layer.
//! 3. Uses `CooperativeAwarenessBasicService` to send UPER-encoded CAMs at
//!    up to 10 Hz and receive + decode incoming CAMs on BTP port 2001.
//! 4. Uses `LocationService` to fan GPS fixes out to both the GN router
//!    (position vector updates) and the CA Basic Service (CAM generation).
//!
//! # Running
//! ```text
//! # The raw socket requires CAP_NET_RAW or root:
//! sudo cargo run --example cam_sender_receiver -- <interface>
//! # e.g.:
//! sudo cargo run --example cam_sender_receiver -- eth0
//! ```
//!
//! If no interface is given the example falls back to `lo` (loopback), which
//! is sufficient to test send→receive on a single machine.

use rustflexstack::btp::router::Router as BTPRouter;
use rustflexstack::facilities::ca_basic_service::{CooperativeAwarenessBasicService, VehicleData};
use rustflexstack::facilities::local_dynamic_map::{
    ldm_constants::ITS_AID_CAM,
    ldm_storage::ItsDataObject,
    ldm_types::{RegisterDataConsumerReq, RegisterDataProviderReq, RequestDataObjectsReq},
    LdmFacility,
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
    // ── Parse optional interface argument ────────────────────────────────────
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());

    println!("=== CAM Sender/Receiver Example (CA Basic Service) ===");
    println!("Interface: {}", iface);

    // ── Generate a random locally-administered MAC ────────────────────────
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
            0xAA,
        ]
    };
    println!(
        "MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // ── MIB ──────────────────────────────────────────────────────────────────
    let mut mib = Mib::new();
    mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(mac));
    mib.itsGnBeaconServiceRetransmitTimer = 0;

    // ── Location Service ─────────────────────────────────────────────────────
    //
    // A single LocationService publishes GPS fixes to multiple subscribers.
    // We subscribe twice: once for the GN router's position vector, and once
    // for the CA Basic Service CAM generation.
    let mut loc_svc = LocationService::new();
    let gn_gps_rx = loc_svc.subscribe(); // → GN position vector updates
    let ca_gps_rx = loc_svc.subscribe(); // → CAM transmission

    // ── Spawn GeoNetworking router ────────────────────────────────────────────
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);

    // ── Spawn BTP router ─────────────────────────────────────────────────────
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    // ── Wire RawLinkLayer ────────────────────────────────────────────────────
    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();
    let raw_ll = RawLinkLayer::new(ll_to_gn_tx, gn_to_ll_rx, &iface, mac);
    raw_ll.start();

    // ── Wire threads ─────────────────────────────────────────────────────────

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

    // ── Bridge: LocationService → GN router position vector ──────────────────
    //
    // Converts each GpsFix into a LongPositionVector and pushes it into the
    // GeoNetworking router so the EPV in every outgoing GN header is current.
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

    // ── Local Dynamic Map ─────────────────────────────────────────────────────
    //
    // Create the LDM centred on the simulated GPS position with a 5 km radius.
    // Parc Tecnològic del Vallès: 41.552°N 2.134°E → ETSI integers × 1e7.
    let ldm = LdmFacility::new(415_520_000, 21_340_000, 5_000.0);

    // Register this node as a CAM data provider and consumer.
    ldm.if_ldm_3
        .register_data_provider(RegisterDataProviderReq {
            application_id: ITS_AID_CAM,
        });
    ldm.if_ldm_4
        .register_data_consumer(RegisterDataConsumerReq {
            application_id: ITS_AID_CAM,
        });

    // ── CA Basic Service ─────────────────────────────────────────────────────
    //
    // VehicleData carries static vehicle metadata that goes into every CAM.
    // station_id should match the GN address mid bytes in a real deployment.
    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let vehicle_data = VehicleData {
        station_id,
        ..VehicleData::default() // PassengerCar, unavailable lengths
    };

    // Pass Some(ldm) so every received CAM is stored in the LDM before being
    // forwarded.  The _cam_rx channel is still available for direct consumers
    // but in this example we read via IF.LDM.4 instead.
    let (ca_svc, _cam_rx) =
        CooperativeAwarenessBasicService::new(btp_handle.clone(), vehicle_data, Some(ldm.clone()));

    // start() consumes the service handle and spawns the TX + RX threads.
    ca_svc.start(ca_gps_rx);

    // ── LDM query printer ─────────────────────────────────────────────────────
    //
    // Every second, query the LDM for all CAM records and print them.
    // This uses the ETSI IF.LDM.4 interface and confirms that received CAMs
    // are correctly stored and retrievable.
    let ldm_reader = ldm.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let resp = ldm_reader
            .if_ldm_4
            .request_data_objects(RequestDataObjectsReq {
                application_id: ITS_AID_CAM,
                data_object_types: vec![ITS_AID_CAM],
                filter: None,
                order: None,
                max_results: None,
            });
        if resp.data_objects.is_empty() {
            println!("[LDM] No CAM records in store");
        } else {
            println!("[LDM] {} CAM record(s):", resp.data_objects.len());
            for entry in &resp.data_objects {
                if let ItsDataObject::Cam(cam) = &entry.data_object {
                    let lat = cam
                        .cam
                        .cam_parameters
                        .basic_container
                        .reference_position
                        .latitude
                        .0 as f64
                        / 1e7;
                    let lon = cam
                        .cam
                        .cam_parameters
                        .basic_container
                        .reference_position
                        .longitude
                        .0 as f64
                        / 1e7;
                    println!(
                        "  [LDM CAM] record={:>5} station={:>10}  lat={:.5}  lon={:.5}",
                        entry.record_id, cam.header.station_id.0, lat, lon,
                    );
                }
            }
        }
    });

    // ── GPS publisher (simulates a real GNSS sensor at 1 Hz) ─────────────────
    //
    // In a real application this thread would read from gpsd or a serial port.
    // Wait briefly for the routers to finish initialising.
    thread::sleep(Duration::from_millis(100));
    println!("Publishing GPS fixes @ 10 Hz — Ctrl+C to stop\n");

    loop {
        thread::sleep(Duration::from_millis(100));
        // 41.552°N  2.134°E — Parc Tecnològic del Vallès
        loc_svc.publish(GpsFix {
            latitude: 41.552,
            longitude: 2.134,
            altitude_m: 120.0,
            speed_mps: 0.0,
            heading_deg: 0.0,
            pai: true,
        });
    }
}

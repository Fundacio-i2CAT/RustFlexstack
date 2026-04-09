// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! C-V2X CAM Sender and Receiver Example
//!
//! Identical to `cam_sender_receiver` but uses the C-V2X link layer
//! ([`Cv2xLinkLayer`]) instead of the raw Ethernet link layer.  CAM packets
//! are transmitted via the SPS (Semi-Persistent Scheduling) flow, which
//! provides reserved periodic bandwidth suitable for safety messages.
//!
//! The C-V2X radio manages its own interface — no network interface argument
//! is required.
//!
//! # Building
//! ```text
//! # First build the C wrapper on the target:
//! cd cv2xlinklayerlibrary && mkdir -p build && cd build && cmake .. && make cv2x_wrapper_c
//!
//! # Then build the Rust example with the cv2x feature:
//! cargo build --example cv2x_cam_sender_receiver --features cv2x
//! ```
//!
//! # Running
//! ```text
//! ./target/debug/examples/cv2x_cam_sender_receiver
//! ```

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
use rustflexstack::link_layer::cv2x_link_layer::Cv2xLinkLayer;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== C-V2X CAM Sender/Receiver Example (SPS flow) ===");

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
    let mut loc_svc = LocationService::new();
    let gn_gps_rx = loc_svc.subscribe();
    let ca_gps_rx = loc_svc.subscribe();

    // ── Spawn GeoNetworking router ────────────────────────────────────────────
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);

    // ── Spawn BTP router ─────────────────────────────────────────────────────
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    // ── Wire Cv2xLinkLayer ───────────────────────────────────────────────────
    //
    // Instead of RawLinkLayer, we use Cv2xLinkLayer which initialises the
    // C-V2X radio and creates SPS + event TX flows automatically.
    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();
    let cv2x_ll = Cv2xLinkLayer::new(ll_to_gn_tx, gn_to_ll_rx);
    cv2x_ll.start();

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
    let ldm = LdmFacility::new(415_520_000, 21_340_000, 5_000.0);
    ldm.if_ldm_3
        .register_data_provider(RegisterDataProviderReq {
            application_id: ITS_AID_CAM,
        });
    ldm.if_ldm_4
        .register_data_consumer(RegisterDataConsumerReq {
            application_id: ITS_AID_CAM,
        });

    // ── CA Basic Service ─────────────────────────────────────────────────────
    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let vehicle_data = VehicleData {
        station_id,
        ..VehicleData::default()
    };

    let (ca_svc, _cam_rx) =
        CooperativeAwarenessBasicService::new(btp_handle.clone(), vehicle_data, Some(ldm.clone()));
    ca_svc.start(ca_gps_rx);

    // ── LDM query printer ─────────────────────────────────────────────────────
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

    // ── GPS publisher (simulates a real GNSS sensor at 10 Hz) ────────────────
    thread::sleep(Duration::from_millis(100));
    println!("Publishing GPS fixes @ 10 Hz — Ctrl+C to stop\n");

    loop {
        thread::sleep(Duration::from_millis(100));
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

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Secured C-V2X CAM Sender and Receiver Example
//!
//! Combines the security middleware from `secured_cam_sender_receiver` with
//! the C-V2X link layer from `cv2x_cam_sender_receiver`.  CAM packets are
//! signed before transmission and verified on reception.  The SPS
//! (Semi-Persistent Scheduling) flow provides reserved periodic bandwidth.
//!
//! GPS positions are sourced from a real GNSS receiver via
//! [`GpsdLocationService`], which connects to a running gpsd daemon.
//!
//! # Prerequisites
//! ```text
//! cargo run --example generate_certificate_chain --target x86_64-unknown-linux-gnu
//! ```
//!
//! Copy the resulting `certs/` directory to the target device.
//!
//! # Running
//! ```text
//! # Ensure gpsd is running on the device (default port 2947)
//! ./secured_cv2x_cam_sender_receiver --at 1
//! ```

use std::env;
use std::fs;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustflexstack::btp::router::Router as BTPRouter;
use rustflexstack::facilities::ca_basic_service::{CooperativeAwarenessBasicService, VehicleData};
use rustflexstack::facilities::gpsd_location_service::GpsdLocationService;
use rustflexstack::facilities::local_dynamic_map::{
    ldm_constants::ITS_AID_CAM,
    ldm_storage::ItsDataObject,
    ldm_types::{RegisterDataConsumerReq, RegisterDataProviderReq, RequestDataObjectsReq},
    LdmFacility,
};
use rustflexstack::geonet::basic_header::{BasicHeader, BasicNH};
use rustflexstack::geonet::gn_address::{GNAddress, M, MID, ST};
use rustflexstack::geonet::mib::Mib;
use rustflexstack::geonet::position_vector::LongPositionVector;
use rustflexstack::geonet::router::Router as GNRouter;
use rustflexstack::link_layer::cv2x_link_layer::Cv2xLinkLayer;

use rustflexstack::security::certificate::{Certificate, OwnCertificate};
use rustflexstack::security::certificate_library::CertificateLibrary;
use rustflexstack::security::ecdsa_backend::EcdsaBackend;
use rustflexstack::security::sign_service::SignService;
use rustflexstack::security::sn_sap::{ReportVerify, SNSignRequest, SNVerifyRequest};
use rustflexstack::security::verify_service::{verify_message, VerifyEvent};

const ITS_AID_CAM_VAL: u64 = 36;

/// Build the security stack: load certificates, create backend, sign & verify
/// services.  Returns a `SignService` ready for use.
fn build_security_stack(at_index: usize) -> SignService {
    let cert_dir = Path::new("certs");

    // ── Load certificates ────────────────────────────────────────────────
    let root_bytes = fs::read(cert_dir.join("root_ca.cert"))
        .expect("root_ca.cert not found — run generate_certificate_chain first");
    let aa_bytes = fs::read(cert_dir.join("aa.cert"))
        .expect("aa.cert not found — run generate_certificate_chain first");

    let root_ca = Certificate::from_bytes(&root_bytes, None);
    let aa = Certificate::from_bytes(&aa_bytes, Some(root_ca.clone()));

    // Load both ATs — one is "ours", the other is a known peer
    let at1_cert_bytes = fs::read(cert_dir.join("at1.cert")).expect("at1.cert not found");
    let at2_cert_bytes = fs::read(cert_dir.join("at2.cert")).expect("at2.cert not found");

    let at1 = Certificate::from_bytes(&at1_cert_bytes, Some(aa.clone()));
    let at2 = Certificate::from_bytes(&at2_cert_bytes, Some(aa.clone()));

    // Load our private key
    let own_key_file = if at_index == 1 { "at1.key" } else { "at2.key" };
    let key_bytes = fs::read(cert_dir.join(own_key_file))
        .unwrap_or_else(|_| panic!("{} not found", own_key_file));

    // ── Create backend and import key ────────────────────────────────────
    let mut backend = EcdsaBackend::new();
    let key_id = backend.import_signing_key(&key_bytes);

    let own_cert = if at_index == 1 {
        at1.clone()
    } else {
        at2.clone()
    };
    let peer_cert = if at_index == 1 {
        at2.clone()
    } else {
        at1.clone()
    };

    // ── Build certificate library ────────────────────────────────────────
    let cert_library = CertificateLibrary::new(
        &backend,
        vec![root_ca],
        vec![aa],
        vec![own_cert.clone(), peer_cert],
    );

    // ── Create sign service and add own certificate ──────────────────────
    let mut sign_service = SignService::new(backend, cert_library);
    let own = OwnCertificate::new(own_cert, key_id);
    sign_service.add_own_certificate(own);

    sign_service
}

fn main() {
    // ── Parse arguments ──────────────────────────────────────────────────
    let args: Vec<String> = env::args().collect();
    let mut at_index: usize = 1;
    let mut gpsd_addr = "127.0.0.1:2947".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--at" => {
                i += 1;
                at_index = args[i].parse::<usize>().expect("--at must be 1 or 2");
                assert!(at_index == 1 || at_index == 2, "--at must be 1 or 2");
            }
            "--gpsd" => {
                i += 1;
                gpsd_addr = args[i].clone();
            }
            _ => {}
        }
        i += 1;
    }

    println!("=== Secured C-V2X CAM Sender/Receiver (SPS + GPSD) ===");
    println!("AT index: {}", at_index);
    println!("GPSD address: {}", gpsd_addr);

    // ── Build security stack ─────────────────────────────────────────────
    let sign_service = build_security_stack(at_index);
    println!(
        "Security stack loaded. Own AT HashedId8: {:02x?}",
        sign_service
            .cert_library
            .own_certificates
            .keys()
            .next()
            .unwrap()
    );

    let sign_service = Arc::new(Mutex::new(sign_service));

    // ── Generate a random locally-administered MAC ───────────────────────
    let mac = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
            ^ (at_index as u32 * 0x1234_5678);
        [
            0x02u8,
            (seed >> 24) as u8,
            (seed >> 16) as u8,
            (seed >> 8) as u8,
            seed as u8,
            at_index as u8,
        ]
    };
    println!(
        "MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // ── MIB ──────────────────────────────────────────────────────────────
    let mut mib = Mib::new();
    mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(mac));
    mib.itsGnBeaconServiceRetransmitTimer = 0;

    // ── GPSD Location Service ────────────────────────────────────────────
    let mut loc_svc = GpsdLocationService::new(&gpsd_addr);
    let gn_gps_rx = loc_svc.subscribe();
    let ca_gps_rx = loc_svc.subscribe();

    // ── Spawn GN router and BTP router ───────────────────────────────────
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    // ── Security middleware: TX path ─────────────────────────────────────
    //
    // Intercept packets from GN → link layer.  Sign the payload and wrap
    // in a secured GN packet with BasicNH::SecuredPacket.
    let (secured_ll_tx, secured_ll_rx) = mpsc::channel::<Vec<u8>>();
    let sign_svc_tx = Arc::clone(&sign_service);
    thread::spawn(move || {
        while let Ok(packet) = gn_to_ll_rx.recv() {
            if packet.len() < 4 {
                let _ = secured_ll_tx.send(packet);
                continue;
            }
            let bh_bytes: [u8; 4] = packet[0..4].try_into().unwrap();
            let bh = BasicHeader::decode(bh_bytes);

            match bh.nh {
                BasicNH::CommonHeader if packet.len() > 4 => {
                    let inner_payload = &packet[4..];

                    let request = SNSignRequest {
                        tbs_message: inner_payload.to_vec(),
                        its_aid: ITS_AID_CAM_VAL,
                        permissions: vec![],
                        generation_location: None,
                    };

                    let sec_message = {
                        let mut svc = sign_svc_tx.lock().unwrap();
                        svc.sign_request(&request).sec_message
                    };

                    let mut new_bh = bh;
                    new_bh.nh = BasicNH::SecuredPacket;
                    let secured_packet: Vec<u8> = new_bh
                        .encode()
                        .iter()
                        .copied()
                        .chain(sec_message.iter().copied())
                        .collect();
                    let _ = secured_ll_tx.send(secured_packet);
                }
                _ => {
                    let _ = secured_ll_tx.send(packet);
                }
            }
        }
    });

    // ── Wire Cv2xLinkLayer (reads from secured_ll_rx, post-signing) ─────
    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();
    let cv2x_ll = Cv2xLinkLayer::new(ll_to_gn_tx, secured_ll_rx);
    cv2x_ll.start();

    // ── Security middleware: RX path ─────────────────────────────────────
    //
    // Intercept packets from link layer → GN router.
    // If BasicNH::SecuredPacket, verify and extract, then forward
    // with BasicNH::CommonHeader.
    let gn_h_rx = gn_handle.clone();
    let sign_svc_rx = Arc::clone(&sign_service);
    thread::spawn(move || {
        while let Ok(packet) = ll_to_gn_rx.recv() {
            if packet.len() < 4 {
                gn_h_rx.send_incoming_packet(packet);
                continue;
            }
            let bh_bytes: [u8; 4] = packet[0..4].try_into().unwrap();
            let bh = BasicHeader::decode(bh_bytes);

            match bh.nh {
                BasicNH::SecuredPacket if packet.len() > 4 => {
                    let sec_message = &packet[4..];
                    let request = SNVerifyRequest {
                        message: sec_message.to_vec(),
                    };

                    let (confirm, _events) = {
                        let mut svc = sign_svc_rx.lock().unwrap();
                        let svc = &mut *svc;
                        let result = verify_message(&request, &svc.backend, &mut svc.cert_library);
                        for event in &result.1 {
                            match event {
                                VerifyEvent::UnknownAt(h8) => {
                                    svc.notify_unknown_at(h8);
                                }
                                VerifyEvent::InlineP2pcdRequest(h3s) => {
                                    svc.notify_inline_p2pcd_request(h3s);
                                }
                                VerifyEvent::ReceivedCaCertificate(cert) => {
                                    svc.notify_received_ca_certificate(cert.as_ref().clone());
                                }
                            }
                        }
                        result
                    };

                    if confirm.report == ReportVerify::Success {
                        println!(
                            "[SEC RX] Verified OK — ITS-AID={}, cert={:02x?}",
                            confirm.its_aid,
                            &confirm.certificate_id[..],
                        );
                        let mut new_bh = bh;
                        new_bh.nh = BasicNH::CommonHeader;
                        let plain_packet: Vec<u8> = new_bh
                            .encode()
                            .iter()
                            .copied()
                            .chain(confirm.plain_message.iter().copied())
                            .collect();
                        gn_h_rx.send_incoming_packet(plain_packet);
                    } else {
                        eprintln!("[SEC RX] Verification failed: {:?}", confirm.report);
                    }
                }
                _ => {
                    gn_h_rx.send_incoming_packet(packet);
                }
            }
        }
    });

    // ── GN → BTP ─────────────────────────────────────────────────────────
    let btp_h1 = btp_handle.clone();
    thread::spawn(move || {
        while let Ok(ind) = gn_to_btp_rx.recv() {
            btp_h1.send_gn_data_indication(ind);
        }
    });

    // ── BTP → GN ─────────────────────────────────────────────────────────
    let gn_h2 = gn_handle.clone();
    thread::spawn(move || {
        while let Ok(req) = btp_to_gn_rx.recv() {
            gn_h2.send_gn_data_request(req);
        }
    });

    // ── LocationService → GN position vector ─────────────────────────────
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

    // ── Local Dynamic Map ────────────────────────────────────────────────
    let ldm = LdmFacility::new(415_520_000, 21_340_000, 5_000.0);
    ldm.if_ldm_3
        .register_data_provider(RegisterDataProviderReq {
            application_id: ITS_AID_CAM,
        });
    ldm.if_ldm_4
        .register_data_consumer(RegisterDataConsumerReq {
            application_id: ITS_AID_CAM,
        });

    // ── CA Basic Service ─────────────────────────────────────────────────
    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let vehicle_data = VehicleData {
        station_id,
        ..VehicleData::default()
    };
    let (ca_svc, _cam_rx) =
        CooperativeAwarenessBasicService::new(btp_handle.clone(), vehicle_data, Some(ldm.clone()));
    ca_svc.start(ca_gps_rx);

    // ── LDM query printer ────────────────────────────────────────────────
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

    // ── Start GPSD location service (blocking — reads GPS forever) ───────
    println!("Starting GPSD location service — Ctrl+C to stop\n");
    loc_svc.start();

    // Keep main thread alive
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

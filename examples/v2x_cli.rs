// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! V2X CLI — comprehensive V2X node example (raw Ethernet link layer)
//!
//! Instantiates a full V2X stack with all available facilities services
//! (CAM, VAM, DENM) and provides command-line options to configure:
//!
//! - **Sending**: transmit CAMs or VAMs (or run receive-only)
//! - **Security**: enable ETSI TS 103 097 packet signing and verification
//! - **GPS source**: static coordinates or real GPSD
//! - **Link layer**: raw Ethernet (see `v2x_cli_cv2x` for C-V2X variant)
//!
//! All three facilities services are always instantiated for reception:
//! - CAM on BTP port 2001 (with LDM storage)
//! - DENM on BTP port 2002
//! - VAM on BTP port 2018
//!
//! # Running
//! ```text
//! # Receive all message types on loopback:
//! sudo cargo run --example v2x_cli
//!
//! # Send CAMs on eth0 with security:
//! sudo cargo run --example v2x_cli -- -i eth0 --send cam --security --at 1
//!
//! # Send VAMs using real GPS:
//! sudo cargo run --example v2x_cli -- -i wlan0 --send vam --gpsd 127.0.0.1:2947
//! ```
//!
//! # Help
//! ```text
//! cargo run --example v2x_cli -- --help
//! ```

use std::env;
use std::fs;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustflexstack::btp::router::Router as BTPRouter;
use rustflexstack::facilities::ca_basic_service::{
    CooperativeAwarenessBasicService, VehicleData as CamVehicleData,
};
use rustflexstack::facilities::decentralized_environmental_notification_service::{
    DecentralizedEnvironmentalNotificationService, VehicleData as DenmVehicleData,
};
use rustflexstack::facilities::gpsd_location_service::GpsdLocationService;
use rustflexstack::facilities::local_dynamic_map::{
    ldm_constants::ITS_AID_CAM,
    ldm_storage::ItsDataObject,
    ldm_types::{RegisterDataConsumerReq, RegisterDataProviderReq, RequestDataObjectsReq},
    LdmFacility,
};
use rustflexstack::facilities::location_service::{GpsFix, LocationService};
use rustflexstack::facilities::vru_awareness_service::{DeviceData, VruAwarenessService};
use rustflexstack::geonet::basic_header::{BasicHeader, BasicNH};
use rustflexstack::geonet::gn_address::{GNAddress, M, MID, ST};
use rustflexstack::geonet::mib::Mib;
use rustflexstack::geonet::position_vector::LongPositionVector;
use rustflexstack::geonet::router::Router as GNRouter;
use rustflexstack::link_layer::raw_link_layer::RawLinkLayer;

use rustflexstack::security::certificate::{Certificate, OwnCertificate};
use rustflexstack::security::certificate_library::CertificateLibrary;
use rustflexstack::security::ecdsa_backend::EcdsaBackend;
use rustflexstack::security::sign_service::SignService;
use rustflexstack::security::sn_sap::{ReportVerify, SNSignRequest, SNVerifyRequest};
use rustflexstack::security::verify_service::{verify_message, VerifyEvent};

fn print_help() {
    eprintln!(
        r#"v2x_cli — comprehensive V2X node (raw Ethernet link layer)

USAGE:
    v2x_cli [OPTIONS]

OPTIONS:
    -i, --iface <NAME>     Network interface [default: lo]
    --send <cam|vam>       Transmit CAMs or VAMs [default: receive-only]
    --security             Enable ETSI TS 103 097 signing/verification
    --at <1|2>             Authorization Ticket index [default: 1]
    --certs-dir <PATH>     Certificate directory [default: certs/]
    --gpsd <ADDR>          Use real GPS from gpsd [e.g. 127.0.0.1:2947]
    --lat <DEG>            Static GPS latitude [default: 41.552]
    --lon <DEG>            Static GPS longitude [default: 2.134]
    -h, --help             Print this help

EXAMPLES:
    # Receive-only on loopback:
    sudo v2x_cli

    # Send CAMs with security on eth0:
    sudo v2x_cli -i eth0 --send cam --security --at 1

    # Send VAMs using real GPS:
    sudo v2x_cli -i wlan0 --send vam --gpsd 127.0.0.1:2947
"#
    );
}

/// Build the security stack: load certificates from `certs_dir`, create
/// ECDSA backend, certificate library, and sign service.
fn build_security_stack(at_index: usize, certs_dir: &str) -> SignService {
    let cert_dir = Path::new(certs_dir);

    let root_bytes = fs::read(cert_dir.join("root_ca.cert"))
        .expect("root_ca.cert not found — run generate_certificate_chain first");
    let aa_bytes = fs::read(cert_dir.join("aa.cert"))
        .expect("aa.cert not found — run generate_certificate_chain first");

    let root_ca = Certificate::from_bytes(&root_bytes, None);
    let aa = Certificate::from_bytes(&aa_bytes, Some(root_ca.clone()));

    let at1_cert_bytes = fs::read(cert_dir.join("at1.cert")).expect("at1.cert not found");
    let at2_cert_bytes = fs::read(cert_dir.join("at2.cert")).expect("at2.cert not found");

    let at1 = Certificate::from_bytes(&at1_cert_bytes, Some(aa.clone()));
    let at2 = Certificate::from_bytes(&at2_cert_bytes, Some(aa.clone()));

    let own_key_file = if at_index == 1 { "at1.key" } else { "at2.key" };
    let key_bytes = fs::read(cert_dir.join(own_key_file))
        .unwrap_or_else(|_| panic!("{} not found", own_key_file));

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

    let cert_library = CertificateLibrary::new(
        &backend,
        vec![root_ca],
        vec![aa],
        vec![own_cert.clone(), peer_cert],
    );

    let mut sign_service = SignService::new(backend, cert_library);
    let own = OwnCertificate::new(own_cert, key_id);
    sign_service.add_own_certificate(own);

    sign_service
}

/// Spawn the TX signing middleware thread.  Intercepts packets from the GN
/// router, signs CommonHeader payloads, and forwards to the link layer.
fn spawn_sign_middleware(
    gn_to_ll_rx: mpsc::Receiver<Vec<u8>>,
    secured_ll_tx: mpsc::Sender<Vec<u8>>,
    sign_service: Arc<Mutex<SignService>>,
    its_aid: u64,
) {
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
                        its_aid,
                        permissions: vec![],
                        generation_location: None,
                    };
                    let sec_message = {
                        let mut svc = sign_service.lock().unwrap();
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
}

/// Spawn the RX verification middleware thread.  Intercepts packets from the
/// link layer, verifies secured packets, and forwards to the GN router.
fn spawn_verify_middleware(
    ll_to_gn_rx: mpsc::Receiver<Vec<u8>>,
    gn_handle: rustflexstack::geonet::router::RouterHandle,
    sign_service: Arc<Mutex<SignService>>,
) {
    thread::spawn(move || {
        while let Ok(packet) = ll_to_gn_rx.recv() {
            if packet.len() < 4 {
                gn_handle.send_incoming_packet(packet);
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
                        let mut svc = sign_service.lock().unwrap();
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
                        gn_handle.send_incoming_packet(plain_packet);
                    } else {
                        eprintln!("[SEC RX] Verification failed: {:?}", confirm.report);
                    }
                }
                _ => {
                    gn_handle.send_incoming_packet(packet);
                }
            }
        }
    });
}

fn main() {
    // ── Parse arguments ──────────────────────────────────────────────────
    let args: Vec<String> = env::args().collect();
    let mut iface = "lo".to_string();
    let mut send_mode: Option<String> = None;
    let mut security = false;
    let mut at_index: usize = 1;
    let mut certs_dir = "certs".to_string();
    let mut use_gpsd = false;
    let mut gpsd_addr = "127.0.0.1:2947".to_string();
    let mut lat = 41.552_f64;
    let mut lon = 2.134_f64;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-i" | "--iface" => {
                i += 1;
                iface = args[i].clone();
            }
            "--send" => {
                i += 1;
                let mode = args[i].to_lowercase();
                assert!(
                    mode == "cam" || mode == "vam",
                    "--send must be 'cam' or 'vam'"
                );
                send_mode = Some(mode);
            }
            "--security" => {
                security = true;
            }
            "--at" => {
                i += 1;
                at_index = args[i].parse::<usize>().expect("--at must be 1 or 2");
                assert!(at_index == 1 || at_index == 2, "--at must be 1 or 2");
            }
            "--certs-dir" => {
                i += 1;
                certs_dir = args[i].clone();
            }
            "--gpsd" => {
                use_gpsd = true;
                // Optional address argument (peek ahead)
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    gpsd_addr = args[i].clone();
                }
            }
            "--lat" => {
                i += 1;
                lat = args[i].parse::<f64>().expect("--lat must be a number");
            }
            "--lon" => {
                i += 1;
                lon = args[i].parse::<f64>().expect("--lon must be a number");
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // ── Banner ───────────────────────────────────────────────────────────
    println!("=== V2X CLI (raw Ethernet link layer) ===");
    println!("Interface:  {}", iface);
    println!(
        "Send mode:  {}",
        send_mode.as_deref().unwrap_or("receive-only")
    );
    println!(
        "Security:   {}",
        if security { "enabled" } else { "disabled" }
    );
    if security {
        println!("  AT index: {}", at_index);
        println!("  Certs:    {}/", certs_dir);
    }
    if use_gpsd {
        println!("GPS source: gpsd ({})", gpsd_addr);
    } else {
        println!("GPS source: static ({:.6}, {:.6})", lat, lon);
    }
    println!("Services:   CAM (rx) + DENM (rx) + VAM (rx)");
    println!();

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
            0xF0,
        ]
    };
    println!(
        "MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // ── MIB ──────────────────────────────────────────────────────────────
    let station_type = match send_mode.as_deref() {
        Some("vam") => ST::Cyclist,
        _ => ST::PassengerCar,
    };
    let mut mib = Mib::new();
    mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, station_type, MID::new(mac));
    mib.itsGnBeaconServiceRetransmitTimer = 0;

    // ── Location Service ─────────────────────────────────────────────────
    let gn_gps_rx;
    let cam_gps_rx: Option<mpsc::Receiver<GpsFix>>;
    let vam_gps_rx: Option<mpsc::Receiver<GpsFix>>;
    let ldm_gps_rx;
    let mut static_loc_svc: Option<LocationService> = None;

    if use_gpsd {
        let mut svc = GpsdLocationService::new(&gpsd_addr);
        gn_gps_rx = svc.subscribe();
        ldm_gps_rx = svc.subscribe();
        cam_gps_rx = if send_mode.as_deref() == Some("cam") {
            Some(svc.subscribe())
        } else {
            None
        };
        vam_gps_rx = if send_mode.as_deref() == Some("vam") {
            Some(svc.subscribe())
        } else {
            None
        };
        svc.start();
    } else {
        let mut svc = LocationService::new();
        gn_gps_rx = svc.subscribe();
        ldm_gps_rx = svc.subscribe();
        cam_gps_rx = if send_mode.as_deref() == Some("cam") {
            Some(svc.subscribe())
        } else {
            None
        };
        vam_gps_rx = if send_mode.as_deref() == Some("vam") {
            Some(svc.subscribe())
        } else {
            None
        };
        static_loc_svc = Some(svc);
    }

    // ── Spawn GN + BTP routers ───────────────────────────────────────────
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);

    // ── Link layer + optional security middleware ────────────────────────
    let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();
    let ll_tx_source: mpsc::Receiver<Vec<u8>>;

    if security {
        let sign_service = build_security_stack(at_index, &certs_dir);
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

        let its_aid: u64 = match send_mode.as_deref() {
            Some("vam") => 638,
            _ => 36,
        };

        // TX: GN → sign → link layer
        let (secured_ll_tx, secured_ll_rx) = mpsc::channel::<Vec<u8>>();
        spawn_sign_middleware(
            gn_to_ll_rx,
            secured_ll_tx,
            Arc::clone(&sign_service),
            its_aid,
        );
        ll_tx_source = secured_ll_rx;

        // RX: link layer → verify → GN
        spawn_verify_middleware(ll_to_gn_rx, gn_handle.clone(), Arc::clone(&sign_service));
    } else {
        ll_tx_source = gn_to_ll_rx;

        // RX: link layer → GN (direct)
        let gn_h_rx = gn_handle.clone();
        thread::spawn(move || {
            while let Ok(pkt) = ll_to_gn_rx.recv() {
                gn_h_rx.send_incoming_packet(pkt);
            }
        });
    }

    // Wire link layer
    let raw_ll = RawLinkLayer::new(ll_to_gn_tx, ll_tx_source, &iface, mac);
    raw_ll.start();

    // ── GN ↔ BTP bridging ────────────────────────────────────────────────
    let btp_h1 = btp_handle.clone();
    thread::spawn(move || {
        while let Ok(ind) = gn_to_btp_rx.recv() {
            btp_h1.send_gn_data_indication(ind);
        }
    });

    let gn_h2 = gn_handle.clone();
    thread::spawn(move || {
        while let Ok(req) = btp_to_gn_rx.recv() {
            gn_h2.send_gn_data_request(req);
        }
    });

    // ── GPS → GN position vector ─────────────────────────────────────────
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

    // ── Local Dynamic Map (for CAMs) ─────────────────────────────────────
    let ldm = LdmFacility::new((lat * 1e7) as i32, (lon * 1e7) as i32, 5_000.0);
    ldm.if_ldm_3
        .register_data_provider(RegisterDataProviderReq {
            application_id: ITS_AID_CAM,
        });
    ldm.if_ldm_4
        .register_data_consumer(RegisterDataConsumerReq {
            application_id: ITS_AID_CAM,
        });

    // ── GPS → LDM area centre ────────────────────────────────────────────
    let ldm_center = ldm.area_center.clone();
    thread::spawn(move || {
        while let Ok(fix) = ldm_gps_rx.recv() {
            ldm_center.update((fix.latitude * 1e7) as i32, (fix.longitude * 1e7) as i32);
        }
    });

    // ── Facilities services ──────────────────────────────────────────────
    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let station_type_num: u8 = match send_mode.as_deref() {
        Some("vam") => 2,
        _ => 5,
    };

    // CAM service — always active for RX; TX if --send cam
    let cam_gps = cam_gps_rx.unwrap_or_else(|| {
        let (_, rx) = mpsc::channel::<GpsFix>();
        rx // sender dropped → TX thread exits immediately
    });
    let cam_vehicle_data = CamVehicleData {
        station_id,
        ..CamVehicleData::default()
    };
    let (ca_svc, _cam_rx) = CooperativeAwarenessBasicService::new(
        btp_handle.clone(),
        cam_vehicle_data,
        Some(ldm.clone()),
    );
    ca_svc.start(cam_gps);

    // DENM service — always active for RX (RX starts in new())
    let denm_vehicle_data = DenmVehicleData {
        station_id,
        station_type: station_type_num,
    };
    let (_den_svc, denm_rx) =
        DecentralizedEnvironmentalNotificationService::new(btp_handle.clone(), denm_vehicle_data);

    // VAM service — always active for RX; TX if --send vam
    let vam_gps = vam_gps_rx.unwrap_or_else(|| {
        let (_, rx) = mpsc::channel::<GpsFix>();
        rx
    });
    let device_data = DeviceData {
        station_id,
        station_type: station_type_num,
    };
    let (vru_svc, vam_rx) = VruAwarenessService::new(btp_handle.clone(), device_data);
    vru_svc.start(vam_gps);

    // ── LDM query printer (CAMs) ─────────────────────────────────────────
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
        if !resp.data_objects.is_empty() {
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
                        "  [CAM] record={:>5} station={:>10}  lat={:.5}  lon={:.5}",
                        entry.record_id, cam.header.station_id.0, lat, lon,
                    );
                }
            }
        }
    });

    // ── DENM printer ─────────────────────────────────────────────────────
    thread::spawn(move || {
        while let Ok(denm) = denm_rx.recv() {
            let lat = denm.denm.management.event_position.latitude.0 as f64 / 1e7;
            let lon = denm.denm.management.event_position.longitude.0 as f64 / 1e7;
            let seq = denm.denm.management.action_id.sequence_number.0;
            println!(
                "[DENM RX] station={:>10}  seq={:>5}  lat={:.5}  lon={:.5}",
                denm.header.station_id.0, seq, lat, lon,
            );
        }
    });

    // ── VAM printer ──────────────────────────────────────────────────────
    thread::spawn(move || {
        while let Ok(vam) = vam_rx.recv() {
            let lat = vam
                .vam
                .vam_parameters
                .basic_container
                .reference_position
                .latitude
                .0 as f64
                / 1e7;
            let lon = vam
                .vam
                .vam_parameters
                .basic_container
                .reference_position
                .longitude
                .0 as f64
                / 1e7;
            println!(
                "[VAM RX]  station={:>10}  lat={:.5}  lon={:.5}",
                vam.header.0.station_id.0, lat, lon,
            );
        }
    });

    // ── Start GPS ────────────────────────────────────────────────────────
    thread::sleep(Duration::from_millis(100));

    if let Some(mut loc_svc) = static_loc_svc {
        println!("Publishing static GPS fixes @ 10 Hz — Ctrl+C to stop\n");
        loop {
            thread::sleep(Duration::from_millis(100));
            loc_svc.publish(GpsFix {
                latitude: lat,
                longitude: lon,
                altitude_m: 120.0,
                speed_mps: 0.0,
                heading_deg: 0.0,
                pai: true,
            });
        }
    } else {
        println!("GPSD location service active — Ctrl+C to stop\n");
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
}

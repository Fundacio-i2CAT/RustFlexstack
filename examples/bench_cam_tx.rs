// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Benchmark: Maximum CAM TX throughput.
//!
//! Sends CAM packets as fast as possible (100 ms ETSI rate-limiter bypassed)
//! and reports packets/s and UPER encode latency per packet in µs.
//!
//! # Usage
//! ```text
//! sudo cargo run --release --example bench_cam_tx -- [interface] [duration_s]
//! # defaults: lo, 10 s
//! ```

use rustflexstack::btp::router::{BTPRouterHandle, Router as BTPRouter};
use rustflexstack::btp::service_access_point::BTPDataRequest;
use rustflexstack::facilities::ca_basic_service::cam_coder::{
    cam_header, generation_delta_time_now, AccelerationComponent, AccelerationConfidence,
    AccelerationValue, Altitude, AltitudeConfidence, AltitudeValue, BasicContainer,
    BasicVehicleContainerHighFrequency, Cam, CamCoder, CamParameters, CamPayload, Curvature,
    CurvatureCalculationMode, CurvatureConfidence, CurvatureValue, DriveDirection, Heading,
    HeadingConfidence, HeadingValue, HighFrequencyContainer, Latitude, Longitude,
    PositionConfidenceEllipse, ReferencePositionWithConfidence, SemiAxisLength, Speed,
    SpeedConfidence, SpeedValue, TrafficParticipantType, VehicleLength,
    VehicleLengthConfidenceIndication, VehicleLengthValue, VehicleWidth, Wgs84AngleValue, YawRate,
    YawRateConfidence, YawRateValue,
};
use rustflexstack::geonet::gn_address::{GNAddress, M, MID, ST};
use rustflexstack::geonet::mib::Mib;
use rustflexstack::geonet::position_vector::LongPositionVector;
use rustflexstack::geonet::router::{Router as GNRouter, RouterHandle};
use rustflexstack::geonet::service_access_point::{
    Area, CommonNH, CommunicationProfile, GNDataIndication, GNDataRequest, HeaderSubType,
    HeaderType, PacketTransportType, TopoBroadcastHST, TrafficClass,
};
use rustflexstack::link_layer::raw_link_layer::RawLinkLayer;
use rustflexstack::security::sn_sap::SecurityProfile;

use std::env;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    let duration_s = env::args()
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10);

    println!("=== Benchmark: Maximum CAM TX throughput ===");
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

    // Seed GN position vector so packets are accepted downstream.
    let mut epv = LongPositionVector::decode([0u8; 24]);
    epv.update_from_gps(41.552, 2.134, 0.0, 0.0, true);
    gn_handle.update_position_vector(epv);
    thread::sleep(Duration::from_millis(50));

    // ── Coder + template CAM ──────────────────────────────────────────────────
    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    let coder = CamCoder::new();
    let template = make_cam(station_id);

    // ── Benchmark loop ────────────────────────────────────────────────────────
    println!("Sending CAMs as fast as possible…\n");
    println!(
        "{:>7}  {:>10}  {:>12}  {:>12}",
        "time(s)", "total_sent", "rate(pkt/s)", "avg_enc(µs)"
    );

    let mut total_sent: u64 = 0;
    let mut total_enc_us: u128 = 0;
    let bench_start = Instant::now();
    let bench_end = bench_start + Duration::from_secs(duration_s);
    let mut win_start = Instant::now();
    let mut win_sent: u64 = 0;

    while Instant::now() < bench_end {
        let t0 = Instant::now();
        let data = match coder.encode(&template) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[TX] Encode error: {e}");
                continue;
            }
        };
        let enc_us = t0.elapsed().as_micros();

        btp_handle.send_btp_data_request(cam_btp_request(data));

        total_sent += 1;
        total_enc_us += enc_us;
        win_sent += 1;

        let win_elapsed = win_start.elapsed();
        if win_elapsed >= Duration::from_secs(1) {
            let pps = win_sent as f64 / win_elapsed.as_secs_f64();
            let avg_enc = total_enc_us / total_sent.max(1) as u128;
            println!(
                "{:>7.1}  {:>10}  {:>12.1}  {:>12}",
                bench_start.elapsed().as_secs_f64(),
                total_sent,
                pps,
                avg_enc
            );
            win_start = Instant::now();
            win_sent = 0;
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    let elapsed = bench_start.elapsed().as_secs_f64();
    let avg_rate = total_sent as f64 / elapsed;
    let avg_encode = total_enc_us / total_sent.max(1) as u128;

    println!();
    println!("=== CAM TX Results ===");
    println!("  Total sent      : {total_sent}");
    println!("  Elapsed         : {elapsed:.3} s");
    println!("  Average rate    : {avg_rate:.1} pkt/s");
    println!("  Avg encode time : {avg_encode} µs");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_cam(station_id: u32) -> Cam {
    let hf = BasicVehicleContainerHighFrequency::new(
        Heading::new(HeadingValue(900), HeadingConfidence(127)),
        Speed::new(SpeedValue(0), SpeedConfidence(127)),
        DriveDirection::unavailable,
        VehicleLength::new(
            VehicleLengthValue(1023),
            VehicleLengthConfidenceIndication::unavailable,
        ),
        VehicleWidth(62),
        AccelerationComponent::new(AccelerationValue(161), AccelerationConfidence(102)),
        Curvature::new(CurvatureValue(1023), CurvatureConfidence::unavailable),
        CurvatureCalculationMode::unavailable,
        YawRate::new(YawRateValue(32767), YawRateConfidence::unavailable),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    Cam::new(
        cam_header(station_id),
        CamPayload::new(
            generation_delta_time_now(),
            CamParameters::new(
                BasicContainer::new(
                    TrafficParticipantType(5),
                    ReferencePositionWithConfidence::new(
                        Latitude(415_520_000),
                        Longitude(21_340_000),
                        PositionConfidenceEllipse::new(
                            SemiAxisLength(4095),
                            SemiAxisLength(4095),
                            Wgs84AngleValue(3601),
                        ),
                        Altitude::new(AltitudeValue(12000), AltitudeConfidence::unavailable),
                    ),
                ),
                HighFrequencyContainer::basicVehicleContainerHighFrequency(hf),
                None,
                None,
                None,
            ),
        ),
    )
}

fn cam_btp_request(data: Vec<u8>) -> BTPDataRequest {
    BTPDataRequest {
        btp_type: CommonNH::BtpB,
        source_port: 0,
        destination_port: 2001,
        destination_port_info: 0,
        gn_packet_transport_type: PacketTransportType {
            header_type: HeaderType::Tsb,
            header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
        },
        gn_destination_address: GNAddress {
            m: M::GnMulticast,
            st: ST::Unknown,
            mid: MID::new([0xFF; 6]),
        },
        communication_profile: CommunicationProfile::Unspecified,
        gn_area: Area {
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
        },
        traffic_class: TrafficClass {
            scf: false,
            channel_offload: false,
            tc_id: 0,
        },
        security_profile: SecurityProfile::NoSecurity,
        its_aid: 36,
        security_permissions: vec![],
        gn_max_hop_limit: 1,
        gn_max_packet_lifetime: None,
        gn_repetition_interval: None,
        gn_max_repetition_time: None,
        destination: None,
        length: data.len() as u16,
        data,
    }
}

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
        0xBB,
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

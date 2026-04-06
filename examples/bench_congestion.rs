// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Benchmark: Congested-scenario TX + RX throughput.
//!
//! Transmits simultaneously:
//!   - 10 CAMs/s  (BTP port 2001, TSB/SingleHop)
//!   - 10 VAMs/s  (BTP port 2018, TSB/SingleHop)
//!   -  5 DENMs/s (BTP port 2002, GeoBroadcast-Circle) via DEN service
//!
//! Concurrently receives and decodes all three message types, counting successes
//! and decode latency.  A 1 Hz stats thread prints running totals.
//!
//! # Usage
//! ```text
//! sudo cargo run --release --example bench_congestion -- [interface] [duration_s]
//! # defaults: lo, 30 s
//! ```

use rustflexstack::btp::router::{BTPRouterHandle, Router as BTPRouter};
use rustflexstack::btp::service_access_point::{BTPDataIndication, BTPDataRequest};
use rustflexstack::facilities::ca_basic_service::cam_coder::{
    cam_header, generation_delta_time_now as cam_gdt, AccelerationComponent,
    AccelerationConfidence, AccelerationValue, Altitude, AltitudeConfidence, AltitudeValue,
    BasicContainer, BasicVehicleContainerHighFrequency, Cam, CamCoder, CamParameters, CamPayload,
    Curvature, CurvatureCalculationMode, CurvatureConfidence, CurvatureValue, DriveDirection,
    Heading, HeadingConfidence, HeadingValue, HighFrequencyContainer, Latitude, Longitude,
    PositionConfidenceEllipse, ReferencePositionWithConfidence, SemiAxisLength, Speed,
    SpeedConfidence, SpeedValue, TrafficParticipantType, VehicleLength,
    VehicleLengthConfidenceIndication, VehicleLengthValue, VehicleWidth, Wgs84AngleValue, YawRate,
    YawRateConfidence, YawRateValue,
};
use rustflexstack::facilities::decentralized_environmental_notification_service::denm_coder::CauseCodeChoice;
use rustflexstack::facilities::decentralized_environmental_notification_service::{
    denm_coder::AccidentSubCauseCode, DENRequest, DecentralizedEnvironmentalNotificationService,
    DenmCoder, VehicleData as DenVehicleData,
};
use rustflexstack::facilities::vru_awareness_service::vam_coder::{
    generation_delta_time_now as vam_gdt, vam_header, AccelerationConfidence as VamAccelConf,
    Altitude as VamAlt, AltitudeConfidence as VamAltConf, AltitudeValue as VamAltVal,
    BasicContainer as VamBasicContainer, Latitude as VamLat, Longitude as VamLon,
    LongitudinalAcceleration as VamLongAccel, LongitudinalAccelerationValue as VamLongAccelVal,
    PositionConfidenceEllipse as VamPCE, ReferencePositionWithConfidence as VamRefPos,
    SemiAxisLength as VamSAL, Speed as VamSpeed, SpeedConfidence as VamSpeedConf,
    SpeedValue as VamSpeedVal, TrafficParticipantType as VamTPT, Vam, VamCoder, VamParameters,
    VruAwareness, VruHighFrequencyContainer, Wgs84Angle as VamWgs84Angle,
    Wgs84AngleConfidence as VamWgs84AnglConf, Wgs84AngleValue as VamWgs84AngleVal,
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
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    let duration_s = env::args()
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);

    println!("=== Benchmark: Congested scenario (CAM + VAM + DENM) ===");
    println!("Interface : {iface}");
    println!("Duration  : {duration_s} s");
    println!("TX target : 10 CAM/s  10 VAM/s  5 DENM/s\n");

    // ── MAC / MIB ─────────────────────────────────────────────────────────────
    let mac = random_mac();
    let mut mib = Mib::new();
    mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(mac));
    mib.itsGnBeaconServiceRetransmitTimer = 0;

    let station_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);

    // ── Routers + link layer ──────────────────────────────────────────────────
    let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib.clone(), None, None, None);
    let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib.clone());

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

    // ── DEN service (single instance for both TX and RX) ─────────────────────
    let vd = DenVehicleData {
        station_id,
        station_type: 5,
    };
    let (den_svc, denm_rx) =
        DecentralizedEnvironmentalNotificationService::new(btp_handle.clone(), vd);

    // ── Shared atomic counters ────────────────────────────────────────────────
    let cam_tx = Arc::new(AtomicU64::new(0));
    let vam_tx = Arc::new(AtomicU64::new(0));
    let denm_tx = Arc::new(AtomicU64::new(0));
    let cam_rx = Arc::new(AtomicU64::new(0));
    let vam_rx = Arc::new(AtomicU64::new(0));
    let denm_rx_cnt = Arc::new(AtomicU64::new(0));
    let rx_err = Arc::new(AtomicU64::new(0));
    let cam_dec_us_total = Arc::new(AtomicU64::new(0));
    let vam_dec_us_total = Arc::new(AtomicU64::new(0));

    let bench_end = Instant::now() + Duration::from_secs(duration_s);

    // ── CAM TX thread (100 ms interval → 10 Hz) ───────────────────────────────
    {
        let btp = btp_handle.clone();
        let cnt = cam_tx.clone();
        let end = bench_end;
        let coder = CamCoder::new();
        let tmpl = make_cam(station_id);
        thread::spawn(move || {
            while Instant::now() < end {
                let t0 = Instant::now();
                if let Ok(data) = coder.encode(&tmpl) {
                    btp.send_btp_data_request(cam_btp_request(data));
                    cnt.fetch_add(1, Ordering::Relaxed);
                }
                let elapsed = t0.elapsed();
                if elapsed < Duration::from_millis(100) {
                    thread::sleep(Duration::from_millis(100) - elapsed);
                }
            }
        });
    }

    // ── VAM TX thread (100 ms interval → 10 Hz) ───────────────────────────────
    {
        let btp = btp_handle.clone();
        let cnt = vam_tx.clone();
        let end = bench_end;
        let coder = VamCoder::new();
        let tmpl = make_vam(station_id);
        thread::spawn(move || {
            while Instant::now() < end {
                let t0 = Instant::now();
                if let Ok(data) = coder.encode(&tmpl) {
                    btp.send_btp_data_request(vam_btp_request(data));
                    cnt.fetch_add(1, Ordering::Relaxed);
                }
                let elapsed = t0.elapsed();
                if elapsed < Duration::from_millis(100) {
                    thread::sleep(Duration::from_millis(100) - elapsed);
                }
            }
        });
    }

    // ── DENM TX (via DEN service at 5 Hz for entire duration) ────────────────
    {
        let cnt = denm_tx.clone();
        let total_ms = duration_s * 1000 + 500;
        let den = den_svc;
        // Count: spawn a watcher that checks every 200 ms how many intervals fired.
        // Simpler: trigger once with interval=200 ms, increment counter in a
        // separate thread counting 200 ms ticks.
        thread::spawn(move || {
            den.trigger_denm(DENRequest {
                event_latitude: 41.552,
                event_longitude: 2.134,
                event_altitude_m: 50.0,
                cause_code: CauseCodeChoice::accident2(AccidentSubCauseCode(0)),
                information_quality: 3,
                event_speed_raw: 16383,
                event_heading_raw: 3601,
                denm_interval_ms: 200, // 5 Hz
                time_period_ms: total_ms,
                relevance_radius_m: 1000,
            });
            // Approximate TX count: 1 DENM every 200 ms.
            let end = Instant::now() + Duration::from_millis(total_ms);
            while Instant::now() < end {
                thread::sleep(Duration::from_millis(200));
                cnt.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    // ── CAM RX thread ─────────────────────────────────────────────────────────
    {
        let (cam_ind_tx, cam_ind_rx) = mpsc::channel::<BTPDataIndication>();
        btp_handle.register_port(2001, cam_ind_tx);
        let cnt = cam_rx.clone();
        let err = rx_err.clone();
        let dec_sum = cam_dec_us_total.clone();
        let end = bench_end;
        thread::spawn(move || {
            let coder = CamCoder::new();
            loop {
                let now = Instant::now();
                if now >= end {
                    break;
                }
                let timeout = (end - now).min(Duration::from_millis(500));
                match cam_ind_rx.recv_timeout(timeout) {
                    Ok(ind) => {
                        let t0 = Instant::now();
                        match coder.decode(&ind.data) {
                            Ok(_) => {
                                cnt.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                err.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        dec_sum.fetch_add(t0.elapsed().as_micros() as u64, Ordering::Relaxed);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
    }

    // ── VAM RX thread ─────────────────────────────────────────────────────────
    {
        let (vam_ind_tx, vam_ind_rx) = mpsc::channel::<BTPDataIndication>();
        btp_handle.register_port(2018, vam_ind_tx);
        let cnt = vam_rx.clone();
        let err = rx_err.clone();
        let dec_sum = vam_dec_us_total.clone();
        let end = bench_end;
        thread::spawn(move || {
            let coder = VamCoder::new();
            loop {
                let now = Instant::now();
                if now >= end {
                    break;
                }
                let timeout = (end - now).min(Duration::from_millis(500));
                match vam_ind_rx.recv_timeout(timeout) {
                    Ok(ind) => {
                        let t0 = Instant::now();
                        match coder.decode(&ind.data) {
                            Ok(_) => {
                                cnt.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                err.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        dec_sum.fetch_add(t0.elapsed().as_micros() as u64, Ordering::Relaxed);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
    }

    // ── DENM RX thread ────────────────────────────────────────────────────────
    {
        let cnt = denm_rx_cnt.clone();
        let end = bench_end;
        thread::spawn(move || loop {
            let now = Instant::now();
            if now >= end {
                break;
            }
            let timeout = (end - now).min(Duration::from_millis(500));
            match denm_rx.recv_timeout(timeout) {
                Ok(_) => {
                    cnt.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        });
    }

    // ── 1 Hz stats printer (main thread) ─────────────────────────────────────
    println!(
        "{:>6}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}",
        "t(s)",
        "cam_tx",
        "cam_rx",
        "cam_dec_µs",
        "vam_tx",
        "vam_rx",
        "vam_dec_µs",
        "den_tx",
        "den_rx",
        "rx_err",
    );

    let mut prev_cam_rx: u64 = 0;
    let mut prev_vam_rx: u64 = 0;
    let mut prev_denm_rx: u64 = 0;

    let bench_start = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(1));
        let t = bench_start.elapsed().as_secs_f64();
        if t >= duration_s as f64 + 1.5 {
            break;
        }

        let ctx = cam_tx.load(Ordering::Relaxed);
        let crx = cam_rx.load(Ordering::Relaxed);
        let vtx = vam_tx.load(Ordering::Relaxed);
        let vrx = vam_rx.load(Ordering::Relaxed);
        let dtx = denm_tx.load(Ordering::Relaxed);
        let drx = denm_rx_cnt.load(Ordering::Relaxed);
        let errs = rx_err.load(Ordering::Relaxed);
        let cdu = cam_dec_us_total.load(Ordering::Relaxed);
        let vdu = vam_dec_us_total.load(Ordering::Relaxed);

        let cam_dec_avg = if crx > 0 { cdu / crx } else { 0 };
        let vam_dec_avg = if vrx > 0 { vdu / vrx } else { 0 };

        let cam_rx_rate = (crx - prev_cam_rx) as f64;
        let vam_rx_rate = (vrx - prev_vam_rx) as f64;
        let denm_rx_rate = (drx - prev_denm_rx) as f64;
        prev_cam_rx = crx;
        prev_vam_rx = vrx;
        prev_denm_rx = drx;

        println!(
            "{:>6.1}  {:>8}  {:>8.1}  {:>10}  {:>8}  {:>8.1}  {:>10}  {:>8}  {:>8.1}  {:>8}",
            t,
            ctx,
            cam_rx_rate,
            cam_dec_avg,
            vtx,
            vam_rx_rate,
            vam_dec_avg,
            dtx,
            denm_rx_rate,
            errs,
        );

        if t > duration_s as f64 {
            break;
        }
    }

    // ── Final summary ─────────────────────────────────────────────────────────
    let elapsed = bench_start.elapsed().as_secs_f64();

    let ctx = cam_tx.load(Ordering::Relaxed);
    let crx = cam_rx.load(Ordering::Relaxed);
    let vtx = vam_tx.load(Ordering::Relaxed);
    let vrx = vam_rx.load(Ordering::Relaxed);
    let dtx = denm_tx.load(Ordering::Relaxed);
    let drx = denm_rx_cnt.load(Ordering::Relaxed);
    let errs = rx_err.load(Ordering::Relaxed);
    let cdu = cam_dec_us_total.load(Ordering::Relaxed);
    let vdu = vam_dec_us_total.load(Ordering::Relaxed);

    let cam_dec_avg = if crx > 0 { cdu / crx } else { 0 };
    let vam_dec_avg = if vrx > 0 { vdu / vrx } else { 0 };

    let cam_ratio = if ctx > 0 {
        crx as f64 / ctx as f64 * 100.0
    } else {
        0.0
    };
    let vam_ratio = if vtx > 0 {
        vrx as f64 / vtx as f64 * 100.0
    } else {
        0.0
    };
    let denm_ratio = if dtx > 0 {
        drx as f64 / dtx as f64 * 100.0
    } else {
        0.0
    };

    println!();
    println!("=== Congestion Benchmark Results ({elapsed:.1} s) ===");
    println!();
    println!(
        "  CAM   TX: {ctx:>8}  RX: {crx:>8}  ratio: {cam_ratio:>6.1}%  avg_dec: {cam_dec_avg} µs"
    );
    println!(
        "  VAM   TX: {vtx:>8}  RX: {vrx:>8}  ratio: {vam_ratio:>6.1}%  avg_dec: {vam_dec_avg} µs"
    );
    println!("  DENM  TX: {dtx:>8}  RX: {drx:>8}  ratio: {denm_ratio:>6.1}%");
    println!("  RX errors: {errs}");
}

// ─── CAM helpers ─────────────────────────────────────────────────────────────

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
            cam_gdt(),
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

// ─── VAM helpers ─────────────────────────────────────────────────────────────

fn make_vam(station_id: u32) -> Vam {
    // VruHighFrequencyContainer::new takes 14 args:
    // heading, speed, longitudinal_acceleration,
    // curvature, curvature_calculation_mode, yaw_rate,
    // lateral_acceleration, vertical_acceleration,
    // vru_lane_position, environment, movement_control,
    // orientation, roll_angle, device_usage
    let hf = VruHighFrequencyContainer::new(
        VamWgs84Angle::new(VamWgs84AngleVal(3601), VamWgs84AnglConf(127)), // heading unavailable
        VamSpeed::new(VamSpeedVal(0), VamSpeedConf(127)),                  // speed 0
        VamLongAccel::new(VamLongAccelVal(161), VamAccelConf(102)),        // accel unavailable
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    Vam::new(
        vam_header(station_id),
        VruAwareness::new(
            vam_gdt(),
            VamParameters::new(
                VamBasicContainer::new(
                    VamTPT(1), // pedestrian
                    VamRefPos::new(
                        VamLat(415_520_000),
                        VamLon(21_340_000),
                        VamPCE::new(VamSAL(4095), VamSAL(4095), VamWgs84AngleVal(3601)),
                        VamAlt::new(VamAltVal(12000), VamAltConf::unavailable),
                    ),
                ),
                hf,
                None,
                None,
                None,
                None, // lf, cluster_info, cluster_op, motion_pred
            ),
        ),
    )
}

fn vam_btp_request(data: Vec<u8>) -> BTPDataRequest {
    BTPDataRequest {
        btp_type: CommonNH::BtpB,
        source_port: 0,
        destination_port: 2018,
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
        its_aid: 16513,
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

// ─── Shared helpers ───────────────────────────────────────────────────────────

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
        0xDD,
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

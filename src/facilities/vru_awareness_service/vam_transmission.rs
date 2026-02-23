// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! VAM Transmission Management.
//!
//! Mirrors `VAMTransmissionManagement` in
//! `flexstack/facilities/vru_awareness_service/vam_transmission_management.py`.
//!
//! [`VAMTransmissionManagement::spawn`] starts a background thread that:
//! 1. Waits for GPS fixes from a [`LocationService`] subscriber channel.
//! 2. Builds a VAM from the fix and the static device data.
//! 3. UPER-encodes the VAM via [`VamCoder`].
//! 4. Sends a [`BTPDataRequest`] on port 2018 via the BTP router handle.
//!
//! The transmission rate is capped at [`T_GEN_VAM_MIN`] = 100 ms (10 Hz) and
//! floored at [`T_GEN_VAM_MAX`] = 5 000 ms (0.2 Hz) per ETSI TS 103 300-3 §6.

use super::vam_coder::{
    generation_delta_time_now, vam_header, AccelerationConfidence, Altitude,
    AltitudeConfidence, AltitudeValue, BasicContainer, Latitude, Longitude,
    LongitudinalAcceleration, LongitudinalAccelerationValue,
    PositionConfidenceEllipse, ReferencePositionWithConfidence, SemiAxisLength,
    Speed, SpeedConfidence, SpeedValue, TrafficParticipantType, Vam, VamCoder,
    VamParameters, VruAwareness, VruHighFrequencyContainer, Wgs84Angle,
    Wgs84AngleConfidence, Wgs84AngleValue,
};
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataRequest;
use crate::facilities::location_service::GpsFix;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::service_access_point::{
    Area, CommunicationProfile, CommonNH, HeaderSubType, HeaderType, PacketTransportType,
    TopoBroadcastHST, TrafficClass,
};
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::{Duration, Instant};

// ─── Timing constants (ETSI TS 103 300-3 §6) ─────────────────────────────────

/// Minimum VAM generation interval: 100 ms (10 Hz maximum rate).
pub const T_GEN_VAM_MIN: Duration = Duration::from_millis(100);
/// Maximum VAM generation interval: 5 000 ms (0.2 Hz minimum rate).
pub const T_GEN_VAM_MAX: Duration = Duration::from_millis(5_000);

// ─── DeviceData ───────────────────────────────────────────────────────────────

/// Static device data used to populate every VAM.
///
/// Mirrors the `DeviceDataProvider` frozen dataclass in the Python
/// implementation (`vam_transmission_management.py`).
#[derive(Debug, Clone)]
pub struct DeviceData {
    /// ITS station ID (0–4 294 967 295).
    pub station_id: u32,
    /// ITS station type / traffic participant type (0–255).
    ///
    /// VRU-relevant values per ETSI TS 102 894-2:
    /// - 0 = unknown
    /// - 1 = pedestrian
    /// - 2 = cyclist
    /// - 3 = moped
    /// - 4 = motorcycle
    pub station_type: u8,
}

impl Default for DeviceData {
    /// Sensible defaults — cyclist, station_id 0.
    fn default() -> Self {
        DeviceData {
            station_id:   0,
            station_type: 2, // cyclist
        }
    }
}

// ─── VAM builder ──────────────────────────────────────────────────────────────

/// Build a complete [`Vam`] from a GPS fix and static device data.
fn build_vam(fix: &GpsFix, dd: &DeviceData) -> Vam {
    let gen_dt = generation_delta_time_now();

    // ── BasicContainer ────────────────────────────────────────────────────────
    let ref_pos = ReferencePositionWithConfidence::new(
        // Latitude: 1/10 µdeg, −900 000 000 .. 900 000 001 (unavail)
        Latitude(((fix.latitude * 1e7).round() as i32).clamp(-900_000_000, 900_000_000)),
        // Longitude: 1/10 µdeg, −1 800 000 000 .. 1 800 000 001 (unavail)
        Longitude(((fix.longitude * 1e7).round() as i32).clamp(-1_800_000_000, 1_800_000_000)),
        // PositionConfidenceEllipse — all axes unavailable
        PositionConfidenceEllipse::new(
            SemiAxisLength(4095), // semiMajorAxisLength unavailable
            SemiAxisLength(4095), // semiMinorAxisLength unavailable
            Wgs84AngleValue(3601), // semiMajorAxisOrientation unavailable
        ),
        // Altitude — value in 0.01 m, 800 001 = unavailable
        Altitude::new(
            AltitudeValue(
                ((fix.altitude_m * 100.0).round() as i32).clamp(-100_000, 800_000),
            ),
            AltitudeConfidence::unavailable,
        ),
    );

    let basic_container = BasicContainer::new(TrafficParticipantType(dd.station_type), ref_pos);

    // ── VruHighFrequencyContainer ─────────────────────────────────────────────
    // Wgs84AngleValue: 0.1°, 0–3 600 valid, 3 601 = unavailable
    // VAM uses Wgs84Angle for heading (not Heading like CAM)
    let heading_raw = ((fix.heading_deg * 10.0).round() as u16).clamp(0, 3600);
    let heading = Wgs84Angle::new(
        Wgs84AngleValue(heading_raw),
        Wgs84AngleConfidence(127), // 127 = unavailable
    );

    // SpeedValue: 0.01 m/s, 0–16 382 valid, 16 383 = unavailable
    // SpeedConfidence: 0.01 m/s, 1–125 valid, 127 = unavailable
    let speed = Speed::new(
        SpeedValue(((fix.speed_mps * 100.0).round() as u16).min(16_382)),
        SpeedConfidence(127), // unavailable
    );

    // LongitudinalAcceleration — OLD CDD style (not AccelerationComponent)
    // LongitudinalAccelerationValue: 0.1 m/s², −160..160 valid, 161 = unavailable
    // AccelerationConfidence: 0..100 valid, 102 = unavailable
    let longitudinal_acceleration = LongitudinalAcceleration::new(
        LongitudinalAccelerationValue(161), // unavailable
        AccelerationConfidence(102),        // unavailable
    );

    let hf = VruHighFrequencyContainer::new(
        heading,
        speed,
        longitudinal_acceleration,
        None, // curvature
        None, // curvatureCalculationMode
        None, // yawRate
        None, // lateralAcceleration
        None, // verticalAcceleration
        None, // vruLanePosition
        None, // environment
        None, // movementControl
        None, // orientation
        None, // rollAngle
        None, // deviceUsage
    );

    // ── Assemble VAM ──────────────────────────────────────────────────────────
    let vam_params = VamParameters::new(
        basic_container,
        hf,
        None, // vruLowFrequencyContainer
        None, // vruClusterInformationContainer
        None, // vruClusterOperationContainer
        None, // vruMotionPredictionContainer
    );

    Vam::new(
        vam_header(dd.station_id),
        VruAwareness::new(gen_dt, vam_params),
    )
}

// ─── VAMTransmissionManagement ───────────────────────────────────────────────

/// VAM Transmission Management.
///
/// Mirrors `VAMTransmissionManagement` in
/// `flexstack/facilities/vru_awareness_service/vam_transmission_management.py`.
pub struct VAMTransmissionManagement;

impl VAMTransmissionManagement {
    /// Spawn the transmission management thread.
    ///
    /// # Arguments
    /// * `btp_handle`  — handle to the BTP router for sending VAMs.
    /// * `coder`       — shared [`VamCoder`] instance.
    /// * `device_data` — static device parameters (station ID, type).
    /// * `gps_rx`      — GPS fix channel (from [`LocationService::subscribe`]).
    pub fn spawn(
        btp_handle:  BTPRouterHandle,
        coder:       VamCoder,
        device_data: DeviceData,
        gps_rx:      Receiver<GpsFix>,
    ) {
        thread::spawn(move || {
            let mut last_sent: Option<Instant> = None;

            while let Ok(fix) = gps_rx.recv() {
                let now = Instant::now();

                // Enforce T_GEN_VAM_MIN — skip if called too quickly.
                if let Some(last) = last_sent {
                    if now.duration_since(last) < T_GEN_VAM_MIN {
                        continue;
                    }
                }

                let vam = build_vam(&fix, &device_data);

                match coder.encode(&vam) {
                    Ok(data) => {
                        let req = BTPDataRequest {
                            btp_type: CommonNH::BtpB,
                            source_port: 0,
                            destination_port: 2018, // BTP port for VAM
                            destination_port_info: 0,
                            gn_packet_transport_type: PacketTransportType {
                                header_type: HeaderType::Tsb,
                                header_sub_type: HeaderSubType::TopoBroadcast(
                                    TopoBroadcastHST::SingleHop,
                                ),
                            },
                            gn_destination_address: GNAddress {
                                m:   M::GnMulticast,
                                st:  ST::Unknown,
                                mid: MID::new([0xFF; 6]),
                            },
                            communication_profile: CommunicationProfile::Unspecified,
                            gn_area: Area {
                                latitude:  0,
                                longitude: 0,
                                a: 0,
                                b: 0,
                                angle: 0,
                            },
                            traffic_class: TrafficClass {
                                scf:            false,
                                channel_offload: false,
                                tc_id:          0,
                            },
                            length: data.len() as u16,
                            data,
                        };
                        btp_handle.send_btp_data_request(req);
                        last_sent = Some(Instant::now());
                    }
                    Err(e) => eprintln!("[VAM TX] Encode error: {}", e),
                }
            }
            eprintln!("[VAM TX] GPS channel closed, thread exiting");
        });
    }
}

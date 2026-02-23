// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CAM Transmission Management.
//!
//! Mirrors `CAMTransmissionManagement` in
//! `flexstack/facilities/ca_basic_service/cam_transmission_management.py`.
//!
//! [`CAMTransmissionManagement::spawn`] starts a background thread that:
//! 1. Waits for GPS fixes from a [`LocationService`] subscriber channel.
//! 2. Builds a CAM from the fix and the static vehicle data.
//! 3. UPER-encodes the CAM via [`CamCoder`].
//! 4. Sends a [`BTPDataRequest`] on port 2001 via the BTP router handle.
//!
//! The transmission rate is capped at [`T_GEN_CAM_MIN`] = 100 ms (10 Hz) and
//! floored at [`T_GEN_CAM_MAX`] = 1 000 ms (1 Hz) per ETSI EN 302 637-2 §6.1.

use super::cam_coder::{
    cam_header, generation_delta_time_now, AccelerationComponent, AccelerationConfidence,
    AccelerationValue, Altitude, AltitudeConfidence, AltitudeValue, BasicContainer,
    BasicVehicleContainerHighFrequency, Cam, CamCoder, CamParameters, CamPayload, Curvature,
    CurvatureCalculationMode, CurvatureConfidence, CurvatureValue, DriveDirection,
    Heading, HeadingConfidence, HeadingValue, HighFrequencyContainer,
    Latitude, Longitude, PositionConfidenceEllipse, ReferencePositionWithConfidence,
    SemiAxisLength, Speed, SpeedConfidence, SpeedValue,
    TrafficParticipantType, VehicleLength, VehicleLengthConfidenceIndication,
    VehicleLengthValue, VehicleWidth, Wgs84AngleValue, YawRate, YawRateConfidence, YawRateValue,
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

// ─── Timing constants (ETSI EN 302 637-2 §6.1) ───────────────────────────────

/// Minimum CAM generation interval: 100 ms (10 Hz maximum rate).
pub const T_GEN_CAM_MIN: Duration = Duration::from_millis(100);
/// Maximum CAM generation interval: 1 000 ms (1 Hz minimum rate).
pub const T_GEN_CAM_MAX: Duration = Duration::from_millis(1_000);

// ─── VehicleData ─────────────────────────────────────────────────────────────

/// Static vehicle data used to populate every CAM.
///
/// Mirrors the `VehicleData` frozen dataclass in the Python implementation.
#[derive(Debug, Clone)]
pub struct VehicleData {
    /// ITS station ID (0–4 294 967 295).
    pub station_id: u32,
    /// ITS station type / traffic participant type (0–255).
    /// Common values: 0 = unknown, 5 = passengerCar, 6 = bus, 15 = roadSideUnit.
    pub station_type: u8,
    /// Drive direction (forward / backward / unavailable).
    pub drive_direction: DriveDirection,
    /// Vehicle length in 0.1 m units (1–1 022 valid; 1 023 = unavailable).
    pub vehicle_length_value: u16,
    /// Vehicle width in 0.1 m units (1–61 valid; 62 = unavailable).
    pub vehicle_width: u8,
}

impl Default for VehicleData {
    /// Sensible defaults — PassengerCar, all kinematic fields unavailable.
    fn default() -> Self {
        VehicleData {
            station_id:           0,
            station_type:         5, // passengerCar
            drive_direction:      DriveDirection::unavailable,
            vehicle_length_value: 1023,
            vehicle_width:        62,
        }
    }
}

// ─── CAM builder ─────────────────────────────────────────────────────────────

/// Build a complete [`Cam`] from a GPS fix and static vehicle data.
fn build_cam(fix: &GpsFix, vd: &VehicleData) -> Cam {
    let gen_dt = generation_delta_time_now();

    // ── BasicContainer ──────────────────────────────────────────────────────
    let ref_pos = ReferencePositionWithConfidence::new(
        // Latitude: 1/10 µdeg, −900 000 000 .. 900 000 001 (unavail)
        Latitude(((fix.latitude * 1e7).round() as i32).clamp(-900_000_000, 900_000_000)),
        // Longitude: 1/10 µdeg, −1 800 000 000 .. 1 800 000 001 (unavail)
        Longitude(((fix.longitude * 1e7).round() as i32).clamp(-1_800_000_000, 1_800_000_000)),
        // PositionConfidenceEllipse — all axes unavailable
        PositionConfidenceEllipse::new(
            SemiAxisLength(4095),      // semiMajorAxisLength unavailable
            SemiAxisLength(4095),      // semiMinorAxisLength unavailable
            Wgs84AngleValue(3601),     // semiMajorAxisOrientation unavailable
        ),
        // Altitude — value in 0.01 m, 800 001 = unavailable
        Altitude::new(
            AltitudeValue(
                ((fix.altitude_m * 100.0).round() as i32).clamp(-100_000, 800_000),
            ),
            AltitudeConfidence::unavailable,
        ),
    );

    let basic_container = BasicContainer::new(
        TrafficParticipantType(vd.station_type),
        ref_pos,
    );

    // ── BasicVehicleContainerHighFrequency ─────────────────────────────────
    // HeadingValue: 0.1°, 0–3 600 valid, 3 601 = unavailable
    let heading_value = HeadingValue(
        ((fix.heading_deg * 10.0).round() as u16).clamp(0, 3600),
    );
    // HeadingConfidence: 0.1°, 1–125 valid, 126 = outOfRange, 127 = unavailable
    let heading = Heading::new(heading_value, HeadingConfidence(127));

    // SpeedValue: 0.01 m/s, 0–16 382 valid, 16 383 = unavailable
    let speed_value = SpeedValue(((fix.speed_mps * 100.0).round() as u16).min(16_382));
    // SpeedConfidence: 0.01 m/s, 1–125 valid, 126 = outOfRange, 127 = unavailable
    let speed = Speed::new(speed_value, SpeedConfidence(127));

    // VehicleLength: 0.1 m, 1–1 022 valid, 1 023 = unavailable
    let vehicle_length = VehicleLength::new(
        VehicleLengthValue(vd.vehicle_length_value.clamp(1, 1023)),
        VehicleLengthConfidenceIndication::unavailable,
    );

    // VehicleWidth: 0.1 m, 1–61 valid, 62 = unavailable
    let vehicle_width = VehicleWidth(vd.vehicle_width.clamp(1, 62));

    // LongitudinalAcceleration → AccelerationComponent (CDD v2)
    // AccelerationValue: 0.1 m/s², −160..160 valid, 161 = unavailable
    // AccelerationConfidence: 0..100 valid (in 0.1 m/s²), 101 = outOfRange, 102 = unavailable
    let longitudinal_acceleration = AccelerationComponent::new(
        AccelerationValue(161),   // unavailable
        AccelerationConfidence(102), // unavailable
    );

    // Curvature: 0.0001 m⁻¹, −1 022..1 022 valid, 1 023 = unavailable
    let curvature = Curvature::new(
        CurvatureValue(1023),             // unavailable
        CurvatureConfidence::unavailable, // = 8
    );

    // YawRate: 0.01 °/s, −32 766..32 766 valid, 32 767 = unavailable
    // YawRateConfidence: enum, 8 = unavailable
    let yaw_rate = YawRate::new(
        YawRateValue(32767),              // unavailable
        YawRateConfidence::unavailable,   // = 8
    );

    let hf = BasicVehicleContainerHighFrequency::new(
        heading,
        speed,
        vd.drive_direction,
        vehicle_length,
        vehicle_width,
        longitudinal_acceleration,
        curvature,
        CurvatureCalculationMode::unavailable,
        yaw_rate,
        None, // accelerationControl
        None, // lanePosition
        None, // steeringWheelAngle
        None, // lateralAcceleration
        None, // verticalAcceleration
        None, // performanceClass
        None, // cenDsrcTollingZone
    );

    Cam::new(
        cam_header(vd.station_id),
        CamPayload::new(
            gen_dt,
            CamParameters::new(
                basic_container,
                HighFrequencyContainer::basicVehicleContainerHighFrequency(hf),
                None, // lowFrequencyContainer
                None, // specialVehicleContainer
                None, // extensionContainers
            ),
        ),
    )
}

// ─── CAMTransmissionManagement ───────────────────────────────────────────────

/// CAM Transmission Management.
pub struct CAMTransmissionManagement;

impl CAMTransmissionManagement {
    /// Spawn the transmission management thread.
    ///
    /// # Arguments
    /// * `btp_handle`   — handle to the BTP router for sending CAMs.
    /// * `coder`        — shared [`CamCoder`] instance.
    /// * `vehicle_data` — static vehicle parameters.
    /// * `gps_rx`       — GPS fix channel (from [`LocationService::subscribe`]).
    pub fn spawn(
        btp_handle:   BTPRouterHandle,
        coder:        CamCoder,
        vehicle_data: VehicleData,
        gps_rx:       Receiver<GpsFix>,
    ) {
        thread::spawn(move || {
            let mut last_sent: Option<Instant> = None;

            while let Ok(fix) = gps_rx.recv() {
                let now = Instant::now();

                // Enforce T_GEN_CAM_MIN — skip if called too quickly.
                if let Some(last) = last_sent {
                    if now.duration_since(last) < T_GEN_CAM_MIN {
                        continue;
                    }
                }

                let cam = build_cam(&fix, &vehicle_data);

                match coder.encode(&cam) {
                    Ok(data) => {
                        let req = BTPDataRequest {
                            btp_type: CommonNH::BtpB,
                            source_port: 0,
                            destination_port: 2001,
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
                    Err(e) => eprintln!("[CAM TX] Encode error: {}", e),
                }
            }
            eprintln!("[CAM TX] GPS channel closed, thread exiting");
        });
    }
}

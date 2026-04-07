// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! VAM Transmission Management — ETSI TS 103 300-3 V2.3.1 (2025-12).
//!
//! Mirrors `VAMTransmissionManagement` in
//! `flexstack/facilities/vru_awareness_service/vam_transmission_management.py`.
//!
//! Key behavioural properties:
//!   - Timer-based (T_CheckVamGen) architecture with condition evaluation (clause 6.4.1).
//!   - Triggering conditions: elapsed time (T_GenVamMax), position (4 m), speed (0.5 m/s),
//!     heading (4°).
//!   - VRU Low-Frequency Container included on first VAM, then every ≥ 2 000 ms (clause 6.2).
//!   - Security profile: VRU_AWARENESS_MESSAGE, ITS-AID: 638.

use super::vam_bindings::etsi_its_cdd::{VruProfileAndSubprofile, VruSubProfilePedestrian};
use super::vam_bindings::vam_pdu_descriptions::VruLowFrequencyContainer;
use super::vam_coder::{
    generation_delta_time_now, vam_header, AccelerationConfidence, Altitude, AltitudeConfidence,
    AltitudeValue, BasicContainer, Latitude, Longitude, LongitudinalAcceleration,
    LongitudinalAccelerationValue, PositionConfidenceEllipse, ReferencePositionWithConfidence,
    SemiAxisLength, Speed, SpeedConfidence, SpeedValue, TrafficParticipantType, Vam, VamCoder,
    VamParameters, VruAwareness, VruHighFrequencyContainer, Wgs84Angle, Wgs84AngleConfidence,
    Wgs84AngleValue,
};
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataRequest;
use crate::facilities::location_service::GpsFix;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::service_access_point::{
    Area, CommonNH, CommunicationProfile, HeaderSubType, HeaderType, PacketTransportType,
    TopoBroadcastHST, TrafficClass,
};
use crate::security::sn_sap::SecurityProfile;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

// ─── Timing constants (ETSI TS 103 300-3 V2.3.1 Table 16, clause 6.2) ───────

/// T_GenVamMin [ms]: minimum time between consecutive VAM generation events.
pub const T_GEN_VAM_MIN_MS: u64 = 100;
/// T_GenVamMax [ms]: maximum time between consecutive VAM generation events.
pub const T_GEN_VAM_MAX_MS: u64 = 5_000;
/// T_CheckVamGen [ms]: timer period for condition evaluation (≤ T_GenVamMin).
pub const T_CHECK_VAM_GEN_MS: u64 = T_GEN_VAM_MIN_MS;
/// T_GenVam_DCC [ms]: DCC-imposed minimum interval.
pub const T_GEN_VAM_DCC_MS: u64 = T_GEN_VAM_MIN_MS;
/// T_GenVam_LFMin [ms]: minimum interval between LF container inclusions.
pub const T_GEN_VAM_LF_MIN_MS: u64 = 2_000;

// ─── Triggering thresholds (Table 17, clause 6.4) ────────────────────────────

/// Minimum Euclidean position change to trigger a new VAM [m].
const MIN_POSITION_CHANGE_M: f64 = 4.0;
/// Minimum ground-speed change to trigger a new VAM [m/s].
const MIN_SPEED_CHANGE_MPS: f64 = 0.5;
/// Minimum heading-vector orientation change to trigger a new VAM [degrees].
const MIN_HEADING_CHANGE_DEG: f64 = 4.0;

// ─── Haversine ────────────────────────────────────────────────────────────────

fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6_371_000.0;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    R * 2.0 * a.sqrt().atan2((1.0 - a).max(0.0).sqrt())
}

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
            station_id: 0,
            station_type: 2, // cyclist
        }
    }
}

// ─── VAM builder ──────────────────────────────────────────────────────────────

/// Build a complete [`Vam`] from a GPS fix and static device data.
fn build_vam(fix: &GpsFix, dd: &DeviceData, lf: Option<VruLowFrequencyContainer>) -> Vam {
    let gen_dt = generation_delta_time_now();

    // ── BasicContainer ────────────────────────────────────────────────────────
    let ref_pos = ReferencePositionWithConfidence::new(
        Latitude(((fix.latitude * 1e7).round() as i32).clamp(-900_000_000, 900_000_000)),
        Longitude(((fix.longitude * 1e7).round() as i32).clamp(-1_800_000_000, 1_800_000_000)),
        PositionConfidenceEllipse::new(
            SemiAxisLength(4095),
            SemiAxisLength(4095),
            Wgs84AngleValue(3601),
        ),
        Altitude::new(
            AltitudeValue(((fix.altitude_m * 100.0).round() as i32).clamp(-100_000, 800_000)),
            AltitudeConfidence::unavailable,
        ),
    );

    let basic_container = BasicContainer::new(TrafficParticipantType(dd.station_type), ref_pos);

    // ── VruHighFrequencyContainer ─────────────────────────────────────────────
    let heading_raw = ((fix.heading_deg * 10.0).round() as u16).clamp(0, 3600);
    let heading = Wgs84Angle::new(Wgs84AngleValue(heading_raw), Wgs84AngleConfidence(127));

    let speed = Speed::new(
        SpeedValue(((fix.speed_mps * 100.0).round() as u16).min(16_382)),
        SpeedConfidence(127),
    );

    let longitudinal_acceleration = LongitudinalAcceleration::new(
        LongitudinalAccelerationValue(161),
        AccelerationConfidence(102),
    );

    let hf = VruHighFrequencyContainer::new(
        heading,
        speed,
        longitudinal_acceleration,
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

    // ── Assemble VAM ──────────────────────────────────────────────────────────
    let vam_params = VamParameters::new(
        basic_container,
        hf,
        lf,
        None, // vruClusterInformationContainer
        None, // vruClusterOperationContainer
        None, // vruMotionPredictionContainer
    );

    Vam::new(
        vam_header(dd.station_id),
        VruAwareness::new(gen_dt, vam_params),
    )
}

// ─── Dynamics check — clause 6.4.1 ──────────────────────────────────────────

/// Return `true` if at least one triggering threshold is exceeded.
fn check_triggers(
    fix: &GpsFix,
    last_lat: Option<f64>,
    last_lon: Option<f64>,
    last_speed: Option<f64>,
    last_heading: Option<f64>,
) -> bool {
    // No reference — treat as changed
    if last_lat.is_none() {
        return true;
    }

    // Position (Euclidean / haversine)
    if let (Some(prev_lat), Some(prev_lon)) = (last_lat, last_lon) {
        if haversine_m(prev_lat, prev_lon, fix.latitude, fix.longitude) > MIN_POSITION_CHANGE_M {
            return true;
        }
    }

    // Speed
    if let Some(prev_speed) = last_speed {
        if (fix.speed_mps - prev_speed).abs() > MIN_SPEED_CHANGE_MPS {
            return true;
        }
    }

    // Heading
    if let Some(prev_heading) = last_heading {
        let mut diff = (fix.heading_deg - prev_heading).abs();
        if diff > 180.0 {
            diff = 360.0 - diff;
        }
        if diff > MIN_HEADING_CHANGE_DEG {
            return true;
        }
    }

    false
}

// ─── LF container builder ───────────────────────────────────────────────────

fn build_lf_container() -> VruLowFrequencyContainer {
    VruLowFrequencyContainer::new(
        VruProfileAndSubprofile::pedestrian(VruSubProfilePedestrian::unavailable),
        None, // sizeClass
        None, // exteriorLights
    )
}

// ─── VAMTransmissionManagement ───────────────────────────────────────────────

/// VAM Transmission Management — ETSI TS 103 300-3 V2.3.1 clause 6.
///
/// Timer-based (T_CheckVamGen) architecture. Evaluates triggering conditions
/// on every tick per clause 6.4.1.
pub struct VAMTransmissionManagement;

impl VAMTransmissionManagement {
    /// Spawn the transmission management thread.
    ///
    /// Implements the T_CheckVamGen timer loop. The thread drains GPS fixes
    /// from `gps_rx`, caching the latest, and evaluates VAM generation
    /// conditions every `T_CHECK_VAM_GEN_MS` milliseconds.
    pub fn spawn(
        btp_handle: BTPRouterHandle,
        coder: VamCoder,
        device_data: DeviceData,
        gps_rx: Receiver<GpsFix>,
    ) {
        thread::spawn(move || {
            let t_gen_vam_ms: u64 = T_GEN_VAM_MIN_MS;
            let _ = t_gen_vam_ms; // used for future DCC integration

            // State of last transmitted VAM
            let mut last_vam_time: Option<Instant> = None;
            let mut last_vam_lat: Option<f64> = None;
            let mut last_vam_lon: Option<f64> = None;
            let mut last_vam_speed: Option<f64> = None;
            let mut last_vam_heading: Option<f64> = None;

            // LF container timing
            let mut last_lf_time: Option<Instant> = None;
            let mut is_first_vam = true;

            // Cached GPS fix
            let mut current_fix: Option<GpsFix> = None;

            loop {
                // Drain GPS fixes for T_CHECK_VAM_GEN_MS, then evaluate conditions
                let deadline = Instant::now() + Duration::from_millis(T_CHECK_VAM_GEN_MS);
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match gps_rx.recv_timeout(remaining) {
                        Ok(fix) => current_fix = Some(fix),
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => {
                            eprintln!("[VAM TX] GPS channel closed, thread exiting");
                            return;
                        }
                    }
                }

                let fix = match current_fix {
                    Some(ref f) => *f,
                    None => continue,
                };

                let now = Instant::now();
                let mut should_send = false;

                if let Some(last_time) = last_vam_time {
                    let elapsed_ms = now.duration_since(last_time).as_millis() as u64;

                    // Condition 1: elapsed ≥ T_GenVamMax
                    // Conditions 2-4: dynamics changed AND elapsed ≥ T_GenVam_DCC
                    if elapsed_ms >= T_GEN_VAM_MAX_MS
                        || (elapsed_ms >= T_GEN_VAM_DCC_MS
                            && check_triggers(
                                &fix,
                                last_vam_lat,
                                last_vam_lon,
                                last_vam_speed,
                                last_vam_heading,
                            ))
                    {
                        should_send = true;
                    }
                } else {
                    // First VAM after activation — send immediately
                    should_send = true;
                }

                if !should_send {
                    continue;
                }

                // Determine LF container inclusion (clause 6.2)
                let include_lf = is_first_vam
                    || last_lf_time.is_none()
                    || now.duration_since(last_lf_time.unwrap()).as_millis() as u64
                        >= T_GEN_VAM_LF_MIN_MS;

                let lf = if include_lf {
                    Some(build_lf_container())
                } else {
                    None
                };

                let vam = build_vam(&fix, &device_data, lf);

                match coder.encode(&vam) {
                    Ok(data) => {
                        let req = BTPDataRequest {
                            btp_type: CommonNH::BtpB,
                            source_port: 0,
                            destination_port: 2018,
                            destination_port_info: 0,
                            gn_packet_transport_type: PacketTransportType {
                                header_type: HeaderType::Tsb,
                                header_sub_type: HeaderSubType::TopoBroadcast(
                                    TopoBroadcastHST::SingleHop,
                                ),
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
                            security_profile: SecurityProfile::VruAwarenessMessage,
                            its_aid: 638,
                            security_permissions: vec![],
                            gn_max_hop_limit: 1,
                            gn_max_packet_lifetime: None,
                            gn_repetition_interval: None,
                            gn_max_repetition_time: None,
                            destination: None,
                            length: data.len() as u16,
                            data,
                        };
                        btp_handle.send_btp_data_request(req);

                        eprintln!("[VAM TX] Sent VAM: station={}", device_data.station_id,);

                        // Update state
                        last_vam_time = Some(now);
                        last_vam_lat = Some(fix.latitude);
                        last_vam_lon = Some(fix.longitude);
                        last_vam_speed = Some(fix.speed_mps);
                        last_vam_heading = Some(fix.heading_deg);

                        if include_lf {
                            last_lf_time = Some(now);
                        }
                        is_first_vam = false;
                    }
                    Err(e) => {
                        eprintln!("[VAM TX] Encode error: {}", e);
                    }
                }
            }
        });
    }
}

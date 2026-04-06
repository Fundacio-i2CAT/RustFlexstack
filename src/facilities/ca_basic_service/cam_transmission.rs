// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CAM Transmission Management — ETSI TS 103 900 V2.2.1 (2025-02).
//!
//! Mirrors `CAMTransmissionManagement` in
//! `flexstack/facilities/ca_basic_service/cam_transmission_management.py`.
//!
//! Key behavioural properties:
//!   - Timer-based (T_CheckCamGen) instead of GPS-callback-reactive (§6.1.3, Annex B).
//!   - T_GenCam is initialised to T_GenCamMax (not T_GenCamMin) as mandated by §6.1.3.
//!   - Condition 1 (dynamics: heading/position/speed) and Condition 2 (time) are both
//!     evaluated on every T_CheckCamGen tick.
//!   - N_GenCam counter resets T_GenCam to T_GenCamMax after N_GenCam consecutive
//!     condition-1 CAMs.
//!   - Low-Frequency, Special-Vehicle, Very-Low-Frequency and Two-Wheeler extension
//!     containers are included according to §6.1.3.
//!   - GN max packet lifetime set to 1000 ms per §5.3.4.1.

use super::cam_bindings::cam_pdu_descriptions::{
    BasicVehicleContainerLowFrequency, ExtensionContainerId, LowFrequencyContainer,
    SpecialVehicleContainer, TwoWheelerContainer, VeryLowFrequencyContainer,
    WrappedExtensionContainer, WrappedExtensionContainers,
};
use super::cam_bindings::etsi_its_cdd::{
    DeltaAltitude, DeltaLatitude, DeltaLongitude, DeltaReferencePosition, ExteriorLights, Path,
    PathDeltaTime, PathPoint, VehicleRole,
};
use super::cam_coder::{
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
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataRequest;
use crate::facilities::location_service::GpsFix;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::service_access_point::{
    Area, CommonNH, CommunicationProfile, HeaderSubType, HeaderType, PacketTransportType,
    TopoBroadcastHST, TrafficClass,
};
use crate::security::sn_sap::SecurityProfile;
use rand::Rng;
use rasn::prelude::*;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

// ─── Timing constants (ETSI TS 103 900 V2.2.1 §6.1.3) ───────────────────────

/// T_GenCamMin [ms]: minimum CAM generation interval (10 Hz maximum rate).
pub const T_GEN_CAM_MIN_MS: u64 = 100;
/// T_GenCamMax [ms]: maximum CAM generation interval (1 Hz minimum rate).
pub const T_GEN_CAM_MAX_MS: u64 = 1_000;
/// T_CheckCamGen [ms]: timer period for condition evaluation (≤ T_GenCamMin).
pub const T_CHECK_CAM_GEN_MS: u64 = T_GEN_CAM_MIN_MS;
/// T_GenCam_DCC [ms]: DCC-imposed minimum interval ∈ [T_GenCamMin, T_GenCamMax].
pub const T_GEN_CAM_DCC_MS: u64 = T_GEN_CAM_MIN_MS;

// ─── Optional-container intervals (§6.1.3) ───────────────────────────────────

/// N_GenCam: max consecutive condition-1-triggered CAMs before resetting T_GenCam.
const N_GEN_CAM_DEFAULT: u32 = 3;
/// Low-frequency container minimum interval [ms].
const T_GEN_CAM_LF_MS: u64 = 500;
/// Special-vehicle container minimum interval [ms].
const T_GEN_CAM_SPECIAL_MS: u64 = 500;
/// Very-low-frequency container minimum interval [ms].
const T_GEN_CAM_VLF_MS: u64 = 10_000;

/// Station types that must include the Two-Wheeler extension container (§6.1.3):
/// cyclist(2), moped(3), motorcycle(4).
const TWO_WHEELER_STATION_TYPES: [u8; 3] = [2, 3, 4];

/// VehicleRole enum names indexed by integer value (§6.1.3 / CDD).
const VEHICLE_ROLE_NAMES: [VehicleRole; 16] = [
    VehicleRole::default,
    VehicleRole::publicTransport,
    VehicleRole::specialTransport,
    VehicleRole::dangerousGoods,
    VehicleRole::roadWork,
    VehicleRole::rescue,
    VehicleRole::emergency,
    VehicleRole::safetyCar,
    VehicleRole::agriculture,
    VehicleRole::commercial,
    VehicleRole::military,
    VehicleRole::roadOperator,
    VehicleRole::taxi,
    VehicleRole::uvar,
    VehicleRole::rfu1,
    VehicleRole::rfu2,
];

// ─── Haversine ────────────────────────────────────────────────────────────────

fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6_371_000.0;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    R * 2.0 * a.sqrt().atan2((1.0 - a).max(0.0).sqrt())
}

// ─── VehicleData ─────────────────────────────────────────────────────────────

/// Static vehicle data used to populate every CAM.
///
/// Mirrors the `VehicleData` frozen dataclass in the Python implementation
/// (ETSI TS 103 900 V2.2.1).
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
    /// VehicleRole (0=default). Used in the Low-Frequency container and to
    /// decide whether a Special-Vehicle container is required (§6.1.3).
    pub vehicle_role: u8,
    /// ExteriorLights BIT STRING (SIZE(8)). One byte; bits ordered MSB→LSB
    /// correspond to lowBeam(0)…parkingLights(7). Default = all off.
    pub exterior_lights: [u8; 1],
    /// Special vehicle container data (CHOICE variant), e.g.
    /// `SpecialVehicleContainer::emergencyContainer(...)`.
    /// `None` if not applicable.
    pub special_vehicle_data: Option<SpecialVehicleContainer>,
}

impl Default for VehicleData {
    /// Sensible defaults — PassengerCar, all kinematic fields unavailable.
    fn default() -> Self {
        VehicleData {
            station_id: 0,
            station_type: 5, // passengerCar
            drive_direction: DriveDirection::unavailable,
            vehicle_length_value: 1023,
            vehicle_width: 62,
            vehicle_role: 0,
            exterior_lights: [0x00],
            special_vehicle_data: None,
        }
    }
}

// ─── CAM builder ─────────────────────────────────────────────────────────────

/// Build the BasicContainer + HighFrequencyContainer portions of a CAM from
/// a GPS fix and static vehicle data.
fn build_cam(
    fix: &GpsFix,
    vd: &VehicleData,
    lf: Option<LowFrequencyContainer>,
    special: Option<SpecialVehicleContainer>,
    extensions: Option<WrappedExtensionContainers>,
) -> Cam {
    let gen_dt = generation_delta_time_now();

    // ── BasicContainer ──────────────────────────────────────────────────────
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

    let basic_container = BasicContainer::new(TrafficParticipantType(vd.station_type), ref_pos);

    // ── BasicVehicleContainerHighFrequency ─────────────────────────────────
    let heading_value = HeadingValue(((fix.heading_deg * 10.0).round() as u16).clamp(0, 3600));
    let heading = Heading::new(heading_value, HeadingConfidence(127));

    let speed_value = SpeedValue(((fix.speed_mps * 100.0).round() as u16).min(16_382));
    let speed = Speed::new(speed_value, SpeedConfidence(127));

    let vehicle_length = VehicleLength::new(
        VehicleLengthValue(vd.vehicle_length_value.clamp(1, 1023)),
        VehicleLengthConfidenceIndication::unavailable,
    );
    let vehicle_width = VehicleWidth(vd.vehicle_width.clamp(1, 62));

    let longitudinal_acceleration = AccelerationComponent::new(
        AccelerationValue(161),
        AccelerationConfidence(102),
    );
    let curvature = Curvature::new(
        CurvatureValue(1023),
        CurvatureConfidence::unavailable,
    );
    let yaw_rate = YawRate::new(
        YawRateValue(32767),
        YawRateConfidence::unavailable,
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
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    Cam::new(
        cam_header(vd.station_id),
        CamPayload::new(
            gen_dt,
            CamParameters::new(
                basic_container,
                HighFrequencyContainer::basicVehicleContainerHighFrequency(hf),
                lf,
                special,
                extensions,
            ),
        ),
    )
}

// ─── Path history entry ──────────────────────────────────────────────────────

struct PathEntry {
    lat: f64,
    lon: f64,
    time_ms: u64,
}

// ─── CAMTransmissionManagement ───────────────────────────────────────────────

/// CAM Transmission Management — ETSI TS 103 900 V2.2.1 §6.1.
///
/// Timer-based (T_CheckCamGen) architecture. Evaluates Condition 1 (dynamics)
/// and Condition 2 (time) on every tick.
pub struct CAMTransmissionManagement;

impl CAMTransmissionManagement {
    /// Spawn the transmission management thread.
    ///
    /// Implements the T_CheckCamGen timer loop per Annex B.2.4. The thread
    /// drains GPS fixes from `gps_rx`, caching the latest, and evaluates CAM
    /// generation conditions every `T_CHECK_CAM_GEN_MS` milliseconds.
    pub fn spawn(
        btp_handle: BTPRouterHandle,
        coder: CamCoder,
        vehicle_data: VehicleData,
        gps_rx: Receiver<GpsFix>,
    ) {
        thread::spawn(move || {
            // §6.1.3 — T_GenCam starts at T_GenCamMax
            let mut t_gen_cam_ms: u64 = T_GEN_CAM_MAX_MS;
            let mut n_gen_cam_counter: u32 = 0;

            // Dynamics state of last transmitted CAM
            let mut last_cam_time: Option<Instant> = None;
            let mut last_cam_heading: Option<f64> = None;
            let mut last_cam_lat: Option<f64> = None;
            let mut last_cam_lon: Option<f64> = None;
            let mut last_cam_speed: Option<f64> = None;

            // Container timing state
            let mut cam_count: u64 = 0;
            let mut last_lf_time: Option<Instant> = None;
            let mut last_vlf_time: Option<Instant> = None;
            let mut last_special_time: Option<Instant> = None;

            // Path history (lat, lon, time_ms) oldest→newest; max 40
            let mut path_history: Vec<PathEntry> = Vec::new();

            // Cached GPS fix
            let mut current_fix: Option<GpsFix> = None;

            // Annex B.2.4 step 1 — non-clock-synchronised start (random initial delay)
            let initial_delay = Duration::from_millis(
                rand::thread_rng().gen_range(0..T_CHECK_CAM_GEN_MS),
            );
            thread::sleep(initial_delay);

            loop {
                // Drain GPS fixes for T_CHECK_CAM_GEN_MS, then evaluate conditions
                let deadline = Instant::now() + Duration::from_millis(T_CHECK_CAM_GEN_MS);
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match gps_rx.recv_timeout(remaining) {
                        Ok(fix) => current_fix = Some(fix),
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => {
                            eprintln!("[CAM TX] GPS channel closed, thread exiting");
                            return;
                        }
                    }
                }

                // Timer tick — evaluate CAM conditions (Annex B.2.4 step 2)
                let fix = match current_fix {
                    Some(ref f) => f.clone(),
                    None => continue,
                };

                let now = Instant::now();

                // First CAM after activation — send immediately
                if last_cam_time.is_none() {
                    generate_and_send(
                        &fix,
                        &vehicle_data,
                        &coder,
                        &btp_handle,
                        now,
                        0,
                        1, // condition 1
                        &mut t_gen_cam_ms,
                        &mut n_gen_cam_counter,
                        &mut last_cam_time,
                        &mut last_cam_heading,
                        &mut last_cam_lat,
                        &mut last_cam_lon,
                        &mut last_cam_speed,
                        &mut cam_count,
                        &mut last_lf_time,
                        &mut last_vlf_time,
                        &mut last_special_time,
                        &mut path_history,
                    );
                    continue;
                }

                let elapsed_ms = now.duration_since(last_cam_time.unwrap()).as_millis() as u64;

                // Condition 1 (§6.1.3): elapsed ≥ T_GenCam_DCC AND dynamics changed
                if elapsed_ms >= T_GEN_CAM_DCC_MS
                    && check_dynamics(
                        &fix,
                        last_cam_heading,
                        last_cam_lat,
                        last_cam_lon,
                        last_cam_speed,
                    )
                {
                    generate_and_send(
                        &fix,
                        &vehicle_data,
                        &coder,
                        &btp_handle,
                        now,
                        elapsed_ms,
                        1,
                        &mut t_gen_cam_ms,
                        &mut n_gen_cam_counter,
                        &mut last_cam_time,
                        &mut last_cam_heading,
                        &mut last_cam_lat,
                        &mut last_cam_lon,
                        &mut last_cam_speed,
                        &mut cam_count,
                        &mut last_lf_time,
                        &mut last_vlf_time,
                        &mut last_special_time,
                        &mut path_history,
                    );
                    continue;
                }

                // Condition 2 (§6.1.3): elapsed ≥ T_GenCam AND elapsed ≥ T_GenCam_DCC
                if elapsed_ms >= t_gen_cam_ms && elapsed_ms >= T_GEN_CAM_DCC_MS {
                    generate_and_send(
                        &fix,
                        &vehicle_data,
                        &coder,
                        &btp_handle,
                        now,
                        elapsed_ms,
                        2,
                        &mut t_gen_cam_ms,
                        &mut n_gen_cam_counter,
                        &mut last_cam_time,
                        &mut last_cam_heading,
                        &mut last_cam_lat,
                        &mut last_cam_lon,
                        &mut last_cam_speed,
                        &mut cam_count,
                        &mut last_lf_time,
                        &mut last_vlf_time,
                        &mut last_special_time,
                        &mut path_history,
                    );
                }
            }
        });
    }
}

// ─── Dynamics check — §6.1.3 Condition 1 ────────────────────────────────────

/// Return `true` if at least one dynamics threshold is exceeded.
///
/// Thresholds (§6.1.3):
///   * |Δheading| > 4°
///   * |Δposition| > 4 m  (haversine)
///   * |Δspeed| > 0.5 m/s
fn check_dynamics(
    fix: &GpsFix,
    last_heading: Option<f64>,
    last_lat: Option<f64>,
    last_lon: Option<f64>,
    last_speed: Option<f64>,
) -> bool {
    // No reference — treat as changed
    if last_heading.is_none() {
        return true;
    }

    // Heading
    if let Some(prev) = last_heading {
        let mut diff = (fix.heading_deg - prev).abs();
        if diff > 180.0 {
            diff = 360.0 - diff;
        }
        if diff > 4.0 {
            return true;
        }
    }

    // Position
    if let (Some(prev_lat), Some(prev_lon)) = (last_lat, last_lon) {
        if haversine_m(prev_lat, prev_lon, fix.latitude, fix.longitude) > 4.0 {
            return true;
        }
    }

    // Speed
    if let Some(prev_speed) = last_speed {
        if (fix.speed_mps - prev_speed).abs() > 0.5 {
            return true;
        }
    }

    false
}

// ─── Optional container inclusion rules (§6.1.3) ────────────────────────────

fn should_include_lf(cam_count: u64, last_lf_time: Option<Instant>, now: Instant) -> bool {
    if cam_count == 0 {
        return true;
    }
    match last_lf_time {
        None => true,
        Some(t) => now.duration_since(t).as_millis() as u64 >= T_GEN_CAM_LF_MS,
    }
}

fn should_include_special_vehicle(
    vehicle_role: u8,
    cam_count: u64,
    last_special_time: Option<Instant>,
    now: Instant,
) -> bool {
    if vehicle_role == 0 {
        return false;
    }
    if cam_count == 0 {
        return true;
    }
    match last_special_time {
        None => true,
        Some(t) => now.duration_since(t).as_millis() as u64 >= T_GEN_CAM_SPECIAL_MS,
    }
}

fn should_include_vlf(
    cam_count: u64,
    last_vlf_time: Option<Instant>,
    now: Instant,
    include_lf: bool,
    include_special: bool,
) -> bool {
    // Second CAM after activation (cam_count == 1)
    if cam_count == 1 {
        return true;
    }
    match last_vlf_time {
        None => false,
        Some(t) => {
            now.duration_since(t).as_millis() as u64 >= T_GEN_CAM_VLF_MS
                && !include_lf
                && !include_special
        }
    }
}

fn should_include_two_wheeler(station_type: u8) -> bool {
    TWO_WHEELER_STATION_TYPES.contains(&station_type)
}

// ─── Low-Frequency container builder ─────────────────────────────────────────

fn build_lf_container(
    vd: &VehicleData,
    fix: &GpsFix,
    path_history: &[PathEntry],
    now_ms: u64,
) -> LowFrequencyContainer {
    let role_idx = vd.vehicle_role as usize;
    let role = if role_idx < VEHICLE_ROLE_NAMES.len() {
        VEHICLE_ROLE_NAMES[role_idx]
    } else {
        VehicleRole::default
    };

    let mut ext_bits = rasn::types::FixedBitString::<8>::default();
    // Set bits from the byte: bit 0 (MSB) = lowBeam, etc.
    for i in 0..8 {
        if vd.exterior_lights[0] & (1 << (7 - i)) != 0 {
            ext_bits.set(i, true);
        }
    }
    let ext_lights = ExteriorLights(ext_bits);

    let path_points = build_path_points(fix, path_history, now_ms);
    let path = Path(path_points);

    LowFrequencyContainer::basicVehicleContainerLowFrequency(
        BasicVehicleContainerLowFrequency::new(role, ext_lights, path),
    )
}

fn build_path_points(
    current_fix: &GpsFix,
    history: &[PathEntry],
    now_ms: u64,
) -> Vec<PathPoint> {
    let mut result = Vec::new();
    for entry in history.iter().rev() {
        let delta_lat = ((entry.lat - current_fix.latitude) * 1e7).round() as i32;
        let delta_lon = ((entry.lon - current_fix.longitude) * 1e7).round() as i32;
        if !(-131_071..=131_072).contains(&delta_lat) {
            break;
        }
        if !(-131_071..=131_072).contains(&delta_lon) {
            break;
        }
        let delta_time_10ms = ((now_ms.saturating_sub(entry.time_ms)) / 10).clamp(1, 65_534);
        result.push(PathPoint::new(
            DeltaReferencePosition::new(
                DeltaLatitude(delta_lat),
                DeltaLongitude(delta_lon),
                DeltaAltitude(12800), // unavailable
            ),
            Some(PathDeltaTime(Integer::from(delta_time_10ms as i128))),
        ));
        if result.len() >= 23 {
            break;
        }
    }
    result
}

// ─── Extension container builder ─────────────────────────────────────────────

fn build_extension_containers(
    include_two_wheeler: bool,
    include_vlf: bool,
) -> Option<WrappedExtensionContainers> {
    let mut containers = Vec::new();

    if include_two_wheeler {
        let tw = TwoWheelerContainer::new(None, None, None, None);
        if let Ok(tw_bytes) = rasn::uper::encode(&tw) {
            containers.push(WrappedExtensionContainer::new(
                ExtensionContainerId(Integer::from(1i128)),
                Any::new(tw_bytes.to_vec()),
            ));
        }
    }

    if include_vlf {
        let vlf = VeryLowFrequencyContainer::new(None, None, None);
        if let Ok(vlf_bytes) = rasn::uper::encode(&vlf) {
            containers.push(WrappedExtensionContainer::new(
                ExtensionContainerId(Integer::from(3i128)),
                Any::new(vlf_bytes.to_vec()),
            ));
        }
    }

    if containers.is_empty() {
        None
    } else {
        Some(WrappedExtensionContainers(containers))
    }
}

// ─── Generate and send ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn generate_and_send(
    fix: &GpsFix,
    vd: &VehicleData,
    coder: &CamCoder,
    btp_handle: &BTPRouterHandle,
    now: Instant,
    elapsed_ms: u64,
    condition: u8,
    t_gen_cam_ms: &mut u64,
    n_gen_cam_counter: &mut u32,
    last_cam_time: &mut Option<Instant>,
    last_cam_heading: &mut Option<f64>,
    last_cam_lat: &mut Option<f64>,
    last_cam_lon: &mut Option<f64>,
    last_cam_speed: &mut Option<f64>,
    cam_count: &mut u64,
    last_lf_time: &mut Option<Instant>,
    last_vlf_time: &mut Option<Instant>,
    last_special_time: &mut Option<Instant>,
    path_history: &mut Vec<PathEntry>,
) {
    let include_lf = should_include_lf(*cam_count, *last_lf_time, now);
    let include_special = should_include_special_vehicle(vd.vehicle_role, *cam_count, *last_special_time, now);
    let include_vlf = should_include_vlf(*cam_count, *last_vlf_time, now, include_lf, include_special);
    let include_tw = should_include_two_wheeler(vd.station_type);

    // Approximate now_ms for path history delta-time calculations
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Build optional containers
    let lf = if include_lf {
        Some(build_lf_container(vd, fix, path_history, now_ms))
    } else {
        None
    };

    let special = if include_special {
        vd.special_vehicle_data.clone()
    } else {
        None
    };

    let extensions = build_extension_containers(include_tw, include_vlf);

    // Build and encode CAM (Annex B.2.5 — skip on failure)
    let cam = build_cam(fix, vd, lf, special, extensions);

    match coder.encode(&cam) {
        Ok(data) => {
            let req = BTPDataRequest {
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
                security_profile: SecurityProfile::CooperativeAwarenessMessage,
                its_aid: 36,
                security_permissions: vec![],
                gn_max_hop_limit: 1,
                gn_max_packet_lifetime: Some(1.0), // §5.3.4.1: 1000 ms
                gn_repetition_interval: None,
                gn_max_repetition_time: None,
                destination: None,
                length: data.len() as u16,
                data,
            };
            btp_handle.send_btp_data_request(req);

            eprintln!(
                "[CAM TX] Sent CAM: station={} cond={}",
                vd.station_id, condition,
            );

            // ── Update state after successful transmission (§6.1.3) ──────
            if condition == 1 {
                *t_gen_cam_ms = elapsed_ms.clamp(T_GEN_CAM_MIN_MS, T_GEN_CAM_MAX_MS);
                *n_gen_cam_counter += 1;
                if *n_gen_cam_counter >= N_GEN_CAM_DEFAULT {
                    *t_gen_cam_ms = T_GEN_CAM_MAX_MS;
                    *n_gen_cam_counter = 0;
                }
            } else {
                *n_gen_cam_counter = 0;
                *t_gen_cam_ms = T_GEN_CAM_MAX_MS;
            }

            *last_cam_time = Some(now);
            *last_cam_heading = Some(fix.heading_deg);
            *last_cam_lat = Some(fix.latitude);
            *last_cam_lon = Some(fix.longitude);
            *last_cam_speed = Some(fix.speed_mps);

            // Update path history
            path_history.push(PathEntry {
                lat: fix.latitude,
                lon: fix.longitude,
                time_ms: now_ms,
            });
            if path_history.len() > 40 {
                path_history.remove(0);
            }

            // Update container timing
            if include_lf {
                *last_lf_time = Some(now);
            }
            if include_special {
                *last_special_time = Some(now);
            }
            if include_vlf {
                *last_vlf_time = Some(now);
            }

            *cam_count += 1;
        }
        Err(e) => {
            eprintln!("[CAM TX] Encode error (Annex B.2.5 — skipping): {}", e);
        }
    }
}

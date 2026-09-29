// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CAM Transmission Management — ETSI TS 103 900 V2.2.1 (2025-02).
//!
//! Mirrors `CAMTransmissionManagement` in
//! `flexstack/facilities/ca_basic_service/cam_transmission_management.py`.
//!
//! Key standard-compliance additions:
//!   - Timer-based (T_CheckCamGen) instead of GPS-callback-reactive (§6.1.3, Annex B).
//!   - T_GenCam is initialised to T_GenCamMax (not T_GenCamMin) as mandated by §6.1.3.
//!   - Condition 1 (dynamics: heading/position/speed) and Condition 2 (time) are both
//!     evaluated on every T_CheckCamGen tick.
//!   - N_GenCam counter resets T_GenCam to T_GenCamMax after N_GenCam consecutive
//!     condition-1 CAMs.
//!   - Low-Frequency, Special-Vehicle, Very-Low-Frequency and Two-Wheeler extension
//!     containers are included according to §6.1.3.
//!   - GN max packet lifetime set to 1000 ms per §5.3.4.1.
//!   - Ingestion into LDM on transmission if LDM adapter is configured.

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
    cam_header, generate_white_cam_static, generation_delta_time_now, AccelerationComponent,
    AccelerationConfidence, AccelerationValue, Altitude, AltitudeConfidence, AltitudeValue,
    BasicContainer, BasicVehicleContainerHighFrequency, Cam, CamCoder, CamParameters, CamPayload,
    Curvature, CurvatureCalculationMode, CurvatureConfidence, CurvatureValue, DriveDirection,
    GenerationDeltaTime, Heading, HeadingConfidence, HeadingValue, HighFrequencyContainer,
    Latitude, Longitude, PositionConfidenceEllipse, ReferencePositionWithConfidence,
    SemiAxisLength, Speed, SpeedConfidence, SpeedValue, StationId, TrafficParticipantType,
    VehicleLength, VehicleLengthConfidenceIndication, VehicleLengthValue, VehicleWidth,
    Wgs84AngleValue, YawRate, YawRateConfidence, YawRateValue,
};
use super::cam_ldm_adaptation::CABasicServiceLDM;
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
pub const N_GEN_CAM_DEFAULT: u32 = 3;
/// Low-frequency container minimum interval [ms].
pub const T_GEN_CAM_LF_MS: u64 = 500;
/// Special-vehicle container minimum interval [ms].
pub const T_GEN_CAM_SPECIAL_MS: u64 = 500;
/// Very-low-frequency container minimum interval [ms].
pub const T_GEN_CAM_VLF_MS: u64 = 10_000;

/// Station types that must include the Two-Wheeler extension container (§6.1.3):
/// cyclist(2), moped(3), motorcycle(4).
pub const TWO_WHEELER_STATION_TYPES: [u8; 3] = [2, 3, 4];

/// VehicleRole enum names indexed by integer value (§6.1.3 / CDD).
pub const VEHICLE_ROLE_NAMES: [VehicleRole; 16] = [
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

/// Return the great-circle distance in metres between two WGS-84 points.
pub fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6_371_000.0;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    R * 2.0 * a.sqrt().atan2((1.0 - a).max(0.0).sqrt())
}

// ─── Confidence Helpers ───────────────────────────────────────────────────────

/// Translates the epx and epy TPV values (in metres) to the position confidence ellipse value.
pub fn create_position_confidence(epx: f64, epy: f64) -> PositionConfidenceEllipse {
    let mut semi_major = (epx * 100.0).round() as u16;
    let mut semi_minor = (epy * 100.0).round() as u16;
    if epy >= epx {
        semi_major = (epy * 100.0).round() as u16;
        semi_minor = (epx * 100.0).round() as u16;
    }
    PositionConfidenceEllipse::new(
        SemiAxisLength(semi_major.min(4095)),
        SemiAxisLength(semi_minor.min(4095)),
        Wgs84AngleValue(0),
    )
}

/// Translates the epv TPV value (in metres) to the altitude confidence value.
pub fn create_altitude_confidence(epv: f64) -> AltitudeConfidence {
    if epv < 0.01 {
        AltitudeConfidence::alt_000_01
    } else if epv < 0.02 {
        AltitudeConfidence::alt_000_02
    } else if epv < 0.05 {
        AltitudeConfidence::alt_000_05
    } else if epv < 0.10 {
        AltitudeConfidence::alt_000_10
    } else if epv < 0.20 {
        AltitudeConfidence::alt_000_20
    } else if epv < 0.50 {
        AltitudeConfidence::alt_000_50
    } else if epv < 1.0 {
        AltitudeConfidence::alt_001_00
    } else if epv < 2.0 {
        AltitudeConfidence::alt_002_00
    } else if epv < 5.0 {
        AltitudeConfidence::alt_005_00
    } else if epv < 10.0 {
        AltitudeConfidence::alt_010_00
    } else if epv < 20.0 {
        AltitudeConfidence::alt_020_00
    } else if epv < 50.0 {
        AltitudeConfidence::alt_050_00
    } else if epv < 100.0 {
        AltitudeConfidence::alt_100_00
    } else if epv <= 200.0 {
        AltitudeConfidence::alt_200_00
    } else {
        AltitudeConfidence::outOfRange
    }
}

/// Translates the epd TPV value (in degrees) to the heading confidence value.
pub fn create_heading_confidence(epd: f64) -> HeadingConfidence {
    if epd <= 12.5 {
        HeadingConfidence(((epd * 10.0).round() as u8).min(126))
    } else {
        HeadingConfidence(126)
    }
}

// ─── VehicleData ─────────────────────────────────────────────────────────────

/// Static vehicle data used to populate every CAM.
///
/// Mirrors the `VehicleData` frozen dataclass in the Python implementation
/// (ETSI TS 103 900 V2.2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct VehicleData {
    /// ITS station ID (0–4 294 967 295).
    pub station_id: u32,
    /// ITS station type / traffic participant type (0–255).
    /// Common values: 0 = unknown, 2 = cyclist, 3 = moped, 4 = motorcycle, 5 = passengerCar.
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
    pub exterior_lights: Vec<u8>,
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
            station_type: 0,
            drive_direction: DriveDirection::unavailable,
            vehicle_length_value: 1023,
            vehicle_width: 62,
            vehicle_role: 0,
            exterior_lights: vec![0x00],
            special_vehicle_data: None,
        }
    }
}

impl VehicleData {
    /// Validate vehicle data parameters according to ETSI specifications.
    pub fn validate(&self) -> Result<(), String> {
        if self.vehicle_role > 15 {
            return Err("vehicle_role must be between 0 and 15".to_string());
        }
        if self.vehicle_length_value > 1023 {
            return Err("Vehicle length must be between 0 and 1023".to_string());
        }
        if self.vehicle_width > 62 {
            return Err("Vehicle width must be between 0 and 62".to_string());
        }
        if self.exterior_lights.is_empty() {
            return Err("exterior_lights must be at least 1 byte".to_string());
        }
        Ok(())
    }

    /// Construct a new `VehicleData` validating its parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        station_id: u32,
        station_type: u8,
        drive_direction: DriveDirection,
        vehicle_length_value: u16,
        vehicle_width: u8,
        vehicle_role: u8,
        exterior_lights: Vec<u8>,
        special_vehicle_data: Option<SpecialVehicleContainer>,
    ) -> Result<Self, String> {
        let vd = VehicleData {
            station_id,
            station_type,
            drive_direction,
            vehicle_length_value,
            vehicle_width,
            vehicle_role,
            exterior_lights,
            special_vehicle_data,
        };
        vd.validate()?;
        Ok(vd)
    }
}

// ─── CooperativeAwarenessMessage ─────────────────────────────────────────────

/// High-level Cooperative Awareness Message builder / container.
///
/// Mirrors `CooperativeAwarenessMessage` in Python.
#[derive(Debug, Clone, PartialEq)]
pub struct CooperativeAwarenessMessage {
    pub cam: Cam,
}

impl Default for CooperativeAwarenessMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl CooperativeAwarenessMessage {
    /// Create a new `CooperativeAwarenessMessage` initialized as a white CAM.
    pub fn new() -> Self {
        CooperativeAwarenessMessage {
            cam: generate_white_cam_static(),
        }
    }

    /// Generate a white CAM statically.
    pub fn generate_white_cam_static() -> Cam {
        generate_white_cam_static()
    }

    /// Generate a white CAM.
    pub fn generate_white_cam(&self) -> Cam {
        generate_white_cam_static()
    }

    /// Populate CAM fields with vehicle data.
    pub fn fullfill_with_vehicle_data(&mut self, vehicle_data: &VehicleData) {
        self.cam.header.station_id = StationId(vehicle_data.station_id);
        self.cam.cam.cam_parameters.basic_container.station_type =
            TrafficParticipantType(vehicle_data.station_type);

        if let HighFrequencyContainer::basicVehicleContainerHighFrequency(ref mut hf) =
            self.cam.cam.cam_parameters.high_frequency_container
        {
            hf.drive_direction = vehicle_data.drive_direction;
            hf.vehicle_length.vehicle_length_value =
                VehicleLengthValue(vehicle_data.vehicle_length_value);
            hf.vehicle_width = VehicleWidth(vehicle_data.vehicle_width);
        }
    }

    /// Populate CAM generation delta time from a UNIX timestamp in seconds.
    pub fn fullfill_gen_delta_time_with_timestamp(&mut self, timestamp_s: f64) {
        self.cam.cam.generation_delta_time = GenerationDeltaTime::from_timestamp(timestamp_s);
    }

    /// Populate CAM fields with GPS fix / TPV data.
    pub fn fullfill_with_tpv_data(&mut self, fix: &GpsFix) {
        let now_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        self.fullfill_gen_delta_time_with_timestamp(now_s);

        let ref_pos = &mut self
            .cam
            .cam
            .cam_parameters
            .basic_container
            .reference_position;
        ref_pos.latitude =
            Latitude(((fix.latitude * 1e7).round() as i32).clamp(-900_000_000, 900_000_000));
        ref_pos.longitude =
            Longitude(((fix.longitude * 1e7).round() as i32).clamp(-1_800_000_000, 1_800_000_000));

        let alt_val = ((fix.altitude_m * 100.0).round() as i32).clamp(-100_000, 800_000);
        ref_pos.altitude.altitude_value = AltitudeValue(alt_val);

        if let HighFrequencyContainer::basicVehicleContainerHighFrequency(ref mut hf) =
            self.cam.cam.cam_parameters.high_frequency_container
        {
            hf.heading.heading_value =
                HeadingValue(((fix.heading_deg * 10.0).round() as u16).clamp(0, 3600));
            let spd = ((fix.speed_mps * 100.0).round() as u16).min(16_382);
            hf.speed.speed_value = SpeedValue(spd);
        }
    }
}

// ─── Path history entry ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct PathEntry {
    pub lat: f64,
    pub lon: f64,
    pub time_ms: u64,
}

// ─── Transmission State ──────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TransmissionState {
    pub last_cam_time_ms: Option<u64>,
    pub last_cam_heading: Option<f64>,
    pub last_cam_lat: Option<f64>,
    pub last_cam_lon: Option<f64>,
    pub last_cam_speed: Option<f64>,

    pub cam_count: u64,
    pub last_lf_time_ms: Option<u64>,
    pub last_vlf_time_ms: Option<u64>,
    pub last_special_time_ms: Option<u64>,

    pub path_history: Vec<PathEntry>,
    pub current_fix: Option<GpsFix>,
    pub last_cam_generation_delta_time: Option<GenerationDeltaTime>,
}

// ─── CAMTransmissionManagement ───────────────────────────────────────────────

/// CAM Transmission Management — ETSI TS 103 900 V2.2.1 §6.1.
#[derive(Clone)]
pub struct CAMTransmissionManagement {
    pub btp_handle: BTPRouterHandle,
    pub cam_coder: CamCoder,
    pub vehicle_data: VehicleData,
    pub ca_basic_service_ldm: Option<CABasicServiceLDM>,

    pub t_gen_cam_ms: Arc<AtomicU64>,
    pub n_gen_cam_counter: Arc<AtomicU32>,

    pub state: Arc<Mutex<TransmissionState>>,
    pub active: Arc<AtomicBool>,
}

impl CAMTransmissionManagement {
    /// Create a new `CAMTransmissionManagement` instance.
    pub fn new(
        btp_handle: BTPRouterHandle,
        cam_coder: CamCoder,
        vehicle_data: VehicleData,
        ca_basic_service_ldm: Option<CABasicServiceLDM>,
    ) -> Self {
        CAMTransmissionManagement {
            btp_handle,
            cam_coder,
            vehicle_data,
            ca_basic_service_ldm,
            t_gen_cam_ms: Arc::new(AtomicU64::new(T_GEN_CAM_MAX_MS)),
            n_gen_cam_counter: Arc::new(AtomicU32::new(0)),
            state: Arc::new(Mutex::new(TransmissionState::default())),
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Activate the CA service (§6.1.2).
    ///
    /// Resets per-activation dynamics and timer state.
    pub fn start(&self) {
        if self.active.swap(true, Ordering::SeqCst) {
            return; // Already active
        }
        self.t_gen_cam_ms.store(T_GEN_CAM_MAX_MS, Ordering::SeqCst);
        self.n_gen_cam_counter.store(0, Ordering::SeqCst);

        if let Ok(mut st) = self.state.lock() {
            st.cam_count = 0;
            st.last_cam_time_ms = None;
            st.last_cam_heading = None;
            st.last_cam_lat = None;
            st.last_cam_lon = None;
            st.last_cam_speed = None;
            st.last_lf_time_ms = None;
            st.last_vlf_time_ms = None;
            st.last_special_time_ms = None;
            st.path_history.clear();
        }
    }

    /// Deactivate the CA service (§6.1.2).
    pub fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    /// Whether the transmission service is active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Current T_GenCam value in milliseconds.
    pub fn t_gen_cam(&self) -> u64 {
        self.t_gen_cam_ms.load(Ordering::SeqCst)
    }

    /// Number of CAMs sent since activation.
    pub fn cam_count(&self) -> u64 {
        self.state.lock().map(|st| st.cam_count).unwrap_or(0)
    }

    /// Timestamp (ms) of the last transmitted CAM.
    pub fn last_cam_time_ms(&self) -> Option<u64> {
        self.state.lock().ok().and_then(|st| st.last_cam_time_ms)
    }

    /// Cache the latest position data (§6.1.3).
    ///
    /// This method only updates the internal position cache and does not
    /// trigger transmission directly.
    pub fn location_service_callback(&self, fix: GpsFix) {
        if let Ok(mut st) = self.state.lock() {
            st.current_fix = Some(fix);
        }
    }

    /// Return true if at least one dynamics threshold is exceeded (§6.1.3 Condition 1).
    ///
    /// Thresholds:
    ///   - |Δheading| > 4°
    ///   - |Δposition| > 4 m (haversine)
    ///   - |Δspeed| > 0.5 m/s
    pub fn check_dynamics(&self, fix: &GpsFix) -> bool {
        let st = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return true,
        };

        if st.last_cam_heading.is_none() {
            return true; // No reference — treat as changed
        }

        // Heading
        if let Some(prev) = st.last_cam_heading {
            let mut diff = (fix.heading_deg - prev).abs();
            if diff > 180.0 {
                diff = 360.0 - diff;
            }
            if diff > 4.0 {
                return true;
            }
        }

        // Position
        if let (Some(prev_lat), Some(prev_lon)) = (st.last_cam_lat, st.last_cam_lon) {
            if haversine_m(prev_lat, prev_lon, fix.latitude, fix.longitude) > 4.0 {
                return true;
            }
        }

        // Speed
        if let Some(prev_speed) = st.last_cam_speed {
            if (fix.speed_mps - prev_speed).abs() > 0.5 {
                return true;
            }
        }

        false
    }

    /// Low-Frequency container: first CAM, then every ≥ 500 ms (§6.1.3).
    pub fn should_include_lf(&self, now_ms: u64) -> bool {
        let st = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return true,
        };
        if st.cam_count == 0 {
            return true;
        }
        match st.last_lf_time_ms {
            None => true,
            Some(t) => now_ms.saturating_sub(t) >= T_GEN_CAM_LF_MS,
        }
    }

    /// Special-Vehicle container: first CAM (if role ≠ default), then ≥ 500 ms (§6.1.3).
    pub fn should_include_special_vehicle(&self, now_ms: u64) -> bool {
        if self.vehicle_data.vehicle_role == 0 {
            return false;
        }
        let st = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return true,
        };
        if st.cam_count == 0 {
            return true;
        }
        match st.last_special_time_ms {
            None => true,
            Some(t) => now_ms.saturating_sub(t) >= T_GEN_CAM_SPECIAL_MS,
        }
    }

    /// Very-Low-Frequency extension container (§6.1.3):
    ///   - Second CAM after activation (cam_count == 1).
    ///   - After that: ≥ 10 s elapsed AND LF/special containers NOT included.
    pub fn should_include_vlf(&self, now_ms: u64, include_lf: bool, include_special: bool) -> bool {
        let st = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };
        if st.cam_count == 1 {
            return true;
        }
        match st.last_vlf_time_ms {
            None => false,
            Some(t) => {
                now_ms.saturating_sub(t) >= T_GEN_CAM_VLF_MS && !include_lf && !include_special
            }
        }
    }

    /// Two-Wheeler extension container in ALL CAMs for cyclist/moped/motorcycle (§6.1.3).
    pub fn should_include_two_wheeler(&self) -> bool {
        TWO_WHEELER_STATION_TYPES.contains(&self.vehicle_data.station_type)
    }

    /// Build the BasicVehicleContainerLowFrequency container.
    pub fn build_lf_container(&self, fix: &GpsFix, now_ms: u64) -> LowFrequencyContainer {
        let role_idx = self.vehicle_data.vehicle_role as usize;
        let role = if role_idx < VEHICLE_ROLE_NAMES.len() {
            VEHICLE_ROLE_NAMES[role_idx]
        } else {
            VehicleRole::default
        };

        let mut ext_bits = rasn::types::FixedBitString::<8>::default();
        let lights_byte = self
            .vehicle_data
            .exterior_lights
            .first()
            .copied()
            .unwrap_or(0);
        for i in 0..8 {
            if lights_byte & (1 << (7 - i)) != 0 {
                ext_bits.set(i, true);
            }
        }
        let ext_lights = ExteriorLights(ext_bits);

        let path_points = self.get_path_history(fix, now_ms);
        let path = Path(path_points);

        LowFrequencyContainer::basicVehicleContainerLowFrequency(
            BasicVehicleContainerLowFrequency::new(role, ext_lights, path),
        )
    }

    /// Convert stored path history to a list of relative PathPoint entries (capped at 23).
    pub fn get_path_history(&self, current_fix: &GpsFix, now_ms: u64) -> Vec<PathPoint> {
        let st = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let mut result = Vec::new();
        for entry in st.path_history.iter().rev() {
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

    /// Evaluate CAM conditions and generate/send if either condition 1 or 2 is met.
    pub fn evaluate_and_maybe_send(&self, now_ms: u64) -> Option<Cam> {
        let fix = {
            let st = self.state.lock().ok()?;
            st.current_fix?
        };

        let (last_time, t_gen_cam) = {
            let st = self.state.lock().ok()?;
            (
                st.last_cam_time_ms,
                self.t_gen_cam_ms.load(Ordering::SeqCst),
            )
        };

        // First CAM after activation — send immediately
        if last_time.is_none() {
            return self.generate_and_send_cam(&fix, now_ms, 1).ok();
        }

        let elapsed_ms = now_ms.saturating_sub(last_time.unwrap());

        // Condition 1 (§6.1.3): elapsed ≥ T_GenCam_DCC AND dynamics changed
        if elapsed_ms.saturating_add(5) >= T_GEN_CAM_DCC_MS && self.check_dynamics(&fix) {
            return self.generate_and_send_cam(&fix, now_ms, 1).ok();
        }

        // Condition 2 (§6.1.3): elapsed ≥ T_GenCam AND elapsed ≥ T_GenCam_DCC
        if elapsed_ms.saturating_add(5) >= t_gen_cam
            && elapsed_ms.saturating_add(5) >= T_GEN_CAM_DCC_MS
        {
            return self.generate_and_send_cam(&fix, now_ms, 2).ok();
        }

        None
    }

    /// Build, encode, and transmit a CAM (Annex B.2.4).
    pub fn generate_and_send_cam(
        &self,
        fix: &GpsFix,
        now_ms: u64,
        condition: u8,
    ) -> Result<Cam, String> {
        let elapsed_ms = self
            .state
            .lock()
            .ok()
            .and_then(|st| st.last_cam_time_ms)
            .map(|t| now_ms.saturating_sub(t))
            .unwrap_or(0);

        let include_lf = self.should_include_lf(now_ms);
        let include_special = self.should_include_special_vehicle(now_ms);
        let include_vlf = self.should_include_vlf(now_ms, include_lf, include_special);
        let include_tw = self.should_include_two_wheeler();

        // ── BasicContainer ──────────────────────────────────────────────────
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
        let basic_container = BasicContainer::new(
            TrafficParticipantType(self.vehicle_data.station_type),
            ref_pos,
        );

        // ── HighFrequencyContainer ───────────────────────────────────────────
        let heading = Heading::new(
            HeadingValue(((fix.heading_deg * 10.0).round() as u16).clamp(0, 3600)),
            HeadingConfidence(127),
        );
        let speed = Speed::new(
            SpeedValue(((fix.speed_mps * 100.0).round() as u16).min(16_382)),
            SpeedConfidence(127),
        );
        let vehicle_length = VehicleLength::new(
            VehicleLengthValue(self.vehicle_data.vehicle_length_value.clamp(1, 1023)),
            VehicleLengthConfidenceIndication::unavailable,
        );
        let vehicle_width = VehicleWidth(self.vehicle_data.vehicle_width.clamp(1, 62));
        let longitudinal_acceleration =
            AccelerationComponent::new(AccelerationValue(161), AccelerationConfidence(102));
        let curvature = Curvature::new(CurvatureValue(1023), CurvatureConfidence::unavailable);
        let yaw_rate = YawRate::new(YawRateValue(32767), YawRateConfidence::unavailable);

        let hf = BasicVehicleContainerHighFrequency::new(
            heading,
            speed,
            self.vehicle_data.drive_direction,
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

        // ── Optional Containers ──────────────────────────────────────────────
        let lf = if include_lf {
            Some(self.build_lf_container(fix, now_ms))
        } else {
            None
        };

        let special = if include_special {
            self.vehicle_data.special_vehicle_data.clone()
        } else {
            None
        };

        let mut ext_vec = Vec::new();
        if include_tw {
            let tw = TwoWheelerContainer::new(None, None, None, None);
            if let Ok(tw_bytes) = rasn::uper::encode(&tw) {
                ext_vec.push(WrappedExtensionContainer::new(
                    ExtensionContainerId(Integer::from(1i128)),
                    Any::new(tw_bytes.to_vec()),
                ));
            }
        }
        if include_vlf {
            let vlf = VeryLowFrequencyContainer::new(None, None, None);
            if let Ok(vlf_bytes) = rasn::uper::encode(&vlf) {
                ext_vec.push(WrappedExtensionContainer::new(
                    ExtensionContainerId(Integer::from(3i128)),
                    Any::new(vlf_bytes.to_vec()),
                ));
            }
        }
        let extensions = if ext_vec.is_empty() {
            None
        } else {
            Some(WrappedExtensionContainers(ext_vec))
        };

        let cam = Cam::new(
            cam_header(self.vehicle_data.station_id),
            CamPayload::new(
                generation_delta_time_now(),
                CamParameters::new(
                    basic_container,
                    HighFrequencyContainer::basicVehicleContainerHighFrequency(hf),
                    lf,
                    special,
                    extensions,
                ),
            ),
        );

        // Transmit (Annex B.2.5 — on encoding/transmission failure skip state update)
        self.send_cam(&cam)?;

        // Update state after successful send
        self.update_send_state(
            fix,
            now_ms,
            elapsed_ms,
            condition,
            include_lf,
            include_special,
            include_vlf,
        );

        Ok(cam)
    }

    /// Encode and transmit a CAM PDU via BTP-B/SHB (§5.3.4.1).
    pub fn send_cam(&self, cam: &Cam) -> Result<(), String> {
        let data = self.cam_coder.encode(cam)?;
        let request = BTPDataRequest {
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
            gn_max_packet_lifetime: Some(1.0), // §5.3.4.1: max 1000 ms
            gn_repetition_interval: None,
            gn_max_repetition_time: None,
            destination: None,
            length: data.len() as u16,
            data,
        };

        self.btp_handle.send_btp_data_request(request);

        if let Some(ref ldm) = self.ca_basic_service_ldm {
            let _ = ldm.add_provider_data_to_ldm(cam);
        }

        Ok(())
    }

    /// Update state variables after a successful CAM transmission.
    #[allow(clippy::too_many_arguments)]
    pub fn update_send_state(
        &self,
        fix: &GpsFix,
        now_ms: u64,
        elapsed_ms: u64,
        condition: u8,
        include_lf: bool,
        include_special: bool,
        include_vlf: bool,
    ) {
        if condition == 1 {
            let clamped = elapsed_ms.clamp(T_GEN_CAM_MIN_MS, T_GEN_CAM_MAX_MS);
            self.t_gen_cam_ms.store(clamped, Ordering::SeqCst);
            let prev_n = self.n_gen_cam_counter.fetch_add(1, Ordering::SeqCst);
            if prev_n + 1 >= N_GEN_CAM_DEFAULT {
                self.t_gen_cam_ms.store(T_GEN_CAM_MAX_MS, Ordering::SeqCst);
                self.n_gen_cam_counter.store(0, Ordering::SeqCst);
            }
        } else {
            self.n_gen_cam_counter.store(0, Ordering::SeqCst);
            self.t_gen_cam_ms.store(T_GEN_CAM_MAX_MS, Ordering::SeqCst);
        }

        if let Ok(mut st) = self.state.lock() {
            st.last_cam_time_ms = Some(now_ms);
            st.last_cam_heading = Some(fix.heading_deg);
            st.last_cam_lat = Some(fix.latitude);
            st.last_cam_lon = Some(fix.longitude);
            st.last_cam_speed = Some(fix.speed_mps);

            st.path_history.push(PathEntry {
                lat: fix.latitude,
                lon: fix.longitude,
                time_ms: now_ms,
            });
            if st.path_history.len() > 40 {
                st.path_history.remove(0);
            }

            if include_lf {
                st.last_lf_time_ms = Some(now_ms);
            }
            if include_special {
                st.last_special_time_ms = Some(now_ms);
            }
            if include_vlf {
                st.last_vlf_time_ms = Some(now_ms);
            }

            st.cam_count += 1;
            st.last_cam_generation_delta_time = Some(GenerationDeltaTime::from_unix_ms(now_ms));
        }
    }

    /// Spawn the transmission management thread.
    pub fn spawn(
        btp_handle: BTPRouterHandle,
        coder: CamCoder,
        vehicle_data: VehicleData,
        gps_rx: Receiver<GpsFix>,
    ) {
        let ctm = CAMTransmissionManagement::new(btp_handle, coder, vehicle_data, None);
        ctm.start();

        thread::spawn(move || {
            // Annex B.2.4 step 1 — non-clock-synchronised start (random initial delay)
            let initial_delay =
                Duration::from_millis(rand::thread_rng().gen_range(0..T_CHECK_CAM_GEN_MS));
            thread::sleep(initial_delay);

            loop {
                if !ctm.is_active() {
                    break;
                }
                let deadline = Instant::now() + Duration::from_millis(T_CHECK_CAM_GEN_MS);
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match gps_rx.recv_timeout(remaining) {
                        Ok(fix) => ctm.location_service_callback(fix),
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => {
                            return;
                        }
                    }
                }

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let _ = ctm.evaluate_and_maybe_send(now_ms);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facilities::local_dynamic_map::LdmFacility;
    use crate::geonet::mib::Mib;

    fn make_test_fix(lat: f64, lon: f64, heading: f64, speed: f64) -> GpsFix {
        GpsFix {
            latitude: lat,
            longitude: lon,
            altitude_m: 100.0,
            speed_mps: speed,
            heading_deg: heading,
            pai: true,
        }
    }

    fn make_test_ctm(
        vd: Option<VehicleData>,
        ldm: Option<CABasicServiceLDM>,
    ) -> CAMTransmissionManagement {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let vehicle_data = vd.unwrap_or_else(|| VehicleData {
            station_id: 1,
            station_type: 5,
            drive_direction: DriveDirection::forward,
            vehicle_length_value: 50,
            vehicle_width: 30,
            ..VehicleData::default()
        });
        CAMTransmissionManagement::new(btp_handle, coder, vehicle_data, ldm)
    }

    // ─── VehicleData tests ───────────────────────────────────────────────────

    #[test]
    fn test_vehicle_data_defaults_and_validation() {
        let vd = VehicleData::default();
        assert_eq!(vd.vehicle_role, 0);
        assert_eq!(vd.exterior_lights, vec![0x00]);
        assert!(vd.special_vehicle_data.is_none());
        assert!(vd.validate().is_ok());

        let mut invalid_role = vd.clone();
        invalid_role.vehicle_role = 16;
        assert!(invalid_role.validate().is_err());

        let mut invalid_lights = vd;
        invalid_lights.exterior_lights = vec![];
        assert!(invalid_lights.validate().is_err());
    }

    // ─── Haversine tests ─────────────────────────────────────────────────────

    #[test]
    fn test_haversine_properties() {
        assert!(haversine_m(41.0, 2.0, 41.0, 2.0).abs() < 1e-4);
        let d = haversine_m(41.0, 2.0, 41.000045, 2.0);
        assert!(d > 4.5 && d < 5.5);
        let d1 = haversine_m(41.0, 2.0, 41.001, 2.001);
        let d2 = haversine_m(41.001, 2.001, 41.0, 2.0);
        assert!((d1 - d2).abs() < 1e-5);
    }

    // ─── Confidence Helpers tests ────────────────────────────────────────────

    #[test]
    fn test_confidence_helpers() {
        let pos_conf = create_position_confidence(8.75, 10.59);
        assert_eq!(pos_conf.semi_major_axis_length.0, 1059);
        assert_eq!(pos_conf.semi_minor_axis_length.0, 875);

        assert_eq!(
            create_altitude_confidence(0.005),
            AltitudeConfidence::alt_000_01
        );
        assert_eq!(
            create_altitude_confidence(0.15),
            AltitudeConfidence::alt_000_20
        );
        assert_eq!(
            create_altitude_confidence(250.0),
            AltitudeConfidence::outOfRange
        );

        assert_eq!(create_heading_confidence(5.0).0, 50);
        assert_eq!(create_heading_confidence(20.0).0, 126);
    }

    // ─── Lifecycle tests ─────────────────────────────────────────────────────

    #[test]
    fn test_ctm_init_and_start_stop() {
        let ctm = make_test_ctm(None, None);
        assert_eq!(ctm.t_gen_cam(), T_GEN_CAM_MAX_MS);
        assert!(!ctm.is_active());
        assert_eq!(ctm.cam_count(), 0);
        assert!(ctm.last_cam_time_ms().is_none());

        ctm.start();
        assert!(ctm.is_active());
        // Idempotent double start
        ctm.start();
        assert!(ctm.is_active());

        ctm.stop();
        assert!(!ctm.is_active());
    }

    #[test]
    fn test_location_service_callback_caches_fix() {
        let ctm = make_test_ctm(None, None);
        let fix = make_test_fix(41.0, 2.0, 90.0, 5.0);
        ctm.location_service_callback(fix);
        let cached = ctm.state.lock().unwrap().current_fix;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().latitude, 41.0);
    }

    // ─── Dynamics check tests ────────────────────────────────────────────────

    #[test]
    fn test_dynamics_check() {
        let ctm = make_test_ctm(None, None);
        let fix = make_test_fix(41.0, 2.0, 90.0, 5.0);
        // No reference -> returns true
        assert!(ctm.check_dynamics(&fix));

        ctm.generate_and_send_cam(&fix, 1_000_000, 1).unwrap();

        // Under 4 deg heading -> false
        assert!(!ctm.check_dynamics(&make_test_fix(41.0, 2.0, 93.0, 5.0)));
        // Over 4 deg heading -> true
        assert!(ctm.check_dynamics(&make_test_fix(41.0, 2.0, 95.0, 5.0)));

        // Heading 360 wrap-around: from 358 to 3 is 5 deg -> true
        {
            let mut st = ctm.state.lock().unwrap();
            st.last_cam_heading = Some(358.0);
        }
        assert!(ctm.check_dynamics(&make_test_fix(41.0, 2.0, 3.0, 5.0)));

        // Position over 4 m -> true
        {
            let mut st = ctm.state.lock().unwrap();
            st.last_cam_heading = Some(90.0);
        }
        assert!(ctm.check_dynamics(&make_test_fix(41.000045, 2.0, 90.0, 5.0)));

        // Speed diff over 0.5 m/s -> true
        assert!(ctm.check_dynamics(&make_test_fix(41.0, 2.0, 90.0, 5.6)));
        // Speed diff under 0.5 m/s -> false
        assert!(!ctm.check_dynamics(&make_test_fix(41.0, 2.0, 90.0, 5.4)));
    }

    // ─── Container inclusion tests ───────────────────────────────────────────

    #[test]
    fn test_container_inclusions() {
        let ctm = make_test_ctm(None, None);
        // LF on first CAM
        assert!(ctm.should_include_lf(1000));
        // Special not on default role
        assert!(!ctm.should_include_special_vehicle(1000));

        let ctm_spec = make_test_ctm(
            Some(VehicleData {
                vehicle_role: 6,
                ..VehicleData::default()
            }),
            None,
        );
        // Special on first CAM when role != default
        assert!(ctm_spec.should_include_special_vehicle(1000));

        // VLF: not on first CAM, but on second CAM (cam_count == 1)
        assert!(!ctm.should_include_vlf(1000, false, false));
        {
            let mut st = ctm.state.lock().unwrap();
            st.cam_count = 1;
        }
        assert!(ctm.should_include_vlf(1000, false, false));

        // Two-Wheeler
        let ctm_cyclist = make_test_ctm(
            Some(VehicleData {
                station_type: 2,
                ..VehicleData::default()
            }),
            None,
        );
        assert!(ctm_cyclist.should_include_two_wheeler());
        assert!(!ctm.should_include_two_wheeler());
    }

    // ─── T_GenCam State Machine tests ────────────────────────────────────────

    #[test]
    fn test_condition1_sets_t_gen_cam_to_elapsed() {
        let ctm = make_test_ctm(None, None);
        let fix = make_test_fix(41.0, 2.0, 90.0, 5.0);

        // Prior CAM at 1000 ms
        ctm.generate_and_send_cam(&fix, 1_000, 1).unwrap();

        // Elapsed = 1500 - 1000 = 500 ms
        ctm.generate_and_send_cam(&fix, 1_500, 1).unwrap();
        assert_eq!(ctm.t_gen_cam(), 500);
    }

    #[test]
    fn test_condition2_resets_t_gen_cam_to_max() {
        let ctm = make_test_ctm(None, None);
        let fix = make_test_fix(41.0, 2.0, 90.0, 5.0);

        ctm.generate_and_send_cam(&fix, 1_000, 1).unwrap();
        ctm.t_gen_cam_ms.store(400, Ordering::SeqCst);

        // Condition 2 resets T_GenCam to T_GenCamMax
        ctm.generate_and_send_cam(&fix, 3_000, 2).unwrap();
        assert_eq!(ctm.t_gen_cam(), T_GEN_CAM_MAX_MS);
    }

    #[test]
    fn test_n_gen_cam_resets_after_default_consecutive() {
        let ctm = make_test_ctm(None, None);
        let fix = make_test_fix(41.0, 2.0, 90.0, 5.0);

        ctm.generate_and_send_cam(&fix, 1_000, 1).unwrap();
        ctm.n_gen_cam_counter
            .store(N_GEN_CAM_DEFAULT - 1, Ordering::SeqCst);

        // Third consecutive condition-1 CAM
        ctm.generate_and_send_cam(&fix, 1_500, 1).unwrap();
        assert_eq!(ctm.t_gen_cam(), T_GEN_CAM_MAX_MS);
        assert_eq!(ctm.n_gen_cam_counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_t_gen_cam_clamped_to_min() {
        let ctm = make_test_ctm(None, None);
        let fix = make_test_fix(41.0, 2.0, 90.0, 5.0);

        ctm.generate_and_send_cam(&fix, 1_950, 1).unwrap();
        // Elapsed = 2000 - 1950 = 50 ms < 100 ms -> clamped to T_GEN_CAM_MIN_MS
        ctm.generate_and_send_cam(&fix, 2_000, 1).unwrap();
        assert_eq!(ctm.t_gen_cam(), T_GEN_CAM_MIN_MS);
    }

    // ─── Conditions Evaluation integration tests ─────────────────────────────

    #[test]
    fn test_evaluate_and_maybe_send() {
        let ctm = make_test_ctm(None, None);
        // No fix -> None
        assert!(ctm.evaluate_and_maybe_send(1000).is_none());

        let fix = make_test_fix(41.0, 2.0, 90.0, 5.0);
        ctm.location_service_callback(fix);

        // First CAM sends immediately
        let first = ctm.evaluate_and_maybe_send(1000);
        assert!(first.is_some());

        // Condition 2 triggers after t_gen_cam
        assert!(ctm.evaluate_and_maybe_send(1050).is_none());
        assert!(ctm.evaluate_and_maybe_send(2001).is_some());
    }

    // ─── Path History tests ──────────────────────────────────────────────────

    #[test]
    fn test_path_history() {
        let ctm = make_test_ctm(None, None);
        let fix1 = make_test_fix(41.0001, 2.0, 90.0, 5.0);
        ctm.generate_and_send_cam(&fix1, 1_000_000, 1).unwrap();

        let fix2 = make_test_fix(41.0, 2.0, 90.0, 5.0);
        let pts = ctm.get_path_history(&fix2, 1_001_000);
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].path_position.delta_latitude.0, 1000);
    }

    // ─── LDM integration test ────────────────────────────────────────────────

    #[test]
    fn test_send_cam_updates_ldm_when_present() {
        let ldm = LdmFacility::new(415_520_000, 21_340_000, 50_000.0);
        let ldm_adapter = CABasicServiceLDM::new(ldm, 5);
        let ctm = make_test_ctm(None, Some(ldm_adapter));
        let fix = make_test_fix(41.552, 2.134, 90.0, 5.0);
        let res = ctm.generate_and_send_cam(&fix, 1_000, 1);
        assert!(res.is_ok());
    }
}

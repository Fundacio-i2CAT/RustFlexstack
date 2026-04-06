// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CAM UPER codec shim.
//!
//! Re-exports the compiled ASN.1 types from [`super::cam_bindings`] and
//! wraps the stateless UPER encode/decode calls in a [`CamCoder`] struct
//! that can be cloned and shared cheaply between threads.
//!
//! All ASN.1 type definitions live in [`super::cam_bindings`].

// ─── Re-exports from compiled ASN.1 bindings ────────────────────────────────

pub use super::cam_bindings::cam_pdu_descriptions::{
    BasicVehicleContainerHighFrequency, CamParameters, CamPayload, HighFrequencyContainer, CAM,
};
pub use super::cam_bindings::etsi_its_cdd::{
    AccelerationComponent, AccelerationConfidence, AccelerationValue, Altitude, AltitudeConfidence,
    AltitudeValue, BasicContainer, Curvature, CurvatureCalculationMode, CurvatureConfidence,
    CurvatureValue, DriveDirection, GenerationDeltaTime, Heading, HeadingConfidence, HeadingValue,
    ItsPduHeader, Latitude, Longitude, MessageId, OrdinalNumber1B, PositionConfidenceEllipse,
    ReferencePositionWithConfidence, SemiAxisLength, Speed, SpeedConfidence, SpeedValue, StationId,
    StationType, TrafficParticipantType, VehicleLength, VehicleLengthConfidenceIndication,
    VehicleLengthValue, VehicleWidth, Wgs84AngleValue, YawRate, YawRateConfidence, YawRateValue,
};

// ─── GenerationDeltaTime helpers ─────────────────────────────────────────────

/// ITS epoch offset from UNIX epoch in milliseconds
/// (2004-01-01T00:00:00 UTC = 1 072 911 600 s).
const ITS_EPOCH_MS: u64 = 1_072_911_600_000;

/// Compute a [`GenerationDeltaTime`] from a UNIX timestamp in milliseconds.
pub fn generation_delta_time_from_unix_ms(unix_ms: u64) -> GenerationDeltaTime {
    let tai_ms = unix_ms.saturating_sub(ITS_EPOCH_MS);
    GenerationDeltaTime((tai_ms % 65_536) as u16)
}

/// Return a [`GenerationDeltaTime`] for the current wall-clock time.
pub fn generation_delta_time_now() -> GenerationDeltaTime {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    generation_delta_time_from_unix_ms(ms)
}

// ─── ITS PDU Header helper ────────────────────────────────────────────────────

/// Build a standard CAM ITS PDU Header (protocol version 2, message ID 2).
pub fn cam_header(station_id: u32) -> ItsPduHeader {
    ItsPduHeader::new(OrdinalNumber1B(2), MessageId(2), StationId(station_id))
}

// ─── Top-level type alias ─────────────────────────────────────────────────────

/// Top-level CAM PDU (alias for [`CAM`] from cam_bindings).
pub type Cam = CAM;

// ─── CamCoder ────────────────────────────────────────────────────────────────

/// UPER encoder/decoder for CAM PDUs.
///
/// Mirrors `CAMCoder` in `flexstack/facilities/ca_basic_service/cam_coder.py`.
///
/// Internally stateless. `Clone` is cheap — used to share a single instance
/// between the transmission and reception management threads.
#[derive(Clone, Debug, Default)]
pub struct CamCoder;

impl CamCoder {
    pub fn new() -> Self {
        CamCoder
    }

    /// UPER-encode a [`Cam`] PDU to bytes.
    pub fn encode(&self, cam: &Cam) -> Result<Vec<u8>, String> {
        rasn::uper::encode(cam)
            .map(|b| b.to_vec())
            .map_err(|e| format!("CAM UPER encode error: {e}"))
    }

    /// UPER-decode a [`Cam`] PDU from bytes.
    pub fn decode(&self, bytes: &[u8]) -> Result<Cam, String> {
        rasn::uper::decode::<Cam>(bytes).map_err(|e| format!("CAM UPER decode error: {e}"))
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! VAM UPER codec shim.
//!
//! Re-exports the compiled ASN.1 types from [`super::vam_bindings`] and
//! wraps the stateless UPER encode/decode calls in a [`VamCoder`] struct
//! that can be cloned and shared cheaply between threads.
//!
//! All ASN.1 type definitions live in [`super::vam_bindings`].

// ─── Re-exports from compiled ASN.1 bindings ─────────────────────────────────

pub use super::vam_bindings::etsi_its_cdd::{
    AccelerationConfidence, Altitude, AltitudeConfidence, AltitudeValue, BasicContainer, Curvature,
    CurvatureCalculationMode, GenerationDeltaTime, ItsPduHeader, Latitude, Longitude,
    LongitudinalAcceleration, LongitudinalAccelerationValue, MessageId, OrdinalNumber1B,
    PositionConfidenceEllipse, ReferencePositionWithConfidence, SemiAxisLength, Speed,
    SpeedConfidence, SpeedValue, StationId, TrafficParticipantType, Wgs84Angle,
    Wgs84AngleConfidence, Wgs84AngleValue,
};
pub use super::vam_bindings::vam_pdu_descriptions::{
    ItsPduHeaderVam, VamParameters, VruAwareness, VruHighFrequencyContainer,
    VruLowFrequencyContainer, VruMotionPredictionContainer, VAM,
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

/// Build a standard VAM ITS PDU Header (protocol version 3, message ID 16).
///
/// Wraps the raw [`ItsPduHeader`] in [`ItsPduHeaderVam`] as required by the
/// VAM PDU descriptor.
pub fn vam_header(station_id: u32) -> ItsPduHeaderVam {
    ItsPduHeaderVam(ItsPduHeader::new(
        OrdinalNumber1B(3),
        MessageId(16),
        StationId(station_id),
    ))
}

// ─── Top-level type alias ─────────────────────────────────────────────────────

/// Top-level VAM PDU (alias for [`VAM`] from vam_bindings).
pub type Vam = VAM;

// ─── VamCoder ────────────────────────────────────────────────────────────────

/// UPER encoder/decoder for VAM PDUs.
///
/// Mirrors `VAMCoder` in `flexstack/facilities/vru_awareness_service/`.
///
/// Internally stateless. `Clone` is cheap — used to share a single instance
/// between the transmission and reception management threads.
#[derive(Clone, Debug, Default)]
pub struct VamCoder;

impl VamCoder {
    pub fn new() -> Self {
        VamCoder
    }

    /// UPER-encode a [`Vam`] PDU to bytes.
    pub fn encode(&self, vam: &Vam) -> Result<Vec<u8>, String> {
        rasn::uper::encode(vam)
            .map(|b| b.to_vec())
            .map_err(|e| format!("VAM UPER encode error: {e}"))
    }

    /// UPER-decode a [`Vam`] PDU from bytes.
    pub fn decode(&self, bytes: &[u8]) -> Result<Vam, String> {
        rasn::uper::decode::<Vam>(bytes).map_err(|e| format!("VAM UPER decode error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_delta_time_from_unix_ms_basic() {
        let gdt = generation_delta_time_from_unix_ms(ITS_EPOCH_MS + 2000);
        assert_eq!(gdt.0, 2000);
    }

    #[test]
    fn generation_delta_time_wraps() {
        let gdt = generation_delta_time_from_unix_ms(ITS_EPOCH_MS + 65_536);
        assert_eq!(gdt.0, 0);
    }

    #[test]
    fn generation_delta_time_now_runs() {
        let _ = generation_delta_time_now();
    }

    #[test]
    fn vam_header_fields() {
        let hdr = vam_header(123);
        assert_eq!(hdr.0.protocol_version.0, 3);
        assert_eq!(hdr.0.message_id.0, 16);
        assert_eq!(hdr.0.station_id.0, 123);
    }

    #[test]
    fn vam_coder_new() {
        let coder = VamCoder::new();
        let coder2 = coder.clone();
        let _ = format!("{:?}", coder2);
    }

    #[test]
    fn vam_coder_default() {
        let _coder = VamCoder;
    }

    #[test]
    fn vam_coder_decode_invalid_bytes() {
        let coder = VamCoder::new();
        let result = coder.decode(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }
}

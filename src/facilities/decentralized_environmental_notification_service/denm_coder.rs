// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DENM UPER codec shim.
//!
//! Re-exports the compiled ASN.1 types from [`super::denm_bindings`] and
//! wraps the stateless UPER encode/decode calls in a [`DenmCoder`] struct
//! that can be cloned and shared cheaply between threads.
//!
//! All ASN.1 type definitions live in [`super::denm_bindings`].

// ─── Re-exports from compiled ASN.1 bindings ─────────────────────────────────

pub use super::denm_bindings::denm_pdu_description::{
    AlacarteContainer, DenmPayload, LocationContainer, ManagementContainer, SituationContainer,
    Termination, DENM,
};
pub use super::denm_bindings::etsi_its_cdd::{
    AccidentSubCauseCode, ActionId, Altitude, AltitudeConfidence, AltitudeValue, CauseCodeChoice,
    CauseCodeV2, DeltaAltitude, DeltaLatitude, DeltaLongitude, DeltaReferencePosition,
    DeltaTimeMilliSecondPositive, DeltaTimeSecond, HeadingValue, InformationQuality, ItsPduHeader,
    Latitude, Longitude, MessageId, OrdinalNumber1B, Path, PathPoint, PosConfidenceEllipse,
    ReferencePosition, SemiAxisLength, SequenceNumber, Speed, SpeedConfidence, SpeedValue,
    StationId, StationType, SubCauseCodeType, TimestampIts, Traces, TrafficParticipantType,
    Wgs84Angle, Wgs84AngleConfidence, Wgs84AngleValue,
};

// ─── ITS epoch constant ───────────────────────────────────────────────────────

/// ITS epoch offset from UNIX epoch in milliseconds
/// (2004-01-01T00:00:00 UTC = 1 072 911 600 s).
const ITS_EPOCH_MS: u64 = 1_072_911_600_000;

/// Return the current ITS timestamp (milliseconds since ITS epoch) as a
/// [`TimestampIts`].
///
/// TimestampIts is a u64 counting milliseconds since 2004-01-01T00:00:00 UTC.
pub fn timestamp_its_now() -> TimestampIts {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    TimestampIts(unix_ms.saturating_sub(ITS_EPOCH_MS))
}

// ─── ITS PDU Header helper ────────────────────────────────────────────────────

/// Build a standard DENM ITS PDU Header (protocol version 2, message ID 1).
pub fn denm_header(station_id: u32) -> ItsPduHeader {
    ItsPduHeader::new(OrdinalNumber1B(2), MessageId(1), StationId(station_id))
}

// ─── Top-level type alias ─────────────────────────────────────────────────────

/// Top-level DENM PDU (alias for [`DENM`] from denm_bindings).
pub type Denm = DENM;

// ─── DenmCoder ───────────────────────────────────────────────────────────────

/// UPER encoder/decoder for DENM PDUs.
///
/// Mirrors `DENMCoder` in
/// `flexstack/facilities/decentralized_environmental_notification_service/denm_coder.py`.
///
/// Internally stateless. `Clone` is cheap — used to share a single instance
/// between the transmission and reception management threads.
#[derive(Clone, Debug, Default)]
pub struct DenmCoder;

impl DenmCoder {
    pub fn new() -> Self {
        DenmCoder
    }

    /// UPER-encode a [`Denm`] PDU to bytes.
    pub fn encode(&self, denm: &Denm) -> Result<Vec<u8>, String> {
        rasn::uper::encode(denm)
            .map(|b| b.to_vec())
            .map_err(|e| format!("DENM UPER encode error: {e}"))
    }

    /// UPER-decode a [`Denm`] PDU from bytes.
    pub fn decode(&self, bytes: &[u8]) -> Result<Denm, String> {
        rasn::uper::decode::<Denm>(bytes).map_err(|e| format!("DENM UPER decode error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_its_now_positive() {
        let ts = timestamp_its_now();
        assert!(ts.0 > 0);
    }

    #[test]
    fn denm_header_fields() {
        let hdr = denm_header(99);
        assert_eq!(hdr.protocol_version.0, 2);
        assert_eq!(hdr.message_id.0, 1);
        assert_eq!(hdr.station_id.0, 99);
    }

    #[test]
    fn denm_coder_new() {
        let coder = DenmCoder::new();
        let coder2 = coder.clone();
        let _ = format!("{:?}", coder2);
    }

    #[test]
    fn denm_coder_default() {
        let _coder = DenmCoder;
    }

    #[test]
    fn denm_coder_decode_invalid_bytes() {
        let coder = DenmCoder::new();
        let result = coder.decode(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }
}

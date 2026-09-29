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
    BasicVehicleContainerHighFrequency, BasicVehicleContainerLowFrequency, CamParameters,
    CamPayload, EHorizonLocationSharingContainer, ExtensionContainerId,
    GeneralizedLanePositionsContainer, HighFrequencyContainer, LowFrequencyContainer,
    PathPredictionContainer, SpecialVehicleContainer, TwoWheelerContainer,
    VehicleMovementControlContainer, VeryLowFrequencyContainer, WrappedExtensionContainer,
    WrappedExtensionContainers, CAM,
};
pub use super::cam_bindings::etsi_its_cdd::{
    AccelerationComponent, AccelerationConfidence, AccelerationValue, Altitude, AltitudeConfidence,
    AltitudeValue, BasicContainer, Curvature, CurvatureCalculationMode, CurvatureConfidence,
    CurvatureValue, DeltaAltitude, DeltaLatitude, DeltaLongitude, DeltaReferencePosition,
    DriveDirection, ExteriorLights, GenerationDeltaTime, Heading, HeadingConfidence, HeadingValue,
    ItsPduHeader, Latitude, Longitude, MessageId, OrdinalNumber1B, Path, PathDeltaTime, PathPoint,
    PositionConfidenceEllipse, ReferencePositionWithConfidence, SemiAxisLength, Speed,
    SpeedConfidence, SpeedValue, StationId, StationType, TrafficParticipantType, VehicleLength,
    VehicleLengthConfidenceIndication, VehicleLengthValue, VehicleRole, VehicleWidth,
    Wgs84AngleValue, YawRate, YawRateConfidence, YawRateValue,
};

use rasn::prelude::*;
use std::ops::{Add, Sub};

// ─── Extension container IDs (§6.1.3) ────────────────────────────────────────

pub const EXTENSION_CONTAINER_ID_TWO_WHEELER: u8 = 1;
pub const EXTENSION_CONTAINER_ID_E_HORIZON: u8 = 2;
pub const EXTENSION_CONTAINER_ID_VLF: u8 = 3;
pub const EXTENSION_CONTAINER_ID_PATH_PREDICTION: u8 = 4;
pub const EXTENSION_CONTAINER_ID_GEN_LANE_POS: u8 = 5;
pub const EXTENSION_CONTAINER_ID_VEHICLE_MOVEMENT_CONTROL: u8 = 6;

/// High-level enum wrapping the six ETSI extension containers.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtensionContainer {
    TwoWheeler(TwoWheelerContainer),
    EHorizonLocationSharing(EHorizonLocationSharingContainer),
    VeryLowFrequency(VeryLowFrequencyContainer),
    PathPrediction(PathPredictionContainer),
    GeneralizedLanePositions(GeneralizedLanePositionsContainer),
    VehicleMovementControl(VehicleMovementControlContainer),
}

impl ExtensionContainer {
    pub fn container_id(&self) -> u8 {
        match self {
            Self::TwoWheeler(_) => EXTENSION_CONTAINER_ID_TWO_WHEELER,
            Self::EHorizonLocationSharing(_) => EXTENSION_CONTAINER_ID_E_HORIZON,
            Self::VeryLowFrequency(_) => EXTENSION_CONTAINER_ID_VLF,
            Self::PathPrediction(_) => EXTENSION_CONTAINER_ID_PATH_PREDICTION,
            Self::GeneralizedLanePositions(_) => EXTENSION_CONTAINER_ID_GEN_LANE_POS,
            Self::VehicleMovementControl(_) => EXTENSION_CONTAINER_ID_VEHICLE_MOVEMENT_CONTROL,
        }
    }
}

// ─── GenerationDeltaTime helpers ─────────────────────────────────────────────

/// ITS epoch offset from UNIX epoch in milliseconds
/// (2004-01-01T00:00:00 UTC = 1 072 915 200 s).
pub const ITS_EPOCH_MS: u64 = 1_072_915_200_000;
/// Elapsed milliseconds offset (leap seconds between 2004 and TAI/ITS time).
pub const ELAPSED_MILLISECONDS: u64 = 5_000;

impl GenerationDeltaTime {
    pub fn new(msec: u16) -> Self {
        GenerationDeltaTime(msec)
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    /// Set the Generation Delta Time from a normal UTC timestamp in seconds.
    pub fn from_timestamp(utc_timestamp_in_seconds: f64) -> Self {
        let ms = (utc_timestamp_in_seconds * 1000.0).round() as i64;
        let diff = ms - (ITS_EPOCH_MS as i64) + (ELAPSED_MILLISECONDS as i64);
        let msec = diff.rem_euclid(65536) as u16;
        GenerationDeltaTime(msec)
    }

    /// Compute a [`GenerationDeltaTime`] from a UNIX timestamp in milliseconds.
    pub fn from_unix_ms(unix_ms: u64) -> Self {
        let diff = (unix_ms as i64) - (ITS_EPOCH_MS as i64) + (ELAPSED_MILLISECONDS as i64);
        let msec = diff.rem_euclid(65536) as u16;
        GenerationDeltaTime(msec)
    }

    /// Returns the generation delta time as timestamp as it would be if received at
    /// a certain point in time (in milliseconds).
    pub fn as_timestamp_in_certain_point(&self, utc_timestamp_in_millis: u64) -> u64 {
        let diff = (utc_timestamp_in_millis as i64) - (ITS_EPOCH_MS as i64)
            + (ELAPSED_MILLISECONDS as i64);
        let number_of_cycles = diff / 65536;
        let transformed_timestamp =
            (self.0 as i64) + 65536 * number_of_cycles + (ITS_EPOCH_MS as i64)
                - (ELAPSED_MILLISECONDS as i64);

        if transformed_timestamp <= utc_timestamp_in_millis as i64 {
            transformed_timestamp as u64
        } else {
            ((self.0 as i64) + 65536 * (number_of_cycles - 1) + (ITS_EPOCH_MS as i64)
                - (ELAPSED_MILLISECONDS as i64)) as u64
        }
    }
}

impl Add for GenerationDeltaTime {
    type Output = GenerationDeltaTime;
    fn add(self, rhs: Self) -> Self::Output {
        GenerationDeltaTime(((self.0 as u32 + rhs.0 as u32) % 65536) as u16)
    }
}

impl Sub for GenerationDeltaTime {
    type Output = GenerationDeltaTime;
    fn sub(self, rhs: Self) -> Self::Output {
        let diff = (self.0 as i32) - (rhs.0 as i32);
        let result = if diff < 0 { diff + 65536 } else { diff };
        GenerationDeltaTime(result as u16)
    }
}

/// Compute a [`GenerationDeltaTime`] from a UNIX timestamp in milliseconds.
pub fn generation_delta_time_from_unix_ms(unix_ms: u64) -> GenerationDeltaTime {
    GenerationDeltaTime::from_unix_ms(unix_ms)
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

/// Generate the standard ETSI white CAM.
pub fn generate_white_cam_static() -> Cam {
    let header = ItsPduHeader::new(OrdinalNumber1B(2), MessageId(2), StationId(0));

    let ref_pos = ReferencePositionWithConfidence::new(
        Latitude(900_000_001),
        Longitude(1_800_000_001),
        PositionConfidenceEllipse::new(
            SemiAxisLength(4095),
            SemiAxisLength(4095),
            Wgs84AngleValue(3601),
        ),
        Altitude::new(AltitudeValue(800_001), AltitudeConfidence::unavailable),
    );
    let basic_container = BasicContainer::new(TrafficParticipantType(0), ref_pos);

    let heading = Heading::new(HeadingValue(3601), HeadingConfidence(127));
    let speed = Speed::new(SpeedValue(16383), SpeedConfidence(127));
    let vehicle_length = VehicleLength::new(
        VehicleLengthValue(1023),
        VehicleLengthConfidenceIndication::unavailable,
    );
    let vehicle_width = VehicleWidth(62);
    let longitudinal_acceleration =
        AccelerationComponent::new(AccelerationValue(161), AccelerationConfidence(102));
    let curvature = Curvature::new(CurvatureValue(1023), CurvatureConfidence::unavailable);
    let yaw_rate = YawRate::new(YawRateValue(32767), YawRateConfidence::unavailable);

    let hf = BasicVehicleContainerHighFrequency::new(
        heading,
        speed,
        DriveDirection::unavailable,
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
        header,
        CamPayload::new(
            GenerationDeltaTime(0),
            CamParameters::new(
                basic_container,
                HighFrequencyContainer::basicVehicleContainerHighFrequency(hf),
                None,
                None,
                None,
            ),
        ),
    )
}

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

    /// Encode an extension container to UPER bytes.
    pub fn encode_extension_container(
        &self,
        container_id: u8,
        container: &ExtensionContainer,
    ) -> Result<Vec<u8>, String> {
        if container.container_id() != container_id {
            return Err(format!(
                "Container variant id {} does not match requested id {container_id}",
                container.container_id()
            ));
        }
        match container {
            ExtensionContainer::TwoWheeler(c) => rasn::uper::encode(c)
                .map(|b| b.to_vec())
                .map_err(|e| format!("TwoWheelerContainer encode error: {e}")),
            ExtensionContainer::EHorizonLocationSharing(c) => rasn::uper::encode(c)
                .map(|b| b.to_vec())
                .map_err(|e| format!("EHorizonLocationSharingContainer encode error: {e}")),
            ExtensionContainer::VeryLowFrequency(c) => rasn::uper::encode(c)
                .map(|b| b.to_vec())
                .map_err(|e| format!("VeryLowFrequencyContainer encode error: {e}")),
            ExtensionContainer::PathPrediction(c) => rasn::uper::encode(c)
                .map(|b| b.to_vec())
                .map_err(|e| format!("PathPredictionContainer encode error: {e}")),
            ExtensionContainer::GeneralizedLanePositions(c) => rasn::uper::encode(c)
                .map(|b| b.to_vec())
                .map_err(|e| format!("GeneralizedLanePositionsContainer encode error: {e}")),
            ExtensionContainer::VehicleMovementControl(c) => rasn::uper::encode(c)
                .map(|b| b.to_vec())
                .map_err(|e| format!("VehicleMovementControlContainer encode error: {e}")),
        }
    }

    /// Decode raw bytes of an extension container by its container ID.
    pub fn decode_extension_container(
        &self,
        container_id: u8,
        data: &[u8],
    ) -> Result<ExtensionContainer, String> {
        match container_id {
            EXTENSION_CONTAINER_ID_TWO_WHEELER => rasn::uper::decode::<TwoWheelerContainer>(data)
                .map(ExtensionContainer::TwoWheeler)
                .map_err(|e| format!("TwoWheelerContainer decode error: {e}")),
            EXTENSION_CONTAINER_ID_E_HORIZON => {
                rasn::uper::decode::<EHorizonLocationSharingContainer>(data)
                    .map(ExtensionContainer::EHorizonLocationSharing)
                    .map_err(|e| format!("EHorizonLocationSharingContainer decode error: {e}"))
            }
            EXTENSION_CONTAINER_ID_VLF => rasn::uper::decode::<VeryLowFrequencyContainer>(data)
                .map(ExtensionContainer::VeryLowFrequency)
                .map_err(|e| format!("VeryLowFrequencyContainer decode error: {e}")),
            EXTENSION_CONTAINER_ID_PATH_PREDICTION => {
                rasn::uper::decode::<PathPredictionContainer>(data)
                    .map(ExtensionContainer::PathPrediction)
                    .map_err(|e| format!("PathPredictionContainer decode error: {e}"))
            }
            EXTENSION_CONTAINER_ID_GEN_LANE_POS => {
                rasn::uper::decode::<GeneralizedLanePositionsContainer>(data)
                    .map(ExtensionContainer::GeneralizedLanePositions)
                    .map_err(|e| format!("GeneralizedLanePositionsContainer decode error: {e}"))
            }
            EXTENSION_CONTAINER_ID_VEHICLE_MOVEMENT_CONTROL => {
                rasn::uper::decode::<VehicleMovementControlContainer>(data)
                    .map(ExtensionContainer::VehicleMovementControl)
                    .map_err(|e| format!("VehicleMovementControlContainer decode error: {e}"))
            }
            unknown => Err(format!("Unknown ExtensionContainerId: {unknown}")),
        }
    }

    /// Wrap an extension container into a [`WrappedExtensionContainer`].
    pub fn wrap_extension_container(
        &self,
        container: &ExtensionContainer,
    ) -> Result<WrappedExtensionContainer, String> {
        let id = container.container_id();
        let bytes = self.encode_extension_container(id, container)?;
        Ok(WrappedExtensionContainer::new(
            ExtensionContainerId(Integer::from(id as i128)),
            Any::new(bytes),
        ))
    }

    /// Unwrap a [`WrappedExtensionContainer`] into an [`ExtensionContainer`].
    pub fn unwrap_extension_container(
        &self,
        wrapped: &WrappedExtensionContainer,
    ) -> Result<ExtensionContainer, String> {
        let id = wrapped
            .container_id
            .0
            .to_string()
            .parse::<u8>()
            .map_err(|e| format!("Invalid container id in wrapped container: {e}"))?;
        self.decode_extension_container(id, wrapped.container_data.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_delta_time_set_in_normal_timestamp() {
        let timestamp: f64 = 1675871599.0;
        let gdt = GenerationDeltaTime::from_timestamp(timestamp);
        let expected = (((timestamp * 1000.0) as i64 - 1072915200000 + 5000) % 65536) as u16;
        assert_eq!(gdt.0, expected);
        assert_eq!(gdt.0, 38176);
    }

    #[test]
    fn generation_delta_time_as_timestamp_in_certain_point() {
        let timestamp = 1755763553.722;
        let reception_timestamp_millis = ((timestamp + 0.3) * 1000.0) as u64;
        let gdt = GenerationDeltaTime::from_timestamp(timestamp);
        assert_eq!(
            gdt.as_timestamp_in_certain_point(reception_timestamp_millis),
            (timestamp * 1000.0).round() as u64
        );
    }

    #[test]
    fn generation_delta_time_operators() {
        let ts1 = GenerationDeltaTime::from_timestamp(1675871599.0);
        let ts2 = GenerationDeltaTime::from_timestamp(1675871600.0);
        assert!(ts2.0 > ts1.0);
        assert!(ts1.0 < ts2.0);

        let gdt = GenerationDeltaTime::from_timestamp(1675871599.0);
        let result = gdt.clone() + GenerationDeltaTime(30);
        assert_eq!(result.0, ((gdt.0 as u32 + 30) % 65536) as u16);

        let gdt1 = GenerationDeltaTime(20);
        let gdt2 = GenerationDeltaTime(30);
        assert_eq!((gdt1 - gdt2).0, 65526);
    }

    #[test]
    fn cam_header_fields() {
        let hdr = cam_header(42);
        assert_eq!(hdr.protocol_version.0, 2);
        assert_eq!(hdr.message_id.0, 2);
        assert_eq!(hdr.station_id.0, 42);
    }

    #[test]
    fn cam_coder_new() {
        let coder = CamCoder::new();
        let coder2 = coder.clone();
        let _ = format!("{:?}", coder2);
    }

    #[test]
    fn cam_coder_decode_invalid_bytes() {
        let coder = CamCoder::new();
        let result = coder.decode(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn white_cam_exact_wire_encoding() {
        let coder = CamCoder::new();
        let white_cam = generate_white_cam_static();
        let encoded = coder.encode(&white_cam).expect("encode white cam");
        let expected = b"\x02\x02\x00\x00\x00\x00\x00\x00\x00\ri:@:\xd2t\x80\
            ?\xff\xff\xfc#\xb7t>\x00\xe1\x1f\xdf\xff\xfe\xbf\xe9\
            \xed\x077\xfe\xeb\xff\xf6\x00";
        assert_eq!(encoded, expected);
        let decoded = coder.decode(&encoded).expect("decode white cam");
        assert_eq!(decoded.header.protocol_version.0, 2);
        assert_eq!(decoded.header.station_id.0, 0);
    }

    #[test]
    fn extension_container_unknown_id_raises() {
        let coder = CamCoder::new();
        let err = coder.decode_extension_container(99, &[0x00]);
        assert!(err.is_err());
    }

    #[test]
    fn vlf_extension_container_roundtrip() {
        let coder = CamCoder::new();
        let vlf =
            ExtensionContainer::VeryLowFrequency(VeryLowFrequencyContainer::new(None, None, None));
        let bytes = coder
            .encode_extension_container(EXTENSION_CONTAINER_ID_VLF, &vlf)
            .expect("encode vlf");
        assert_eq!(bytes, vec![0x00]);
        let decoded = coder
            .decode_extension_container(EXTENSION_CONTAINER_ID_VLF, &bytes)
            .expect("decode vlf");
        assert_eq!(decoded, vlf);
    }

    #[test]
    fn two_wheeler_extension_container_roundtrip() {
        let coder = CamCoder::new();
        let tw = ExtensionContainer::TwoWheeler(TwoWheelerContainer::new(None, None, None, None));
        let bytes = coder
            .encode_extension_container(EXTENSION_CONTAINER_ID_TWO_WHEELER, &tw)
            .expect("encode tw");
        assert_eq!(bytes, vec![0x00]);
        let decoded = coder
            .decode_extension_container(EXTENSION_CONTAINER_ID_TWO_WHEELER, &bytes)
            .expect("decode tw");
        assert_eq!(decoded, tw);
    }

    #[test]
    fn extension_containers_in_cam_roundtrip() {
        let coder = CamCoder::new();
        let mut cam = generate_white_cam_static();

        let vlf =
            ExtensionContainer::VeryLowFrequency(VeryLowFrequencyContainer::new(None, None, None));
        let tw = ExtensionContainer::TwoWheeler(TwoWheelerContainer::new(None, None, None, None));

        let wrapped_vlf = coder.wrap_extension_container(&vlf).expect("wrap vlf");
        let wrapped_tw = coder.wrap_extension_container(&tw).expect("wrap tw");

        cam.cam.cam_parameters.extension_containers =
            Some(WrappedExtensionContainers(vec![wrapped_vlf, wrapped_tw]));

        let encoded = coder.encode(&cam).expect("encode cam with extensions");
        let decoded = coder.decode(&encoded).expect("decode cam with extensions");

        let exts = decoded
            .cam
            .cam_parameters
            .extension_containers
            .expect("extensionContainers");
        assert_eq!(exts.0.len(), 2);

        let unwrapped0 = coder.unwrap_extension_container(&exts.0[0]).unwrap();
        let unwrapped1 = coder.unwrap_extension_container(&exts.0[1]).unwrap();
        assert_eq!(unwrapped0, vlf);
        assert_eq!(unwrapped1, tw);
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DENM Transmission Management.
//!
//! Mirrors `DENMTransmissionManagement` in
//! `flexstack/facilities/decentralized_environmental_notification_service/denm_transmission_management.py`.
//!
//! The main entry point is [`DENMTransmissionManagement::trigger_denm_sending`],
//! which spawns a background thread that:
//! 1. Builds DENM PDUs from a [`DENRequest`] and static vehicle data.
//! 2. UPER-encodes each DENM via [`DenmCoder`].
//! 3. Sends a [`BTPDataRequest`] on BTP port **2002** using GeoBroadcast-Circle
//!    transport, centred at the event position.
//!
//! Transmission repeats at the interval specified in the [`DENRequest`] until
//! the configured `time_period_ms` has elapsed.

use super::denm_coder::{
    denm_header, timestamp_its_now, ActionId, Altitude, AltitudeConfidence, AltitudeValue,
    CauseCodeChoice, CauseCodeV2, DeltaAltitude, DeltaLatitude, DeltaLongitude,
    DeltaReferencePosition, DeltaTimeMilliSecondPositive, DeltaTimeSecond, Denm, DenmCoder,
    DenmPayload, HeadingValue, InformationQuality, Latitude, LocationContainer, Longitude,
    ManagementContainer, Path, PathPoint, PosConfidenceEllipse, ReferencePosition, SemiAxisLength,
    SequenceNumber, SituationContainer, Speed, SpeedConfidence, SpeedValue, StationId, StationType,
    Traces, TrafficParticipantType, Wgs84Angle, Wgs84AngleConfidence,
    Wgs84AngleValue,
};
use crate::btp::router::BTPRouterHandle;
use crate::security::sn_sap::SecurityProfile;
use crate::btp::service_access_point::BTPDataRequest;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::service_access_point::{
    Area, CommonNH, CommunicationProfile, GeoBroadcastHST, HeaderSubType, HeaderType,
    PacketTransportType, TrafficClass,
};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::Duration;

// ─── VehicleData ─────────────────────────────────────────────────────────────

/// Static vehicle data used to populate every DENM.
///
/// Mirrors `VehicleData` from the CA Basic Service Python implementation
/// (re-used in the DEN Service as well).
#[derive(Debug, Clone)]
pub struct VehicleData {
    /// ITS station ID.
    pub station_id: u32,
    /// ITS station type (TrafficParticipantType).
    /// Common values: 0 = unknown, 5 = passengerCar, 6 = bus, 15 = rsu.
    pub station_type: u8,
}

impl Default for VehicleData {
    fn default() -> Self {
        VehicleData {
            station_id: 0,
            station_type: 5, // passengerCar
        }
    }
}

// ─── DENRequest ──────────────────────────────────────────────────────────────

/// Parameters passed by the application layer to request a DENM transmission.
///
/// Mirrors `DENRequest` from
/// `flexstack/applications/road_hazard_signalling_service/service_access_point.py`.
#[derive(Debug, Clone)]
pub struct DENRequest {
    // ── Event position ───────────────────────────────────────────────────────
    /// Event latitude in decimal degrees (WGS-84).
    pub event_latitude: f64,
    /// Event longitude in decimal degrees (WGS-84).
    pub event_longitude: f64,
    /// Event altitude in metres above WGS-84 ellipsoid.
    pub event_altitude_m: f64,

    // ── Cause code ───────────────────────────────────────────────────────────
    /// ITS cause code choice for the event type.
    pub cause_code: CauseCodeChoice,

    // ── Quality / kinematics at the event ────────────────────────────────────
    /// Information quality (0 = unavailable, 1–7 valid, 7 = highest).
    pub information_quality: u8,
    /// Event speed in 0.01 m/s (16 383 = unavailable).
    pub event_speed_raw: u16,
    /// Event heading in 0.1 ° (3 601 = unavailable).
    pub event_heading_raw: u16,

    // ── Transmission timing ──────────────────────────────────────────────────
    /// DENM re-transmission interval in milliseconds.
    pub denm_interval_ms: u64,
    /// Total period to keep sending DENMs in milliseconds.
    pub time_period_ms: u64,

    // ── Geo-broadcast radius ─────────────────────────────────────────────────
    /// Radius of the geo-broadcast circle in metres.
    pub relevance_radius_m: u32,
}

impl Default for DENRequest {
    fn default() -> Self {
        DENRequest {
            event_latitude: 0.0,
            event_longitude: 0.0,
            event_altitude_m: 0.0,
            cause_code: CauseCodeChoice::accident2(super::denm_coder::AccidentSubCauseCode(0)),
            information_quality: 0,
            event_speed_raw: 16383,  // unavailable
            event_heading_raw: 3601, // unavailable
            denm_interval_ms: 1000,
            time_period_ms: 5000,
            relevance_radius_m: 1000,
        }
    }
}

// ─── Sequence number counter ──────────────────────────────────────────────────

/// Global atomic sequence number, shared across all DENM transmissions.
static SEQUENCE_NUMBER: AtomicU16 = AtomicU16::new(0);

fn next_sequence_number() -> u16 {
    SEQUENCE_NUMBER.fetch_add(1, Ordering::Relaxed) % 65535
}

// ─── DENM builder ────────────────────────────────────────────────────────────

/// Build a single [`Denm`] PDU from a [`DENRequest`] and vehicle data.
pub fn build_denm(request: &DENRequest, vd: &VehicleData, seq_nr: u16) -> Denm {
    let now = timestamp_its_now();

    // ── ManagementContainer ───────────────────────────────────────────────────
    let event_pos = ReferencePosition::new(
        Latitude(((request.event_latitude * 1e7).round() as i32).clamp(-900_000_000, 900_000_000)),
        Longitude(
            ((request.event_longitude * 1e7).round() as i32).clamp(-1_800_000_000, 1_800_000_000),
        ),
        PosConfidenceEllipse::new(
            SemiAxisLength(4095), // unavailable
            SemiAxisLength(4095), // unavailable
            HeadingValue(3601),   // unavailable (uses HeadingValue in DENM)
        ),
        Altitude::new(
            AltitudeValue(
                ((request.event_altitude_m * 100.0).round() as i32).clamp(-100_000, 800_000),
            ),
            AltitudeConfidence::unavailable,
        ),
    );

    let action_id = ActionId::new(StationId(vd.station_id), SequenceNumber(seq_nr));

    let management = ManagementContainer::new(
        action_id,
        now.clone(), // detectionTime
        now.clone(), // referenceTime
        None,        // termination — active DENM
        event_pos,
        None,                 // awarenessDistance
        None,                 // trafficDirection
        DeltaTimeSecond(600), // validityDuration: 600 s default
        Some(DeltaTimeMilliSecondPositive(
            request.denm_interval_ms.min(10_000) as u16,
        )),
        StationType(TrafficParticipantType(vd.station_type)),
    );

    // ── SituationContainer ────────────────────────────────────────────────────
    let situation = SituationContainer::new(
        InformationQuality(request.information_quality.min(7)),
        CauseCodeV2::new(request.cause_code.clone()),
        None, // linkedCause
        None, // eventZone
        None, // ext_group_linked_denms
        None, // ext_group_event_end_factor
    );

    // ── LocationContainer ─────────────────────────────────────────────────────
    // A minimal detection zone: one path with one point at the event position
    // delta (zero offset — the event is at the reference position).
    let path_point = PathPoint::new(
        DeltaReferencePosition::new(
            DeltaLatitude(131072),  // 131072 = unavailable
            DeltaLongitude(131072), // 131072 = unavailable
            DeltaAltitude(12800),   // 12800  = unavailable
        ),
        None, // pathDeltaTime
    );
    let path = Path(rasn::types::SequenceOf::from(vec![path_point]));
    let traces = Traces(rasn::types::SequenceOf::from(vec![path]));

    let event_speed = Speed::new(
        SpeedValue(request.event_speed_raw.min(16_383)),
        SpeedConfidence(127), // unavailable
    );
    let event_heading = Wgs84Angle::new(
        Wgs84AngleValue(request.event_heading_raw.min(3601)),
        Wgs84AngleConfidence(127), // unavailable
    );

    let location = LocationContainer::new(
        Some(event_speed),
        Some(event_heading),
        traces,
        None, // roadType
        None, // ext_group_lane_positions
    );

    // ── Assemble DENM ─────────────────────────────────────────────────────────
    Denm::new(
        denm_header(vd.station_id),
        DenmPayload::new(
            management,
            Some(situation),
            Some(location),
            None, // alacarte
        ),
    )
}

// ─── DENMTransmissionManagement ──────────────────────────────────────────────

/// DENM Transmission Management.
///
/// Mirrors `DENMTransmissionManagement` in
/// `flexstack/facilities/decentralized_environmental_notification_service/denm_transmission_management.py`.
pub struct DENMTransmissionManagement {
    btp_handle: BTPRouterHandle,
    coder: DenmCoder,
    vehicle_data: VehicleData,
}

impl DENMTransmissionManagement {
    pub fn new(btp_handle: BTPRouterHandle, coder: DenmCoder, vehicle_data: VehicleData) -> Self {
        DENMTransmissionManagement {
            btp_handle,
            coder,
            vehicle_data,
        }
    }

    /// Trigger repeated DENM transmission in a new background thread.
    ///
    /// DENMs are sent every `request.denm_interval_ms` milliseconds for
    /// `request.time_period_ms` total milliseconds.
    pub fn trigger_denm_sending(&self, request: DENRequest) {
        let btp_handle = self.btp_handle.clone();
        let coder = self.coder.clone();
        let vehicle_data = self.vehicle_data.clone();

        thread::spawn(move || {
            let interval = Duration::from_millis(request.denm_interval_ms);
            let end_time =
                std::time::Instant::now() + Duration::from_millis(request.time_period_ms);

            while std::time::Instant::now() < end_time {
                let seq_nr = next_sequence_number();
                let denm = build_denm(&request, &vehicle_data, seq_nr);
                transmit_denm(&btp_handle, &coder, &denm, &request);
                thread::sleep(interval);
            }
            eprintln!("[DENM TX] Finished transmission period");
        });
    }

    /// Transmit a single pre-built DENM immediately (fire-and-forget).
    pub fn send_single_denm(&self, request: &DENRequest) {
        let seq_nr = next_sequence_number();
        let denm = build_denm(request, &self.vehicle_data, seq_nr);
        transmit_denm(&self.btp_handle, &self.coder, &denm, request);
    }
}

// ─── Internal transmit helper ─────────────────────────────────────────────────

fn transmit_denm(
    btp_handle: &BTPRouterHandle,
    coder: &DenmCoder,
    denm: &Denm,
    request: &DENRequest,
) {
    match coder.encode(denm) {
        Ok(data) => {
            // Event position in 1/10 µdeg for the GN area centre (Area uses u32).
            let area_lat = ((request.event_latitude * 1e7).round() as i32)
                .clamp(-900_000_000, 900_000_000) as u32;
            let area_lon = ((request.event_longitude * 1e7).round() as i32)
                .clamp(-1_800_000_000, 1_800_000_000) as u32;

            let req = BTPDataRequest {
                btp_type: CommonNH::BtpB,
                source_port: 0,
                destination_port: 2002, // BTP port for DENM
                destination_port_info: 0,
                gn_packet_transport_type: PacketTransportType {
                    header_type: HeaderType::GeoBroadcast,
                    header_sub_type: HeaderSubType::GeoBroadcast(
                        GeoBroadcastHST::GeoBroadcastCircle,
                    ),
                },
                gn_destination_address: GNAddress {
                    m: M::GnMulticast,
                    st: ST::Unknown,
                    mid: MID::new([0xFF; 6]),
                },
                communication_profile: CommunicationProfile::Unspecified,
                gn_area: Area {
                    latitude: area_lat,
                    longitude: area_lon,
                    a: request.relevance_radius_m as u16, // semi-major axis (m)
                    b: 0,
                    angle: 0,
                },
                traffic_class: TrafficClass {
                    scf: false,
                    channel_offload: false,
                    tc_id: 0,
                },
                security_profile: SecurityProfile::DecentralizedEnvironmentalNotificationMessage,
                its_aid: 37,
                security_permissions: vec![],
                gn_max_hop_limit: 10,
                gn_max_packet_lifetime: None,
                gn_repetition_interval: None,
                gn_max_repetition_time: None,
                destination: None,
                length: data.len() as u16,
                data,
            };

            btp_handle.send_btp_data_request(req);
            eprintln!(
                "[DENM TX] Sent DENM station_id={}",
                denm.header.station_id.0
            );
        }
        Err(e) => eprintln!("[DENM TX] Encode error: {}", e),
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DENM transmission: originating ITS-S operation of the DEN service
//! (ETSI TS 103 831 V2.3.1 (2025-11), clauses 5.3.1 and 8.2).
//!
//! The protocol rules live in [`super::den_protocol`]; this module turns
//! application requests into protocol operations and hands the resulting DENMs
//! to BTP (port 2002, GeoBroadcast, clause 6.1.3.4).
//!
//! Two request styles are supported:
//! * the standard requests [`DENMTransmissionManagement::trigger`],
//!   [`update`](DENMTransmissionManagement::update) and
//!   [`terminate`](DENMTransmissionManagement::terminate) (AppDENM_trigger,
//!   AppDENM_update, AppDENM_termination) taking a [`DenmRequest`];
//! * the road-hazard [`DENRequest`], converted to an AppDENM_trigger with
//!   repetition ([`DENMTransmissionManagement::trigger_denm_sending`]).
//!
//! Mirrors `flexstack/facilities/decentralized_environmental_notification_service/denm_transmission_management.py`.

use super::den_protocol::{DenActionId, DenProtocol, DenResult, DenmRequest, OutgoingDenm};
use super::denm_coder::{
    denm_header, timestamp_its_now, ActionId, Altitude, AltitudeConfidence, AltitudeValue,
    CauseCodeChoice, CauseCodeV2, DeltaAltitude, DeltaLatitude, DeltaLongitude,
    DeltaReferencePosition, DeltaTimeMilliSecondPositive, DeltaTimeSecond, Denm, DenmCoder,
    DenmPayload, HeadingValue, InformationQuality, Latitude, LocationContainer, Longitude,
    ManagementContainer, Path, PathPoint, PosConfidenceEllipse, ReferencePosition, SemiAxisLength,
    SequenceNumber, SituationContainer, Speed, SpeedConfidence, SpeedValue, StationId, StationType,
    Traces, TrafficParticipantType, Wgs84Angle, Wgs84AngleConfidence, Wgs84AngleValue,
};
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataRequest;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::service_access_point::{
    Area, CommonNH, CommunicationProfile, HeaderSubType, HeaderType, PacketTransportType,
};
use crate::security::sn_sap::SecurityProfile;
use std::sync::{Arc, Condvar, Mutex};

/// BTP port of the DEN service (ETSI TS 103 248).
pub const DENM_BTP_PORT: u16 = 2002;
/// ITS-AID of the DEN service (ETSI TS 102 965).
pub const DENM_ITS_AID: u64 = 37;

/// Source of the current time of the DEN service (TimestampIts, ms).
pub type DenClock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Protocol engine shared by transmission, reception and the timer thread.
pub struct DenShared {
    pub protocol: Mutex<DenProtocol>,
    /// Signalled whenever the protocol timers may have changed.
    pub wakeup: Condvar,
    clock: Option<DenClock>,
}

impl DenShared {
    pub fn new(protocol: DenProtocol) -> Arc<Self> {
        Self::with_clock(protocol, None)
    }

    /// Shared engine whose time is read from `clock` (the system time when `None`).
    pub fn with_clock(protocol: DenProtocol, clock: Option<DenClock>) -> Arc<Self> {
        Arc::new(DenShared {
            protocol: Mutex::new(protocol),
            wakeup: Condvar::new(),
            clock,
        })
    }

    /// Current TimestampIts (ms) of the DEN service.
    pub fn now(&self) -> u64 {
        self.clock
            .as_ref()
            .map_or_else(|| timestamp_its_now().0, |clock| clock())
    }
}

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

/// Originating ITS-S operation of the DEN service (clause 8.2).
///
/// Mirrors `DENMTransmissionManagement` in the Python stack.
pub struct DENMTransmissionManagement {
    btp_handle: BTPRouterHandle,
    coder: DenmCoder,
    vehicle_data: VehicleData,
    shared: Arc<DenShared>,
}

/// Engine for a DEN service of this station; DENMs are validated by encoding.
pub fn new_protocol(
    vehicle_data: &VehicleData,
    kaf_enabled: bool,
    coder: &DenmCoder,
) -> DenProtocol {
    let coder = coder.clone();
    DenProtocol::new(
        vehicle_data.station_id,
        vehicle_data.station_type,
        kaf_enabled,
        Some(Box::new(move |denm: &Denm| coder.encode(denm).map(|_| ()))),
    )
}

impl DENMTransmissionManagement {
    /// Standalone transmission management with its own protocol engine (no
    /// timer thread: DENM repetition needs the DEN service).
    pub fn new(btp_handle: BTPRouterHandle, coder: DenmCoder, vehicle_data: VehicleData) -> Self {
        let shared = DenShared::new(new_protocol(&vehicle_data, false, &coder));
        Self::with_shared(btp_handle, coder, vehicle_data, shared)
    }

    /// Transmission management on a protocol engine shared with reception.
    pub fn with_shared(
        btp_handle: BTPRouterHandle,
        coder: DenmCoder,
        vehicle_data: VehicleData,
        shared: Arc<DenShared>,
    ) -> Self {
        DENMTransmissionManagement {
            btp_handle,
            coder,
            vehicle_data,
            shared,
        }
    }

    // ── Standard application requests (clause 5.3.1) ──────────────────────

    /// AppDENM_trigger: returns the new actionId or a failure notification.
    pub fn trigger(&self, request: &DenmRequest) -> DenResult {
        let now = self.shared.now();
        let (result, outgoing) = self.shared.protocol.lock().unwrap().trigger(request, now);
        self.dispatch(result, outgoing)
    }

    /// AppDENM_update for an event triggered by this ITS-S.
    pub fn update(&self, action_id: DenActionId, request: &DenmRequest) -> DenResult {
        let now = self.shared.now();
        let (result, outgoing) = self
            .shared
            .protocol
            .lock()
            .unwrap()
            .update(action_id, request, now);
        self.dispatch(result, outgoing)
    }

    /// AppDENM_termination: cancellation (own event) or negation (received event).
    pub fn terminate(&self, action_id: DenActionId, request: &DenmRequest) -> DenResult {
        let now = self.shared.now();
        let (result, outgoing) = self
            .shared
            .protocol
            .lock()
            .unwrap()
            .terminate(action_id, request, now);
        self.dispatch(result, outgoing)
    }

    // ── Road hazard signalling requests (DENRequest) ───────────────────────

    /// AppDENM_trigger repeated every `denm_interval_ms` for `time_period_ms`
    /// (DENM repetition, clause 6.1.2.3), with transmissionInterval set so
    /// receivers may keep it alive. Repetition needs the DEN service timer.
    pub fn trigger_denm_sending(&self, request: DENRequest) {
        let _ = self.trigger(&self.to_denm_request(&request, true));
    }

    /// A single new DENM, no repetition.
    pub fn send_single_denm(&self, request: &DENRequest) {
        let _ = self.trigger(&self.to_denm_request(request, false));
    }

    /// AppDENM_trigger request carrying the content of a road-hazard request.
    pub fn to_denm_request(&self, request: &DENRequest, repeat: bool) -> DenmRequest {
        let denm = build_denm(request, &self.vehicle_data, 0);
        let mut out = DenmRequest::new(denm.denm.management.event_position.clone());
        out.situation = denm.denm.situation;
        out.location = denm.denm.location;
        out.validity_duration = Some(if request.time_period_ms == 0 {
            super::den_protocol::DEFAULT_VALIDITY_DURATION_S
        } else {
            request.time_period_ms.div_ceil(1000).max(1) as u32
        });
        out.transmission_interval = Some(request.denm_interval_ms.clamp(1, 10_000) as u16);
        out.station_type = Some(self.vehicle_data.station_type);
        if repeat {
            out.repetition_interval = Some(request.denm_interval_ms);
            out.repetition_duration = Some(request.time_period_ms);
        }
        out.destination_area = Some(Area {
            latitude: denm.denm.management.event_position.latitude.0 as u32,
            longitude: denm.denm.management.event_position.longitude.0 as u32,
            a: request.relevance_radius_m.min(u32::from(u16::MAX)) as u16,
            b: 0,
            angle: 0,
        });
        out
    }

    // ── Transmission ───────────────────────────────────────────────────────

    fn dispatch(&self, result: DenResult, outgoing: Vec<OutgoingDenm>) -> DenResult {
        for item in &outgoing {
            transmit(&self.btp_handle, &self.coder, item);
        }
        if let Err(failure) = result {
            eprintln!("[DEN] request failed: {failure:?}");
        }
        self.shared.wakeup.notify_all();
        result
    }

    /// Encode a DENM and pass it to BTP-B port 2002 over GeoBroadcast.
    pub fn transmit(&self, outgoing: &OutgoingDenm) {
        transmit(&self.btp_handle, &self.coder, outgoing);
    }
}

/// Encode a DENM and pass it to BTP-B port 2002 over GeoBroadcast.
pub fn transmit(btp_handle: &BTPRouterHandle, coder: &DenmCoder, outgoing: &OutgoingDenm) {
    let Ok(data) = coder.encode(&outgoing.denm) else {
        return;
    };
    btp_handle.send_btp_data_request(BTPDataRequest {
        btp_type: CommonNH::BtpB,
        source_port: 0,
        destination_port: DENM_BTP_PORT,
        destination_port_info: 0,
        gn_packet_transport_type: PacketTransportType {
            header_type: HeaderType::GeoBroadcast,
            header_sub_type: HeaderSubType::GeoBroadcast(outgoing.area_type),
        },
        gn_destination_address: GNAddress {
            m: M::GnMulticast,
            st: ST::Unknown,
            mid: MID::new([0xFF; 6]),
        },
        communication_profile: CommunicationProfile::Unspecified,
        gn_area: outgoing.area,
        traffic_class: outgoing.traffic_class,
        security_profile: SecurityProfile::DecentralizedEnvironmentalNotificationMessage,
        its_aid: DENM_ITS_AID,
        // Sender-side SSP check (clause 6.2.2.2): sign only with an AT
        // granting the cause code of this DENM.
        security_permissions: super::denm_ssp::permissions_bitmap(&outgoing.denm),
        gn_max_hop_limit: 10,
        gn_max_packet_lifetime: None,
        gn_repetition_interval: None,
        gn_max_repetition_time: None,
        destination: None,
        length: data.len() as u16,
        data,
    });
}

#[cfg(test)]
mod tests {
    use super::super::denm_coder::AccidentSubCauseCode;
    use super::*;
    use crate::geonet::mib::Mib;
    use crate::geonet::service_access_point::GeoBroadcastHST;
    use std::time::Duration;

    fn vehicle(station_id: u32) -> VehicleData {
        VehicleData {
            station_id,
            station_type: 5,
        }
    }

    /// New event (TS 103 831 clauses 6.1.1, 8.2.2): the actionID of a new DENM contains the StationID of
    /// the originating ITS-S.
    #[test]
    fn build_denm_action_id_contains_station_id() {
        let denm = build_denm(&DENRequest::default(), &vehicle(4242), 7);
        let action_id = &denm.denm.management.action_id;
        assert_eq!(action_id.originating_station_id.0, 4242);
        assert_eq!(action_id.sequence_number.0, 7);
        assert_eq!(denm.header.station_id.0, 4242);
    }

    /// New event (TS 103 831 clauses 6.1.1, 8.2.2): cause and sub-cause are those provided by the
    /// application.
    #[test]
    fn build_denm_carries_application_cause_code() {
        let request = DENRequest {
            cause_code: CauseCodeChoice::accident2(AccidentSubCauseCode(3)),
            ..DENRequest::default()
        };
        let denm = build_denm(&request, &vehicle(1), 0);
        let situation = denm.denm.situation.expect("situation container");
        assert_eq!(situation.event_type.cc_and_scc, request.cause_code);
    }

    /// New event (TS 103 831 clauses 6.1.1, 8.2.2): referenceTime of a new DENM is the current time.
    #[test]
    fn build_denm_reference_time_is_now() {
        let before = timestamp_its_now().0;
        let denm = build_denm(&DENRequest::default(), &vehicle(1), 0);
        let after = timestamp_its_now().0;
        let reference = denm.denm.management.reference_time.0;
        assert!(reference >= before && reference <= after);
    }

    /// DENM encapsulation (TS 103 831 clause 5.4.2.2): a DENM is sent as BTP-B to port 2002 in a
    /// GeoNetworking GBC (circle) packet.
    #[test]
    fn send_single_denm_uses_btp_b_port_2002_over_gbc() {
        let (btp_handle, gn_rx) = crate::btp::router::Router::spawn(Mib::new());
        let dtm = DENMTransmissionManagement::new(btp_handle, DenmCoder::new(), vehicle(1));
        dtm.send_single_denm(&DENRequest::default());

        let gn_req = gn_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("DENM did not reach GeoNetworking");
        assert_eq!(gn_req.upper_protocol_entity, CommonNH::BtpB);
        assert_eq!(
            gn_req.packet_transport_type.header_type,
            HeaderType::GeoBroadcast
        );
        assert_eq!(
            gn_req.packet_transport_type.header_sub_type,
            HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle)
        );
        // BTP-B header: destination port 2002 (0x07D2).
        assert_eq!(&gn_req.data[0..2], &[0x07, 0xD2]);
        assert_eq!(gn_req.its_aid, 37);
    }
}

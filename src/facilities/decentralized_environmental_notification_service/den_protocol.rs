// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DEN service protocol engine (ETSI TS 103 831 V2.3.1 (2025-11), clause 8).
//!
//! Pure protocol logic, independent of threads, sockets and codecs:
//!
//! * originating ITS-S operation (clause 8.2): AppDENM_trigger, AppDENM_update,
//!   AppDENM_termination, the originating ITS-S message table, timers
//!   T_O_Validity, T_RepetitionDuration and T_Repetition;
//! * forwarding ITS-S operation (clause 8.3): the optional Keep-Alive
//!   Forwarding (KAF), the forwarding ITS-S message table, timers T_F_Validity
//!   and T_Forwarding, DENM regeneration;
//! * receiving ITS-S operation (clause 8.4): the receiving ITS-S message table
//!   and timer T_R_Validity.
//!
//! Time is always passed in as `now` (TimestampIts, ms since
//! 2004-01-01T00:00:00Z, TAI). The engine never transmits: operations return
//! the DENMs to hand to the networking & transport layer as [`OutgoingDenm`].
//! [`DenProtocol::tick`] fires expired timers and
//! [`DenProtocol::next_deadline`] tells a scheduler when to call it next.
//!
//! Mirrors `flexstack/facilities/decentralized_environmental_notification_service/den_protocol.py`.

use std::collections::HashMap;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::denm_bindings::etsi_its_cdd::{StandardLength3b, TrafficDirection};
use super::denm_coder::{
    denm_header, ActionId, AlacarteContainer, DeltaTimeMilliSecondPositive, DeltaTimeSecond, Denm,
    DenmPayload, LocationContainer, ManagementContainer, ReferencePosition, SequenceNumber,
    SituationContainer, StationId, StationType, Termination, TimestampIts, TrafficParticipantType,
};
use crate::geonet::service_access_point::{Area, GeoBroadcastHST, TrafficClass};

/// Default validityDuration (`defaultValidity`, Annex A) in seconds.
pub const DEFAULT_VALIDITY_DURATION_S: u32 = 600;
/// Upper bound of the random part of the T_Forwarding timeout (clause 8.3.2.5).
pub const KAF_MAX_RANDOM_DELAY_MS: u64 = 150;
/// Radius of the default circular destination area around the event position.
pub const DEFAULT_DESTINATION_RADIUS_M: u16 = 1000;
const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// State of a DENM entry in an ITS-S message table (clauses 8.2.1.6, 8.4.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenmState {
    Active,
    Cancelled,
    Negated,
}

/// Reason of a failure notification to the ITS-S application (clause 8.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenFailure {
    /// T_O_Validity expiration time lies in the past (clause 8.2.3.4).
    ValidityExpired,
    /// actionId not found in the ITS-S message tables (clause 8.2.3.3).
    UnknownActionId,
    /// The DENM could not be generated (clause 8.2.3.2).
    GenerationFailed,
}

/// Why the receiving ITS-S discarded a DENM (clause 8.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardReason {
    Expired,
    UnknownTermination,
    Outdated,
    Repeated,
    SspInconsistent,
}

/// actionId: originating stationId and sequenceNumber (clause 6.1.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DenActionId {
    pub station_id: u32,
    pub sequence_number: u16,
}

impl DenActionId {
    pub fn to_asn(self) -> ActionId {
        ActionId::new(
            StationId(self.station_id),
            SequenceNumber(self.sequence_number),
        )
    }

    pub fn from_asn(action_id: &ActionId) -> Self {
        DenActionId {
            station_id: action_id.originating_station_id.0,
            sequence_number: action_id.sequence_number.0,
        }
    }
}

/// Data passed with AppDENM_trigger / AppDENM_update / AppDENM_termination
/// (clause 5.3.1, Tables 2 to 4). See the Python `DENMRequest` for the
/// meaning of each field.
#[derive(Debug, Clone)]
pub struct DenmRequest {
    pub event_position: ReferencePosition,
    /// TimestampIts (ms) of the detection; the current time when `None`.
    pub detection_time: Option<u64>,
    pub situation: Option<SituationContainer>,
    pub location: Option<LocationContainer>,
    pub alacarte: Option<AlacarteContainer>,
    pub awareness_distance: Option<StandardLength3b>,
    pub traffic_direction: Option<TrafficDirection>,
    /// validityDuration in seconds; 600 s when not provided.
    pub validity_duration: Option<u32>,
    /// DENM repetition interval and duration in ms (clause 6.1.2.3).
    pub repetition_interval: Option<u64>,
    pub repetition_duration: Option<u64>,
    /// transmissionInterval in ms, enables KAF at forwarding ITS-Ss.
    pub transmission_interval: Option<u16>,
    pub station_type: Option<u8>,
    /// actionId assigned by a central entity (Table 2, note 10).
    pub action_id: Option<DenActionId>,
    pub destination_area: Option<Area>,
    pub destination_area_type: GeoBroadcastHST,
    pub traffic_class: Option<TrafficClass>,
}

impl DenmRequest {
    /// A request with only the event position set.
    pub fn new(event_position: ReferencePosition) -> Self {
        DenmRequest {
            event_position,
            detection_time: None,
            situation: None,
            location: None,
            alacarte: None,
            awareness_distance: None,
            traffic_direction: None,
            validity_duration: None,
            repetition_interval: None,
            repetition_duration: None,
            transmission_interval: None,
            station_type: None,
            action_id: None,
            destination_area: None,
            destination_area_type: GeoBroadcastHST::GeoBroadcastCircle,
            traffic_class: None,
        }
    }
}

/// A DENM to pass to the networking & transport layer (GeoBroadcast).
#[derive(Debug, Clone)]
pub struct OutgoingDenm {
    pub denm: Denm,
    pub area: Area,
    pub area_type: GeoBroadcastHST,
    pub traffic_class: TrafficClass,
}

/// Result of the receiving ITS-S operation for one received DENM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceptionOutcome {
    pub accepted: bool,
    pub action_id: DenActionId,
    pub state: Option<DenmState>,
    pub reason: Option<DiscardReason>,
}

/// Answer to an application request: the actionId or a failure notification.
pub type DenResult = Result<DenActionId, DenFailure>;

/// Validation hook: a DENM generation exception when it returns `Err`.
pub type DenmValidator = Box<dyn Fn(&Denm) -> Result<(), String> + Send>;

#[derive(Debug, Clone)]
pub struct OriginatingEntry {
    pub denm: Denm,
    pub state: DenmState,
    pub validity_expiry: u64,
    pub area: Area,
    pub area_type: GeoBroadcastHST,
    pub traffic_class: TrafficClass,
    pub repetition_interval: Option<u64>,
    pub repetition_duration: Option<u64>,
    pub repetition_end: Option<u64>,
    pub next_repetition: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ReceivingEntry {
    pub reference_time: u64,
    pub detection_time: u64,
    pub state: DenmState,
    pub validity_expiry: u64,
    pub denm: Denm,
}

#[derive(Debug, Clone)]
pub struct ForwardingEntry {
    pub denm: Denm,
    pub reference_time: u64,
    pub validity_expiry: u64,
    pub forwarding_timeout: u64,
    pub next_forwarding: Option<u64>,
    pub area: Area,
    pub area_type: GeoBroadcastHST,
    pub traffic_class: TrafficClass,
}

/// State conveyed by a DENM: termination absent, isCancellation or isNegation.
pub fn state_of(management: &ManagementContainer) -> DenmState {
    match management.termination {
        None => DenmState::Active,
        Some(Termination::isCancellation) => DenmState::Cancelled,
        Some(Termination::isNegation) => DenmState::Negated,
    }
}

/// True when the point (1/10 micro-degree) lies inside or on the border of the
/// GeoBroadcast area: geometric function F >= 0 of ETSI EN 302 931, with the
/// area rotated by its azimuth angle (degrees from north).
pub fn inside_area(area: &Area, area_type: GeoBroadcastHST, latitude: i32, longitude: i32) -> bool {
    let (centre_lat, centre_lon) = (area.latitude as i32, area.longitude as i32);
    let lat0 = (centre_lat as f64 / 1e7).to_radians();
    let d_north = ((latitude - centre_lat) as f64 / 1e7).to_radians() * EARTH_RADIUS_M;
    let d_east = ((longitude - centre_lon) as f64 / 1e7).to_radians() * EARTH_RADIUS_M * lat0.cos();
    let theta = (area.angle as f64).to_radians();
    let x = d_north * theta.cos() + d_east * theta.sin();
    let y = -d_north * theta.sin() + d_east * theta.cos();
    let a = (area.a as f64).max(1e-9);
    let b = (area.b as f64).max(1e-9);
    let f = match area_type {
        GeoBroadcastHST::GeoBroadcastCircle => 1.0 - (x / a).powi(2) - (y / a).powi(2),
        GeoBroadcastHST::GeoBroadcastEllipse => 1.0 - (x / a).powi(2) - (y / b).powi(2),
        GeoBroadcastHST::GeoBroadcastRectangle => {
            (1.0 - (x / a).powi(2)).min(1.0 - (y / b).powi(2))
        }
    };
    f >= 0.0
}

/// Circle of [`DEFAULT_DESTINATION_RADIUS_M`] centred on the event position.
pub fn default_area(position: &ReferencePosition) -> Area {
    Area {
        latitude: position.latitude.0 as u32,
        longitude: position.longitude.0 as u32,
        a: DEFAULT_DESTINATION_RADIUS_M,
        b: 0,
        angle: 0,
    }
}

/// DEN service protocol engine for one ITS-S.
pub struct DenProtocol {
    pub station_id: u32,
    pub station_type: u8,
    pub kaf_enabled: bool,
    pub originating: HashMap<DenActionId, OriginatingEntry>,
    pub receiving: HashMap<DenActionId, ReceivingEntry>,
    pub forwarding: HashMap<DenActionId, ForwardingEntry>,
    pub ego_position: Option<(i32, i32)>,
    next_sequence_number: u16,
    validate: Option<DenmValidator>,
    rng: StdRng,
}

impl DenProtocol {
    /// Create the engine. `validate` receives every DENM generated for an
    /// application request; an `Err` turns it into a DENM generation
    /// exception (clause 8.2.3.2). The DEN service passes the UPER encoder.
    pub fn new(
        station_id: u32,
        station_type: u8,
        kaf_enabled: bool,
        validate: Option<DenmValidator>,
    ) -> Self {
        DenProtocol {
            station_id,
            station_type,
            kaf_enabled,
            originating: HashMap::new(),
            receiving: HashMap::new(),
            forwarding: HashMap::new(),
            ego_position: None,
            next_sequence_number: 0,
            validate,
            rng: StdRng::from_entropy(),
        }
    }

    /// Seed the KAF random delay generator (tests).
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng = StdRng::seed_from_u64(seed);
        self
    }

    /// Re-seed the KAF random delay generator (tests).
    pub fn set_seed(&mut self, seed: u64) {
        self.rng = StdRng::seed_from_u64(seed);
    }

    /// Next sequence number to try (tests and diagnostics).
    pub fn set_next_sequence_number(&mut self, value: u16) {
        self.next_sequence_number = value;
    }

    // ── Originating ITS-S (clause 8.2) ─────────────────────────────────────

    /// AppDENM_trigger: generate a new DENM (clause 8.2.2).
    pub fn trigger(&mut self, request: &DenmRequest, now: u64) -> (DenResult, Vec<OutgoingDenm>) {
        let detection_time = request.detection_time.unwrap_or(now);
        let validity = request
            .validity_duration
            .unwrap_or(DEFAULT_VALIDITY_DURATION_S);
        let expiry = detection_time + u64::from(validity) * 1000;
        if expiry < now {
            return (Err(DenFailure::ValidityExpired), vec![]);
        }
        let (Some(situation), Some(location)) = (&request.situation, &request.location) else {
            return (Err(DenFailure::GenerationFailed), vec![]);
        };
        let action_id = match request.action_id {
            Some(id) => id,
            None => match self.new_action_id() {
                Some(id) => id,
                None => return (Err(DenFailure::GenerationFailed), vec![]),
            },
        };
        let management = self.management(action_id, detection_time, now, None, request, validity);
        let denm = self.denm(
            management,
            Some(situation.clone()),
            Some(location.clone()),
            request.alacarte.clone(),
        );
        self.store_and_send(
            action_id,
            denm,
            DenmState::Active,
            expiry,
            request,
            request.repetition_interval,
            request.repetition_duration,
            now,
        )
    }

    /// AppDENM_update: generate an update DENM for an own event (clause 8.2.2).
    pub fn update(
        &mut self,
        action_id: DenActionId,
        request: &DenmRequest,
        now: u64,
    ) -> (DenResult, Vec<OutgoingDenm>) {
        let Some(entry) = self.originating.get(&action_id).cloned() else {
            return (Err(DenFailure::UnknownActionId), vec![]);
        };
        let previous = &entry.denm.denm.management;
        let detection_time = request.detection_time.unwrap_or(now);
        let validity = request
            .validity_duration
            .unwrap_or(previous.validity_duration.0);
        let expiry = detection_time + u64::from(validity) * 1000;
        if expiry < now {
            return (Err(DenFailure::ValidityExpired), vec![]);
        }
        let reference_time = now.max(previous.reference_time.0 + 1);
        let mut merged = request.clone();
        if merged.awareness_distance.is_none() {
            merged.awareness_distance = previous.awareness_distance;
        }
        if merged.traffic_direction.is_none() {
            merged.traffic_direction = previous.traffic_direction;
        }
        if merged.transmission_interval.is_none() {
            merged.transmission_interval = previous.transmission_interval.as_ref().map(|t| t.0);
        }
        if merged.station_type.is_none() {
            merged.station_type = Some(previous.station_type.0 .0);
        }
        if merged.destination_area.is_none() {
            merged.destination_area = Some(entry.area);
            merged.destination_area_type = entry.area_type;
        }
        if merged.traffic_class.is_none() {
            merged.traffic_class = Some(entry.traffic_class);
        }
        let body = &entry.denm.denm;
        let situation = request.situation.clone().or_else(|| body.situation.clone());
        let location = request.location.clone().or_else(|| body.location.clone());
        let alacarte = request.alacarte.clone().or_else(|| body.alacarte.clone());
        if situation.is_none() || location.is_none() {
            return (Err(DenFailure::GenerationFailed), vec![]);
        }
        let management = self.management(
            action_id,
            detection_time,
            reference_time,
            None,
            &merged,
            validity,
        );
        let denm = self.denm(management, situation, location, alacarte);
        let interval = request.repetition_interval.or(entry.repetition_interval);
        let duration = request.repetition_duration.or(entry.repetition_duration);
        self.store_and_send(
            action_id,
            denm,
            DenmState::Active,
            expiry,
            &merged,
            interval,
            duration,
            reference_time,
        )
    }

    /// AppDENM_termination: cancellation DENM for an own active event, negation
    /// DENM for an active event received from another ITS-S (clause 8.2.2).
    pub fn terminate(
        &mut self,
        action_id: DenActionId,
        request: &DenmRequest,
        now: u64,
    ) -> (DenResult, Vec<OutgoingDenm>) {
        let detection_time = request.detection_time.unwrap_or(now);
        let validity = request
            .validity_duration
            .unwrap_or(DEFAULT_VALIDITY_DURATION_S);
        let expiry = detection_time + u64::from(validity) * 1000;
        if expiry < now {
            return (Err(DenFailure::ValidityExpired), vec![]);
        }
        let own = self
            .originating
            .get(&action_id)
            .filter(|e| e.state == DenmState::Active);
        let received = self
            .receiving
            .get(&action_id)
            .filter(|e| e.state == DenmState::Active);
        let (termination, state, reference_time) = if let Some(own) = own {
            let previous = own.denm.denm.management.reference_time.0;
            (
                Termination::isCancellation,
                DenmState::Cancelled,
                now.max(previous + 1),
            )
        } else if let Some(received) = received {
            (
                Termination::isNegation,
                DenmState::Negated,
                received.reference_time,
            )
        } else {
            return (Err(DenFailure::UnknownActionId), vec![]);
        };
        let management = self.management(
            action_id,
            detection_time,
            reference_time,
            Some(termination),
            request,
            validity,
        );
        let denm = self.denm(management, None, None, None);
        self.store_and_send(
            action_id,
            denm,
            state,
            expiry,
            request,
            request.repetition_interval,
            request.repetition_duration,
            reference_time,
        )
    }

    /// Pseudonym change (clause 6.1.1.2): update the actionIds and ITS PDU
    /// headers of all DENMs generated and stored by this ITS-S.
    pub fn update_station_id(&mut self, station_id: u32) {
        let old = self.station_id;
        self.station_id = station_id;
        let entries: Vec<_> = self.originating.drain().collect();
        for (mut action_id, mut entry) in entries {
            entry.denm.header.station_id = StationId(station_id);
            if action_id.station_id == old {
                action_id.station_id = station_id;
                entry.denm.denm.management.action_id = action_id.to_asn();
            }
            self.originating.insert(action_id, entry);
        }
        for entry in self.forwarding.values_mut() {
            entry.denm.header.station_id = StationId(station_id);
        }
    }

    // ── Receiving ITS-S (clause 8.4) and KAF (clause 8.3) ──────────────────

    /// Receiving ITS-S operation for one decoded DENM (clause 8.4.2), followed
    /// by the KAF operation (clause 8.3.3) when KAF is enabled. `area` is the
    /// GeoBroadcast destination area of the packet; `ssp_consistent` is the
    /// result of the SSP check of the signer (true without security).
    pub fn receive(
        &mut self,
        denm: &Denm,
        now: u64,
        area: Option<(Area, GeoBroadcastHST)>,
        ssp_consistent: bool,
    ) -> ReceptionOutcome {
        let management = &denm.denm.management;
        let action_id = DenActionId::from_asn(&management.action_id);
        let reference_time = management.reference_time.0;
        let detection_time = management.detection_time.0;
        let state = state_of(management);
        let expiry = detection_time + u64::from(management.validity_duration.0) * 1000;
        let discard = |reason| ReceptionOutcome {
            accepted: false,
            action_id,
            state: None,
            reason: Some(reason),
        };
        if expiry < now {
            return discard(DiscardReason::Expired);
        }
        let accepted = ReceptionOutcome {
            accepted: true,
            action_id,
            state: Some(state),
            reason: None,
        };
        let outcome = match self.receiving.get_mut(&action_id) {
            None => {
                if state != DenmState::Active {
                    return discard(DiscardReason::UnknownTermination);
                }
                if !ssp_consistent {
                    return discard(DiscardReason::SspInconsistent);
                }
                self.receiving.insert(
                    action_id,
                    ReceivingEntry {
                        reference_time,
                        detection_time,
                        state,
                        validity_expiry: expiry,
                        denm: denm.clone(),
                    },
                );
                accepted
            }
            Some(entry) => {
                if reference_time < entry.reference_time || detection_time < entry.detection_time {
                    return discard(DiscardReason::Outdated);
                }
                if reference_time == entry.reference_time
                    && detection_time == entry.detection_time
                    && state == entry.state
                {
                    discard(DiscardReason::Repeated)
                } else if !ssp_consistent {
                    return discard(DiscardReason::SspInconsistent);
                } else {
                    entry.reference_time = reference_time;
                    entry.detection_time = detection_time;
                    entry.state = state;
                    entry.validity_expiry = expiry;
                    entry.denm = denm.clone();
                    accepted
                }
            }
        };
        if self.kaf_enabled {
            self.kaf_receive(action_id, denm, now, area);
        }
        outcome
    }

    /// KAF operation upon reception (clause 8.3.3).
    ///
    /// Step 1 of clause 8.3.3 reads "check if the termination exists in the
    /// received DENM; if yes, continue, otherwise omit further steps". Taken
    /// literally only terminated DENMs would be forwarded, which contradicts
    /// clause 6.1.4.2 and the test purposes TP/DEN/KAFW/BV-01 and BV-07 of
    /// ETSI TS 102 869-2 V1.6.1 (the same wording is in ETSI EN 302 637-3
    /// V1.3.1). Both kinds are therefore forwarded here.
    fn kaf_receive(
        &mut self,
        action_id: DenActionId,
        denm: &Denm,
        now: u64,
        area: Option<(Area, GeoBroadcastHST)>,
    ) {
        let management = &denm.denm.management;
        let reference_time = management.reference_time.0;
        if let Some(entry) = self.forwarding.get_mut(&action_id) {
            let same_state = state_of(&entry.denm.denm.management) == state_of(management);
            if reference_time == entry.reference_time && same_state {
                // Same DENM seen again (originator or another forwarder): restart.
                if entry.next_forwarding.is_some() {
                    entry.next_forwarding = Some(now + entry.forwarding_timeout);
                }
                return;
            }
            if reference_time < entry.reference_time {
                return;
            }
            // Equal referenceTime with a state change (e.g. a negation) updates
            // the entry, as the receiving ITS-S rules do (clauses 8.3.2.6, 8.4.1.6).
        }
        let validity_ms = u64::from(management.validity_duration.0) * 1000;
        let Some(transmission_interval) = &management.transmission_interval else {
            // No KAF requested by the originator (clause 7.1.3): stop forwarding.
            self.forwarding.remove(&action_id);
            return;
        };
        let timeout = (2 * u64::from(transmission_interval.0)
            + self.rng.gen_range(0..=KAF_MAX_RANDOM_DELAY_MS))
        .min(validity_ms);
        let mut regenerated = denm.clone();
        regenerated.header = denm_header(self.station_id);
        let (area, area_type) = area.unwrap_or((
            default_area(&management.event_position),
            GeoBroadcastHST::GeoBroadcastCircle,
        ));
        self.forwarding.insert(
            action_id,
            ForwardingEntry {
                denm: regenerated,
                reference_time,
                validity_expiry: management.detection_time.0 + validity_ms,
                forwarding_timeout: timeout,
                next_forwarding: Some(now + timeout),
                area,
                area_type,
                traffic_class: TrafficClass {
                    scf: false,
                    channel_offload: false,
                    tc_id: 0,
                },
            },
        );
    }

    /// Own position (1/10 micro-degree), used by KAF to check the area.
    pub fn set_ego_position(&mut self, latitude: i32, longitude: i32) {
        self.ego_position = Some((latitude, longitude));
    }

    // ── Timers ─────────────────────────────────────────────────────────────

    /// Fire every timer expired at `now`. Returns the DENMs to send
    /// (repetitions and KAF forwards) and the actionIds removed from the
    /// receiving ITS-S message table (T_R_Validity expiry).
    pub fn tick(&mut self, now: u64) -> (Vec<OutgoingDenm>, Vec<DenActionId>) {
        let mut outgoing = Vec::new();
        self.originating.retain(|_, e| e.validity_expiry > now); // T_O_Validity
        for entry in self.originating.values_mut() {
            if let (Some(next), Some(interval)) = (entry.next_repetition, entry.repetition_interval)
            {
                if next <= now {
                    // T_Repetition
                    outgoing.push(OutgoingDenm {
                        denm: entry.denm.clone(),
                        area: entry.area,
                        area_type: entry.area_type,
                        traffic_class: entry.traffic_class,
                    });
                    let mut nxt = next + interval;
                    while nxt <= now {
                        nxt += interval;
                    }
                    entry.next_repetition = Some(nxt);
                }
            }
            if let (Some(next), Some(end)) = (entry.next_repetition, entry.repetition_end) {
                if next > end {
                    entry.next_repetition = None; // T_RepetitionDuration
                }
            }
        }
        let expired: Vec<DenActionId> = self
            .receiving
            .iter()
            .filter(|(_, e)| e.validity_expiry <= now)
            .map(|(a, _)| *a)
            .collect();
        for action_id in &expired {
            self.receiving.remove(action_id); // T_R_Validity
        }
        self.forwarding.retain(|_, e| e.validity_expiry > now); // T_F_Validity
        let ego = self.ego_position;
        for entry in self.forwarding.values_mut() {
            let Some(next) = entry.next_forwarding else {
                continue;
            };
            if next > now {
                continue;
            }
            // T_Forwarding
            let inside =
                ego.is_some_and(|(lat, lon)| inside_area(&entry.area, entry.area_type, lat, lon));
            if !inside {
                entry.next_forwarding = None; // outside: stop forwarding
                continue;
            }
            outgoing.push(OutgoingDenm {
                denm: entry.denm.clone(),
                area: entry.area,
                area_type: entry.area_type,
                traffic_class: entry.traffic_class,
            });
            entry.next_forwarding = Some(now + entry.forwarding_timeout);
        }
        (outgoing, expired)
    }

    /// Earliest pending timer expiry, or `None` when no timer is running.
    pub fn next_deadline(&self) -> Option<u64> {
        let originating = self
            .originating
            .values()
            .flat_map(|e| [Some(e.validity_expiry), e.next_repetition]);
        let receiving = self.receiving.values().map(|e| Some(e.validity_expiry));
        let forwarding = self
            .forwarding
            .values()
            .flat_map(|e| [Some(e.validity_expiry), e.next_forwarding]);
        originating
            .chain(receiving)
            .chain(forwarding)
            .flatten()
            .min()
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    /// Unused actionId (clause 6.1.1.1): next sequence number not in use.
    fn new_action_id(&mut self) -> Option<DenActionId> {
        for _ in 0..=u16::MAX as u32 {
            let sequence_number = self.next_sequence_number;
            self.next_sequence_number = sequence_number.wrapping_add(1);
            let candidate = DenActionId {
                station_id: self.station_id,
                sequence_number,
            };
            if !self.originating.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn management(
        &self,
        action_id: DenActionId,
        detection_time: u64,
        reference_time: u64,
        termination: Option<Termination>,
        request: &DenmRequest,
        validity: u32,
    ) -> ManagementContainer {
        ManagementContainer::new(
            action_id.to_asn(),
            TimestampIts(detection_time),
            TimestampIts(reference_time),
            termination,
            request.event_position.clone(),
            request.awareness_distance,
            request.traffic_direction,
            DeltaTimeSecond(validity),
            request
                .transmission_interval
                .map(DeltaTimeMilliSecondPositive),
            StationType(TrafficParticipantType(
                request.station_type.unwrap_or(self.station_type),
            )),
        )
    }

    fn denm(
        &self,
        management: ManagementContainer,
        situation: Option<SituationContainer>,
        location: Option<LocationContainer>,
        alacarte: Option<AlacarteContainer>,
    ) -> Denm {
        Denm::new(
            denm_header(self.station_id),
            DenmPayload::new(management, situation, location, alacarte),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn store_and_send(
        &mut self,
        action_id: DenActionId,
        denm: Denm,
        state: DenmState,
        expiry: u64,
        request: &DenmRequest,
        interval: Option<u64>,
        duration: Option<u64>,
        reference_time: u64,
    ) -> (DenResult, Vec<OutgoingDenm>) {
        if let Some(validate) = &self.validate {
            if validate(&denm).is_err() {
                return (Err(DenFailure::GenerationFailed), vec![]);
            }
        }
        let area = request
            .destination_area
            .unwrap_or_else(|| default_area(&request.event_position));
        let traffic_class = request.traffic_class.unwrap_or(TrafficClass {
            scf: false,
            channel_offload: false,
            tc_id: 0,
        });
        let mut entry = OriginatingEntry {
            denm: denm.clone(),
            state,
            validity_expiry: expiry,
            area,
            area_type: request.destination_area_type,
            traffic_class,
            repetition_interval: interval,
            repetition_duration: duration,
            repetition_end: None,
            next_repetition: None,
        };
        if let (Some(interval), Some(duration)) = (interval, duration) {
            if interval > 0 && duration > 0 {
                // T_Repetition and T_RepetitionDuration not greater than validityDuration.
                let validity_ms = expiry - denm.denm.management.detection_time.0;
                let interval = interval.min(validity_ms);
                let duration = duration.min(validity_ms);
                entry.repetition_interval = Some(interval);
                entry.repetition_end = Some(reference_time + duration);
                let next = reference_time + interval;
                entry.next_repetition = (next <= reference_time + duration).then_some(next);
            }
        }
        self.originating.insert(action_id, entry);
        let outgoing = vec![OutgoingDenm {
            denm,
            area,
            area_type: request.destination_area_type,
            traffic_class,
        }];
        (Ok(action_id), outgoing)
    }
}

#[cfg(test)]
mod tests {
    //! Mirrors `tests/flexstack/facilities/decentralized_environmental_notification_service/test_den_protocol.py`.
    //! Unit tests of the engine, grouped like the ETSI TS 102 869-2 V1.6.1
    //! test purposes; the TPs themselves are checked one by one, through the
    //! whole stack, in `super::super::conformance`.
    use super::super::denm_coder::{
        AccidentSubCauseCode, CauseCodeChoice, CauseCodeV2, DenmCoder, InformationQuality,
    };
    use super::super::denm_transmission::{build_denm, DENRequest, VehicleData};
    use super::*;

    const T0: u64 = 600_000_000_000;

    fn coder() -> DenmCoder {
        DenmCoder::new()
    }

    fn template() -> Denm {
        build_denm(&DENRequest::default(), &VehicleData::default(), 0)
    }

    fn situation(info: u8, sub: u8) -> SituationContainer {
        SituationContainer::new(
            InformationQuality(info),
            CauseCodeV2::new(CauseCodeChoice::accident2(AccidentSubCauseCode(sub))),
            None,
            None,
            None,
            None,
        )
    }

    fn req() -> DenmRequest {
        let t = template();
        let mut r = DenmRequest::new(t.denm.management.event_position.clone());
        r.situation = Some(situation(3, 0));
        r.location = t.denm.location;
        r
    }

    fn station(id: u32) -> DenProtocol {
        let c = coder();
        DenProtocol::new(
            id,
            5,
            false,
            Some(Box::new(move |d: &Denm| c.encode(d).map(|_| ()))),
        )
        .with_seed(1)
    }

    fn kaf_station(id: u32) -> DenProtocol {
        let mut s = station(id);
        s.kaf_enabled = true;
        s
    }

    fn ota(o: &OutgoingDenm) -> Denm {
        let c = coder();
        c.decode(&c.encode(&o.denm).unwrap()).unwrap()
    }

    fn mgmt(o: &OutgoingDenm) -> &ManagementContainer {
        &o.denm.denm.management
    }

    fn rep(interval: u64, duration: u64) -> DenmRequest {
        let mut r = req();
        r.repetition_interval = Some(interval);
        r.repetition_duration = Some(duration);
        r
    }

    // ── AppDENM_trigger ───────────────────────────────────────────────────

    #[test]
    fn evgn_bv01_trigger_generates_new_denm() {
        let (res, out) = station(7).trigger(&req(), T0);
        assert!(res.is_ok());
        assert_eq!(out.len(), 1);
        let d = ota(&out[0]);
        assert!(d.denm.management.termination.is_none());
        assert!(d.denm.situation.is_some() && d.denm.location.is_some());
    }

    #[test]
    fn evgn_bv02_new_action_id_per_denm() {
        let mut s = station(7);
        let ids: std::collections::HashSet<_> = (0..5)
            .map(|i| s.trigger(&req(), T0 + i).0.unwrap())
            .collect();
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn evgn_bv03_action_id_contains_station_id() {
        let (res, out) = station(4242).trigger(&req(), T0);
        assert_eq!(res.unwrap().station_id, 4242);
        assert_eq!(mgmt(&out[0]).action_id.originating_station_id.0, 4242);
    }

    #[test]
    fn evgn_bv04_cause_code_from_application() {
        let mut r = req();
        r.situation = Some(situation(5, 3));
        let (_, out) = station(7).trigger(&r, T0);
        assert_eq!(ota(&out[0]).denm.situation, Some(situation(5, 3)));
    }

    #[test]
    fn evgn_bv05_reference_time_is_now() {
        let mut r = req();
        r.detection_time = Some(T0 - 500);
        let (_, out) = station(7).trigger(&r, T0);
        assert_eq!(mgmt(&out[0]).reference_time.0, T0);
        assert_eq!(mgmt(&out[0]).detection_time.0, T0 - 500);
    }

    #[test]
    fn evgn_bv07_next_unused_sequence_number() {
        let mut s = station(7);
        let a = s.trigger(&req(), T0).0.unwrap();
        let b = s.trigger(&req(), T0 + 1).0.unwrap();
        assert_eq!(b.sequence_number, a.sequence_number + 1);
    }

    #[test]
    fn evgn_bv08_sequence_number_wraps() {
        let mut s = station(7);
        s.set_next_sequence_number(65535);
        assert_eq!(s.trigger(&req(), T0).0.unwrap().sequence_number, 65535);
        assert_eq!(s.trigger(&req(), T0 + 1).0.unwrap().sequence_number, 0);
    }

    #[test]
    fn sequence_numbers_in_use_are_skipped() {
        let mut s = station(7);
        let _ = s.trigger(&req(), T0);
        s.set_next_sequence_number(0);
        assert_eq!(s.trigger(&req(), T0 + 1).0.unwrap().sequence_number, 1);
    }

    #[test]
    fn evgn_bv10_evrp_bv08_pseudonym_change() {
        let mut s = station(7);
        let id = s.trigger(&rep(100, 1000), T0).0.unwrap();
        s.update_station_id(8);
        let moved = DenActionId {
            station_id: 8,
            sequence_number: id.sequence_number,
        };
        assert!(s.originating.contains_key(&moved) && !s.originating.contains_key(&id));
        let (out, _) = s.tick(T0 + 100);
        assert_eq!(mgmt(&out[0]).action_id.originating_station_id.0, 8);
        assert_eq!(out[0].denm.header.station_id.0, 8);
        assert_eq!(s.trigger(&req(), T0 + 200).0.unwrap().station_id, 8);
    }

    #[test]
    fn action_id_from_central_entity() {
        let mut r = req();
        r.action_id = Some(DenActionId {
            station_id: 99,
            sequence_number: 12,
        });
        assert_eq!(station(7).trigger(&r, T0).0.unwrap(), r.action_id.unwrap());
    }

    #[test]
    fn validity_in_the_past_is_failure() {
        let mut r = req();
        r.detection_time = Some(T0 - 20_000);
        r.validity_duration = Some(10);
        let (res, out) = station(7).trigger(&r, T0);
        assert_eq!(res, Err(DenFailure::ValidityExpired));
        assert!(out.is_empty());
    }

    #[test]
    fn missing_situation_is_generation_failure() {
        let mut r = req();
        r.situation = None;
        assert_eq!(
            station(7).trigger(&r, T0).0,
            Err(DenFailure::GenerationFailed)
        );
    }

    #[test]
    fn unencodable_denm_is_generation_failure() {
        let mut r = req();
        r.situation = Some(situation(99, 0));
        let (res, out) = station(7).trigger(&r, T0);
        assert_eq!(res, Err(DenFailure::GenerationFailed));
        assert!(out.is_empty());
    }

    #[test]
    fn default_validity_and_optional_fields() {
        let mut r = req();
        r.awareness_distance = Some(StandardLength3b::lessThan200m);
        r.traffic_direction = Some(TrafficDirection::allTrafficDirections);
        r.transmission_interval = Some(500);
        let (_, out) = station(7).trigger(&r, T0);
        let m = ota(&out[0]).denm.management;
        assert_eq!(m.validity_duration.0, DEFAULT_VALIDITY_DURATION_S);
        assert_eq!(m.awareness_distance, Some(StandardLength3b::lessThan200m));
        assert_eq!(m.transmission_interval.map(|t| t.0), Some(500));
    }

    // ── AppDENM_update ────────────────────────────────────────────────────

    fn triggered() -> (DenProtocol, DenActionId) {
        let mut s = station(7);
        let id = s.trigger(&req(), T0).0.unwrap();
        (s, id)
    }

    #[test]
    fn evup_bv01_update_generates_update_denm() {
        let (mut s, id) = triggered();
        let mut r = req();
        r.situation = Some(situation(6, 1));
        let (res, out) = s.update(id, &r, T0 + 1000);
        assert!(res.is_ok());
        assert_eq!(ota(&out[0]).denm.situation, Some(situation(6, 1)));
    }

    #[test]
    fn evup_bv02_update_keeps_action_id() {
        let (mut s, id) = triggered();
        let (res, out) = s.update(id, &req(), T0 + 1000);
        assert_eq!(res, Ok(id));
        assert_eq!(DenActionId::from_asn(&mgmt(&out[0]).action_id), id);
    }

    #[test]
    fn evup_bv03_update_reference_time_is_now_and_increases() {
        let (mut s, id) = triggered();
        let (_, out) = s.update(id, &req(), T0 + 1000);
        assert_eq!(mgmt(&out[0]).reference_time.0, T0 + 1000);
        let (_, out) = s.update(id, &req(), T0 + 1000);
        assert_eq!(mgmt(&out[0]).reference_time.0, T0 + 1001);
    }

    #[test]
    fn evup_bo04_update_unknown_action_id_fails() {
        let (mut s, _) = triggered();
        let id = DenActionId {
            station_id: 7,
            sequence_number: 999,
        };
        let (res, out) = s.update(id, &req(), T0 + 1000);
        assert_eq!(res, Err(DenFailure::UnknownActionId));
        assert!(out.is_empty());
    }

    #[test]
    fn update_keeps_containers_not_provided() {
        let (mut s, id) = triggered();
        let mut r = req();
        r.situation = None;
        r.location = None;
        let (_, out) = s.update(id, &r, T0 + 1000);
        assert_eq!(out[0].denm.denm.situation, Some(situation(3, 0)));
        assert!(out[0].denm.denm.location.is_some());
    }

    // ── AppDENM_termination ───────────────────────────────────────────────

    fn shared_event() -> (DenProtocol, DenProtocol, DenActionId) {
        let mut a = station(7);
        let mut b = station(9);
        let (res, out) = a.trigger(&req(), T0);
        b.receive(&ota(&out[0]), T0 + 10, None, true);
        (a, b, res.unwrap())
    }

    #[test]
    fn evtr_bv01_bv04_bv08_cancellation() {
        let (mut a, _, id) = shared_event();
        let (res, out) = a.terminate(id, &req(), T0 + 500);
        assert!(res.is_ok());
        let d = ota(&out[0]);
        assert_eq!(
            d.denm.management.termination,
            Some(Termination::isCancellation)
        );
        assert!(
            d.denm.situation.is_none() && d.denm.location.is_none() && d.denm.alacarte.is_none()
        );
        assert_eq!(d.denm.management.reference_time.0, T0 + 500);
        assert_eq!(a.originating[&id].state, DenmState::Cancelled);
    }

    #[test]
    fn evtr_bv02_bv03_bv05_negation() {
        let (_, mut b, id) = shared_event();
        let (res, out) = b.terminate(id, &req(), T0 + 500);
        assert!(res.is_ok());
        let d = ota(&out[0]);
        assert_eq!(d.denm.management.termination, Some(Termination::isNegation));
        assert_eq!(DenActionId::from_asn(&d.denm.management.action_id), id);
        assert_eq!(d.denm.management.reference_time.0, T0);
        assert_eq!(d.header.station_id.0, 9);
        assert!(d.denm.situation.is_none() && d.denm.location.is_none());
        assert_eq!(b.originating[&id].state, DenmState::Negated);
    }

    #[test]
    fn evtr_bo06_bo07_unknown_action_id() {
        let (_, mut b, _) = shared_event();
        let id = DenActionId {
            station_id: 1,
            sequence_number: 1,
        };
        assert_eq!(
            b.terminate(id, &req(), T0 + 500).0,
            Err(DenFailure::UnknownActionId)
        );
    }

    #[test]
    fn termination_detection_time_and_no_double_cancel() {
        let (mut a, _, id) = shared_event();
        let mut r = req();
        r.detection_time = Some(T0 + 400);
        let (_, out) = a.terminate(id, &r, T0 + 500);
        assert_eq!(mgmt(&out[0]).detection_time.0, T0 + 400);
        assert_eq!(
            a.terminate(id, &req(), T0 + 600).0,
            Err(DenFailure::UnknownActionId)
        );
    }

    // ── Repetition ────────────────────────────────────────────────────────

    fn sent_times(s: &mut DenProtocol, from: u64, to: u64) -> Vec<u64> {
        (from..to).filter(|t| !s.tick(*t).0.is_empty()).collect()
    }

    #[test]
    fn evrp_ti01_repetition_interval() {
        let mut s = station(7);
        let _ = s.trigger(&rep(100, 1000), T0);
        assert_eq!(
            sent_times(&mut s, T0 + 1, T0 + 501),
            vec![T0 + 100, T0 + 200, T0 + 300, T0 + 400, T0 + 500]
        );
    }

    #[test]
    fn evrp_bv02_repeats_latest_update() {
        let mut s = station(7);
        let id = s.trigger(&rep(100, 1000), T0).0.unwrap();
        let mut r = req();
        r.situation = Some(situation(7, 2));
        let _ = s.update(id, &r, T0 + 150);
        let (out, _) = s.tick(T0 + 250);
        assert_eq!(out[0].denm.denm.situation, Some(situation(7, 2)));
    }

    #[test]
    fn evrp_bv03_stops_at_validity() {
        let mut s = station(7);
        let mut r = rep(100, 5000);
        r.validity_duration = Some(1);
        let id = s.trigger(&r, T0).0.unwrap();
        assert_eq!(s.tick(T0 + 900).0.len(), 1);
        assert!(s.tick(T0 + 1000).0.is_empty());
        assert!(!s.originating.contains_key(&id));
    }

    #[test]
    fn evrp_bv04_stops_at_repetition_duration() {
        let mut s = station(7);
        let _ = s.trigger(&rep(100, 250), T0);
        assert_eq!(
            sent_times(&mut s, T0 + 1, T0 + 1001),
            vec![T0 + 100, T0 + 200]
        );
    }

    #[test]
    fn evrp_bv05_bv06_no_repetition_without_both_parameters() {
        let mut s = station(7);
        let mut r = req();
        r.repetition_duration = Some(1000);
        let _ = s.trigger(&r, T0);
        let mut r = req();
        r.repetition_interval = Some(100);
        let _ = s.trigger(&r, T0);
        assert!(sent_times(&mut s, T0 + 1, T0 + 2000).is_empty());
    }

    #[test]
    fn evrp_bv09_bv10_repetition_keeps_action_id_and_times() {
        let mut s = station(7);
        let (res, first) = s.trigger(&rep(100, 1000), T0);
        for t in [T0 + 100, T0 + 200] {
            let (out, _) = s.tick(t);
            assert_eq!(
                DenActionId::from_asn(&mgmt(&out[0]).action_id),
                res.unwrap()
            );
            assert_eq!(mgmt(&out[0]).reference_time, mgmt(&first[0]).reference_time);
            assert_eq!(mgmt(&out[0]).detection_time, mgmt(&first[0]).detection_time);
        }
    }

    #[test]
    fn evrp_bv11_default_validity_600s() {
        let mut s = station(7);
        let id = s.trigger(&rep(100_000, 10_000_000), T0).0.unwrap();
        s.tick(T0 + 599_999);
        assert!(s.originating.contains_key(&id));
        s.tick(T0 + 600_000);
        assert!(!s.originating.contains_key(&id));
    }

    #[test]
    fn cancellation_stops_repetition_and_deadline() {
        let mut s = station(7);
        assert_eq!(s.next_deadline(), None);
        let id = s.trigger(&rep(100, 1000), T0).0.unwrap();
        assert_eq!(s.next_deadline(), Some(T0 + 100));
        let _ = s.terminate(id, &req(), T0 + 150);
        assert!(s.tick(T0 + 200).0.is_empty());
    }

    // ── Receiving ITS-S ───────────────────────────────────────────────────

    fn rx_setup() -> (DenProtocol, DenProtocol, DenActionId, Denm) {
        let mut a = station(7);
        let (res, out) = a.trigger(&req(), T0);
        (a, station(9), res.unwrap(), ota(&out[0]))
    }

    fn update_of(a: &mut DenProtocol, id: DenActionId, at: u64) -> Denm {
        ota(&a.update(id, &req(), at).1[0])
    }

    #[test]
    fn msrv_bv01_new_action_id_accepted() {
        let (_, mut b, _, first) = rx_setup();
        let o = b.receive(&first, T0 + 1, None, true);
        assert!(o.accepted);
        assert_eq!(o.state, Some(DenmState::Active));
    }

    #[test]
    fn msrv_bv02_newer_reference_time_accepted() {
        let (mut a, mut b, id, first) = rx_setup();
        b.receive(&first, T0 + 1, None, true);
        assert!(
            b.receive(&update_of(&mut a, id, T0 + 1000), T0 + 1001, None, true)
                .accepted
        );
    }

    #[test]
    fn msrv_bo03_bo04_unknown_termination_discarded() {
        let (mut a, mut b, id, _) = rx_setup();
        let out = a.terminate(id, &req(), T0 + 10).1;
        let o = b.receive(&ota(&out[0]), T0 + 11, None, true);
        assert_eq!(o.reason, Some(DiscardReason::UnknownTermination));
    }

    #[test]
    fn msrv_bo05_older_reference_time_discarded() {
        let (mut a, mut b, id, first) = rx_setup();
        b.receive(&update_of(&mut a, id, T0 + 1000), T0 + 1001, None, true);
        assert_eq!(
            b.receive(&first, T0 + 1002, None, true).reason,
            Some(DiscardReason::Outdated)
        );
    }

    #[test]
    fn msrv_bo06_older_detection_time_discarded() {
        let (mut a, mut b, id, _) = rx_setup();
        let mut r = req();
        r.detection_time = Some(T0 + 900);
        let upd = ota(&a.update(id, &r, T0 + 1000).1[0]);
        b.receive(&upd, T0 + 1001, None, true);
        let mut older = upd.clone();
        older.denm.management.detection_time = TimestampIts(T0 + 800);
        older.denm.management.reference_time = TimestampIts(T0 + 2000);
        assert_eq!(
            b.receive(&older, T0 + 2001, None, true).reason,
            Some(DiscardReason::Outdated)
        );
    }

    #[test]
    fn msrv_bv07_equal_reference_time_state_change_accepted() {
        let (_, mut b, id, first) = rx_setup();
        b.receive(&first, T0 + 1, None, true);
        let mut n = station(11);
        n.receive(&first, T0 + 2, None, true);
        let mut r = req();
        r.detection_time = Some(T0);
        let out = n.terminate(id, &r, T0 + 3).1;
        let o = b.receive(&ota(&out[0]), T0 + 4, None, true);
        assert!(o.accepted);
        assert_eq!(o.state, Some(DenmState::Negated));
    }

    #[test]
    fn repeated_and_cancelled_and_expired() {
        let (mut a, mut b, id, first) = rx_setup();
        b.receive(&first, T0 + 1, None, true);
        assert_eq!(
            b.receive(&first, T0 + 100, None, true).reason,
            Some(DiscardReason::Repeated)
        );
        let out = a.terminate(id, &req(), T0 + 10).1;
        assert_eq!(
            b.receive(&ota(&out[0]), T0 + 11, None, true).state,
            Some(DenmState::Cancelled)
        );
        let (_, mut c, _, first) = rx_setup();
        assert_eq!(
            c.receive(&first, T0 + 601_000, None, true).reason,
            Some(DiscardReason::Expired)
        );
    }

    #[test]
    fn t_r_validity_removes_entry() {
        let (_, mut b, id, first) = rx_setup();
        b.receive(&first, T0 + 1, None, true);
        let (_, expired) = b.tick(T0 + 600_000);
        assert_eq!(expired, vec![id]);
        assert!(!b.receiving.contains_key(&id));
    }

    #[test]
    fn msrv_bo08x_bo09x_ssp_inconsistent_discarded() {
        let (mut a, mut b, id, first) = rx_setup();
        assert_eq!(
            b.receive(&first, T0 + 1, None, false).reason,
            Some(DiscardReason::SspInconsistent)
        );
        assert!(!b.receiving.contains_key(&id));
        b.receive(&first, T0 + 1, None, true);
        let upd = update_of(&mut a, id, T0 + 1000);
        assert_eq!(
            b.receive(&upd, T0 + 1001, None, false).reason,
            Some(DiscardReason::SspInconsistent)
        );
    }

    // ── Keep-Alive Forwarding ─────────────────────────────────────────────

    const LAT: i32 = 415_520_000;
    const LON: i32 = 21_340_000;

    fn kaf_area() -> Option<(Area, GeoBroadcastHST)> {
        Some((
            Area {
                latitude: LAT as u32,
                longitude: LON as u32,
                a: 1000,
                b: 0,
                angle: 0,
            },
            GeoBroadcastHST::GeoBroadcastCircle,
        ))
    }

    fn kaf_setup(ti: Option<u16>, validity: u32) -> (DenProtocol, DenProtocol, DenActionId, Denm) {
        let mut a = station(7);
        let mut f = kaf_station(9);
        f.set_ego_position(LAT, LON);
        let mut r = req();
        r.transmission_interval = ti;
        r.validity_duration = Some(validity);
        let (res, out) = a.trigger(&r, T0);
        let d = ota(&out[0]);
        f.receive(&d, T0, kaf_area(), true);
        (a, f, res.unwrap(), d)
    }

    fn forwards(f: &mut DenProtocol, until: u64) -> Vec<(u64, OutgoingDenm)> {
        (T0 + 1..until)
            .flat_map(|t| f.tick(t).0.into_iter().map(move |o| (t, o)))
            .collect()
    }

    #[test]
    fn kafw_bv01_forwards_after_delay() {
        let (_, mut f, id, _) = kaf_setup(Some(100), 10);
        let timeout = f.forwarding[&id].forwarding_timeout;
        assert_eq!(forwards(&mut f, T0 + timeout + 1).len(), 1);
    }

    #[test]
    fn kafw_bv02_same_denm_restarts_timer() {
        let (_, mut f, id, d) = kaf_setup(Some(100), 10);
        let timeout = f.forwarding[&id].forwarding_timeout;
        for t in (T0 + 100..T0 + 2000).step_by(100) {
            f.receive(&d, t, kaf_area(), true);
            assert!(f.tick(t).0.is_empty());
        }
        assert_eq!(f.forwarding[&id].next_forwarding, Some(T0 + 1900 + timeout));
    }

    #[test]
    fn kafw_ti03_forwarding_delay() {
        let (_, f, id, _) = kaf_setup(Some(100), 10);
        let timeout = f.forwarding[&id].forwarding_timeout;
        assert!((200..=350).contains(&timeout));
        let (_, f, id, _) = kaf_setup(Some(10_000), 5);
        assert_eq!(f.forwarding[&id].forwarding_timeout, 5000);
    }

    #[test]
    fn kafw_bv04_bv05_bv06_bv08_regeneration() {
        let (_, mut f, _, d) = kaf_setup(Some(100), 10);
        let (_, out) = forwards(&mut f, T0 + 400).remove(0);
        let fwd = ota(&out);
        assert_eq!(fwd.header.station_id.0, 9);
        assert_eq!(fwd.denm, d.denm);
    }

    #[test]
    fn kafw_bv07_negation_keeps_termination() {
        let (_, mut f, id, d) = kaf_setup(Some(100), 10);
        let mut n = station(11);
        n.receive(&d, T0 + 1, None, true);
        let mut r = req();
        r.transmission_interval = Some(100);
        r.detection_time = Some(T0);
        let out = n.terminate(id, &r, T0 + 2).1;
        f.receive(&ota(&out[0]), T0 + 2, kaf_area(), true);
        let (_, fwd) = forwards(&mut f, T0 + 500).remove(0);
        assert_eq!(
            fwd.denm.denm.management.termination,
            Some(Termination::isNegation)
        );
    }

    #[test]
    fn kafw_bv09_stops_after_validity() {
        let (_, mut f, id, _) = kaf_setup(Some(100), 1);
        assert!(forwards(&mut f, T0 + 3000)
            .iter()
            .all(|(t, _)| *t < T0 + 1000));
        assert!(!f.forwarding.contains_key(&id));
    }

    #[test]
    fn kafw_bv10_stops_outside_area() {
        let mut a = station(7);
        let mut f = kaf_station(9);
        f.set_ego_position(LAT + 10_000_000, LON);
        let mut r = req();
        r.transmission_interval = Some(100);
        let out = a.trigger(&r, T0).1;
        f.receive(&ota(&out[0]), T0, kaf_area(), true);
        assert!(forwards(&mut f, T0 + 2000).is_empty());
    }

    #[test]
    fn kafw_bv11_no_forwarding_without_transmission_interval() {
        let (_, f, id, _) = kaf_setup(None, 10);
        assert!(!f.forwarding.contains_key(&id));
    }

    #[test]
    fn kaf_older_reference_time_not_stored_and_disabled_by_default() {
        let (mut a, mut f, id, d) = kaf_setup(Some(100), 10);
        let mut r = req();
        r.transmission_interval = Some(100);
        r.validity_duration = Some(10);
        let upd = ota(&a.update(id, &r, T0 + 50).1[0]);
        f.receive(&upd, T0 + 50, kaf_area(), true);
        let latest = f.forwarding[&id].reference_time;
        f.receive(&d, T0 + 60, kaf_area(), true);
        assert_eq!(f.forwarding[&id].reference_time, latest);
        let mut plain = station(12);
        plain.receive(&d, T0, None, true);
        assert!(plain.forwarding.is_empty());
    }

    // ── Destination area ──────────────────────────────────────────────────

    #[test]
    fn destination_area_circle_and_rotated_rectangle() {
        let circle = Area {
            latitude: LAT as u32,
            longitude: LON as u32,
            a: 100,
            b: 0,
            angle: 0,
        };
        let c = GeoBroadcastHST::GeoBroadcastCircle;
        assert!(inside_area(&circle, c, LAT, LON));
        assert!(inside_area(&circle, c, LAT + 8000, LON));
        assert!(!inside_area(&circle, c, LAT + 10_000, LON));
        let rect = Area {
            latitude: LAT as u32,
            longitude: LON as u32,
            a: 1000,
            b: 10,
            angle: 90,
        };
        let r = GeoBroadcastHST::GeoBroadcastRectangle;
        let east_500m = LON + (500.0 / (111_320.0 * 0.7485) * 1e7) as i32;
        let north_500m = LAT + (500.0 / 111_195.0 * 1e7) as i32;
        assert!(inside_area(&rect, r, LAT, east_500m));
        assert!(!inside_area(&rect, r, north_500m, LON));
    }
}

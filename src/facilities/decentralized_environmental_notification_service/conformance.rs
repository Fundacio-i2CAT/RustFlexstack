// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DEN basic service conformance tests: one test per Test Purpose of ETSI
//! TS 102 869-2 V1.6.1, against ETSI TS 103 831 V2.3.1 (2025-11).
//!
//! Each test is named after its TP and quotes the TP identifier, so that a
//! search for the identifier finds it. The tests drive complete stations (DEN
//! service -> BTP -> GeoNetworking -> link layer) on one virtual clock (the
//! `clock` of the DEN service; security uses the real time) and check the
//! GeoBroadcast frames that leave the IUT, decoded from the wire. A second
//! station plays the test system: it triggers real events, or sends DENMs it
//! builds itself (outdated, terminated, unknown actionIds) through its own
//! stack. Received frames go up GN and BTP to the DEN reception
//! ([`process_indication`], the function the reception thread runs).
//!
//! Mirrors `tests/flexstack/facilities/decentralized_environmental_notification_service/test_den_conformance.py`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rasn::prelude::Integer;

use super::den_protocol::{
    default_area, DenActionId, DenFailure, DenResult, DenmRequest, OutgoingDenm,
    KAF_MAX_RANDOM_DELAY_MS,
};
use super::denm_bindings::etsi_its_cdd as cdd;
use super::denm_coder::{
    denm_header, AlacarteContainer, CauseCodeChoice, CauseCodeV2, DeltaTimeMilliSecondPositive,
    DeltaTimeSecond, Denm, DenmCoder, DenmPayload, InformationQuality, Latitude, Longitude,
    ManagementContainer, ReferencePosition, SituationContainer, StationType, Termination,
    TimestampIts, TrafficParticipantType,
};
use super::denm_reception::{process_indication, ReceivedDenm};
use super::denm_ssp::cause_code_ssp_bit;
use super::denm_transmission::{build_denm, transmit, DENRequest, VehicleData};
use super::{DecentralizedEnvironmentalNotificationService, DenConfig};
use crate::btp::router::{BTPRouterHandle, Router as BtpRouter};
use crate::btp::service_access_point::{BTPDataIndication, BTPDataRequest};
use crate::facilities::ca_basic_service::conformance::Pki;
use crate::geonet::basic_header::{BasicHeader, BasicNH};
use crate::geonet::common_header::CommonHeader;
use crate::geonet::gbc_extended_header::GBCExtendedHeader;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::mib::{GnSecurity, Mib};
use crate::geonet::position_vector::Tst;
use crate::geonet::router::Router as GnRouter;
use crate::geonet::service_access_point::{
    CommonNH, GNDataIndication, GNDataRequest, GeoBroadcastHST, HeaderSubType, HeaderType,
    TrafficClass,
};
use crate::security::certificate::{decode_ieee1609_dot2_data, OwnCertificate};
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::security_asn::ieee1609_dot2::{
    HeaderInfo, Ieee1609Dot2Content, SequenceOfCertificate, SignerIdentifier,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    Elevation, Latitude as SecLatitude, Longitude as SecLongitude, NinetyDegreeInt,
    OneEightyDegreeInt, Psid, ThreeDLocation, Time64, Uint16, Uint64,
};
use crate::security::sign_service::SignService;
use crate::security::time_service::timestamp_its_microseconds;

const LAT: i32 = 415_520_000;
const LON: i32 = 21_340_000;
const IUT_ID: u32 = 0x1001;
const TESTER_ID: u32 = 0x2002;
const NEW_ID: u32 = 0x3003;
const KAF_SEED: u64 = 7;
const PSID_DENM: u64 = 37;
const DEFAULT_VALIDITY_S: u32 = 600;
/// ITS-AID of the request used to flush the BTP router (never sent).
const FLUSH_AID: u64 = u64::MAX;
/// TP/DEN/SSP/BV-01-X, MSRV/BO-08-X, MSRV/BO-09-X variants 01-24 (octets 1-3
/// of Table 10), in TP order.
const SSP_CAUSES: [u8; 24] = [
    1, 2, 3, 6, 9, 10, 11, 12, 14, 15, 17, 18, 19, 26, 27, 91, 92, 93, 94, 95, 96, 97, 98, 99,
];

fn addr(n: u8) -> GNAddress {
    GNAddress::new(M::GnUnicast, ST::Unknown, MID::new([2, 0, 0, 0, 0, n]))
}

/// CauseCodeChoice of a cause code value (DENM v2 ASN.1 names).
fn cause(code: u8, sub: u8) -> CauseCodeChoice {
    use cdd::*;
    match code {
        1 => CauseCodeChoice::trafficCondition1(TrafficConditionSubCauseCode(sub)),
        2 => CauseCodeChoice::accident2(AccidentSubCauseCode(sub)),
        3 => CauseCodeChoice::roadworks3(RoadworksSubCauseCode(sub)),
        6 => CauseCodeChoice::adhesion6(AdhesionSubCauseCode(sub)),
        9 => CauseCodeChoice::hazardousLocation_SurfaceCondition9(
            HazardousLocationSurfaceConditionSubCauseCode(sub),
        ),
        10 => CauseCodeChoice::hazardousLocation_ObstacleOnTheRoad10(
            HazardousLocationObstacleOnTheRoadSubCauseCode(sub),
        ),
        11 => CauseCodeChoice::hazardousLocation_AnimalOnTheRoad11(
            HazardousLocationAnimalOnTheRoadSubCauseCode(sub),
        ),
        12 => CauseCodeChoice::humanPresenceOnTheRoad12(HumanPresenceOnTheRoadSubCauseCode(sub)),
        14 => CauseCodeChoice::wrongWayDriving14(WrongWayDrivingSubCauseCode(sub)),
        15 => CauseCodeChoice::rescueRecoveryAndMaintenanceWorkInProgress15(
            RescueRecoveryAndMaintenanceWorkInProgressSubCauseCode(sub),
        ),
        17 => CauseCodeChoice::adverseWeatherCondition_Wind17(
            AdverseWeatherConditionWindSubCauseCode(sub),
        ),
        18 => CauseCodeChoice::adverseWeatherCondition_Visibility18(
            AdverseWeatherConditionVisibilitySubCauseCode(sub),
        ),
        19 => CauseCodeChoice::adverseWeatherCondition_Precipitation19(
            AdverseWeatherConditionPrecipitationSubCauseCode(sub),
        ),
        26 => CauseCodeChoice::slowVehicle26(SlowVehicleSubCauseCode(sub)),
        27 => CauseCodeChoice::dangerousEndOfQueue27(DangerousEndOfQueueSubCauseCode(sub)),
        91 => CauseCodeChoice::vehicleBreakdown91(VehicleBreakdownSubCauseCode(sub)),
        92 => CauseCodeChoice::postCrash92(PostCrashSubCauseCode(sub)),
        93 => CauseCodeChoice::humanProblem93(HumanProblemSubCauseCode(sub)),
        94 => CauseCodeChoice::stationaryVehicle94(StationaryVehicleSubCauseCode(sub)),
        95 => CauseCodeChoice::emergencyVehicleApproaching95(
            EmergencyVehicleApproachingSubCauseCode(sub),
        ),
        96 => CauseCodeChoice::hazardousLocation_DangerousCurve96(
            HazardousLocationDangerousCurveSubCauseCode(sub),
        ),
        97 => CauseCodeChoice::collisionRisk97(CollisionRiskSubCauseCode(sub)),
        98 => CauseCodeChoice::signalViolation98(SignalViolationSubCauseCode(sub)),
        99 => CauseCodeChoice::dangerousSituation99(DangerousSituationSubCauseCode(sub)),
        _ => panic!("no CauseCodeChoice for {code}"),
    }
}

fn situation(code: u8, sub: u8) -> SituationContainer {
    SituationContainer::new(
        InformationQuality(3),
        CauseCodeV2::new(cause(code, sub)),
        None,
        None,
        None,
        None,
    )
}

fn template() -> Denm {
    build_denm(&DENRequest::default(), &VehicleData::default(), 0)
}

fn position() -> ReferencePosition {
    let mut position = template().denm.management.event_position;
    position.latitude = Latitude(LAT);
    position.longitude = Longitude(LON);
    position
}

fn alacarte() -> AlacarteContainer {
    AlacarteContainer::new(
        Some(cdd::LanePosition(2)),
        None,
        Some(cdd::Temperature(21)),
        None,
        None,
        None,
        None,
    )
}

pub(crate) fn request(code: u8, sub: u8) -> DenmRequest {
    let mut r = DenmRequest::new(position());
    r.situation = Some(situation(code, sub));
    r.location = template().denm.location;
    r
}

fn repeated(interval: u64, duration: Option<u64>, validity: Option<u32>) -> DenmRequest {
    let mut r = request(2, 0);
    r.repetition_interval = Some(interval);
    r.repetition_duration = duration;
    r.validity_duration = validity;
    r
}

/// DENM BitmapSsp version 2 granting every cause code but `clear` (octet, mask).
fn denm_ssp(clear: Option<(usize, u8)>) -> Vec<(u64, Option<Vec<u8>>)> {
    let mut ssp = vec![2, 0xFF, 0xFF, 0xFF, 0xFF];
    if let Some((octet, mask)) = clear {
        ssp[octet] &= !mask;
    }
    vec![(PSID_DENM, Some(ssp))]
}

/// A GeoBroadcast frame carrying a DENM, decoded from the wire (secured or not).
struct Frame {
    secured: bool,
    psid: Option<u64>,
    /// Common Header .. DENM
    plain: Vec<u8>,
    common: CommonHeader,
    gbc: GBCExtendedHeader,
    destination_port: u16,
    denm: Denm,
}

impl Frame {
    fn decode(raw: &[u8]) -> Frame {
        let basic = BasicHeader::decode(raw[0..4].try_into().unwrap());
        let secured = matches!(basic.nh, BasicNH::SecuredPacket);
        let (plain, psid) = if secured {
            let Ieee1609Dot2Content::signedData(sd) = decode_ieee1609_dot2_data(&raw[4..]).content
            else {
                panic!("expected signedData");
            };
            let psid = u64::try_from(&sd.tbs_data.header_info.psid.0).unwrap();
            let inner = sd.tbs_data.payload.data.as_ref().expect("payload data");
            let Ieee1609Dot2Content::unsecuredData(opaque) = &inner.content else {
                panic!("expected unsecuredData");
            };
            (opaque.0.to_vec(), Some(psid))
        } else {
            (raw[4..].to_vec(), None)
        };
        Frame {
            secured,
            psid,
            common: CommonHeader::decode(plain[0..8].try_into().unwrap()),
            gbc: GBCExtendedHeader::decode(plain[8..52].try_into().unwrap()),
            destination_port: u16::from_be_bytes([plain[52], plain[53]]),
            // fails if the DENM is not valid UPER
            denm: DenmCoder::new().decode(&plain[56..]).expect("valid DENM"),
            plain,
        }
    }

    fn management(&self) -> &ManagementContainer {
        &self.denm.denm.management
    }

    fn action_id(&self) -> DenActionId {
        DenActionId::from_asn(&self.management().action_id)
    }

    fn reference_time(&self) -> u64 {
        self.management().reference_time.0
    }

    fn sequence_number(&self) -> u16 {
        self.action_id().sequence_number
    }

    fn termination(&self) -> Option<Termination> {
        self.management().termination
    }

    fn cause(&self) -> CauseCodeChoice {
        self.denm
            .denm
            .situation
            .as_ref()
            .expect("situation container")
            .event_type
            .cc_and_scc
            .clone()
    }
}

/// A complete ITS-S: DEN service on BTP on GeoNetworking, the link layer
/// captured with the virtual time of each frame.
struct Station {
    addr: GNAddress,
    gn: GnRouter,
    ll_rx: Receiver<Vec<u8>>,
    gn_btp_rx: Receiver<GNDataIndication>,
    btp: BTPRouterHandle,
    btp_gn_rx: Receiver<GNDataRequest>,
    port_rx: Receiver<BTPDataIndication>,
    den: DecentralizedEnvironmentalNotificationService,
    coder: DenmCoder,
    offset: Arc<AtomicU64>,
    log: Vec<(u64, Vec<u8>)>,
    received: Vec<ReceivedDenm>,
}

impl Station {
    fn now(&self) -> u64 {
        self.offset.load(Ordering::SeqCst)
    }

    /// Wait until every BTP request made so far has reached GN, pass them to
    /// GN and collect the frames sent.
    fn pump(&mut self) {
        self.btp.send_btp_data_request(BTPDataRequest {
            btp_type: CommonNH::BtpB,
            its_aid: FLUSH_AID,
            ..BTPDataRequest::new()
        });
        loop {
            let request = self
                .btp_gn_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("BTP flush");
            if request.its_aid == FLUSH_AID {
                break;
            }
            self.gn.gn_data_request(request);
        }
        let now = self.now();
        while let Ok(raw) = self.ll_rx.try_recv() {
            self.log.push((now, raw));
        }
    }

    /// DENMs originated by this station (GN source = own address), in order.
    fn denms(&self) -> Vec<Frame> {
        self.log
            .iter()
            .map(|(_, raw)| Frame::decode(raw))
            .filter(|f| f.gbc.so_pv.gn_addr == self.addr)
            .collect()
    }

    /// Virtual times (ms) of the DENMs originated by this station.
    fn times(&self) -> Vec<u64> {
        self.log
            .iter()
            .filter(|(_, raw)| Frame::decode(raw).gbc.so_pv.gn_addr == self.addr)
            .map(|(t, _)| *t)
            .collect()
    }

    fn last(&self) -> Frame {
        self.denms().pop().expect("a DENM was sent")
    }

    fn last_raw(&self) -> Vec<u8> {
        self.log.last().expect("a frame was sent").1.clone()
    }

    fn trigger(&mut self, r: &DenmRequest) -> DenResult {
        let result = self.den.trigger(r);
        self.pump();
        result
    }

    fn update(&mut self, action_id: DenActionId, r: &DenmRequest) -> DenResult {
        let result = self.den.update(action_id, r);
        self.pump();
        result
    }

    fn terminate(&mut self, action_id: DenActionId) -> DenResult {
        let result = self.den.terminate(action_id, &DenmRequest::new(position()));
        self.pump();
        result
    }

    /// A frame received from the radio: GN -> BTP -> DEN reception.
    fn deliver(&mut self, raw: &[u8]) {
        self.gn.process_basic_header(raw);
        while let Ok(indication) = self.gn_btp_rx.try_recv() {
            self.btp.send_gn_data_indication(indication);
            let btp = self
                .port_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("BTP indication on port 2002");
            if let Some(received) = process_indication(&self.coder, self.den.shared(), &btp) {
                self.received.push(received);
            }
        }
        let now = self.now();
        while let Ok(raw) = self.ll_rx.try_recv() {
            self.log.push((now, raw));
        }
    }

    /// Send a DENM built by the test, over this station's BTP and GN; returns the frame.
    fn send(&mut self, denm: Denm) -> Vec<u8> {
        let area = default_area(&denm.denm.management.event_position);
        transmit(
            &self.btp,
            &self.coder,
            &OutgoingDenm {
                denm,
                area,
                area_type: GeoBroadcastHST::GeoBroadcastCircle,
                traffic_class: TrafficClass {
                    scf: false,
                    channel_offload: false,
                    tc_id: 0,
                },
            },
        );
        self.pump();
        self.last_raw()
    }

    fn originating_empty(&self) -> bool {
        self.den
            .shared()
            .protocol
            .lock()
            .unwrap()
            .originating
            .is_empty()
    }

    fn forwarding_empty(&self) -> bool {
        self.den
            .shared()
            .protocol
            .lock()
            .unwrap()
            .forwarding
            .is_empty()
    }

    fn knows_received(&self, action_id: DenActionId) -> bool {
        self.den
            .shared()
            .protocol
            .lock()
            .unwrap()
            .receiving
            .contains_key(&action_id)
    }
}

/// What the test system puts in a DENM it builds; times are virtual offsets (ms).
struct Spec {
    reference: Option<i64>,
    detection: Option<i64>,
    termination: Option<Termination>,
    transmission_interval: Option<u16>,
    validity: u32,
    cause: u8,
    alacarte: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
            reference: None,
            detection: None,
            termination: None,
            transmission_interval: None,
            validity: DEFAULT_VALIDITY_S,
            cause: 2,
            alacarte: false,
        }
    }
}

/// Virtual clock, stations and the test system.
struct World {
    start: u64,
    offset: Arc<AtomicU64>,
    s: Vec<Station>,
}

impl World {
    fn new() -> World {
        World {
            start: super::denm_coder::timestamp_its_now().0,
            offset: Arc::new(AtomicU64::new(0)),
            s: vec![],
        }
    }

    fn now(&self) -> u64 {
        self.offset.load(Ordering::SeqCst)
    }

    fn its(&self) -> u64 {
        self.start + self.now()
    }

    fn station(
        &mut self,
        station_id: u32,
        n: u8,
        kaf: bool,
        sign: Option<SignService>,
        verify: Option<(EcdsaBackend, CertificateLibrary)>,
    ) -> usize {
        let mut mib = Mib::new();
        mib.itsGnBeaconServiceRetransmitTimer = 0;
        mib.itsGnLocalGnAddr = addr(n);
        if sign.is_some() || verify.is_some() {
            mib.itsGnSecurity = GnSecurity::Enabled;
        }
        let (ll_tx, ll_rx) = mpsc::channel();
        let (gn_btp_tx, gn_btp_rx) = mpsc::channel();
        let (backend, library) = verify.unzip();
        let mut gn = GnRouter::new(mib, ll_tx, gn_btp_tx, sign, backend, library);
        gn.ego_position_vector.latitude = LAT as u32;
        gn.ego_position_vector.longitude = LON as u32;
        gn.ego_position_vector.pai = true;
        gn.ego_position_vector.tst = Tst::set_in_normal_timestamp_milliseconds(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
        let (btp, btp_gn_rx) = BtpRouter::spawn(mib);
        let (start, offset) = (self.start, Arc::clone(&self.offset));
        let (den, _denm_rx) = DecentralizedEnvironmentalNotificationService::with_config(
            btp.clone(),
            VehicleData {
                station_id,
                station_type: 5,
            },
            DenConfig {
                kaf_enabled: kaf,
                no_scheduler: true,
                clock: Some(Arc::new(move || start + offset.load(Ordering::SeqCst))),
                ..Default::default()
            },
        );
        den.shared().protocol.lock().unwrap().set_seed(KAF_SEED);
        den.set_ego_position(LAT, LON);
        // Replaces the port of the reception thread: received DENMs are
        // processed synchronously by `deliver`.
        let (port_tx, port_rx) = mpsc::channel();
        btp.register_port(2002, port_tx);
        self.s.push(Station {
            addr: addr(n),
            gn,
            ll_rx,
            gn_btp_rx,
            btp,
            btp_gn_rx,
            port_rx,
            den,
            coder: DenmCoder::new(),
            offset: Arc::clone(&self.offset),
            log: vec![],
            received: vec![],
        });
        self.s.len() - 1
    }

    fn iut(&mut self) -> usize {
        self.station(IUT_ID, 1, false, None, None)
    }

    fn kaf_iut(&mut self) -> usize {
        self.station(IUT_ID, 1, true, None, None)
    }

    fn tester(&mut self) -> usize {
        self.station(TESTER_ID, 9, false, None, None)
    }

    /// Advance the virtual clock to `offset_ms`, firing every DEN timer due on the way.
    fn at(&mut self, offset_ms: u64) {
        loop {
            let due = self
                .s
                .iter()
                .enumerate()
                .filter_map(|(i, s)| {
                    let deadline = s.den.shared().protocol.lock().unwrap().next_deadline()?;
                    (deadline <= self.start + offset_ms).then_some((deadline, i))
                })
                .min();
            let Some((deadline, i)) = due else { break };
            let now = self.now().max(deadline - self.start);
            self.offset.store(now, Ordering::SeqCst);
            self.s[i].den.process_timers(Some(deadline));
            self.s[i].pump();
        }
        self.offset.store(offset_ms, Ordering::SeqCst);
    }

    /// A DENM as the test system builds it.
    fn denm(&self, station_id: u32, sequence_number: u16, spec: Spec) -> Denm {
        let reference = spec.reference.unwrap_or(self.now() as i64);
        let detection = spec.detection.unwrap_or(reference);
        let management = ManagementContainer::new(
            DenActionId {
                station_id,
                sequence_number,
            }
            .to_asn(),
            TimestampIts((self.start as i64 + detection) as u64),
            TimestampIts((self.start as i64 + reference) as u64),
            spec.termination,
            position(),
            None,
            None,
            DeltaTimeSecond(spec.validity),
            spec.transmission_interval.map(DeltaTimeMilliSecondPositive),
            StationType(TrafficParticipantType(5)),
        );
        let active = spec.termination.is_none();
        Denm {
            header: denm_header(TESTER_ID),
            denm: DenmPayload::new(
                management,
                active.then(|| situation(spec.cause, 0)),
                if active {
                    template().denm.location
                } else {
                    None
                },
                (active && spec.alacarte).then(alacarte),
            ),
        }
    }

    /// The test system sends `denm`; the IUT `iut` receives it.
    fn relay(&mut self, tester: usize, iut: usize, denm: Denm) -> Vec<u8> {
        let raw = self.s[tester].send(denm);
        self.s[iut].deliver(&raw);
        raw
    }
}

// ── TP/DEN/MSGF: message format (EN 302 637-3 clauses B.1, 6.1.3.2; TS 103 831 V2.3.1) ──

/// TP/DEN/MSGF/BV-01: the DENM sent on an AppDENM_trigger request has an ITS PDU
/// header with protocolVersion 2 and messageID 1 (denm).
#[test]
fn tp_den_msgf_bv_01() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut].trigger(&request(2, 0)).unwrap();
    let frames = w.s[iut].denms();
    let header = &frames[0].denm.header;
    assert_eq!((header.protocol_version.0, header.message_id.0), (2, 1));
}

/// TP/DEN/MSGF/BV-02: the location container of the DENM sent contains at least
/// one trace (detectionZonesToEventPosition, the Traces of TS 103 831 V2.3.1).
#[test]
fn tp_den_msgf_bv_02() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut].trigger(&request(2, 0)).unwrap();
    let frames = w.s[iut].denms();
    let location = frames[0]
        .denm
        .denm
        .location
        .as_ref()
        .expect("location container");
    assert!(!location.detection_zones_to_event_position.0.is_empty());
}

// ── TP/DEN/EVGN: new event generation (TS 103 831 clauses 6.1.1, 6.1.2.1, 8.2.1) ──

/// TP/DEN/EVGN/BV-01: an AppDENM_trigger request makes the IUT send a valid DENM.
#[test]
fn tp_den_evgn_bv_01() {
    let mut w = World::new();
    let iut = w.iut();
    let action_id = w.s[iut].trigger(&request(2, 0)).unwrap();
    let frames = w.s[iut].denms();
    assert_eq!(frames.len(), 1);
    let header = &frames[0].denm.header;
    assert_eq!(
        (
            header.protocol_version.0,
            header.message_id.0,
            header.station_id.0
        ),
        (2, 1, IUT_ID)
    );
    assert_eq!(frames[0].action_id(), action_id);
    assert!(frames[0].denm.denm.situation.is_some() && frames[0].denm.denm.location.is_some());
}

/// TP/DEN/EVGN/BV-02: each new event gets an actionID not used before.
#[test]
fn tp_den_evgn_bv_02() {
    let mut w = World::new();
    let iut = w.iut();
    for step in 0..5 {
        w.at(step * 100);
        w.s[iut].trigger(&request(2, 0)).unwrap();
    }
    let ids: HashSet<_> = w.s[iut].denms().iter().map(Frame::action_id).collect();
    assert_eq!(ids.len(), 5);
}

/// TP/DEN/EVGN/BV-03: the new actionID carries the IUT StationID as originatingStationID.
#[test]
fn tp_den_evgn_bv_03() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut].trigger(&request(2, 0)).unwrap();
    assert_eq!(w.s[iut].last().action_id().station_id, IUT_ID);
}

/// TP/DEN/EVGN/BV-04: causeCode and subCauseCode are those given by the application.
#[test]
fn tp_den_evgn_bv_04() {
    let mut w = World::new();
    let iut = w.iut();
    for (code, sub) in [(2, 3), (3, 4), (99, 5)] {
        w.s[iut].trigger(&request(code, sub)).unwrap();
        assert_eq!(w.s[iut].last().cause(), cause(code, sub), "cause {code}");
    }
}

/// TP/DEN/EVGN/BV-05: referenceTime of a new event is the current time (CLT).
#[test]
fn tp_den_evgn_bv_05() {
    let mut w = World::new();
    let iut = w.iut();
    for step in 0..3 {
        w.at(step * 100);
        w.s[iut].trigger(&request(2, 0)).unwrap();
    }
    w.at(437);
    w.s[iut].trigger(&request(2, 0)).unwrap();
    assert_eq!(w.s[iut].last().reference_time(), w.its());
}

/// TP/DEN/EVGN/BV-07: the new event gets sequenceNumber SEQ1 + 1 when unused.
#[test]
fn tp_den_evgn_bv_07() {
    let mut w = World::new();
    let iut = w.iut();
    for _ in 0..3 {
        w.s[iut].trigger(&request(2, 0)).unwrap();
    }
    let seq1 = w.s[iut].last().sequence_number();
    w.s[iut].trigger(&request(2, 0)).unwrap();
    assert_eq!(w.s[iut].last().sequence_number(), seq1 + 1);
}

/// TP/DEN/EVGN/BV-08: SEQ1 + 1 being used by an active event, the new event
/// gets SEQ1 + 2, also across the 65535 -> 0 wrap-around.
#[test]
fn tp_den_evgn_bv_08() {
    for seq1 in [0u16, 65534] {
        let mut w = World::new();
        let iut = w.iut();
        // Event on SEQ1 + 1, actionId assigned by a central entity (Table 2 note 10).
        let mut busy = request(2, 0);
        busy.action_id = Some(DenActionId {
            station_id: IUT_ID,
            sequence_number: seq1.wrapping_add(1),
        });
        w.s[iut].trigger(&busy).unwrap();
        w.s[iut]
            .den
            .shared()
            .protocol
            .lock()
            .unwrap()
            .set_next_sequence_number(seq1);
        w.s[iut].trigger(&request(2, 0)).unwrap();
        assert_eq!(w.s[iut].last().sequence_number(), seq1);
        w.s[iut].trigger(&request(2, 0)).unwrap();
        assert_eq!(w.s[iut].last().sequence_number(), seq1.wrapping_add(2));
    }
}

/// TP/DEN/EVGN/BV-10: after a StationID change, new actionIDs use the new StationID.
#[test]
fn tp_den_evgn_bv_10() {
    let mut w = World::new();
    let iut = w.iut();
    for _ in 0..2 {
        w.s[iut].trigger(&request(2, 0)).unwrap();
    }
    assert_eq!(w.s[iut].last().action_id().station_id, IUT_ID);
    w.s[iut].den.update_station_id(NEW_ID);
    w.s[iut].trigger(&request(2, 0)).unwrap();
    assert_eq!(w.s[iut].last().action_id().station_id, NEW_ID);
    assert_eq!(w.s[iut].last().denm.header.station_id.0, NEW_ID);
}

// ── TP/DEN/EVUP: event update (TS 103 831 clauses 6.1.2.2, 8.2.1.2, 8.2.1.3) ──

fn event(w: &mut World) -> (usize, DenActionId, Frame) {
    let iut = w.iut();
    let action_id = w.s[iut].trigger(&request(2, 0)).unwrap();
    let first = w.s[iut].last();
    (iut, action_id, first)
}

/// TP/DEN/EVUP/BV-01: an AppDENM_update request makes the IUT send a valid DENM.
#[test]
fn tp_den_evup_bv_01() {
    let mut w = World::new();
    let (iut, action_id, _) = event(&mut w);
    w.at(100);
    w.s[iut].update(action_id, &request(2, 2)).unwrap();
    assert_eq!(w.s[iut].denms().len(), 2);
    assert_eq!(w.s[iut].last().cause(), cause(2, 2));
}

/// TP/DEN/EVUP/BV-02: the update DENM keeps ACTION_ID1 (StationID unchanged).
#[test]
fn tp_den_evup_bv_02() {
    let mut w = World::new();
    let (iut, action_id, first) = event(&mut w);
    w.at(100);
    w.s[iut].update(action_id, &request(2, 2)).unwrap();
    assert_eq!(w.s[iut].last().action_id(), action_id);
    assert_eq!(
        w.s[iut].last().management().action_id,
        first.management().action_id
    );
}

/// TP/DEN/EVUP/BV-03: the update DENM has referenceTime = CLT > REFERENCETIME1.
#[test]
fn tp_den_evup_bv_03() {
    let mut w = World::new();
    let (iut, action_id, first) = event(&mut w);
    w.at(250);
    w.s[iut].update(action_id, &request(2, 2)).unwrap();
    assert_eq!(w.s[iut].last().reference_time(), w.its());
    assert!(w.s[iut].last().reference_time() > first.reference_time());
}

/// TP/DEN/EVUP/BO-04: no DENM for an update of an actionID not in the
/// originating ITS-S message table.
#[test]
fn tp_den_evup_bo_04() {
    let mut w = World::new();
    let (iut, _, _) = event(&mut w);
    w.s[iut].trigger(&request(2, 0)).unwrap();
    let unknown = DenActionId {
        station_id: IUT_ID,
        sequence_number: 77,
    };
    assert_eq!(
        w.s[iut].update(unknown, &request(2, 0)),
        Err(DenFailure::UnknownActionId)
    );
    assert_eq!(w.s[iut].denms().len(), 2);
}

// ── TP/DEN/EVTR: cancellation and negation (TS 103 831 clauses 6.1.2.4, 7.1.1, 8.2.1.3, 8.2.2) ──

/// The IUT has received an event of the test system (and `updates` updates of it).
fn received_event(w: &mut World, updates: u64) -> (usize, usize, DenActionId) {
    let (iut, tester) = (w.iut(), w.tester());
    let action_id = w.s[tester].trigger(&request(2, 0)).unwrap();
    let raw = w.s[tester].last_raw();
    w.s[iut].deliver(&raw);
    for step in 1..=updates {
        w.at(step * 100);
        w.s[tester]
            .update(action_id, &request(2, step as u8))
            .unwrap();
        let raw = w.s[tester].last_raw();
        w.s[iut].deliver(&raw);
    }
    assert_eq!(w.s[iut].received.len() as u64, updates + 1);
    (iut, tester, action_id)
}

/// TP/DEN/EVTR/BV-01: AppDENM_termination of an own event: cancellation DENM with ACTION_ID1.
#[test]
fn tp_den_evtr_bv_01() {
    let mut w = World::new();
    let iut = w.iut();
    let mut r = request(2, 0);
    r.validity_duration = Some(30);
    let action_id = w.s[iut].trigger(&r).unwrap();
    w.at(100);
    w.s[iut].terminate(action_id).unwrap();
    assert_eq!(w.s[iut].last().action_id(), action_id);
    assert_eq!(
        w.s[iut].last().termination(),
        Some(Termination::isCancellation)
    );
}

/// TP/DEN/EVTR/BV-02: AppDENM_termination of a received event: negation DENM with ACTION_ID1.
#[test]
fn tp_den_evtr_bv_02() {
    let mut w = World::new();
    let (iut, _, action_id) = received_event(&mut w, 0);
    assert_ne!(action_id.station_id, IUT_ID);
    w.at(100);
    w.s[iut].terminate(action_id).unwrap();
    assert_eq!(w.s[iut].last().action_id(), action_id);
    assert_eq!(w.s[iut].last().termination(), Some(Termination::isNegation));
}

/// TP/DEN/EVTR/BV-03: the negation DENM carries the latest referenceTime
/// received for the event (REFERENCETIME2).
#[test]
fn tp_den_evtr_bv_03() {
    let mut w = World::new();
    let (iut, _, action_id) = received_event(&mut w, 1);
    let received = &w.s[iut].received;
    let reference2 = received[1].denm.denm.management.reference_time.0;
    assert!(reference2 > received[0].denm.denm.management.reference_time.0);
    w.at(300);
    w.s[iut].terminate(action_id).unwrap();
    assert_eq!(w.s[iut].last().reference_time(), reference2);
    assert_eq!(w.s[iut].last().termination(), Some(Termination::isNegation));
}

/// TP/DEN/EVTR/BV-04: a cancellation DENM has no situation, location nor a la carte container.
#[test]
fn tp_den_evtr_bv_04() {
    let mut w = World::new();
    let iut = w.iut();
    let mut r = request(2, 0);
    r.alacarte = Some(alacarte());
    let action_id = w.s[iut].trigger(&r).unwrap();
    assert!(w.s[iut].last().denm.denm.alacarte.is_some());
    w.at(100);
    w.s[iut].terminate(action_id).unwrap();
    let payload = &w.s[iut].last().denm.denm;
    assert_eq!(
        payload.management.termination,
        Some(Termination::isCancellation)
    );
    assert!(
        payload.situation.is_none() && payload.location.is_none() && payload.alacarte.is_none()
    );
}

/// TP/DEN/EVTR/BV-05: a negation DENM has no situation, location nor a la carte container.
#[test]
fn tp_den_evtr_bv_05() {
    let mut w = World::new();
    let (iut, tester) = (w.iut(), w.tester());
    let denm = w.denm(
        TESTER_ID,
        4,
        Spec {
            alacarte: true,
            ..Default::default()
        },
    );
    w.relay(tester, iut, denm);
    w.at(100);
    w.s[iut]
        .terminate(DenActionId {
            station_id: TESTER_ID,
            sequence_number: 4,
        })
        .unwrap();
    let payload = &w.s[iut].last().denm.denm;
    assert_eq!(
        payload.management.termination,
        Some(Termination::isNegation)
    );
    assert!(
        payload.situation.is_none() && payload.location.is_none() && payload.alacarte.is_none()
    );
}

/// TP/DEN/EVTR/BO-06: no termination DENM for an own-StationID actionID the IUT never sent.
#[test]
fn tp_den_evtr_bo_06() {
    let mut w = World::new();
    let iut = w.iut();
    for _ in 0..3 {
        w.s[iut].trigger(&request(2, 0)).unwrap();
    }
    let unknown = DenActionId {
        station_id: IUT_ID,
        sequence_number: 50,
    };
    assert_eq!(
        w.s[iut].terminate(unknown),
        Err(DenFailure::UnknownActionId)
    );
    assert_eq!(w.s[iut].denms().len(), 3);
}

/// TP/DEN/EVTR/BO-07: no termination DENM for a non-IUT actionID the IUT never received.
#[test]
fn tp_den_evtr_bo_07() {
    let mut w = World::new();
    let (iut, tester) = (w.iut(), w.tester());
    for seq in 0..3 {
        let denm = w.denm(TESTER_ID, seq, Spec::default());
        w.relay(tester, iut, denm);
    }
    assert_eq!(w.s[iut].received.len(), 3);
    let unknown = DenActionId {
        station_id: TESTER_ID,
        sequence_number: 50,
    };
    assert_eq!(
        w.s[iut].terminate(unknown),
        Err(DenFailure::UnknownActionId)
    );
    assert!(w.s[iut].denms().is_empty());
}

/// TP/DEN/EVTR/BV-08: the cancellation DENM has referenceTime = CLT.
#[test]
fn tp_den_evtr_bv_08() {
    let mut w = World::new();
    let iut = w.iut();
    let mut r = request(2, 0);
    r.validity_duration = Some(30);
    let action_id = w.s[iut].trigger(&r).unwrap();
    w.at(321);
    w.s[iut].terminate(action_id).unwrap();
    assert_eq!(
        w.s[iut].last().termination(),
        Some(Termination::isCancellation)
    );
    assert_eq!(w.s[iut].last().reference_time(), w.its());
}

// ── TP/DEN/EVRP: DENM repetition (TS 103 831 clauses 6.1.1.2, 6.1.2.3, 8.1.1.1, 8.2.1.5, 8.2.2) ──

/// TP/DEN/EVRP/TI-01: the DENM is repeated every repetitionInterval (INTERVAL_1).
#[test]
fn tp_den_evrp_ti_01() {
    let mut w = World::new();
    let iut = w.iut();
    let action_id = w.s[iut]
        .trigger(&repeated(100, Some(1000), Some(10)))
        .unwrap();
    w.at(1000);
    assert_eq!(
        w.s[iut].times(),
        (0..=1000).step_by(100).collect::<Vec<_>>()
    );
    assert!(w.s[iut].denms().iter().all(|f| f.action_id() == action_id));
}

/// TP/DEN/EVRP/BV-02: after an update, the repetitions carry the most up-to-date DENM.
#[test]
fn tp_den_evrp_bv_02() {
    let mut w = World::new();
    let iut = w.iut();
    let action_id = w.s[iut]
        .trigger(&repeated(100, Some(2000), Some(10)))
        .unwrap();
    w.at(250);
    w.s[iut].update(action_id, &request(2, 4)).unwrap();
    let update_reference = w.s[iut].last().reference_time();
    w.at(800);
    let station = &w.s[iut];
    for (time, frame) in station.times().into_iter().zip(station.denms()) {
        if time >= 250 {
            assert_eq!(frame.cause(), cause(2, 4), "at {time}");
            assert_eq!(frame.reference_time(), update_reference, "at {time}");
        }
    }
    assert!(station.times().iter().filter(|t| **t > 250).count() > 3);
}

/// TP/DEN/EVRP/BV-03: no repetition after validityDuration (DURATION_2)
/// expires, also when repetitionDuration is longer than validityDuration.
#[test]
fn tp_den_evrp_bv_03() {
    for (duration, last) in [(1500, 1500), (5000, 1900)] {
        let mut w = World::new();
        let iut = w.iut();
        w.s[iut]
            .trigger(&repeated(100, Some(duration), Some(2)))
            .unwrap();
        w.at(4000);
        assert_eq!(
            *w.s[iut].times().last().unwrap(),
            last,
            "repetitionDuration {duration}"
        );
        assert!(w.s[iut].originating_empty());
    }
}

/// TP/DEN/EVRP/BV-04: no repetition after repetitionDuration (DURATION_1) expires.
#[test]
fn tp_den_evrp_bv_04() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut]
        .trigger(&repeated(100, Some(500), Some(10)))
        .unwrap();
    w.at(3000);
    assert_eq!(w.s[iut].times(), (0..=500).step_by(100).collect::<Vec<_>>());
}

/// TP/DEN/EVRP/BV-05: no repetition without repetitionInterval.
#[test]
fn tp_den_evrp_bv_05() {
    let mut w = World::new();
    let iut = w.iut();
    let mut r = request(2, 0);
    r.repetition_duration = Some(1000);
    r.validity_duration = Some(5);
    w.s[iut].trigger(&r).unwrap();
    w.at(6000);
    assert_eq!(w.s[iut].times(), vec![0]);
}

/// TP/DEN/EVRP/BV-06: no repetition without repetitionDuration.
#[test]
fn tp_den_evrp_bv_06() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut].trigger(&repeated(100, None, Some(5))).unwrap();
    w.at(6000);
    assert_eq!(w.s[iut].times(), vec![0]);
}

/// TP/DEN/EVRP/BV-08: after a StationID change, the repetitions carry the new
/// StationID as originatingStationID.
#[test]
fn tp_den_evrp_bv_08() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut]
        .trigger(&repeated(100, Some(1000), Some(10)))
        .unwrap();
    w.at(150);
    w.s[iut].den.update_station_id(NEW_ID);
    w.at(200);
    assert_eq!(*w.s[iut].times().last().unwrap(), 200);
    assert_eq!(w.s[iut].last().action_id().station_id, NEW_ID);
    assert_eq!(w.s[iut].last().denm.header.station_id.0, NEW_ID);
    assert_eq!(w.s[iut].denms()[1].action_id().station_id, IUT_ID);
}

/// TP/DEN/EVRP/BV-09: repetitions keep ACTION_ID_1 (StationID unchanged).
#[test]
fn tp_den_evrp_bv_09() {
    let mut w = World::new();
    let iut = w.iut();
    let action_id = w.s[iut]
        .trigger(&repeated(100, Some(1000), Some(10)))
        .unwrap();
    w.at(1000);
    let ids: HashSet<_> = w.s[iut].denms().iter().map(Frame::action_id).collect();
    assert_eq!(ids, HashSet::from([action_id]));
}

/// TP/DEN/EVRP/BV-10: repetitions keep REFERENCE_TIME_1.
#[test]
fn tp_den_evrp_bv_10() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut]
        .trigger(&repeated(100, Some(1000), Some(10)))
        .unwrap();
    w.at(1000);
    let references: HashSet<_> = w.s[iut].denms().iter().map(Frame::reference_time).collect();
    assert_eq!(references, HashSet::from([w.start]));
    assert_eq!(w.s[iut].denms().len(), 11);
}

/// TP/DEN/EVRP/BV-11: without validityDuration, repetition stops when the
/// default validityDuration (600 s) expires: never with INTERVAL_1 > 600 s,
/// and none at or after 600 s with a shorter interval.
#[test]
fn tp_den_evrp_bv_11() {
    let cases: [(u64, Vec<u64>); 2] = [
        (700_000, vec![0]),
        (100_000, (0..=500_000).step_by(100_000).collect()),
    ];
    for (interval, expected) in cases {
        let mut w = World::new();
        let iut = w.iut();
        w.s[iut]
            .trigger(&repeated(interval, Some(1_000_000), None))
            .unwrap();
        w.at(1_200_000);
        assert_eq!(w.s[iut].times(), expected, "repetitionInterval {interval}");
        assert!(w.s[iut].originating_empty());
    }
}

// ── TP/DEN/PAR: DENM encapsulation (TS 103 831 clause 5.4.2.2) ──

/// TP/DEN/PAR/BV-01: the DENM is carried in a BTP-B packet (destination port 2002).
#[test]
fn tp_den_par_bv_01() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut].trigger(&request(2, 0)).unwrap();
    assert_eq!(w.s[iut].last().common.nh, CommonNH::BtpB);
    assert_eq!(w.s[iut].last().destination_port, 2002);
}

/// TP/DEN/PAR/BV-02: the DENM is carried in a GeoBroadcast packet.
#[test]
fn tp_den_par_bv_02() {
    let mut w = World::new();
    let iut = w.iut();
    w.s[iut].trigger(&request(2, 0)).unwrap();
    assert_eq!(w.s[iut].last().common.ht, HeaderType::GeoBroadcast);
    assert_eq!(
        w.s[iut].last().common.hst,
        HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle)
    );
}

// ── TP/DEN/SSP: sender-side SSP check (TS 103 831 clause 6.2.2.2, Table 10) ──

/// TP/DEN/SSP/BV-01-X (variants 01-24): the IUT does not send a DENM with
/// CAUSE_CODE_X when its AT's DENM SSP has SSP_BIT_X at 0; with the bit set it
/// sends it, signed.
#[test]
fn tp_den_ssp_bv_01_x() {
    let mut pki = Pki::new();
    for (index, code) in SSP_CAUSES.into_iter().enumerate() {
        let bit = cause_code_ssp_bit(code).unwrap();
        for (clear, sent) in [(Some(bit), false), (None, true)] {
            let mut w = World::new();
            let at = pki.at(&denm_ssp(clear));
            let iut = w.station(IUT_ID, 1, false, Some(pki.sign_service(at)), None);
            let _ = w.s[iut].trigger(&request(code, 0));
            let variant = format!("variant {:02} sent {sent}", index + 1);
            assert_eq!(w.s[iut].log.len(), usize::from(sent), "{variant}");
            if sent {
                let frame = w.s[iut].last();
                assert!(frame.secured, "{variant}");
                assert_eq!(frame.psid, Some(PSID_DENM), "{variant}");
            }
        }
    }
}

/// Re-sign the GN payload of an unsecured GBC `frame` with `at`, regardless of its permissions.
fn secured(pki: &Pki, at: &OwnCertificate, frame: &[u8]) -> Vec<u8> {
    let plain = Frame::decode(frame).plain;
    let header = HeaderInfo::new(
        Psid(Integer::from(PSID_DENM as i64)),
        Some(Time64(Uint64(timestamp_its_microseconds()))),
        None,
        Some(ThreeDLocation::new(
            SecLatitude(NinetyDegreeInt(LAT)),
            SecLongitude(OneEightyDegreeInt(LON)),
            Elevation(Uint16(0xF000)),
        )),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let signer =
        SignerIdentifier::certificate(SequenceOfCertificate(vec![at.cert.inner.0.clone()]));
    let secured = SignService::new(pki.backend.clone(), pki.library())
        .build_signed_data(&plain, header, signer, at);
    let mut out = BasicHeader::decode(frame[0..4].try_into().unwrap())
        .set_nh(BasicNH::SecuredPacket)
        .encode()
        .to_vec();
    out.extend_from_slice(&secured);
    out
}

// ── TP/DEN/MSRV: receiving ITS-S (TS 103 831 clauses 6.2.2.2, 8.4.2) ──

/// TP/DEN/MSRV/BV-01: a DENM with an unknown actionID that is not a
/// termination is passed to the application.
#[test]
fn tp_den_msrv_bv_01() {
    let mut w = World::new();
    let (iut, tester) = (w.iut(), w.tester());
    w.s[iut].trigger(&request(2, 0)).unwrap(); // the IUT has sent events
    w.s[tester].trigger(&request(3, 0)).unwrap();
    let raw = w.s[tester].last_raw();
    w.s[iut].deliver(&raw);
    assert_eq!(w.s[iut].received.len(), 1);
    assert_eq!(w.s[iut].received[0].denm, Frame::decode(&raw).denm);
}

/// TP/DEN/MSRV/BV-02: a known actionID with referenceTime greater than the
/// highest received is passed to the application.
#[test]
fn tp_den_msrv_bv_02() {
    let mut w = World::new();
    let (iut, tester) = (w.iut(), w.tester());
    let first = w.denm(
        TESTER_ID,
        1,
        Spec {
            reference: Some(0),
            ..Default::default()
        },
    );
    w.relay(tester, iut, first);
    w.at(100);
    let second = w.denm(
        TESTER_ID,
        1,
        Spec {
            reference: Some(100),
            ..Default::default()
        },
    );
    w.relay(tester, iut, second);
    assert_eq!(w.s[iut].received.len(), 2);
    assert_eq!(
        w.s[iut].received[1].denm.denm.management.reference_time.0,
        w.start + 100
    );
}

/// TP/DEN/MSRV/BO-03: a termination DENM for an unknown actionID with the IUT
/// StationID is discarded.
#[test]
fn tp_den_msrv_bo_03() {
    let mut w = World::new();
    let (iut, tester) = (w.iut(), w.tester());
    for _ in 0..2 {
        w.s[iut].trigger(&request(2, 0)).unwrap();
    }
    let termination = w.denm(
        IUT_ID,
        40,
        Spec {
            termination: Some(Termination::isNegation),
            ..Default::default()
        },
    );
    w.relay(tester, iut, termination);
    assert!(w.s[iut].received.is_empty());
    assert!(!w.s[iut].knows_received(DenActionId {
        station_id: IUT_ID,
        sequence_number: 40
    }));
}

/// TP/DEN/MSRV/BO-04: a termination DENM for an unknown actionID with a
/// non-IUT StationID is discarded.
#[test]
fn tp_den_msrv_bo_04() {
    let mut w = World::new();
    let (iut, tester) = (w.iut(), w.tester());
    for seq in 0..2 {
        let denm = w.denm(TESTER_ID, seq, Spec::default());
        w.relay(tester, iut, denm);
    }
    let termination = w.denm(
        TESTER_ID,
        40,
        Spec {
            termination: Some(Termination::isCancellation),
            ..Default::default()
        },
    );
    w.relay(tester, iut, termination);
    assert_eq!(w.s[iut].received.len(), 2);
    assert!(!w.s[iut].knows_received(DenActionId {
        station_id: TESTER_ID,
        sequence_number: 40
    }));
}

/// Two DENMs of ACTION_ID1 = (TESTER_ID, 1) with (referenceTime, detectionTime)
/// offsets; returns how many reached the application.
fn reception_pair(first: (i64, i64), second: (i64, i64)) -> usize {
    let mut w = World::new();
    let (iut, tester) = (w.iut(), w.tester());
    w.at(600);
    for (reference, detection) in [first, second] {
        let denm = w.denm(
            TESTER_ID,
            1,
            Spec {
                reference: Some(reference),
                detection: Some(detection),
                ..Default::default()
            },
        );
        w.relay(tester, iut, denm);
    }
    w.s[iut].received.len()
}

/// TP/DEN/MSRV/BO-05: a DENM with referenceTime less than the highest received is discarded.
#[test]
fn tp_den_msrv_bo_05() {
    assert_eq!(reception_pair((500, 500), (400, 400)), 1);
}

/// TP/DEN/MSRV/BO-06: same referenceTime and detectionTime less than the
/// highest received: discarded.
#[test]
fn tp_den_msrv_bo_06() {
    assert_eq!(reception_pair((500, 300), (500, 200)), 1);
}

/// TP/DEN/MSRV/BV-07: same referenceTime and detectionTime greater than the
/// highest received: passed to the application.
#[test]
fn tp_den_msrv_bv_07() {
    assert_eq!(reception_pair((500, 300), (500, 400)), 2);
}

fn secured_pair(w: &mut World, pki: &Pki) -> (usize, usize) {
    let iut = w.station(
        IUT_ID,
        1,
        false,
        None,
        Some((pki.backend.clone(), pki.library())),
    );
    (iut, w.tester())
}

/// TP/DEN/MSRV/BO-08: a secured DENM whose signing AT has no DENM ITS-AID in
/// its appPermissions is discarded; the same DENM signed with an AT
/// permitting it is accepted.
#[test]
fn tp_den_msrv_bo_08() {
    let mut pki = Pki::new();
    for (permissions, accepted) in [(vec![(36, None)], false), (denm_ssp(None), true)] {
        let mut w = World::new();
        let (iut, tester) = secured_pair(&mut w, &pki);
        let denm = w.denm(TESTER_ID, 1, Spec::default());
        let frame = w.s[tester].send(denm);
        let at = pki.at(&permissions);
        w.s[iut].deliver(&secured(&pki, &at, &frame));
        assert_eq!(w.s[iut].received.len(), usize::from(accepted));
    }
}

/// TP/DEN/MSRV/BO-08-X (variants 01-24): a secured DENM for a new event with
/// CAUSE_CODE_X, signed with an AT whose DENM SSP lacks SSP_BIT_X, is
/// discarded; with the bit it is accepted.
#[test]
fn tp_den_msrv_bo_08_x() {
    let mut pki = Pki::new();
    for (index, code) in SSP_CAUSES.into_iter().enumerate() {
        let bit = cause_code_ssp_bit(code).unwrap();
        for (clear, accepted) in [(Some(bit), false), (None, true)] {
            let mut w = World::new();
            let (iut, tester) = secured_pair(&mut w, &pki);
            let denm = w.denm(
                TESTER_ID,
                1,
                Spec {
                    cause: code,
                    ..Default::default()
                },
            );
            let frame = w.s[tester].send(denm);
            let at = pki.at(&denm_ssp(clear));
            w.s[iut].deliver(&secured(&pki, &at, &frame));
            assert_eq!(
                w.s[iut].received.len(),
                usize::from(accepted),
                "variant {:02} accepted {accepted}",
                index + 1
            );
        }
    }
}

/// TP/DEN/MSRV/BO-09-X (variants 01-24): for an existing event with
/// CAUSE_CODE_X received under an SSP with SSP_BIT_X, a newer DENM signed with
/// an AT lacking SSP_BIT_X is discarded; signed with the bit, it is accepted.
#[test]
fn tp_den_msrv_bo_09_x() {
    let mut pki = Pki::new();
    for (index, code) in SSP_CAUSES.into_iter().enumerate() {
        let bit = cause_code_ssp_bit(code).unwrap();
        for (clear, accepted) in [(Some(bit), false), (None, true)] {
            let mut w = World::new();
            let (iut, tester) = secured_pair(&mut w, &pki);
            let with_bit = pki.at(&denm_ssp(None));
            for (reference, at) in [(0, with_bit), (1, pki.at(&denm_ssp(clear)))] {
                let denm = w.denm(
                    TESTER_ID,
                    1,
                    Spec {
                        reference: Some(reference),
                        cause: code,
                        ..Default::default()
                    },
                );
                let frame = w.s[tester].send(denm);
                w.s[iut].deliver(&secured(&pki, &at, &frame));
                if reference == 0 {
                    assert_eq!(w.s[iut].received.len(), 1);
                }
            }
            assert_eq!(
                w.s[iut].received.len(),
                1 + usize::from(accepted),
                "variant {:02} accepted {accepted}",
                index + 1
            );
        }
    }
}

// ── TP/DEN/KAFW: Keep-Alive Forwarding (TS 103 831 clauses 8.3.2, 8.3.3) ──

/// T_Forwarding of the first KAF reception of a station seeded with KAF_SEED.
fn kaf_timeout(transmission_interval: u64, validity_s: u64) -> u64 {
    let random = StdRng::seed_from_u64(KAF_SEED).gen_range(0..=KAF_MAX_RANDOM_DELAY_MS);
    (2 * transmission_interval + random).min(validity_s * 1000)
}

/// IUT with KAF, having received at the current time the test system DENM
/// ACTION_ID1 = (TESTER_ID, 1).
fn kaf_received(w: &mut World, spec: Spec) -> (usize, usize, Denm) {
    let (iut, tester) = (w.kaf_iut(), w.tester());
    let denm = w.denm(TESTER_ID, 1, spec);
    w.relay(tester, iut, denm.clone());
    assert_eq!(w.s[iut].received.len(), 1);
    (iut, tester, denm)
}

fn kaf_spec(validity: u32) -> Spec {
    Spec {
        reference: Some(0),
        transmission_interval: Some(200),
        validity,
        ..Default::default()
    }
}

/// TP/DEN/KAFW/BV-01: with no further DENM of ACTION_ID1 during T_Forwarding,
/// the IUT reconstructs and sends it when T_Forwarding expires; a repetition
/// received in the meantime restarts the timer.
#[test]
fn tp_den_kafw_bv_01() {
    let mut w = World::new();
    let (iut, tester, sent) = kaf_received(&mut w, kaf_spec(10));
    let timeout = kaf_timeout(200, 10);
    w.at(timeout - 1);
    assert!(w.s[iut].denms().is_empty());
    w.at(timeout);
    assert_eq!(w.s[iut].times(), vec![timeout]);
    assert_eq!(
        w.s[iut].last().action_id(),
        DenActionId {
            station_id: TESTER_ID,
            sequence_number: 1
        }
    );
    // Counter-check: the same DENM received again at timeout / 2 restarts T_Forwarding.
    let other = w.station(0x4004, 3, true, None, None);
    w.relay(tester, other, sent.clone());
    let restart = w.now() + timeout / 2;
    w.at(restart);
    w.relay(tester, other, sent);
    w.at(restart + timeout - 1);
    assert!(w.s[other].denms().is_empty());
    w.at(restart + timeout);
    assert_eq!(w.s[other].denms().len(), 1);
}

/// TP/DEN/KAFW/BV-02: a DENM of ACTION_ID1 with an older referenceTime does
/// not restart T_Forwarding: the IUT forwards when the timer started at
/// REFERENCETIME_1 expires.
#[test]
fn tp_den_kafw_bv_02() {
    let mut w = World::new();
    let (iut, tester, _) = kaf_received(&mut w, kaf_spec(10));
    let timeout = kaf_timeout(200, 10);
    w.at(100);
    let older = w.denm(
        TESTER_ID,
        1,
        Spec {
            reference: Some(-50),
            ..kaf_spec(10)
        },
    );
    w.relay(tester, iut, older);
    w.at(timeout);
    assert_eq!(w.s[iut].times(), vec![timeout]);
    assert_eq!(w.s[iut].last().reference_time(), w.start);
}

/// TP/DEN/KAFW/TI-03: the forwarding delay is min(2 x transmissionInterval +
/// rnd(0, 150 ms), validityDuration), from the reception and again after
/// each forwarding.
#[test]
fn tp_den_kafw_ti_03() {
    for interval in [100u16, 500, 1000] {
        let mut w = World::new();
        let (iut, _, _) = kaf_received(
            &mut w,
            Spec {
                transmission_interval: Some(interval),
                ..kaf_spec(10)
            },
        );
        let timeout = kaf_timeout(u64::from(interval), 10);
        w.at(timeout - 1);
        assert!(w.s[iut].denms().is_empty(), "interval {interval}");
        w.at(2 * timeout);
        assert_eq!(w.s[iut].times(), vec![timeout, 2 * timeout]);
        assert!(timeout >= 2 * u64::from(interval));
        assert!(timeout <= 2 * u64::from(interval) + 150);
    }
}

/// TP/DEN/KAFW/BV-04: the forwarded DENM has the IUT StationID in the ITS PDU header.
#[test]
fn tp_den_kafw_bv_04() {
    let mut w = World::new();
    let (iut, _, _) = kaf_received(&mut w, kaf_spec(10));
    w.at(kaf_timeout(200, 10));
    assert_eq!(w.s[iut].last().denm.header.station_id.0, IUT_ID);
}

/// TP/DEN/KAFW/BV-05: the forwarded DENM keeps ACTION_ID1.
#[test]
fn tp_den_kafw_bv_05() {
    let mut w = World::new();
    let (iut, _, sent) = kaf_received(&mut w, kaf_spec(10));
    w.at(kaf_timeout(200, 10));
    assert_eq!(
        w.s[iut].last().management().action_id,
        sent.denm.management.action_id
    );
}

/// TP/DEN/KAFW/BV-06: the forwarded DENM keeps REFERENCETIME_1.
#[test]
fn tp_den_kafw_bv_06() {
    let mut w = World::new();
    let (iut, _, sent) = kaf_received(&mut w, kaf_spec(10));
    w.at(kaf_timeout(200, 10));
    assert_eq!(
        w.s[iut].last().management().reference_time,
        sent.denm.management.reference_time
    );
}

/// TP/DEN/KAFW/BV-07: a received negation DENM is forwarded with termination isNegation.
#[test]
fn tp_den_kafw_bv_07() {
    let mut w = World::new();
    let (iut, tester, _) = kaf_received(&mut w, kaf_spec(10));
    w.at(100);
    let negation = w.denm(
        TESTER_ID,
        1,
        Spec {
            termination: Some(Termination::isNegation),
            ..kaf_spec(10)
        },
    );
    w.relay(tester, iut, negation);
    assert_eq!(w.s[iut].received.len(), 2);
    w.at(100 + kaf_timeout(200, 10) + 500);
    assert!(!w.s[iut].denms().is_empty());
    assert_eq!(w.s[iut].last().termination(), Some(Termination::isNegation));
    assert!(w.s[iut].times().iter().all(|t| *t > 100));
}

/// TP/DEN/KAFW/BV-08: the forwarded DENM keeps the management, situation,
/// location and a la carte containers.
#[test]
fn tp_den_kafw_bv_08() {
    let mut w = World::new();
    let (iut, _, sent) = kaf_received(
        &mut w,
        Spec {
            alacarte: true,
            ..kaf_spec(10)
        },
    );
    w.at(kaf_timeout(200, 10));
    let forwarded = w.s[iut].last().denm.denm;
    let received = &w.s[iut].received[0].denm.denm;
    assert_eq!(forwarded.management, received.management);
    assert_eq!(forwarded.situation, received.situation);
    assert_eq!(forwarded.location, received.location);
    assert_eq!(forwarded.alacarte, received.alacarte);
    assert_eq!(forwarded.alacarte, sent.denm.alacarte);
}

/// TP/DEN/KAFW/BV-09: the IUT stops forwarding when validityDuration (DURATION_1) expires.
#[test]
fn tp_den_kafw_bv_09() {
    let mut w = World::new();
    let (iut, _, _) = kaf_received(&mut w, kaf_spec(2));
    w.at(5000);
    assert!(w.s[iut].times().len() >= 3);
    assert!(*w.s[iut].times().last().unwrap() < 2000);
    assert!(w.s[iut].forwarding_empty());
}

/// TP/DEN/KAFW/BV-10: the IUT stops forwarding once its position is outside
/// the relevance (destination) area.
#[test]
fn tp_den_kafw_bv_10() {
    let mut w = World::new();
    let (iut, _, _) = kaf_received(&mut w, kaf_spec(10));
    w.at(kaf_timeout(200, 10));
    assert_eq!(w.s[iut].denms().len(), 1);
    w.s[iut].den.set_ego_position(LAT + 1_000_000, LON); // 0.1 degree (~11 km) north
    w.at(10_000);
    assert_eq!(w.s[iut].denms().len(), 1);
}

/// TP/DEN/KAFW/BV-11: a DENM without transmissionInterval is not forwarded.
#[test]
fn tp_den_kafw_bv_11() {
    let mut w = World::new();
    let (iut, _, _) = kaf_received(
        &mut w,
        Spec {
            transmission_interval: None,
            ..kaf_spec(10)
        },
    );
    w.at(12_000);
    assert!(w.s[iut].denms().is_empty());
    assert!(w.s[iut].forwarding_empty());
}

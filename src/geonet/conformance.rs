// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! GeoNetworking conformance tests: one test per Test Purpose of ETSI TS
//! 102 871-2 V2.1.1, against ETSI TS 103 836-4-1 V2.2.1 (2026-04) and TS
//! 103 836-4-2 / -4-3 V2.1.1.
//!
//! Each test is named after its TP and quotes the TP identifier, so that a
//! search for the identifier finds it. The IUT is a GeoNetworking router on
//! an injected clock; the test system sends frames from the ETSI test nodes
//! (clause 4 of TS 102 871-2) and checks the frames the IUT passes to its
//! link layer, with their destination link-layer address, and the
//! indications it passes up.
//!
//! Geometry (north axis, metres from the IUT), after CF01-CF04: ItsNodeA
//! 1500 m (out of range), ItsNodeB 400 m and ItsNodeD 200 m (in the
//! direction of A, B closer to A), ItsNodeC 400 m south. AREA1: circle of
//! 600 m around the IUT; AREA2: circle of 300 m around B (not the IUT).
//!
//! The TPs of the Advanced forwarding algorithm (GBC/AREA/ADV) are not
//! applicable (removed in Release 2) and TP/GEONW/FDV/SHB/BV-03 (LTE-V2X time
//! synchronisation) is not implemented.
//!
//! Mirrors `tests/flexstack/geonet/test_gn_conformance.py`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::basic_header::{BasicHeader, LT};
use super::common_header::CommonHeader;
use super::dcc_net::DccNet;
use super::gbc_extended_header::GBCExtendedHeader;
use super::gn_address::{GNAddress, M, MID, ST};
use super::guc_extended_header::GUCExtendedHeader;
use super::ls_extended_header::{LSReplyExtendedHeader, LSRequestExtendedHeader};
use super::mib::{
    AreaForwardingAlgorithm, GnIfType, LocalGnAddrConfMethod, Mib, NonAreaForwardingAlgorithm,
};
use super::position_vector::{LongPositionVector, ShortPositionVector, Tst};
use super::router::Router;
use super::service_access_point::{
    Area, CommonNH, CommunicationProfile, GNDataIndication, GNDataRequest, GeoAnycastHST,
    GeoBroadcastHST, HeaderSubType, HeaderType, LocationServiceHST, PacketTransportType,
    TopoBroadcastHST, TrafficClass, UnspecifiedHST,
};
use super::tsb_extended_header::TSBExtendedHeader;
use crate::security::sn_sap::SecurityProfile;

const EGO_LAT: i64 = 421_255_850;
const EGO_LON: u32 = 27_601_710;
const IUT: u8 = 0x01;
const A: u8 = 0x0A;
const B: u8 = 0x0B;
const C: u8 = 0x0C;
const D: u8 = 0x0D;
const FAR: u8 = 0x0F;
const DEFAULT_LT_MS: u32 = 60_000;

fn north(metres: f64) -> u32 {
    let per_degree = 6_371_000.0 * std::f64::consts::PI / 180.0;
    (EGO_LAT + (metres / per_degree * 1e7).round() as i64) as u32
}

fn pos(n: u8) -> u32 {
    match n {
        A => north(1500.0),
        B => north(400.0),
        C => north(-400.0),
        D => north(200.0),
        FAR => north(-1100.0),
        _ => EGO_LAT as u32,
    }
}

fn circle(latitude: u32, radius: u16) -> Area {
    Area {
        latitude,
        longitude: EGO_LON,
        a: radius,
        b: radius,
        angle: 0,
    }
}

fn area1() -> Area {
    circle(EGO_LAT as u32, 600)
}

fn area2() -> Area {
    circle(pos(B), 300)
}

/// "Addressed to ItsNodeA": a small area around A (IUT outside).
fn area_a() -> Area {
    circle(pos(A), 200)
}

/// 12.6 km2 > itsGnMaxGeoAreaSize.
fn big_area() -> Area {
    circle(pos(B), 2000)
}

fn addr(n: u8) -> GNAddress {
    GNAddress::new(
        M::GnUnicast,
        ST::PassengerCar,
        MID::new([0x02, 0, 0, 0, 0, n]),
    )
}

fn mac(n: u8) -> [u8; 6] {
    addr(n).mid.as_bytes()
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn tst(offset_ms: i64) -> Tst {
    Tst::set_in_normal_timestamp_milliseconds((unix_ms() as i64 + offset_ms) as u64)
}

fn lpv_at(n: u8, latitude: u32, pai: bool, tst_offset_ms: i64) -> LongPositionVector {
    LongPositionVector {
        gn_addr: addr(n),
        tst: tst(tst_offset_ms),
        latitude,
        longitude: EGO_LON,
        pai,
        s: 0,
        h: 0,
    }
}

fn lpv(n: u8) -> LongPositionVector {
    lpv_at(n, pos(n), true, 0)
}

fn spv(n: u8) -> ShortPositionVector {
    ShortPositionVector {
        gn_address: addr(n),
        tst: tst(0),
        latitude: pos(n),
        longitude: EGO_LON,
    }
}

fn lt_ms(ms: u32) -> u32 {
    LT::start_in_milliseconds(ms).get_value_in_milliseconds()
}

/// TO_CBF_WO_ACC of TS 103 836-4-1 V2.2.1 clauses E.3.2.2-E.3.2.3 (and
/// F.3.2.2-F.3.2.3): segment SEGN = max(1, ceil(D / DIST_MAX)).
fn cbf_timeout_ms(distance_m: f64, mib: &Mib) -> f64 {
    let dist_max = f64::from(mib.itsGnDefaultMaxCommunicationRange);
    let (min, max) = (
        f64::from(mib.itsGnCbfMinTime),
        f64::from(mib.itsGnCbfMaxTime),
    );
    let segn = (distance_m / dist_max).ceil().max(1.0);
    max * segn + (min - max) / dist_max * (distance_m - dist_max * (segn - 1.0))
}

fn close_to(value: u64, expected: f64) -> bool {
    (value as f64 - expected).abs() <= 1.0
}

// ── Test system: frames from the test nodes ────────────────────────────────

struct Pkt {
    rhl: u8,
    mhl: u8,
    scf: bool,
    lifetime_ms: Option<u32>,
    version: u8,
    payload: Vec<u8>,
}

impl Default for Pkt {
    fn default() -> Self {
        Pkt {
            rhl: 5,
            mhl: 10,
            scf: false,
            lifetime_ms: None,
            version: 1,
            payload: b"payload".to_vec(),
        }
    }
}

fn packet(ht: HeaderType, hst: HeaderSubType, nh: CommonNH, ext: &[u8], p: &Pkt) -> Vec<u8> {
    let mut basic = BasicHeader::initialize_with_mib(&Mib::new()).set_rhl(p.rhl);
    basic.version = p.version;
    if let Some(ms) = p.lifetime_ms {
        basic = basic.set_lt(LT::start_in_milliseconds(ms));
    }
    let common = CommonHeader {
        nh,
        reserved: 0,
        ht,
        hst,
        tc: TrafficClass {
            scf: p.scf,
            channel_offload: false,
            tc_id: 0,
        },
        flags: 0,
        pl: p.payload.len() as u16,
        mhl: p.mhl,
        reserved2: 0,
    };
    let mut out = basic.encode().to_vec();
    out.extend_from_slice(&common.encode());
    out.extend_from_slice(ext);
    out.extend_from_slice(&p.payload);
    out
}

fn with_rhl(packet: &[u8], rhl: u8) -> Vec<u8> {
    let mut p = packet.to_vec();
    p[3] = rhl;
    p
}

fn beacon(n: u8, pai: bool) -> Vec<u8> {
    let p = Pkt {
        rhl: 1,
        mhl: 1,
        payload: vec![],
        ..Default::default()
    };
    packet(
        HeaderType::Beacon,
        HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
        CommonNH::Any,
        &lpv_at(n, pos(n), pai, 0).encode(),
        &p,
    )
}

fn shb_full(so: &LongPositionVector, payload: &[u8], mco: [u8; 4], version: u8) -> Vec<u8> {
    let mut ext = so.encode().to_vec();
    ext.extend_from_slice(&mco);
    let p = Pkt {
        rhl: 1,
        mhl: 1,
        version,
        payload: payload.to_vec(),
        ..Default::default()
    };
    packet(
        HeaderType::Tsb,
        HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
        CommonNH::BtpB,
        &ext,
        &p,
    )
}

fn shb(so: &LongPositionVector) -> Vec<u8> {
    shb_full(so, b"payload", [0; 4], 1)
}

fn tsb(so: &LongPositionVector, sn: u16, p: &Pkt) -> Vec<u8> {
    let ext = TSBExtendedHeader {
        sn,
        reserved: 0,
        so_pv: *so,
    };
    packet(
        HeaderType::Tsb,
        HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop),
        CommonNH::BtpB,
        &ext.encode(),
        p,
    )
}

fn guc(so: &LongPositionVector, sn: u16, de: ShortPositionVector, p: &Pkt) -> Vec<u8> {
    let ext = GUCExtendedHeader {
        sn,
        reserved: 0,
        so_pv: *so,
        de_pv: de,
    };
    packet(
        HeaderType::GeoUnicast,
        HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
        CommonNH::BtpB,
        &ext.encode(),
        p,
    )
}

fn gbc(so: &LongPositionVector, sn: u16, area: Area, anycast: bool, p: &Pkt) -> Vec<u8> {
    let ext = GBCExtendedHeader {
        sn,
        reserved: 0,
        so_pv: *so,
        latitude: area.latitude,
        longitude: area.longitude,
        a: area.a,
        b: area.b,
        angle: area.angle,
        reserved2: 0,
    };
    let (ht, hst) = if anycast {
        (
            HeaderType::GeoAnycast,
            HeaderSubType::GeoAnycast(GeoAnycastHST::GeoAnycastCircle),
        )
    } else {
        (
            HeaderType::GeoBroadcast,
            HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle),
        )
    };
    packet(ht, hst, CommonNH::BtpB, &ext.encode(), p)
}

fn ls_request(so: &LongPositionVector, sn: u16, sought: GNAddress, rhl: u8) -> Vec<u8> {
    let ext = LSRequestExtendedHeader {
        sn,
        reserved: 0,
        so_pv: *so,
        request_gn_addr: sought,
    };
    let p = Pkt {
        rhl,
        payload: vec![],
        ..Default::default()
    };
    packet(
        HeaderType::Ls,
        HeaderSubType::LocationService(LocationServiceHST::LsRequest),
        CommonNH::Any,
        &ext.encode(),
        &p,
    )
}

fn ls_reply(so: &LongPositionVector, sn: u16, de: ShortPositionVector, rhl: u8) -> Vec<u8> {
    let ext = LSReplyExtendedHeader {
        sn,
        reserved: 0,
        so_pv: *so,
        de_pv: de,
    };
    let p = Pkt {
        rhl,
        payload: vec![],
        ..Default::default()
    };
    packet(
        HeaderType::Ls,
        HeaderSubType::LocationService(LocationServiceHST::LsReply),
        CommonNH::Any,
        &ext.encode(),
        &p,
    )
}

fn scf() -> Pkt {
    Pkt {
        scf: true,
        ..Default::default()
    }
}

fn rhl_mhl(rhl: u8, mhl: u8, scf: bool) -> Pkt {
    Pkt {
        rhl,
        mhl,
        scf,
        ..Default::default()
    }
}

// ── Frames the IUT sent ─────────────────────────────────────────────────────

enum Ext {
    None,
    Tsb(TSBExtendedHeader),
    Guc(GUCExtendedHeader),
    Gbc(GBCExtendedHeader),
    LsRequest(LSRequestExtendedHeader),
    LsReply(LSReplyExtendedHeader),
}

struct Frame {
    destination: Option<[u8; 6]>,
    at: u64,
    basic: BasicHeader,
    common: CommonHeader,
    so_pv: LongPositionVector,
    mco: Option<[u8; 4]>,
    ext: Ext,
    payload: Vec<u8>,
}

impl Frame {
    fn decode(raw: &[u8], destination: Option<[u8; 6]>, at: u64) -> Frame {
        let basic = BasicHeader::decode(raw[0..4].try_into().unwrap());
        let common = CommonHeader::decode(raw[4..12].try_into().unwrap());
        let body = &raw[12..];
        let lpv = |b: &[u8]| LongPositionVector::decode(b[0..24].try_into().unwrap());
        let (so_pv, mco, ext, size) = match (&common.ht, &common.hst) {
            (HeaderType::Beacon, _) => (lpv(body), None, Ext::None, 24),
            (HeaderType::Tsb, HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop)) => (
                lpv(body),
                Some(body[24..28].try_into().unwrap()),
                Ext::None,
                28,
            ),
            (HeaderType::Tsb, _) => {
                let e = TSBExtendedHeader::decode(&body[0..28]);
                (e.so_pv, None, Ext::Tsb(e), 28)
            }
            (HeaderType::GeoUnicast, _) => {
                let e = GUCExtendedHeader::decode(&body[0..48]);
                (e.so_pv, None, Ext::Guc(e), 48)
            }
            (HeaderType::GeoBroadcast | HeaderType::GeoAnycast, _) => {
                let e = GBCExtendedHeader::decode(body[0..44].try_into().unwrap());
                (e.so_pv, None, Ext::Gbc(e), 44)
            }
            (_, HeaderSubType::LocationService(LocationServiceHST::LsRequest)) => {
                let e = LSRequestExtendedHeader::decode(&body[0..36]);
                (e.so_pv, None, Ext::LsRequest(e), 36)
            }
            _ => {
                let e = LSReplyExtendedHeader::decode(&body[0..48]);
                (e.so_pv, None, Ext::LsReply(e), 48)
            }
        };
        Frame {
            destination,
            at,
            basic,
            common,
            so_pv,
            mco,
            ext,
            payload: body[size..].to_vec(),
        }
    }

    fn guc(&self) -> &GUCExtendedHeader {
        match &self.ext {
            Ext::Guc(e) => e,
            _ => panic!("not a GUC"),
        }
    }

    fn gbc(&self) -> &GBCExtendedHeader {
        match &self.ext {
            Ext::Gbc(e) => e,
            _ => panic!("not a GBC/GAC"),
        }
    }

    fn sn(&self) -> u16 {
        match &self.ext {
            Ext::Tsb(e) => e.sn,
            Ext::Guc(e) => e.sn,
            Ext::Gbc(e) => e.sn,
            Ext::LsRequest(e) => e.sn,
            Ext::LsReply(e) => e.sn,
            Ext::None => panic!("no SN"),
        }
    }

    fn is_ls_request(&self) -> bool {
        matches!(self.ext, Ext::LsRequest(_))
    }
}

/// The IUT: a GN router on an injected clock, its link layer and upper
/// layer captured.
struct Iut {
    router: Router,
    clock: Arc<AtomicU64>,
    ll_rx: Receiver<Vec<u8>>,
    unicast_rx: Receiver<(Vec<u8>, [u8; 6])>,
    btp_rx: Receiver<GNDataIndication>,
    frames: Vec<Frame>,
    indications: Vec<GNDataIndication>,
}

impl Iut {
    fn with(configure: impl FnOnce(&mut Mib), beacons: bool) -> Iut {
        let mut mib = Mib::new();
        mib.itsGnLocalGnAddr = addr(IUT);
        if !beacons {
            mib.itsGnBeaconServiceRetransmitTimer = 0;
        }
        configure(&mut mib);
        let (ll_tx, ll_rx) = mpsc::channel();
        let (btp_tx, btp_rx) = mpsc::channel();
        let (unicast_tx, unicast_rx) = mpsc::channel();
        let mut router = Router::new(mib, ll_tx, btp_tx, None, None, None);
        let clock = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&clock);
        router.set_clock(Box::new(move || c.load(Ordering::SeqCst)));
        router.set_unicast_sender(unicast_tx);
        router.ego_position_vector.latitude = EGO_LAT as u32;
        router.ego_position_vector.longitude = EGO_LON;
        router.ego_position_vector.pai = true;
        router.ego_position_vector.tst = tst(0);
        Iut {
            router,
            clock,
            ll_rx,
            unicast_rx,
            btp_rx,
            frames: vec![],
            indications: vec![],
        }
    }

    fn new() -> Iut {
        Self::with(|_| {}, false)
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn collect(&mut self) {
        let now = self.now();
        while let Ok(raw) = self.ll_rx.try_recv() {
            self.frames.push(Frame::decode(&raw, None, now));
        }
        while let Ok((raw, mac)) = self.unicast_rx.try_recv() {
            self.frames.push(Frame::decode(&raw, Some(mac), now));
        }
        self.indications.extend(self.btp_rx.try_iter());
    }

    // lower tester
    fn receive(&mut self, packet: &[u8], sender: u8) {
        self.router.process_incoming(packet, Some(mac(sender)));
        self.collect();
    }

    fn beacons_from(&mut self, nodes: &[u8]) {
        for n in nodes {
            self.receive(&beacon(*n, true), *n);
        }
    }

    // time
    fn at(&mut self, ms: u64) {
        while let Some(deadline) = self.router.next_deadline().filter(|d| *d <= ms) {
            self.clock.store(deadline.max(self.now()), Ordering::SeqCst);
            let now = self.now();
            self.router.tick(now);
            self.collect();
        }
        self.clock.store(ms, Ordering::SeqCst);
    }

    fn next_deadline(&self) -> u64 {
        self.router.next_deadline().expect("a pending timer")
    }

    // upper tester
    #[allow(clippy::too_many_arguments)]
    fn request(
        &mut self,
        ht: HeaderType,
        hst: HeaderSubType,
        payload: &[u8],
        scf: bool,
        area: Area,
        destination: Option<GNAddress>,
        lifetime_s: Option<f64>,
    ) {
        self.router.gn_data_request(GNDataRequest {
            upper_protocol_entity: CommonNH::BtpB,
            packet_transport_type: PacketTransportType {
                header_type: ht,
                header_sub_type: hst,
            },
            communication_profile: CommunicationProfile::Unspecified,
            traffic_class: TrafficClass {
                scf,
                channel_offload: false,
                tc_id: 0,
            },
            security_profile: SecurityProfile::NoSecurity,
            its_aid: 0,
            security_permissions: vec![],
            max_hop_limit: 0,
            max_packet_lifetime: lifetime_s,
            destination,
            length: payload.len() as u16,
            data: payload.to_vec(),
            area,
        });
        self.collect();
    }

    fn request_shb(&mut self, payload: &[u8]) {
        self.request(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            payload,
            false,
            area1(),
            None,
            None,
        );
    }

    fn request_tsb(&mut self) {
        self.request(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop),
            b"tsb",
            false,
            area1(),
            None,
            None,
        );
    }

    fn request_gbc(&mut self, area: Area, scf: bool, anycast: bool, lifetime_s: Option<f64>) {
        let (ht, hst) = if anycast {
            (
                HeaderType::GeoAnycast,
                HeaderSubType::GeoAnycast(GeoAnycastHST::GeoAnycastCircle),
            )
        } else {
            (
                HeaderType::GeoBroadcast,
                HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle),
            )
        };
        self.request(ht, hst, b"gbc", scf, area, None, lifetime_s);
    }

    fn request_guc(&mut self, de: u8, scf: bool, payload: &[u8], lifetime_s: Option<f64>) {
        self.request(
            HeaderType::GeoUnicast,
            HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
            payload,
            scf,
            area1(),
            Some(addr(de)),
            lifetime_s,
        );
    }

    // observations
    fn sent(&self, ht: HeaderType) -> Vec<&Frame> {
        self.frames.iter().filter(|f| f.common.ht == ht).collect()
    }

    fn ls_requests(&self) -> Vec<&Frame> {
        self.frames.iter().filter(|f| f.is_ls_request()).collect()
    }
}

fn beacon_iut() -> Iut {
    Iut::with(|_| {}, true)
}

// ── TP/GEONW/FDV: header formatting and data validity ───────────────────────

/// TP/GEONW/FDV/BAH/BV-01: a GBC carries version = itsGnProtocolVersion and
/// RHL = itsGnDefaultHopLimit in its Basic Header.
#[test]
fn tp_geonw_fdv_bah_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_gbc(area1(), false, false, None);
    let f = iut.sent(HeaderType::GeoBroadcast)[0];
    assert_eq!(f.basic.version, iut.router.mib.itsGnProtocolVersion);
    assert_eq!(f.basic.rhl, iut.router.mib.itsGnDefaultHopLimit);
}

/// TP/GEONW/FDV/BAH/BI-02: an SHB with a version other than
/// itsGnProtocolVersion is discarded (the same SHB with the right version is
/// passed up).
#[test]
fn tp_geonw_fdv_bah_bi_02() {
    let mut iut = Iut::new();
    iut.receive(&shb_full(&lpv(B), b"v1", [0; 4], 1), B);
    assert_eq!(iut.indications.len(), 1);
    iut.receive(&shb_full(&lpv(B), b"v2", [0; 4], 2), B);
    assert_eq!(iut.indications.len(), 1);
}

/// TP/GEONW/FDV/COH/BV-01: a Beacon has HT = 1 (BEACON), HST = 0 and PL = 0.
#[test]
fn tp_geonw_fdv_coh_bv_01() {
    let mut iut = beacon_iut();
    let deadline = iut.next_deadline();
    iut.at(deadline);
    let f = iut.sent(HeaderType::Beacon)[0];
    assert_eq!(f.common.hst.encode(), 0);
    assert_eq!(f.common.pl, 0);
}

/// TP/GEONW/FDV/COH/BV-02: an SHB has HT = 5 (TSB), HST = 0 (SINGLE_HOP),
/// MHL = 1 and PL = length of the payload it carries.
#[test]
fn tp_geonw_fdv_coh_bv_02() {
    let mut iut = Iut::new();
    iut.request_shb(&[b'x'; 37]);
    let f = iut.sent(HeaderType::Tsb)[0];
    assert_eq!(
        f.common.hst,
        HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop)
    );
    assert_eq!((f.common.mhl, f.common.pl), (1, 37));
    assert_eq!(f.payload, vec![b'x'; 37]);
}

/// TP/GEONW/FDV/COH/BV-03: a GBC has Flags = itsGnIsMobile and MHL =
/// itsGnDefaultHopLimit.
#[test]
fn tp_geonw_fdv_coh_bv_03() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_gbc(area1(), false, false, None);
    let f = iut.sent(HeaderType::GeoBroadcast)[0];
    assert_eq!(f.common.flags >> 7, iut.router.mib.itsGnIsMobile.encode());
    assert_eq!(f.common.mhl, iut.router.mib.itsGnDefaultHopLimit);
}

/// TP/GEONW/FDV/COH/BO-04: a TSB with RHL > MHL is discarded (not forwarded
/// nor passed up).
#[test]
fn tp_geonw_fdv_coh_bo_04() {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.receive(&tsb(&lpv(C), 1, &rhl_mhl(5, 3, false)), C);
    assert!(iut.sent(HeaderType::Tsb).is_empty());
    assert!(iut.indications.is_empty());
}

/// TP/GEONW/FDV/BEA/BV-01: a Beacon has HT = BEACON, HST = 0, NH = 0 and the
/// IUT LPV as SO PV.
#[test]
fn tp_geonw_fdv_bea_bv_01() {
    let mut iut = beacon_iut();
    let deadline = iut.next_deadline();
    iut.at(deadline);
    let f = iut.sent(HeaderType::Beacon)[0];
    assert_eq!(f.common.hst.encode(), 0);
    assert_eq!(f.common.nh, CommonNH::Any);
    let ego = iut.router.ego_position_vector;
    assert_eq!(f.so_pv.gn_addr, ego.gn_addr);
    assert_eq!(
        (f.so_pv.latitude, f.so_pv.longitude),
        (ego.latitude, ego.longitude)
    );
}

/// TP/GEONW/FDV/BEA/BV-02: the Beacon SO PV GN_ADDR is itsGnLocalGnAddr, with
/// the ITS-S type in ST.
#[test]
fn tp_geonw_fdv_bea_bv_02() {
    let mut iut = beacon_iut();
    let deadline = iut.next_deadline();
    iut.at(deadline);
    let so = iut.sent(HeaderType::Beacon)[0].so_pv.gn_addr;
    assert_eq!(so, iut.router.mib.itsGnLocalGnAddr);
    assert!(matches!(so.st, ST::PassengerCar));
}

/// The IUT after a position fix of 2026-11-17T10:00:00.250Z.
fn beacon_after_fix() -> LongPositionVector {
    let mut iut = beacon_iut();
    let mut epv = iut.router.ego_position_vector;
    epv.update_from_gps_at(41.3, 2.1, 0.0, 0.0, true, Some(1_794_909_600_250));
    iut.router.refresh_ego_position_vector(epv);
    let deadline = iut.next_deadline();
    iut.at(deadline);
    iut.sent(HeaderType::Beacon)[0].so_pv
}

/// TP/GEONW/FDV/BEA/BV-03: the Beacon SO PV is the latest position of the IUT.
#[test]
fn tp_geonw_fdv_bea_bv_03() {
    let so = beacon_after_fix();
    assert_eq!((so.latitude, so.longitude), (413_000_000, 21_000_000));
}

/// TP/GEONW/FDV/BEA/BV-04: the Beacon SO PV TST is the acquisition time of
/// the position (milliseconds included).
#[test]
fn tp_geonw_fdv_bea_bv_04() {
    let so = beacon_after_fix();
    assert_eq!(
        so.tst.encode(),
        Tst::set_in_normal_timestamp_milliseconds(1_794_909_600_250).encode()
    );
}

/// TP/GEONW/FDV/BEA/BV-05: over ITS-G5 the Beacon SO PV MID is the 48-bit MAC
/// address of the interface (TS 103 836-4-2 clause 6.1); a GN address with
/// another MID is reported.
#[test]
fn tp_geonw_fdv_bea_bv_05() {
    let interface_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mut iut = Iut::with(
        |m| {
            m.itsGnIfType = GnIfType::ItsG5;
            m.itsGnLocalGnAddr = GNAddress::new(
                M::GnUnicast,
                ST::PassengerCar,
                MID::from_its_g5_mac(interface_mac),
            );
        },
        true,
    );
    assert!(iut
        .router
        .media_dependent_address_ok(Some(MID::new(interface_mac))));
    let deadline = iut.next_deadline();
    iut.at(deadline);
    assert_eq!(
        iut.sent(HeaderType::Beacon)[0].so_pv.gn_addr.mid.as_bytes(),
        interface_mac
    );
    assert!(!iut
        .router
        .media_dependent_address_ok(Some(MID::new([0; 6]))));
}

/// TP/GEONW/FDV/BEA/BV-06: over LTE-V2X the Beacon SO PV MID carries the
/// Layer 2 ID in octets 2-4 and 0 in octets 5-7 (TS 103 836-4-3 clause 5.2).
#[test]
fn tp_geonw_fdv_bea_bv_06() {
    let mut iut = Iut::with(
        |m| {
            m.itsGnIfType = GnIfType::LteV2x;
            m.itsGnLocalGnAddr = GNAddress::new(
                M::GnUnicast,
                ST::PassengerCar,
                MID::from_lte_v2x_l2_id(0xABCDEF).unwrap(),
            );
        },
        true,
    );
    assert!(iut.router.media_dependent_address_ok(None));
    let deadline = iut.next_deadline();
    iut.at(deadline);
    assert_eq!(
        iut.sent(HeaderType::Beacon)[0].so_pv.gn_addr.mid.as_bytes(),
        [0xAB, 0xCD, 0xEF, 0, 0, 0]
    );
}

/// TP/GEONW/FDV/GUC/BV-01: a GUC to B has HT = 2, HST = 0, DE PV = position
/// of B and SO PV = position of the IUT.
#[test]
fn tp_geonw_fdv_guc_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_guc(B, false, b"guc", None);
    let f = iut.sent(HeaderType::GeoUnicast)[0];
    assert_eq!(f.common.hst.encode(), 0);
    assert_eq!(
        (f.guc().de_pv.gn_address, f.guc().de_pv.latitude),
        (addr(B), pos(B))
    );
    assert_eq!(
        (f.so_pv.gn_addr, f.so_pv.latitude),
        (addr(IUT), EGO_LAT as u32)
    );
}

/// TP/GEONW/FDV/GBC/BV-01: a GBC has HT = 4 and SO PV = position of the IUT.
#[test]
fn tp_geonw_fdv_gbc_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_gbc(area1(), false, false, None);
    let f = iut.sent(HeaderType::GeoBroadcast)[0];
    assert_eq!(
        (f.so_pv.gn_addr, f.so_pv.latitude),
        (addr(IUT), EGO_LAT as u32)
    );
}

/// TP/GEONW/FDV/GAC/BV-01: a GAC has HT = 3 and SO PV = position of the IUT.
#[test]
fn tp_geonw_fdv_gac_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_gbc(area1(), false, true, None);
    let f = iut.sent(HeaderType::GeoAnycast)[0];
    assert_eq!(
        (f.so_pv.gn_addr, f.so_pv.latitude),
        (addr(IUT), EGO_LAT as u32)
    );
}

/// TP/GEONW/FDV/SHB/BV-01: an SHB has HT = TSB, HST = SINGLE_HOP, MHL = 1 and
/// the IUT LPV.
#[test]
fn tp_geonw_fdv_shb_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_shb(b"shb");
    let f = iut.sent(HeaderType::Tsb)[0];
    assert_eq!(
        f.common.hst,
        HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop)
    );
    assert_eq!(f.common.mhl, 1);
    assert_eq!(
        (f.so_pv.gn_addr, f.so_pv.latitude),
        (addr(IUT), EGO_LAT as u32)
    );
}

fn dcc_iut() -> Iut {
    let mut iut = Iut::with(|m| m.itsGnIfType = GnIfType::ItsG5, false);
    iut.router
        .set_dcc_net(DccNet::new(None, 20.0).with_rng(Box::new(|| 0.0)));
    iut
}

/// TP/GEONW/FDV/SHB/BV-02: with DCC_NET over ITS-G5 the SHB carries the
/// DCC-MCO field: CBR_L_0_Hop, CBR_L_1_Hop and the transmit power (TS 103
/// 836-4-2 clauses 6.3.3, 7.2.1).
#[test]
fn tp_geonw_fdv_shb_bv_02() {
    let mut iut = dcc_iut();
    iut.beacons_from(&[B]);
    iut.receive(&shb_full(&lpv(B), b"payload", [127, 64, 10, 0], 1), B);
    iut.at(0); // T_Trig: CBR_L_1_Hop from B
    iut.router.dcc_net_mut().unwrap().report_local_cbr(0.3);
    iut.request_shb(b"shb");
    assert_eq!(
        iut.sent(HeaderType::Tsb).last().unwrap().mco,
        Some([76, 127, 20, 0])
    );
}

/// TP/GEONW/FDV/TSB/BV-01: a TSB has HT = 5, HST = 1 (MULTI_HOP) and SO PV =
/// position of the IUT.
#[test]
fn tp_geonw_fdv_tsb_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_tsb();
    let f = iut.sent(HeaderType::Tsb)[0];
    assert_eq!(
        f.common.hst,
        HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop)
    );
    assert_eq!(
        (f.so_pv.gn_addr, f.so_pv.latitude),
        (addr(IUT), EGO_LAT as u32)
    );
}

// ── TP/GEONW/PON/LOT, LPV, SQN, GNA ──────────────────────────────────────────

/// GUC to `n` sent without LS; the frame.
fn guc_without_ls(iut: &mut Iut, n: u8) -> &Frame {
    iut.request_guc(n, false, b"guc", None);
    assert!(iut.ls_requests().is_empty());
    iut.sent(HeaderType::GeoUnicast).last().unwrap()
}

/// TP/GEONW/PON/LOT/BV-01: a Beacon creates the LocTE of B: a GUC to B needs
/// no LS and carries the Beacon SO PV as DE PV.
#[test]
fn tp_geonw_pon_lot_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    let f = guc_without_ls(&mut iut, B);
    assert_eq!(
        (f.guc().de_pv.gn_address, f.guc().de_pv.latitude),
        (addr(B), pos(B))
    );
}

/// TP/GEONW/PON/LOT/BV-02: an LS Reply creates the LocTE of A: after the
/// first GUC, a second GUC to A needs no LS and carries the LS Reply SO PV as
/// DE PV.
#[test]
fn tp_geonw_pon_lot_bv_02() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_guc(A, false, b"guc", None);
    assert_eq!(iut.ls_requests().len(), 1);
    iut.at(100);
    iut.receive(&ls_reply(&lpv(A), 1, spv(IUT), 5), B);
    assert_eq!(iut.sent(HeaderType::GeoUnicast).len(), 1);
    iut.request_guc(A, false, b"guc", None);
    assert_eq!(iut.ls_requests().len(), 1);
    let gucs = iut.sent(HeaderType::GeoUnicast);
    assert_eq!(gucs.len(), 2);
    assert_eq!(
        (gucs[1].guc().de_pv.gn_address, gucs[1].guc().de_pv.latitude),
        (addr(A), pos(A))
    );
}

/// TP/GEONW/PON/LOT/BV-03-X (variants 01-08): a Beacon, GUC, GAC, GBC, TSB,
/// SHB, LS Request or LS Reply originated by NODE creates its LocTE: a GUC to
/// NODE needs no LS and carries the SO PV of the message as DE PV.
#[test]
fn tp_geonw_pon_lot_bv_03_x() {
    let variants: [(&str, u8, Vec<u8>); 8] = [
        ("01", B, beacon(B, true)),
        ("02", A, guc(&lpv(A), 1, spv(IUT), &Pkt::default())),
        ("03", A, gbc(&lpv(A), 1, area1(), true, &Pkt::default())),
        ("04", A, gbc(&lpv(A), 1, area1(), false, &Pkt::default())),
        ("05", A, tsb(&lpv(A), 1, &Pkt::default())),
        ("06", B, shb(&lpv(B))),
        ("07", A, ls_request(&lpv(A), 1, addr(IUT), 5)),
        ("08", A, ls_reply(&lpv(A), 1, spv(IUT), 5)),
    ];
    for (variant, node, message) in variants {
        let mut iut = Iut::new();
        if node == A {
            iut.beacons_from(&[B]);
        }
        iut.receive(&message, B);
        iut.request_guc(node, false, b"guc", None);
        assert!(iut.ls_requests().is_empty(), "variant {variant}");
        let f = *iut.sent(HeaderType::GeoUnicast).last().unwrap();
        assert_eq!(f.guc().de_pv.gn_address, addr(node), "variant {variant}");
        assert_eq!(f.guc().de_pv.latitude, pos(node), "variant {variant}");
    }
}

/// TP/GEONW/PON/LOT/BV-04: without Beacons from B for itsGnLifetimeLocTE the
/// LocTE expires: a GUC to B starts an LS Request for B (MID of B, other bits
/// 0).
#[test]
fn tp_geonw_pon_lot_bv_04() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    let lifetime = u64::from(iut.router.mib.itsGnLifetimeLocTE) * 1000;
    iut.at(lifetime + 1);
    iut.request_guc(B, false, b"guc", None);
    let requests = iut.ls_requests();
    assert_eq!(requests.len(), 1);
    let Ext::LsRequest(e) = &requests[0].ext else {
        unreachable!()
    };
    assert_eq!(
        e.request_gn_addr,
        GNAddress::new(M::GnUnicast, ST::Unknown, addr(B).mid)
    );
}

/// TP/GEONW/PON/LOT/BV-05-X (variants 01-07): a GUC, GAC, GBC, TSB, SHB, LS
/// Request or LS Reply from B with an older TST and another position does not
/// update the LocTE: the GUC to B carries the Beacon position.
#[test]
fn tp_geonw_pon_lot_bv_05_x() {
    let older = || lpv_at(B, north(450.0), true, -1000);
    let variants: [(&str, Vec<u8>); 7] = [
        ("01", guc(&older(), 1, spv(IUT), &Pkt::default())),
        ("02", gbc(&older(), 1, area1(), true, &Pkt::default())),
        ("03", gbc(&older(), 1, area1(), false, &Pkt::default())),
        ("04", tsb(&older(), 1, &Pkt::default())),
        ("05", shb(&older())),
        ("06", ls_request(&older(), 1, addr(IUT), 5)),
        ("07", ls_reply(&older(), 1, spv(IUT), 5)),
    ];
    for (variant, message) in variants {
        let mut iut = Iut::new();
        iut.beacons_from(&[B]);
        iut.receive(&message, B);
        let f = guc_without_ls(&mut iut, B);
        assert_eq!(f.guc().de_pv.latitude, pos(B), "variant {variant}");
    }
}

/// TP/GEONW/PON/LOT/BV-06: with DCC_NET, an SHB from B (older TST, other
/// position) updates the LocTEX-G5 of B with its DCC-MCO, while the LocTE
/// keeps the Beacon position; no LS is needed for B. The TP's expected SHB
/// (SO PV and DCC-MCO equal to B's) cannot hold for an IUT's own SHB; the
/// IUT's SHB carries its own DCC-MCO (TS 103 836-4-2 clauses 6.2, 7.2).
#[test]
fn tp_geonw_pon_lot_bv_06() {
    let mut iut = dcc_iut();
    iut.beacons_from(&[B]);
    iut.receive(
        &shb_full(
            &lpv_at(B, north(450.0), true, -1000),
            b"payload",
            [102, 51, 15, 0],
            1,
        ),
        B,
    );
    let loctex = iut
        .router
        .dcc_net()
        .unwrap()
        .loctex_of(&addr(B))
        .unwrap()
        .clone();
    assert_eq!(
        (
            (loctex.cbr_r_0_hop * 255.0).round() as u8,
            (loctex.cbr_r_1_hop * 255.0).round() as u8,
            loctex.tx_power_dbm
        ),
        (102, 51, 15)
    );
    assert_eq!(
        iut.router
            .location_table
            .get_entry_ref(&addr(B))
            .unwrap()
            .position_vector
            .latitude,
        pos(B)
    );
    iut.request_shb(b"shb");
    assert!(iut.ls_requests().is_empty());
    let own = iut.router.dcc_net().unwrap().dcc_mco();
    assert_eq!(iut.sent(HeaderType::Tsb).last().unwrap().mco, Some(own));
}

/// TP/GEONW/PON/LOT/BV-07: without DCC_NET, after an SHB with a DCC-MCO from
/// B the IUT's SHB carries a DCC-MCO with CBR_L_0_Hop, CBR_L_1_Hop and
/// transmit power 0.
#[test]
fn tp_geonw_pon_lot_bv_07() {
    let mut iut = Iut::with(|m| m.itsGnIfType = GnIfType::ItsG5, false);
    iut.beacons_from(&[B]);
    iut.receive(
        &shb_full(
            &lpv_at(B, north(450.0), true, -1000),
            b"payload",
            [102, 51, 15, 0],
            1,
        ),
        B,
    );
    iut.request_shb(b"shb");
    assert!(iut.ls_requests().is_empty());
    assert_eq!(iut.sent(HeaderType::Tsb).last().unwrap().mco, Some([0; 4]));
}

/// TP/GEONW/PON/LPV/BV-01: after a position change the next Beacon carries
/// the new position.
#[test]
fn tp_geonw_pon_lpv_bv_01() {
    let mut iut = beacon_iut();
    let deadline = iut.next_deadline();
    iut.at(deadline);
    let mut epv = iut.router.ego_position_vector;
    epv.update_from_gps_at(41.4, 2.2, 0.0, 0.0, true, None);
    iut.router.refresh_ego_position_vector(epv);
    let deadline = iut.next_deadline();
    iut.at(deadline);
    let so = iut.sent(HeaderType::Beacon).last().unwrap().so_pv;
    assert_eq!((so.latitude, so.longitude), (414_000_000, 22_000_000));
}

/// TP/GEONW/PON/SQN/BV-01: the first GBC has SN 0.
#[test]
fn tp_geonw_pon_sqn_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_gbc(area1(), false, false, None);
    assert_eq!(iut.sent(HeaderType::GeoBroadcast)[0].sn(), 0);
}

/// TP/GEONW/PON/SQN/BV-02: the next GBC has SN1 + 1.
#[test]
fn tp_geonw_pon_sqn_bv_02() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_gbc(area1(), false, false, None);
    iut.request_gbc(area1(), false, false, None);
    let gbcs = iut.sent(HeaderType::GeoBroadcast);
    assert_eq!(gbcs[1].sn(), gbcs[0].sn() + 1);
}

/// TP/GEONW/PON/GNA/BV-01: with auto address configuration the Beacon SO PV
/// GN_ADDR is itsGnLocalGnAddr.
#[test]
fn tp_geonw_pon_gna_bv_01() {
    let mut iut = Iut::with(
        |m| m.itsGnLocalGnAddrConfMethod = LocalGnAddrConfMethod::Auto,
        true,
    );
    let deadline = iut.next_deadline();
    iut.at(deadline);
    assert_eq!(
        iut.sent(HeaderType::Beacon)[0].so_pv.gn_addr,
        iut.router.mib.itsGnLocalGnAddr
    );
}

/// TP/GEONW/PON/GNA/BV-02: duplicate address detection: after an SHB from B
/// with the IUT's GN_ADDR, the next SHB of the IUT uses another GN_ADDR
/// (clause 10.2.1.5).
#[test]
fn tp_geonw_pon_gna_bv_02() {
    let mut iut = Iut::with(
        |m| m.itsGnLocalGnAddrConfMethod = LocalGnAddrConfMethod::Auto,
        false,
    );
    let changes = Arc::new(Mutex::new(vec![]));
    let sink = Arc::clone(&changes);
    iut.router
        .set_address_change_callback(Box::new(move |a| sink.lock().unwrap().push(a)));
    iut.request_shb(b"shb");
    let first = iut.sent(HeaderType::Tsb).last().unwrap().so_pv.gn_addr;
    let mut clash = lpv(B);
    clash.gn_addr = first;
    iut.receive(&shb(&clash), B);
    iut.request_shb(b"shb");
    let second = iut.sent(HeaderType::Tsb).last().unwrap().so_pv.gn_addr;
    assert_ne!(second, first);
    assert_eq!(changes.lock().unwrap().as_slice(), &[second]);
    assert_eq!(iut.router.mib.itsGnLocalGnAddr, second);
    assert_eq!(second.mid.as_bytes()[0] & 0x03, 0x02); // unicast, locally administered
}

// ── TP/GEONW/PON/LOS and TP/GEONW/CAP/LOS: Location Service ─────────────────

/// TP/GEONW/PON/LOS/BV-01: a GUC to an unknown A starts an LS Request (HT =
/// LS, HST = LS_REQUEST, NH = 0) for the MID of A with the other bits 0.
#[test]
fn tp_geonw_pon_los_bv_01() {
    let mut iut = Iut::new();
    iut.request_guc(A, false, b"guc", None);
    let request = iut.ls_requests()[0];
    assert_eq!(request.common.nh, CommonNH::Any);
    let Ext::LsRequest(e) = &request.ext else {
        unreachable!()
    };
    assert_eq!(e.request_gn_addr.mid.as_bytes(), addr(A).mid.as_bytes());
    assert_eq!(&e.request_gn_addr.encode()[0..2], &[0, 0]);
}

/// TP/GEONW/PON/LOS/BV-02: a second GUC to A while the LS is active sends no
/// second LS Request.
#[test]
fn tp_geonw_pon_los_bv_02() {
    let mut iut = Iut::new();
    iut.request_guc(A, false, b"guc", None);
    iut.at(500);
    iut.request_guc(A, false, b"guc", None);
    assert_eq!(iut.ls_requests().len(), 1);
}

/// TP/GEONW/PON/LOS/BV-03: on the LS Reply the buffered GUC is sent with LT =
/// default LT - waiting time.
#[test]
fn tp_geonw_pon_los_bv_03() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_guc(A, true, b"guc", None);
    iut.at(500);
    iut.receive(&ls_reply(&lpv(A), 1, spv(IUT), 5), B);
    let f = iut.sent(HeaderType::GeoUnicast)[0];
    assert_eq!(
        f.basic.lt.get_value_in_milliseconds(),
        lt_ms(DEFAULT_LT_MS - 500)
    );
}

/// TP/GEONW/PON/LOS/BV-04: the LS buffer is FIFO: PL1 then PL2 after the LS
/// Reply.
#[test]
fn tp_geonw_pon_los_bv_04() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_guc(A, true, b"PL1", None);
    iut.request_guc(A, true, b"PL2", None);
    iut.at(200);
    iut.receive(&ls_reply(&lpv(A), 1, spv(IUT), 5), B);
    let payloads: Vec<_> = iut
        .sent(HeaderType::GeoUnicast)
        .iter()
        .map(|f| f.payload.clone())
        .collect();
    assert_eq!(payloads, vec![b"PL1".to_vec(), b"PL2".to_vec()]);
}

/// TP/GEONW/PON/LOS/BV-05: GUCs whose LT expired in the LS buffer are
/// discarded.
#[test]
fn tp_geonw_pon_los_bv_05() {
    let mut iut = Iut::new();
    iut.request_guc(A, true, b"PL1", Some(0.5));
    iut.request_guc(A, true, b"PL2", Some(0.5));
    iut.at(800);
    iut.receive(&ls_reply(&lpv(A), 1, spv(IUT), 5), B);
    assert!(iut.sent(HeaderType::GeoUnicast).is_empty());
}

/// TP/GEONW/PON/LOS/TI-06: without LS Reply the LS Request is retransmitted
/// when itsGnLocationServiceRetransmitTimer expires.
#[test]
fn tp_geonw_pon_los_ti_06() {
    let mut iut = Iut::new();
    iut.request_guc(A, true, b"guc", None);
    let timer = u64::from(iut.router.mib.itsGnLocationServiceRetransmitTimer);
    iut.at(timer - 1);
    assert_eq!(iut.ls_requests().len(), 1);
    iut.at(timer);
    let times: Vec<_> = iut.ls_requests().iter().map(|f| f.at).collect();
    assert_eq!(times, vec![0, timer]);
}

/// TP/GEONW/PON/LOS/BV-07: without LS Reply the LS Request is retransmitted
/// itsGnLocationServiceMaxRetrans times.
#[test]
fn tp_geonw_pon_los_bv_07() {
    let mut iut = Iut::new();
    iut.request_guc(A, true, b"guc", None);
    let timer = u64::from(iut.router.mib.itsGnLocationServiceRetransmitTimer);
    let max = usize::from(iut.router.mib.itsGnLocationServiceMaxRetrans);
    iut.at(timer * (max as u64 + 5));
    assert_eq!(iut.ls_requests().len(), 1 + max);
}

/// TP/GEONW/PON/LOS/BV-08: an LS Request for the IUT is answered with an LS
/// Reply (NH = 0) whose DE PV is the SO PV of the request.
#[test]
fn tp_geonw_pon_los_bv_08() {
    let mut iut = Iut::new();
    let request_addr = GNAddress::new(M::GnUnicast, ST::Unknown, addr(IUT).mid);
    iut.receive(&ls_request(&lpv(B), 7, request_addr, 5), B);
    let replies: Vec<_> = iut
        .frames
        .iter()
        .filter(|f| matches!(f.ext, Ext::LsReply(_)))
        .collect();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].common.nh, CommonNH::Any);
    let Ext::LsReply(e) = &replies[0].ext else {
        unreachable!()
    };
    assert_eq!((e.de_pv.gn_address, e.de_pv.latitude), (addr(B), pos(B)));
}

/// TP/GEONW/PON/LOS/BO-09: the same LS Request received again (from D) is not
/// answered again.
#[test]
fn tp_geonw_pon_los_bo_09() {
    let mut iut = Iut::new();
    let request = ls_request(&lpv(B), 7, addr(IUT), 5);
    iut.receive(&request, B);
    iut.receive(&request, D);
    assert_eq!(iut.sent(HeaderType::Ls).len(), 1);
}

/// TP/GEONW/PON/LOS/BV-10: an LS Request for another router (RHL > 1) is
/// re-broadcast with RHL - 1.
#[test]
fn tp_geonw_pon_los_bv_10() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, C]);
    iut.receive(&ls_request(&lpv(C), 3, addr(A), 5), C);
    let forwarded = iut.ls_requests();
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].basic.rhl, 4);
    assert_eq!(
        (forwarded[0].sn(), forwarded[0].so_pv.gn_addr),
        (3, addr(C))
    );
    assert_eq!(forwarded[0].destination, None);
}

/// TP/GEONW/PON/LOS/BV-11: an LS Reply for B (RHL > 1) is forwarded to B with
/// RHL - 1.
#[test]
fn tp_geonw_pon_los_bv_11() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, C]);
    iut.receive(&ls_reply(&lpv(C), 3, spv(B), 5), C);
    let forwarded = iut.sent(HeaderType::Ls);
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].basic.rhl, 4);
    assert_eq!(forwarded[0].destination, Some(mac(B)));
}

fn pending(lifetime_s: Option<f64>) -> Iut {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_guc(A, true, b"guc", lifetime_s);
    iut
}

fn gucs_to(iut: &Iut, n: u8) -> usize {
    iut.sent(HeaderType::GeoUnicast)
        .iter()
        .filter(|f| f.guc().de_pv.gn_address == addr(n))
        .count()
}

/// TP/GEONW/PON/LOS/BV-12: a GUC from A addressed to the IUT flushes the LS
/// buffer of A.
#[test]
fn tp_geonw_pon_los_bv_12() {
    let mut iut = pending(None);
    iut.at(300);
    iut.receive(&guc(&lpv(A), 1, spv(IUT), &Pkt::default()), B);
    assert_eq!(iut.sent(HeaderType::GeoUnicast).len(), 1);
    assert_eq!(gucs_to(&iut, A), 1);
}

/// TP/GEONW/PON/LOS/BV-13: LS buffer FIFO with lifetime: after LT2 (< LT1)
/// expired, only PL1 is sent.
#[test]
fn tp_geonw_pon_los_bv_13() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_guc(A, true, b"PL1", Some(5.0));
    iut.request_guc(A, true, b"PL2", Some(0.5));
    iut.at(800);
    iut.receive(&ls_reply(&lpv(A), 1, spv(IUT), 5), B);
    let payloads: Vec<_> = iut
        .sent(HeaderType::GeoUnicast)
        .iter()
        .map(|f| f.payload.clone())
        .collect();
    assert_eq!(payloads, vec![b"PL1".to_vec()]);
}

/// TP/GEONW/PON/LOS/BV-14: after itsGnLocationServiceMaxRetrans
/// retransmissions the LS fails and its buffer is discarded: a later GUC from
/// A sends nothing to A.
#[test]
fn tp_geonw_pon_los_bv_14() {
    let mut iut = Iut::new();
    iut.request_guc(A, true, b"guc", None);
    let timer = u64::from(iut.router.mib.itsGnLocationServiceRetransmitTimer);
    let max = usize::from(iut.router.mib.itsGnLocationServiceMaxRetrans);
    iut.at(timer * (max as u64 + 2));
    assert_eq!(iut.ls_requests().len(), 1 + max);
    iut.receive(&guc(&lpv(A), 1, spv(IUT), &Pkt::default()), B);
    assert!(iut.sent(HeaderType::GeoUnicast).is_empty());
}

/// TP/GEONW/PON/LOS/BV-15: a GUC from A addressed to B (forwarded by the IUT)
/// also flushes the LS buffer of A.
#[test]
fn tp_geonw_pon_los_bv_15() {
    let mut iut = pending(None);
    iut.at(300);
    iut.receive(&guc(&lpv(A), 1, spv(B), &Pkt::default()), C);
    assert_eq!(gucs_to(&iut, A), 1);
}

fn retransmission_stops(de: u8) {
    let mut iut = pending(None);
    let timer = u64::from(iut.router.mib.itsGnLocationServiceRetransmitTimer);
    iut.at(timer);
    assert_eq!(iut.ls_requests().len(), 2);
    iut.at(timer + 300);
    iut.receive(&guc(&lpv(A), 1, spv(de), &Pkt::default()), C);
    iut.at(timer * 6);
    assert_eq!(iut.ls_requests().len(), 2);
    assert_eq!(gucs_to(&iut, A), 1);
}

/// TP/GEONW/PON/LOS/BV-16: a GUC from A addressed to the IUT stops the LS
/// Request retransmissions; the buffered GUC is sent instead.
#[test]
fn tp_geonw_pon_los_bv_16() {
    retransmission_stops(IUT);
}

/// TP/GEONW/PON/LOS/BV-17: a GUC from A addressed to B stops the LS Request
/// retransmissions; the buffered GUC is sent instead.
#[test]
fn tp_geonw_pon_los_bv_17() {
    retransmission_stops(B);
}

/// TP/GEONW/CAP/LOS/BV-01: when itsGnLocationServicePacketBufferSize is
/// exceeded the oldest packets are removed and the new one is queued at the
/// end.
#[test]
fn tp_geonw_cap_los_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    let payloads: Vec<Vec<u8>> = (1..=3).map(|i| vec![i; 400]).collect(); // 1200 > 1024 octets
    for payload in &payloads {
        iut.request_guc(A, true, payload, None);
    }
    iut.receive(&ls_reply(&lpv(A), 1, spv(IUT), 5), B);
    let sent: Vec<_> = iut
        .sent(HeaderType::GeoUnicast)
        .iter()
        .map(|f| f.payload.clone())
        .collect();
    assert_eq!(sent, payloads[1..].to_vec());
}

// ── TP/GEONW/PON/FPB and TP/GEONW/CAP/FPB: forwarding packet buffers ─────────

/// LocTE of A, not a neighbour: a TSB originated by A relayed by C (RHL 1:
/// not re-broadcast).
fn knows_a(iut: &mut Iut) {
    iut.receive(&tsb(&lpv(A), 50, &rhl_mhl(1, 10, false)), C);
}

/// TP/GEONW/PON/FPB/BV-01: a source GUC without next hop (SCF) is buffered
/// and sent to B when B's Beacon arrives.
#[test]
fn tp_geonw_pon_fpb_bv_01() {
    let mut iut = Iut::new();
    knows_a(&mut iut);
    iut.request_guc(A, true, b"guc", None);
    assert!(iut.sent(HeaderType::GeoUnicast).is_empty());
    iut.at(200);
    iut.beacons_from(&[B]);
    let gucs = iut.sent(HeaderType::GeoUnicast);
    assert_eq!(gucs.len(), 1);
    assert_eq!(gucs[0].destination, Some(mac(B)));
}

fn forwarder_buffer(sns: &[u16], lifetime_ms: Option<u32>) -> Iut {
    let mut iut = Iut::new();
    for sn in sns {
        let p = Pkt {
            rhl: 10,
            mhl: 10,
            scf: true,
            lifetime_ms,
            ..Default::default()
        };
        iut.receive(&guc(&lpv(C), *sn, spv(A), &p), C);
    }
    assert!(iut.sent(HeaderType::GeoUnicast).is_empty());
    iut
}

/// TP/GEONW/PON/FPB/BV-02: a received GUC without next hop (SCF) is buffered
/// and forwarded to B with RHL - 1 and the same SN when B's Beacon arrives.
#[test]
fn tp_geonw_pon_fpb_bv_02() {
    let mut iut = forwarder_buffer(&[7], None);
    iut.beacons_from(&[B]);
    let f = iut.sent(HeaderType::GeoUnicast)[0];
    assert_eq!((f.basic.rhl, f.sn(), f.destination), (9, 7, Some(mac(B))));
}

/// TP/GEONW/PON/FPB/BV-03: the UC forwarding buffer is FIFO: SN1 then SN2.
#[test]
fn tp_geonw_pon_fpb_bv_03() {
    let mut iut = forwarder_buffer(&[7, 8], None);
    iut.beacons_from(&[B]);
    let sns: Vec<_> = iut
        .sent(HeaderType::GeoUnicast)
        .iter()
        .map(|f| f.sn())
        .collect();
    assert_eq!(sns, vec![7, 8]);
}

/// TP/GEONW/PON/FPB/BV-04: a buffered GUC whose LT expired is not forwarded.
#[test]
fn tp_geonw_pon_fpb_bv_04() {
    let mut iut = forwarder_buffer(&[7], Some(1000));
    iut.at(2000);
    iut.beacons_from(&[B]);
    assert!(iut.sent(HeaderType::GeoUnicast).is_empty());
}

/// TP/GEONW/PON/FPB/BV-06: a source GBC without neighbours (SCF) is buffered
/// and broadcast when a Beacon arrives.
#[test]
fn tp_geonw_pon_fpb_bv_06() {
    let mut iut = Iut::new();
    iut.request_gbc(area1(), true, false, None);
    assert!(iut.sent(HeaderType::GeoBroadcast).is_empty());
    iut.beacons_from(&[D]);
    let gbcs = iut.sent(HeaderType::GeoBroadcast);
    assert_eq!(gbcs.len(), 1);
    assert_eq!(gbcs[0].destination, None);
}

/// TP/GEONW/PON/FPB/BV-07: the BC forwarding buffer is FIFO: GBC1 (SN1) then
/// GBC2 (SN2).
#[test]
fn tp_geonw_pon_fpb_bv_07() {
    let mut iut = Iut::new();
    iut.request_gbc(area1(), true, false, None);
    iut.request_gbc(area1(), true, false, None);
    iut.beacons_from(&[B]);
    let sns: Vec<_> = iut
        .sent(HeaderType::GeoBroadcast)
        .iter()
        .map(|f| f.sn())
        .collect();
    assert_eq!(sns, vec![0, 1]);
}

/// TP/GEONW/PON/FPB/BV-08: buffered GBCs whose LT expired are not broadcast.
#[test]
fn tp_geonw_pon_fpb_bv_08() {
    let mut iut = Iut::new();
    iut.request_gbc(area1(), true, false, Some(1.0));
    iut.request_gbc(area1(), true, false, Some(1.0));
    iut.at(2000);
    iut.beacons_from(&[B]);
    assert!(iut.sent(HeaderType::GeoBroadcast).is_empty());
}

/// TP/GEONW/PON/FPB/BV-09: the buffered source GUC is sent with LT = default
/// LT - waiting time.
#[test]
fn tp_geonw_pon_fpb_bv_09() {
    let mut iut = Iut::new();
    knows_a(&mut iut);
    iut.request_guc(A, true, b"guc", None);
    iut.at(1500);
    iut.beacons_from(&[B]);
    let f = iut.sent(HeaderType::GeoUnicast)[0];
    assert_eq!(
        f.basic.lt.get_value_in_milliseconds(),
        lt_ms(DEFAULT_LT_MS - 1500)
    );
}

/// TP/GEONW/PON/FPB/BV-10: the buffered source GBC is broadcast with LT =
/// default LT - waiting time.
#[test]
fn tp_geonw_pon_fpb_bv_10() {
    let mut iut = Iut::new();
    iut.request_gbc(area1(), true, false, None);
    iut.at(1500);
    iut.beacons_from(&[B]);
    let f = iut.sent(HeaderType::GeoBroadcast)[0];
    assert_eq!(
        f.basic.lt.get_value_in_milliseconds(),
        lt_ms(DEFAULT_LT_MS - 1500)
    );
}

/// TP/GEONW/PON/FPB/BV-11-X (variants 01-05): without next hop and with SCF
/// = 0 a source GUC, GAC (AREA2), GBC (AREA2), TSB or SHB is broadcast
/// immediately.
#[test]
fn tp_geonw_pon_fpb_bv_11_x() {
    type Send = fn(&mut Iut);
    let variants: [(&str, HeaderType, Send); 5] = [
        ("01", HeaderType::GeoUnicast, |i| {
            i.request_guc(A, false, b"guc", None)
        }),
        ("02", HeaderType::GeoAnycast, |i| {
            i.request_gbc(area2(), false, true, None)
        }),
        ("03", HeaderType::GeoBroadcast, |i| {
            i.request_gbc(area2(), false, false, None)
        }),
        ("04", HeaderType::Tsb, |i| i.request_tsb()),
        ("05", HeaderType::Tsb, |i| i.request_shb(b"shb")),
    ];
    for (variant, ht, send) in variants {
        let mut iut = Iut::new();
        knows_a(&mut iut);
        let before = iut.sent(ht.clone()).len();
        send(&mut iut);
        let frames = iut.sent(ht);
        assert_eq!(frames.len() - before, 1, "variant {variant}");
        let f = frames.last().unwrap();
        assert_eq!((f.destination, f.at), (None, 0), "variant {variant}");
    }
}

/// TP/GEONW/PON/FPB/BV-12-X (variants 01-04): without next hop and with SCF
/// = 0 a received GUC (to A), GAC (AREA2), GBC (AREA2) or TSB is forwarded by
/// broadcast immediately.
#[test]
fn tp_geonw_pon_fpb_bv_12_x() {
    let p = || rhl_mhl(10, 10, false);
    let variants: [(&str, HeaderType, Vec<u8>); 4] = [
        ("01", HeaderType::GeoUnicast, guc(&lpv(C), 1, spv(A), &p())),
        (
            "02",
            HeaderType::GeoAnycast,
            gbc(&lpv(C), 1, area2(), true, &p()),
        ),
        (
            "03",
            HeaderType::GeoBroadcast,
            gbc(&lpv(C), 1, area2(), false, &p()),
        ),
        ("04", HeaderType::Tsb, tsb(&lpv(C), 1, &p())),
    ];
    for (variant, ht, packet) in variants {
        let mut iut = Iut::new();
        iut.receive(&packet, C);
        let frames = iut.sent(ht);
        assert_eq!(frames.len(), 1, "variant {variant}");
        assert_eq!(frames[0].destination, None, "variant {variant}");
        assert_eq!(frames[0].basic.rhl, 9, "variant {variant}");
    }
}

/// TP/GEONW/CAP/FPB/BV-01: when itsGnUcForwardingPacketBufferSize is exceeded
/// the oldest packets are removed and the new GUC is queued at the end.
#[test]
fn tp_geonw_cap_fpb_bv_01() {
    let mut iut = Iut::with(|m| m.itsGnUcForwardingPacketBufferSize = 1, false); // 1 kB
    for sn in 1..=3 {
        let p = Pkt {
            rhl: 10,
            mhl: 10,
            scf: true,
            payload: vec![0; 400],
            ..Default::default()
        };
        iut.receive(&guc(&lpv(C), sn, spv(A), &p), C);
    }
    iut.beacons_from(&[B]);
    let sns: Vec<_> = iut
        .sent(HeaderType::GeoUnicast)
        .iter()
        .map(|f| f.sn())
        .collect();
    assert_eq!(sns, vec![2, 3]);
}

/// TP/GEONW/CAP/FPB/BV-02: when itsGnBcForwardingPacketBufferSize is exceeded
/// the oldest packets are removed and the new GBC is queued at the end.
#[test]
fn tp_geonw_cap_fpb_bv_02() {
    let mut iut = Iut::with(|m| m.itsGnBcForwardingPacketBufferSize = 1, false); // 1 kB
    for sn in 1..=3 {
        let p = Pkt {
            rhl: 10,
            mhl: 10,
            scf: true,
            payload: vec![0; 400],
            ..Default::default()
        };
        iut.receive(&gbc(&lpv(C), sn, area2(), false, &p), C);
    }
    iut.beacons_from(&[B]);
    let sns: Vec<_> = iut
        .sent(HeaderType::GeoBroadcast)
        .iter()
        .map(|f| f.sn())
        .collect();
    assert_eq!(sns, vec![2, 3]);
}

// ── TP/GEONW/PON/BEA: Beacon service ────────────────────────────────────────

/// TP/GEONW/PON/BEA/TI-01: Beacons are sent every
/// itsGnBeaconServiceRetransmitTimer + RAND[0, itsGnBeaconServiceMaxJitter].
#[test]
fn tp_geonw_pon_bea_ti_01() {
    let mut iut = beacon_iut();
    while iut.sent(HeaderType::Beacon).len() < 6 {
        let deadline = iut.next_deadline();
        iut.at(deadline);
    }
    let times: Vec<_> = iut.sent(HeaderType::Beacon).iter().map(|f| f.at).collect();
    let timer = u64::from(iut.router.mib.itsGnBeaconServiceRetransmitTimer);
    let jitter = u64::from(iut.router.mib.itsGnBeaconServiceMaxJitter);
    for w in times.windows(2) {
        assert!((timer..=timer + jitter).contains(&(w[1] - w[0])), "{w:?}");
    }
}

/// TP/GEONW/PON/BEA/BV-02: an SHB restarts the Beacon timer: the next Beacon
/// comes itsGnBeaconServiceRetransmitTimer (+ jitter) after the SHB.
#[test]
fn tp_geonw_pon_bea_bv_02() {
    let mut iut = beacon_iut();
    let deadline = iut.next_deadline();
    iut.at(deadline);
    iut.beacons_from(&[B]);
    iut.at(2000);
    iut.request_shb(b"shb");
    let timer = u64::from(iut.router.mib.itsGnBeaconServiceRetransmitTimer);
    let jitter = u64::from(iut.router.mib.itsGnBeaconServiceMaxJitter);
    iut.at(2000 + timer - 1);
    assert_eq!(iut.sent(HeaderType::Beacon).len(), 1);
    iut.at(2000 + timer + jitter);
    let beacons = iut.sent(HeaderType::Beacon);
    assert_eq!(beacons.len(), 2);
    assert!(beacons[1].at >= 2000 + timer);
}

// ── TP/GEONW/PON/GUC: GeoUnicast ────────────────────────────────────────────

fn stale(n: u8) -> ShortPositionVector {
    ShortPositionVector {
        gn_address: addr(n),
        tst: tst(-5000),
        latitude: north(1400.0),
        longitude: EGO_LON,
    }
}

/// TP/GEONW/PON/GUC/ALL/BV-03: a forwarded GUC has RHL - 1 and the same MHL.
/// DE PV, after TS 103 836-4-1 V2.2.1 clause 10.3.8.3: for A, not a
/// neighbour, step 7 applies (the LocTE of A is updated from a newer DE PV,
/// never from an older one) and the DE PV is forwarded unchanged; the DE PV
/// is replaced by a newer LocTE only when DE is a neighbour (step 8), checked
/// with D. The TP (Release 1) expects the replacement for A.
#[test]
fn tp_geonw_pon_guc_all_bv_03() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, C, D]);
    iut.receive(&guc(&lpv(A), 1, spv(IUT), &Pkt::default()), B); // GEOUNI1 from A
    iut.receive(&guc(&lpv(C), 2, stale(A), &rhl_mhl(7, 9, true)), C); // GEOUNI2
    let f = iut.sent(HeaderType::GeoUnicast)[0];
    assert_eq!((f.basic.rhl, f.common.mhl), (6, 9));
    assert_eq!(f.guc().de_pv.latitude, north(1400.0));
    let a_lat = |iut: &Iut| {
        iut.router
            .location_table
            .get_entry_ref(&addr(A))
            .unwrap()
            .position_vector
            .latitude
    };
    assert_eq!(a_lat(&iut), pos(A));
    iut.receive(&guc(&lpv(C), 3, stale(D), &rhl_mhl(7, 9, true)), C); // to neighbour D
    assert_eq!(
        iut.sent(HeaderType::GeoUnicast)
            .last()
            .unwrap()
            .guc()
            .de_pv
            .latitude,
        pos(D)
    );
    let newer = ShortPositionVector {
        gn_address: addr(A),
        tst: tst(1000),
        latitude: north(1600.0),
        longitude: EGO_LON,
    };
    iut.receive(&guc(&lpv(C), 4, newer, &rhl_mhl(7, 9, true)), C); // step 7: LocTE updated
    assert_eq!(a_lat(&iut), north(1600.0));
}

/// TP/GEONW/PON/GUC/ALL/BO-04: a GUC to A with RHL 1 is not forwarded.
#[test]
fn tp_geonw_pon_guc_all_bo_04() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, C]);
    iut.receive(&guc(&lpv(C), 2, spv(A), &rhl_mhl(1, 10, true)), C);
    assert!(iut.sent(HeaderType::GeoUnicast).is_empty());
}

/// TP/GEONW/PON/GUC/ALL/BV-05: a GUC addressed to the IUT is passed to the
/// right upper protocol.
#[test]
fn tp_geonw_pon_guc_all_bv_05() {
    let mut iut = Iut::new();
    let p = Pkt {
        payload: b"data".to_vec(),
        ..Default::default()
    };
    iut.receive(&guc(&lpv(B), 2, spv(IUT), &p), B);
    assert_eq!(iut.indications.len(), 1);
    assert_eq!(iut.indications[0].upper_protocol_entity, CommonNH::BtpB);
    assert_eq!(iut.indications[0].data, b"data");
}

/// TP/GEONW/PON/GUC/ALL/BV-06: a GUC addressed to B is not passed up.
#[test]
fn tp_geonw_pon_guc_all_bv_06() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, C]);
    iut.receive(&guc(&lpv(C), 2, spv(B), &Pkt::default()), C);
    assert!(iut.indications.is_empty());
}

/// TP/GEONW/PON/GUC/ALL/BO-08: a GUC to the IUT received twice is passed up once.
#[test]
fn tp_geonw_pon_guc_all_bo_08() {
    let mut iut = Iut::new();
    iut.beacons_from(&[C, B]);
    let packet = guc(&lpv(C), 2, spv(IUT), &scf());
    iut.receive(&packet, C);
    iut.receive(&with_rhl(&packet, 4), B);
    assert_eq!(iut.indications.len(), 1);
}

/// TP/GEONW/PON/GUC/GRD/BV-01: a GUC to B (greedy) carries B's Beacon
/// position as DE PV and goes to B's link-layer address.
#[test]
fn tp_geonw_pon_guc_grd_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.request_guc(B, false, b"guc", None);
    let f = iut.sent(HeaderType::GeoUnicast)[0];
    assert_eq!(f.guc().de_pv.latitude, pos(B));
    assert_eq!(f.destination, Some(mac(B)));
}

/// TP/GEONW/PON/GUC/GRD/BV-02: a GUC to A is forwarded to the greedy next hop
/// B (not D, not C).
#[test]
fn tp_geonw_pon_guc_grd_bv_02() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, D, C]);
    iut.receive(&guc(&lpv(C), 2, spv(A), &scf()), C);
    assert_eq!(
        iut.sent(HeaderType::GeoUnicast)[0].destination,
        Some(mac(B))
    );
}

/// TP/GEONW/PON/GUC/GRD/BO-07: the same GUC received again (from B) is not
/// forwarded again.
#[test]
fn tp_geonw_pon_guc_grd_bo_07() {
    let mut iut = Iut::new();
    iut.beacons_from(&[C, B]);
    let packet = guc(&lpv(C), 2, spv(A), &scf());
    iut.receive(&packet, C);
    iut.receive(&with_rhl(&packet, 4), B);
    assert_eq!(iut.sent(HeaderType::GeoUnicast).len(), 1);
}

fn nonarea_cbf_iut() -> Iut {
    Iut::with(
        |m| m.itsGnNonAreaForwardingAlgorithm = NonAreaForwardingAlgorithm::Cbf,
        false,
    )
}

/// TP/GEONW/PON/GUC/CBF/BV-01: with CBF a GUC to B is broadcast with B's
/// position as DE PV.
#[test]
fn tp_geonw_pon_guc_cbf_bv_01() {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B]);
    iut.request_guc(B, false, b"guc", None);
    let f = iut.sent(HeaderType::GeoUnicast)[0];
    assert_eq!(f.guc().de_pv.latitude, pos(B));
    assert_eq!(f.destination, None);
}

/// Time at which a GUC to A from `so`, received from `sender`, is re-broadcast.
fn guc_cbf_time(iut: &mut Iut, so: u8, sender: u8) -> u64 {
    iut.receive(&guc(&lpv(so), 2, spv(A), &scf()), sender);
    assert!(iut.sent(HeaderType::GeoUnicast).is_empty());
    iut.at(500);
    let gucs = iut.sent(HeaderType::GeoUnicast);
    assert_eq!(gucs.len(), 1);
    assert_eq!(gucs[0].destination, None);
    gucs[0].at
}

/// TP/GEONW/PON/GUC/CBF/BV-02: a GUC from C is re-broadcast when the CBF
/// timer of its progress (400 m) expires.
#[test]
fn tp_geonw_pon_guc_cbf_bv_02() {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B, C]);
    let at = guc_cbf_time(&mut iut, C, C);
    assert!(close_to(at, cbf_timeout_ms(400.0, &iut.router.mib)), "{at}");
}

/// TP/GEONW/PON/GUC/CBF/BV-07: the same GUC heard from B (a better forwarder)
/// before the CBF timer expires cancels the re-broadcast.
#[test]
fn tp_geonw_pon_guc_cbf_bv_07() {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B, C]);
    let packet = guc(&lpv(C), 2, spv(A), &scf());
    iut.receive(&packet, C);
    iut.at(20);
    iut.receive(&with_rhl(&packet, 4), B);
    iut.at(500);
    assert!(iut.sent(HeaderType::GeoUnicast).is_empty());
}

/// TP/GEONW/PON/GUC/CBF/BV-20: with a progress beyond
/// itsGnDefaultMaxCommunicationRange (1100 m) the GUC is re-broadcast when
/// the CBF timer of the second segment expires. The TP (Release 1) expects
/// itsGnCbfMinTime; TS 103 836-4-1 V2.2.1 clauses E.3.2.2-E.3.2.3 assign
/// progress beyond DIST_MAX to segment SEGN = 2 (190.1 ms here).
#[test]
fn tp_geonw_pon_guc_cbf_bv_20() {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B, FAR]);
    let at = guc_cbf_time(&mut iut, FAR, FAR);
    assert!(
        close_to(at, cbf_timeout_ms(1100.0, &iut.router.mib)),
        "{at}"
    );
}

/// TP/GEONW/PON/GUC/CBF/BV-21: a GUC from an unknown sender D is re-broadcast
/// after CBF_MAX.
#[test]
fn tp_geonw_pon_guc_cbf_bv_21() {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B, C]);
    let at = guc_cbf_time(&mut iut, C, D);
    assert!(
        close_to(at, f64::from(iut.router.mib.itsGnCbfMaxTime)),
        "{at}"
    );
}

/// TP/GEONW/PON/GUC/CBF/BV-22: a GUC from a sender D with PAI = 0 is
/// re-broadcast after CBF_MAX.
#[test]
fn tp_geonw_pon_guc_cbf_bv_22() {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B]);
    iut.receive(&beacon(D, false), D);
    let at = guc_cbf_time(&mut iut, C, D);
    assert!(
        close_to(at, f64::from(iut.router.mib.itsGnCbfMaxTime)),
        "{at}"
    );
}

// ── GBC and GAC: shared forwarding checks ───────────────────────────────────

fn kind(anycast: bool) -> HeaderType {
    if anycast {
        HeaderType::GeoAnycast
    } else {
        HeaderType::GeoBroadcast
    }
}

fn area_frames(iut: &Iut, anycast: bool) -> Vec<&Frame> {
    iut.sent(kind(anycast))
}

fn nonarea_retransmission(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, C]);
    iut.receive(&gbc(&lpv(C), 2, area2(), anycast, &rhl_mhl(7, 9, true)), C);
    let f = area_frames(&iut, anycast)[0];
    assert_eq!((f.basic.rhl, f.common.mhl), (6, 9));
    assert_eq!((f.gbc().latitude, f.gbc().a), (area2().latitude, area2().a));
}

fn nonarea_rhl_one(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, C]);
    iut.receive(&gbc(&lpv(C), 2, area2(), anycast, &rhl_mhl(1, 10, true)), C);
    iut.at(500);
    assert!(area_frames(&iut, anycast).is_empty());
}

fn nonarea_not_passed_up(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.receive(&gbc(&lpv(B), 2, area2(), anycast, &scf()), B);
    assert!(iut.indications.is_empty());
}

fn nonarea_too_big(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, D]);
    iut.receive(&gbc(&lpv(C), 2, big_area(), anycast, &scf()), C);
    iut.at(500);
    assert!(area_frames(&iut, anycast).is_empty());
}

fn nonarea_sender_inside(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, C, D]);
    iut.receive(&gbc(&lpv(D), 2, area2(), anycast, &scf()), D);
    iut.at(500);
    assert!(area_frames(&iut, anycast).is_empty());
    assert!(iut.indications.is_empty());
}

fn nonarea_greedy_source(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.request_gbc(area2(), true, anycast, None);
    let f = area_frames(&iut, anycast)[0];
    assert_eq!(f.destination, Some(mac(B)));
    assert_eq!((f.gbc().latitude, f.gbc().a), (area2().latitude, area2().a));
}

fn nonarea_greedy_forwarder(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, D, C]);
    iut.receive(&gbc(&lpv(C), 2, area2(), anycast, &scf()), C);
    assert_eq!(area_frames(&iut, anycast)[0].destination, Some(mac(B)));
}

fn nonarea_greedy_duplicate(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, D]);
    let packet = gbc(&lpv(C), 2, area2(), anycast, &scf());
    iut.receive(&packet, C);
    iut.receive(&with_rhl(&packet, 4), D);
    assert_eq!(area_frames(&iut, anycast).len(), 1);
}

fn nonarea_cbf_source(anycast: bool) {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[D, B]);
    iut.request_gbc(area2(), true, anycast, None);
    let frames = area_frames(&iut, anycast);
    assert_eq!(frames.len(), 1);
    assert_eq!((frames[0].at, frames[0].destination), (0, None));
}

fn nonarea_cbf_time(iut: &mut Iut, so: u8, sender: u8, area: Area, anycast: bool) -> u64 {
    iut.receive(&gbc(&lpv(so), 2, area, anycast, &scf()), sender);
    assert!(area_frames(iut, anycast).is_empty());
    iut.at(500);
    let frames = area_frames(iut, anycast);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].destination, None);
    frames[0].at
}

fn nonarea_cbf_timer(anycast: bool) {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B, C]);
    let at = nonarea_cbf_time(&mut iut, C, C, area_a(), anycast);
    assert!(close_to(at, cbf_timeout_ms(400.0, &iut.router.mib)), "{at}");
}

fn nonarea_cbf_better_forwarder(anycast: bool) {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B, C]);
    let packet = gbc(&lpv(C), 2, area_a(), anycast, &scf());
    iut.receive(&packet, C);
    iut.at(20);
    iut.receive(&with_rhl(&packet, 4), B);
    iut.at(500);
    assert!(area_frames(&iut, anycast).is_empty());
}

fn nonarea_cbf_second_segment(anycast: bool) {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B, FAR]);
    let at = nonarea_cbf_time(&mut iut, FAR, FAR, area_a(), anycast);
    assert!(
        close_to(at, cbf_timeout_ms(1100.0, &iut.router.mib)),
        "{at}"
    );
}

fn nonarea_cbf_unknown_sender(anycast: bool) {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B]);
    let at = nonarea_cbf_time(&mut iut, C, D, area2(), anycast);
    assert!(
        close_to(at, f64::from(iut.router.mib.itsGnCbfMaxTime)),
        "{at}"
    );
}

fn nonarea_cbf_sender_pai_0(anycast: bool) {
    let mut iut = nonarea_cbf_iut();
    iut.beacons_from(&[B]);
    iut.receive(&beacon(D, false), D);
    let at = nonarea_cbf_time(&mut iut, C, D, area2(), anycast);
    assert!(
        close_to(at, f64::from(iut.router.mib.itsGnCbfMaxTime)),
        "{at}"
    );
}

fn area_source(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.request_gbc(area1(), true, anycast, None);
    let f = area_frames(&iut, anycast)[0];
    assert_eq!((f.at, f.destination), (0, None));
    assert_eq!((f.gbc().latitude, f.gbc().a), (area1().latitude, area1().a));
}

fn area_passed_up(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    let p = Pkt {
        scf: true,
        payload: b"area".to_vec(),
        ..Default::default()
    };
    iut.receive(&gbc(&lpv(B), 2, area1(), anycast, &p), B);
    assert_eq!(iut.indications.len(), 1);
    assert_eq!(iut.indications[0].upper_protocol_entity, CommonNH::BtpB);
    assert_eq!(iut.indications[0].data, b"area");
}

fn area_duplicate_not_passed_up(anycast: bool) {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    let packet = gbc(&lpv(B), 2, area1(), anycast, &scf());
    iut.receive(&packet, B);
    iut.receive(&with_rhl(&packet, 4), D);
    assert_eq!(iut.indications.len(), 1);
}

// ── TP/GEONW/PON/GBC: GeoBroadcast ──────────────────────────────────────────

/// TP/GEONW/PON/GBC/NONAREA/ALL/BV-03: a forwarded GBC (AREA2) has RHL - 1,
/// the same MHL and the same destination area.
#[test]
fn tp_geonw_pon_gbc_nonarea_all_bv_03() {
    nonarea_retransmission(false);
}

/// TP/GEONW/PON/GBC/NONAREA/ALL/BV-04: a GBC with RHL 1 is not retransmitted.
#[test]
fn tp_geonw_pon_gbc_nonarea_all_bv_04() {
    nonarea_rhl_one(false);
}

/// TP/GEONW/PON/GBC/NONAREA/ALL/BV-06: a GBC received outside its area
/// (AREA2) is not passed up.
#[test]
fn tp_geonw_pon_gbc_nonarea_all_bv_06() {
    nonarea_not_passed_up(false);
}

/// TP/GEONW/PON/GBC/NONAREA/ALL/BO-09: a GBC with an area larger than
/// itsGnMaxGeoAreaSize is not retransmitted (clause B.3).
#[test]
fn tp_geonw_pon_gbc_nonarea_all_bo_09() {
    nonarea_too_big(false);
}

/// TP/GEONW/PON/GBC/NONAREA/ALL/BO-10: a GBC from a known sender D inside
/// AREA2, received by the IUT outside AREA2, is discarded (Annex D).
#[test]
fn tp_geonw_pon_gbc_nonarea_all_bo_10() {
    nonarea_sender_inside(false);
}

/// TP/GEONW/PON/GBC/NONAREA/GRD/BV-01: a source GBC to AREA2 (IUT outside) is
/// line forwarded to the greedy next hop B.
#[test]
fn tp_geonw_pon_gbc_nonarea_grd_bv_01() {
    nonarea_greedy_source(false);
}

/// TP/GEONW/PON/GBC/NONAREA/GRD/BV-02: a GBC from C to AREA2 is line
/// forwarded to B.
#[test]
fn tp_geonw_pon_gbc_nonarea_grd_bv_02() {
    nonarea_greedy_forwarder(false);
}

/// TP/GEONW/PON/GBC/NONAREA/GRD/BO-07: the same GBC received again (from D)
/// is not forwarded again.
#[test]
fn tp_geonw_pon_gbc_nonarea_grd_bo_07() {
    nonarea_greedy_duplicate(false);
}

/// TP/GEONW/PON/GBC/NONAREA/CBF/BV-01: with CBF a source GBC to AREA2 is
/// broadcast immediately.
#[test]
fn tp_geonw_pon_gbc_nonarea_cbf_bv_01() {
    nonarea_cbf_source(false);
}

/// TP/GEONW/PON/GBC/NONAREA/CBF/BV-02: a GBC from C towards A is re-broadcast
/// when the CBF timer of its progress (400 m) expires.
#[test]
fn tp_geonw_pon_gbc_nonarea_cbf_bv_02() {
    nonarea_cbf_timer(false);
}

/// TP/GEONW/PON/GBC/NONAREA/CBF/BV-07: the same GBC heard from B (a better
/// forwarder) before the CBF timer expires cancels the re-broadcast.
#[test]
fn tp_geonw_pon_gbc_nonarea_cbf_bv_07() {
    nonarea_cbf_better_forwarder(false);
}

/// TP/GEONW/PON/GBC/NONAREA/CBF/BV-20: with a progress beyond
/// itsGnDefaultMaxCommunicationRange (1100 m) the GBC is re-broadcast when
/// the CBF timer of the second segment expires (TS 103 836-4-1 V2.2.1 clause
/// E.3.2.2; the Release 1 TP expects itsGnCbfMinTime).
#[test]
fn tp_geonw_pon_gbc_nonarea_cbf_bv_20() {
    nonarea_cbf_second_segment(false);
}

/// TP/GEONW/PON/GBC/NONAREA/CBF/BV-21: a GBC from an unknown sender D (IUT
/// outside AREA2) is re-broadcast after CBF_MAX.
#[test]
fn tp_geonw_pon_gbc_nonarea_cbf_bv_21() {
    nonarea_cbf_unknown_sender(false);
}

/// TP/GEONW/PON/GBC/NONAREA/CBF/BV-22: a GBC from a sender D with PAI = 0
/// (IUT outside AREA2) is re-broadcast after CBF_MAX.
#[test]
fn tp_geonw_pon_gbc_nonarea_cbf_bv_22() {
    nonarea_cbf_sender_pai_0(false);
}

/// TP/GEONW/PON/GBC/AREA/ALL/BV-01: a source GBC to AREA1 (IUT inside) is
/// broadcast immediately.
#[test]
fn tp_geonw_pon_gbc_area_all_bv_01() {
    area_source(false);
}

/// TP/GEONW/PON/GBC/AREA/ALL/BV-03: a GBC to AREA1 is retransmitted with RHL
/// - 1 and the same MHL.
#[test]
fn tp_geonw_pon_gbc_area_all_bv_03() {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.receive(&gbc(&lpv(B), 2, area1(), false, &rhl_mhl(7, 9, true)), B);
    iut.at(500);
    let f = iut.sent(HeaderType::GeoBroadcast)[0];
    assert_eq!((f.basic.rhl, f.common.mhl), (6, 9));
}

/// TP/GEONW/PON/GBC/AREA/ALL/BV-04: a GBC to AREA1 with RHL 1 is not
/// retransmitted.
#[test]
fn tp_geonw_pon_gbc_area_all_bv_04() {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.receive(&gbc(&lpv(B), 2, area1(), false, &rhl_mhl(1, 10, true)), B);
    iut.at(500);
    assert!(iut.sent(HeaderType::GeoBroadcast).is_empty());
}

/// TP/GEONW/PON/GBC/AREA/ALL/BV-05: a GBC received inside its area is passed
/// to the right upper protocol.
#[test]
fn tp_geonw_pon_gbc_area_all_bv_05() {
    area_passed_up(false);
}

/// TP/GEONW/PON/GBC/AREA/ALL/BO-08: the same GBC received again (from D) is
/// not passed up again.
#[test]
fn tp_geonw_pon_gbc_area_all_bo_08() {
    area_duplicate_not_passed_up(false);
}

fn simple_iut() -> Iut {
    let mut iut = Iut::with(
        |m| m.itsGnAreaForwardingAlgorithm = AreaForwardingAlgorithm::Simple,
        false,
    );
    iut.beacons_from(&[D, B]);
    iut
}

/// TP/GEONW/PON/GBC/AREA/SMP/BV-02: with Simple forwarding a GBC received
/// inside its area is re-broadcast immediately.
#[test]
fn tp_geonw_pon_gbc_area_smp_bv_02() {
    let mut iut = simple_iut();
    iut.receive(&gbc(&lpv(B), 2, area1(), false, &scf()), B);
    let frames = iut.sent(HeaderType::GeoBroadcast);
    assert_eq!(frames.len(), 1);
    assert_eq!((frames[0].at, frames[0].destination), (0, None));
}

/// TP/GEONW/PON/GBC/AREA/SMP/BO-07: the same GBC received again (from D) is
/// not re-broadcast again.
#[test]
fn tp_geonw_pon_gbc_area_smp_bo_07() {
    let mut iut = simple_iut();
    let packet = gbc(&lpv(B), 2, area1(), false, &scf());
    iut.receive(&packet, B);
    iut.receive(&with_rhl(&packet, 4), D);
    assert_eq!(iut.sent(HeaderType::GeoBroadcast).len(), 1);
}

fn area_cbf_time(iut: &mut Iut, sender: u8) -> u64 {
    iut.receive(&gbc(&lpv(C), 2, area1(), false, &scf()), sender);
    assert!(iut.sent(HeaderType::GeoBroadcast).is_empty());
    iut.at(500);
    let frames = iut.sent(HeaderType::GeoBroadcast);
    assert_eq!(frames.len(), 1);
    frames[0].at
}

/// TP/GEONW/PON/GBC/AREA/CBF/BV-02: a GBC from a known sender C inside the
/// area is buffered and re-broadcast when the contention timer (distance 400
/// m) expires.
#[test]
fn tp_geonw_pon_gbc_area_cbf_bv_02() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, D, C]);
    let at = area_cbf_time(&mut iut, C);
    assert!(close_to(at, cbf_timeout_ms(400.0, &iut.router.mib)), "{at}");
}

/// TP/GEONW/PON/GBC/AREA/CBF/BV-07: the same GBC received from D while
/// buffered is removed from the CBF buffer and not re-broadcast.
#[test]
fn tp_geonw_pon_gbc_area_cbf_bv_07() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, D]);
    let packet = gbc(&lpv(C), 2, area1(), false, &scf());
    iut.receive(&packet, C);
    iut.at(20);
    iut.receive(&with_rhl(&packet, 4), D);
    iut.at(500);
    assert!(iut.sent(HeaderType::GeoBroadcast).is_empty());
}

/// TP/GEONW/PON/GBC/AREA/CBF/BV-21: a GBC from an unknown sender D inside the
/// area is re-broadcast after CBF_MAX.
#[test]
fn tp_geonw_pon_gbc_area_cbf_bv_21() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    let at = area_cbf_time(&mut iut, D);
    assert!(
        close_to(at, f64::from(iut.router.mib.itsGnCbfMaxTime)),
        "{at}"
    );
}

/// TP/GEONW/PON/GBC/AREA/CBF/BV-22: a GBC from a sender D with PAI = 0 inside
/// the area is re-broadcast after CBF_MAX.
#[test]
fn tp_geonw_pon_gbc_area_cbf_bv_22() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B]);
    iut.receive(&beacon(D, false), D);
    let at = area_cbf_time(&mut iut, D);
    assert!(
        close_to(at, f64::from(iut.router.mib.itsGnCbfMaxTime)),
        "{at}"
    );
}

// ── TP/GEONW/PON/GAC: GeoAnycast ────────────────────────────────────────────

/// TP/GEONW/PON/GAC/NONAREA/ALL/BV-03: a forwarded GAC (AREA2) has RHL - 1,
/// the same MHL and the same destination area.
#[test]
fn tp_geonw_pon_gac_nonarea_all_bv_03() {
    nonarea_retransmission(true);
}

/// TP/GEONW/PON/GAC/NONAREA/ALL/BO-04: a GAC with RHL 1 is not retransmitted.
#[test]
fn tp_geonw_pon_gac_nonarea_all_bo_04() {
    nonarea_rhl_one(true);
}

/// TP/GEONW/PON/GAC/NONAREA/ALL/BV-06: a GAC received outside its area
/// (AREA2) is not passed up.
#[test]
fn tp_geonw_pon_gac_nonarea_all_bv_06() {
    nonarea_not_passed_up(true);
}

/// TP/GEONW/PON/GAC/NONAREA/ALL/BO-09: a GAC with an area larger than
/// itsGnMaxGeoAreaSize is not retransmitted (clause B.3).
#[test]
fn tp_geonw_pon_gac_nonarea_all_bo_09() {
    nonarea_too_big(true);
}

/// TP/GEONW/PON/GAC/NONAREA/ALL/BV-10: a GAC from a known sender D inside
/// AREA2, received by the IUT outside AREA2, is discarded (Annex D).
#[test]
fn tp_geonw_pon_gac_nonarea_all_bv_10() {
    nonarea_sender_inside(true);
}

/// TP/GEONW/PON/GAC/NONAREA/GRD/BV-01: a source GAC to AREA2 (IUT outside) is
/// line forwarded to the greedy next hop B.
#[test]
fn tp_geonw_pon_gac_nonarea_grd_bv_01() {
    nonarea_greedy_source(true);
}

/// TP/GEONW/PON/GAC/NONAREA/GRD/BV-02: a GAC from C to AREA2 is line
/// forwarded to B.
#[test]
fn tp_geonw_pon_gac_nonarea_grd_bv_02() {
    nonarea_greedy_forwarder(true);
}

/// TP/GEONW/PON/GAC/NONAREA/GRD/BO-07: the same GAC received again is not
/// forwarded again.
#[test]
fn tp_geonw_pon_gac_nonarea_grd_bo_07() {
    nonarea_greedy_duplicate(true);
}

/// TP/GEONW/PON/GAC/NONAREA/CBF/BV-01: with CBF a source GAC to AREA2 is
/// broadcast immediately.
#[test]
fn tp_geonw_pon_gac_nonarea_cbf_bv_01() {
    nonarea_cbf_source(true);
}

/// TP/GEONW/PON/GAC/NONAREA/CBF/BV-02: a GAC from C towards A is re-broadcast
/// when the CBF timer of its progress (400 m) expires.
#[test]
fn tp_geonw_pon_gac_nonarea_cbf_bv_02() {
    nonarea_cbf_timer(true);
}

/// TP/GEONW/PON/GAC/NONAREA/CBF/BV-07: the same GAC heard from B (a better
/// forwarder) before the CBF timer expires cancels the re-broadcast.
#[test]
fn tp_geonw_pon_gac_nonarea_cbf_bv_07() {
    nonarea_cbf_better_forwarder(true);
}

/// TP/GEONW/PON/GAC/NONAREA/CBF/BV-20: with a progress beyond
/// itsGnDefaultMaxCommunicationRange (1100 m) the GAC is re-broadcast when
/// the CBF timer of the second segment expires (TS 103 836-4-1 V2.2.1 clause
/// E.3.2.2; the Release 1 TP expects itsGnCbfMinTime).
#[test]
fn tp_geonw_pon_gac_nonarea_cbf_bv_20() {
    nonarea_cbf_second_segment(true);
}

/// TP/GEONW/PON/GAC/NONAREA/CBF/BV-21: a GAC from an unknown sender D (IUT
/// outside AREA2) is re-broadcast after CBF_MAX.
#[test]
fn tp_geonw_pon_gac_nonarea_cbf_bv_21() {
    nonarea_cbf_unknown_sender(true);
}

/// TP/GEONW/PON/GAC/NONAREA/CBF/BV-22: a GAC from a sender D with PAI = 0
/// (IUT outside AREA2) is re-broadcast after CBF_MAX.
#[test]
fn tp_geonw_pon_gac_nonarea_cbf_bv_22() {
    nonarea_cbf_sender_pai_0(true);
}

/// TP/GEONW/PON/GAC/AREA/ALL/BV-01: a source GAC to AREA1 (IUT inside) is
/// broadcast immediately.
#[test]
fn tp_geonw_pon_gac_area_all_bv_01() {
    area_source(true);
}

/// TP/GEONW/PON/GAC/AREA/ALL/BV-02: a GAC received inside its area is neither
/// forwarded nor re-broadcast.
#[test]
fn tp_geonw_pon_gac_area_all_bv_02() {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.receive(&gbc(&lpv(B), 2, area1(), true, &scf()), B);
    iut.at(500);
    assert!(iut.sent(HeaderType::GeoAnycast).is_empty());
}

/// TP/GEONW/PON/GAC/AREA/ALL/BV-05: a GAC received inside its area is passed
/// to the right upper protocol.
#[test]
fn tp_geonw_pon_gac_area_all_bv_05() {
    area_passed_up(true);
}

/// TP/GEONW/PON/GAC/AREA/ALL/BO-08: the same GAC received again is not passed
/// up again.
#[test]
fn tp_geonw_pon_gac_area_all_bo_08() {
    area_duplicate_not_passed_up(true);
}

// ── TP/GEONW/PON/TSB: Topologically-Scoped Broadcast ────────────────────────

/// TP/GEONW/PON/TSB/BV-01: a TSB request is broadcast as a TSB packet.
#[test]
fn tp_geonw_pon_tsb_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[B, D]);
    iut.request_tsb();
    let frames = iut.sent(HeaderType::Tsb);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].common.hst,
        HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop)
    );
    assert_eq!(frames[0].destination, None);
}

/// TP/GEONW/PON/TSB/BV-02: a TSB with RHL > 1 received for the first time is
/// re-broadcast.
#[test]
fn tp_geonw_pon_tsb_bv_02() {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.receive(&tsb(&lpv(C), 4, &Pkt::default()), C);
    let frames = iut.sent(HeaderType::Tsb);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].destination, None);
}

/// TP/GEONW/PON/TSB/BV-03: the re-broadcast TSB has RHL - 1 and the same MHL.
#[test]
fn tp_geonw_pon_tsb_bv_03() {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.receive(&tsb(&lpv(C), 4, &rhl_mhl(7, 9, false)), C);
    let f = iut.sent(HeaderType::Tsb)[0];
    assert_eq!((f.basic.rhl, f.common.mhl), (6, 9));
}

/// TP/GEONW/PON/TSB/BO-04: a TSB with RHL 1 is not re-broadcast.
#[test]
fn tp_geonw_pon_tsb_bo_04() {
    let mut iut = Iut::new();
    iut.receive(&tsb(&lpv(C), 4, &rhl_mhl(1, 10, false)), C);
    assert!(iut.sent(HeaderType::Tsb).is_empty());
}

/// TP/GEONW/PON/TSB/BV-05: a TSB received for the first time is passed to the
/// right upper protocol.
#[test]
fn tp_geonw_pon_tsb_bv_05() {
    let mut iut = Iut::new();
    let p = Pkt {
        payload: b"tsb!".to_vec(),
        ..Default::default()
    };
    iut.receive(&tsb(&lpv(C), 4, &p), C);
    assert_eq!(iut.indications.len(), 1);
    assert_eq!(iut.indications[0].upper_protocol_entity, CommonNH::BtpB);
    assert_eq!(iut.indications[0].data, b"tsb!");
}

/// TP/GEONW/PON/TSB/BO-07: the same TSB received again (from D, RHL - 1) is
/// not re-broadcast again.
#[test]
fn tp_geonw_pon_tsb_bo_07() {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    let packet = tsb(&lpv(B), 4, &Pkt::default());
    iut.receive(&packet, B);
    iut.receive(&with_rhl(&packet, 4), D);
    assert_eq!(iut.sent(HeaderType::Tsb).len(), 1);
}

/// TP/GEONW/PON/TSB/BO-08: the same TSB received again (from D) is not passed
/// up again.
#[test]
fn tp_geonw_pon_tsb_bo_08() {
    let mut iut = Iut::new();
    let packet = tsb(&lpv(B), 4, &Pkt::default());
    iut.receive(&packet, B);
    iut.receive(&with_rhl(&packet, 4), D);
    assert_eq!(iut.indications.len(), 1);
}

// ── TP/GEONW/PON/SHB: Single-Hop Broadcast ──────────────────────────────────

/// TP/GEONW/PON/SHB/BV-01: an SHB request is broadcast as an SHB packet.
#[test]
fn tp_geonw_pon_shb_bv_01() {
    let mut iut = Iut::new();
    iut.beacons_from(&[D, B]);
    iut.request_shb(b"shb");
    let frames = iut.sent(HeaderType::Tsb);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].common.hst,
        HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop)
    );
    assert_eq!(frames[0].destination, None);
}

/// TP/GEONW/PON/SHB/BV-05: a received SHB is passed to the upper layer.
#[test]
fn tp_geonw_pon_shb_bv_05() {
    let mut iut = Iut::new();
    iut.receive(&shb_full(&lpv(B), b"hello", [0; 4], 1), B);
    assert_eq!(iut.indications.len(), 1);
    assert_eq!(iut.indications[0].upper_protocol_entity, CommonNH::BtpB);
    assert_eq!(iut.indications[0].data, b"hello");
}

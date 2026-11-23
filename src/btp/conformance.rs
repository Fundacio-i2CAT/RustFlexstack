// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ETSI TS 102 870-2 V1.2.1 (2022-03) test purposes of the Basic Transport
//! Protocol, one test per TP, on complete stations: the BTP router on a
//! GeoNetworking router whose link layer is captured, frames decoded from the
//! wire. The receiving IUT gets the frame sent by a second station (the test
//! system). Mirrors FlexStack `tests/flexstack/btp/test_btp_conformance.py`.
//!
//! Frame of an unsecured SHB: Basic Header (4) | Common Header (8) | SHB
//! Extended Header (24 + 4) | BTP header (4) | payload. The Common Header NH is
//! 1 for BTP-A and 2 for BTP-B (ETSI TS 103 836-4-1 V2.2.1 table 9).

use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use super::btp_header::{BTPAHeader, BTPBHeader};
use super::router::{BTPRouterHandle, Router as BtpRouter};
use super::service_access_point::{BTPDataIndication, BTPDataRequest};
use crate::geonet::basic_header::{BasicHeader, BasicNH};
use crate::geonet::common_header::CommonHeader;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::mib::Mib;
use crate::geonet::router::Router as GnRouter;
use crate::geonet::service_access_point::{
    CommonNH, GNDataIndication, GNDataRequest, HeaderSubType, HeaderType, PacketTransportType,
    TopoBroadcastHST,
};

const SOURCE_PORT: u16 = 5000;
const DESTINATION_PORT: u16 = 2001;
const DESTINATION_PORT_INFO: u16 = 0x1234;
const PAYLOAD: &[u8] = b"upper layer payload";
/// Basic, Common and SHB Extended Header.
const HEADERS: usize = 4 + 8 + 28;

/// BTP on a GeoNetworking router (security disabled), the indications of
/// DESTINATION_PORT collected.
struct Station {
    addr: GNAddress,
    gn: GnRouter,
    ll_rx: Receiver<Vec<u8>>,
    gn_btp_rx: Receiver<GNDataIndication>,
    btp: BTPRouterHandle,
    btp_gn_rx: Receiver<GNDataRequest>,
    port_rx: Receiver<BTPDataIndication>,
}

impl Station {
    fn new(n: u8) -> Station {
        let addr = GNAddress::new(M::GnUnicast, ST::Unknown, MID::new([2, 0, 0, 0, 0, n]));
        let mut mib = Mib::new();
        mib.itsGnLocalGnAddr = addr;
        mib.itsGnBeaconServiceRetransmitTimer = 0;
        let (ll_tx, ll_rx) = mpsc::channel();
        let (gn_btp_tx, gn_btp_rx) = mpsc::channel();
        let mut gn = GnRouter::new(mib, ll_tx, gn_btp_tx, None, None, None);
        gn.ego_position_vector.latitude = 415_520_000;
        gn.ego_position_vector.longitude = 21_340_000;
        gn.ego_position_vector.pai = true;
        let (btp, btp_gn_rx) = BtpRouter::spawn(mib);
        let (port_tx, port_rx) = mpsc::channel();
        btp.register_port(DESTINATION_PORT, port_tx);
        Station {
            addr,
            gn,
            ll_rx,
            gn_btp_rx,
            btp,
            btp_gn_rx,
            port_rx,
        }
    }

    /// A BTP-data request (SHB); the frame sent.
    fn send(
        &mut self,
        btp_type: CommonNH,
        source_port: u16,
        destination_port_info: u16,
    ) -> Vec<u8> {
        self.send_request(BTPDataRequest {
            btp_type,
            source_port,
            destination_port_info,
            ..shb_request()
        })
    }

    /// The BTP-data request `request`; the frame sent.
    fn send_request(&mut self, request: BTPDataRequest) -> Vec<u8> {
        self.btp.send_btp_data_request(request);
        let request = self
            .btp_gn_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("GN-DATA.request from BTP");
        self.gn.gn_data_request(request);
        self.ll_rx.try_recv().expect("frame sent")
    }

    /// A frame from the radio: GN -> BTP; the indications of DESTINATION_PORT.
    fn deliver(&mut self, frame: &[u8]) -> Vec<BTPDataIndication> {
        self.gn.process_basic_header(frame);
        let mut received = vec![];
        while let Ok(indication) = self.gn_btp_rx.try_recv() {
            self.btp.send_gn_data_indication(indication);
            if let Ok(btp) = self.port_rx.recv_timeout(Duration::from_secs(2)) {
                received.push(btp);
            }
        }
        received
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        self.btp.clone().shutdown();
    }
}

/// A BTP-B request to DESTINATION_PORT carrying PAYLOAD in a SHB.
fn shb_request() -> BTPDataRequest {
    BTPDataRequest {
        btp_type: CommonNH::BtpB,
        destination_port: DESTINATION_PORT,
        gn_packet_transport_type: PacketTransportType {
            header_type: HeaderType::Tsb,
            header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
        },
        length: PAYLOAD.len() as u16,
        data: PAYLOAD.to_vec(),
        ..BTPDataRequest::new()
    }
}

/// (Common Header, BTP header, payload) of an unsecured SHB frame.
fn decode(frame: &[u8]) -> (CommonHeader, [u8; 4], Vec<u8>) {
    let basic = BasicHeader::decode(frame[0..4].try_into().unwrap());
    assert!(matches!(basic.nh, BasicNH::CommonHeader));
    let common = CommonHeader::decode(frame[4..12].try_into().unwrap());
    (
        common,
        frame[HEADERS..HEADERS + 4].try_into().unwrap(),
        frame[HEADERS + 4..].to_vec(),
    )
}

fn same(a: &GNAddress, b: &GNAddress) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

// ── TP/BTP/PGA and TP/BTP/PGB: packet generation ─────────────────────────────

/// TP/BTP/PGA/BV/01: a BTP-data request of type BTP-A with SOURCE_PORT and
/// DESTINATION_PORT gives a BTP-A packet with these ports and the payload.
#[test]
fn tp_btp_pga_bv_01() {
    let frame = Station::new(1).send(CommonNH::BtpA, SOURCE_PORT, 0);
    let (common, header, payload) = decode(&frame);
    assert_eq!(common.nh, CommonNH::BtpA);
    let btp = BTPAHeader::decode(header);
    assert_eq!(
        (btp.destination_port(), btp.source_port()),
        (DESTINATION_PORT, SOURCE_PORT)
    );
    assert_eq!(payload, PAYLOAD);
    assert_eq!(common.pl as usize, 4 + PAYLOAD.len());
}

/// TP/BTP/PGB/BV/01: a BTP-data request of type BTP-B with DESTINATION_PORT and
/// DESTINATION_PORT_INFO gives a BTP-B packet with both and the payload.
#[test]
fn tp_btp_pgb_bv_01() {
    let frame = Station::new(1).send(CommonNH::BtpB, 0, DESTINATION_PORT_INFO);
    let (common, header, payload) = decode(&frame);
    assert_eq!(common.nh, CommonNH::BtpB);
    let btp = BTPBHeader::decode(header);
    assert_eq!(
        (btp.destination_port, btp.destination_port_info),
        (DESTINATION_PORT, DESTINATION_PORT_INFO)
    );
    assert_eq!(payload, PAYLOAD);
    assert_eq!(common.pl as usize, 4 + PAYLOAD.len());
}

/// TP/BTP/PGB/BV/02: a BTP-B request without Destination Port Info gives a
/// BTP-B packet whose destination port info is 0.
#[test]
fn tp_btp_pgb_bv_02() {
    let frame = Station::new(1).send(CommonNH::BtpB, 0, 0);
    let (common, header, payload) = decode(&frame);
    assert_eq!(common.nh, CommonNH::BtpB);
    let mut expected = DESTINATION_PORT.to_be_bytes().to_vec();
    expected.extend([0, 0]);
    assert_eq!(header.to_vec(), expected);
    assert_eq!(payload, PAYLOAD);
}

// ── TP/BTP/PP: packet processing ─────────────────────────────────────────────

/// TP/BTP/PP/BV/01: a valid BTP-A packet (SOURCE_PORT, DESTINATION_PORT,
/// payload) received by the IUT is passed to the upper layer of DESTINATION_PORT.
#[test]
fn tp_btp_pp_bv_01() {
    let (mut tester, mut iut) = (Station::new(9), Station::new(1));
    let frame = tester.send(CommonNH::BtpA, SOURCE_PORT, 0);
    let received = iut.deliver(&frame);
    assert_eq!(received.len(), 1);
    let indication = &received[0];
    assert_eq!(
        (indication.source_port, indication.destination_port),
        (SOURCE_PORT, DESTINATION_PORT)
    );
    assert_eq!(indication.data, PAYLOAD);
    assert!(same(
        &indication.gn_source_position_vector.gn_addr,
        &tester.addr
    ));
}

/// TP/BTP/PP/BV/02: a valid BTP-B packet (DESTINATION_PORT,
/// DESTINATION_PORT_INFO, payload) received by the IUT is passed to the upper
/// protocol of DESTINATION_PORT.
#[test]
fn tp_btp_pp_bv_02() {
    let (mut tester, mut iut) = (Station::new(9), Station::new(1));
    let frame = tester.send(CommonNH::BtpB, 0, DESTINATION_PORT_INFO);
    let received = iut.deliver(&frame);
    assert_eq!(received.len(), 1);
    let indication = &received[0];
    assert_eq!(
        (
            indication.destination_port,
            indication.destination_port_info
        ),
        (DESTINATION_PORT, DESTINATION_PORT_INFO)
    );
    assert_eq!(indication.data, PAYLOAD);
    assert!(same(
        &indication.gn_source_position_vector.gn_addr,
        &tester.addr
    ));
}

// ── EN 302 636-5-1 V2.2.1 clauses 8.2 and 8.3 (service primitives, no TP) ────

/// Table 6: packet transport type, destination area, traffic class, maximum
/// packet lifetime and maximum hop limit; Length = ITS-FSDU + 4.
#[test]
fn source_operations_pass_the_gn_parameters() {
    use crate::geonet::gbc_extended_header::GBCExtendedHeader;
    use crate::geonet::service_access_point::{Area, GeoBroadcastHST, TrafficClass};
    let frame = Station::new(1).send_request(BTPDataRequest {
        gn_packet_transport_type: PacketTransportType {
            header_type: HeaderType::GeoBroadcast,
            header_sub_type: HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle),
        },
        gn_area: Area {
            latitude: 415_520_000,
            longitude: 21_340_000,
            a: 500,
            b: 0,
            angle: 0,
        },
        traffic_class: TrafficClass {
            scf: false,
            channel_offload: true,
            tc_id: 3,
        },
        gn_max_packet_lifetime: Some(5.0),
        gn_max_hop_limit: 4,
        ..shb_request()
    });
    let basic = BasicHeader::decode(frame[0..4].try_into().unwrap());
    let common = CommonHeader::decode(frame[4..12].try_into().unwrap());
    let gbc = GBCExtendedHeader::decode(frame[12..56].try_into().unwrap());
    assert_eq!(common.ht, HeaderType::GeoBroadcast);
    assert_eq!(common.nh, CommonNH::BtpB);
    assert_eq!((common.tc.channel_offload, common.tc.tc_id), (true, 3));
    assert_eq!(common.mhl, 4);
    assert_eq!(basic.lt.get_value_in_seconds(), 5);
    assert_eq!((gbc.latitude, gbc.a), (415_520_000, 500));
    assert_eq!(common.pl as usize, PAYLOAD.len() + 4);
    let mut btp = DESTINATION_PORT.to_be_bytes().to_vec();
    btp.extend([0, 0]);
    assert_eq!(frame[56..60].to_vec(), btp);
}

/// Table 6: GN Destination address of a GeoUnicast; table 7: the indication
/// carries the destination the packet was generated with.
#[test]
fn geounicast_destination_address() {
    use crate::geonet::service_access_point::UnspecifiedHST;
    let (mut tester, mut iut) = (Station::new(9), Station::new(1));
    let hello = iut.send(CommonNH::BtpB, 0, 0);
    tester.deliver(&hello); // the tester learns the IUT
    let frame = tester.send_request(BTPDataRequest {
        btp_type: CommonNH::BtpA,
        source_port: SOURCE_PORT,
        gn_destination_address: iut.addr,
        gn_packet_transport_type: PacketTransportType {
            header_type: HeaderType::GeoUnicast,
            header_sub_type: HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
        },
        ..shb_request()
    });
    let common = CommonHeader::decode(frame[4..12].try_into().unwrap());
    assert_eq!(common.ht, HeaderType::GeoUnicast);
    let received = iut.deliver(&frame);
    assert_eq!(received.len(), 1);
    let indication = &received[0];
    assert_eq!(
        indication.gn_packet_transport_type.header_type,
        HeaderType::GeoUnicast
    );
    assert!(same(&indication.gn_destination_address, &iut.addr));
    assert_eq!(indication.source_port, SOURCE_PORT);
    assert_eq!(indication.data, PAYLOAD);
}

/// Table 7: packet transport type, source position vector, traffic class,
/// remaining packet lifetime, no security report; Length = GN-PDU payload - 4.
#[test]
fn destination_operations_pass_the_gn_parameters() {
    use crate::geonet::service_access_point::TrafficClass;
    let (mut tester, mut iut) = (Station::new(9), Station::new(1));
    let frame = tester.send_request(BTPDataRequest {
        traffic_class: TrafficClass {
            scf: false,
            channel_offload: false,
            tc_id: 2,
        },
        gn_max_packet_lifetime: Some(10.0),
        ..shb_request()
    });
    let received = iut.deliver(&frame);
    let indication = &received[0];
    assert_eq!(
        indication.gn_packet_transport_type.header_type,
        HeaderType::Tsb
    );
    assert!(same(
        &indication.gn_source_position_vector.gn_addr,
        &tester.addr
    ));
    assert_eq!(indication.gn_traffic_class.tc_id, 2);
    assert_eq!(indication.gn_remaining_packet_lifetime, Some(10.0));
    assert!(indication.gn_security_report.is_none());
    assert_eq!(indication.length as usize, PAYLOAD.len());
    assert_eq!(indication.data, PAYLOAD);
}

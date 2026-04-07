// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use super::gn_address::GNAddress;
use super::position_vector::LongPositionVector;
use crate::security::sn_sap::SecurityProfile;

#[derive(Clone, PartialEq, Debug)]
pub enum CommonNH {
    Any,
    BtpA,
    BtpB,
    IpV6,
}

impl CommonNH {
    pub fn decode(value: u8) -> Self {
        match value {
            0 => CommonNH::Any,
            1 => CommonNH::BtpA,
            2 => CommonNH::BtpB,
            3 => CommonNH::IpV6,
            _ => panic!("Invalid Next Header Value!"),
        }
    }

    pub fn encode(&self) -> u8 {
        match self {
            CommonNH::Any => 0,
            CommonNH::BtpA => 1,
            CommonNH::BtpB => 2,
            CommonNH::IpV6 => 3,
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum HeaderType {
    Any,
    Beacon,
    GeoUnicast,
    GeoAnycast,
    GeoBroadcast,
    Tsb,
    Ls,
}

impl HeaderType {
    pub fn decode(value: u8) -> Self {
        match value {
            0 => HeaderType::Any,
            1 => HeaderType::Beacon,
            2 => HeaderType::GeoUnicast,
            3 => HeaderType::GeoAnycast,
            4 => HeaderType::GeoBroadcast,
            5 => HeaderType::Tsb,
            6 => HeaderType::Ls,
            _ => panic!("Invalid Header Type Value!"),
        }
    }

    pub fn encode(&self) -> u8 {
        match self {
            HeaderType::Any => 0,
            HeaderType::Beacon => 1,
            HeaderType::GeoUnicast => 2,
            HeaderType::GeoAnycast => 3,
            HeaderType::GeoBroadcast => 4,
            HeaderType::Tsb => 5,
            HeaderType::Ls => 6,
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum HeaderSubType {
    Unspecified(UnspecifiedHST),
    GeoAnycast(GeoAnycastHST),
    GeoBroadcast(GeoBroadcastHST),
    TopoBroadcast(TopoBroadcastHST),
    LocationService(LocationServiceHST),
}

impl HeaderSubType {
    pub fn decode(header_type: &HeaderType, value: u8) -> Self {
        match header_type {
            HeaderType::Any => HeaderSubType::Unspecified(UnspecifiedHST::decode(value)),
            HeaderType::Beacon => HeaderSubType::Unspecified(UnspecifiedHST::decode(value)),
            HeaderType::GeoUnicast => HeaderSubType::Unspecified(UnspecifiedHST::decode(value)),
            HeaderType::GeoAnycast => HeaderSubType::GeoAnycast(GeoAnycastHST::decode(value)),
            HeaderType::GeoBroadcast => HeaderSubType::GeoBroadcast(GeoBroadcastHST::decode(value)),
            HeaderType::Tsb => HeaderSubType::TopoBroadcast(TopoBroadcastHST::decode(value)),
            HeaderType::Ls => HeaderSubType::LocationService(LocationServiceHST::decode(value)),
        }
    }

    pub fn encode(&self) -> u8 {
        match self {
            HeaderSubType::Unspecified(hst) => hst.encode(),
            HeaderSubType::GeoAnycast(hst) => hst.encode(),
            HeaderSubType::GeoBroadcast(hst) => hst.encode(),
            HeaderSubType::TopoBroadcast(hst) => hst.encode(),
            HeaderSubType::LocationService(hst) => hst.encode(),
        }
    }
}

#[derive(Clone, PartialEq, Copy, Debug)]
pub enum UnspecifiedHST {
    Unspecified,
}

impl UnspecifiedHST {
    pub fn decode(value: u8) -> Self {
        match value {
            0 => UnspecifiedHST::Unspecified,
            _ => panic!("Invalid Header Sub Type Value!"),
        }
    }

    pub fn encode(&self) -> u8 {
        match self {
            UnspecifiedHST::Unspecified => 0,
        }
    }
}

#[derive(Clone, PartialEq, Copy, Debug)]
pub enum GeoAnycastHST {
    GeoAnycastCircle,
    GeoAnycastRectangle,
    GeoAnycastEllipse,
}

impl GeoAnycastHST {
    pub fn encode(&self) -> u8 {
        match self {
            GeoAnycastHST::GeoAnycastCircle => 0,
            GeoAnycastHST::GeoAnycastRectangle => 1,
            GeoAnycastHST::GeoAnycastEllipse => 2,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => GeoAnycastHST::GeoAnycastCircle,
            1 => GeoAnycastHST::GeoAnycastRectangle,
            2 => GeoAnycastHST::GeoAnycastEllipse,
            _ => panic!("Invalid GeoAnycast Header Sub Type Value!"),
        }
    }
}

#[derive(Clone, PartialEq, Copy, Debug)]
pub enum GeoBroadcastHST {
    GeoBroadcastCircle,
    GeoBroadcastRectangle,
    GeoBroadcastEllipse,
}

impl GeoBroadcastHST {
    pub fn encode(&self) -> u8 {
        match self {
            GeoBroadcastHST::GeoBroadcastCircle => 0,
            GeoBroadcastHST::GeoBroadcastRectangle => 1,
            GeoBroadcastHST::GeoBroadcastEllipse => 2,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => GeoBroadcastHST::GeoBroadcastCircle,
            1 => GeoBroadcastHST::GeoBroadcastRectangle,
            2 => GeoBroadcastHST::GeoBroadcastEllipse,
            _ => panic!("Invalid GeoBroadcast Header Sub Type Value!"),
        }
    }
}

#[derive(Clone, PartialEq, Copy, Debug)]
pub enum TopoBroadcastHST {
    SingleHop,
    MultiHop,
}

impl TopoBroadcastHST {
    pub fn encode(&self) -> u8 {
        match self {
            TopoBroadcastHST::SingleHop => 0,
            TopoBroadcastHST::MultiHop => 1,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => TopoBroadcastHST::SingleHop,
            1 => TopoBroadcastHST::MultiHop,
            _ => panic!("Invalid TopoBroadcast Header Sub Type Value!"),
        }
    }
}

#[derive(Clone, PartialEq, Copy, Debug)]
pub enum LocationServiceHST {
    LsRequest,
    LsReply,
}

impl LocationServiceHST {
    pub fn encode(&self) -> u8 {
        match self {
            LocationServiceHST::LsRequest => 0,
            LocationServiceHST::LsReply => 1,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => LocationServiceHST::LsRequest,
            1 => LocationServiceHST::LsReply,
            _ => panic!("Invalid LocationService Header Sub Type Value!"),
        }
    }
}

#[derive(Clone, PartialEq, Copy, Debug)]
pub struct TrafficClass {
    pub scf: bool,
    pub channel_offload: bool,
    pub tc_id: u8,
}

impl TrafficClass {
    pub fn encode(&self) -> u8 {
        let mut value: u8 = 0;
        if self.scf {
            value |= 0b1000_0000;
        }
        if self.channel_offload {
            value |= 0b0100_0000;
        }
        value |= self.tc_id & 0b0011_1111;
        value
    }

    pub fn decode(value: u8) -> Self {
        let scf = value & 0b1000_0000 != 0;
        let channel_offload = value & 0b0100_0000 != 0;
        let tc_id = value & 0b0011_1111;
        TrafficClass {
            scf,
            channel_offload,
            tc_id,
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct PacketTransportType {
    pub header_type: HeaderType,
    pub header_sub_type: HeaderSubType,
}

#[derive(Clone, PartialEq)]
pub enum CommunicationProfile {
    Unspecified,
}

#[derive(Clone, PartialEq, Copy, Debug)]
pub struct Area {
    pub latitude: u32,
    pub longitude: u32,
    pub a: u16,
    pub b: u16,
    pub angle: u16,
}

pub struct GNDataRequest {
    pub upper_protocol_entity: CommonNH,
    pub packet_transport_type: PacketTransportType,
    pub communication_profile: CommunicationProfile,
    pub traffic_class: TrafficClass,
    pub security_profile: SecurityProfile,
    pub its_aid: u64,
    pub security_permissions: Vec<u8>,
    pub max_hop_limit: u8,
    pub max_packet_lifetime: Option<f64>,
    pub destination: Option<GNAddress>,
    pub length: u16,
    pub data: Vec<u8>,
    pub area: Area,
}

#[derive(Debug, PartialEq)]
pub enum ResultCode {
    Accepted,
    MaximumLengthExceeded,
    MaximumLifetimeExceeded,
    RepetitionIntervalTooSmall,
    UnsupportedTrafficClass,
    GeographicalScopeTooLarge,
    Unspecified,
}

pub struct GNDataConfirm {
    pub result_code: ResultCode,
}

pub struct GNDataIndication {
    pub upper_protocol_entity: CommonNH,
    pub packet_transport_type: PacketTransportType,
    pub source_position_vector: LongPositionVector,
    pub traffic_class: TrafficClass,
    pub destination_area: Option<Area>,
    pub remaining_packet_lifetime: Option<f64>,
    pub remaining_hop_limit: Option<u8>,
    pub length: u16,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CommonNH ──────────────────────────────────────────────────────

    #[test]
    fn common_nh_encode_decode_roundtrip() {
        for (nh, val) in [
            (CommonNH::Any, 0u8),
            (CommonNH::BtpA, 1),
            (CommonNH::BtpB, 2),
            (CommonNH::IpV6, 3),
        ] {
            assert_eq!(nh.encode(), val);
            assert_eq!(CommonNH::decode(val), nh);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid Next Header Value")]
    fn common_nh_decode_invalid() {
        CommonNH::decode(99);
    }

    // ── HeaderType ────────────────────────────────────────────────────

    #[test]
    fn header_type_encode_decode_roundtrip() {
        for (ht, val) in [
            (HeaderType::Any, 0u8),
            (HeaderType::Beacon, 1),
            (HeaderType::GeoUnicast, 2),
            (HeaderType::GeoAnycast, 3),
            (HeaderType::GeoBroadcast, 4),
            (HeaderType::Tsb, 5),
            (HeaderType::Ls, 6),
        ] {
            assert_eq!(ht.encode(), val);
            assert_eq!(HeaderType::decode(val), ht);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid Header Type Value")]
    fn header_type_decode_invalid() {
        HeaderType::decode(99);
    }

    // ── HeaderSubType ─────────────────────────────────────────────────

    #[test]
    fn header_sub_type_unspecified() {
        let hst = HeaderSubType::decode(&HeaderType::Any, 0);
        assert_eq!(hst.encode(), 0);
        assert!(matches!(hst, HeaderSubType::Unspecified(_)));
    }

    #[test]
    fn header_sub_type_geo_anycast() {
        for val in 0..3u8 {
            let hst = HeaderSubType::decode(&HeaderType::GeoAnycast, val);
            assert_eq!(hst.encode(), val);
            assert!(matches!(hst, HeaderSubType::GeoAnycast(_)));
        }
    }

    #[test]
    fn header_sub_type_geo_broadcast() {
        for val in 0..3u8 {
            let hst = HeaderSubType::decode(&HeaderType::GeoBroadcast, val);
            assert_eq!(hst.encode(), val);
            assert!(matches!(hst, HeaderSubType::GeoBroadcast(_)));
        }
    }

    #[test]
    fn header_sub_type_topo_broadcast() {
        let shb = HeaderSubType::decode(&HeaderType::Tsb, 0);
        assert!(matches!(
            shb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop)
        ));
        let mhb = HeaderSubType::decode(&HeaderType::Tsb, 1);
        assert!(matches!(
            mhb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop)
        ));
    }

    #[test]
    fn header_sub_type_location_service() {
        let req = HeaderSubType::decode(&HeaderType::Ls, 0);
        assert!(matches!(
            req,
            HeaderSubType::LocationService(LocationServiceHST::LsRequest)
        ));
        let rep = HeaderSubType::decode(&HeaderType::Ls, 1);
        assert!(matches!(
            rep,
            HeaderSubType::LocationService(LocationServiceHST::LsReply)
        ));
    }

    // ── TrafficClass ──────────────────────────────────────────────────

    #[test]
    fn traffic_class_encode_decode() {
        let tc = TrafficClass {
            scf: true,
            channel_offload: false,
            tc_id: 10,
        };
        let encoded = tc.encode();
        let decoded = TrafficClass::decode(encoded);
        assert_eq!(tc, decoded);
    }

    // ── GeoAnycastHST ─────────────────────────────────────────────────

    #[test]
    fn geo_anycast_hst_roundtrip() {
        for val in 0..3u8 {
            assert_eq!(GeoAnycastHST::decode(val).encode(), val);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid GeoAnycast Header Sub Type Value")]
    fn geo_anycast_hst_invalid() {
        GeoAnycastHST::decode(99);
    }

    // ── GeoBroadcastHST ───────────────────────────────────────────────

    #[test]
    fn geo_broadcast_hst_roundtrip() {
        for val in 0..3u8 {
            assert_eq!(GeoBroadcastHST::decode(val).encode(), val);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid GeoBroadcast Header Sub Type Value")]
    fn geo_broadcast_hst_invalid() {
        GeoBroadcastHST::decode(99);
    }

    // ── TopoBroadcastHST ──────────────────────────────────────────────

    #[test]
    fn topo_broadcast_hst_roundtrip() {
        assert_eq!(TopoBroadcastHST::SingleHop.encode(), 0);
        assert_eq!(TopoBroadcastHST::MultiHop.encode(), 1);
        assert_eq!(TopoBroadcastHST::decode(0).encode(), 0);
        assert_eq!(TopoBroadcastHST::decode(1).encode(), 1);
    }

    #[test]
    #[should_panic(expected = "Invalid TopoBroadcast Header Sub Type Value")]
    fn topo_broadcast_hst_invalid() {
        TopoBroadcastHST::decode(99);
    }

    // ── LocationServiceHST ────────────────────────────────────────────

    #[test]
    fn location_service_hst_roundtrip() {
        assert_eq!(LocationServiceHST::LsRequest.encode(), 0);
        assert_eq!(LocationServiceHST::LsReply.encode(), 1);
    }

    #[test]
    #[should_panic(expected = "Invalid LocationService Header Sub Type Value")]
    fn location_service_hst_invalid() {
        LocationServiceHST::decode(99);
    }
}

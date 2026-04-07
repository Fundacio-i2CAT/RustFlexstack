// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use super::mib::Mib;
use super::service_access_point::{
    CommonNH, GNDataRequest, HeaderSubType, HeaderType, TrafficClass, UnspecifiedHST,
};
use std::cmp::PartialEq;

#[derive(Debug)]
pub struct CommonHeader {
    pub nh: CommonNH,
    pub reserved: u8,
    pub ht: HeaderType,
    pub hst: HeaderSubType,
    pub tc: TrafficClass,
    pub flags: u8,
    pub pl: u16,
    pub mhl: u8,
    pub reserved2: u8,
}

impl CommonHeader {
    pub fn initialize_with_request(request: &GNDataRequest, mib: &Mib) -> Self {
        CommonHeader {
            nh: request.upper_protocol_entity.clone(),
            reserved: 0,
            ht: request.packet_transport_type.header_type.clone(),
            hst: request.packet_transport_type.header_sub_type.clone(),
            tc: request.traffic_class.clone(),
            flags: (mib.itsGnIsMobile.encode()) << 7,
            pl: request.length.clone(),
            mhl: request.max_hop_limit,
            reserved2: 0,
        }
    }

    pub fn initialize_beacon(mib: &Mib) -> Self {
        CommonHeader {
            nh: CommonNH::Any,
            reserved: 0,
            ht: HeaderType::Beacon,
            hst: HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
            tc: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            flags: (mib.itsGnIsMobile.encode()) << 7,
            pl: 0,
            mhl: 1,
            reserved2: 0,
        }
    }

    pub fn encode(&self) -> [u8; 8] {
        let mut bytes: [u8; 8] = [0; 8];
        bytes[0] = (self.nh.encode() << 4) | (self.reserved & 0b0000_1111);
        bytes[1] = (self.ht.encode() << 4) | (self.hst.encode() & 0b0000_1111);
        bytes[2] = self.tc.encode();
        bytes[3] = self.flags;
        bytes[4] = (self.pl >> 8) as u8;
        bytes[5] = self.pl as u8;
        bytes[6] = self.mhl;
        bytes[7] = self.reserved2;
        bytes
    }

    pub fn decode(bytes: [u8; 8]) -> Self {
        let header_type: HeaderType = HeaderType::decode(bytes[1] >> 4);
        CommonHeader {
            nh: CommonNH::decode(bytes[0] >> 4),
            reserved: bytes[0] & 0b0000_1111,
            ht: header_type.clone(),
            hst: HeaderSubType::decode(&header_type, bytes[1] & 0b0000_1111),
            tc: TrafficClass::decode(bytes[2]),
            flags: bytes[3],
            pl: ((bytes[4] as u16) << 8) | (bytes[5] as u16),
            mhl: bytes[6],
            reserved2: bytes[7],
        }
    }
}

impl PartialEq for CommonHeader {
    fn eq(&self, other: &Self) -> bool {
        self.nh == other.nh
            && self.reserved == other.reserved
            && self.ht == other.ht
            && self.hst == other.hst
            && self.tc == other.tc
            && self.flags == other.flags
            && self.pl == other.pl
            && self.mhl == other.mhl
            && self.reserved2 == other.reserved2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geonet::mib::Mib;
    use crate::geonet::service_access_point::{
        Area, CommonNH, CommunicationProfile, GNDataRequest, HeaderSubType, HeaderType,
        PacketTransportType, TopoBroadcastHST, TrafficClass,
    };
    use crate::security::sn_sap::SecurityProfile;

    fn make_gn_request() -> GNDataRequest {
        GNDataRequest {
            upper_protocol_entity: CommonNH::BtpB,
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            },
            communication_profile: CommunicationProfile::Unspecified,
            traffic_class: TrafficClass {
                scf: true,
                channel_offload: false,
                tc_id: 2,
            },
            security_profile: SecurityProfile::NoSecurity,
            its_aid: 36,
            security_permissions: vec![],
            max_hop_limit: 1,
            max_packet_lifetime: None,
            destination: None,
            length: 100,
            data: vec![0u8; 100],
            area: Area {
                latitude: 0,
                longitude: 0,
                a: 0,
                b: 0,
                angle: 0,
            },
        }
    }

    #[test]
    fn common_header_encode_decode_roundtrip() {
        let mib = Mib::new();
        let req = make_gn_request();
        let ch = CommonHeader::initialize_with_request(&req, &mib);
        let encoded = ch.encode();
        let decoded = CommonHeader::decode(encoded);
        assert_eq!(ch, decoded);
    }

    #[test]
    fn common_header_fields() {
        let mib = Mib::new();
        let req = make_gn_request();
        let ch = CommonHeader::initialize_with_request(&req, &mib);
        assert_eq!(ch.nh, CommonNH::BtpB);
        assert_eq!(ch.ht, HeaderType::Tsb);
        assert_eq!(ch.pl, 100);
        assert_eq!(ch.mhl, 1);
        assert!(ch.tc.scf);
        assert!(!ch.tc.channel_offload);
        assert_eq!(ch.tc.tc_id, 2);
    }

    #[test]
    fn common_header_beacon() {
        let mib = Mib::new();
        let ch = CommonHeader::initialize_beacon(&mib);
        assert_eq!(ch.nh, CommonNH::Any);
        assert_eq!(ch.ht, HeaderType::Beacon);
        assert_eq!(ch.pl, 0);
        assert_eq!(ch.mhl, 1);
    }

    #[test]
    fn common_header_nh_byte() {
        let mib = Mib::new();
        let req = make_gn_request();
        let ch = CommonHeader::initialize_with_request(&req, &mib);
        let bytes = ch.encode();
        // NH is upper nibble of byte 0: BtpB = 2 → 0x2X
        assert_eq!(bytes[0] >> 4, 2);
    }

    #[test]
    fn common_header_payload_length_encoding() {
        let mib = Mib::new();
        let mut req = make_gn_request();
        req.length = 1024;
        let ch = CommonHeader::initialize_with_request(&req, &mib);
        let bytes = ch.encode();
        let pl_decoded = (bytes[4] as u16) << 8 | bytes[5] as u16;
        assert_eq!(pl_decoded, 1024);
    }

    #[test]
    fn traffic_class_encode_decode() {
        let tc = TrafficClass {
            scf: true,
            channel_offload: true,
            tc_id: 0x3F,
        };
        let encoded = tc.encode();
        assert_eq!(encoded, 0xFF);
        let decoded = TrafficClass::decode(encoded);
        assert!(decoded.scf);
        assert!(decoded.channel_offload);
        assert_eq!(decoded.tc_id, 0x3F);
    }

    #[test]
    fn traffic_class_all_false() {
        let tc = TrafficClass {
            scf: false,
            channel_offload: false,
            tc_id: 0,
        };
        assert_eq!(tc.encode(), 0);
        let decoded = TrafficClass::decode(0);
        assert!(!decoded.scf);
        assert!(!decoded.channel_offload);
        assert_eq!(decoded.tc_id, 0);
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::position_vector::LongPositionVector;
use crate::geonet::service_access_point::{
    Area, CommonNH, CommunicationProfile, GNDataIndication, HeaderSubType, HeaderType,
    PacketTransportType, TrafficClass, UnspecifiedHST,
};
use crate::security::sn_sap::SecurityProfile;

/// BTP Data Request — ETSI EN 302 636-5-1 V2.2.1 Annex A.2.
pub struct BTPDataRequest {
    pub btp_type: CommonNH,
    pub source_port: u16,
    pub destination_port: u16,
    pub destination_port_info: u16,
    pub gn_packet_transport_type: PacketTransportType,
    pub gn_destination_address: GNAddress,
    pub gn_area: Area,
    pub gn_max_hop_limit: u8,
    pub gn_max_packet_lifetime: Option<f64>,
    pub gn_repetition_interval: Option<u32>,
    pub gn_max_repetition_time: Option<u32>,
    pub communication_profile: CommunicationProfile,
    pub traffic_class: TrafficClass,
    pub security_profile: SecurityProfile,
    pub its_aid: u64,
    pub security_permissions: Vec<u8>,
    pub destination: Option<GNAddress>,
    pub length: u16,
    pub data: Vec<u8>,
}

impl BTPDataRequest {
    pub fn new() -> Self {
        BTPDataRequest {
            btp_type: CommonNH::Any,
            source_port: 0,
            destination_port: 0,
            destination_port_info: 0,
            gn_packet_transport_type: PacketTransportType {
                header_type: HeaderType::Any,
                header_sub_type: HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
            },
            gn_destination_address: GNAddress {
                m: M::GnUnicast,
                st: ST::Unknown,
                mid: MID::new([0; 6]),
            },
            gn_area: Area {
                latitude: 0,
                longitude: 0,
                a: 0,
                b: 0,
                angle: 0,
            },
            gn_max_hop_limit: 1,
            gn_max_packet_lifetime: None,
            gn_repetition_interval: None,
            gn_max_repetition_time: None,
            communication_profile: CommunicationProfile::Unspecified,
            traffic_class: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            security_profile: SecurityProfile::NoSecurity,
            its_aid: 0,
            security_permissions: vec![],
            destination: None,
            length: 0,
            data: vec![],
        }
    }
}

/// BTP Data Indication — ETSI EN 302 636-5-1 V2.2.1 Annex A.3.
pub struct BTPDataIndication {
    pub source_port: u16,
    pub destination_port: u16,
    pub destination_port_info: u16,
    pub gn_packet_transport_type: PacketTransportType,
    pub gn_destination_address: GNAddress,
    pub gn_source_position_vector: LongPositionVector,
    pub gn_security_report: Option<Vec<u8>>,
    pub gn_certificate_id: Option<Vec<u8>>,
    pub gn_permissions: Option<Vec<u8>>,
    pub gn_traffic_class: TrafficClass,
    pub gn_remaining_packet_lifetime: Option<f64>,
    pub length: u16,
    pub data: Vec<u8>,
}

impl BTPDataIndication {
    pub fn new() -> Self {
        BTPDataIndication {
            source_port: 0,
            destination_port: 0,
            destination_port_info: 0,
            gn_packet_transport_type: PacketTransportType {
                header_type: HeaderType::Any,
                header_sub_type: HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
            },
            gn_destination_address: GNAddress {
                m: M::GnUnicast,
                st: ST::Unknown,
                mid: MID::new([0; 6]),
            },
            gn_source_position_vector: LongPositionVector::decode([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            gn_security_report: None,
            gn_certificate_id: None,
            gn_permissions: None,
            gn_traffic_class: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            gn_remaining_packet_lifetime: None,
            length: 0,
            data: vec![],
        }
    }

    /// Construct a BTPDataIndication from a GNDataIndication.
    /// Strips the first 4 bytes (BTP header) from the payload.
    pub fn initialize_with_gn_data_indication(
        gn_data_indication: &GNDataIndication,
    ) -> Self {
        let payload = if gn_data_indication.data.len() > 4 {
            gn_data_indication.data[4..].to_vec()
        } else {
            vec![]
        };
        BTPDataIndication {
            source_port: 0,
            destination_port: 0,
            destination_port_info: 0,
            gn_packet_transport_type: gn_data_indication.packet_transport_type.clone(),
            gn_destination_address: GNAddress {
                m: M::GnUnicast,
                st: ST::Unknown,
                mid: MID::new([0; 6]),
            },
            gn_source_position_vector: gn_data_indication.source_position_vector,
            gn_security_report: None,
            gn_certificate_id: None,
            gn_permissions: None,
            gn_traffic_class: gn_data_indication.traffic_class,
            gn_remaining_packet_lifetime: gn_data_indication.remaining_packet_lifetime,
            length: payload.len() as u16,
            data: payload,
        }
    }

    /// Return a new indication with the destination port and port info set.
    pub fn set_destination_port_and_info(
        self,
        destination_port: u16,
        destination_port_info: u16,
    ) -> Self {
        BTPDataIndication {
            destination_port,
            destination_port_info,
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geonet::service_access_point::{
        CommonNH, GNDataIndication, HeaderSubType, HeaderType, PacketTransportType,
        TopoBroadcastHST, TrafficClass,
    };
    use crate::geonet::position_vector::LongPositionVector;

    #[test]
    fn btp_data_request_default() {
        let req = BTPDataRequest::new();
        assert_eq!(req.source_port, 0);
        assert_eq!(req.destination_port, 0);
        assert_eq!(req.destination_port_info, 0);
        assert_eq!(req.gn_max_hop_limit, 1);
        assert_eq!(req.length, 0);
        assert!(req.data.is_empty());
        assert!(req.gn_max_packet_lifetime.is_none());
    }

    #[test]
    fn btp_data_indication_default() {
        let ind = BTPDataIndication::new();
        assert_eq!(ind.source_port, 0);
        assert_eq!(ind.destination_port, 0);
        assert_eq!(ind.length, 0);
        assert!(ind.data.is_empty());
        assert!(ind.gn_security_report.is_none());
    }

    #[test]
    fn btp_data_indication_set_port() {
        let ind = BTPDataIndication::new();
        let updated = ind.set_destination_port_and_info(2001, 42);
        assert_eq!(updated.destination_port, 2001);
        assert_eq!(updated.destination_port_info, 42);
        // Other fields should remain at defaults
        assert_eq!(updated.source_port, 0);
    }

    #[test]
    fn btp_data_indication_from_gn_data_indication() {
        // Build a minimal GNDataIndication with 6 bytes payload (4 BTP header + 2 data)
        let gn_ind = GNDataIndication {
            upper_protocol_entity: CommonNH::BtpB,
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            },
            source_position_vector: LongPositionVector::decode([0u8; 24]),
            traffic_class: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            destination_area: None,
            remaining_packet_lifetime: Some(1.0),
            remaining_hop_limit: None,
            length: 6,
            data: vec![0x07, 0xD1, 0x00, 0x00, 0xAA, 0xBB],
        };

        let btp_ind = BTPDataIndication::initialize_with_gn_data_indication(&gn_ind);
        // First 4 bytes (BTP header) should be stripped
        assert_eq!(btp_ind.data, vec![0xAA, 0xBB]);
        assert_eq!(btp_ind.length, 2);
        assert_eq!(btp_ind.gn_remaining_packet_lifetime, Some(1.0));
    }

    #[test]
    fn btp_data_indication_from_gn_short_payload() {
        let gn_ind = GNDataIndication {
            upper_protocol_entity: CommonNH::BtpB,
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            },
            source_position_vector: LongPositionVector::decode([0u8; 24]),
            traffic_class: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            destination_area: None,
            remaining_packet_lifetime: None,
            remaining_hop_limit: None,
            length: 2,
            data: vec![0x07, 0xD1], // Only 2 bytes — too short for BTP header
        };

        let btp_ind = BTPDataIndication::initialize_with_gn_data_indication(&gn_ind);
        assert!(btp_ind.data.is_empty());
        assert_eq!(btp_ind.length, 0);
    }
}

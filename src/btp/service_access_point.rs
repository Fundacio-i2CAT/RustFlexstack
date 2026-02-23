// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use crate::geonet::gn_address::{GNAddress, M, ST, MID};
use crate::geonet::service_access_point::{Area, GNDataIndication, PacketTransportType, CommunicationProfile, TrafficClass, CommonNH, HeaderType, HeaderSubType, UnspecifiedHST};
use crate::geonet::position_vector::LongPositionVector;

pub struct BTPDataRequest{
    pub btp_type : CommonNH,
    pub source_port : u16,
    pub destination_port : u16,
    pub destination_port_info : u16,
    pub gn_packet_transport_type : PacketTransportType,
    pub gn_destination_address : GNAddress,
    pub gn_area : Area,
    pub communication_profile : CommunicationProfile,
    pub traffic_class : TrafficClass,
    pub length : u16,
    pub data : Vec<u8>,
}

impl BTPDataRequest {
    pub fn new() -> Self{
        BTPDataRequest{
            btp_type : CommonNH::Any,
            source_port : 0,
            destination_port : 0,
            destination_port_info : 0,
            gn_packet_transport_type : PacketTransportType{
                header_type : HeaderType::Any,
                header_sub_type : HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
            },
            gn_destination_address : GNAddress{
                m : M::GnUnicast,
                st : ST::Unknown,
                mid : MID::new([0; 6]),
            },
            gn_area : Area{
                latitude: 0,
                longitude: 0,
                a: 0,
                b: 0,
                angle: 0,
            },
            communication_profile : CommunicationProfile::Unspecified,
            traffic_class : TrafficClass{
                scf : false,
                channel_offload : false,
                tc_id : 0,
            },
            length : 0,
            data : vec![0,0],
        }
    }
}

pub struct BTPDataIndication{
    pub source_port : u16,
    pub destination_port : u16,
    pub destination_port_info : u16,
    pub gn_packet_transport_type : PacketTransportType,
    pub gn_destination_address : GNAddress,
    pub gn_source_position_vector : LongPositionVector,
    pub gn_traffic_class : TrafficClass,
    pub length : u16,
    pub data : Vec<u8>,
}

impl BTPDataIndication{

    pub fn new() -> Self{
        BTPDataIndication{
            source_port : 0,
            destination_port : 0,
            destination_port_info : 0,
            gn_packet_transport_type : PacketTransportType{
                header_type : HeaderType::Any,
                header_sub_type : HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
            },
            gn_destination_address : GNAddress{
                m : M::GnUnicast,
                st : ST::Unknown,
                mid : MID::new([0; 6]),
            },
            gn_source_position_vector : LongPositionVector::decode([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
            gn_traffic_class : TrafficClass{
                scf : false,
                channel_offload : false,
                tc_id : 0,
            },
            length : 0,
            data : vec![0,0],
        }
    }

    pub fn initialize_with_gn_data_indication(&mut self, gn_data_indication: &GNDataIndication){
        self.gn_packet_transport_type = gn_data_indication.packet_transport_type.clone();
        self.gn_source_position_vector = gn_data_indication.source_position_vector.clone();
        self.gn_traffic_class = gn_data_indication.traffic_class.clone();
        self.data = gn_data_indication.data[4..].to_vec().clone();
        self.length = self.data.len() as u16;
    }
}

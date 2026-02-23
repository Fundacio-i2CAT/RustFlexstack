// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use super::position_vector::LongPositionVector;
use super::service_access_point::GNDataRequest;

#[derive(Clone, PartialEq, Debug)]
pub struct GBCExtendedHeader{
    pub sn : u16,
    pub reserved : u16,
    pub so_pv : LongPositionVector,
    pub latitude : u32,
    pub longitude : u32,
    pub a : u16,
    pub b : u16,
    pub angle : u16,
    pub reserved2 : u16,
}

impl GBCExtendedHeader{
    pub fn initialize_with_request(request : GNDataRequest) -> Self{
        GBCExtendedHeader{
            sn : 0,
            reserved : 0,
            so_pv : LongPositionVector::decode([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
            latitude : request.area.latitude.clone(),
            longitude : request.area.longitude.clone(),
            a : request.area.a.clone(),
            b : request.area.b.clone(),
            angle : request.area.angle.clone(),
            reserved2 : 0,
        }
    }

    pub fn encode(&self) -> [u8; 44] {
        let mut bytes : [u8; 44] = [0; 44];
        bytes[0] = (self.sn >> 8) as u8;
        bytes[1] = self.sn as u8;
        bytes[2] = (self.reserved >> 8) as u8;
        bytes[3] = self.reserved as u8;
        bytes[4..28].copy_from_slice(&self.so_pv.encode());
        bytes[28..32].copy_from_slice(&self.latitude.to_be_bytes());
        bytes[32..36].copy_from_slice(&self.longitude.to_be_bytes());
        bytes[36..38].copy_from_slice(&self.a.to_be_bytes());
        bytes[38..40].copy_from_slice(&self.b.to_be_bytes());
        bytes[40..42].copy_from_slice(&self.angle.to_be_bytes());
        bytes[42..44].copy_from_slice(&self.reserved2.to_be_bytes());
        bytes
    }

    pub fn decode(bytes : [u8; 44]) -> Self {
        let mut sn : u16 = 0;
        sn |= (bytes[0] as u16) << 8;
        sn |= bytes[1] as u16;
        let mut reserved : u16 = 0;
        reserved |= (bytes[2] as u16) << 8;
        reserved |= bytes[3] as u16;
        let so_pv = LongPositionVector::decode(bytes[4..28].try_into().unwrap());
        let mut latitude : u32 = 0;
        for i in 0..4{
            latitude |= (bytes[28+i] as u32) << (8*(3-i));
        }
        let mut longitude : u32 = 0;
        for i in 0..4{
            longitude |= (bytes[32+i] as u32) << (8*(3-i));
        }
        let mut a : u16 = 0;
        for i in 0..2{
            a |= (bytes[36+i] as u16) << (8*(1-i));
        }
        let mut b : u16 = 0;
        for i in 0..2{
            b |= (bytes[38+i] as u16) << (8*(1-i));
        }
        let mut angle : u16 = 0;
        for i in 0..2{
            angle |= (bytes[40+i] as u16) << (8*(1-i));
        }
        let mut reserved2 : u16 = 0;
        for i in 0..2{
            reserved2 |= (bytes[42+i] as u16) << (8*(1-i));
        }
        GBCExtendedHeader{
            sn,
            reserved,
            so_pv,
            latitude,
            longitude,
            a,
            b,
            angle,
            reserved2,
        }
    }
}
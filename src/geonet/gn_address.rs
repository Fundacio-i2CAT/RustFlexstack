// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use std::cmp::PartialEq;

#[derive(Clone, Copy, Debug)]
pub enum M{
    GnUnicast,
    GnMulticast
}

impl M{
    pub fn encode_to_address(&self) -> u64 {
        match self {
            M::GnUnicast => {
                (1 << 7) << 8*7
            },
            M::GnMulticast => {
                (0 << 7) << 8*7
            },
        }
    }

    pub fn decode_from_address(address: u64) -> Self{
        // Bit 63 is the M (multicast/unicast) flag
        if (address >> 63) & 1 == 1 {
            M::GnUnicast
        } else {
            M::GnMulticast
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ST{
    Unknown,
    Pedestrian,
    Cyclist,
    Moped,
    Motorcycle,
    PassengerCar,
    Bus,
    LightTruck,
    HeavyTruck,
    Trailer,
    SpecialVehicle,
    Tram,
    RoadSideUnit
}

impl ST{
    pub fn encode_to_address(&self) -> u64{
        match self{
            ST::Unknown => {
                (0 << 3) << 8*7
            },
            ST::Pedestrian => {
                (1 << 3) << 8*7
            },
            ST::Cyclist => {
                (2 << 3) << 8*7
            },
            ST::Moped => {
                (3 << 3) << 8*7
            },
            ST::Motorcycle => {
                (4 << 3) << 8*7
            },
            ST::PassengerCar => {
                (5 << 3) << 8*7
            },
            ST::Bus => {
                (6 << 3) << 8*7
            },
            ST::LightTruck => {
                (7 << 3) << 8*7
            },
            ST::HeavyTruck => {
                (8 << 3) << 8*7
            },
            ST::Trailer => {
                (9 << 3) << 8*7
            },
            ST::SpecialVehicle => {
                (10 << 3) << 8*7
            },
            ST::Tram => {
                (11 << 3) << 8*7
            },
            ST::RoadSideUnit => {
                (12 << 3) << 8*7
            },
        }
    }

    pub fn decode_from_address(address: u64) -> Self{
        // Station type occupies bits 58-62 (bits 3-7 of the most significant byte)
        match (address >> (8 * 7 + 3)) & 0x1F {
            0 => ST::Unknown,
            1 => ST::Pedestrian,
            2 => ST::Cyclist,
            3 => ST::Moped,
            4 => ST::Motorcycle,
            5 => ST::PassengerCar,
            6 => ST::Bus,
            7 => ST::LightTruck,
            8 => ST::HeavyTruck,
            9 => ST::Trailer,
            10 => ST::SpecialVehicle,
            11 => ST::Tram,
            12 => ST::RoadSideUnit,
            _ => panic!("Invalid ST value"),
        }
    }
}

#[derive(Clone, Copy, Debug)]

pub struct MID{
    mid : [u8; 6]
}

impl MID{
    pub fn new(mid: [u8; 6]) -> Self{
        MID{
            mid
        }
    }

    pub fn encode_to_address(&self) -> u64{
        let mut address: u64 = 0;
        for i in 0..6{
            address |= (self.mid[i] as u64) << (8*(5-i));
        }
        address
    }

    pub fn decode_from_address(address: u64) -> Self{
        let mut mid: [u8; 6] = [0; 6];
        for i in 0..6{
            mid[i] = (address >> (8*(5-i))) as u8;
        }
        MID{
            mid
        }
    }
}


#[derive(Clone, Copy, Debug)]

pub struct GNAddress{
    pub m: M,
    pub st: ST,
    pub mid: MID,
}

impl GNAddress{
    pub fn new(m: M, st: ST, mid: MID) -> Self{
        GNAddress{
            m,
            st,
            mid,
        }
    }

    pub fn encode_to_int(&self) -> u64{
        self.m.encode_to_address() | self.st.encode_to_address() | self.mid.encode_to_address()
    }

    pub fn encode(&self) -> [u8; 8]{
        self.encode_to_int().to_be_bytes()
    }

    pub fn decode(data: &[u8]) -> Self{
        let as_number : u64 = u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
        let m : M = M::decode_from_address(as_number);
        let st : ST = ST::decode_from_address(as_number);
        let mid : MID = MID::decode_from_address(as_number);
        GNAddress{
            m,
            st,
            mid,
        }
        
    }
}

impl PartialEq for GNAddress{
    fn eq(&self, other: &Self) -> bool{
        self.encode_to_int() == other.encode_to_int()
    }
}
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use std::cmp::PartialEq;

#[derive(Clone, Copy, Debug)]
pub enum M {
    GnUnicast,
    GnMulticast,
}

impl M {
    pub fn encode_to_address(&self) -> u64 {
        match self {
            M::GnUnicast => (0 << 7) << (8 * 7),
            M::GnMulticast => (1 << 7) << (8 * 7),
        }
    }

    pub fn decode_from_address(address: u64) -> Self {
        // Bit 63 is the M (multicast/unicast) flag
        if (address >> 63) & 1 == 1 {
            M::GnMulticast
        } else {
            M::GnUnicast
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ST {
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
    RoadSideUnit,
}

impl ST {
    pub fn encode_to_address(&self) -> u64 {
        match self {
            ST::Unknown => (0 << 2) << (8 * 7),
            ST::Pedestrian => (1 << 2) << (8 * 7),
            ST::Cyclist => (2 << 2) << (8 * 7),
            ST::Moped => (3 << 2) << (8 * 7),
            ST::Motorcycle => (4 << 2) << (8 * 7),
            ST::PassengerCar => (5 << 2) << (8 * 7),
            ST::Bus => (6 << 2) << (8 * 7),
            ST::LightTruck => (7 << 2) << (8 * 7),
            ST::HeavyTruck => (8 << 2) << (8 * 7),
            ST::Trailer => (9 << 2) << (8 * 7),
            ST::SpecialVehicle => (10 << 2) << (8 * 7),
            ST::Tram => (11 << 2) << (8 * 7),
            ST::RoadSideUnit => (12 << 2) << (8 * 7),
        }
    }

    pub fn decode_from_address(address: u64) -> Self {
        // Station type occupies bits 62-58 (bits 6-2 of the most significant byte)
        // Bit 63 is M (manual/derived), so ST starts at bit 62
        match (address >> (8 * 7 + 2)) & 0x1F {
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
            _ => ST::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug)]

pub struct MID {
    mid: [u8; 6],
}

impl MID {
    pub fn new(mid: [u8; 6]) -> Self {
        MID { mid }
    }

    pub fn encode_to_address(&self) -> u64 {
        let mut address: u64 = 0;
        for i in 0..6 {
            address |= (self.mid[i] as u64) << (8 * (5 - i));
        }
        address
    }

    pub fn decode_from_address(address: u64) -> Self {
        let mut mid: [u8; 6] = [0; 6];
        for (i, byte) in mid.iter_mut().enumerate() {
            *byte = (address >> (8 * (5 - i))) as u8;
        }
        MID { mid }
    }
}

#[derive(Clone, Copy, Debug)]

pub struct GNAddress {
    pub m: M,
    pub st: ST,
    pub mid: MID,
}

impl GNAddress {
    pub fn new(m: M, st: ST, mid: MID) -> Self {
        GNAddress { m, st, mid }
    }

    pub fn encode_to_int(&self) -> u64 {
        self.m.encode_to_address() | self.st.encode_to_address() | self.mid.encode_to_address()
    }

    pub fn encode(&self) -> [u8; 8] {
        self.encode_to_int().to_be_bytes()
    }

    pub fn decode(data: &[u8]) -> Self {
        let as_number: u64 = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let m: M = M::decode_from_address(as_number);
        let st: ST = ST::decode_from_address(as_number);
        let mid: MID = MID::decode_from_address(as_number);
        GNAddress { m, st, mid }
    }
}

impl PartialEq for GNAddress {
    fn eq(&self, other: &Self) -> bool {
        self.encode_to_int() == other.encode_to_int()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m_encode_decode_unicast() {
        let encoded = M::GnUnicast.encode_to_address();
        let decoded = M::decode_from_address(encoded);
        assert!(matches!(decoded, M::GnUnicast));
    }

    #[test]
    fn m_encode_decode_multicast() {
        let encoded = M::GnMulticast.encode_to_address();
        let decoded = M::decode_from_address(encoded);
        assert!(matches!(decoded, M::GnMulticast));
    }

    #[test]
    fn st_encode_decode_all_variants() {
        let variants = [
            (ST::Unknown, 0),
            (ST::Pedestrian, 1),
            (ST::Cyclist, 2),
            (ST::Moped, 3),
            (ST::Motorcycle, 4),
            (ST::PassengerCar, 5),
            (ST::Bus, 6),
            (ST::LightTruck, 7),
            (ST::HeavyTruck, 8),
            (ST::Trailer, 9),
            (ST::SpecialVehicle, 10),
            (ST::Tram, 11),
            (ST::RoadSideUnit, 12),
        ];
        for (st, _) in &variants {
            let encoded = st.encode_to_address();
            let decoded = ST::decode_from_address(encoded);
            // Check roundtrip: encode, then decode → same bit pattern
            assert_eq!(decoded.encode_to_address(), st.encode_to_address());
        }
    }

    #[test]
    fn st_decode_unknown_value() {
        // Unknown ST values (> 12) should map to Unknown
        let addr = 0x1F_u64 << (8 * 7 + 2); // ST bits = 31
        let decoded = ST::decode_from_address(addr);
        assert!(matches!(decoded, ST::Unknown));
    }

    #[test]
    fn mid_encode_decode_roundtrip() {
        let mid = MID::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let encoded = mid.encode_to_address();
        let decoded = MID::decode_from_address(encoded);
        assert_eq!(decoded.mid, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn mid_all_zeros() {
        let mid = MID::new([0, 0, 0, 0, 0, 0]);
        assert_eq!(mid.encode_to_address(), 0);
    }

    #[test]
    fn gn_address_encode_decode_roundtrip() {
        let addr = GNAddress::new(
            M::GnUnicast,
            ST::PassengerCar,
            MID::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        );
        let bytes = addr.encode();
        assert_eq!(bytes.len(), 8);
        let decoded = GNAddress::decode(&bytes);
        assert_eq!(addr, decoded);
    }

    #[test]
    fn gn_address_equality() {
        let a = GNAddress::new(M::GnUnicast, ST::Bus, MID::new([1, 2, 3, 4, 5, 6]));
        let b = GNAddress::new(M::GnUnicast, ST::Bus, MID::new([1, 2, 3, 4, 5, 6]));
        assert_eq!(a, b);
    }

    #[test]
    fn gn_address_inequality_different_mid() {
        let a = GNAddress::new(M::GnUnicast, ST::Bus, MID::new([1, 2, 3, 4, 5, 6]));
        let b = GNAddress::new(M::GnUnicast, ST::Bus, MID::new([6, 5, 4, 3, 2, 1]));
        assert_ne!(a, b);
    }

    #[test]
    fn gn_address_inequality_different_m() {
        let a = GNAddress::new(M::GnUnicast, ST::Bus, MID::new([1, 2, 3, 4, 5, 6]));
        let b = GNAddress::new(M::GnMulticast, ST::Bus, MID::new([1, 2, 3, 4, 5, 6]));
        assert_ne!(a, b);
    }

    #[test]
    fn gn_address_encode_to_int_consistency() {
        let addr = GNAddress::new(
            M::GnMulticast,
            ST::RoadSideUnit,
            MID::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        );
        let int_val = addr.encode_to_int();
        let bytes = int_val.to_be_bytes();
        assert_eq!(bytes, addr.encode());
    }
}

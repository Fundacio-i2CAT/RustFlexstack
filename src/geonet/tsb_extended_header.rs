// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! TSB Extended Header — ETSI EN 302 636-4-1 V1.4.1 (2020-01) §9.8.3 (Table 12).
//!
//! Layout (28 bytes):
//!   SN         2 octets
//!   Reserved   2 octets
//!   SO PV     24 octets  (Long Position Vector)

use super::position_vector::LongPositionVector;

#[derive(Clone, PartialEq, Debug)]
pub struct TSBExtendedHeader {
    pub sn: u16,
    pub reserved: u16,
    pub so_pv: LongPositionVector,
}

impl TSBExtendedHeader {
    pub fn initialize_with_sequence_number_ego_pv(
        sequence_number: u16,
        ego_pv: LongPositionVector,
    ) -> Self {
        TSBExtendedHeader {
            sn: sequence_number,
            reserved: 0,
            so_pv: ego_pv,
        }
    }

    pub fn encode(&self) -> [u8; 28] {
        let mut bytes = [0u8; 28];
        bytes[0..2].copy_from_slice(&self.sn.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.reserved.to_be_bytes());
        bytes[4..28].copy_from_slice(&self.so_pv.encode());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 28, "TSB Extended Header too short");
        let sn = u16::from_be_bytes([bytes[0], bytes[1]]);
        let reserved = u16::from_be_bytes([bytes[2], bytes[3]]);
        let so_pv = LongPositionVector::decode(bytes[4..28].try_into().unwrap());
        TSBExtendedHeader {
            sn,
            reserved,
            so_pv,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geonet::gn_address::{GNAddress, M, MID, ST};
    use crate::geonet::position_vector::{LongPositionVector, Tst};

    fn make_tsb() -> TSBExtendedHeader {
        let so_pv = LongPositionVector {
            gn_addr: GNAddress::new(
                M::GnUnicast,
                ST::Motorcycle,
                MID::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            ),
            tst: Tst::set_in_normal_timestamp_milliseconds(1_717_200_000_000),
            latitude: 415520000,
            longitude: 21340000,
            pai: true,
            s: 300,
            h: 450,
        };
        TSBExtendedHeader::initialize_with_sequence_number_ego_pv(77, so_pv)
    }

    #[test]
    fn tsb_encode_decode_roundtrip() {
        let header = make_tsb();
        let encoded = header.encode();
        assert_eq!(encoded.len(), 28);
        let decoded = TSBExtendedHeader::decode(&encoded);
        assert_eq!(header, decoded);
    }

    #[test]
    fn tsb_sequence_number() {
        let header = make_tsb();
        assert_eq!(header.sn, 77);
        assert_eq!(header.reserved, 0);
    }

    #[test]
    #[should_panic(expected = "TSB Extended Header too short")]
    fn tsb_decode_too_short() {
        TSBExtendedHeader::decode(&[0u8; 5]);
    }
}

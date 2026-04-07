// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! GUC Extended Header — ETSI EN 302 636-4-1 V1.4.1 (2020-01) §9.8.2 (Table 11).
//!
//! Layout (48 bytes):
//!   SN         2 octets
//!   Reserved   2 octets
//!   SO PV     24 octets  (Long Position Vector)
//!   DE PV     20 octets  (Short Position Vector)

use super::position_vector::{LongPositionVector, ShortPositionVector};

#[derive(Clone, PartialEq, Debug)]
pub struct GUCExtendedHeader {
    pub sn: u16,
    pub reserved: u16,
    pub so_pv: LongPositionVector,
    pub de_pv: ShortPositionVector,
}

impl GUCExtendedHeader {
    pub fn initialize_with_sequence_number_ego_pv_de_pv(
        sequence_number: u16,
        ego_pv: LongPositionVector,
        de_pv: ShortPositionVector,
    ) -> Self {
        GUCExtendedHeader {
            sn: sequence_number,
            reserved: 0,
            so_pv: ego_pv,
            de_pv,
        }
    }

    /// Return a copy with an updated DE PV (used by forwarder step 8).
    pub fn with_de_pv(&self, de_pv: ShortPositionVector) -> Self {
        GUCExtendedHeader {
            sn: self.sn,
            reserved: self.reserved,
            so_pv: self.so_pv,
            de_pv,
        }
    }

    pub fn encode(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        bytes[0..2].copy_from_slice(&self.sn.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.reserved.to_be_bytes());
        bytes[4..28].copy_from_slice(&self.so_pv.encode());
        bytes[28..48].copy_from_slice(&self.de_pv.encode());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 48, "GUC Extended Header too short");
        let sn = u16::from_be_bytes([bytes[0], bytes[1]]);
        let reserved = u16::from_be_bytes([bytes[2], bytes[3]]);
        let so_pv = LongPositionVector::decode(bytes[4..28].try_into().unwrap());
        let de_pv = ShortPositionVector::decode(bytes[28..48].try_into().unwrap());
        GUCExtendedHeader {
            sn,
            reserved,
            so_pv,
            de_pv,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geonet::gn_address::{GNAddress, M, MID, ST};
    use crate::geonet::position_vector::{LongPositionVector, ShortPositionVector, Tst};

    fn make_guc() -> GUCExtendedHeader {
        let so_pv = LongPositionVector {
            gn_addr: GNAddress::new(M::GnUnicast, ST::PassengerCar, MID::new([1, 2, 3, 4, 5, 6])),
            tst: Tst::set_in_normal_timestamp_milliseconds(1_717_200_000_000),
            latitude: 415520000,
            longitude: 21340000,
            pai: true,
            s: 500,
            h: 1800,
        };
        let de_pv = ShortPositionVector {
            gn_address: GNAddress::new(M::GnUnicast, ST::Bus, MID::new([6, 5, 4, 3, 2, 1])),
            tst: Tst::set_in_normal_timestamp_milliseconds(1_717_200_000_000),
            latitude: 415530000,
            longitude: 21350000,
        };
        GUCExtendedHeader::initialize_with_sequence_number_ego_pv_de_pv(99, so_pv, de_pv)
    }

    #[test]
    fn guc_encode_decode_roundtrip() {
        let header = make_guc();
        let encoded = header.encode();
        assert_eq!(encoded.len(), 48);
        let decoded = GUCExtendedHeader::decode(&encoded);
        assert_eq!(header, decoded);
    }

    #[test]
    fn guc_sequence_number() {
        let header = make_guc();
        assert_eq!(header.sn, 99);
    }

    #[test]
    fn guc_with_de_pv() {
        let header = make_guc();
        let new_de_pv = ShortPositionVector::decode([0u8; 20]);
        let updated = header.with_de_pv(new_de_pv.clone());
        assert_eq!(updated.de_pv, new_de_pv);
        assert_eq!(updated.sn, header.sn);
    }

    #[test]
    #[should_panic(expected = "GUC Extended Header too short")]
    fn guc_decode_too_short() {
        GUCExtendedHeader::decode(&[0u8; 10]);
    }
}

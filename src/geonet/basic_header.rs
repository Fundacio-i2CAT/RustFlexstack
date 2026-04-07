// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use super::mib::Mib;

#[derive(Clone, Copy, Debug)]
pub enum BasicNH {
    Any,
    CommonHeader,
    SecuredPacket,
}

impl BasicNH {
    pub fn encode(&self) -> u8 {
        match self {
            BasicNH::Any => 0,
            BasicNH::CommonHeader => 1,
            BasicNH::SecuredPacket => 2,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => BasicNH::Any,
            1 => BasicNH::CommonHeader,
            2 => BasicNH::SecuredPacket,
            _ => panic!("Invalid BasicNH Value"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum LTBase {
    FiftyMilliseconds,
    OneSecond,
    TenSeconds,
    OneHundredSeconds,
}

impl LTBase {
    pub fn decode(value: u8) -> Self {
        match value {
            0 => LTBase::FiftyMilliseconds,
            1 => LTBase::OneSecond,
            2 => LTBase::TenSeconds,
            3 => LTBase::OneHundredSeconds,
            _ => panic!("Invalid LTBase Value"),
        }
    }

    pub fn encode(&self) -> u8 {
        match self {
            LTBase::FiftyMilliseconds => 0,
            LTBase::OneSecond => 1,
            LTBase::TenSeconds => 2,
            LTBase::OneHundredSeconds => 3,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LT {
    multiplier: u8,
    base: LTBase,
}

impl LT {
    pub fn start_in_milliseconds(value: u32) -> Self {
        if value >= 100000 {
            return LT {
                multiplier: (value / 100000) as u8,
                base: LTBase::OneHundredSeconds,
            };
        } else if value >= 10000 {
            return LT {
                multiplier: (value / 10000) as u8,
                base: LTBase::TenSeconds,
            };
        } else if value >= 1000 {
            return LT {
                multiplier: (value / 1000) as u8,
                base: LTBase::OneSecond,
            };
        } else if value >= 50 {
            return LT {
                multiplier: (value / 50) as u8,
                base: LTBase::FiftyMilliseconds,
            };
        } else {
            panic!("Invalid LT Value");
        }
    }
    pub fn start_in_seconds(value: u8) -> Self {
        LT::start_in_milliseconds(value as u32 * 1000)
    }

    pub fn get_value_in_milliseconds(&self) -> u32 {
        match self.base {
            LTBase::FiftyMilliseconds => 50 * self.multiplier as u32,
            LTBase::OneSecond => 1000 * self.multiplier as u32,
            LTBase::TenSeconds => 10000 * self.multiplier as u32,
            LTBase::OneHundredSeconds => 100000 * self.multiplier as u32,
        }
    }
    pub fn get_value_in_seconds(&self) -> u8 {
        (self.get_value_in_milliseconds() / 1000) as u8
    }
    pub fn encode(&self) -> u8 {
        self.multiplier << 2 | (self.base.encode() & 0x3)
    }

    pub fn decode(value: u8) -> Self {
        LT {
            multiplier: value >> 2,
            base: LTBase::decode(value & 0x3),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BasicHeader {
    pub version: u8,
    pub nh: BasicNH,
    pub reserved: u8,
    pub lt: LT,
    pub rhl: u8,
}

impl BasicHeader {
    pub fn decode(bytes: [u8; 4]) -> Self {
        BasicHeader {
            version: bytes[0] >> 4,
            nh: BasicNH::decode(bytes[0] & 0xF),
            reserved: 0,
            lt: LT::decode(bytes[2]),
            rhl: bytes[3],
        }
    }

    pub fn initialize_with_mib(mib: &Mib) -> Self {
        BasicHeader {
            version: mib.itsGnProtocolVersion.clone(),
            nh: BasicNH::CommonHeader,
            rhl: mib.itsGnDefaultHopLimit.clone(),
            reserved: 0,
            lt: LT::start_in_seconds(mib.itsGnDefaultPacketLifetime.clone()),
        }
    }

    /// Initialize from MIB with optional max_packet_lifetime and explicit RHL.
    pub fn initialize_with_mib_request_and_rhl(
        mib: &Mib,
        max_packet_lifetime: Option<f64>,
        rhl: u8,
    ) -> Self {
        let lt = if let Some(lifetime_secs) = max_packet_lifetime {
            LT::start_in_milliseconds((lifetime_secs * 1000.0) as u32)
        } else {
            LT::start_in_seconds(mib.itsGnDefaultPacketLifetime)
        };
        BasicHeader {
            version: mib.itsGnProtocolVersion,
            nh: BasicNH::CommonHeader,
            reserved: 0,
            lt,
            rhl,
        }
    }

    /// Return a copy with a different next-header value.
    pub fn set_nh(self, nh: BasicNH) -> Self {
        BasicHeader { nh, ..self }
    }

    /// Return a copy with a different remaining hop limit.
    pub fn set_rhl(self, rhl: u8) -> Self {
        BasicHeader { rhl, ..self }
    }

    pub fn encode(&self) -> [u8; 4] {
        [
            self.version << 4 | self.nh.encode(),
            self.reserved,
            self.lt.encode(),
            self.rhl,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geonet::mib::Mib;

    // ── BasicNH ───────────────────────────────────────────────────────

    #[test]
    fn basic_nh_encode_decode_roundtrip() {
        for (nh, val) in [
            (BasicNH::Any, 0u8),
            (BasicNH::CommonHeader, 1),
            (BasicNH::SecuredPacket, 2),
        ] {
            assert_eq!(nh.encode(), val);
            assert_eq!(BasicNH::decode(val).encode(), val);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid BasicNH Value")]
    fn basic_nh_decode_invalid() {
        BasicNH::decode(99);
    }

    // ── LTBase ────────────────────────────────────────────────────────

    #[test]
    fn lt_base_encode_decode_roundtrip() {
        for i in 0..4u8 {
            assert_eq!(LTBase::decode(i).encode(), i);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid LTBase Value")]
    fn lt_base_decode_invalid() {
        LTBase::decode(5);
    }

    // ── LT ────────────────────────────────────────────────────────────

    #[test]
    fn lt_from_milliseconds_50ms_base() {
        let lt = LT::start_in_milliseconds(250);
        assert_eq!(lt.get_value_in_milliseconds(), 250);
    }

    #[test]
    fn lt_from_milliseconds_1s_base() {
        let lt = LT::start_in_milliseconds(3000);
        assert_eq!(lt.get_value_in_milliseconds(), 3000);
    }

    #[test]
    fn lt_from_milliseconds_10s_base() {
        let lt = LT::start_in_milliseconds(30000);
        assert_eq!(lt.get_value_in_milliseconds(), 30000);
    }

    #[test]
    fn lt_from_milliseconds_100s_base() {
        let lt = LT::start_in_milliseconds(600000);
        assert_eq!(lt.get_value_in_milliseconds(), 600000);
    }

    #[test]
    fn lt_from_seconds() {
        let lt = LT::start_in_seconds(60);
        assert_eq!(lt.get_value_in_seconds(), 60);
        assert_eq!(lt.get_value_in_milliseconds(), 60000);
    }

    #[test]
    fn lt_encode_decode_roundtrip() {
        let lt = LT::start_in_milliseconds(3000);
        let encoded = lt.encode();
        let decoded = LT::decode(encoded);
        assert_eq!(decoded.get_value_in_milliseconds(), 3000);
    }

    #[test]
    #[should_panic(expected = "Invalid LT Value")]
    fn lt_too_small() {
        LT::start_in_milliseconds(10);
    }

    // ── BasicHeader ───────────────────────────────────────────────────

    #[test]
    fn basic_header_encode_decode_roundtrip() {
        let mib = Mib::new();
        let bh = BasicHeader::initialize_with_mib(&mib);
        let encoded = bh.encode();
        let decoded = BasicHeader::decode(encoded);
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.rhl, mib.itsGnDefaultHopLimit);
    }

    #[test]
    fn basic_header_version_field() {
        let mib = Mib::new();
        let bh = BasicHeader::initialize_with_mib(&mib);
        let bytes = bh.encode();
        assert_eq!(bytes[0] >> 4, 1); // protocol version 1
    }

    #[test]
    fn basic_header_set_nh() {
        let mib = Mib::new();
        let bh = BasicHeader::initialize_with_mib(&mib).set_nh(BasicNH::SecuredPacket);
        assert_eq!(bh.nh.encode(), 2);
    }

    #[test]
    fn basic_header_set_rhl() {
        let mib = Mib::new();
        let bh = BasicHeader::initialize_with_mib(&mib).set_rhl(5);
        assert_eq!(bh.rhl, 5);
    }

    #[test]
    fn basic_header_with_lifetime_and_rhl() {
        let mib = Mib::new();
        let bh = BasicHeader::initialize_with_mib_request_and_rhl(&mib, Some(3.0), 7);
        assert_eq!(bh.rhl, 7);
        assert_eq!(bh.lt.get_value_in_milliseconds(), 3000);
    }

    #[test]
    fn basic_header_with_default_lifetime() {
        let mib = Mib::new();
        let bh = BasicHeader::initialize_with_mib_request_and_rhl(&mib, None, 7);
        assert_eq!(bh.rhl, 7);
        assert_eq!(
            bh.lt.get_value_in_milliseconds(),
            mib.itsGnDefaultPacketLifetime as u32 * 1000
        );
    }
}

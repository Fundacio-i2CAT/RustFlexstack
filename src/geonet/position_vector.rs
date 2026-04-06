// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use std::cmp::{PartialEq, PartialOrd};
use std::ops::{Add, Sub};

use super::gn_address::GNAddress;

#[derive(Clone, Copy, Debug)]
pub struct Tst {
    msec: u32,
}

impl Tst {
    pub fn set_in_normal_timestamp_milliseconds(msec: u64) -> Self {
        // TAI epoch offset: 2004-01-01T00:00:00 UTC = 1 072 911 600 s
        // Timestamp = (unix_ms - tai_offset_ms) mod 2^32
        const TAI_OFFSET_MS: u64 = 1_072_911_600_000;
        let value: u32 = if msec > TAI_OFFSET_MS {
            ((msec - TAI_OFFSET_MS) & 0xFFFF_FFFF) as u32
        } else {
            0
        };
        Tst { msec: value }
    }

    pub fn set_in_normal_timestamp_seconds(sec: u64) -> Self {
        let value: u32 = (((sec - 1072911600) * 1000) % 2u64.pow(32))
            .try_into()
            .unwrap();
        Tst { msec: value }
    }

    pub fn encode(&self) -> [u8; 4] {
        self.msec.to_be_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Self {
        let mut msec: u32 = 0;
        for i in 0..4 {
            msec |= (bytes[i] as u32) << (8 * (3 - i));
        }
        Tst { msec }
    }
}

impl Sub for Tst {
    type Output = u32;

    fn sub(self, other: Self) -> u32 {
        self.msec - other.msec
    }
}

impl Add for Tst {
    type Output = Tst;

    fn add(self, other: Self) -> Tst {
        Tst {
            msec: self.msec + other.msec,
        }
    }
}

impl PartialEq for Tst {
    fn eq(&self, other: &Self) -> bool {
        self.msec == other.msec
    }
}

impl PartialOrd for Tst {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // 2^31 is the serial-number half-range used for TAI ms wraparound comparison
        // (RFC 1982 / ETSI EN 302 636-4-1 §9.2.2.1).
        // We must NOT use 2u32.pow(32) — that overflows u32 in debug builds.
        const HALF: u32 = 0x8000_0000;
        if (self.msec > other.msec && self.msec - other.msec <= HALF)
            || (other.msec > self.msec && other.msec - self.msec > HALF)
        {
            Some(std::cmp::Ordering::Greater)
        } else if self == other {
            Some(std::cmp::Ordering::Equal)
        } else {
            Some(std::cmp::Ordering::Less)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LongPositionVector {
    pub gn_addr: GNAddress,
    pub tst: Tst,
    pub latitude: u32,
    pub longitude: u32,
    pub pai: bool,
    pub s: u16,
    pub h: u16,
}

impl LongPositionVector {
    pub fn encode(&self) -> [u8; 24] {
        let mut bytes: [u8; 24] = [0; 24];
        bytes[0..8].clone_from_slice(&self.gn_addr.encode());
        bytes[8..12].clone_from_slice(&self.tst.encode());
        bytes[12..16].clone_from_slice(&self.latitude.to_be_bytes());
        bytes[16..20].clone_from_slice(&self.longitude.to_be_bytes());
        // Byte 20: PAI flag (bit 7) | speed high byte (bits 0-6)
        bytes[20] = ((self.pai as u8) << 7) | ((self.s >> 8) as u8 & 0x7F);
        bytes[21] = (self.s & 0xFF) as u8;
        bytes[22..24].clone_from_slice(&self.h.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; 24]) -> Self {
        let gn_addr = GNAddress::decode(&bytes[0..8]);
        let tst = Tst::decode(&bytes[8..12]);
        let mut latitude: u32 = 0;
        for i in 0..4 {
            latitude |= (bytes[12 + i] as u32) << (8 * (3 - i));
        }
        let mut longitude: u32 = 0;
        for i in 0..4 {
            longitude |= (bytes[16 + i] as u32) << (8 * (3 - i));
        }
        let pai = (bytes[20] >> 7) == 1;
        // Speed is 15 bits: lower 7 bits of byte 20 + all of byte 21
        let s: u16 = (((bytes[20] & 0x7F) as u16) << 8) | (bytes[21] as u16);
        let mut h: u16 = 0;
        for i in 0..2 {
            h |= (bytes[22 + i] as u16) << (8 * (1 - i));
        }
        LongPositionVector {
            gn_addr,
            tst,
            latitude,
            longitude,
            pai,
            s,
            h,
        }
    }
}

impl PartialEq for LongPositionVector {
    fn eq(&self, other: &Self) -> bool {
        self.gn_addr == other.gn_addr
            && self.tst == other.tst
            && self.latitude == other.latitude
            && self.longitude == other.longitude
            && self.pai == other.pai
            && self.s == other.s
            && self.h == other.h
    }
}

impl LongPositionVector {
    /// Update position, speed, heading and accuracy from a GPS measurement.
    ///
    /// * `latitude_deg`  – latitude in degrees (positive = North)
    /// * `longitude_deg` – longitude in degrees (positive = East)
    /// * `speed_mps`     – speed in m/s (0.01 m/s resolution, max 163.82 m/s)
    /// * `heading_deg`   – heading in degrees (0 = North, clockwise)
    /// * `pai`           – position accuracy indicator
    pub fn update_from_gps(
        &mut self,
        latitude_deg: f64,
        longitude_deg: f64,
        speed_mps: f64,
        heading_deg: f64,
        pai: bool,
    ) {
        use std::time::SystemTime;
        // Encode latitude and longitude as 1/10 microdegrees (i32, cast to u32)
        self.latitude = ((latitude_deg * 1e7) as i32) as u32;
        self.longitude = ((longitude_deg * 1e7) as i32) as u32;
        // Speed in units of 0.01 m/s, 15-bit value
        self.s = ((speed_mps / 0.01) as u16).min(0x7FFF);
        // Heading in units of 0.1 degrees, 16-bit value
        self.h = ((heading_deg * 10.0) as u16) % 3600;
        self.pai = pai;
        // Update timestamp to current TAI time
        let unix_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.tst = Tst::set_in_normal_timestamp_milliseconds(unix_ms);
    }
}

#[derive(Clone, Debug)]
pub struct ShortPositionVector {
    pub gn_address: GNAddress,
    pub tst: Tst,
    pub latitude: u32,
    pub longitude: u32,
}

impl ShortPositionVector {
    pub fn encode(&self) -> [u8; 20] {
        let mut bytes: [u8; 20] = [0; 20];
        bytes[0..8].clone_from_slice(&self.gn_address.encode());
        bytes[8..12].clone_from_slice(&self.tst.encode());
        bytes[12..16].clone_from_slice(&self.latitude.to_be_bytes());
        bytes[16..20].clone_from_slice(&self.longitude.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; 20]) -> Self {
        let gn_address = GNAddress::decode(&bytes[0..8]);
        let tst = Tst::decode(&bytes[8..12]);
        let mut latitude: u32 = 0;
        for i in 0..4 {
            latitude |= (bytes[12 + i] as u32) << (8 * (3 - i));
        }
        let mut longitude: u32 = 0;
        for i in 0..4 {
            longitude |= (bytes[16 + i] as u32) << (8 * (3 - i));
        }
        ShortPositionVector {
            gn_address,
            tst,
            latitude,
            longitude,
        }
    }
}

impl PartialEq for ShortPositionVector {
    fn eq(&self, other: &Self) -> bool {
        self.gn_address == other.gn_address
            && self.tst == other.tst
            && self.latitude == other.latitude
            && self.longitude == other.longitude
    }
}

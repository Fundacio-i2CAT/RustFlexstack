// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! LS Extended Headers — ETSI EN 302 636-4-1 V1.4.1 (2020-01).
//!
//! - [`LSRequestExtendedHeader`] — §9.8.7 Table 16, 36 bytes.
//! - [`LSReplyExtendedHeader`]   — §9.8.8 Table 17, 48 bytes.

use super::gn_address::GNAddress;
use super::position_vector::{LongPositionVector, ShortPositionVector};

// ── LS Request Extended Header ──────────────────────────────────────────

/// LS Request Extended Header (36 bytes).
///
/// Layout:
///   SN               2 octets
///   Reserved         2 octets
///   SO PV           24 octets  (Long Position Vector)
///   Request GN_ADDR  8 octets
#[derive(Clone, PartialEq, Debug)]
pub struct LSRequestExtendedHeader {
    pub sn: u16,
    pub reserved: u16,
    pub so_pv: LongPositionVector,
    pub request_gn_addr: GNAddress,
}

impl LSRequestExtendedHeader {
    pub fn initialize(
        sequence_number: u16,
        ego_pv: LongPositionVector,
        request_gn_addr: GNAddress,
    ) -> Self {
        LSRequestExtendedHeader {
            sn: sequence_number,
            reserved: 0,
            so_pv: ego_pv,
            request_gn_addr,
        }
    }

    pub fn encode(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[0..2].copy_from_slice(&self.sn.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.reserved.to_be_bytes());
        bytes[4..28].copy_from_slice(&self.so_pv.encode());
        bytes[28..36].copy_from_slice(&self.request_gn_addr.encode());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 36, "LS Request Extended Header too short");
        let sn = u16::from_be_bytes([bytes[0], bytes[1]]);
        let reserved = u16::from_be_bytes([bytes[2], bytes[3]]);
        let so_pv = LongPositionVector::decode(bytes[4..28].try_into().unwrap());
        let request_gn_addr = GNAddress::decode(&bytes[28..36]);
        LSRequestExtendedHeader {
            sn,
            reserved,
            so_pv,
            request_gn_addr,
        }
    }
}

// ── LS Reply Extended Header ────────────────────────────────────────────

/// LS Reply Extended Header (48 bytes).
///
/// Layout (identical to GUC Extended Header §9.8.2):
///   SN        2 octets
///   Reserved  2 octets
///   SO PV    24 octets  (Long Position Vector — replier)
///   DE PV    20 octets  (Short Position Vector — requester)
#[derive(Clone, PartialEq, Debug)]
pub struct LSReplyExtendedHeader {
    pub sn: u16,
    pub reserved: u16,
    pub so_pv: LongPositionVector,
    pub de_pv: ShortPositionVector,
}

impl LSReplyExtendedHeader {
    pub fn initialize(
        sequence_number: u16,
        ego_pv: LongPositionVector,
        de_pv: ShortPositionVector,
    ) -> Self {
        LSReplyExtendedHeader {
            sn: sequence_number,
            reserved: 0,
            so_pv: ego_pv,
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
        assert!(bytes.len() >= 48, "LS Reply Extended Header too short");
        let sn = u16::from_be_bytes([bytes[0], bytes[1]]);
        let reserved = u16::from_be_bytes([bytes[2], bytes[3]]);
        let so_pv = LongPositionVector::decode(bytes[4..28].try_into().unwrap());
        let de_pv = ShortPositionVector::decode(bytes[28..48].try_into().unwrap());
        LSReplyExtendedHeader {
            sn,
            reserved,
            so_pv,
            de_pv,
        }
    }
}

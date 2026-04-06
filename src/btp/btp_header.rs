// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! BTP (Basic Transport Protocol) header structures.
//!
//! ETSI EN 302 636-5-1 defines two header variants:
//!
//! | Header | Field 1            | Field 2          | Use case                  |
//! |--------|--------------------|------------------|---------------------------|
//! | BTP-A  | Destination port   | Source port      | Acknowledged / unicast    |
//! | BTP-B  | Destination port   | Port info        | Connectionless / broadcast|
//!
//! Both headers are 4 bytes long.

use super::service_access_point::BTPDataRequest;

// ------------------------------------------------------------------
// BTP-A header
// ------------------------------------------------------------------

/// BTP-A header: carries both destination *and* source port numbers.
///
/// Used when the sender wants the receiver to be able to reply to a specific
/// source port (connection-oriented / acknowledged communication).
#[derive(Debug)]
pub struct BTPAHeader {
    destination_port: u16,
    source_port: u16,
}

impl BTPAHeader {
    pub fn new() -> Self {
        BTPAHeader {
            destination_port: 0,
            source_port: 0,
        }
    }

    /// Build a BTP-A header from a [`BTPDataRequest`].
    pub fn initialize_with_request(request: &BTPDataRequest) -> Self {
        BTPAHeader {
            destination_port: request.destination_port,
            source_port: request.source_port,
        }
    }

    /// Return the destination port number.
    pub fn destination_port(&self) -> u16 {
        self.destination_port
    }

    /// Return the source port number.
    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    /// Encode to 4 bytes (big-endian): destination port, source port.
    pub fn encode(&self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&self.destination_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.source_port.to_be_bytes());
        bytes
    }

    /// Decode from 4 bytes.
    pub fn decode(bytes: [u8; 4]) -> Self {
        BTPAHeader {
            destination_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            source_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        }
    }
}

// ------------------------------------------------------------------
// BTP-B header
// ------------------------------------------------------------------

/// BTP-B header: carries a destination port and a 16-bit port info field.
///
/// The port info field can carry additional protocol information (e.g. the
/// TPDU protocol ID for IP-over-GN use cases).  Used for connectionless
/// broadcast (CAM port 2001, DENM port 2002, …).
#[derive(Debug)]
pub struct BTPBHeader {
    /// Destination port (e.g. 2001 for CAM, 2002 for DENM).
    pub destination_port: u16,
    /// Extra port-info field (typically 0 for standard applications).
    pub destination_port_info: u16,
}

impl BTPBHeader {
    pub fn new() -> Self {
        BTPBHeader {
            destination_port: 0,
            destination_port_info: 0,
        }
    }

    /// Build a BTP-B header from a [`BTPDataRequest`].
    pub fn initialize_with_request(request: &BTPDataRequest) -> Self {
        BTPBHeader {
            destination_port: request.destination_port,
            destination_port_info: request.destination_port_info,
        }
    }

    /// Encode to 4 bytes (big-endian): destination port, port info.
    pub fn encode(&self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&self.destination_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.destination_port_info.to_be_bytes());
        bytes
    }

    /// Decode from 4 bytes.
    pub fn decode(bytes: [u8; 4]) -> Self {
        BTPBHeader {
            destination_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port_info: u16::from_be_bytes([bytes[2], bytes[3]]),
        }
    }
}

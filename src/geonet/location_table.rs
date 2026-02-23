// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Location Table — stores position vectors and PDR for known GeoNetworking peers.
//!
//! The [`LocationTable`] is the GN-equivalent of an ARP table: it maps a
//! [`GNAddress`] to a [`LocationTableEntry`] that carries the most recent
//! Long Position Vector (LPV), a neighbour flag, and a Duplicate Packet List
//! (DPL) used for duplicate-packet detection.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::SystemTime;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use super::gbc_extended_header::GBCExtendedHeader;
use super::gn_address::GNAddress;
use super::mib::Mib;
use super::position_vector::{LongPositionVector, Tst};

fn packet_hash(data: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    h.finish()
}

/// A single row in the Location Table.
///
/// Holds the most recent LPV from a remote station, its neighbour status,
/// a Duplicate Packet List (DPL), and a smoothed Packet Data Rate estimate.
#[derive(Clone, PartialEq)]
pub struct LocationTableEntry {
    /// Copy of the MIB used to read tunable parameters (e.g. DPL length, PDR beta).
    pub mib: Mib,
    /// Most recent Long Position Vector received from this station.
    pub position_vector: LongPositionVector,
    /// Whether a Location Service request is pending for this entry.
    pub ls_pending: bool,
    /// `true` if the last received packet was a SHB (single-hop neighbour).
    pub is_neighbour: bool,
    /// Duplicate Packet List — circular buffer of recently seen packet hashes.
    pub dpl: VecDeque<u64>,
    /// Timestamp of the last packet used for PDR estimation.
    pub tst: Tst,
    /// Smoothed Packet Data Rate in bytes/s (EMA).
    pub pdr: u16,
}

impl LocationTableEntry {
    /// Create a new, empty entry seeded from `mib`.
    pub fn new(mib: Mib) -> Self {
        LocationTableEntry {
            mib,
            position_vector: LongPositionVector::decode([0u8; 24]),
            ls_pending: false,
            is_neighbour: false,
            dpl: VecDeque::new(),
            tst: Tst::set_in_normal_timestamp_milliseconds(0),
            pdr: 0,
        }
    }

    /// Update the stored LPV only if `position_vector` is strictly newer
    /// (ETSI EN 302 636-4-1 Annex C.2).
    pub fn update_position_vector(&mut self, position_vector: &LongPositionVector) {
        if position_vector.tst > self.position_vector.tst {
            self.position_vector = *position_vector;
        }
    }

    /// Update the smoothed PDR estimate using the EMA formula:
    ///
    /// `PDR_new = β · PDR_old + (1 − β) · current_rate`
    pub fn update_pdr(&mut self, position_vector: &LongPositionVector, packet_size: u16) {
        let elapsed_ms = position_vector.tst - self.tst;
        self.tst = position_vector.tst;
        if elapsed_ms > 0 {
            let current_pdr = (packet_size as u32 * 1000 / elapsed_ms as u32) as u16;
            let beta = self.mib.itsGnMaxPacketDataRateEmaBeta as f32 / 100.0;
            self.pdr = (beta * self.pdr as f32 + (1.0 - beta) * current_pdr as f32) as u16;
        }
    }

    /// Process a received SHB (TSB Single-Hop Broadcast) packet.
    ///
    /// The first 24 bytes of `packet` must be the sender's Long Position Vector.
    /// Returns `true` if the packet is new (not a duplicate).
    pub fn update_with_shb_packet(&mut self, packet: &[u8]) -> bool {
        let pv_bytes: [u8; 24] = packet[0..24].try_into().unwrap();
        let position_vector = LongPositionVector::decode(pv_bytes);
        let is_new = self.check_duplicate_packet(packet);
        self.update_position_vector(&position_vector);
        self.update_pdr(&position_vector, (packet.len() + 12) as u16);
        self.is_neighbour = true;
        is_new
    }

    /// Process a received GBC (Geo-Broadcast) packet.
    ///
    /// The LPV is taken from `gbc_extended_header`.
    /// The entry is *not* marked as a direct neighbour.
    /// Returns `true` if the packet is new (not a duplicate).
    pub fn update_with_gbc_packet(
        &mut self,
        packet: &[u8],
        gbc_extended_header: &GBCExtendedHeader,
    ) -> bool {
        let position_vector = gbc_extended_header.so_pv;
        let is_new = self.check_duplicate_packet(packet);
        self.update_position_vector(&position_vector);
        self.update_pdr(&position_vector, (packet.len() + 12) as u16);
        self.is_neighbour = false;
        is_new
    }

    /// Return `true` if `packet` has not been seen before and record its hash.
    /// When the DPL is full the oldest entry is evicted (FIFO circular buffer).
    pub fn check_duplicate_packet(&mut self, packet: &[u8]) -> bool {
        let hash = packet_hash(packet);
        if self.dpl.contains(&hash) {
            return false;
        }
        self.dpl.push_back(hash);
        let max_len = self.mib.itsGnDPLLength as usize;
        while self.dpl.len() > max_len {
            self.dpl.pop_front();
        }
        true
    }
}

// ------------------------------------------------------------------
// LocationTable
// ------------------------------------------------------------------

/// The GeoNetworking Location Table.
///
/// Stores one [`LocationTableEntry`] per remote GN address.  Entries are
/// created lazily on first contact and expire after
/// `mib.itsGnLifetimeLocTE` seconds without an update.
pub struct LocationTable {
    /// MIB used when creating new entries.
    pub mib: Mib,
    /// O(1) address → entry map keyed by the 64-bit encoded GN address.
    pub entries: HashMap<u64, LocationTableEntry>,
}

impl LocationTable {
    /// Create an empty location table.
    pub fn new(mib: Mib) -> Self {
        LocationTable {
            mib,
            entries: HashMap::new(),
        }
    }

    /// Look up a mutable reference to the entry for `gn_address`, or `None`.
    pub fn get_entry(&mut self, gn_address: &GNAddress) -> Option<&mut LocationTableEntry> {
        self.entries.get_mut(&gn_address.encode_to_int())
    }

    /// Remove all entries whose LPV timestamp is older than
    /// `itsGnLifetimeLocTE` seconds.  Uses `retain` to avoid index bugs.
    pub fn refresh_table(&mut self) {
        let current_time = Tst::set_in_normal_timestamp_seconds(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
        );
        let lifetime_ms = (self.mib.itsGnLifetimeLocTE as u32) * 1000;
        self.entries.retain(|_, entry| {
            (current_time - entry.position_vector.tst) <= lifetime_ms
        });
    }

    /// Insert or update an entry for a newly received SHB packet.
    pub fn new_shb_packet(&mut self, position_vector: &LongPositionVector, packet: &[u8]) {
        let key = position_vector.gn_addr.encode_to_int();
        let mib = self.mib;
        let entry = self.entries.entry(key).or_insert_with(|| LocationTableEntry::new(mib));
        entry.update_with_shb_packet(packet);
    }

    /// Insert or update an entry for a newly received GBC packet.
    pub fn new_gbc_packet(&mut self, gbc_extended_header: &GBCExtendedHeader, packet: &[u8]) {
        let key = gbc_extended_header.so_pv.gn_addr.encode_to_int();
        let mib = self.mib;
        let entry = self.entries.entry(key).or_insert_with(|| LocationTableEntry::new(mib));
        // Correctly call update_with_gbc_packet (was copy-paste bug calling update_with_shb_packet)
        entry.update_with_gbc_packet(packet, gbc_extended_header);
    }

    /// Return a snapshot of all current neighbour entries
    /// (those for which the last received packet was a SHB).
    pub fn get_neighbours(&self) -> Vec<LocationTableEntry> {
        self.entries
            .values()
            .filter(|e| e.is_neighbour)
            .cloned()
            .collect()
    }
}

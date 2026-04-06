// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Location Table — stores position vectors and PDR for known GeoNetworking peers.
//!
//! Implements §8.1 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).
//!
//! Duplicate Packet Detection (DPD) uses **sequence-number-based** ring
//! buffers per source (Annex A.2).  SHB/Beacon packets have no SN field
//! and must NOT be duplicate-checked via SN (§A.1).

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::SystemTime;

use super::gbc_extended_header::GBCExtendedHeader;
use super::gn_address::GNAddress;
use super::guc_extended_header::GUCExtendedHeader;
use super::ls_extended_header::{LSReplyExtendedHeader, LSRequestExtendedHeader};
use super::mib::Mib;
use super::position_vector::{LongPositionVector, Tst};
use super::tsb_extended_header::TSBExtendedHeader;

/// A single row in the Location Table.
#[derive(Clone)]
pub struct LocationTableEntry {
    pub mib: Mib,
    pub position_vector: LongPositionVector,
    pub ls_pending: bool,
    pub is_neighbour: bool,
    /// Duplicate Packet List — ring buffer of recently seen sequence numbers (Annex A.2).
    pub dpl_deque: VecDeque<u16>,
    /// O(1) SN lookup companion to `dpl_deque`.
    pub dpl_set: HashSet<u16>,
    /// Timestamp of the last PDR measurement.
    pub tst: Tst,
    /// Smoothed Packet Data Rate in bytes/s (EMA, Annex B.2).
    pub pdr: f64,
}

impl LocationTableEntry {
    pub fn new(mib: Mib) -> Self {
        LocationTableEntry {
            mib,
            position_vector: LongPositionVector::decode([0u8; 24]),
            ls_pending: false,
            is_neighbour: false,
            dpl_deque: VecDeque::new(),
            dpl_set: HashSet::new(),
            tst: Tst::set_in_normal_timestamp_milliseconds(0),
            pdr: 0.0,
        }
    }

    /// Update the stored LPV only if strictly newer (§C.2).
    /// When the stored TST is zero (initial entry), accepts unconditionally.
    pub fn update_position_vector(&mut self, position_vector: &LongPositionVector) {
        if self.position_vector.tst == Tst::set_in_normal_timestamp_milliseconds(0) {
            self.position_vector = *position_vector;
        } else if position_vector.tst > self.position_vector.tst {
            self.position_vector = *position_vector;
        }
    }

    /// Update the smoothed PDR estimate (EMA, Annex B.2).
    pub fn update_pdr(&mut self, position_vector: &LongPositionVector, packet_size: u32) {
        let elapsed_ms = position_vector.tst - self.tst;
        self.tst = position_vector.tst;
        if elapsed_ms > 0 {
            let time_since = elapsed_ms as f64 / 1000.0;
            let current_pdr = packet_size as f64 / time_since;
            let beta = self.mib.itsGnMaxPacketDataRateEmaBeta as f64 / 100.0;
            self.pdr = beta * self.pdr + (1.0 - beta) * current_pdr;
        }
    }

    /// SN-based DPD per Annex A.2.  Returns `true` if duplicate.
    ///
    /// Only applicable to multi-hop packets (GUC, TSB, GBC, GAC, LS).
    /// BEACON and SHB do NOT carry an SN field and must NOT call this.
    pub fn check_duplicate_sn(&mut self, sn: u16) -> bool {
        if self.dpl_set.contains(&sn) {
            return true;
        }
        let max_len = self.mib.itsGnDPLLength as usize;
        if self.dpl_deque.len() >= max_len {
            if let Some(oldest) = self.dpl_deque.pop_front() {
                self.dpl_set.remove(&oldest);
            }
        }
        self.dpl_deque.push_back(sn);
        self.dpl_set.insert(sn);
        false
    }

    /// Process a received SHB packet (§10.3.10.3 steps 4-6).
    /// SHB has no SN — DPD does not apply (§A.1).
    pub fn update_with_shb_packet(
        &mut self,
        position_vector: &LongPositionVector,
        packet_size: u32,
    ) {
        self.update_position_vector(position_vector);
        self.update_pdr(position_vector, packet_size);
        self.is_neighbour = true;
    }

    /// Process a received GBC packet (§10.3.11.3 steps 3-6).
    pub fn update_with_gbc_packet(
        &mut self,
        gbc_extended_header: &GBCExtendedHeader,
        packet_size: u32,
    ) -> bool {
        if self.check_duplicate_sn(gbc_extended_header.sn) {
            return true;
        }
        self.update_position_vector(&gbc_extended_header.so_pv);
        self.update_pdr(&gbc_extended_header.so_pv, packet_size);
        self.is_neighbour = false;
        false
    }

    /// Process a received TSB packet (§10.3.9.3 steps 3-6).
    pub fn update_with_tsb_packet(
        &mut self,
        tsb_extended_header: &TSBExtendedHeader,
        packet_size: u32,
        is_new_entry: bool,
    ) -> bool {
        if self.check_duplicate_sn(tsb_extended_header.sn) {
            return true;
        }
        self.update_position_vector(&tsb_extended_header.so_pv);
        self.update_pdr(&tsb_extended_header.so_pv, packet_size);
        if is_new_entry {
            self.is_neighbour = false;
        }
        false
    }
}

// ------------------------------------------------------------------
// LocationTable
// ------------------------------------------------------------------

pub struct LocationTable {
    pub mib: Mib,
    pub entries: HashMap<u64, LocationTableEntry>,
}

impl LocationTable {
    pub fn new(mib: Mib) -> Self {
        LocationTable {
            mib,
            entries: HashMap::new(),
        }
    }

    pub fn get_entry(&mut self, gn_address: &GNAddress) -> Option<&mut LocationTableEntry> {
        self.entries.get_mut(&gn_address.encode_to_int())
    }

    pub fn get_entry_ref(&self, gn_address: &GNAddress) -> Option<&LocationTableEntry> {
        self.entries.get(&gn_address.encode_to_int())
    }

    /// Get or create a LocTE without modifying fields (for Location Service).
    pub fn ensure_entry(&mut self, gn_address: &GNAddress) -> &mut LocationTableEntry {
        let key = gn_address.encode_to_int();
        let mib = self.mib;
        self.entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib))
    }

    /// Remove expired entries (§8.1.3).
    pub fn refresh_table(&mut self) {
        let current_time = Tst::set_in_normal_timestamp_seconds(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
        );
        let lifetime_ms = (self.mib.itsGnLifetimeLocTE as u32) * 1000;
        self.entries
            .retain(|_, entry| (current_time - entry.position_vector.tst) <= lifetime_ms);
    }

    pub fn new_shb_packet(&mut self, position_vector: &LongPositionVector, packet: &[u8]) {
        let key = position_vector.gn_addr.encode_to_int();
        let mib = self.mib;
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        entry.update_with_shb_packet(position_vector, (packet.len() + 12) as u32);
        self.refresh_table();
    }

    /// Returns `true` if the packet is a duplicate.
    pub fn new_gbc_packet(
        &mut self,
        gbc_extended_header: &GBCExtendedHeader,
        packet: &[u8],
    ) -> bool {
        let key = gbc_extended_header.so_pv.gn_addr.encode_to_int();
        let mib = self.mib;
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        let dup = entry.update_with_gbc_packet(gbc_extended_header, (packet.len() + 12) as u32);
        self.refresh_table();
        dup
    }

    /// Returns `true` if the packet is a duplicate.
    pub fn new_guc_packet(
        &mut self,
        guc_extended_header: &GUCExtendedHeader,
        packet: &[u8],
    ) -> bool {
        let so_pv = &guc_extended_header.so_pv;
        let key = so_pv.gn_addr.encode_to_int();
        let mib = self.mib;
        let is_new_entry = !self.entries.contains_key(&key);
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        if entry.check_duplicate_sn(guc_extended_header.sn) {
            return true;
        }
        entry.update_position_vector(so_pv);
        entry.update_pdr(so_pv, (packet.len() + 12) as u32);
        if is_new_entry {
            entry.is_neighbour = false;
        }
        self.refresh_table();
        false
    }

    /// Returns `true` if the packet is a duplicate.
    pub fn new_tsb_packet(
        &mut self,
        tsb_extended_header: &TSBExtendedHeader,
        packet: &[u8],
    ) -> bool {
        let key = tsb_extended_header.so_pv.gn_addr.encode_to_int();
        let mib = self.mib;
        let is_new_entry = !self.entries.contains_key(&key);
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        let dup = entry.update_with_tsb_packet(
            tsb_extended_header,
            (packet.len() + 12) as u32,
            is_new_entry,
        );
        self.refresh_table();
        dup
    }

    /// Returns `true` if the packet is a duplicate.
    pub fn new_gac_packet(
        &mut self,
        gbc_extended_header: &GBCExtendedHeader,
        packet: &[u8],
    ) -> bool {
        // GAC and GBC share wire format.
        let so_pv = &gbc_extended_header.so_pv;
        let key = so_pv.gn_addr.encode_to_int();
        let mib = self.mib;
        let is_new_entry = !self.entries.contains_key(&key);
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        if entry.check_duplicate_sn(gbc_extended_header.sn) {
            return true;
        }
        entry.update_position_vector(so_pv);
        entry.update_pdr(so_pv, (packet.len() + 12) as u32);
        if is_new_entry {
            entry.is_neighbour = false;
        }
        self.refresh_table();
        false
    }

    /// Returns `true` if the packet is a duplicate.
    pub fn new_ls_request_packet(
        &mut self,
        ls_request_header: &LSRequestExtendedHeader,
        packet: &[u8],
    ) -> bool {
        let so_pv = &ls_request_header.so_pv;
        let key = so_pv.gn_addr.encode_to_int();
        let mib = self.mib;
        let is_new_entry = !self.entries.contains_key(&key);
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        if entry.check_duplicate_sn(ls_request_header.sn) {
            return true;
        }
        entry.update_position_vector(so_pv);
        entry.update_pdr(so_pv, (packet.len() + 12) as u32);
        if is_new_entry {
            entry.is_neighbour = false;
        }
        self.refresh_table();
        false
    }

    /// Returns `true` if the packet is a duplicate.
    pub fn new_ls_reply_packet(
        &mut self,
        ls_reply_header: &LSReplyExtendedHeader,
        packet: &[u8],
    ) -> bool {
        let so_pv = &ls_reply_header.so_pv;
        let key = so_pv.gn_addr.encode_to_int();
        let mib = self.mib;
        let is_new_entry = !self.entries.contains_key(&key);
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        if entry.check_duplicate_sn(ls_reply_header.sn) {
            return true;
        }
        entry.update_position_vector(so_pv);
        entry.update_pdr(so_pv, (packet.len() + 12) as u32);
        if is_new_entry {
            entry.is_neighbour = false;
        }
        self.refresh_table();
        false
    }

    pub fn get_neighbours(&self) -> Vec<&LocationTableEntry> {
        self.entries.values().filter(|e| e.is_neighbour).collect()
    }
}

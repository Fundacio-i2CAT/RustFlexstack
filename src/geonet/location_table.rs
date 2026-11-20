// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Location Table — stores position vectors and PDR for known GeoNetworking peers.
//!
//! Implements §8.2 of ETSI TS 103 836-4-1 V2.2.1 (2026-04).
//!
//! Duplicate Packet Detection (DPD) uses **sequence-number-based** ring
//! buffers per source (Annex A.2).  SHB/Beacon packets have no SN field
//! and must NOT be duplicate-checked via SN (§A.1).

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

use super::gbc_extended_header::GBCExtendedHeader;
use super::gn_address::{GNAddress, MID};
use super::guc_extended_header::GUCExtendedHeader;
use super::ls_extended_header::{LSReplyExtendedHeader, LSRequestExtendedHeader};
use super::mib::Mib;
use super::position_vector::{LongPositionVector, ShortPositionVector, Tst};
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
    /// Local time (ms, router clock) of the last update: start of the
    /// itsGnLifetimeLocTE soft-state timer (clause 8.2.3).
    pub updated_ms: Option<u64>,
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
            updated_ms: None,
        }
    }

    /// Update the stored LPV only if strictly newer (§C.2).
    /// When the stored TST is zero (initial entry), accepts unconditionally.
    pub fn update_position_vector(&mut self, position_vector: &LongPositionVector) {
        if self.position_vector.tst == Tst::set_in_normal_timestamp_milliseconds(0)
            || position_vector.tst > self.position_vector.tst
        {
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
    /// Local time (ms, router clock); see [`LocationTable::set_now`].
    now_ms: u64,
}

impl LocationTable {
    pub fn new(mib: Mib) -> Self {
        LocationTable {
            mib,
            entries: HashMap::new(),
            now_ms: 0,
        }
    }

    /// Local time (ms, router clock) used for the LocTE lifetime; the router
    /// sets it before processing a request, a packet or its timers.
    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// Whether the soft-state lifetime of `entry` has not expired (clause
    /// 8.2.3). Entries of a pending Location Service carry no PV yet; they
    /// are removed by the LS itself (clause 10.3.7.1.3).
    fn alive(&self, entry: &LocationTableEntry) -> bool {
        let lifetime_ms = u64::from(self.mib.itsGnLifetimeLocTE) * 1000;
        entry.ls_pending
            || entry
                .updated_ms
                .is_none_or(|updated| self.now_ms.saturating_sub(updated) <= lifetime_ms)
    }

    pub fn get_entry(&mut self, gn_address: &GNAddress) -> Option<&mut LocationTableEntry> {
        self.refresh_table();
        self.entries.get_mut(&gn_address.encode_to_int())
    }

    /// LocTE of `gn_address`; `None` when absent or expired.
    pub fn get_entry_ref(&self, gn_address: &GNAddress) -> Option<&LocationTableEntry> {
        self.entries
            .get(&gn_address.encode_to_int())
            .filter(|entry| self.alive(entry))
    }

    /// Forwarder step 7 of clauses 10.3.8.3 / 10.3.7.2: when the DE LocTE
    /// does not exist or is not a neighbour, update PV(DE) with the DE PV of
    /// the packet (clause C.2, only when newer). The DE PV is a Short
    /// Position Vector: PAI, speed and heading are set to 0 (NOTE 3).
    pub fn update_with_de_pv(&mut self, de_pv: &ShortPositionVector) {
        let key = de_pv.gn_address.encode_to_int();
        let mib = self.mib;
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        if entry.is_neighbour {
            return;
        }
        entry.update_position_vector(&LongPositionVector {
            gn_addr: de_pv.gn_address,
            tst: de_pv.tst,
            latitude: de_pv.latitude,
            longitude: de_pv.longitude,
            pai: false,
            s: 0,
            h: 0,
        });
        self.touch(key);
    }

    /// Restart the lifetime of an updated LocTE, then expire the others.
    fn touch(&mut self, key: u64) {
        let now = self.now_ms;
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.updated_ms = Some(now);
        }
        self.refresh_table();
    }

    /// Get or create a LocTE without modifying fields (for Location Service).
    pub fn ensure_entry(&mut self, gn_address: &GNAddress) -> &mut LocationTableEntry {
        let key = gn_address.encode_to_int();
        let mib = self.mib;
        self.entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib))
    }

    /// LocTE whose GN_ADDR carries the link-layer address `mid` in its MID
    /// field, used to identify the previous sender of a received packet.
    pub fn get_entry_by_mid(&self, mid: &[u8; 6]) -> Option<&LocationTableEntry> {
        let address = MID::new(*mid).encode_to_address();
        self.entries
            .iter()
            .find(|(key, entry)| *key & 0xFFFF_FFFF_FFFF == address && self.alive(entry))
            .map(|(_, entry)| entry)
    }

    /// Remove the LocTE of `gn_address` (e.g. when a LS does not complete).
    pub fn remove_entry(&mut self, gn_address: &GNAddress) {
        self.entries.remove(&gn_address.encode_to_int());
    }

    /// Remove the entries whose soft-state lifetime itsGnLifetimeLocTE,
    /// restarted at each update on the local clock, has expired (clause
    /// 8.2.3). Entries created without update start their lifetime now.
    pub fn refresh_table(&mut self) {
        let now = self.now_ms;
        for entry in self.entries.values_mut() {
            entry.updated_ms.get_or_insert(now);
        }
        let lifetime_ms = u64::from(self.mib.itsGnLifetimeLocTE) * 1000;
        self.entries.retain(|_, entry| {
            entry.ls_pending
                || entry
                    .updated_ms
                    .is_none_or(|updated| now.saturating_sub(updated) <= lifetime_ms)
        });
    }

    pub fn new_shb_packet(&mut self, position_vector: &LongPositionVector, packet: &[u8]) {
        let key = position_vector.gn_addr.encode_to_int();
        let mib = self.mib;
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| LocationTableEntry::new(mib));
        entry.update_with_shb_packet(position_vector, (packet.len() + 12) as u32);
        self.touch(key);
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
        if dup {
            self.refresh_table();
        } else {
            self.touch(key);
        }
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
        self.touch(key);
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
        if dup {
            self.refresh_table();
        } else {
            self.touch(key);
        }
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
        self.touch(key);
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
        self.touch(key);
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
        self.touch(key);
        false
    }

    pub fn get_neighbours(&self) -> Vec<&LocationTableEntry> {
        self.entries
            .values()
            .filter(|e| e.is_neighbour && self.alive(e))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geonet::gn_address::{GNAddress, M, MID, ST};
    use crate::geonet::position_vector::{LongPositionVector, Tst};

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn make_mib() -> Mib {
        Mib::new()
    }

    fn make_lpv(mid: [u8; 6], msec: u64) -> LongPositionVector {
        LongPositionVector {
            gn_addr: GNAddress::new(M::GnUnicast, ST::PassengerCar, MID::new(mid)),
            tst: Tst::set_in_normal_timestamp_milliseconds(msec),
            latitude: 415520000,
            longitude: 21340000,
            pai: true,
            s: 500,
            h: 900,
        }
    }

    // ── LocationTableEntry ────────────────────────────────────────────

    #[test]
    fn entry_new_defaults() {
        let entry = LocationTableEntry::new(make_mib());
        assert!(!entry.is_neighbour);
        assert!(!entry.ls_pending);
        assert!(entry.dpl_deque.is_empty());
        assert_eq!(entry.pdr, 0.0);
    }

    #[test]
    fn entry_update_position_vector_accepts_newer() {
        let mut entry = LocationTableEntry::new(make_mib());
        let pv1 = make_lpv([1, 2, 3, 4, 5, 6], 1_717_200_000_000);
        let pv2 = make_lpv([1, 2, 3, 4, 5, 6], 1_717_200_001_000);

        entry.update_position_vector(&pv1);
        assert_eq!(entry.position_vector.tst, pv1.tst);

        entry.update_position_vector(&pv2);
        assert_eq!(entry.position_vector.tst, pv2.tst);
    }

    #[test]
    fn entry_update_position_vector_rejects_older() {
        let mut entry = LocationTableEntry::new(make_mib());
        let pv_new = make_lpv([1, 2, 3, 4, 5, 6], 1_717_200_001_000);
        let pv_old = make_lpv([1, 2, 3, 4, 5, 6], 1_717_200_000_000);

        entry.update_position_vector(&pv_new);
        entry.update_position_vector(&pv_old);
        // Should still be pv_new
        assert_eq!(entry.position_vector.tst, pv_new.tst);
    }

    #[test]
    fn entry_check_duplicate_sn_not_duplicate() {
        let mut entry = LocationTableEntry::new(make_mib());
        assert!(!entry.check_duplicate_sn(1));
        assert!(!entry.check_duplicate_sn(2));
        assert!(!entry.check_duplicate_sn(3));
    }

    #[test]
    fn entry_check_duplicate_sn_is_duplicate() {
        let mut entry = LocationTableEntry::new(make_mib());
        assert!(!entry.check_duplicate_sn(42));
        assert!(entry.check_duplicate_sn(42));
    }

    #[test]
    fn entry_dpl_ring_buffer_eviction() {
        let mib = make_mib();
        let max_len = mib.itsGnDPLLength as usize;
        let mut entry = LocationTableEntry::new(mib);

        // Fill the DPL
        for i in 0..max_len {
            assert!(!entry.check_duplicate_sn(i as u16));
        }
        assert_eq!(entry.dpl_deque.len(), max_len);

        // Add one more — oldest (0) should be evicted
        assert!(!entry.check_duplicate_sn(100));
        assert_eq!(entry.dpl_deque.len(), max_len);
        // SN 0 should no longer be marked as duplicate
        assert!(!entry.check_duplicate_sn(0));
    }

    #[test]
    fn entry_shb_packet_marks_neighbour() {
        let mut entry = LocationTableEntry::new(make_mib());
        let pv = make_lpv([1, 2, 3, 4, 5, 6], 1_717_200_000_000);
        entry.update_with_shb_packet(&pv, 100);
        assert!(entry.is_neighbour);
    }

    #[test]
    fn entry_gbc_packet_not_neighbour() {
        let mut entry = LocationTableEntry::new(make_mib());
        let gbc = GBCExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: make_lpv([1, 2, 3, 4, 5, 6], 1_717_200_000_000),
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
            reserved2: 0,
        };
        let dup = entry.update_with_gbc_packet(&gbc, 100);
        assert!(!dup);
        assert!(!entry.is_neighbour);
    }

    #[test]
    fn entry_gbc_packet_duplicate() {
        let mut entry = LocationTableEntry::new(make_mib());
        let gbc = GBCExtendedHeader {
            sn: 42,
            reserved: 0,
            so_pv: make_lpv([1, 2, 3, 4, 5, 6], 1_717_200_000_000),
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
            reserved2: 0,
        };
        assert!(!entry.update_with_gbc_packet(&gbc, 100));
        assert!(entry.update_with_gbc_packet(&gbc, 100));
    }

    // ── LocationTable ─────────────────────────────────────────────────

    #[test]
    fn table_new_empty() {
        let table = LocationTable::new(make_mib());
        assert!(table.entries.is_empty());
    }

    #[test]
    fn table_new_shb_creates_entry() {
        let mut table = LocationTable::new(make_mib());
        let pv = make_lpv([1, 2, 3, 4, 5, 6], now_ms());
        table.new_shb_packet(&pv, &[0u8; 10]);
        assert_eq!(table.entries.len(), 1);
        let entry = table.get_entry_ref(&pv.gn_addr).unwrap();
        assert!(entry.is_neighbour);
    }

    #[test]
    fn table_new_gbc_creates_entry() {
        let mut table = LocationTable::new(make_mib());
        let gbc = GBCExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: make_lpv([1, 2, 3, 4, 5, 6], now_ms()),
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
            reserved2: 0,
        };
        let dup = table.new_gbc_packet(&gbc, &[0u8; 10]);
        assert!(!dup);
        assert_eq!(table.entries.len(), 1);
    }

    #[test]
    fn table_new_gbc_duplicate() {
        let mut table = LocationTable::new(make_mib());
        let gbc = GBCExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: make_lpv([1, 2, 3, 4, 5, 6], now_ms()),
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
            reserved2: 0,
        };
        assert!(!table.new_gbc_packet(&gbc, &[0u8; 10]));
        assert!(table.new_gbc_packet(&gbc, &[0u8; 10]));
    }

    #[test]
    fn table_new_tsb_creates_entry() {
        let mut table = LocationTable::new(make_mib());
        let tsb = TSBExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: make_lpv([1, 2, 3, 4, 5, 6], now_ms()),
        };
        let dup = table.new_tsb_packet(&tsb, &[0u8; 10]);
        assert!(!dup);
        assert_eq!(table.entries.len(), 1);
    }

    #[test]
    fn table_new_guc_creates_entry() {
        let mut table = LocationTable::new(make_mib());
        let guc = GUCExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: make_lpv([1, 2, 3, 4, 5, 6], now_ms()),
            de_pv: crate::geonet::position_vector::ShortPositionVector::decode([0u8; 20]),
        };
        let dup = table.new_guc_packet(&guc, &[0u8; 10]);
        assert!(!dup);
        assert_eq!(table.entries.len(), 1);
    }

    #[test]
    fn table_new_ls_request_creates_entry() {
        let mut table = LocationTable::new(make_mib());
        let addr = GNAddress::new(M::GnUnicast, ST::Bus, MID::new([0xAA; 6]));
        let ls = LSRequestExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: make_lpv([1, 2, 3, 4, 5, 6], now_ms()),
            request_gn_addr: addr,
        };
        let dup = table.new_ls_request_packet(&ls, &[0u8; 10]);
        assert!(!dup);
        assert_eq!(table.entries.len(), 1);
    }

    #[test]
    fn table_new_ls_reply_creates_entry() {
        let mut table = LocationTable::new(make_mib());
        let ls = LSReplyExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: make_lpv([1, 2, 3, 4, 5, 6], now_ms()),
            de_pv: crate::geonet::position_vector::ShortPositionVector::decode([0u8; 20]),
        };
        let dup = table.new_ls_reply_packet(&ls, &[0u8; 10]);
        assert!(!dup);
    }

    #[test]
    fn table_get_neighbours() {
        let mut table = LocationTable::new(make_mib());
        // Add SHB (neighbour) and GBC (not neighbour)
        let pv1 = make_lpv([1, 2, 3, 4, 5, 6], now_ms());
        table.new_shb_packet(&pv1, &[0u8; 10]);

        let gbc = GBCExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: make_lpv([6, 5, 4, 3, 2, 1], now_ms()),
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
            reserved2: 0,
        };
        table.new_gbc_packet(&gbc, &[0u8; 10]);

        let neighbours = table.get_neighbours();
        assert_eq!(neighbours.len(), 1);
    }

    #[test]
    fn table_ensure_entry() {
        let mut table = LocationTable::new(make_mib());
        let addr = GNAddress::new(M::GnUnicast, ST::PassengerCar, MID::new([1; 6]));
        let _entry = table.ensure_entry(&addr);
        assert_eq!(table.entries.len(), 1);
        // Calling again doesn't create a second entry
        let _entry2 = table.ensure_entry(&addr);
        assert_eq!(table.entries.len(), 1);
    }

    // ── Refresh (clause 8.2) ──────────────────────────────────────────

    fn unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn refresh_keeps_ls_pending_placeholder() {
        let mut table = LocationTable::new(make_mib());
        let sought = make_lpv([2, 0, 0, 0, 0, 7], 0).gn_addr;
        table.ensure_entry(&sought).ls_pending = true;
        table.refresh_table();
        assert!(table.get_entry_ref(&sought).is_some());
    }

    /// §8.2.3: the LocTE lifetime runs on the local clock from the last
    /// update, whatever the sender's TST (a sender clock 60 s behind or 0.5 s
    /// ahead). Mirrors the Python test of the same name.
    #[test]
    fn lifetime_follows_local_clock_not_sender_tst() {
        let mut table = LocationTable::new(make_mib());
        let ahead = make_lpv([2, 0, 0, 0, 0, 1], unix_ms() + 500);
        let behind = make_lpv([2, 0, 0, 0, 0, 2], unix_ms() - 60_000);
        table.new_shb_packet(&ahead, &[]);
        table.new_shb_packet(&behind, &[]);
        assert!(table.get_entry_ref(&ahead.gn_addr).is_some());
        assert!(table.get_entry_ref(&behind.gn_addr).is_some());
        table.set_now(20_000);
        assert!(table.get_entry_ref(&ahead.gn_addr).is_some());
        table.set_now(20_001);
        assert!(table.get_entry_ref(&ahead.gn_addr).is_none());
        assert!(table.get_entry_ref(&behind.gn_addr).is_none());
    }

    #[test]
    fn entry_by_mid_and_removal() {
        let mut table = LocationTable::new(make_mib());
        let pv = make_lpv([2, 0, 0, 0, 0, 3], unix_ms());
        table.new_shb_packet(&pv, &[]);
        assert!(table.get_entry_by_mid(&[2, 0, 0, 0, 0, 3]).is_some());
        assert!(table.get_entry_by_mid(&[2, 0, 0, 0, 0, 4]).is_none());
        table.remove_entry(&pv.gn_addr);
        assert!(table.get_entry_ref(&pv.gn_addr).is_none());
    }
}

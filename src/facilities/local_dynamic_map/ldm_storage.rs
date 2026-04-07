// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! LDM in-memory storage — `ItsDataObject`, `StoredRecord`, `LdmStore`.
//!
//! `LdmStore` is the sole mutable state of the LDM; it is always wrapped in
//! `Arc<RwLock<LdmStore>>` so that readers (queries, subscription checks) can
//! proceed concurrently while writers (insert / update / delete) hold an
//! exclusive lock.
//!
//! # Design choices
//! * **`ItsDataObject` is a typed enum** — zero runtime overhead; no dynamic
//!   dispatch, no heap-allocated trait objects, no schema-on-the-wire parsing.
//! * **`HashMap<u64, StoredRecord>`** — O(1) lookup/insert/delete vs. the
//!   Python `TinyDB` O(n) list scans.
//! * **Record IDs** are generated from a monotonically increasing `u64`
//!   counter; they never repeat within a process lifetime.

use crate::facilities::ca_basic_service::cam_coder::Cam;
use crate::facilities::decentralized_environmental_notification_service::denm_coder::Denm;
use crate::facilities::local_dynamic_map::ldm_constants::now_its_ms;
use crate::facilities::vru_awareness_service::vam_coder::Vam;

use std::collections::HashMap;

// ─── ITS data object (typed enum, Option A) ──────────────────────────────────

/// A typed ITS data object stored in the LDM.
///
/// Each variant boxes the full PDU to keep `StoredRecord` lean when the LDM
/// holds a large population of mixed types.
#[derive(Debug)]
pub enum ItsDataObject {
    /// ETSI EN 302 637-2 Cooperative Awareness Message.
    Cam(Box<Cam>),
    /// ETSI EN 302 637-3 Decentralized Environmental Notification Message.
    Denm(Box<Denm>),
    /// ETSI TS 103 300-3 VRU Awareness Message.
    Vam(Box<Vam>),
    /// Unknown or future message type — stored as raw bytes.
    Unknown { its_aid: u32, raw: Vec<u8> },
}

impl ItsDataObject {
    /// Return the ITS-AID of this object's application type.
    pub fn its_aid(&self) -> u32 {
        use crate::facilities::local_dynamic_map::ldm_constants::{
            ITS_AID_CAM, ITS_AID_DENM, ITS_AID_VAM,
        };
        match self {
            ItsDataObject::Cam(_) => ITS_AID_CAM,
            ItsDataObject::Denm(_) => ITS_AID_DENM,
            ItsDataObject::Vam(_) => ITS_AID_VAM,
            ItsDataObject::Unknown { its_aid, .. } => *its_aid,
        }
    }
}

// ─── Stored record ────────────────────────────────────────────────────────────

/// A single LDM record.
///
/// All fields except `data_object` are plain integers or scalars so that
/// filtering and maintenance can inspect them without decoding the PDU.
#[derive(Debug)]
pub struct StoredRecord {
    /// LDM-assigned monotonic identifier.
    pub id: u64,
    /// ITS-AID of the data provider.
    pub application_id: u32,
    /// Time this record was inserted / last updated (ms since ITS epoch).
    pub timestamp_its_ms: u64,
    /// Validity window in seconds; record expires when
    /// `timestamp_its_ms + time_validity_s * 1000 < now`.
    pub time_validity_s: u32,
    /// Position latitude (ETSI × 1e7 integer units).
    pub lat_etsi: i32,
    /// Position longitude (ETSI × 1e7 integer units).
    pub lon_etsi: i32,
    /// Altitude in centimetres above WGS-84 ellipsoid.
    pub altitude_cm: i32,
    /// The ITS data object.
    pub data_object: ItsDataObject,
}

impl StoredRecord {
    /// Return `true` if this record has passed its validity horizon.
    pub fn is_expired(&self) -> bool {
        let expiry_ms = self.timestamp_its_ms + (self.time_validity_s as u64) * 1000;
        now_its_ms() > expiry_ms
    }
}

// ─── LDM store ───────────────────────────────────────────────────────────────

/// In-memory LDM record store.
///
/// Always shared behind `Arc<RwLock<LdmStore>>`.
pub struct LdmStore {
    records: HashMap<u64, StoredRecord>,
    next_id: u64,
}

impl LdmStore {
    /// Create an empty store.
    pub fn new() -> Self {
        LdmStore {
            records: HashMap::new(),
            next_id: 1,
        }
    }

    // ── Write operations ──────────────────────────────────────────────────

    /// Insert a new record and return its assigned ID.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        application_id: u32,
        timestamp_its_ms: u64,
        time_validity_s: u32,
        lat_etsi: i32,
        lon_etsi: i32,
        altitude_cm: i32,
        data_object: ItsDataObject,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.records.insert(
            id,
            StoredRecord {
                id,
                application_id,
                timestamp_its_ms,
                time_validity_s,
                lat_etsi,
                lon_etsi,
                altitude_cm,
                data_object,
            },
        );
        id
    }

    /// Replace an existing record's payload and metadata.
    ///
    /// Returns `false` when `id` is not found.
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        id: u64,
        timestamp_its_ms: u64,
        time_validity_s: u32,
        lat_etsi: i32,
        lon_etsi: i32,
        altitude_cm: i32,
        data_object: ItsDataObject,
    ) -> bool {
        if let Some(rec) = self.records.get_mut(&id) {
            rec.timestamp_its_ms = timestamp_its_ms;
            rec.time_validity_s = time_validity_s;
            rec.lat_etsi = lat_etsi;
            rec.lon_etsi = lon_etsi;
            rec.altitude_cm = altitude_cm;
            rec.data_object = data_object;
            true
        } else {
            false
        }
    }

    /// Remove a record by ID.  Returns `true` if the record existed.
    pub fn remove(&mut self, id: u64) -> bool {
        self.records.remove(&id).is_some()
    }

    /// Remove all expired records and return the count removed.
    pub fn remove_expired(&mut self) -> usize {
        let expired: Vec<u64> = self
            .records
            .values()
            .filter(|r| r.is_expired())
            .map(|r| r.id)
            .collect();
        let n = expired.len();
        for id in expired {
            self.records.remove(&id);
        }
        n
    }

    /// Remove all records whose position is outside a radius (metres) from
    /// a reference point, using the Haversine formula.
    pub fn remove_out_of_area(
        &mut self,
        area_lat_etsi: i32,
        area_lon_etsi: i32,
        area_radius_m: f64,
    ) -> usize {
        use crate::facilities::local_dynamic_map::ldm_constants::haversine_m;
        let out: Vec<u64> = self
            .records
            .values()
            .filter(|r| {
                haversine_m(r.lat_etsi, r.lon_etsi, area_lat_etsi, area_lon_etsi) > area_radius_m
            })
            .map(|r| r.id)
            .collect();
        let n = out.len();
        for id in out {
            self.records.remove(&id);
        }
        n
    }

    // ── Read operations ───────────────────────────────────────────────────

    /// Iterate over all stored records (immutable).
    pub fn iter(&self) -> impl Iterator<Item = &StoredRecord> {
        self.records.values()
    }

    /// Return the number of records currently in the store.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Return `true` when the store is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Default for LdmStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_new_empty() {
        let store = LdmStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn store_default() {
        let store = LdmStore::default();
        assert!(store.is_empty());
    }

    #[test]
    fn store_insert_returns_ids() {
        let mut store = LdmStore::new();
        let id1 = store.insert(
            36,
            1_000_000,
            60,
            415520000,
            21340000,
            12000,
            ItsDataObject::Unknown {
                its_aid: 36,
                raw: vec![0xCA],
            },
        );
        let id2 = store.insert(
            37,
            1_000_001,
            60,
            415520000,
            21340000,
            12000,
            ItsDataObject::Unknown {
                its_aid: 37,
                raw: vec![0xDE],
            },
        );
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn store_update_existing() {
        let mut store = LdmStore::new();
        let id = store.insert(
            36,
            1_000_000,
            60,
            0,
            0,
            0,
            ItsDataObject::Unknown {
                its_aid: 36,
                raw: vec![],
            },
        );
        let ok = store.update(
            id,
            2_000_000,
            120,
            100,
            200,
            300,
            ItsDataObject::Unknown {
                its_aid: 36,
                raw: vec![1],
            },
        );
        assert!(ok);
        let rec = store.iter().find(|r| r.id == id).unwrap();
        assert_eq!(rec.timestamp_its_ms, 2_000_000);
        assert_eq!(rec.time_validity_s, 120);
    }

    #[test]
    fn store_update_nonexistent() {
        let mut store = LdmStore::new();
        let ok = store.update(
            999,
            0,
            0,
            0,
            0,
            0,
            ItsDataObject::Unknown {
                its_aid: 0,
                raw: vec![],
            },
        );
        assert!(!ok);
    }

    #[test]
    fn store_remove() {
        let mut store = LdmStore::new();
        let id = store.insert(
            36,
            0,
            60,
            0,
            0,
            0,
            ItsDataObject::Unknown {
                its_aid: 36,
                raw: vec![],
            },
        );
        assert!(store.remove(id));
        assert!(store.is_empty());
        assert!(!store.remove(id));
    }

    #[test]
    fn store_remove_expired() {
        let mut store = LdmStore::new();
        // Insert a record that expired long ago
        store.insert(
            36,
            0, // timestamp = epoch
            1, // validity = 1 second
            0,
            0,
            0,
            ItsDataObject::Unknown {
                its_aid: 36,
                raw: vec![],
            },
        );
        let removed = store.remove_expired();
        assert_eq!(removed, 1);
        assert!(store.is_empty());
    }

    #[test]
    fn store_remove_out_of_area() {
        let mut store = LdmStore::new();
        // Insert a record at Barcelona (lat 41.552, lon 2.134)
        store.insert(
            36,
            now_its_ms(),
            3600,
            415520000,
            21340000,
            0,
            ItsDataObject::Unknown {
                its_aid: 36,
                raw: vec![],
            },
        );
        // Remove everything outside 1m of Madrid (40.4168, -3.7038)
        let removed = store.remove_out_of_area(404168000, -37038000, 1.0);
        assert_eq!(removed, 1);
    }

    #[test]
    fn store_iter() {
        let mut store = LdmStore::new();
        store.insert(
            36,
            0,
            3600,
            0,
            0,
            0,
            ItsDataObject::Unknown {
                its_aid: 36,
                raw: vec![],
            },
        );
        store.insert(
            37,
            0,
            3600,
            0,
            0,
            0,
            ItsDataObject::Unknown {
                its_aid: 37,
                raw: vec![],
            },
        );
        let count = store.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn its_data_object_its_aid() {
        assert_eq!(
            ItsDataObject::Unknown {
                its_aid: 99,
                raw: vec![]
            }
            .its_aid(),
            99
        );
    }
}

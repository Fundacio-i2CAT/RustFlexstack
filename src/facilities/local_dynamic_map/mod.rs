// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Local Dynamic Map (LDM) facility.
//!
//! Implements the ETSI TS 103 301 Local Dynamic Map in pure Rust, replacing
//! the Python reference's TinyDB JSON-on-disk backend with a lock-guarded
//! in-memory `HashMap`.
//!
//! # Architecture
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                      LdmFacility                         │
//! │                                                          │
//! │  IfLdm3 ──────────────────────────────────┐             │
//! │  (register/add/update/delete provider data) │             │
//! │                                             ▼             │
//! │                                    LdmService             │
//! │                                         │                 │
//! │  IfLdm4 ──────────────────────────────►─┤             │
//! │  (register/query/subscribe consumer)    │                 │
//! │                                         ▼                 │
//! │                                    LdmStore               │
//! │                              (HashMap<u64, StoredRecord>) │
//! │                                         ▲                 │
//! │                             LdmMaintenance (1 Hz thread)  │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick start
//! ```no_run
//! use rustflexstack::facilities::local_dynamic_map::{LdmFacility, LdmHandle};
//! use rustflexstack::facilities::local_dynamic_map::ldm_types::{
//!     RegisterDataConsumerReq, RequestDataObjectsReq,
//! };
//! use rustflexstack::facilities::local_dynamic_map::ldm_constants::ITS_AID_CAM;
//!
//! // Parc Tecnològic del Vallès, 5 km radius
//! let ldm: LdmHandle = LdmFacility::new(415_520_000, 21_340_000, 5_000.0);
//!
//! ldm.if_ldm_4.register_data_consumer(RegisterDataConsumerReq { application_id: ITS_AID_CAM });
//!
//! let resp = ldm.if_ldm_4.request_data_objects(RequestDataObjectsReq {
//!     application_id:    ITS_AID_CAM,
//!     data_object_types: vec![ITS_AID_CAM],
//!     filter:            None,
//!     order:             None,
//!     max_results:       None,
//! });
//! println!("LDM contains {} CAM record(s)", resp.data_objects.len());
//! ```

pub mod if_ldm_3;
pub mod if_ldm_4;
pub mod ldm_constants;
pub mod ldm_maintenance;
pub mod ldm_service;
pub mod ldm_storage;
pub mod ldm_types;

pub use if_ldm_3::IfLdm3;
pub use if_ldm_4::IfLdm4;
pub use ldm_storage::ItsDataObject;

use std::sync::Arc;

use ldm_maintenance::LdmMaintenance;
use ldm_service::LdmService;
use ldm_storage::LdmStore;

/// A cheaply-cloneable handle to a running LDM facility.
///
/// All clones share the same underlying service and store.
pub type LdmHandle = Arc<LdmFacility>;

/// Top-level LDM facility.
///
/// Holds both ETSI interfaces and exposes them as public fields so callers
/// can invoke provider and consumer operations directly:
///
/// ```no_run
/// # use rustflexstack::facilities::local_dynamic_map::{LdmFacility, LdmHandle};
/// # let ldm: LdmHandle = LdmFacility::new(0, 0, 0.0);
/// ldm.if_ldm_3.add_provider_data(/* ... */);
/// ldm.if_ldm_4.request_data_objects(/* ... */);
/// ```
pub struct LdmFacility {
    /// ETSI IF.LDM.3 — Data Provider interface.
    pub if_ldm_3: IfLdm3,
    /// ETSI IF.LDM.4 — Data Consumer interface.
    pub if_ldm_4: IfLdm4,
}

impl LdmFacility {
    /// Create a new LDM facility and spawn the maintenance thread.
    ///
    /// # Arguments
    /// * `area_lat_etsi`  — latitude of the local station (ETSI × 1e7).
    /// * `area_lon_etsi`  — longitude of the local station (ETSI × 1e7).
    /// * `area_radius_m`  — maintenance area radius in metres.
    ///                      Pass `0.0` to disable spatial GC.
    ///
    /// # Returns
    /// An `LdmHandle` (`Arc<LdmFacility>`) that can be shared freely across
    /// threads.
    pub fn new(area_lat_etsi: i32, area_lon_etsi: i32, area_radius_m: f64) -> LdmHandle {
        let store = Arc::new(std::sync::RwLock::new(LdmStore::new()));
        let service = LdmService::new(store);

        let if_ldm_3 = IfLdm3::new(service.clone());
        let if_ldm_4 = IfLdm4::new(service.clone());

        LdmMaintenance::spawn(service, area_lat_etsi, area_lon_etsi, area_radius_m);

        Arc::new(LdmFacility { if_ldm_3, if_ldm_4 })
    }
}

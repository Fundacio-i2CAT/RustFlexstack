// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! IF.LDM.3 — Data Provider interface.
//!
//! Exposes the five ETSI-specified operations that a data *provider* uses to
//! manage its objects in the LDM:
//!
//! | Operation | Description |
//! |-----------|-------------|
//! | `register_data_provider`   | Announce a new provider to the LDM. |
//! | `deregister_data_provider` | Remove a provider registration. |
//! | `add_provider_data`        | Insert a new data object. |
//! | `update_provider_data`     | Replace an existing data object. |
//! | `delete_provider_data`     | Remove a data object by record ID. |
//!
//! All methods are thin delegations to `LdmService`.

use std::sync::Arc;

use crate::facilities::local_dynamic_map::ldm_service::LdmService;
use crate::facilities::local_dynamic_map::ldm_types::{
    AddDataProviderReq, AddDataProviderResp,
    DeleteDataProviderReq, DeleteDataProviderResp,
    DeregisterDataProviderReq, DeregisterDataProviderResp,
    RegisterDataProviderReq, RegisterDataProviderResp,
    UpdateDataProviderReq, UpdateDataProviderResp,
};

/// ETSI IF.LDM.3 — Data Provider interface.
///
/// Cheap to clone; all state is behind `Arc<LdmService>`.
#[derive(Clone)]
pub struct IfLdm3 {
    service: Arc<LdmService>,
}

impl IfLdm3 {
    pub(crate) fn new(service: Arc<LdmService>) -> Self {
        IfLdm3 { service }
    }

    /// Register a data provider by its ITS-AID.
    ///
    /// Idempotent — re-registering the same AID is accepted silently.
    pub fn register_data_provider(&self, req: RegisterDataProviderReq) -> RegisterDataProviderResp {
        self.service.register_data_provider(req)
    }

    /// Deregister a data provider.
    pub fn deregister_data_provider(
        &self,
        req: DeregisterDataProviderReq,
    ) -> DeregisterDataProviderResp {
        self.service.deregister_data_provider(req)
    }

    /// Insert a new ITS data object into the LDM.
    ///
    /// On success the response contains the assigned `record_id`.
    pub fn add_provider_data(&self, req: AddDataProviderReq) -> AddDataProviderResp {
        self.service.add_provider_data(req)
    }

    /// Replace the payload and metadata of an existing record.
    pub fn update_provider_data(&self, req: UpdateDataProviderReq) -> UpdateDataProviderResp {
        self.service.update_provider_data(req)
    }

    /// Delete a record by its LDM-assigned `record_id`.
    pub fn delete_provider_data(&self, req: DeleteDataProviderReq) -> DeleteDataProviderResp {
        self.service.delete_provider_data(req)
    }
}

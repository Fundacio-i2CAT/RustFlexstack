// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! IF.LDM.4 — Data Consumer interface.
//!
//! Exposes the five ETSI-specified operations that a data *consumer* uses to
//! retrieve objects from the LDM:
//!
//! | Operation | Description |
//! |-----------|-------------|
//! | `register_data_consumer`   | Announce a new consumer to the LDM. |
//! | `deregister_data_consumer` | Remove a consumer registration. |
//! | `request_data_objects`     | One-shot query returning matching records. |
//! | `subscribe_data_consumer`  | Periodic push: returns a channel `Receiver`. |
//! | `unsubscribe_data_consumer`| Cancel an active subscription. |
//!
//! All methods are thin delegations to `LdmService`.

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use crate::facilities::local_dynamic_map::ldm_service::LdmService;
use crate::facilities::local_dynamic_map::ldm_types::{
    DeregisterDataConsumerReq, DeregisterDataConsumerResp, RegisterDataConsumerReq,
    RegisterDataConsumerResp, RequestDataObjectsReq, RequestDataObjectsResp,
    SubscribeDataObjectsReq, SubscribeDataObjectsResp, UnsubscribeDataConsumerReq,
    UnsubscribeDataConsumerResp,
};

/// ETSI IF.LDM.4 — Data Consumer interface.
///
/// Cheap to clone; all state is behind `Arc<LdmService>`.
#[derive(Clone)]
pub struct IfLdm4 {
    service: Arc<LdmService>,
}

impl IfLdm4 {
    pub(crate) fn new(service: Arc<LdmService>) -> Self {
        IfLdm4 { service }
    }

    /// Register a data consumer by its ITS-AID.
    pub fn register_data_consumer(&self, req: RegisterDataConsumerReq) -> RegisterDataConsumerResp {
        self.service.register_data_consumer(req)
    }

    /// Deregister a data consumer.
    pub fn deregister_data_consumer(
        &self,
        req: DeregisterDataConsumerReq,
    ) -> DeregisterDataConsumerResp {
        self.service.deregister_data_consumer(req)
    }

    /// One-shot query: returns all current records matching `req`.
    ///
    /// This is the low-latency path; it takes a read-lock, filters, and
    /// returns immediately.
    pub fn request_data_objects(&self, req: RequestDataObjectsReq) -> RequestDataObjectsResp {
        self.service.request_data_objects(req)
    }

    /// Subscribe to periodic LDM notifications.
    ///
    /// Returns `(response, receiver)`.  The `receiver` will receive
    /// `RequestDataObjectsResp` messages at approximately the requested
    /// `notify_interval_ms` cadence, driven by the maintenance thread.
    ///
    /// The subscription is automatically cancelled when the `receiver` is
    /// dropped (the maintenance thread detects the broken channel).
    pub fn subscribe_data_consumer(
        &self,
        req: SubscribeDataObjectsReq,
    ) -> (SubscribeDataObjectsResp, Receiver<RequestDataObjectsResp>) {
        let (tx, rx) = mpsc::channel::<RequestDataObjectsResp>();
        let resp = self.service.subscribe_data_consumer(req, tx);
        (resp, rx)
    }

    /// Cancel an active subscription by ID.
    pub fn unsubscribe_data_consumer(
        &self,
        req: UnsubscribeDataConsumerReq,
    ) -> UnsubscribeDataConsumerResp {
        self.service.unsubscribe_data_consumer(req)
    }
}

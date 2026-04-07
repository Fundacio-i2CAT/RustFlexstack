// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! LDM service layer — business logic for insert, query, and subscriptions.
//!
//! `LdmService` is the central component shared by both `IfLdm3` and `IfLdm4`.
//! It holds:
//! * an `Arc<RwLock<LdmStore>>` for the actual record storage,
//! * registered provider and consumer ITS-AID sets,
//! * an ordered list of active subscriptions.
//!
//! The maintenance thread calls `fire_subscriptions` once per second; the
//! method walks all `SubscriptionEntry`s and, when their notify interval has
//! elapsed, sends the current matching records through the subscription
//! channel.

use std::collections::HashSet;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::facilities::local_dynamic_map::ldm_constants::now_its_ms;
use crate::facilities::local_dynamic_map::ldm_storage::{ItsDataObject, LdmStore, StoredRecord};
use crate::facilities::local_dynamic_map::ldm_types::{
    AddDataProviderReq, AddDataProviderResp, AddDataProviderResult, ComparisonOperator,
    DataObjectEntry, DeleteDataProviderReq, DeleteDataProviderResp, DeleteDataProviderResult,
    DeregisterDataConsumerAck, DeregisterDataConsumerReq, DeregisterDataConsumerResp,
    DeregisterDataProviderAck, DeregisterDataProviderReq, DeregisterDataProviderResp, Filter,
    FilterAttribute, LogicalOperator, RegisterDataConsumerReq, RegisterDataConsumerResp,
    RegisterDataConsumerResult, RegisterDataProviderReq, RegisterDataProviderResp,
    RegisterDataProviderResult, RequestDataObjectsReq, RequestDataObjectsResp,
    RequestedDataObjectsResult, SubscribeDataObjectsReq, SubscribeDataObjectsResp,
    SubscribeDataObjectsResult, UnsubscribeDataConsumerAck, UnsubscribeDataConsumerReq,
    UnsubscribeDataConsumerResp, UpdateDataProviderReq, UpdateDataProviderResp,
    UpdateDataProviderResult,
};

// ─── Subscription entry (Option B — Sender<>) ────────────────────────────────

/// Internal state for one active subscription.
struct SubscriptionEntry {
    id: u64,
    request: SubscribeDataObjectsReq,
    tx: Sender<RequestDataObjectsResp>,
    last_notified: Instant,
}

// ─── LdmService ──────────────────────────────────────────────────────────────

/// Core LDM service.  Shared (via `Arc`) between `IfLdm3` and `IfLdm4`.
pub struct LdmService {
    /// Underlying in-memory record store.
    pub store: Arc<RwLock<LdmStore>>,

    /// ITS-AIDs of registered data providers.
    providers: Mutex<HashSet<u32>>,

    /// ITS-AIDs of registered data consumers.
    consumers: Mutex<HashSet<u32>>,

    /// Active subscriptions.
    subscriptions: Mutex<Vec<SubscriptionEntry>>,

    /// Monotonic counter for subscription IDs.
    next_sub_id: Mutex<u64>,
}

impl LdmService {
    /// Create a new `LdmService` wrapping the given store.
    pub fn new(store: Arc<RwLock<LdmStore>>) -> Arc<Self> {
        Arc::new(LdmService {
            store,
            providers: Mutex::new(HashSet::new()),
            consumers: Mutex::new(HashSet::new()),
            subscriptions: Mutex::new(Vec::new()),
            next_sub_id: Mutex::new(1),
        })
    }

    // ── IF.LDM.3 — data-provider operations ──────────────────────────────

    pub fn register_data_provider(&self, req: RegisterDataProviderReq) -> RegisterDataProviderResp {
        self.providers.lock().unwrap().insert(req.application_id);
        RegisterDataProviderResp {
            result: RegisterDataProviderResult::Accepted,
        }
    }

    pub fn deregister_data_provider(
        &self,
        req: DeregisterDataProviderReq,
    ) -> DeregisterDataProviderResp {
        let removed = self.providers.lock().unwrap().remove(&req.application_id);
        DeregisterDataProviderResp {
            ack: if removed {
                DeregisterDataProviderAck::Accepted
            } else {
                DeregisterDataProviderAck::Rejected
            },
        }
    }

    pub fn add_provider_data(&self, req: AddDataProviderReq) -> AddDataProviderResp {
        let timestamp = if req.timestamp_its == 0 {
            now_its_ms()
        } else {
            req.timestamp_its
        };
        let id = self.store.write().unwrap().insert(
            req.application_id,
            timestamp,
            req.time_validity_s,
            req.lat_etsi,
            req.lon_etsi,
            req.altitude_cm,
            req.data_object,
        );
        AddDataProviderResp {
            result: AddDataProviderResult::Succeed,
            record_id: Some(id),
        }
    }

    pub fn update_provider_data(&self, req: UpdateDataProviderReq) -> UpdateDataProviderResp {
        let timestamp = if req.timestamp_its == 0 {
            now_its_ms()
        } else {
            req.timestamp_its
        };
        let ok = self.store.write().unwrap().update(
            req.record_id,
            timestamp,
            req.time_validity_s,
            req.lat_etsi,
            req.lon_etsi,
            req.altitude_cm,
            req.data_object,
        );
        UpdateDataProviderResp {
            result: if ok {
                UpdateDataProviderResult::Succeed
            } else {
                UpdateDataProviderResult::UnknownId
            },
        }
    }

    pub fn delete_provider_data(&self, req: DeleteDataProviderReq) -> DeleteDataProviderResp {
        let ok = self.store.write().unwrap().remove(req.record_id);
        DeleteDataProviderResp {
            result: if ok {
                DeleteDataProviderResult::Succeed
            } else {
                DeleteDataProviderResult::Failed
            },
        }
    }

    // ── IF.LDM.4 — data-consumer operations ──────────────────────────────

    pub fn register_data_consumer(&self, req: RegisterDataConsumerReq) -> RegisterDataConsumerResp {
        self.consumers.lock().unwrap().insert(req.application_id);
        RegisterDataConsumerResp {
            result: RegisterDataConsumerResult::Accepted,
        }
    }

    pub fn deregister_data_consumer(
        &self,
        req: DeregisterDataConsumerReq,
    ) -> DeregisterDataConsumerResp {
        let removed = self.consumers.lock().unwrap().remove(&req.application_id);
        DeregisterDataConsumerResp {
            ack: if removed {
                DeregisterDataConsumerAck::Succeed
            } else {
                DeregisterDataConsumerAck::Failed
            },
        }
    }

    /// Query the LDM for data objects matching the request.
    pub fn request_data_objects(&self, req: RequestDataObjectsReq) -> RequestDataObjectsResp {
        let store = self.store.read().unwrap();
        let mut entries: Vec<DataObjectEntry> = store
            .iter()
            .filter(|r| !r.is_expired())
            .filter(|r| type_matches(r, &req.data_object_types))
            .filter(|r| filter_matches(r, &req.filter))
            .map(record_to_entry)
            .collect();

        // Apply ordering.
        if let Some(ref order) = req.order {
            for o in order.iter().rev() {
                entries.sort_by(|a, b| {
                    let av = attribute_value_entry(a, &o.attribute);
                    let bv = attribute_value_entry(b, &o.attribute);
                    match o.direction {
                        crate::facilities::local_dynamic_map::ldm_types::OrderingDirection::Ascending  => av.cmp(&bv),
                        crate::facilities::local_dynamic_map::ldm_types::OrderingDirection::Descending => bv.cmp(&av),
                    }
                });
            }
        }

        // Limit results.
        if let Some(max) = req.max_results {
            entries.truncate(max);
        }

        RequestDataObjectsResp {
            result: RequestedDataObjectsResult::Succeed,
            data_objects: entries,
        }
    }

    /// Register a subscription and return the subscription ID plus a receiver
    /// on which periodic notifications will arrive.
    pub fn subscribe_data_consumer(
        &self,
        req: SubscribeDataObjectsReq,
        tx: Sender<RequestDataObjectsResp>,
    ) -> SubscribeDataObjectsResp {
        let id = {
            let mut counter = self.next_sub_id.lock().unwrap();
            let id = *counter;
            *counter += 1;
            id
        };
        self.subscriptions.lock().unwrap().push(SubscriptionEntry {
            id,
            request: req,
            tx,
            last_notified: Instant::now(),
        });
        SubscribeDataObjectsResp {
            result: SubscribeDataObjectsResult::Successful,
            subscription_id: Some(id),
        }
    }

    /// Cancel a subscription.
    pub fn unsubscribe_data_consumer(
        &self,
        req: UnsubscribeDataConsumerReq,
    ) -> UnsubscribeDataConsumerResp {
        let mut subs = self.subscriptions.lock().unwrap();
        let before = subs.len();
        subs.retain(|s| s.id != req.subscription_id);
        UnsubscribeDataConsumerResp {
            ack: if subs.len() < before {
                UnsubscribeDataConsumerAck::Succeed
            } else {
                UnsubscribeDataConsumerAck::Failed
            },
        }
    }

    /// Called by the maintenance thread (typically 1 Hz).
    ///
    /// For each subscription whose `notify_interval_ms` has elapsed since it
    /// was last fired, build the current matching result set and send it
    /// through the subscription channel.  Subscriptions whose receiver has
    /// been dropped are pruned automatically.
    pub fn fire_subscriptions(&self) {
        let store = self.store.read().unwrap();
        let mut subs = self.subscriptions.lock().unwrap();
        let now = Instant::now();

        subs.retain_mut(|s| {
            let elapsed_ms = now.duration_since(s.last_notified).as_millis() as u64;
            if elapsed_ms < s.request.notify_interval_ms {
                return true; // not yet time to notify — keep alive
            }

            // Build response.
            let mut entries: Vec<DataObjectEntry> = store
                .iter()
                .filter(|r| !r.is_expired())
                .filter(|r| type_matches(r, &s.request.data_object_types))
                .filter(|r| filter_matches(r, &s.request.filter))
                .map(record_to_entry)
                .collect();

            if let Some(max) = s.request.max_results {
                entries.truncate(max);
            }

            let resp = RequestDataObjectsResp {
                result: RequestedDataObjectsResult::Succeed,
                data_objects: entries,
            };

            // Update timestamp before sending.
            s.last_notified = now;

            // If the receiver has been dropped, prune this subscription.
            s.tx.send(resp).is_ok()
        });
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

fn type_matches(record: &StoredRecord, types: &[u32]) -> bool {
    types.is_empty() || types.contains(&record.application_id)
}

fn filter_matches(record: &StoredRecord, filter: &Option<Filter>) -> bool {
    let Some(f) = filter else { return true };

    let r1 = eval_statement(record, &f.stmt1);
    match (&f.logical, &f.stmt2) {
        (Some(LogicalOperator::And), Some(s2)) => r1 && eval_statement(record, s2),
        (Some(LogicalOperator::Or), Some(s2)) => r1 || eval_statement(record, s2),
        _ => r1,
    }
}

fn eval_statement(
    record: &StoredRecord,
    stmt: &crate::facilities::local_dynamic_map::ldm_types::FilterStatement,
) -> bool {
    let val = attribute_value_record(record, &stmt.attribute);
    let ref_v = stmt.ref_value;
    match stmt.operator {
        ComparisonOperator::Equal => val == ref_v,
        ComparisonOperator::NotEqual => val != ref_v,
        ComparisonOperator::GreaterThan => val > ref_v,
        ComparisonOperator::LessThan => val < ref_v,
        ComparisonOperator::GreaterThanOrEqual => val >= ref_v,
        ComparisonOperator::LessThanOrEqual => val <= ref_v,
    }
}

/// Extract a filterable integer value from a `StoredRecord`.
fn attribute_value_record(record: &StoredRecord, attr: &FilterAttribute) -> i64 {
    match attr {
        FilterAttribute::ApplicationId => record.application_id as i64,
        FilterAttribute::Latitude => record.lat_etsi as i64,
        FilterAttribute::Longitude => record.lon_etsi as i64,
        FilterAttribute::Altitude => record.altitude_cm as i64,
        // Fields that require PDU inspection — extract best-effort.
        FilterAttribute::StationType => extract_station_type(record),
        FilterAttribute::StationId => extract_station_id(record),
        FilterAttribute::Speed => 0, // not available at StoredRecord level
        FilterAttribute::Heading => 0,
    }
}

/// Extract a filterable integer value from a `DataObjectEntry` (for ordering).
fn attribute_value_entry(entry: &DataObjectEntry, attr: &FilterAttribute) -> i64 {
    match attr {
        FilterAttribute::ApplicationId => entry.application_id as i64,
        FilterAttribute::Latitude => entry.lat_etsi as i64,
        FilterAttribute::Longitude => entry.lon_etsi as i64,
        FilterAttribute::Altitude => entry.altitude_cm as i64,
        _ => 0,
    }
}

fn extract_station_id(record: &StoredRecord) -> i64 {
    match &record.data_object {
        ItsDataObject::Cam(cam) => cam.header.station_id.0 as i64,
        ItsDataObject::Denm(denm) => denm.header.station_id.0 as i64,
        ItsDataObject::Vam(vam) => vam.header.0.station_id.0 as i64,
        ItsDataObject::Unknown { .. } => 0,
    }
}

fn extract_station_type(record: &StoredRecord) -> i64 {
    match &record.data_object {
        ItsDataObject::Cam(cam) => cam.cam.cam_parameters.basic_container.station_type.0 as i64,
        ItsDataObject::Vam(vam) => vam.vam.vam_parameters.basic_container.station_type.0 as i64,
        _ => 0,
    }
}

/// Convert a `StoredRecord` reference to a `DataObjectEntry`.
///
/// `data_object` cannot be cloned cheaply (PDUs can be large), so we build
/// a *shallow copy* of the metadata fields and reconstruct the entry.
/// Since `DataObjectEntry` owns its `ItsDataObject`, and we only have a
/// shared borrow of `StoredRecord`, we serialise/deserialise via UPER for
/// full fidelity … but that is expensive.
///
/// **Trade-off chosen here**: build a minimal `ItsDataObject` placeholder
/// (preserving the original) is not possible without a `Clone` impl on the
/// generated rasn types.  Instead, we provide a `Clone`-free approach by
/// converting entries lazily in the query path and allowing `DataObjectEntry`
/// to hold an `Arc<ItsDataObject>` if needed in future.
///
/// For now the simplest correct approach is to derive `Clone` for the whole
/// PDU tree — but we cannot do that here.  Instead we reconstruct the entry
/// using raw pointer tricks — which is unsound.
///
/// **Chosen resolution**: add `#[derive(Clone)]` support is not available for
/// rasn types.  We therefore re-encode via UPER and decode afresh so that
/// each `DataObjectEntry` owns an independent copy.  This is done lazily
/// only when a consumer issues a query.
fn record_to_entry(record: &StoredRecord) -> DataObjectEntry {
    use crate::facilities::ca_basic_service::cam_coder::CamCoder;
    use crate::facilities::decentralized_environmental_notification_service::denm_coder::DenmCoder;
    use crate::facilities::local_dynamic_map::ldm_constants::{
        ITS_AID_CAM, ITS_AID_DENM, ITS_AID_VAM,
    };
    use crate::facilities::vru_awareness_service::vam_coder::VamCoder;

    let data_object = match &record.data_object {
        ItsDataObject::Cam(cam) => match CamCoder.encode(cam) {
            Ok(bytes) => match CamCoder.decode(&bytes) {
                Ok(c) => ItsDataObject::Cam(Box::new(c)),
                Err(_) => ItsDataObject::Unknown {
                    its_aid: ITS_AID_CAM,
                    raw: bytes,
                },
            },
            Err(_) => ItsDataObject::Unknown {
                its_aid: ITS_AID_CAM,
                raw: vec![],
            },
        },
        ItsDataObject::Denm(denm) => match DenmCoder.encode(denm) {
            Ok(bytes) => match DenmCoder.decode(&bytes) {
                Ok(d) => ItsDataObject::Denm(Box::new(d)),
                Err(_) => ItsDataObject::Unknown {
                    its_aid: ITS_AID_DENM,
                    raw: bytes,
                },
            },
            Err(_) => ItsDataObject::Unknown {
                its_aid: ITS_AID_DENM,
                raw: vec![],
            },
        },
        ItsDataObject::Vam(vam) => match VamCoder.encode(vam) {
            Ok(bytes) => match VamCoder.decode(&bytes) {
                Ok(v) => ItsDataObject::Vam(Box::new(v)),
                Err(_) => ItsDataObject::Unknown {
                    its_aid: ITS_AID_VAM,
                    raw: bytes,
                },
            },
            Err(_) => ItsDataObject::Unknown {
                its_aid: ITS_AID_VAM,
                raw: vec![],
            },
        },
        ItsDataObject::Unknown { its_aid, raw } => ItsDataObject::Unknown {
            its_aid: *its_aid,
            raw: raw.clone(),
        },
    };

    DataObjectEntry {
        record_id: record.id,
        application_id: record.application_id,
        timestamp_its: record.timestamp_its_ms,
        lat_etsi: record.lat_etsi,
        lon_etsi: record.lon_etsi,
        altitude_cm: record.altitude_cm,
        data_object,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facilities::local_dynamic_map::ldm_storage::ItsDataObject;
    use crate::facilities::local_dynamic_map::ldm_types::*;
    use std::sync::mpsc;

    fn make_service() -> Arc<LdmService> {
        let store = Arc::new(RwLock::new(LdmStore::new()));
        LdmService::new(store)
    }

    fn unknown_data(aid: u32) -> ItsDataObject {
        ItsDataObject::Unknown {
            its_aid: aid,
            raw: vec![0xAA],
        }
    }

    #[test]
    fn register_and_deregister_provider() {
        let svc = make_service();
        let resp = svc.register_data_provider(RegisterDataProviderReq { application_id: 36 });
        assert_eq!(resp.result, RegisterDataProviderResult::Accepted);

        let resp = svc.deregister_data_provider(DeregisterDataProviderReq { application_id: 36 });
        assert_eq!(resp.ack, DeregisterDataProviderAck::Accepted);

        // Deregister again should be rejected
        let resp = svc.deregister_data_provider(DeregisterDataProviderReq { application_id: 36 });
        assert_eq!(resp.ack, DeregisterDataProviderAck::Rejected);
    }

    #[test]
    fn register_and_deregister_consumer() {
        let svc = make_service();
        let resp = svc.register_data_consumer(RegisterDataConsumerReq { application_id: 36 });
        assert_eq!(resp.result, RegisterDataConsumerResult::Accepted);

        let resp = svc.deregister_data_consumer(DeregisterDataConsumerReq { application_id: 36 });
        assert_eq!(resp.ack, DeregisterDataConsumerAck::Succeed);

        let resp = svc.deregister_data_consumer(DeregisterDataConsumerReq { application_id: 36 });
        assert_eq!(resp.ack, DeregisterDataConsumerAck::Failed);
    }

    #[test]
    fn add_provider_data() {
        let svc = make_service();
        let resp = svc.add_provider_data(AddDataProviderReq {
            application_id: 36,
            timestamp_its: 1_000_000,
            time_validity_s: 3600,
            lat_etsi: 415520000,
            lon_etsi: 21340000,
            altitude_cm: 12000,
            data_object: unknown_data(36),
        });
        assert_eq!(resp.result, AddDataProviderResult::Succeed);
        assert!(resp.record_id.is_some());
    }

    #[test]
    fn update_provider_data_existing() {
        let svc = make_service();
        let add_resp = svc.add_provider_data(AddDataProviderReq {
            application_id: 36,
            timestamp_its: 1_000_000,
            time_validity_s: 3600,
            lat_etsi: 0,
            lon_etsi: 0,
            altitude_cm: 0,
            data_object: unknown_data(36),
        });
        let id = add_resp.record_id.unwrap();

        let upd_resp = svc.update_provider_data(UpdateDataProviderReq {
            record_id: id,
            timestamp_its: 2_000_000,
            time_validity_s: 7200,
            lat_etsi: 100,
            lon_etsi: 200,
            altitude_cm: 300,
            data_object: unknown_data(36),
        });
        assert_eq!(upd_resp.result, UpdateDataProviderResult::Succeed);
    }

    #[test]
    fn update_provider_data_nonexistent() {
        let svc = make_service();
        let resp = svc.update_provider_data(UpdateDataProviderReq {
            record_id: 999,
            timestamp_its: 0,
            time_validity_s: 0,
            lat_etsi: 0,
            lon_etsi: 0,
            altitude_cm: 0,
            data_object: unknown_data(0),
        });
        assert_eq!(resp.result, UpdateDataProviderResult::UnknownId);
    }

    #[test]
    fn delete_provider_data() {
        let svc = make_service();
        let add_resp = svc.add_provider_data(AddDataProviderReq {
            application_id: 36,
            timestamp_its: now_its_ms(),
            time_validity_s: 3600,
            lat_etsi: 0,
            lon_etsi: 0,
            altitude_cm: 0,
            data_object: unknown_data(36),
        });
        let id = add_resp.record_id.unwrap();

        let del_resp = svc.delete_provider_data(DeleteDataProviderReq { record_id: id });
        assert_eq!(del_resp.result, DeleteDataProviderResult::Succeed);

        let del_resp = svc.delete_provider_data(DeleteDataProviderReq { record_id: id });
        assert_eq!(del_resp.result, DeleteDataProviderResult::Failed);
    }

    #[test]
    fn request_data_objects_no_filter() {
        let svc = make_service();
        svc.add_provider_data(AddDataProviderReq {
            application_id: 36,
            timestamp_its: now_its_ms(),
            time_validity_s: 3600,
            lat_etsi: 415520000,
            lon_etsi: 21340000,
            altitude_cm: 12000,
            data_object: unknown_data(36),
        });
        svc.add_provider_data(AddDataProviderReq {
            application_id: 37,
            timestamp_its: now_its_ms(),
            time_validity_s: 3600,
            lat_etsi: 0,
            lon_etsi: 0,
            altitude_cm: 0,
            data_object: unknown_data(37),
        });

        let resp = svc.request_data_objects(RequestDataObjectsReq {
            application_id: 36,
            data_object_types: vec![],
            filter: None,
            order: None,
            max_results: None,
        });
        assert_eq!(resp.result, RequestedDataObjectsResult::Succeed);
        assert_eq!(resp.data_objects.len(), 2);
    }

    #[test]
    fn request_data_objects_with_type_filter() {
        let svc = make_service();
        svc.add_provider_data(AddDataProviderReq {
            application_id: 36,
            timestamp_its: now_its_ms(),
            time_validity_s: 3600,
            lat_etsi: 0,
            lon_etsi: 0,
            altitude_cm: 0,
            data_object: unknown_data(36),
        });
        svc.add_provider_data(AddDataProviderReq {
            application_id: 37,
            timestamp_its: now_its_ms(),
            time_validity_s: 3600,
            lat_etsi: 0,
            lon_etsi: 0,
            altitude_cm: 0,
            data_object: unknown_data(37),
        });

        let resp = svc.request_data_objects(RequestDataObjectsReq {
            application_id: 36,
            data_object_types: vec![36],
            filter: None,
            order: None,
            max_results: None,
        });
        assert_eq!(resp.data_objects.len(), 1);
    }

    #[test]
    fn request_data_objects_with_filter() {
        let svc = make_service();
        svc.add_provider_data(AddDataProviderReq {
            application_id: 36,
            timestamp_its: now_its_ms(),
            time_validity_s: 3600,
            lat_etsi: 415520000,
            lon_etsi: 21340000,
            altitude_cm: 0,
            data_object: unknown_data(36),
        });
        svc.add_provider_data(AddDataProviderReq {
            application_id: 36,
            timestamp_its: now_its_ms(),
            time_validity_s: 3600,
            lat_etsi: 400000000,
            lon_etsi: 21340000,
            altitude_cm: 0,
            data_object: unknown_data(36),
        });

        let resp = svc.request_data_objects(RequestDataObjectsReq {
            application_id: 36,
            data_object_types: vec![],
            filter: Some(Filter {
                stmt1: FilterStatement {
                    attribute: FilterAttribute::Latitude,
                    operator: ComparisonOperator::GreaterThan,
                    ref_value: 410000000,
                },
                logical: None,
                stmt2: None,
            }),
            order: None,
            max_results: None,
        });
        assert_eq!(resp.data_objects.len(), 1);
    }

    #[test]
    fn request_data_objects_max_results() {
        let svc = make_service();
        for _ in 0..5 {
            svc.add_provider_data(AddDataProviderReq {
                application_id: 36,
                timestamp_its: now_its_ms(),
                time_validity_s: 3600,
                lat_etsi: 0,
                lon_etsi: 0,
                altitude_cm: 0,
                data_object: unknown_data(36),
            });
        }

        let resp = svc.request_data_objects(RequestDataObjectsReq {
            application_id: 36,
            data_object_types: vec![],
            filter: None,
            order: None,
            max_results: Some(3),
        });
        assert_eq!(resp.data_objects.len(), 3);
    }

    #[test]
    fn subscribe_and_unsubscribe() {
        let svc = make_service();
        let (tx, _rx) = mpsc::channel();
        let resp = svc.subscribe_data_consumer(
            SubscribeDataObjectsReq {
                application_id: 36,
                data_object_types: vec![],
                filter: None,
                notify_interval_ms: 1000,
                max_results: None,
            },
            tx,
        );
        assert_eq!(resp.result, SubscribeDataObjectsResult::Successful);
        let sub_id = resp.subscription_id.unwrap();

        let unsub_resp =
            svc.unsubscribe_data_consumer(UnsubscribeDataConsumerReq { subscription_id: sub_id });
        assert_eq!(unsub_resp.ack, UnsubscribeDataConsumerAck::Succeed);

        // Unsubscribe again should fail
        let unsub_resp =
            svc.unsubscribe_data_consumer(UnsubscribeDataConsumerReq { subscription_id: sub_id });
        assert_eq!(unsub_resp.ack, UnsubscribeDataConsumerAck::Failed);
    }

    #[test]
    fn fire_subscriptions_prunes_dead() {
        let svc = make_service();
        let (tx, rx) = mpsc::channel();
        svc.subscribe_data_consumer(
            SubscribeDataObjectsReq {
                application_id: 36,
                data_object_types: vec![],
                filter: None,
                notify_interval_ms: 0, // fire immediately
                max_results: None,
            },
            tx,
        );
        drop(rx); // drop receiver
        svc.fire_subscriptions(); // should prune
        assert_eq!(svc.subscriptions.lock().unwrap().len(), 0);
    }
}

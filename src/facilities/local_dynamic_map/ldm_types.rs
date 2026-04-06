// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ETSI IF.LDM.3 / IF.LDM.4 request and response types.
//!
//! Mirrors the Python dataclasses defined in
//! `flexstack/facilities/local_dynamic_map/ldm_classes.py`.
//!
//! Naming follows ETSI TS 103 301 Table 7 (IF.LDM.3) and Table 8 (IF.LDM.4).

use crate::facilities::local_dynamic_map::ldm_storage::ItsDataObject;

// ─── Result / acknowledgement enums ─────────────────────────────────────────

/// Result returned by `register_data_provider`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterDataProviderResult {
    Accepted,
    Rejected,
}

/// Acknowledgement returned by `deregister_data_provider`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeregisterDataProviderAck {
    Accepted,
    Rejected,
}

/// Result returned by `add_provider_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddDataProviderResult {
    Succeed,
    Failed,
}

/// Result returned by `update_provider_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDataProviderResult {
    Succeed,
    UnknownId,
    InconsistentType,
}

/// Result returned by `delete_provider_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteDataProviderResult {
    Succeed,
    Failed,
}

/// Result returned by `register_data_consumer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterDataConsumerResult {
    Accepted,
    Warning,
    Rejected,
}

/// Acknowledgement returned by `deregister_data_consumer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeregisterDataConsumerAck {
    Succeed,
    Failed,
}

/// Result code returned alongside a `RequestDataObjectsResp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedDataObjectsResult {
    Succeed,
    InvalidItsAid,
    InvalidDataObjectType,
    InvalidPriority,
    InvalidFilter,
    InvalidOrder,
}

/// Result code returned alongside a `SubscribeDataObjectsResp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscribeDataObjectsResult {
    Successful,
    InvalidItsAid,
    InvalidDataObjectType,
    InvalidPriority,
    InvalidFilter,
    InvalidOrder,
    InvalidNotifyTime,
    InvalidMultiplicity,
}

/// Acknowledgement returned by `unsubscribe_data_consumer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsubscribeDataConsumerAck {
    Succeed,
    Failed,
}

// ─── Filtering ───────────────────────────────────────────────────────────────

/// Typed attribute selector for LDM filter expressions.
///
/// Using an enum rather than `String` avoids runtime string parsing and makes
/// filter construction exhaustive / type-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAttribute {
    /// Station type (0 = unknown, 5 = passenger car, …).
    StationType,
    /// Numeric station identifier.
    StationId,
    /// Latitude in ETSI × 1e7 integer units.
    Latitude,
    /// Longitude in ETSI × 1e7 integer units.
    Longitude,
    /// Speed in cm/s (CAM / VAM high-frequency container).
    Speed,
    /// Heading in 0.1° units (CAM / VAM high-frequency container).
    Heading,
    /// ITS-AID of the record's data provider.
    ApplicationId,
    /// Altitude in cm above WGS-84 ellipsoid.
    Altitude,
}

/// Comparison operator for a `FilterStatement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonOperator {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

/// Logical operator combining two `FilterStatement`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalOperator {
    And,
    Or,
}

/// A single attribute comparison: `attribute OP ref_value`.
#[derive(Debug, Clone)]
pub struct FilterStatement {
    pub attribute: FilterAttribute,
    pub operator: ComparisonOperator,
    /// Reference value; ETSI coordinates, speeds, etc. are all expressible as
    /// `i64` without loss.
    pub ref_value: i64,
}

/// A filter expression composed of one or two `FilterStatement`s.
///
/// If `logical` and `stmt2` are `None` only `stmt1` is evaluated.
#[derive(Debug, Clone)]
pub struct Filter {
    pub stmt1: FilterStatement,
    pub logical: Option<LogicalOperator>,
    pub stmt2: Option<FilterStatement>,
}

// ─── Ordering ────────────────────────────────────────────────────────────────

/// Sort direction for an ordering tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderingDirection {
    Ascending,
    Descending,
}

/// A single sort key used in `RequestDataObjectsReq::order`.
#[derive(Debug, Clone)]
pub struct OrderTupleValue {
    pub attribute: FilterAttribute,
    pub direction: OrderingDirection,
}

// ─── IF.LDM.3 — Data Provider interface ──────────────────────────────────────

/// Request to register a new data provider.
#[derive(Debug, Clone)]
pub struct RegisterDataProviderReq {
    /// ITS-AID identifying the application (e.g. `ITS_AID_CAM = 2`).
    pub application_id: u32,
}

/// Response to `register_data_provider`.
#[derive(Debug)]
pub struct RegisterDataProviderResp {
    pub result: RegisterDataProviderResult,
}

/// Request to deregister a data provider.
#[derive(Debug, Clone)]
pub struct DeregisterDataProviderReq {
    pub application_id: u32,
}

/// Response to `deregister_data_provider`.
#[derive(Debug)]
pub struct DeregisterDataProviderResp {
    pub ack: DeregisterDataProviderAck,
}

/// Request to add a new data object to the LDM.
#[derive(Debug)]
pub struct AddDataProviderReq {
    /// ITS-AID of the providing application.
    pub application_id: u32,
    /// Timestamp in milliseconds since ITS epoch (2004-01-01).
    pub timestamp_its: u64,
    /// Latitude in ETSI × 1e7 integer units.
    pub lat_etsi: i32,
    /// Longitude in ETSI × 1e7 integer units.
    pub lon_etsi: i32,
    /// Altitude in centimetres above WGS-84 ellipsoid.
    pub altitude_cm: i32,
    /// How long (in whole seconds) this record is considered valid.
    pub time_validity_s: u32,
    /// The ITS data object to store.
    pub data_object: ItsDataObject,
}

/// Response to `add_provider_data`.
#[derive(Debug)]
pub struct AddDataProviderResp {
    pub result: AddDataProviderResult,
    /// Unique LDM record identifier assigned on `Succeed`.
    pub record_id: Option<u64>,
}

/// Request to update an existing data object in the LDM.
#[derive(Debug)]
pub struct UpdateDataProviderReq {
    /// LDM record identifier returned by a prior `add_provider_data` call.
    pub record_id: u64,
    /// New timestamp in milliseconds since ITS epoch.
    pub timestamp_its: u64,
    /// Updated latitude (ETSI × 1e7).
    pub lat_etsi: i32,
    /// Updated longitude (ETSI × 1e7).
    pub lon_etsi: i32,
    /// Updated altitude in cm.
    pub altitude_cm: i32,
    /// Updated validity window in seconds.
    pub time_validity_s: u32,
    /// Replacement data object; must have the same `ItsDataObject` variant as
    /// the record being updated.
    pub data_object: ItsDataObject,
}

/// Response to `update_provider_data`.
#[derive(Debug)]
pub struct UpdateDataProviderResp {
    pub result: UpdateDataProviderResult,
}

/// Request to delete a data object from the LDM.
#[derive(Debug, Clone)]
pub struct DeleteDataProviderReq {
    pub record_id: u64,
}

/// Response to `delete_provider_data`.
#[derive(Debug)]
pub struct DeleteDataProviderResp {
    pub result: DeleteDataProviderResult,
}

// ─── IF.LDM.4 — Data Consumer interface ──────────────────────────────────────

/// Request to register a new data consumer.
#[derive(Debug, Clone)]
pub struct RegisterDataConsumerReq {
    /// ITS-AID of the consuming application.
    pub application_id: u32,
}

/// Response to `register_data_consumer`.
#[derive(Debug)]
pub struct RegisterDataConsumerResp {
    pub result: RegisterDataConsumerResult,
}

/// Request to deregister a data consumer.
#[derive(Debug, Clone)]
pub struct DeregisterDataConsumerReq {
    pub application_id: u32,
}

/// Response to `deregister_data_consumer`.
#[derive(Debug)]
pub struct DeregisterDataConsumerResp {
    pub ack: DeregisterDataConsumerAck,
}

/// Request to query the LDM for matching data objects.
#[derive(Debug, Clone)]
pub struct RequestDataObjectsReq {
    /// ITS-AID of the requesting application.
    pub application_id: u32,
    /// ITS-AID values of the data types to retrieve (e.g. `[ITS_AID_CAM]`).
    /// An empty vector means "all types".
    pub data_object_types: Vec<u32>,
    /// Optional filter expression.
    pub filter: Option<Filter>,
    /// Optional sort order; applied after filtering.
    pub order: Option<Vec<OrderTupleValue>>,
    /// Maximum number of records to return (`None` = unlimited).
    pub max_results: Option<usize>,
}

/// A single result record returned inside `RequestDataObjectsResp`.
#[derive(Debug)]
pub struct DataObjectEntry {
    /// LDM-assigned record identifier.
    pub record_id: u64,
    /// ITS-AID of the data provider.
    pub application_id: u32,
    /// Timestamp of the record (ms since ITS epoch).
    pub timestamp_its: u64,
    /// Latitude of the record (ETSI × 1e7).
    pub lat_etsi: i32,
    /// Longitude of the record (ETSI × 1e7).
    pub lon_etsi: i32,
    /// Altitude of the record in cm.
    pub altitude_cm: i32,
    /// The stored data object.
    pub data_object: ItsDataObject,
}

/// Response to `request_data_objects`.
#[derive(Debug)]
pub struct RequestDataObjectsResp {
    pub result: RequestedDataObjectsResult,
    pub data_objects: Vec<DataObjectEntry>,
}

/// Request to subscribe to periodic LDM notifications.
#[derive(Debug, Clone)]
pub struct SubscribeDataObjectsReq {
    /// ITS-AID of the subscribing application.
    pub application_id: u32,
    /// ITS-AID values to subscribe to; empty = all types.
    pub data_object_types: Vec<u32>,
    /// Optional filter applied before delivering notifications.
    pub filter: Option<Filter>,
    /// Minimum interval between notifications in milliseconds.
    pub notify_interval_ms: u64,
    /// Maximum number of records per notification.
    pub max_results: Option<usize>,
}

/// Response to `subscribe_data_consumer`.
#[derive(Debug)]
pub struct SubscribeDataObjectsResp {
    pub result: SubscribeDataObjectsResult,
    /// Opaque subscription identifier; pass to `unsubscribe_data_consumer`.
    pub subscription_id: Option<u64>,
}

/// Request to cancel an active subscription.
#[derive(Debug, Clone)]
pub struct UnsubscribeDataConsumerReq {
    pub subscription_id: u64,
}

/// Response to `unsubscribe_data_consumer`.
#[derive(Debug)]
pub struct UnsubscribeDataConsumerResp {
    pub ack: UnsubscribeDataConsumerAck,
}

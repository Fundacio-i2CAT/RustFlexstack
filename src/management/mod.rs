// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! # Management Layer
//!
//! Decentralized Congestion Control (DCC) algorithms and transmission management
//! as specified in ETSI TS 102 687 V1.2.1 (2018-04).
//!
//! This module provides:
//! - Reactive DCC algorithm ([`dcc_reactive`]) per clause 5.3 and Annex A.
//! - Adaptive DCC algorithm (LIMERIC) and Gate Keeper admission control ([`dcc_adaptive`])
//!   per clause 5.4 and Annex B.
//! - Channel Busy Ratio sources from the access layer ([`cbr`]).
//! - The DCC entity ([`dcc_entity`]) that evaluates the selected algorithm every
//!   200 ms and provides `T_GenCam_DCC` to the CA basic service.

pub mod cbr;
pub mod dcc_adaptive;
pub mod dcc_entity;
pub mod dcc_reactive;

pub use cbr::{
    cbr_from_samples, parse_survey_dump, CbrProvider, Nl80211SurveyCbr, SharedCbr, SurveySample,
};
pub use dcc_adaptive::{DccAdaptive, DccAdaptiveParameters, GateKeeper};
pub use dcc_entity::{
    clamp_t_gen_cam_dcc, DccEntity, DccEntityHandle, DccEntityOutput, DccMode,
    DCC_EVALUATION_PERIOD_MS, T_GEN_CAM_DCC_MAX_MS, T_GEN_CAM_DCC_MIN_MS,
};
pub use dcc_reactive::{DccReactive, DccReactiveOutput, DccState, DccStateConfig};

/// Errors encountered during DCC calculations and validation.
#[derive(Debug, Clone, PartialEq)]
pub enum DccError {
    /// Channel Busy Ratio (CBR) measurement was outside the permitted `[0.0, 1.0]` range.
    InvalidCbr { name: &'static str, value: f64 },
    /// Packet transmission duration `t_on` was not positive.
    InvalidTon(f64),
    /// Duty-cycle fraction `delta` was not positive.
    InvalidDelta(f64),
}

impl std::fmt::Display for DccError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DccError::InvalidCbr { name, value } => {
                write!(f, "{name} must be in [0.0, 1.0], got {value}")
            }
            DccError::InvalidTon(val) => {
                write!(f, "t_on must be positive, got {val}")
            }
            DccError::InvalidDelta(val) => {
                write!(f, "delta must be positive, got {val}")
            }
        }
    }
}

impl std::error::Error for DccError {}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Decentralized Environmental Notification (DEN) Service (ETSI EN 302 637-3 /
//! ETSI TS 103 831).
//!
//! Implements DENM generation and reception on top of the BTP and
//! GeoNetworking layers already present in this crate.
//!
//! # Architecture
//! ```text
//! Application ──DENRequest──► DENMTransmissionManagement ──BTPDataRequest──► BTP
//!                                                                              │
//!                              DENMReceptionManagement  ◄──BTPDataIndication──┘
//!                                      │
//!                               Sender<Denm>  ──►  application (Receiver<Denm>)
//! ```
//!
//! # Quick start
//! ```no_run
//! use rustflexstack::btp::router::Router as BTPRouter;
//! use rustflexstack::geonet::mib::Mib;
//! use rustflexstack::facilities::decentralized_environmental_notification_service::{
//!     DecentralizedEnvironmentalNotificationService, VehicleData, DENRequest,
//! };
//! use rustflexstack::facilities::decentralized_environmental_notification_service::denm_coder::CauseCodeChoice;
//!
//! let mib = Mib::new();
//! let (btp_handle, _) = BTPRouter::spawn(mib);
//!
//! let (den_svc, denm_rx) = DecentralizedEnvironmentalNotificationService::new(
//!     btp_handle,
//!     VehicleData::default(),
//! );
//!
//! // Trigger a road-hazard DENM (accident, sub-cause 0).
//! den_svc.trigger_denm(DENRequest::default());
//!
//! while let Ok(denm) = denm_rx.recv() {
//!     println!("DENM from station {}", denm.header.station_id.0);
//! }
//! ```

pub mod denm_bindings;
pub mod denm_coder;
pub mod denm_reception;
pub mod denm_transmission;

pub use denm_coder::{Denm, DenmCoder};
pub use denm_reception::DENMReceptionManagement;
pub use denm_transmission::{DENRequest, DENMTransmissionManagement, VehicleData};

use crate::btp::router::BTPRouterHandle;
use std::sync::mpsc::{self, Receiver, Sender};

/// Top-level Decentralized Environmental Notification Service.
///
/// Mirrors `DecentralizedEnvironmentalNotificationService` in
/// `flexstack/facilities/decentralized_environmental_notification_service/den_service.py`.
///
/// Create with [`new`](Self::new), then call
/// [`trigger_denm`](Self::trigger_denm) whenever the application layer needs
/// to generate and broadcast a DENM.
pub struct DecentralizedEnvironmentalNotificationService {
    tx_management: DENMTransmissionManagement,
    /// Reception management writes decoded DENMs into this sender.
    denm_tx:       Sender<Denm>,
}

impl DecentralizedEnvironmentalNotificationService {
    /// Create a new DEN Service.
    ///
    /// Returns `(service, denm_receiver)`.  Hold `denm_receiver` to consume
    /// decoded incoming DENMs.  The reception thread is started immediately
    /// (it registers BTP port 2002 right away).
    pub fn new(
        btp_handle:   BTPRouterHandle,
        vehicle_data: VehicleData,
    ) -> (Self, Receiver<Denm>) {
        let coder = DenmCoder::new();
        let (denm_tx, denm_rx) = mpsc::channel::<Denm>();

        // Start reception immediately.
        DENMReceptionManagement::spawn(btp_handle.clone(), coder.clone(), denm_tx.clone());

        let tx_management = DENMTransmissionManagement::new(
            btp_handle,
            coder,
            vehicle_data,
        );

        let svc = DecentralizedEnvironmentalNotificationService { tx_management, denm_tx };
        (svc, denm_rx)
    }

    /// Trigger periodic DENM transmissions in a background thread.
    ///
    /// DENMs are sent every `request.denm_interval_ms` milliseconds for
    /// `request.time_period_ms` total milliseconds, then the thread exits.
    pub fn trigger_denm(&self, request: DENRequest) {
        self.tx_management.trigger_denm_sending(request);
    }

    /// Send a single DENM immediately (fire-and-forget, blocks briefly for encode).
    pub fn send_single_denm(&self, request: &DENRequest) {
        self.tx_management.send_single_denm(request);
    }
}

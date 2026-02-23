// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! VRU Awareness Service — VRU Awareness Basic Service (ETSI TS 103 300-3).
//!
//! Implements VAM generation and reception on top of the BTP and
//! GeoNetworking layers already present in this crate.
//!
//! # Architecture
//! ```text
//! LocationService ──GpsFix──► VAMTransmissionManagement ──BTPDataRequest──► BTP
//!                                                                            │
//!                              VAMReceptionManagement  ◄──BTPDataIndication──┘
//!                                      │
//!                               Sender<Vam>  ──►  application (Receiver<Vam>)
//! ```
//!
//! # Quick start
//! ```no_run
//! use rustflexstack::btp::router::Router as BTPRouter;
//! use rustflexstack::geonet::mib::Mib;
//! use rustflexstack::facilities::vru_awareness_service::{
//!     VruAwarenessService, DeviceData,
//! };
//! use rustflexstack::facilities::location_service::LocationService;
//!
//! let mib = Mib::new();
//! let (btp_handle, _) = BTPRouter::spawn(mib);
//! let mut loc_svc = LocationService::new();
//!
//! let (vru_svc, vam_rx) =
//!     VruAwarenessService::new(btp_handle, DeviceData::default());
//! vru_svc.start(loc_svc.subscribe());
//!
//! while let Ok(vam) = vam_rx.recv() {
//!     println!("VAM from station {}", vam.header.0.station_id.0);
//! }
//! ```

pub mod vam_bindings;
pub mod vam_coder;
pub mod vam_reception;
pub mod vam_transmission;

pub use vam_coder::{Vam, VamCoder};
pub use vam_reception::VAMReceptionManagement;
pub use vam_transmission::{DeviceData, VAMTransmissionManagement};

use crate::btp::router::BTPRouterHandle;
use crate::facilities::location_service::GpsFix;
use std::sync::mpsc::{self, Receiver, Sender};

/// Top-level VRU Awareness Service.
///
/// Mirrors `VRUAwarenessService` in
/// `flexstack/facilities/vru_awareness_service/vru_awareness_service.py`.
///
/// Create with [`new`](Self::new), then call [`start`](Self::start) once the
/// GPS channel wiring is ready.
pub struct VruAwarenessService {
    btp_handle:  BTPRouterHandle,
    device_data: DeviceData,
    /// Reception management writes decoded VAMs into this sender.
    vam_tx:      Sender<Vam>,
}

impl VruAwarenessService {
    /// Create a new VRU Awareness Service.
    ///
    /// Returns `(service, vam_receiver)`.  Hold `vam_receiver` to consume
    /// decoded incoming VAMs.  Call [`start`](Self::start) with a GPS fix
    /// receiver to begin transmitting and receiving.
    pub fn new(
        btp_handle:  BTPRouterHandle,
        device_data: DeviceData,
    ) -> (Self, Receiver<Vam>) {
        let (vam_tx, vam_rx) = mpsc::channel::<Vam>();
        let svc = VruAwarenessService { btp_handle, device_data, vam_tx };
        (svc, vam_rx)
    }

    /// Spawn the transmission and reception management threads.
    ///
    /// * `gps_rx` — a `Receiver<GpsFix>` from [`LocationService::subscribe`].
    ///
    /// The reception thread registers BTP port 2018 immediately.
    /// The transmission thread starts producing VAMs as soon as fixes arrive.
    pub fn start(self, gps_rx: Receiver<GpsFix>) {
        let coder = VamCoder::new();
        VAMReceptionManagement::spawn(self.btp_handle.clone(), coder.clone(), self.vam_tx);
        VAMTransmissionManagement::spawn(self.btp_handle, coder, self.device_data, gps_rx);
    }
}

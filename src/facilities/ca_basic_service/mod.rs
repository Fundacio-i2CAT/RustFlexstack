// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CA Basic Service — Cooperative Awareness Basic Service (ETSI TS 103 900 V2.2.1).
//!
//! Implements CAM generation and reception on top of the BTP and
//! GeoNetworking layers already present in this crate.
//!
//! # Architecture
//! ```text
//! LocationService ──GpsFix──► CAMTransmissionManagement ──BTPDataRequest──► BTP
//!                                                                              │
//!                              CAMReceptionManagement  ◄──BTPDataIndication──┘
//!                                      │
//!                               Sender<Cam>  ──►  application (Receiver<Cam>)
//! ```
//!
//! # Quick start
//! ```no_run
//! use rustflexstack::btp::router::Router as BTPRouter;
//! use rustflexstack::geonet::mib::Mib;
//! use rustflexstack::facilities::ca_basic_service::{
//!     CooperativeAwarenessBasicService, VehicleData,
//! };
//! use rustflexstack::facilities::location_service::LocationService;
//!
//! let mib = Mib::new();
//! let (btp_handle, _) = BTPRouter::spawn(mib);
//! let mut loc_svc = LocationService::new();
//!
//! let (ca_svc, cam_rx) =
//!     CooperativeAwarenessBasicService::new(btp_handle, VehicleData::default());
//! ca_svc.start(loc_svc.subscribe());
//!
//! while let Ok(cam) = cam_rx.recv() {
//!     println!("CAM from station {}", cam.header.station_id);
//! }
//! ```

pub mod cam_bindings;
pub mod cam_coder;
pub mod cam_reception;
pub mod cam_transmission;

pub use cam_coder::{Cam, CamCoder};
pub use cam_reception::CAMReceptionManagement;
pub use cam_transmission::{CAMTransmissionManagement, VehicleData};

use crate::btp::router::BTPRouterHandle;
use crate::facilities::local_dynamic_map::LdmHandle;
use crate::facilities::location_service::GpsFix;
use std::sync::mpsc::{self, Receiver, Sender};

/// Top-level Cooperative Awareness Basic Service.
///
/// Mirrors `CooperativeAwarenessBasicService` in
/// `flexstack/facilities/ca_basic_service/ca_basic_service.py`.
///
/// Create with [`new`](Self::new), then call [`start`](Self::start) once the
/// GPS channel wiring is ready.
pub struct CooperativeAwarenessBasicService {
    btp_handle: BTPRouterHandle,
    vehicle_data: VehicleData,
    /// Reception management writes decoded CAMs into this sender.
    cam_tx: Sender<Cam>,
    /// Optional LDM handle — if provided, received CAMs are stored in the LDM.
    ldm: Option<LdmHandle>,
}

impl CooperativeAwarenessBasicService {
    /// Create a new CA Basic Service.
    ///
    /// Returns `(service, cam_receiver)`.  Hold `cam_receiver` to consume
    /// decoded incoming CAMs.  Call [`start`](Self::start) with a GPS fix
    /// receiver to begin transmitting and receiving.
    ///
    /// Pass `Some(ldm_handle)` to have every received CAM inserted into the
    /// LDM automatically before it is delivered to the `cam_receiver`.
    pub fn new(
        btp_handle: BTPRouterHandle,
        vehicle_data: VehicleData,
        ldm: Option<LdmHandle>,
    ) -> (Self, Receiver<Cam>) {
        let (cam_tx, cam_rx) = mpsc::channel::<Cam>();
        let svc = CooperativeAwarenessBasicService {
            btp_handle,
            vehicle_data,
            cam_tx,
            ldm,
        };
        (svc, cam_rx)
    }

    /// Spawn the transmission and reception management threads.
    ///
    /// * `gps_rx` — a `Receiver<GpsFix>` from [`LocationService::subscribe`].
    ///
    /// The reception thread registers BTP port 2001 immediately.
    /// The transmission thread starts producing CAMs as soon as fixes arrive.
    pub fn start(self, gps_rx: Receiver<GpsFix>) {
        let coder = CamCoder::new();
        CAMReceptionManagement::spawn(
            self.btp_handle.clone(),
            coder.clone(),
            self.cam_tx,
            self.ldm,
        );
        CAMTransmissionManagement::spawn(self.btp_handle, coder, self.vehicle_data, gps_rx);
    }
}

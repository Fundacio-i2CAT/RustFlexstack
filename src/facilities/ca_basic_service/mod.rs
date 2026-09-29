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
//!     CooperativeAwarenessBasicService::new(btp_handle, VehicleData::default(), None);
//! ca_svc.start(loc_svc.subscribe());
//!
//! while let Ok(cam) = cam_rx.recv() {
//!     println!("CAM from station {}", cam.header.station_id);
//! }
//! ```

pub mod cam_bindings;
pub mod cam_coder;
pub mod cam_ldm_adaptation;
pub mod cam_reception;
pub mod cam_transmission;

pub use cam_coder::{Cam, CamCoder};
pub use cam_ldm_adaptation::{CABasicServiceLDM, CaBasicServiceLdm};
pub use cam_reception::CAMReceptionManagement;
pub use cam_transmission::{
    create_altitude_confidence, create_heading_confidence, create_position_confidence, haversine_m,
    CAMTransmissionManagement, CooperativeAwarenessMessage, VehicleData, N_GEN_CAM_DEFAULT,
    TWO_WHEELER_STATION_TYPES, T_CHECK_CAM_GEN_MS, T_GEN_CAM_DCC_MS, T_GEN_CAM_LF_MS,
    T_GEN_CAM_MAX_MS, T_GEN_CAM_MIN_MS, T_GEN_CAM_SPECIAL_MS, T_GEN_CAM_VLF_MS,
};

use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataIndication;
use crate::facilities::local_dynamic_map::LdmHandle;
use crate::facilities::location_service::GpsFix;
use rand::Rng;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Top-level Cooperative Awareness Basic Service.
///
/// Mirrors `CooperativeAwarenessBasicService` in
/// `flexstack/facilities/ca_basic_service/ca_basic_service.py`.
///
/// Create with [`new`](Self::new), then call [`start`](Self::start) once the
/// GPS channel wiring is ready. Call [`stop`](Self::stop) to deactivate the service.
pub struct CooperativeAwarenessBasicService {
    pub cam_coder: CamCoder,
    pub cam_transmission_management: CAMTransmissionManagement,
    pub cam_reception_management: CAMReceptionManagement,
    pub ca_basic_service_ldm: Option<CABasicServiceLDM>,
}

impl CooperativeAwarenessBasicService {
    /// Create a new CA Basic Service.
    ///
    /// Returns `(service, cam_receiver)`. Hold `cam_receiver` to consume
    /// decoded incoming CAMs. Call [`start`](Self::start) with a GPS fix
    /// receiver to begin transmitting and receiving.
    ///
    /// Pass `Some(ldm_handle)` to have received and transmitted CAMs inserted
    /// into the LDM automatically.
    pub fn new(
        btp_handle: BTPRouterHandle,
        vehicle_data: VehicleData,
        ldm: Option<LdmHandle>,
    ) -> (Self, Receiver<Cam>) {
        let cam_coder = CamCoder::new();
        let ca_basic_service_ldm = ldm.map(|l| CABasicServiceLDM::new(l, 5));
        let (cam_tx, cam_rx) = mpsc::channel::<Cam>();

        let cam_reception_management = CAMReceptionManagement::new_with_channel(
            btp_handle.clone(),
            cam_coder.clone(),
            ca_basic_service_ldm.clone(),
            cam_tx,
        );

        let cam_transmission_management = CAMTransmissionManagement::new(
            btp_handle,
            cam_coder.clone(),
            vehicle_data,
            ca_basic_service_ldm.clone(),
        );

        let svc = CooperativeAwarenessBasicService {
            cam_coder,
            cam_transmission_management,
            cam_reception_management,
            ca_basic_service_ldm,
        };

        (svc, cam_rx)
    }

    /// Activate the CA service (§6.1.2).
    ///
    /// Spawns the transmission and reception management background worker threads.
    /// * `gps_rx` — a `Receiver<GpsFix>` from [`LocationService::subscribe`](crate::facilities::location_service::LocationService::subscribe).
    pub fn start(&self, gps_rx: Receiver<GpsFix>) {
        self.cam_transmission_management.start();

        // 1. Reception thread: register BTP port 2001
        let btp_handle = self.cam_reception_management.btp_handle.clone();
        let crm = self.cam_reception_management.clone();
        let (ind_tx, ind_rx) = mpsc::channel::<BTPDataIndication>();
        btp_handle.register_port(2001, ind_tx);

        thread::spawn(move || {
            while let Ok(indication) = ind_rx.recv() {
                let _ = crm.reception_callback(&indication);
            }
        });

        // 2. Transmission thread: drains GPS fixes and evaluates conditions
        let ctm = self.cam_transmission_management.clone();
        thread::spawn(move || {
            let initial_delay =
                Duration::from_millis(rand::thread_rng().gen_range(0..T_CHECK_CAM_GEN_MS));
            thread::sleep(initial_delay);

            loop {
                if !ctm.is_active() {
                    break;
                }
                let deadline = Instant::now() + Duration::from_millis(T_CHECK_CAM_GEN_MS);
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match gps_rx.recv_timeout(remaining) {
                        Ok(fix) => ctm.location_service_callback(fix),
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => {
                            return;
                        }
                    }
                }

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let _ = ctm.evaluate_and_maybe_send(now_ms);
            }
        });
    }

    /// Deactivate the CA service (§6.1.2).
    ///
    /// Stops CAM transmission.
    pub fn stop(&self) {
        self.cam_transmission_management.stop();
    }

    /// Update position fix directly via the location service callback (§6.1.3).
    pub fn location_service_callback(&self, fix: GpsFix) {
        self.cam_transmission_management
            .location_service_callback(fix);
    }

    /// Register an application callback for received CAMs (IF.CAM — §6.2).
    pub fn add_application_callback<F>(&self, callback: F)
    where
        F: Fn(&Cam, u64) + Send + Sync + 'static,
    {
        self.cam_reception_management
            .add_application_callback(callback);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facilities::local_dynamic_map::LdmFacility;
    use crate::geonet::mib::Mib;

    #[test]
    fn test_ca_basic_service_init() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let (service, _cam_rx) =
            CooperativeAwarenessBasicService::new(btp_handle, VehicleData::default(), None);

        assert!(!service.cam_transmission_management.is_active());
        assert!(service.ca_basic_service_ldm.is_none());
    }

    #[test]
    fn test_ca_basic_service_with_ldm() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let ldm = LdmFacility::new(415_520_000, 21_340_000, 5_000.0);
        let (service, _cam_rx) =
            CooperativeAwarenessBasicService::new(btp_handle, VehicleData::default(), Some(ldm));

        assert!(service.ca_basic_service_ldm.is_some());
    }

    #[test]
    fn test_start_and_stop_lifecycle() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let (service, _cam_rx) =
            CooperativeAwarenessBasicService::new(btp_handle, VehicleData::default(), None);

        let (_gps_tx, gps_rx) = mpsc::channel::<GpsFix>();
        service.start(gps_rx);
        assert!(service.cam_transmission_management.is_active());

        service.stop();
        assert!(!service.cam_transmission_management.is_active());
    }

    #[test]
    fn test_location_service_callback_available() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let (service, _cam_rx) =
            CooperativeAwarenessBasicService::new(btp_handle, VehicleData::default(), None);

        let fix = GpsFix {
            latitude: 41.0,
            longitude: 2.0,
            altitude_m: 50.0,
            speed_mps: 10.0,
            heading_deg: 90.0,
            pai: true,
        };
        service.location_service_callback(fix);
        let cached = service
            .cam_transmission_management
            .state
            .lock()
            .unwrap()
            .current_fix;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().latitude, 41.0);
    }
}

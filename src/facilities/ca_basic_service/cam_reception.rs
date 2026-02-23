// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CAM Reception Management.
//!
//! Mirrors `CAMReceptionManagement` in
//! `flexstack/facilities/ca_basic_service/cam_reception_management.py`.
//!
//! [`CAMReceptionManagement::spawn`] starts a background thread that:
//! 1. Registers BTP port 2001 with the BTP router.
//! 2. Waits for [`BTPDataIndication`] messages from the router.
//! 3. Decodes the UPER payload via [`CamCoder`].
//! 4. Optionally stores the decoded CAM in the LDM (if a handle is provided).
//! 5. Forwards the decoded [`Cam`] to the caller via an MPSC channel.

use super::cam_coder::{Cam, CamCoder};
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataIndication;
use crate::facilities::local_dynamic_map::{
    ldm_constants::{now_its_ms, ITS_AID_CAM},
    ldm_storage::ItsDataObject,
    ldm_types::AddDataProviderReq,
    LdmHandle,
};
use std::sync::mpsc::{self, Sender};
use std::thread;

/// CAM Reception Management.
///
/// Spawned as a background thread via [`CAMReceptionManagement::spawn`].
pub struct CAMReceptionManagement;

impl CAMReceptionManagement {
    /// Spawn the reception management thread.
    ///
    /// # Arguments
    /// * `btp_handle` — handle to the BTP router; used to register port 2001.
    /// * `coder`      — shared [`CamCoder`] instance for UPER decoding.
    /// * `cam_tx`     — sender into which decoded [`Cam`] PDUs are pushed.
    /// * `ldm`        — optional LDM handle; when `Some`, each decoded CAM is
    ///                  inserted into the LDM before forwarding.
    ///
    /// The caller should hold the corresponding `Receiver<Cam>` — typically
    /// returned from [`CooperativeAwarenessBasicService::new`].
    pub fn spawn(
        btp_handle: BTPRouterHandle,
        coder:      CamCoder,
        cam_tx:     Sender<Cam>,
        ldm:        Option<LdmHandle>,
    ) {
        // Create an internal BTPDataIndication channel and register it
        // on BTP port 2001 (CAM destination port per ETSI EN 302 637-2).
        let (ind_tx, ind_rx) = mpsc::channel::<BTPDataIndication>();
        btp_handle.register_port(2001, ind_tx);

        thread::spawn(move || {
            while let Ok(indication) = ind_rx.recv() {
                match coder.decode(&indication.data) {
                    Ok(cam) => {
                        eprintln!(
                            "[CAM RX] station={} gen_dt={} lat={:.5} lon={:.5}",
                            cam.header.station_id.0,
                            cam.cam.generation_delta_time.0,
                            cam.cam.cam_parameters.basic_container.reference_position.latitude.0 as f64 / 1e7,
                            cam.cam.cam_parameters.basic_container.reference_position.longitude.0 as f64 / 1e7,
                        );

                        // Insert into LDM if a handle was provided.
                        if let Some(ref ldm_handle) = ldm {
                            let ref_pos = &cam.cam.cam_parameters.basic_container.reference_position;
                            let lat = ref_pos.latitude.0;
                            let lon = ref_pos.longitude.0;
                            let alt = ref_pos.altitude.altitude_value.0;
                            ldm_handle.if_ldm_3.add_provider_data(AddDataProviderReq {
                                application_id:  ITS_AID_CAM,
                                timestamp_its:   now_its_ms(),
                                lat_etsi:        lat,
                                lon_etsi:        lon,
                                altitude_cm:     (alt / 10) as i32, // AltitudeValue in 0.01 m → cm
                                time_validity_s: 1,                  // CAM validity: 1 s
                                data_object:     ItsDataObject::Cam(Box::new(cam.clone())),
                            });
                        }

                        // Forward to caller; if they dropped the receiver, stop quietly.
                        if cam_tx.send(cam).is_err() {
                            break;
                        }
                    }
                    Err(e) => eprintln!("[CAM RX] Decode error: {}", e),
                }
            }
            eprintln!("[CAM RX] Thread exiting");
        });
    }
}

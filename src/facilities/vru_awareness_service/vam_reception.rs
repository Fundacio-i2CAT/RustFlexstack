// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! VAM Reception Management — ETSI TS 103 300-3 V2.3.1 (2025-12).
//!
//! Mirrors `VAMReceptionManagement` in
//! `flexstack/facilities/vru_awareness_service/vam_reception_management.py`.
//!
//! [`VAMReceptionManagement::spawn`] starts a background thread that:
//! 1. Registers BTP port 2018 with the BTP router.
//! 2. Waits for [`BTPDataIndication`] messages from the router.
//! 3. Decodes the UPER payload via [`VamCoder`].
//! 4. Forwards the decoded [`Vam`] to the caller via an MPSC channel.

use super::vam_coder::{Vam, VamCoder};
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataIndication;
use std::sync::mpsc::{self, Sender};
use std::thread;

/// VAM Reception Management.
///
/// Spawned as a background thread via [`VAMReceptionManagement::spawn`].
pub struct VAMReceptionManagement;

impl VAMReceptionManagement {
    /// Spawn the reception management thread.
    ///
    /// # Arguments
    /// * `btp_handle` — handle to the BTP router; used to register port 2018.
    /// * `coder`      — shared [`VamCoder`] instance for UPER decoding.
    /// * `vam_tx`     — sender into which decoded [`Vam`] PDUs are pushed.
    ///
    /// The caller should hold the corresponding `Receiver<Vam>` — typically
    /// returned from [`VruAwarenessService::new`].
    pub fn spawn(btp_handle: BTPRouterHandle, coder: VamCoder, vam_tx: Sender<Vam>) {
        // Create an internal BTPDataIndication channel and register it
        // on BTP port 2018 (VAM destination port per ETSI TS 103 300-3).
        let (ind_tx, ind_rx) = mpsc::channel::<BTPDataIndication>();
        btp_handle.register_port(2018, ind_tx);

        thread::spawn(move || {
            while let Ok(indication) = ind_rx.recv() {
                match coder.decode(&indication.data) {
                    Ok(vam) => {
                        eprintln!(
                            "[VAM RX] station={} gen_dt={} lat={:.5} lon={:.5}",
                            vam.header.0.station_id.0,
                            vam.vam.generation_delta_time.0,
                            vam.vam
                                .vam_parameters
                                .basic_container
                                .reference_position
                                .latitude
                                .0 as f64
                                / 1e7,
                            vam.vam
                                .vam_parameters
                                .basic_container
                                .reference_position
                                .longitude
                                .0 as f64
                                / 1e7,
                        );
                        // Forward to caller; if they dropped the receiver, stop quietly.
                        if vam_tx.send(vam).is_err() {
                            break;
                        }
                    }
                    Err(e) => eprintln!("[VAM RX] Decode error (clause 7): {}", e),
                }
            }
            eprintln!("[VAM RX] Thread exiting");
        });
    }
}

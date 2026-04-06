// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DENM Reception Management.
//!
//! Mirrors `DENMReceptionManagement` in
//! `flexstack/facilities/decentralized_environmental_notification_service/denm_reception_management.py`.
//!
//! [`DENMReceptionManagement::spawn`] starts a background thread that:
//! 1. Registers BTP port 2002 with the BTP router.
//! 2. Waits for [`BTPDataIndication`] messages from the router.
//! 3. Decodes the UPER payload via [`DenmCoder`].
//! 4. Forwards the decoded [`Denm`] to the caller via an MPSC channel.

use super::denm_coder::{Denm, DenmCoder};
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataIndication;
use std::sync::mpsc::{self, Sender};
use std::thread;

/// DENM Reception Management.
///
/// Spawned as a background thread via [`DENMReceptionManagement::spawn`].
pub struct DENMReceptionManagement;

impl DENMReceptionManagement {
    /// Spawn the reception management thread.
    ///
    /// # Arguments
    /// * `btp_handle` — handle to the BTP router; used to register port 2002.
    /// * `coder`      — shared [`DenmCoder`] instance for UPER decoding.
    /// * `denm_tx`    — sender into which decoded [`Denm`] PDUs are pushed.
    ///
    /// The caller should hold the corresponding `Receiver<Denm>` — typically
    /// returned from [`DecentralizedEnvironmentalNotificationService::new`].
    pub fn spawn(btp_handle: BTPRouterHandle, coder: DenmCoder, denm_tx: Sender<Denm>) {
        // Create an internal BTPDataIndication channel and register it
        // on BTP port 2002 (DENM destination port per ETSI EN 302 637-3).
        let (ind_tx, ind_rx) = mpsc::channel::<BTPDataIndication>();
        btp_handle.register_port(2002, ind_tx);

        thread::spawn(move || {
            while let Ok(indication) = ind_rx.recv() {
                match coder.decode(&indication.data) {
                    Ok(denm) => {
                        eprintln!(
                            "[DENM RX] station={} seq={} lat={:.5} lon={:.5}",
                            denm.header.station_id.0,
                            denm.denm.management.action_id.sequence_number.0,
                            denm.denm.management.event_position.latitude.0 as f64 / 1e7,
                            denm.denm.management.event_position.longitude.0 as f64 / 1e7,
                        );
                        // Forward to caller; if they dropped the receiver, stop quietly.
                        if denm_tx.send(denm).is_err() {
                            break;
                        }
                    }
                    Err(e) => eprintln!("[DENM RX] Decode error: {}", e),
                }
            }
            eprintln!("[DENM RX] Thread exiting");
        });
    }
}

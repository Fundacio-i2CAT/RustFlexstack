// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DENM reception: receiving ITS-S operation of the DEN service
//! (ETSI TS 103 831 V2.3.1 (2025-11), clause 8.4) and the reception side of
//! the optional Keep-Alive Forwarding (clause 8.3).
//!
//! A background thread registered on BTP port 2002 decodes each DENM and
//! processes it against the receiving ITS-S message table of the shared
//! [`DenProtocol`](super::den_protocol::DenProtocol). Accepted DENMs (new
//! event, update, termination of a known event) are passed on; outdated,
//! repeated, expired and unknown-termination DENMs are discarded.
//!
//! Mirrors `flexstack/facilities/decentralized_environmental_notification_service/denm_reception_management.py`.

use super::den_protocol::{DenmState, ReceptionOutcome};
use super::denm_coder::{Denm, DenmCoder};
use super::denm_ssp::ssp_consistent;
use super::denm_transmission::{new_protocol, DenShared, VehicleData, DENM_BTP_PORT};
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataIndication;
use crate::geonet::service_access_point::{HeaderSubType, HeaderType};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread;

/// DENM passed to ITS-S applications (IF.DataCollect, clause 5.3.1.5).
#[derive(Debug, Clone)]
pub struct ReceivedDenm {
    pub denm: Denm,
    /// State of the event after this DENM: active, cancelled or negated.
    pub state: DenmState,
}

/// DENM Reception Management.
pub struct DENMReceptionManagement;

impl DENMReceptionManagement {
    /// Spawn a standalone reception thread with its own protocol engine.
    /// Accepted DENMs are pushed into `denm_tx`.
    pub fn spawn(btp_handle: BTPRouterHandle, coder: DenmCoder, denm_tx: Sender<Denm>) {
        let shared = DenShared::new(new_protocol(&VehicleData::default(), false, &coder));
        Self::spawn_with(btp_handle, coder, shared, Some(denm_tx), None);
    }

    /// Spawn the reception thread on a protocol engine shared with
    /// transmission and the timer thread. Accepted DENMs go to `denm_tx`
    /// (DENM only) and `events_tx` (DENM and state).
    pub fn spawn_with(
        btp_handle: BTPRouterHandle,
        coder: DenmCoder,
        shared: Arc<DenShared>,
        denm_tx: Option<Sender<Denm>>,
        events_tx: Option<Sender<ReceivedDenm>>,
    ) {
        let (ind_tx, ind_rx) = mpsc::channel::<BTPDataIndication>();
        btp_handle.register_port(DENM_BTP_PORT, ind_tx);
        thread::spawn(move || {
            while let Ok(indication) = ind_rx.recv() {
                let Some(received) = process_indication(&coder, &shared, &indication) else {
                    continue;
                };
                let mut delivered = false;
                if let Some(tx) = &denm_tx {
                    delivered |= tx.send(received.denm.clone()).is_ok();
                }
                if let Some(tx) = &events_tx {
                    delivered |= tx.send(received).is_ok();
                }
                if !delivered && (denm_tx.is_some() || events_tx.is_some()) {
                    break; // every consumer is gone
                }
            }
        });
    }
}

/// Decode and process one BTP indication (clause 8.4.2). Returns the DENM and
/// its state when the receiving ITS-S accepts it.
pub fn process_indication(
    coder: &DenmCoder,
    shared: &DenShared,
    indication: &BTPDataIndication,
) -> Option<ReceivedDenm> {
    // ETSI TS 103 097 V2.2.1 clause 7.1.2: a
    // secured DENM shall carry the DENM ITS-AID.
    if indication
        .gn_its_aid
        .is_some_and(|aid| aid != super::denm_transmission::DENM_ITS_AID)
    {
        return None;
    }
    // DENM decoding exception (clause 8.4.3.2): discard.
    let denm = coder.decode(&indication.data).ok()?;
    let area = match (
        indication.gn_destination_area,
        &indication.gn_packet_transport_type.header_type,
        &indication.gn_packet_transport_type.header_sub_type,
    ) {
        (Some(area), HeaderType::GeoBroadcast, HeaderSubType::GeoBroadcast(kind)) => {
            Some((area, *kind))
        }
        _ => None,
    };
    let now = shared.now();
    let ssp_ok = ssp_consistent(indication.gn_permissions.as_deref(), &denm);
    let outcome: ReceptionOutcome = shared
        .protocol
        .lock()
        .unwrap()
        .receive(&denm, now, area, ssp_ok);
    shared.wakeup.notify_all();
    if !outcome.accepted {
        return None;
    }
    Some(ReceivedDenm {
        denm,
        state: outcome.state.unwrap_or(DenmState::Active),
    })
}

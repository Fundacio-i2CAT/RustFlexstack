// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Decentralized Environmental Notification (DEN) Service.
//!
//! Implements ETSI TS 103 831 V2.3.1 (2025-11) "Decentralized Environmental
//! Notification Service; Release 2" (latest version), the successor of ETSI
//! EN 302 637-3 V1.3.1 (2019-04). DENMs use DENM-PDU-Descriptions v2.3
//! (Annex A) over the Common Data Dictionary v4.3 (ETSI TS 102 894-2).
//!
//! # Architecture
//! ```text
//! Application ──DenmRequest / DENRequest──► DENMTransmissionManagement ──► BTP (port 2002)
//!                                                │  (originating ITS-S, clause 8.2)
//!                                    DenProtocol (message tables, timers)
//!                                                │  (receiving ITS-S 8.4, KAF 8.3)
//! Application ◄──Denm / ReceivedDenm── DENMReceptionManagement ◄── BTP
//!                       timer thread ── tick() ──► repetitions, KAF forwards
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

#[cfg(test)]
pub(crate) mod conformance;
pub mod den_protocol;
pub mod denm_bindings;
pub mod denm_coder;
pub mod denm_reception;
pub mod denm_ssp;
pub mod denm_transmission;

pub use den_protocol::{
    DenActionId, DenFailure, DenProtocol, DenResult, DenmRequest, DenmState, OutgoingDenm,
};
pub use denm_coder::{Denm, DenmCoder};
pub use denm_reception::{DENMReceptionManagement, ReceivedDenm};
pub use denm_transmission::{
    DENMTransmissionManagement, DENRequest, DenClock, DenShared, VehicleData,
};

use crate::btp::router::BTPRouterHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_IDLE_WAIT: Duration = Duration::from_secs(1);

/// Options of the DEN service.
#[derive(Default)]
pub struct DenConfig {
    /// Activate Keep-Alive Forwarding of received DENMs (clause 6.1.4.2). KAF
    /// only forwards while [`DecentralizedEnvironmentalNotificationService::set_ego_position`]
    /// has placed the station inside the DENM destination area.
    pub kaf_enabled: bool,
    /// Also deliver accepted DENMs with their state (active / cancelled / negated).
    pub events: Option<Sender<ReceivedDenm>>,
    /// Be notified when a received event expires (T_R_Validity).
    pub expiry: Option<Sender<DenActionId>>,
    /// Do not start the timer thread (tests drive [`DecentralizedEnvironmentalNotificationService::process_timers`]).
    pub no_scheduler: bool,
    /// Time source of the service (TimestampIts, ms); the system time when `None`.
    pub clock: Option<DenClock>,
}

/// Top-level Decentralized Environmental Notification Service.
///
/// Mirrors `DecentralizedEnvironmentalNotificationService` in
/// `flexstack/facilities/decentralized_environmental_notification_service/den_service.py`.
pub struct DecentralizedEnvironmentalNotificationService {
    tx_management: DENMTransmissionManagement,
    shared: Arc<DenShared>,
    btp_handle: BTPRouterHandle,
    coder: DenmCoder,
    expiry: Option<Sender<DenActionId>>,
    running: Arc<AtomicBool>,
    scheduler: Option<JoinHandle<()>>,
}

impl DecentralizedEnvironmentalNotificationService {
    /// Create a DEN service. Returns `(service, denm_receiver)`; accepted
    /// incoming DENMs are delivered on `denm_receiver`. Reception and the
    /// timer thread start immediately.
    pub fn new(btp_handle: BTPRouterHandle, vehicle_data: VehicleData) -> (Self, Receiver<Denm>) {
        Self::with_config(btp_handle, vehicle_data, DenConfig::default())
    }

    /// Create a DEN service with options (KAF, events with state, expiry).
    pub fn with_config(
        btp_handle: BTPRouterHandle,
        vehicle_data: VehicleData,
        config: DenConfig,
    ) -> (Self, Receiver<Denm>) {
        let coder = DenmCoder::new();
        let shared = DenShared::with_clock(
            denm_transmission::new_protocol(&vehicle_data, config.kaf_enabled, &coder),
            config.clock,
        );
        let (denm_tx, denm_rx) = mpsc::channel::<Denm>();
        DENMReceptionManagement::spawn_with(
            btp_handle.clone(),
            coder.clone(),
            shared.clone(),
            Some(denm_tx),
            config.events,
        );
        let tx_management = DENMTransmissionManagement::with_shared(
            btp_handle.clone(),
            coder.clone(),
            vehicle_data,
            shared.clone(),
        );
        let mut svc = DecentralizedEnvironmentalNotificationService {
            tx_management,
            shared,
            btp_handle,
            coder,
            expiry: config.expiry,
            running: Arc::new(AtomicBool::new(false)),
            scheduler: None,
        };
        if !config.no_scheduler {
            svc.start();
        }
        (svc, denm_rx)
    }

    // ── Application interface ──────────────────────────────────────────────

    /// AppDENM_trigger.
    pub fn trigger(&self, request: &DenmRequest) -> DenResult {
        self.tx_management.trigger(request)
    }

    /// AppDENM_update.
    pub fn update(&self, action_id: DenActionId, request: &DenmRequest) -> DenResult {
        self.tx_management.update(action_id, request)
    }

    /// AppDENM_termination.
    pub fn terminate(&self, action_id: DenActionId, request: &DenmRequest) -> DenResult {
        self.tx_management.terminate(action_id, request)
    }

    /// Road-hazard DENM repeated every `denm_interval_ms` for `time_period_ms`.
    pub fn trigger_denm(&self, request: DENRequest) {
        self.tx_management.trigger_denm_sending(request);
    }

    /// Send a single road-hazard DENM (no repetition).
    pub fn send_single_denm(&self, request: &DENRequest) {
        self.tx_management.send_single_denm(request);
    }

    /// Pseudonym change: re-label all stored own DENMs (clause 6.1.1.2).
    pub fn update_station_id(&self, station_id: u32) {
        self.shared
            .protocol
            .lock()
            .unwrap()
            .update_station_id(station_id);
    }

    /// Own position in 1/10 micro-degree, used by Keep-Alive Forwarding.
    pub fn set_ego_position(&self, latitude: i32, longitude: i32) {
        self.shared
            .protocol
            .lock()
            .unwrap()
            .set_ego_position(latitude, longitude);
    }

    /// Shared protocol engine (message tables), e.g. for inspection.
    pub fn shared(&self) -> &Arc<DenShared> {
        &self.shared
    }

    // ── Timers ─────────────────────────────────────────────────────────────

    /// Fire the expired protocol timers at `now` (TimestampIts ms; current
    /// time when `None`) and transmit the resulting DENMs.
    pub fn process_timers(&self, now: Option<u64>) {
        process_timers(
            &self.shared,
            &self.btp_handle,
            &self.coder,
            self.expiry.as_ref(),
            now,
        );
    }

    /// Start the timer thread (idempotent).
    pub fn start(&mut self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let (shared, running) = (self.shared.clone(), self.running.clone());
        let (btp, coder, expiry) = (
            self.btp_handle.clone(),
            self.coder.clone(),
            self.expiry.clone(),
        );
        self.scheduler = Some(thread::spawn(move || loop {
            {
                let guard = shared.protocol.lock().unwrap();
                if !running.load(Ordering::SeqCst) {
                    return;
                }
                let now = shared.now();
                match guard.next_deadline() {
                    Some(deadline) if deadline <= now => {}
                    deadline => {
                        let wait = deadline
                            .map(|d| Duration::from_millis(d - now).min(MAX_IDLE_WAIT))
                            .unwrap_or(MAX_IDLE_WAIT);
                        let _ = shared.wakeup.wait_timeout(guard, wait).unwrap();
                        continue;
                    }
                }
            }
            process_timers(&shared, &btp, &coder, expiry.as_ref(), None);
        }));
    }

    /// Stop the timer thread.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.shared.wakeup.notify_all();
        if let Some(handle) = self.scheduler.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for DecentralizedEnvironmentalNotificationService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn process_timers(
    shared: &DenShared,
    btp_handle: &BTPRouterHandle,
    coder: &DenmCoder,
    expiry: Option<&Sender<DenActionId>>,
    now: Option<u64>,
) {
    let now = now.unwrap_or_else(|| shared.now());
    let (outgoing, expired) = shared.protocol.lock().unwrap().tick(now);
    for item in &outgoing {
        denm_transmission::transmit(btp_handle, coder, item);
    }
    if let Some(tx) = expiry {
        for action_id in expired {
            let _ = tx.send(action_id);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Mirrors test_den_service.py and test_denm_reception_management.py.
    use super::den_protocol::{DenmRequest, DenmState};
    use super::denm_coder::Termination;
    use super::denm_reception::process_indication;
    use super::denm_transmission::{build_denm, new_protocol};
    use super::*;
    use crate::btp::service_access_point::BTPDataIndication;
    use crate::geonet::mib::Mib;
    use crate::geonet::service_access_point::{
        Area, GNDataRequest, GeoBroadcastHST, HeaderSubType, HeaderType,
    };
    use std::sync::mpsc::Receiver;

    fn request() -> DenmRequest {
        let t = build_denm(&DENRequest::default(), &VehicleData::default(), 0);
        let mut r = DenmRequest::new(t.denm.management.event_position.clone());
        r.situation = t.denm.situation;
        r.location = t.denm.location;
        r
    }

    fn service(
        config: DenConfig,
    ) -> (
        DecentralizedEnvironmentalNotificationService,
        Receiver<GNDataRequest>,
    ) {
        let (btp, gn_rx) = crate::btp::router::Router::spawn(Mib::new());
        let vd = VehicleData {
            station_id: 7,
            station_type: 5,
        };
        let (svc, _rx) =
            DecentralizedEnvironmentalNotificationService::with_config(btp, vd, config);
        (svc, gn_rx)
    }

    fn received(gn_rx: &Receiver<GNDataRequest>) -> Vec<Denm> {
        let coder = DenmCoder::new();
        let mut out = vec![];
        while let Ok(r) = gn_rx.recv_timeout(Duration::from_millis(200)) {
            out.push(coder.decode(&r.data[4..]).unwrap());
        }
        out
    }

    #[test]
    fn process_timers_sends_repetitions_with_same_reference_time() {
        let (svc, gn_rx) = service(DenConfig {
            no_scheduler: true,
            ..Default::default()
        });
        let mut r = request();
        r.repetition_interval = Some(100);
        r.repetition_duration = Some(1000);
        let id = svc.trigger(&r).unwrap();
        let reference = svc.shared().protocol.lock().unwrap().originating[&id]
            .denm
            .denm
            .management
            .reference_time
            .0;
        svc.process_timers(Some(reference + 100));
        svc.process_timers(Some(reference + 200));
        let sent = received(&gn_rx);
        assert_eq!(sent.len(), 3);
        assert!(sent
            .iter()
            .all(|d| d.denm.management.reference_time.0 == reference));
    }

    #[test]
    fn scheduler_thread_sends_repetitions() {
        let (mut svc, gn_rx) = service(DenConfig::default());
        let mut r = request();
        r.repetition_interval = Some(50);
        r.repetition_duration = Some(1000);
        svc.trigger(&r).unwrap();
        let mut n = 0;
        while gn_rx.recv_timeout(Duration::from_secs(2)).is_ok() {
            n += 1;
            if n == 3 {
                break;
            }
        }
        assert_eq!(n, 3);
        svc.stop();
    }

    #[test]
    fn trigger_update_terminate_on_the_wire() {
        let (svc, gn_rx) = service(DenConfig {
            no_scheduler: true,
            ..Default::default()
        });
        let id = svc.trigger(&request()).unwrap();
        assert!(svc.update(id, &request()).is_ok());
        assert!(svc.terminate(id, &request()).is_ok());
        let terminations: Vec<_> = received(&gn_rx)
            .iter()
            .map(|d| d.denm.management.termination)
            .collect();
        assert_eq!(
            terminations,
            vec![None, None, Some(Termination::isCancellation)]
        );
    }

    #[test]
    fn legacy_trigger_denm_schedules_repetition() {
        let (svc, gn_rx) = service(DenConfig {
            no_scheduler: true,
            ..Default::default()
        });
        svc.trigger_denm(DENRequest::default());
        let p = svc.shared().protocol.lock().unwrap();
        let entry = p.originating.values().next().unwrap();
        assert_eq!(entry.repetition_interval, Some(1000));
        assert!(entry.next_repetition.is_some());
        assert_eq!(
            entry
                .denm
                .denm
                .management
                .transmission_interval
                .as_ref()
                .map(|t| t.0),
            Some(1000)
        );
        assert_eq!(entry.denm.denm.management.validity_duration.0, 5);
        drop(p);
        assert_eq!(received(&gn_rx).len(), 1);
    }

    fn indication(denm: &Denm, permissions: Option<Vec<u8>>) -> BTPDataIndication {
        let mut ind = BTPDataIndication::new();
        ind.destination_port = 2002;
        ind.gn_packet_transport_type.header_type = HeaderType::GeoBroadcast;
        ind.gn_packet_transport_type.header_sub_type =
            HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle);
        ind.gn_destination_area = Some(Area {
            latitude: 1,
            longitude: 2,
            a: 1000,
            b: 0,
            angle: 0,
        });
        ind.gn_permissions = permissions;
        ind.data = DenmCoder::new().encode(denm).unwrap();
        ind
    }

    fn originated() -> Denm {
        let coder = DenmCoder::new();
        let mut p = new_protocol(
            &VehicleData {
                station_id: 3,
                station_type: 5,
            },
            false,
            &coder,
        );
        let mut r = request();
        r.transmission_interval = Some(100);
        p.trigger(&r, denm_coder::timestamp_its_now().0)
            .1
            .remove(0)
            .denm
    }

    #[test]
    fn reception_accepts_new_event_once() {
        let coder = DenmCoder::new();
        let shared = DenShared::new(new_protocol(&VehicleData::default(), true, &coder));
        let denm = originated();
        let rx = process_indication(&coder, &shared, &indication(&denm, None)).unwrap();
        assert_eq!(rx.state, DenmState::Active);
        assert!(process_indication(&coder, &shared, &indication(&denm, None)).is_none());
        let p = shared.protocol.lock().unwrap();
        assert_eq!(p.forwarding.values().next().unwrap().area.a, 1000);
    }

    /// ETSI TS 103 097 clause 7.1.2: a secured DENM shall carry the DENM ITS-AID.
    #[test]
    fn reception_discards_secured_denm_with_another_its_aid() {
        let coder = DenmCoder::new();
        let shared = DenShared::new(new_protocol(&VehicleData::default(), false, &coder));
        let denm = originated();
        let mut ind = indication(&denm, None);
        ind.gn_its_aid = Some(36);
        assert!(process_indication(&coder, &shared, &ind).is_none());
        ind.gn_its_aid = Some(37);
        assert!(process_indication(&coder, &shared, &ind).is_some());
    }

    /// Sender-side SSP: accident(2) needs octet 1 bit 0x40 (Table 10).
    #[test]
    fn permissions_bitmap_requests_the_cause_code_bit() {
        let mut denm = originated();
        assert_eq!(denm_ssp::permissions_bitmap(&denm), vec![0, 0x40]);
        denm.denm.situation = None;
        assert_eq!(denm_ssp::permissions_bitmap(&denm), vec![0]);
    }

    #[test]
    fn reception_checks_ssp_and_discards_undecodable() {
        let coder = DenmCoder::new();
        let shared = DenShared::new(new_protocol(&VehicleData::default(), false, &coder));
        let denm = originated(); // accident(2)
        assert!(process_indication(
            &coder,
            &shared,
            &indication(&denm, Some(vec![2, 0x80, 0, 0, 0]))
        )
        .is_none());
        assert!(process_indication(
            &coder,
            &shared,
            &indication(&denm, Some(vec![2, 0x40, 0, 0, 0]))
        )
        .is_some());
        let mut bad = BTPDataIndication::new();
        bad.data = vec![0xFF, 0x00];
        assert!(process_indication(&coder, &shared, &bad).is_none());
    }

    #[test]
    fn expiry_is_notified() {
        let (exp_tx, exp_rx) = mpsc::channel();
        let (svc, _) = service(DenConfig {
            no_scheduler: true,
            expiry: Some(exp_tx),
            ..Default::default()
        });
        let coder = DenmCoder::new();
        let denm = originated();
        process_indication(&coder, svc.shared(), &indication(&denm, None)).unwrap();
        let detection = denm.denm.management.detection_time.0;
        svc.process_timers(Some(detection + 600_000));
        assert_eq!(
            exp_rx.try_recv().unwrap(),
            DenActionId::from_asn(&denm.denm.management.action_id)
        );
    }

    #[test]
    fn station_id_and_ego_position() {
        let (svc, _) = service(DenConfig {
            no_scheduler: true,
            kaf_enabled: true,
            ..Default::default()
        });
        let mut r = request();
        r.repetition_interval = Some(100);
        r.repetition_duration = Some(1000);
        let id = svc.trigger(&r).unwrap();
        svc.update_station_id(8);
        svc.set_ego_position(1, 2);
        let p = svc.shared().protocol.lock().unwrap();
        assert!(p.originating.contains_key(&DenActionId {
            station_id: 8,
            sequence_number: id.sequence_number
        }));
        assert_eq!(p.ego_position, Some((1, 2)));
        assert!(p.kaf_enabled);
    }
}

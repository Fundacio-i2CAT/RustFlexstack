// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Peer-to-peer CRL / CTL distribution of an ITS-S (ETSI TS 103 601 V2.1.1
//! clauses 5.3 and 5.4): the CRL / CTL Distribution Application (CXLDA).
//!
//! **Responder (clause 5.4).** A CRL or Delta CTL (ECTL of the TLM, CTL of a
//! Root CA) received from the DC is verified, applied and broadcast at
//! frequency `f1` during `d1` (case 1). A neighbour's P2P request for a list the
//! ITS-S holds in a more recent version starts its broadcast at `f2` during
//! `d2` (case 2). The broadcast stops at the end of the period, at the
//! nextUpdate of the list, or when the same or a newer version of the list is
//! received from another ITS-S (clause 5.4.3). The SM-PDU is sent unsecured at
//! the GeoNetworking layer (it is signed by its issuer) in a SHB, BTP-B port
//! 2014 (CTL) or 2015 (CRL).
//!
//! **Requester (clause 5.3).** A pending request is inserted in the
//! `contributedExtensions` of the next CAM (clause 5.3.4: one request per CAM):
//! `EtsiTs102941CrlRequest` with the thisUpdate of the last CRL of the issuer,
//! `EtsiTs102941DeltaCtlRequest` with the ctlSequence of its last CTL (absent
//! when none is known). A request is started on demand, when the CRL of an
//! issuer passes its nextUpdate, and when a neighbour requests a CTL more
//! recent than the one held (clause 5.3.6); it ends when the list is received.
//! A CTL request also ends at the nextUpdate of the CTL held.
//!
//! Not implemented: the Full CTL broadcast and its Segmented CTL Response
//! Message (clause 5.5, optional PICS items R1.1.2 / R1.2.5); a received
//! `EtsiTs102941FullCtlRequest` is ignored.
//!
//! The service owns the [`TrustStore`]; the verify library of the station is
//! passed to the calls that apply a list. Broadcasts received on the BTP ports
//! are queued ([`TrustListDistribution::queue_broadcast`]) and applied by
//! [`TrustListDistribution::process_received`].
//!
//! Mirrors `flexstack/security/pki_client/distribution.py`.

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};

use rasn::prelude::*;

use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataRequest;
use crate::geonet::service_access_point::{
    CommonNH, HeaderSubType, HeaderType, PacketTransportType, TopoBroadcastHST,
};
use crate::security::certificate::Certificate;
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::header_extensions::TrustListRequest;
use crate::security::pki_client::client::PkiClock;
use crate::security::pki_client::messages::time32;
use crate::security::pki_client::transport::PkiTransport;
use crate::security::pki_client::trust_lists::{
    ListKind, ListVersion, TrustListError, TrustStore, PSID_CRL, PSID_CTL,
};
use crate::security::security_asn::etsi_ts103097_extension_module::{
    EtsiTs102941CrlRequest, EtsiTs102941CtlRequest,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{HashedId8, Time32, Uint32, Uint8};
use crate::security::sign_service::TrustListRequestProvider;
use crate::security::sn_sap::SecurityProfile;
use crate::security::time_service::unix_time_secs;
use crate::security::verify_service::TrustListListener;

/// BTP-B destination port of the CTL broadcast (ETSI TS 103 601 clause 5.4.4
/// refers to ETSI TS 103 248; value of TS 103 525-2 SECPKI_ITS-S_CTLDIST_03).
pub const CTL_PORT: u16 = 2014;
/// BTP-B destination port of the CRL broadcast (SECPKI_ITS-S_CRLDIST_02).
pub const CRL_PORT: u16 = 2015;

/// Parameters of the service (PIXITs of TS 103 525-2). Defaults: the
/// recommended values of TS 103 601 clause 5.4.2 NOTE 1 and NOTE 3.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DistributionConfig {
    /// Broadcast the lists received from the DC (case 1).
    pub redistribute: bool,
    /// Hz, case 1.
    pub f1: f64,
    /// Seconds, case 1.
    pub d1: f64,
    /// Hz, case 2 (answer to a P2P request).
    pub f2: f64,
    /// Seconds, case 2.
    pub d2: f64,
}

impl Default for DistributionConfig {
    fn default() -> Self {
        Self {
            redistribute: true,
            f1: 1.0,
            d1: 7.0 * 24.0 * 3600.0,
            f2: 1.0,
            d2: 10.0,
        }
    }
}

type Key = (ListKind, [u8; 8]);

/// A list being broadcast.
#[derive(Debug, Clone)]
struct Broadcast {
    message: Vec<u8>,
    version: ListVersion,
    /// 1 / f, seconds.
    period: f64,
    /// End of the broadcast period (UTC seconds).
    until: f64,
    /// Next transmission (UTC seconds).
    next_tx: f64,
}

fn newer_or_same(received: &ListVersion, sent: &ListVersion) -> bool {
    if received.kind == ListKind::Crl {
        received.this_update.unwrap_or(0) >= sent.this_update.unwrap_or(0)
    } else {
        received.sequence.unwrap_or(0) >= sent.sequence.unwrap_or(0)
    }
}

struct Inner {
    trust: TrustStore,
    config: DistributionConfig,
    clock: PkiClock,
    btp: Option<BTPRouterHandle>,
    held: HashMap<Key, (Vec<u8>, ListVersion)>,
    broadcasts: HashMap<Key, Broadcast>,
    requests: Vec<Key>,
    rotation: usize,
    received: Vec<Vec<u8>>,
}

/// CRL / CTL distribution of the ITS-S (module documentation). Cloning gives
/// another handle on the same service.
#[derive(Clone)]
pub struct TrustListDistribution {
    inner: Arc<Mutex<Inner>>,
}

impl TrustListDistribution {
    /// The service on `trust` (system clock, no BTP router: see
    /// [`TrustListDistribution::with_btp`]).
    pub fn new(trust: TrustStore, config: DistributionConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                trust,
                config,
                clock: Arc::new(unix_time_secs),
                btp: None,
                held: HashMap::new(),
                broadcasts: HashMap::new(),
                requests: Vec::new(),
                rotation: 0,
                received: Vec::new(),
            })),
        }
    }

    /// Use `clock` (UTC seconds) instead of the system time.
    pub fn with_clock(self, clock: PkiClock) -> Self {
        self.lock().clock = clock;
        self
    }

    /// Send the broadcasts through `btp`.
    pub fn with_btp(self, btp: BTPRouterHandle) -> Self {
        self.lock().btp = Some(btp);
        self
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register the CTL and CRL ports (open to unsecured packets) on `btp`; the
    /// broadcasts received are queued for [`TrustListDistribution::process_received`].
    pub fn attach(&self, btp: &BTPRouterHandle) {
        self.lock().btp = Some(btp.clone());
        let (tx, rx) = mpsc::channel();
        btp.register_port_accepting_unsecured(CTL_PORT, tx.clone());
        btp.register_port_accepting_unsecured(CRL_PORT, tx);
        let service = self.clone();
        std::thread::spawn(move || {
            while let Ok(indication) = rx.recv() {
                service.queue_broadcast(indication.data);
            }
        });
    }

    /// Change the parameters.
    pub fn set_config(&self, config: DistributionConfig) {
        self.lock().config = config;
    }

    /// Read access to the trust store.
    pub fn with_trust<R>(&self, f: impl FnOnce(&TrustStore) -> R) -> R {
        f(&self.lock().trust)
    }

    /// The lists being broadcast.
    pub fn broadcasting(&self) -> Vec<(ListKind, [u8; 8])> {
        self.lock().broadcasts.keys().copied().collect()
    }

    /// Number of the broadcasts queued and not yet processed.
    pub fn queued(&self) -> usize {
        self.lock().received.len()
    }

    /// The pending P2P requests, in turn order.
    pub fn pending_requests(&self) -> Vec<(ListKind, [u8; 8])> {
        self.lock().requests.clone()
    }

    // ── reception ──────────────────────────────────────────────────────────

    /// Queue a CRL / CTL broadcast by a neighbour (payload of BTP port 2014 / 2015).
    pub fn queue_broadcast(&self, message: Vec<u8>) {
        self.lock().received.push(message);
    }

    /// Apply the queued broadcasts; the CA certificates revoked by them.
    pub fn process_received(
        &self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
    ) -> HashSet<[u8; 8]> {
        let queued = std::mem::take(&mut self.lock().received);
        let mut revoked = HashSet::new();
        for message in queued {
            if let Ok((_, r)) = self.receive(library, backend, &message, false) {
                revoked.extend(r);
            }
        }
        revoked
    }

    /// A CRL / CTL received from the DC (`from_dc`) or from a neighbour:
    /// verified, applied when it is new, then redistributed (case 1) or ending a
    /// broadcast of the same or an older version (clause 5.4.3). Its version and
    /// the CA certificates it revokes; an error for a list that does not verify.
    pub fn receive(
        &self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
        message: &[u8],
        from_dc: bool,
    ) -> Result<(ListVersion, HashSet<[u8; 8]>), TrustListError> {
        let mut inner = self.lock();
        let version = inner.trust.inspect(library, backend, message)?;
        let key = (version.kind, version.issuer);
        let (applied, revoked) = match inner.trust.process(library, backend, message) {
            Ok((_, revoked)) => (true, revoked),
            Err(e) if e.code == "outdated" || e.code == "outofsequence" => (false, HashSet::new()),
            Err(e) => return Err(e),
        };
        if !from_dc
            && inner
                .broadcasts
                .get(&key)
                .is_some_and(|current| newer_or_same(&version, &current.version))
        {
            inner.broadcasts.remove(&key);
        }
        if applied {
            inner.requests.retain(|k| *k != key);
            if !version.full {
                inner.held.insert(key, (message.to_vec(), version.clone()));
                if from_dc && inner.config.redistribute {
                    let (f1, d1) = (inner.config.f1, inner.config.d1);
                    inner.start(key, f1, d1);
                }
            }
        }
        Ok((version, revoked))
    }

    /// Download the due lists from the DC / CPOC and redistribute them; the URLs
    /// fetched and the CA certificates revoked.
    pub fn refresh(
        &self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
        transport: &dyn PkiTransport,
    ) -> (Vec<String>, HashSet<[u8; 8]>) {
        let urls = self.lock().trust.due_downloads();
        let mut revoked = HashSet::new();
        for url in &urls {
            if let Ok(message) = transport.get(url) {
                if let Ok((_, r)) = self.receive(library, backend, &message, true) {
                    revoked.extend(r);
                }
            }
        }
        (urls, revoked)
    }

    /// P2P requests in a verified message of a neighbour (clauses 5.3.6, 5.4.2).
    pub fn on_requests(&self, requests: &[TrustListRequest]) {
        let mut inner = self.lock();
        for request in requests {
            match request {
                TrustListRequest::Crl(r) => inner.answer_crl(
                    request.issuer(),
                    r.last_known_update.as_ref().map(|t| t.0 .0),
                ),
                TrustListRequest::DeltaCtl(r) => inner.answer_ctl(
                    request.issuer(),
                    r.last_known_ctl_sequence.as_ref().map(|s| s.0),
                ),
                TrustListRequest::FullCtl(_) => {}
            }
        }
    }

    /// The listener to set on the GN router / verify service.
    pub fn request_listener(&self) -> TrustListListener {
        let service = self.clone();
        Arc::new(move |requests: &[TrustListRequest], _at: &Certificate| {
            service.on_requests(requests)
        })
    }

    /// The provider to set on the sign service (`trust_list_request`).
    pub fn request_provider(&self) -> TrustListRequestProvider {
        let service = self.clone();
        Arc::new(move || service.next_request())
    }

    // ── requests ───────────────────────────────────────────────────────────

    /// Request the next CRL of the Root CA `issuer` (HashedId8) from the neighbours.
    pub fn request_crl(&self, issuer: [u8; 8]) {
        self.lock().request((ListKind::Crl, issuer));
    }

    /// Request the next Delta CTL of the TLM or Root CA `issuer` from the neighbours.
    pub fn request_ctl(&self, issuer: [u8; 8]) {
        self.lock().request_ctl(issuer);
    }

    /// The request to insert in the next CAM (one per CAM, in turn).
    pub fn next_request(&self) -> Option<TrustListRequest> {
        let mut inner = self.lock();
        if inner.requests.is_empty() {
            return None;
        }
        let key = inner.requests[inner.rotation % inner.requests.len()];
        inner.rotation += 1;
        let info = inner.trust.lists.get(&key);
        let issuer = HashedId8(FixedOctetString::from(key.1));
        Some(if key.0 == ListKind::Crl {
            TrustListRequest::Crl(EtsiTs102941CrlRequest::new(
                issuer,
                info.and_then(|i| i.this_update).map(|t| Time32(Uint32(t))),
            ))
        } else {
            TrustListRequest::DeltaCtl(EtsiTs102941CtlRequest::new(
                issuer,
                info.and_then(|i| i.sequence).map(Uint8),
            ))
        })
    }

    // ── timers ─────────────────────────────────────────────────────────────

    /// Send the broadcasts due, end the expired ones and start the requests due
    /// (to be called periodically).
    pub fn tick(&self) {
        let mut inner = self.lock();
        let now = (inner.clock)();
        let now32 = time32(now);
        let keys: Vec<Key> = inner.broadcasts.keys().copied().collect();
        for key in keys {
            let b = inner.broadcasts[&key].clone();
            if now >= b.until || now32 >= b.version.next_update {
                inner.broadcasts.remove(&key);
            } else if now >= b.next_tx {
                inner.send(key, &b.message);
                if let Some(b) = inner.broadcasts.get_mut(&key) {
                    b.next_tx = (b.next_tx + b.period).max(now);
                }
            }
        }
        let expired: Vec<Key> = inner
            .requests
            .iter()
            .copied()
            .filter(|key| {
                key.0 != ListKind::Crl
                    && inner
                        .trust
                        .lists
                        .get(key)
                        .is_some_and(|i| now32 >= i.next_update)
            })
            .collect();
        inner.requests.retain(|k| !expired.contains(k));
        let due: Vec<[u8; 8]> = inner
            .trust
            .lists
            .iter()
            .filter(|((kind, _), info)| *kind == ListKind::Crl && now32 >= info.next_update)
            .map(|((_, issuer), _)| *issuer)
            .collect();
        for issuer in due {
            inner.request((ListKind::Crl, issuer));
        }
    }
}

impl Inner {
    fn request(&mut self, key: Key) {
        if !self.requests.contains(&key) {
            self.requests.push(key);
        }
    }

    fn request_ctl(&mut self, issuer: [u8; 8]) {
        let kind = if self.trust.tlms.contains_key(&issuer) {
            ListKind::Ectl
        } else {
            ListKind::RcaCtl
        };
        self.request((kind, issuer));
    }

    fn answer_crl(&mut self, issuer: [u8; 8], last_known: Option<u32>) {
        let key = (ListKind::Crl, issuer);
        if let Some((_, v)) = self.held.get(&key) {
            if last_known.is_none_or(|t| v.this_update.unwrap_or(0) > t) {
                let (f2, d2) = (self.config.f2, self.config.d2);
                self.start(key, f2, d2);
            }
        }
    }

    fn answer_ctl(&mut self, issuer: [u8; 8], last_known: Option<u8>) {
        for kind in [ListKind::Ectl, ListKind::RcaCtl] {
            let key = (kind, issuer);
            if let Some((_, v)) = self.held.get(&key) {
                if last_known.is_none_or(|s| v.sequence.unwrap_or(0) > s) {
                    let (f2, d2) = (self.config.f2, self.config.d2);
                    self.start(key, f2, d2);
                }
            }
            let held_sequence = self.trust.lists.get(&key).map(|i| i.sequence.unwrap_or(0));
            if let (Some(held), Some(last)) = (held_sequence, last_known) {
                if last > held {
                    self.request_ctl(issuer); // the neighbour knows a newer CTL
                }
            }
        }
    }

    fn start(&mut self, key: Key, frequency: f64, duration: f64) {
        let Some((message, version)) = self.held.get(&key).cloned() else {
            return;
        };
        let now = (self.clock)();
        if self
            .broadcasts
            .get(&key)
            .is_some_and(|b| b.version == version && b.until >= now + duration)
        {
            return; // already broadcast for longer
        }
        self.broadcasts.insert(
            key,
            Broadcast {
                message: message.clone(),
                version,
                period: 1.0 / frequency,
                until: now + duration,
                next_tx: now + 1.0 / frequency,
            },
        );
        self.send(key, &message);
    }

    fn send(&self, key: Key, message: &[u8]) {
        let Some(btp) = &self.btp else {
            return;
        };
        let crl = key.0 == ListKind::Crl;
        btp.send_btp_data_request(BTPDataRequest {
            btp_type: CommonNH::BtpB,
            destination_port: if crl { CRL_PORT } else { CTL_PORT },
            gn_packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            },
            security_profile: SecurityProfile::Unsecured,
            its_aid: if crl { PSID_CRL } else { PSID_CTL },
            length: message.len() as u16,
            data: message.to_vec(),
            ..BTPDataRequest::new()
        });
    }
}

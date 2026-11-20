// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ETSI TS 103 525-2 V2.1.1 ITS-S test purposes of the request repetition
//! (clauses 5.2.2.3 and 5.2.3.3, ETSI TS 103 601 clauses 5.1 / 5.2) and of the
//! P2P CTL / CRL distribution (clauses 5.2.5 and 5.2.7, ETSI TS 103 601 clauses
//! 5.3 / 5.4), one test per TP (an ID the standard defines twice has one test
//! covering both). Mirrors the same TPs of FlexStack `test_pki_conformance.py`.

use std::sync::Arc;

use super::client::PkiState;
use super::conformance::{Iut, TrustWorld};
use super::distribution::{DistributionConfig, TrustListDistribution, CRL_PORT, CTL_PORT};
use super::messages::time32;
use super::transport::RetryPolicy;
use super::trust_lists::{ListInfo, ListKind, TrustListError};
use crate::btp::service_access_point::BTPDataRequest;
use crate::geonet::service_access_point::{
    CommonNH, HeaderSubType, HeaderType, PacketTransportType, TopoBroadcastHST,
};
use crate::security::conformance::Station;
use crate::security::header_extensions::{decode_requests, TrustListRequest};
use crate::security::pki_asn::decode;
use crate::security::pki_asn::etsi_ts102941_messages_itss::{
    EtsiTs102941Data, EtsiTs102941DataContent,
};
use crate::security::security_asn::etsi_ts103097_extension_module::{
    EtsiTs102941CrlRequest, EtsiTs102941CtlRequest,
};
use crate::security::security_asn::ieee1609_dot2::{Ieee1609Dot2Content, Ieee1609Dot2Data};
use crate::security::security_asn::ieee1609_dot2_base_types::{HashedId8, Time32, Uint32, Uint8};
use crate::security::sn_sap::SecurityProfile;
use rasn::prelude::FixedOctetString;

// ─── Request repetition ────────────────────────────────────────────────────

const TH1: f64 = 10.0;
const N1: u32 = 3;
const TH2: f64 = 100.0;

/// The IUT with the repetition of TS 103 601 clauses 5.1 / 5.2
/// (PIXIT_*_TIMEOUT_TH1 = 10 s, PIXIT_*_MAX_N1 = 3, PIXIT_*_TIMEOUT_TH2 = 100 s);
/// waiting advances its clock and the transport records the instant of every POST.
fn retry_iut(th1: f64, n1: u32, th2: f64) -> Iut {
    let mut iut = Iut::new();
    let policy = RetryPolicy { th1, n1, th2 };
    iut.client.enrolment_retry = Some(policy);
    iut.client.authorization_retry = Some(policy);
    let n = Arc::clone(&iut.now);
    *iut.transport.clock.lock().unwrap() = Some(Arc::new(move || *n.lock().unwrap()));
    let n = Arc::clone(&iut.now);
    iut.client.sleep = Arc::new(move |s| *n.lock().unwrap() += s);
    iut
}

fn now(iut: &Iut) -> f64 {
    *iut.now.lock().unwrap()
}

fn posts_to(iut: &Iut, url: &str) -> Vec<(f64, Vec<u8>)> {
    let times = iut.transport.times.lock().unwrap().clone();
    let posts = iut.transport.posts.lock().unwrap().clone();
    times
        .into_iter()
        .zip(posts)
        .filter(|(_, (u, _, _))| u == url)
        .map(|(t, (_, body, _))| (t, body))
        .collect()
}

fn lose(iut: &Iut, n: u32) {
    *iut.transport.lose.lock().unwrap() = n;
}

fn instants(posts: &[(f64, Vec<u8>)]) -> Vec<f64> {
    posts.iter().map(|(t, _)| *t).collect()
}

/// SECPKI_ITS-S_ENR_REP_01_BV: the Enrolment Response to the request sent at T1
/// is not received: at T1 + PIXIT_ENR_TIMEOUT_TH1 the IUT sends an
/// EnrolmentRequestMessage to the EA.
#[test]
fn tp_secpki_its_s_enr_rep_01_bv() {
    let mut iut = retry_iut(TH1, N1, TH2);
    lose(&iut, 1);
    let t1 = now(&iut);
    iut.enrol().unwrap();
    let ea = iut.transport.ea_url.clone();
    assert_eq!(instants(&posts_to(&iut, &ea)), vec![t1, t1 + TH1]);
}

/// SECPKI_ITS-S_ENR_REP_02_BV: the re-sent Enrolment Request is the message M
/// sent first (same encrypted message, hence the same AES key k, clause 5.1.2).
#[test]
fn tp_secpki_its_s_enr_rep_02_bv() {
    let mut iut = retry_iut(TH1, N1, TH2);
    lose(&iut, 1);
    let ec = iut.enrol().unwrap();
    let ea = iut.transport.ea_url.clone();
    let posts = posts_to(&iut, &ea);
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[1].1, posts[0].1);
    assert_eq!(iut.pki().enrolments.len(), 1); // one request M
    assert_eq!(iut.client.ec().unwrap().as_hashedid8(), ec.as_hashedid8());
}

/// SECPKI_ITS-S_ENR_REP_03_BV: having sent the Enrolment Request more than once,
/// the IUT receives the Enrolment Response and stops sending Enrolment Requests.
#[test]
fn tp_secpki_its_s_enr_rep_03_bv() {
    let mut iut = retry_iut(TH1, N1, TH2);
    lose(&iut, 2);
    iut.enrol().unwrap();
    let ea = iut.transport.ea_url.clone();
    assert_eq!(posts_to(&iut, &ea).len(), 3);
    assert_eq!(iut.client.state(), PkiState::Enrolled);
    iut.advance(10.0 * TH1); // no repetition left
    assert_eq!(iut.transport.posts.lock().unwrap().len(), 3);
}

/// SECPKI_ITS-S_ENR_REP_04_BV: after PIXIT_ENR_MAX_N1 Enrolment Request messages
/// the IUT stops sending Enrolment Requests (and gives up the request).
#[test]
fn tp_secpki_its_s_enr_rep_04_bv() {
    let mut iut = retry_iut(TH1, N1, TH2);
    lose(&iut, 99);
    assert!(iut.enrol().is_err());
    let ea = iut.transport.ea_url.clone();
    let posts = posts_to(&iut, &ea);
    assert_eq!(posts.len() as u32, N1);
    assert!(posts.iter().all(|(_, m)| *m == posts[0].1));
    assert_eq!(iut.client.state(), PkiState::Initialized);
}

/// SECPKI_ITS-S_ENR_REP_05_BV (both TPs of this ID): the IUT stops sending the
/// Enrolment Request when the local time reaches T1 + PIXIT_ENR_TIMEOUT_TH2 (TH2
/// = 25 s, TH1 = 10 s, N1 = 10: transmissions at T1, T1 + 10 and T1 + 20 only).
#[test]
fn tp_secpki_its_s_enr_rep_05_bv() {
    let mut iut = retry_iut(10.0, 10, 25.0);
    lose(&iut, 99);
    let t1 = now(&iut);
    assert!(iut.enrol().is_err());
    let ea = iut.transport.ea_url.clone();
    assert_eq!(
        instants(&posts_to(&iut, &ea)),
        vec![t1, t1 + 10.0, t1 + 20.0]
    );
}

fn enrolled(lose_n: u32) -> Iut {
    let mut iut = retry_iut(TH1, N1, TH2);
    iut.enrol().unwrap();
    lose(&iut, lose_n);
    iut
}

/// SECPKI_ITS-S_AUTH_REP_01_BV: the Authorization Response to the request sent at
/// T1 is not received: at T1 + PIXIT_AUTH_TIMEOUT_TH1 the IUT sends an
/// AuthorizationRequestMessage (to the AA; the TP text says EA).
#[test]
fn tp_secpki_its_s_auth_rep_01_bv() {
    let mut iut = enrolled(1);
    let t1 = now(&iut);
    iut.authorize().unwrap();
    let aa = iut.transport.aa_url.clone();
    assert_eq!(instants(&posts_to(&iut, &aa)), vec![t1, t1 + TH1]);
}

/// SECPKI_ITS-S_AUTH_REP_02_BV: the re-sent AuthorizationRequestMessage is the
/// message M sent first to the AA.
#[test]
fn tp_secpki_its_s_auth_rep_02_bv() {
    let mut iut = enrolled(1);
    iut.authorize().unwrap();
    let aa = iut.transport.aa_url.clone();
    let posts = posts_to(&iut, &aa);
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[1].1, posts[0].1);
    assert_eq!(iut.pki().authorizations.len(), 1);
}

/// SECPKI_ITS-S_AUTH_REP_03_BV: having sent the Authorization Request more than
/// once, the IUT receives the Authorization Response and stops sending requests.
#[test]
fn tp_secpki_its_s_auth_rep_03_bv() {
    let mut iut = enrolled(2);
    iut.authorize().unwrap();
    let aa = iut.transport.aa_url.clone();
    assert_eq!(posts_to(&iut, &aa).len(), 3);
    assert_eq!(iut.client.state(), PkiState::Authorized);
}

/// SECPKI_ITS-S_AUTH_REP_04_BV: after PIXIT_AUTH_MAX_N1 Authorization Request
/// messages the IUT stops sending Authorization Requests.
#[test]
fn tp_secpki_its_s_auth_rep_04_bv() {
    let mut iut = enrolled(99);
    assert!(iut.authorize().is_err());
    let aa = iut.transport.aa_url.clone();
    assert_eq!(posts_to(&iut, &aa).len() as u32, N1);
    assert_eq!(iut.client.state(), PkiState::Enrolled);
}

/// SECPKI_ITS-S_AUTH_REP_05_BV: the IUT stops sending the Authorization Request
/// when the local time reaches T1 + PIXIT_AUTH_TIMEOUT_TH2 (TH2 = 25 s, TH1 =
/// 10 s, N1 = 10).
#[test]
fn tp_secpki_its_s_auth_rep_05_bv() {
    let mut iut = retry_iut(10.0, 10, 25.0);
    iut.enrol().unwrap();
    lose(&iut, 99);
    let t1 = now(&iut);
    assert!(iut.authorize().is_err());
    let aa = iut.transport.aa_url.clone();
    assert_eq!(
        instants(&posts_to(&iut, &aa)),
        vec![t1, t1 + 10.0, t1 + 20.0]
    );
}

// ─── CTL and CRL distribution ──────────────────────────────────────────────

const D1: f64 = 60.0;
const D2: f64 = 10.0;
const D1_MS: u64 = 60_000;
const D2_MS: u64 = 10_000;

type Frame = (u64, u16, Vec<u8>);

/// The unsecured SHB of `station` sent at or after `since_ms`: (ms, BTP-B
/// destination port, payload). Basic Header NH = 1 (low nibble of octet 0),
/// Common Header HT / HST = TSB / single hop (octet 5 = 0x50); Basic (4) +
/// Common (8) + SHB (28) + BTP-B (4) headers.
pub(super) fn frames(station: &Station, since_ms: u64) -> Vec<Frame> {
    station
        .log
        .iter()
        .filter(|(ms, raw)| *ms >= since_ms && raw[0] & 0x0F == 1 && raw[5] == 0x50)
        .map(|(ms, raw)| {
            (
                *ms,
                u16::from_be_bytes([raw[40], raw[41]]),
                raw[44..].to_vec(),
            )
        })
        .collect()
}

fn payloads(station: &Station) -> Vec<Vec<u8>> {
    frames(station, 0).into_iter().map(|(_, _, p)| p).collect()
}

/// The IUT with the CRL / CTL distribution service (PIXIT D1 = 60 s, D2 = 10 s,
/// f1 = f2 = 1 Hz) on its BTP, sign service and GN router.
pub(super) struct CxlIut {
    pub(super) station: Station,
    pub(super) cxl: TrustListDistribution,
}

pub(super) fn cxl_iut(w: &mut TrustWorld, redistribute: bool) -> CxlIut {
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    let (mut station, store) = w.iut(&[&rca], &[&aa]);
    station.open_trust_list_ports();
    let c = w.clock.clone();
    let cxl = TrustListDistribution::new(
        store,
        DistributionConfig {
            redistribute,
            d1: D1,
            d2: D2,
            ..Default::default()
        },
    )
    .with_clock(Arc::new(move || c.unix_ms() as f64 / 1000.0))
    .with_btp(station.btp.clone());
    station.gn.set_trust_list_listener(cxl.request_listener());
    station.gn.sign_service_mut().unwrap().trust_list_request = Some(cxl.request_provider());
    CxlIut { station, cxl }
}

impl CxlIut {
    pub(super) fn receive(&mut self, w: &TrustWorld, message: &[u8]) -> Result<(), TrustListError> {
        let backend = w.backend.clone();
        let library = self.station.gn.verify_library_mut().unwrap();
        let result = self.cxl.receive(library, &backend, message, true);
        self.station.flush_btp();
        result.map(|_| ())
    }

    pub(super) fn tick(&mut self) {
        self.cxl.tick();
        self.station.flush_btp();
    }

    /// Advance the clock to `until_ms` in steps, running the distribution timers.
    pub(super) fn run(&mut self, w: &TrustWorld, until_ms: u64, step_ms: u64) {
        let mut t = w.clock.ms() + step_ms;
        while t <= until_ms {
            w.clock.set(t);
            self.tick();
            t += step_ms;
        }
    }

    /// A frame from the radio; the lists received on the CTL / CRL ports are
    /// handed to the distribution service.
    pub(super) fn deliver(&mut self, w: &TrustWorld, raw: &[u8], at_ms: u64) {
        self.station.deliver(raw, at_ms);
        for message in std::mem::take(&mut self.station.trust_lists) {
            self.cxl.queue_broadcast(message);
        }
        let backend = w.backend.clone();
        self.cxl
            .process_received(self.station.gn.verify_library_mut().unwrap(), &backend);
        self.station.flush_btp();
    }

    pub(super) fn info(&self, key: (ListKind, [u8; 8])) -> Option<ListInfo> {
        self.cxl.with_trust(|t| t.lists.get(&key).cloned())
    }

    /// The ETSI originating header extensions of the next CAM of the IUT.
    pub(super) fn requests_in_cam(&mut self, at_ms: u64) -> Vec<TrustListRequest> {
        let cam = self.station.cam_sent(at_ms);
        match cam.sd.tbs_data.header_info.contributed_extensions {
            None => vec![],
            Some(blocks) => {
                assert!(blocks.0.iter().all(|b| b.contributor_id.0 == 2));
                decode_requests(&blocks)
            }
        }
    }
}

/// A neighbour broadcasts `message` (unsecured SHB) and the IUT receives it.
pub(super) fn neighbour_broadcast(w: &mut TrustWorld, iut: &mut CxlIut, message: &[u8], port: u16) {
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    let mut neighbour = w.tester(&aa, &rca, 9);
    neighbour.btp.send_btp_data_request(BTPDataRequest {
        btp_type: CommonNH::BtpB,
        destination_port: port,
        gn_packet_transport_type: PacketTransportType {
            header_type: HeaderType::Tsb,
            header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
        },
        security_profile: SecurityProfile::Unsecured,
        length: message.len() as u16,
        data: message.to_vec(),
        ..BTPDataRequest::new()
    });
    neighbour.flush_btp();
    let raw = neighbour.log.last().unwrap().1.clone();
    let at = w.clock.ms();
    iut.deliver(w, &raw, at);
}

/// A neighbour's CAM carrying the P2P request `request`, received by the IUT.
pub(super) fn neighbour_request(
    w: &mut TrustWorld,
    iut: &mut CxlIut,
    request: TrustListRequest,
    at_ms: u64,
) {
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    let mut neighbour = w.tester(&aa, &rca, 9);
    neighbour.gn.sign_service_mut().unwrap().trust_list_request =
        Some(Arc::new(move || Some(request.clone())));
    let raw = neighbour.certificate_cam(at_ms).raw;
    let before = iut.station.cams;
    iut.deliver(w, &raw, at_ms);
    assert_eq!(iut.station.cams, before + 1);
}

pub(super) fn h8(h: [u8; 8]) -> HashedId8 {
    HashedId8(FixedOctetString::from(h))
}

pub(super) fn crl_request(issuer: [u8; 8], last: Option<u32>) -> TrustListRequest {
    TrustListRequest::Crl(EtsiTs102941CrlRequest::new(
        h8(issuer),
        last.map(|t| Time32(Uint32(t))),
    ))
}

pub(super) fn ctl_request(issuer: [u8; 8], last: Option<u8>) -> TrustListRequest {
    TrustListRequest::DeltaCtl(EtsiTs102941CtlRequest::new(h8(issuer), last.map(Uint8)))
}

const KINDS: [ListKind; 2] = [ListKind::Ectl, ListKind::RcaCtl];

pub(super) fn delta(w: &mut TrustWorld, kind: ListKind) -> Vec<u8> {
    if kind == ListKind::Ectl {
        w.ectl_of(&[], 3600, false)
    } else {
        let rca = w.rca.clone();
        w.rca_ctl_of(&rca, &[], 3600, false)
    }
}

fn full(w: &mut TrustWorld, kind: ListKind) -> Vec<u8> {
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    if kind == ListKind::Ectl {
        w.ectl(&[&rca], 3600)
    } else {
        w.rca_ctl(&rca, &[&aa], 3600)
    }
}

fn issuer(w: &TrustWorld, kind: ListKind) -> [u8; 8] {
    if kind == ListKind::Ectl {
        w.tlm.as_hashedid8()
    } else {
        w.rca.as_hashedid8()
    }
}

fn etsi_content(message: &[u8]) -> EtsiTs102941DataContent {
    let data: Ieee1609Dot2Data = decode(message).unwrap();
    let Ieee1609Dot2Content::signedData(signed) = data.content else {
        panic!("signed list")
    };
    let Some(Ieee1609Dot2Content::unsecuredData(payload)) =
        signed.tbs_data.payload.data.map(|d| d.content)
    else {
        panic!("payload")
    };
    let etsi: EtsiTs102941Data = decode(payload.0.as_ref()).unwrap();
    etsi.content
}

/// SECPKI_ITS-S_CTLDIST_01_BV: the IUT without CTL information receives a Delta
/// CTL (from its DC) and starts broadcasting it (ECTL and Root CA CTL).
#[test]
fn tp_secpki_its_s_ctldist_01_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        assert!(iut.cxl.with_trust(|t| t.lists.is_empty()));
        let d = delta(&mut w, kind);
        iut.receive(&w, &d).unwrap();
        assert_eq!(payloads(&iut.station), vec![d], "{kind:?}");
    }
}

/// SECPKI_ITS-S_CTLDIST_02_BV: the IUT holding a CTL with ctlSequence SN receives
/// a Delta CTL with a greater ctlSequence and starts broadcasting it.
#[test]
fn tp_secpki_its_s_ctldist_02_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let f = full(&mut w, kind);
        iut.receive(&w, &f).unwrap(); // SN = 0 (full: not broadcast)
        assert!(frames(&iut.station, 0).is_empty());
        let d = delta(&mut w, kind);
        iut.receive(&w, &d).unwrap(); // ctlSequence 1 > SN
        assert_eq!(
            iut.info((kind, issuer(&w, kind))).unwrap().sequence,
            Some(1)
        );
        assert_eq!(payloads(&iut.station), vec![d], "{kind:?}");
    }
}

/// SECPKI_ITS-S_CTLDIST_03_BV: the Delta CTL (A: TlmCertificateTrustListMessage,
/// B: RcaCertificateTrustListMessage) is broadcast with BTP port 2014 (unsecured SHB).
#[test]
fn tp_secpki_its_s_ctldist_03_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let d = delta(&mut w, kind);
        iut.receive(&w, &d).unwrap();
        iut.run(&w, 3000, 100);
        let sent = frames(&iut.station, 0);
        assert!(sent.len() >= 3); // f1 = 1 Hz
        for (_, port, payload) in sent {
            assert_eq!(port, 2014);
            match (kind, etsi_content(&payload)) {
                (ListKind::Ectl, EtsiTs102941DataContent::certificateTrustListTlm(c))
                | (ListKind::RcaCtl, EtsiTs102941DataContent::certificateTrustListRca(c)) => {
                    assert!(!c.is_full_ctl)
                }
                _ => panic!("{kind:?}: unexpected content"),
            }
        }
    }
}

/// SECPKI_ITS-S_CTLDIST_04_BV: the IUT broadcasting the Delta CTL (SN) signed with
/// CERT_TLM / CERT_IUT_A_RCA stops when it receives that Delta CTL with a
/// ctlSequence equal to or higher than SN from another ITS-S.
#[test]
fn tp_secpki_its_s_ctldist_04_bv() {
    for kind in KINDS {
        for higher in [false, true] {
            let mut w = TrustWorld::new();
            let mut iut = cxl_iut(&mut w, true);
            let d = delta(&mut w, kind);
            iut.receive(&w, &d).unwrap();
            iut.run(&w, 2000, 100);
            let other = if higher {
                delta(&mut w, kind)
            } else {
                d.clone()
            };
            neighbour_broadcast(&mut w, &mut iut, &other, CTL_PORT);
            let stopped = w.clock.ms();
            iut.run(&w, 6000, 100);
            assert!(
                frames(&iut.station, stopped + 1).is_empty(),
                "{kind:?} {higher}"
            );
        }
    }
}

/// SECPKI_ITS-S_CTLDIST_05_BV: the IUT without CTL information for CERT,
/// requested to get it, sends secured messages with an ETSI contributed extension
/// (contributorId 2) EtsiTs102941CtlRequest with issuerId = HashedId8(CERT),
/// without lastKnownCtlSequence.
#[test]
fn tp_secpki_its_s_ctldist_05_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        iut.cxl.request_ctl(issuer(&w, kind));
        let expected = vec![ctl_request(issuer(&w, kind), None)];
        assert_eq!(iut.requests_in_cam(0), expected);
        assert_eq!(iut.requests_in_cam(1000), expected);
    }
}

/// SECPKI_ITS-S_CTLDIST_06_BV: the IUT holding the CTL of CERT with ctlSequence
/// SN, requested to get the CTL information, sends the EtsiTs102941CtlRequest with
/// issuerId = HashedId8(CERT) and lastKnownCtlSequence = SN.
#[test]
fn tp_secpki_its_s_ctldist_06_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let f = full(&mut w, kind);
        iut.receive(&w, &f).unwrap();
        let d = delta(&mut w, kind);
        iut.receive(&w, &d).unwrap(); // SN = 1
        iut.cxl.request_ctl(issuer(&w, kind));
        assert_eq!(
            iut.requests_in_cam(0),
            vec![ctl_request(issuer(&w, kind), Some(1))]
        );
    }
}

/// SECPKI_ITS-S_CTLDIST_07_BV: the IUT holding the CTL of CERT (SN) receives a
/// secured message whose EtsiTs102941CtlRequest for CERT has a
/// lastKnownCtlSequence higher than SN: it starts sending requests with
/// lastKnownCtlSequence = SN.
#[test]
fn tp_secpki_its_s_ctldist_07_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let f = full(&mut w, kind);
        iut.receive(&w, &f).unwrap();
        assert!(iut.requests_in_cam(0).is_empty());
        let h = issuer(&w, kind);
        neighbour_request(&mut w, &mut iut, ctl_request(h, Some(3)), 500);
        assert_eq!(iut.requests_in_cam(1000), vec![ctl_request(h, Some(0))]);
    }
}

/// SECPKI_ITS-S_CTLDIST_08_BV: the IUT holding a Delta CTL M (SN) signed with
/// CERT receives a secured message whose EtsiTs102941CtlRequest for CERT has a
/// lastKnownCtlSequence lower than SN: it starts broadcasting M.
#[test]
fn tp_secpki_its_s_ctldist_08_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, false);
        let f = full(&mut w, kind);
        iut.receive(&w, &f).unwrap();
        let m = delta(&mut w, kind); // SN = 1
        iut.receive(&w, &m).unwrap();
        assert!(frames(&iut.station, 0).is_empty()); // not redistributed (PIXIT)
        let h = issuer(&w, kind);
        neighbour_request(&mut w, &mut iut, ctl_request(h, Some(0)), 500);
        let sent: Vec<(u16, Vec<u8>)> = frames(&iut.station, 0)
            .into_iter()
            .map(|(_, p, d)| (p, d))
            .collect();
        assert_eq!(sent, vec![(CTL_PORT, m)], "{kind:?}");
    }
}

/// SECPKI_ITS-S_CTLDIST_09_BV: the IUT broadcasting a Delta CTL started at T stops
/// broadcasting it at T + D1 (PIXIT D1 = 60 s).
#[test]
fn tp_secpki_its_s_ctldist_09_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let d = delta(&mut w, kind);
        iut.receive(&w, &d).unwrap(); // T = 0
        iut.run(&w, D1_MS - 100, 100);
        assert!(!frames(&iut.station, D1_MS - 1500).is_empty()); // still broadcasting
        iut.run(&w, D1_MS + 5000, 100);
        assert!(frames(&iut.station, D1_MS).is_empty());
        assert_eq!(frames(&iut.station, 0).len(), D1 as usize); // 1 Hz during D1
    }
}

/// SECPKI_ITS-S_CTLDIST_10_BV: the IUT broadcasting the requested Delta CTL,
/// started at T, stops broadcasting it at T + D2 (PIXIT D2 = 10 s).
#[test]
fn tp_secpki_its_s_ctldist_10_bv() {
    for kind in KINDS {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, false);
        let d = delta(&mut w, kind);
        iut.receive(&w, &d).unwrap();
        let h = issuer(&w, kind);
        neighbour_request(&mut w, &mut iut, ctl_request(h, None), 0); // T = 0
        iut.run(&w, D2_MS + 5000, 100);
        assert!(frames(&iut.station, D2_MS).is_empty());
        assert_eq!(frames(&iut.station, 0).len(), D2 as usize);
    }
}

/// SECPKI_ITS-S_CRLDIST_01_BV: the IUT, with CERT_IUT_A_RCA and no CRL of it yet,
/// receives the CRL (thisUpdate T, nextUpdate N) from the DC and starts
/// broadcasting it.
#[test]
fn tp_secpki_its_s_crldist_01_bv() {
    let mut w = TrustWorld::new();
    let mut iut = cxl_iut(&mut w, true);
    let rca = w.rca.clone();
    let crl = w.crl(&rca, &[], 0);
    iut.receive(&w, &crl).unwrap();
    assert_eq!(payloads(&iut.station), vec![crl]);
}

/// SECPKI_ITS-S_CRLDIST_02_BV (both TPs of this ID): the
/// CertificateRevocationListMessage is broadcast with BTP port 2015; received
/// from the DC at T, its broadcast stops at T + D1 (PIXIT D1 = 60 s).
#[test]
fn tp_secpki_its_s_crldist_02_bv() {
    let mut w = TrustWorld::new();
    let mut iut = cxl_iut(&mut w, true);
    let rca = w.rca.clone();
    let crl = w.crl(&rca, &[], 0);
    iut.receive(&w, &crl).unwrap(); // T = 0
    iut.run(&w, D1_MS + 5000, 100);
    let sent = frames(&iut.station, 0);
    assert!(sent
        .iter()
        .all(|(_, port, p)| *port == CRL_PORT && *p == crl));
    assert!(matches!(
        etsi_content(&crl),
        EtsiTs102941DataContent::certificateRevocationList(_)
    ));
    assert!(frames(&iut.station, D1_MS).is_empty());
    assert_eq!(sent.len(), D1 as usize);
}

/// SECPKI_ITS-S_CRLDIST_03_BV: the IUT broadcasting the CRL from the DC
/// (nextUpdate N) stops when its time reaches N (D1 = 1 week, N = thisUpdate +
/// 1 hour).
#[test]
fn tp_secpki_its_s_crldist_03_bv() {
    let mut w = TrustWorld::new();
    let mut iut = cxl_iut(&mut w, true);
    iut.cxl.set_config(DistributionConfig::default()); // D1 = 1 week
    let rca = w.rca.clone();
    let crl = w.crl(&rca, &[], 0);
    iut.receive(&w, &crl).unwrap();
    let next = iut
        .info((ListKind::Crl, rca.as_hashedid8()))
        .unwrap()
        .next_update;
    let n_ms = (next - time32(w.clock.base_ms as f64 / 1000.0)) as u64 * 1000;
    iut.run(&w, n_ms - 2000, 1000);
    assert!(!frames(&iut.station, n_ms - 3000).is_empty());
    iut.run(&w, n_ms + 10_000, 1000);
    assert!(frames(&iut.station, n_ms + 1000).is_empty());
}

/// SECPKI_ITS-S_CRLDIST_04_BV (both TPs of this ID): (1) the IUT broadcasting the
/// CRL (thisUpdate T) stops when it receives the CRL of CERT_IUT_A_RCA with
/// thisUpdate equal to or greater than T from another station; (2) the IUT that
/// never received a CRL of CERT_IUT_A_RCA, requested to get it, sends
/// EtsiTs102941CrlRequest with issuerId = HashedId8(CERT_IUT_A_RCA) and without
/// lastKnownUpdate.
#[test]
fn tp_secpki_its_s_crldist_04_bv() {
    for greater in [false, true] {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let rca = w.rca.clone();
        let crl = w.crl(&rca, &[], 0);
        iut.receive(&w, &crl).unwrap();
        iut.run(&w, 2000, 100);
        let other = if greater {
            w.crl(&rca, &[], 5)
        } else {
            crl.clone()
        };
        neighbour_broadcast(&mut w, &mut iut, &other, CRL_PORT);
        let stopped = w.clock.ms();
        iut.run(&w, 6000, 100);
        assert!(frames(&iut.station, stopped + 1).is_empty(), "{greater}");
    }
    let mut w = TrustWorld::new();
    let mut iut = cxl_iut(&mut w, true);
    iut.cxl.request_crl(w.rca.as_hashedid8());
    assert_eq!(
        iut.requests_in_cam(0),
        vec![crl_request(w.rca.as_hashedid8(), None)]
    );
}

/// SECPKI_ITS-S_CRLDIST_05_BV: the IUT that received the CRL of CERT_IUT_A_RCA
/// (thisUpdate T), requested to get the CRL, sends EtsiTs102941CrlRequest with
/// issuerId = HashedId8(CERT_IUT_A_RCA) and lastKnownUpdate = T.
#[test]
fn tp_secpki_its_s_crldist_05_bv() {
    let mut w = TrustWorld::new();
    let mut iut = cxl_iut(&mut w, true);
    let rca = w.rca.clone();
    let crl = w.crl(&rca, &[], 0);
    iut.receive(&w, &crl).unwrap();
    let t = iut
        .info((ListKind::Crl, rca.as_hashedid8()))
        .unwrap()
        .this_update;
    iut.cxl.request_crl(rca.as_hashedid8());
    assert_eq!(
        iut.requests_in_cam(0),
        vec![crl_request(rca.as_hashedid8(), t)]
    );
}

/// SECPKI_ITS-S_CRLDIST_06_BV (both TPs of this ID): the IUT holding the CRL, no
/// longer broadcasting it, receives a CRL request without lastKnownUpdate (at T):
/// it starts broadcasting the CRL and stops at T + D2 (PIXIT D2 = 10 s; the second
/// TP text says D1).
#[test]
fn tp_secpki_its_s_crldist_06_bv() {
    let mut w = TrustWorld::new();
    let mut iut = cxl_iut(&mut w, true);
    let rca = w.rca.clone();
    let crl = w.crl(&rca, &[], 0);
    iut.receive(&w, &crl).unwrap();
    iut.run(&w, D1_MS + 1000, 100); // D1 elapsed: stopped
    let t_ms = D1_MS + 2000;
    assert!(frames(&iut.station, D1_MS).is_empty());
    neighbour_request(
        &mut w,
        &mut iut,
        crl_request(rca.as_hashedid8(), None),
        t_ms,
    );
    iut.run(&w, t_ms + D2_MS + 5000, 100);
    let sent = frames(&iut.station, t_ms);
    assert!(sent
        .iter()
        .all(|(_, port, p)| *port == CRL_PORT && *p == crl));
    assert_eq!(sent.len(), D2 as usize);
    assert!(frames(&iut.station, t_ms + D2_MS).is_empty());
}

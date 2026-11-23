// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ITS-S PKI conformance tests: one test per Test Purpose of ETSI TS 103 525-2
//! V2.1.1 clause 5.2 (IUT = ITS-S), against ETSI TS 102 941 V2.2.1.
//!
//! Each test is named after its TP and quotes the TP identifier. A TP with
//! variants is one test covering every variant.
//!
//! Enrolment and authorization (CFG_ENR_ITS-S, CFG_AUTH_ITS-S): the IUT is a
//! [`PkiClient`] on an injected clock; the EA and AA are the test system of
//! [`super::ts_pki`] (written independently of the client), reached through an
//! in-memory transport. The tests look at what the EA / AA received,
//! decrypted and decoded with the official ASN.1, and at the IUT state.
//!
//! CTL and CRL handling (CFG_CXL_P2P): the IUT is a complete station (CA basic
//! service on BTP on a secured GeoNetworking router) whose trust information is
//! updated by a [`TrustStore`]; the test system signs ECTLs, Root CA CTLs,
//! CRLs and CAMs. CRL handling of the own certificates uses the PkiClient.
//!
//! Not covered here: the repetition TPs (ETSI TS 103 601), the CTL/CRL
//! distribution TPs (ETSI TS 103 601), butterfly authorization (optional,
//! PICS_SECPKI_AUTH_BFK, not implemented) and SECPKI_ITS-S_AUTH_16_BV
//! (ecSignature not encrypted: the official ASN.1 requires
//! encryptedEcSignature).
//!
//! Mirrors `tests/flexstack/security/pki_client/test_pki_conformance.py`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use rasn::prelude::*;
use sha2::{Digest, Sha256};

use super::client::{PkiClient, PkiError, PkiState};
use super::trust_lists::{ListKind, TrustStore};
use super::ts_pki::{
    psid_ssp, root_permissions, signed_data, signed_ok, unsecured, Received, Transport, TsPki,
    PSID_CERT_REQUEST, PSID_CRL, PSID_CTL,
};
use crate::security::certificate::{
    encode_ieee1609_dot2_data, encode_tbs_data, Certificate, OwnCertificate,
};
use crate::security::conformance::{
    app_permissions, at_tbs as station_at_tbs, psid_ssps, resign, Clock, Options, Pki, Station,
    TS_ID,
};
use crate::security::ecdsa_backend::{EcdsaBackend, KeyAlgorithm};
use crate::security::pki_asn::encode;
use crate::security::pki_asn::etsi_ts102941_base_types::EcSignature;
use crate::security::pki_asn::etsi_ts102941_messages_itss::{
    EtsiTs102941Data, EtsiTs102941DataContent,
};
use crate::security::pki_asn::etsi_ts102941_trust_lists::{
    AaEntry, CtlCommand, CtlEntry, CtlFormat, DcEntry, RootCaEntry, TlmEntry, ToBeSignedCrl,
};
use crate::security::pki_asn::etsi_ts102941_types_enrolment::{
    EnrolmentResponseCode, InnerEcRequest,
};
use crate::security::pki_client::messages::time32;
use crate::security::security_asn::ieee1609_dot2::{
    EncryptedDataEncryptionKey, HashedData, HeaderInfo, Ieee1609Dot2Content, Ieee1609Dot2Data,
    RecipientInfo, SignedData, SignedDataPayload, SignerIdentifier, ToBeSignedData,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    Duration as AsnDuration, HashAlgorithm, HashedId8, Opaque, Psid, SequenceOfPsidSsp,
    ServiceSpecificPermissions, Time32, Time64, Uint16, Uint32, Uint64, Uint8,
};
use crate::security::verify_service::security_checks::ca_tbs;

pub(super) const ITS_ID: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

pub(super) fn temp_dir() -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "rustflexstack-pki-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ))
}

/// The IUT (PkiClient) with the test system EA / AA and a clock of its own.
pub(super) struct Iut {
    pub(super) pki: Arc<Mutex<TsPki>>,
    pub(super) transport: Transport,
    pub(super) client: PkiClient,
    pub(super) now: Arc<Mutex<f64>>,
}

impl Iut {
    pub(super) fn new() -> Iut {
        Iut::with(true)
    }

    pub(super) fn with(pop: bool) -> Iut {
        let pki = Arc::new(Mutex::new(TsPki::new()));
        let transport = Transport::new(Arc::clone(&pki));
        let now = Arc::new(Mutex::new(Clock::new().unix_ms() as f64 / 1000.0));
        let (ea, aa, root) = {
            let p = pki.lock().unwrap();
            (
                p.ea.own.cert.clone(),
                p.aa.own.cert.clone(),
                p.root.cert.clone(),
            )
        };
        let n = Arc::clone(&now);
        let mut client = PkiClient::new(
            transport.ea_url.clone(),
            transport.aa_url.clone(),
            ea,
            aa,
            root,
            None,
            temp_dir(),
            None,
            None,
        )
        .with_transport(Box::new(transport.clone()))
        .with_clock(Arc::new(move || *n.lock().unwrap()))
        .with_its_id(ITS_ID.to_vec());
        client.pop = pop;
        pki.lock()
            .unwrap()
            .register(&ITS_ID, client.canonical_public_key());
        Iut {
            pki,
            transport,
            client,
            now,
        }
    }

    pub(super) fn enrol(&mut self) -> Result<OwnCertificate, PkiError> {
        self.client.enroll(None, None)
    }

    pub(super) fn authorize(&mut self) -> Result<OwnCertificate, PkiError> {
        self.client.authorize(None, None, None)
    }

    pub(super) fn pki(&self) -> std::sync::MutexGuard<'_, TsPki> {
        self.pki.lock().unwrap()
    }

    /// The last request received by the EA.
    pub(super) fn enrolment(&self) -> Received {
        self.pki().enrolments.last().unwrap().clone()
    }

    /// The last request received by the AA.
    pub(super) fn authorization(&self) -> Received {
        self.pki().authorizations.last().unwrap().clone()
    }

    pub(super) fn advance(&self, seconds: f64) {
        *self.now.lock().unwrap() += seconds;
    }
}

fn outer_signer(r: &Received) -> SignerIdentifier {
    signed_data(&r.outer).signer.clone()
}

fn digest(h: [u8; 8]) -> SignerIdentifier {
    SignerIdentifier::digest(HashedId8(FixedOctetString::from(h)))
}

/// headerInfo with psid 623 and generationTime only.
fn assert_header(data: &Ieee1609Dot2Data) {
    let header = &signed_data(data).tbs_data.header_info;
    assert_eq!(u64::try_from(&header.psid.0).unwrap(), PSID_CERT_REQUEST);
    assert!(header.generation_time.is_some());
    let expected = HeaderInfo::new(
        header.psid.clone(),
        header.generation_time.clone(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert_eq!(*header, expected, "no other header");
}

fn ssp_of(certificate: &Certificate, psid: u64) -> Option<Vec<u8>> {
    certificate
        .tbs()
        .app_permissions
        .as_ref()?
        .0
        .iter()
        .find_map(|p| {
            (u64::try_from(&p.psid.0).ok() == Some(psid)).then(|| match &p.ssp {
                Some(ServiceSpecificPermissions::bitmapSsp(b)) => b.0.to_vec(),
                _ => vec![],
            })
        })
}

// ─── Enrolment (TS 103 525-2 clause 5.2.2) ─────────────────────────────────

/// SECPKI_ITS-S_ENR_01_BV: triggered to request an EC, the IUT sends an
/// EnrolmentRequestMessage to the EA.
#[test]
fn tp_secpki_its_s_enr_01_bv() {
    let mut iut = Iut::new();
    assert_eq!(iut.client.state(), PkiState::Initialized);
    iut.enrol().unwrap();
    let (url, content, content_type) = iut.transport.posts.lock().unwrap()[0].clone();
    assert_eq!(
        (url.as_str(), content_type.as_str()),
        (iut.transport.ea_url.as_str(), "application/x-its-request")
    );
    let data: Ieee1609Dot2Data = crate::security::pki_asn::decode(&content).unwrap();
    assert!(matches!(
        data.content,
        Ieee1609Dot2Content::encryptedData(_)
    ));
    assert!(matches!(
        iut.enrolment().etsi.content,
        EtsiTs102941DataContent::enrolmentRequest(_)
    ));
}

/// SECPKI_ITS-S_ENR_02_BV: an initial request has itsId = canonical identifier,
/// outer signer self and the outer signature computed with the canonical key.
#[test]
fn tp_secpki_its_s_enr_02_bv() {
    let mut iut = Iut::new();
    iut.enrol().unwrap();
    let r = iut.enrolment();
    assert_eq!(r.ec().its_id.as_ref(), ITS_ID);
    assert_eq!(outer_signer(&r), SignerIdentifier::R_self(()));
    assert!(signed_ok(&r.outer, &iut.client.canonical_public_key(), &[]));
}

/// SECPKI_ITS-S_ENR_03_BV: with a valid EC the request is a re-keying request:
/// itsId and signer are the digest of the EC, signed with the EC key.
#[test]
fn tp_secpki_its_s_enr_03_bv() {
    let mut iut = Iut::new();
    let ec = iut.enrol().unwrap();
    iut.enrol().unwrap();
    let r = iut.enrolment();
    assert_eq!(r.ec().its_id.as_ref(), ec.as_hashedid8());
    assert_eq!(outer_signer(&r), digest(ec.as_hashedid8()));
    assert!(signed_ok(
        &r.outer,
        &ec.cert.verification_key().unwrap(),
        ec.cert.to_canonical().encode()
    ));
}

/// SECPKI_ITS-S_ENR_05_BV: once the EC expires the IUT is 'initialized' again:
/// the next request uses the canonical identifier.
#[test]
fn tp_secpki_its_s_enr_05_bv() {
    let mut iut = Iut::new();
    iut.pki().ec_duration = AsnDuration::hours(Uint16(1));
    iut.enrol().unwrap();
    assert_eq!(iut.client.state(), PkiState::Enrolled);
    iut.advance(2.0 * 3600.0); // the EC expires
    assert_eq!(iut.client.state(), PkiState::Initialized);
    iut.enrol().unwrap();
    let r = iut.enrolment();
    assert_eq!(r.ec().its_id.as_ref(), ITS_ID);
    assert_eq!(outer_signer(&r), SignerIdentifier::R_self(()));
}

/// SECPKI_ITS-S_ENR_06_BV: each request (initial, then re-keying) carries a new
/// verification key.
#[test]
fn tp_secpki_its_s_enr_06_bv() {
    let mut iut = Iut::new();
    for _ in 0..3 {
        iut.enrol().unwrap();
    }
    let enrolments = iut.pki().enrolments.clone();
    let signers: Vec<bool> = enrolments
        .iter()
        .map(|r| matches!(outer_signer(r), SignerIdentifier::R_self(())))
        .collect();
    assert_eq!(signers, vec![true, false, false]);
    let keys: HashSet<Vec<u8>> = enrolments
        .iter()
        .map(|r| encode(&r.ec().public_keys.verification_key))
        .collect();
    assert_eq!(keys.len(), 3);
}

/// SECPKI_ITS-S_ENR_07_BV: requestedSubjectAttributes contain no
/// certIssuePermissions (initialized and enrolled).
#[test]
fn tp_secpki_its_s_enr_07_bv() {
    let mut iut = Iut::new();
    iut.enrol().unwrap();
    iut.enrol().unwrap();
    for r in &iut.pki().enrolments {
        assert!(r
            .ec()
            .requested_subject_attributes
            .cert_issue_permissions
            .is_none());
    }
}

/// SECPKI_ITS-S_ENR_08_BV: the headerInfo of InnerECRequestSignedForPOP has
/// psid AID_CERT_REQ and generationTime only.
#[test]
fn tp_secpki_its_s_enr_08_bv() {
    let mut iut = Iut::new();
    iut.enrol().unwrap();
    iut.enrol().unwrap();
    for r in &iut.pki().enrolments {
        assert_header(r.pop.as_ref().unwrap());
    }
}

/// SECPKI_ITS-S_ENR_09_BV: the headerInfo of the outer EtsiTs103097Data-Signed
/// has psid AID_CERT_REQ and generationTime only.
#[test]
fn tp_secpki_its_s_enr_09_bv() {
    let mut iut = Iut::new();
    iut.enrol().unwrap();
    iut.enrol().unwrap();
    for r in &iut.pki().enrolments {
        assert_header(&r.outer);
    }
}

fn recipient_of(data: &Ieee1609Dot2Data) -> (Vec<RecipientInfo>, bool) {
    let Ieee1609Dot2Content::encryptedData(e) = &data.content else {
        panic!("not encryptedData")
    };
    let p256 = matches!(&e.recipients.0[0], RecipientInfo::certRecipInfo(r)
        if matches!(r.enc_key, EncryptedDataEncryptionKey::eciesNistP256(_)));
    (e.recipients.0.clone(), p256)
}

/// SECPKI_ITS-S_ENR_10_BV: exactly one certRecipInfo with the EA's HashedId8;
/// the AES key is encrypted (encKey) with the EA's encryption key and decrypts
/// the ciphertext (done by the test system EA).
#[test]
fn tp_secpki_its_s_enr_10_bv() {
    let mut iut = Iut::new();
    iut.enrol().unwrap();
    let r = iut.enrolment();
    let (recipients, p256) = recipient_of(&r.encrypted);
    assert_eq!(recipients.len(), 1);
    let RecipientInfo::certRecipInfo(recipient) = &recipients[0] else {
        panic!("not certRecipInfo")
    };
    assert_eq!(
        recipient.recipient_id.0.as_ref(),
        iut.pki().ea.own.as_hashedid8()
    );
    assert!(p256, "encKey of the EA key type (eciesNistP256)");
}

/// SECPKI_ITS-S_ENR_11_BV: the InnerECRequestSignedForPOP signature is computed
/// on the InnerECRequest with the private key of its verificationKey.
#[test]
fn tp_secpki_its_s_enr_11_bv() {
    let mut iut = Iut::new();
    iut.enrol().unwrap();
    let r = iut.enrolment();
    let pop = r.pop.as_ref().unwrap();
    assert_eq!(signed_data(pop).signer, SignerIdentifier::R_self(()));
    assert!(signed_ok(pop, &r.ec().public_keys.verification_key, &[]));
    let inner: InnerEcRequest = crate::security::pki_asn::decode(&unsecured(pop)).unwrap();
    assert_eq!(&inner, r.ec());
}

/// SECPKI_ITS-S_ENR_12_BV: enrolled, the request is signed with the EC, whose
/// appPermissions grant AID_CERT_REQ with SSP version 1 and the enrolment
/// request bit (clause B.4, 80h).
#[test]
fn tp_secpki_its_s_enr_12_bv() {
    let mut iut = Iut::new();
    let ec = iut.enrol().unwrap();
    iut.enrol().unwrap();
    assert_eq!(outer_signer(&iut.enrolment()), digest(ec.as_hashedid8()));
    let ssp = ssp_of(&ec.cert, PSID_CERT_REQUEST).unwrap();
    assert_eq!(ssp[0], 1);
    assert!(ssp[1] & 0x80 != 0);
}

// ─── Enrolment response (TS 103 525-2 clause 5.2.2.2) ──────────────────────

/// SECPKI_ITS-S_ENR_RCV_01_BV: after a response with responseCode != 0 the IUT
/// stays in X_STATE (1 'initialized', 2 'enrolled').
#[test]
fn tp_secpki_its_s_enr_rcv_01_bv() {
    let mut iut = Iut::new();
    iut.pki().ea_code = EnrolmentResponseCode::deniedrequest;
    match iut.enrol() {
        Err(PkiError::Enrolment(e)) => assert_eq!(e.code, "deniedrequest"),
        other => panic!("{other:?}"),
    }
    assert_eq!(iut.client.state(), PkiState::Initialized); // variant 1
    let mut iut = Iut::new();
    let ec = iut.enrol().unwrap();
    iut.pki().ea_code = EnrolmentResponseCode::deniedrequest;
    assert!(iut.enrol().is_err());
    assert_eq!(iut.client.state(), PkiState::Enrolled); // variant 2
    assert_eq!(iut.client.ec().unwrap().as_hashedid8(), ec.as_hashedid8());
}

/// SECPKI_ITS-S_ENR_RCV_02_BV: a positive EnrolmentResponse (responseCode 0,
/// EC) switches the IUT to 'enrolled' with that EC.
#[test]
fn tp_secpki_its_s_enr_rcv_02_bv() {
    let mut iut = Iut::new();
    let ec = iut.enrol().unwrap();
    assert_eq!(iut.client.state(), PkiState::Enrolled);
    assert_eq!(ec.cert.inner, iut.pki().issued_ecs.last().unwrap().inner);
    assert_eq!(
        ec.cert.verification_key().unwrap(),
        iut.enrolment().ec().public_keys.verification_key
    );
}

/// SECPKI_ITS-S_ENR_RCV_03_BE: an EC without AID_CERT_REQ in its
/// appPermissions is not used for re-enrolment: the next request is initial.
#[test]
fn tp_secpki_its_s_enr_rcv_03_be() {
    let mut iut = Iut::new();
    iut.pki().ec_permissions = SequenceOfPsidSsp(vec![psid_ssp(36, None)]);
    iut.enrol().unwrap();
    assert_eq!(iut.client.state(), PkiState::Enrolled);
    iut.enrol().unwrap();
    assert_eq!(outer_signer(&iut.enrolment()), SignerIdentifier::R_self(()));
    assert_eq!(iut.enrolment().ec().its_id.as_ref(), ITS_ID);
}

/// SECPKI_ITS-S_ENR_RCV_04_BE: an EC whose AID_CERT_REQ SSP has the enrolment
/// request bit 0 is not used for re-enrolment: the next request is initial.
#[test]
fn tp_secpki_its_s_enr_rcv_04_be() {
    let mut iut = Iut::new();
    iut.pki().ec_permissions =
        SequenceOfPsidSsp(vec![psid_ssp(PSID_CERT_REQUEST, Some(&[1, 0x40]))]);
    iut.enrol().unwrap();
    iut.enrol().unwrap();
    assert_eq!(outer_signer(&iut.enrolment()), SignerIdentifier::R_self(()));
    assert_eq!(iut.enrolment().ec().its_id.as_ref(), ITS_ID);
}

// ─── Authorization (TS 103 525-2 clause 5.2.3) ─────────────────────────────

fn enrolled(pop: bool) -> Iut {
    let mut iut = Iut::with(pop);
    iut.enrol().unwrap();
    iut
}

fn ec_signature(r: &Received) -> SignedData {
    signed_data(r.ec_signature.as_ref().unwrap()).clone()
}

/// SECPKI_ITS-S_AUTH_01_BV: triggered to request an AT, the enrolled IUT sends
/// an EtsiTs103097Data-Encrypted to the AA.
#[test]
fn tp_secpki_its_s_auth_01_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let (url, content, content_type) = iut.transport.posts.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        (url.as_str(), content_type.as_str()),
        (iut.transport.aa_url.as_str(), "application/x-its-request")
    );
    let data: Ieee1609Dot2Data = crate::security::pki_asn::decode(&content).unwrap();
    assert!(matches!(
        data.content,
        Ieee1609Dot2Content::encryptedData(_)
    ));
    assert_eq!(iut.client.state(), PkiState::Authorized);
}

/// SECPKI_ITS-S_AUTH_02_BV: encrypted to one AA only: recipients of size 1, a
/// certRecipInfo with the HashedId8 of the AA certificate.
#[test]
fn tp_secpki_its_s_auth_02_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let (recipients, _) = recipient_of(&iut.authorization().encrypted);
    assert_eq!(recipients.len(), 1);
    let RecipientInfo::certRecipInfo(r) = &recipients[0] else {
        panic!("not certRecipInfo")
    };
    assert_eq!(r.recipient_id.0.as_ref(), iut.pki().aa.own.as_hashedid8());
}

/// SECPKI_ITS-S_AUTH_03_BV: the data is encrypted with a symmetric key that the
/// AA decrypts with the private key of its encryptionKey (AA_ENC_PUB_KEY).
#[test]
fn tp_secpki_its_s_auth_03_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let r = iut.authorization();
    assert!(recipient_of(&r.encrypted).1);
    assert!(matches!(
        r.etsi.content,
        EtsiTs102941DataContent::authorizationRequest(_)
    ));
}

/// SECPKI_ITS-S_AUTH_04_BV: a request never reuses the encryption key or the
/// nonce of the N previous requests (N = 4).
#[test]
fn tp_secpki_its_s_auth_04_bv() {
    let mut iut = enrolled(true);
    for _ in 0..5 {
        iut.authorize().unwrap();
    }
    let all = iut.pki().authorizations.clone();
    let mut nonces = HashSet::new();
    let mut keys = HashSet::new();
    let mut encrypted_keys = HashSet::new();
    for r in &all {
        let Ieee1609Dot2Content::encryptedData(e) = &r.encrypted.content else {
            panic!()
        };
        let crate::security::security_asn::ieee1609_dot2::SymmetricCiphertext::aes128ccm(c) =
            &e.ciphertext
        else {
            panic!()
        };
        nonces.insert(c.nonce.to_vec());
        keys.insert(r.session_key);
        let RecipientInfo::certRecipInfo(ri) = &e.recipients.0[0] else {
            panic!()
        };
        let EncryptedDataEncryptionKey::eciesNistP256(k) = &ri.enc_key else {
            panic!()
        };
        encrypted_keys.insert(k.c.to_vec());
    }
    assert_eq!((nonces.len(), keys.len(), encrypted_keys.len()), (5, 5, 5));
}

/// SECPKI_ITS-S_AUTH_05_BV: EtsiTs102941Data version 1 with an authorizationRequest.
#[test]
fn tp_secpki_its_s_auth_05_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let r = iut.authorization();
    assert_eq!(r.etsi.version, 1);
    assert!(matches!(
        r.etsi.content,
        EtsiTs102941DataContent::authorizationRequest(_)
    ));
}

/// SECPKI_ITS-S_AUTH_06_BV: each request has a new verificationKey and hmacKey,
/// and no encryptionKey (the IUT requests none), differing from the N previous ones.
#[test]
fn tp_secpki_its_s_auth_06_bv() {
    let mut iut = enrolled(true);
    for _ in 0..4 {
        iut.authorize().unwrap();
    }
    let all = iut.pki().authorizations.clone();
    let keys: HashSet<Vec<u8>> = all
        .iter()
        .map(|r| encode(&r.at().public_keys.verification_key))
        .collect();
    let hmacs: HashSet<Vec<u8>> = all.iter().map(|r| r.at().hmac_key.to_vec()).collect();
    assert_eq!((keys.len(), hmacs.len()), (4, 4));
    assert!(all
        .iter()
        .all(|r| r.at().public_keys.encryption_key.is_none()));
}

/// SECPKI_ITS-S_AUTH_07_BV: keyTag = HMAC-SHA256(hmacKey, verificationKey ||
/// encryptionKey) truncated to 128 bits (clause 6.2.3.3.1).
#[test]
fn tp_secpki_its_s_auth_07_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let r = iut.authorization();
    let inner = r.at();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(inner.hmac_key.as_ref()).unwrap();
    mac.update(&encode(&inner.public_keys.verification_key));
    assert_eq!(
        &mac.finalize().into_bytes()[..16],
        inner.shared_at_request.key_tag.as_ref()
    );
    assert!(r.checks["keyTag"]);
}

/// SECPKI_ITS-S_AUTH_08_BV: sharedAtRequest.eaId is the HashedId8 of the EA
/// that issued the EC.
#[test]
fn tp_secpki_its_s_auth_08_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let ea = iut.pki().ea.own.as_hashedid8();
    assert_eq!(
        iut.authorization().at().shared_at_request.ea_id.0.as_ref(),
        ea
    );
    assert_eq!(
        iut.client.ec().unwrap().cert.get_issuer_hashedid8(),
        Some(ea)
    );
}

/// SECPKI_ITS-S_AUTH_09_BV: sharedAtRequest.certificateFormat is 1.
#[test]
fn tp_secpki_its_s_auth_09_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    assert_eq!(
        iut.authorization()
            .at()
            .shared_at_request
            .certificate_format
            .0,
        1
    );
}

/// SECPKI_ITS-S_AUTH_10_BV: requestedSubjectAttributes contain appPermissions
/// and no certIssuePermissions.
#[test]
fn tp_secpki_its_s_auth_10_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let attributes = iut
        .authorization()
        .at()
        .shared_at_request
        .requested_subject_attributes
        .clone();
    assert!(attributes.app_permissions.is_some());
    assert!(attributes.cert_issue_permissions.is_none());
}

/// SECPKI_ITS-S_AUTH_11_BV: the ecSignature (SignedExternalPayload) payload is
/// extDataHash, the SHA-256 hash of the sharedATRequest.
#[test]
fn tp_secpki_its_s_auth_11_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let r = iut.authorization();
    let expected: [u8; 32] = Sha256::digest(encode(&r.at().shared_at_request)).into();
    let payload = ec_signature(&r).tbs_data.payload.clone();
    assert!(payload.data.is_none());
    assert!(
        matches!(payload.ext_data_hash, Some(HashedData::sha256HashedData(h)) if h.0.as_ref() == expected)
    );
}

/// SECPKI_ITS-S_AUTH_12_BV: the ecSignature headerInfo has psid
/// AID_PKI_CERT_REQUEST and generationTime only.
#[test]
fn tp_secpki_its_s_auth_12_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    assert_header(iut.authorization().ec_signature.as_ref().unwrap());
}

/// SECPKI_ITS-S_AUTH_13_BV: the ecSignature hashId is a supported hash
/// algorithm (that of the EC key).
#[test]
fn tp_secpki_its_s_auth_13_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let expected = if iut.client.ec().unwrap().cert.uses_sha384() {
        HashAlgorithm::sha384
    } else {
        HashAlgorithm::sha256
    };
    assert_eq!(ec_signature(&iut.authorization()).hash_id, expected);
}

/// SECPKI_ITS-S_AUTH_14_BV: the ecSignature signer is the HashedId8 of CERT_EC
/// and the signature verifies with the EC verification key.
#[test]
fn tp_secpki_its_s_auth_14_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let ec = iut.client.ec().unwrap().clone();
    let r = iut.authorization();
    assert_eq!(ec_signature(&r).signer, digest(ec.as_hashedid8()));
    assert!(signed_ok(
        r.ec_signature.as_ref().unwrap(),
        &ec.cert.verification_key().unwrap(),
        ec.cert.to_canonical().encode()
    ));
}

/// SECPKI_ITS-S_AUTH_15_BV: (privacy) encryptedEcSignature with one
/// certRecipInfo for CERT_EA (encKey of the EA key type) whose ciphertext is
/// the SignedExternalPayload.
#[test]
fn tp_secpki_its_s_auth_15_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let r = iut.authorization();
    let EcSignature::encryptedEcSignature(encrypted) = &r.at().ec_signature else {
        panic!("ecSignature not encrypted")
    };
    let (recipients, p256) = recipient_of(encrypted);
    assert_eq!(recipients.len(), 1);
    let RecipientInfo::certRecipInfo(ri) = &recipients[0] else {
        panic!("not certRecipInfo")
    };
    assert_eq!(ri.recipient_id.0.as_ref(), iut.pki().ea.own.as_hashedid8());
    assert!(p256);
    assert!(ec_signature(&r).tbs_data.payload.ext_data_hash.is_some());
}

/// SECPKI_ITS-S_AUTH_17_BV: without proof of possession the encrypted data is an
/// unsecured Ieee1609Dot2Data (unsecuredData).
#[test]
fn tp_secpki_its_s_auth_17_bv() {
    let mut iut = enrolled(false);
    iut.authorize().unwrap();
    assert!(matches!(
        iut.authorization().outer.content,
        Ieee1609Dot2Content::unsecuredData(_)
    ));
    assert_eq!(iut.client.state(), PkiState::Authorized);
}

/// SECPKI_ITS-S_AUTH_18_BV: with proof of possession the request is a
/// self-signed EtsiTs103097Data-Signed (valid hashId, headerInfo psid
/// AID_PKI_CERT_REQUEST and generationTime only), signed with the key of its
/// verificationKey.
#[test]
fn tp_secpki_its_s_auth_18_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let r = iut.authorization();
    let sd = signed_data(&r.outer);
    assert_eq!(sd.hash_id, HashAlgorithm::sha256);
    assert_header(&r.outer);
    assert_eq!(sd.signer, SignerIdentifier::R_self(()));
    assert!(signed_ok(
        &r.outer,
        &r.at().public_keys.verification_key,
        &[]
    ));
}

/// SECPKI_ITS-S_AUTH_19_BV: the ecSignature signer (the EC) is permitted to sign
/// it: appPermissions with AID_CERT_REQ, SSP version 1 and the authorization
/// request bit (clause B.5: 40h, bit 1 of Table B.5); an EC without it is not used.
#[test]
fn tp_secpki_its_s_auth_19_bv() {
    let mut iut = enrolled(true);
    iut.authorize().unwrap();
    let ssp = ssp_of(&iut.client.ec().unwrap().cert, PSID_CERT_REQUEST).unwrap();
    assert_eq!(ssp[0], 1);
    assert!(ssp[1] & 0x40 != 0);
    let mut iut = Iut::new();
    iut.pki().ec_permissions =
        SequenceOfPsidSsp(vec![psid_ssp(PSID_CERT_REQUEST, Some(&[1, 0x80]))]);
    iut.enrol().unwrap();
    assert!(matches!(iut.authorize(), Err(PkiError::Authorization(_))));
    assert!(iut.pki().authorizations.is_empty());
}

// ─── CTL and CRL handling (TS 103 525-2 clauses 5.2.4 and 5.2.6) ───────────

/// A CTL / CRL message signed by `issuer` (signer certificate, clause 6.3.4).
pub(super) fn signed_list(
    issuer: &OwnCertificate,
    backend: &EcdsaBackend,
    psid: u64,
    content: EtsiTs102941DataContent,
    clock: &Clock,
) -> Vec<u8> {
    let etsi = encode(&EtsiTs102941Data::new(content));
    let tbs = ToBeSignedData::new(
        Box::new(SignedDataPayload::new(
            Some(Ieee1609Dot2Data::new(
                Uint8(3),
                Ieee1609Dot2Content::unsecuredData(Opaque(etsi.into())),
            )),
            None,
            None,
        )),
        HeaderInfo::new(
            Psid(Integer::from(psid)),
            Some(Time64(Uint64(clock.its_us()))),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
    );
    let signature = issuer.sign_message(backend, &encode_tbs_data(&tbs));
    encode_ieee1609_dot2_data(&Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::signedData(SignedData::new(
            HashAlgorithm::sha256,
            tbs,
            SignerIdentifier::certificate(
                crate::security::security_asn::ieee1609_dot2::SequenceOfCertificate(vec![issuer
                    .cert
                    .inner
                    .0
                    .clone()]),
            ),
            signature,
        )),
    ))
}

/// TLM, Root CAs, AAs and ATs of the test system; the IUT station and testers.
pub(super) struct TrustWorld {
    pub(super) clock: Clock,
    pub(super) backend: EcdsaBackend,
    pub(super) tlm: OwnCertificate,
    pub(super) rca: OwnCertificate,
    pub(super) aa: OwnCertificate,
    pub(super) sequence: std::collections::HashMap<[u8; 8], u8>,
}

pub(super) const CPOC: &str = "https://cpoc.ts/";
pub(super) const DC: &str = "https://dc.ts/";

impl TrustWorld {
    pub(super) fn new() -> TrustWorld {
        let mut backend = EcdsaBackend::new();
        let mut tlm_tbs = ca_tbs();
        tlm_tbs.app_permissions = Some(SequenceOfPsidSsp(vec![psid_ssp(
            PSID_CTL,
            Some(&[1, 0xC8]),
        )]));
        let tlm = OwnCertificate::initialize_self_signed(&mut backend, tlm_tbs);
        let rca = Self::root_on(&mut backend);
        let aa = OwnCertificate::initialize_issued(&mut backend, ca_tbs(), &rca);
        TrustWorld {
            clock: Clock::new(),
            backend,
            tlm,
            rca,
            aa,
            sequence: Default::default(),
        }
    }

    fn root_on(backend: &mut EcdsaBackend) -> OwnCertificate {
        let mut tbs = ca_tbs();
        tbs.app_permissions = Some(root_permissions());
        OwnCertificate::initialize_self_signed(backend, tbs)
    }

    pub(super) fn root(&mut self) -> OwnCertificate {
        Self::root_on(&mut self.backend)
    }

    pub(super) fn aa_of(&mut self, root: &OwnCertificate) -> OwnCertificate {
        OwnCertificate::initialize_issued(&mut self.backend, ca_tbs(), root)
    }

    pub(super) fn at(&mut self, aa: &OwnCertificate) -> OwnCertificate {
        let mut tbs = station_at_tbs();
        tbs.app_permissions = Some(psid_ssps(&app_permissions()));
        OwnCertificate::initialize_issued_with(&mut self.backend, tbs, aa, KeyAlgorithm::NistP256)
    }

    pub(super) fn pki(&self, roots: &[&OwnCertificate], aas: &[&OwnCertificate]) -> Pki {
        Pki {
            backend: self.backend.clone(),
            root: self.rca.clone(),
            aa: self.aa.clone(),
            roots: roots.iter().map(|r| r.cert.clone()).collect(),
            aas: aas.iter().map(|a| a.cert.clone()).collect(),
        }
    }

    /// The IUT and its trust store (TLM trusted).
    pub(super) fn iut(
        &mut self,
        roots: &[&OwnCertificate],
        aas: &[&OwnCertificate],
    ) -> (Station, TrustStore) {
        let aa = self.aa.clone();
        let at = self.at(&aa);
        let station = Station::new(
            &self.clock,
            &self.pki(roots, aas),
            vec![at],
            Options::default(),
        );
        let c = self.clock.clone();
        let store = TrustStore::new(vec![self.tlm.cert.clone()])
            .with_clock(Arc::new(move || c.unix_ms() as f64 / 1000.0));
        (station, store)
    }

    pub(super) fn tester(&mut self, aa: &OwnCertificate, root: &OwnCertificate, n: u8) -> Station {
        let at = self.at(aa);
        Station::new(
            &self.clock,
            &self.pki(&[root], &[aa]),
            vec![at],
            Options {
                n,
                station_id: TS_ID,
                ..Options::default()
            },
        )
    }

    fn next(&mut self, issuer: &OwnCertificate) -> u8 {
        let entry = self
            .sequence
            .entry(issuer.as_hashedid8())
            .or_insert(u8::MAX);
        *entry = entry.wrapping_add(1);
        *entry
    }

    pub(super) fn now32(&self) -> u32 {
        time32(self.clock.unix_ms() as f64 / 1000.0)
    }

    pub(super) fn ectl(&mut self, roots: &[&OwnCertificate], next_update_s: u32) -> Vec<u8> {
        self.ectl_of(roots, next_update_s, true)
    }

    /// A full or delta (`full` false) ECTL of the TLM.
    pub(super) fn ectl_of(
        &mut self,
        roots: &[&OwnCertificate],
        next_update_s: u32,
        full: bool,
    ) -> Vec<u8> {
        let mut commands: Vec<CtlCommand> = roots
            .iter()
            .map(|r| {
                CtlCommand::add(CtlEntry::rca(RootCaEntry {
                    selfsigned_root_ca: r.cert.inner.clone(),
                    successor_to: None,
                }))
            })
            .collect();
        commands.push(CtlCommand::add(CtlEntry::tlm(TlmEntry {
            self_signed_tlm_certificate: self.tlm.cert.inner.clone(),
            successor_to: None,
            access_point: Ia5String::try_from(CPOC.to_string()).unwrap(),
        })));
        let tlm = self.tlm.clone();
        let sequence = self.next(&tlm);
        let content = CtlFormat::new(
            Integer::from(1),
            Time32(Uint32(self.now32() + next_update_s)),
            full,
            sequence,
            commands,
        );
        signed_list(
            &self.tlm,
            &self.backend,
            PSID_CTL,
            EtsiTs102941DataContent::certificateTrustListTlm(content),
            &self.clock,
        )
    }

    pub(super) fn rca_ctl(
        &mut self,
        rca: &OwnCertificate,
        aas: &[&OwnCertificate],
        next_update_s: u32,
    ) -> Vec<u8> {
        self.rca_ctl_of(rca, aas, next_update_s, true)
    }

    /// A full or delta (`full` false) CTL of the Root CA `rca`.
    pub(super) fn rca_ctl_of(
        &mut self,
        rca: &OwnCertificate,
        aas: &[&OwnCertificate],
        next_update_s: u32,
        full: bool,
    ) -> Vec<u8> {
        let mut commands: Vec<CtlCommand> = aas
            .iter()
            .map(|a| {
                CtlCommand::add(CtlEntry::aa(AaEntry {
                    aa_certificate: a.cert.inner.clone(),
                    access_point: Ia5String::try_from("https://aa.ts/".to_string()).unwrap(),
                }))
            })
            .collect();
        commands.push(CtlCommand::add(CtlEntry::dc(DcEntry {
            url: Ia5String::try_from(DC.to_string()).unwrap(),
            cert: vec![HashedId8(FixedOctetString::from(rca.as_hashedid8()))],
        })));
        let sequence = self.next(rca);
        let content = CtlFormat::new(
            Integer::from(1),
            Time32(Uint32(self.now32() + next_update_s)),
            full,
            sequence,
            commands,
        );
        signed_list(
            rca,
            &self.backend,
            PSID_CTL,
            EtsiTs102941DataContent::certificateTrustListRca(content),
            &self.clock,
        )
    }

    pub(super) fn crl(
        &self,
        rca: &OwnCertificate,
        revoked: &[&OwnCertificate],
        this_update_offset: i64,
    ) -> Vec<u8> {
        let now = (self.now32() as i64 + this_update_offset) as u32;
        let content = ToBeSignedCrl::new(
            Integer::from(1),
            Time32(Uint32(now)),
            Time32(Uint32(now + 3600)),
            revoked
                .iter()
                .map(|c| HashedId8(FixedOctetString::from(c.as_hashedid8())))
                .collect(),
        );
        signed_list(
            rca,
            &self.backend,
            PSID_CRL,
            EtsiTs102941DataContent::certificateRevocationList(content),
            &self.clock,
        )
    }
}

pub(super) fn process(
    iut: &mut Station,
    store: &mut TrustStore,
    backend: &EcdsaBackend,
    message: &[u8],
) -> Result<(ListKind, HashSet<[u8; 8]>), super::trust_lists::TrustListError> {
    store.process(iut.gn.verify_library_mut().unwrap(), backend, message)
}

/// A CAM of `tester` (signed with its certificate, optionally modified and
/// re-signed) is accepted / discarded by the IUT.
fn assert_cam(
    iut: &mut Station,
    tester: &mut Station,
    backend: &EcdsaBackend,
    accepted: bool,
    at_ms: u64,
    requested: Option<&OwnCertificate>,
) {
    let mut raw = tester.certificate_cam(at_ms).raw;
    if let Some(aa) = requested {
        let aa = aa.cert.inner.0.clone();
        raw = resign(
            &raw,
            &tester.ats[0],
            backend,
            |sd| sd.tbs_data.header_info.requested_certificate = Some(aa),
            true,
            None,
        );
    }
    let before = iut.cams;
    iut.deliver(&raw, at_ms);
    assert_eq!(
        iut.cams,
        before + usize::from(accepted),
        "CAM accepted = {accepted}"
    );
}

/// SECPKI_ITS-S_CTL_01_BV: after a TLM CTL containing CERT_RCA_NEW, a CAM signed
/// with an AT of an AA of CERT_RCA_NEW is accepted (the AA delivered as
/// requestedCertificate).
#[test]
fn tp_secpki_its_s_ctl_01_bv() {
    let mut w = TrustWorld::new();
    let rca_new = w.root();
    let aa_new = w.aa_of(&rca_new);
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    let (mut iut, mut store) = w.iut(&[&rca], &[&aa]);
    let mut tester = w.tester(&aa_new, &rca_new, 9);
    assert_cam(&mut iut, &mut tester, &w.backend, false, 0, Some(&aa_new)); // RCA_NEW not trusted
    let ectl = w.ectl(&[&rca, &rca_new], 3600);
    assert_eq!(
        process(&mut iut, &mut store, &w.backend, &ectl).unwrap().0,
        ListKind::Ectl
    );
    assert_cam(&mut iut, &mut tester, &w.backend, true, 100, Some(&aa_new));
}

/// SECPKI_ITS-S_CTL_02_BV: after a TLM CTL not containing CERT_RCA (trusted
/// from the previous ECTL), CAMs chained to CERT_RCA are rejected.
#[test]
fn tp_secpki_its_s_ctl_02_bv() {
    let mut w = TrustWorld::new();
    let rca_other = w.root();
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    let (mut iut, mut store) = w.iut(&[], &[]);
    let ectl = w.ectl(&[&rca, &rca_other], 3600);
    process(&mut iut, &mut store, &w.backend, &ectl).unwrap();
    let backend = w.backend.clone();
    assert!(iut
        .gn
        .verify_library_mut()
        .unwrap()
        .learn_ca_certificate(&backend, aa.cert.clone()));
    let mut tester = w.tester(&aa, &rca, 9);
    assert_cam(&mut iut, &mut tester, &w.backend, true, 0, None);
    let ectl = w.ectl(&[&rca_other], 3600); // full ECTL without RCA
    process(&mut iut, &mut store, &w.backend, &ectl).unwrap();
    assert!(!iut
        .gn
        .verify_library_mut()
        .unwrap()
        .known_root_certificates
        .contains_key(&rca.as_hashedid8()));
    assert_cam(&mut iut, &mut tester, &w.backend, false, 100, None);
    let digest_cam = tester.cam_sent(200).raw; // also with the digest
    let before = iut.cams;
    iut.deliver(&digest_cam, 200);
    assert_eq!(iut.cams, before);
}

/// SECPKI_ITS-S_CTL_03_BV: after the CTL of CERT_RCA containing CERT_AA_NEW, a
/// CAM signed with an AT issued by CERT_AA_NEW is accepted.
#[test]
fn tp_secpki_its_s_ctl_03_bv() {
    let mut w = TrustWorld::new();
    let rca = w.rca.clone();
    let aa = w.aa.clone();
    let aa_new = w.aa_of(&rca);
    let (mut iut, mut store) = w.iut(&[&rca], &[&aa]);
    let mut tester = w.tester(&aa_new, &rca, 9);
    assert_cam(&mut iut, &mut tester, &w.backend, false, 0, None); // AA_NEW unknown
    let ctl = w.rca_ctl(&rca, &[&aa, &aa_new], 3600);
    assert_eq!(
        process(&mut iut, &mut store, &w.backend, &ctl).unwrap().0,
        ListKind::RcaCtl
    );
    assert_cam(&mut iut, &mut tester, &w.backend, true, 100, None);
}

pub(super) fn hex(h: [u8; 8]) -> String {
    h.iter().map(|b| format!("{b:02X}")).collect()
}

/// SECPKI_ITS-S_CTL_04_BV: when the TLM CTL (nextUpdate T1, CPOC URL) expires,
/// the IUT requests a new CTL from the CPOC (TS 102 941 Annex E.4: getectl).
#[test]
fn tp_secpki_its_s_ctl_04_bv() {
    let mut w = TrustWorld::new();
    let rca = w.rca.clone();
    let (mut iut, mut store) = w.iut(&[], &[]);
    let ectl = w.ectl(&[&rca], 60);
    process(&mut iut, &mut store, &w.backend, &ectl).unwrap();
    let transport = Transport::new(Arc::new(Mutex::new(TsPki::new())));
    let backend = w.backend.clone();
    assert!(store
        .refresh(iut.gn.verify_library_mut().unwrap(), &backend, &transport)
        .0
        .is_empty()); // T1 not reached
    w.clock.set(61_000);
    let url = format!("{CPOC}getectl/{}", hex(w.tlm.as_hashedid8()));
    let next = w.ectl(&[&rca], 3600);
    transport.files.lock().unwrap().insert(url.clone(), next);
    assert_eq!(
        store
            .refresh(iut.gn.verify_library_mut().unwrap(), &backend, &transport)
            .0,
        vec![url.clone()]
    );
    assert_eq!(*transport.gets.lock().unwrap(), vec![url]);
    assert_eq!(
        store.lists[&(ListKind::Ectl, w.tlm.as_hashedid8())].sequence,
        Some(1)
    );
}

/// SECPKI_ITS-S_CTL_05_BV: when the RCA CTL (nextUpdate T1, RCA DC URL) expires,
/// the IUT requests a new CTL from the RCA DC (TS 102 941 Annex D.1: getctl).
#[test]
fn tp_secpki_its_s_ctl_05_bv() {
    let mut w = TrustWorld::new();
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    let (mut iut, mut store) = w.iut(&[&rca], &[]);
    let ctl = w.rca_ctl(&rca, &[&aa], 60);
    process(&mut iut, &mut store, &w.backend, &ctl).unwrap();
    let transport = Transport::new(Arc::new(Mutex::new(TsPki::new())));
    let backend = w.backend.clone();
    assert!(store
        .refresh(iut.gn.verify_library_mut().unwrap(), &backend, &transport)
        .0
        .is_empty());
    w.clock.set(61_000);
    let url = format!("{DC}getctl/{}", hex(rca.as_hashedid8()));
    let next = w.rca_ctl(&rca, &[&aa], 3600);
    transport.files.lock().unwrap().insert(url.clone(), next);
    assert_eq!(
        store
            .refresh(iut.gn.verify_library_mut().unwrap(), &backend, &transport)
            .0,
        vec![url.clone()]
    );
    assert_eq!(*transport.gets.lock().unwrap(), vec![url]);
}

/// SECPKI_ITS-S_CRL_01_BV: the IUT accepts the CRL information of its Root CA
/// (signed by CERT_IUT_A_RCA); one signed by another key is rejected.
#[test]
fn tp_secpki_its_s_crl_01_bv() {
    let mut w = TrustWorld::new();
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    let (mut iut, mut store) = w.iut(&[&rca], &[&aa]);
    let other = w.root();
    assert!(process(&mut iut, &mut store, &w.backend, &w.crl(&other, &[], 0)).is_err());
    assert_eq!(
        process(&mut iut, &mut store, &w.backend, &w.crl(&rca, &[], 0))
            .unwrap()
            .0,
        ListKind::Crl
    );
    assert!(store
        .lists
        .contains_key(&(ListKind::Crl, rca.as_hashedid8())));
}

/// A PkiClient (authorized) and a trust store over a library of its PKI.
fn crl_iut() -> (
    Iut,
    TrustStore,
    crate::security::certificate_library::CertificateLibrary,
) {
    let mut iut = Iut::new();
    iut.enrol().unwrap();
    iut.authorize().unwrap();
    assert_eq!(iut.client.state(), PkiState::Authorized);
    let library = {
        let p = iut.pki();
        crate::security::certificate_library::CertificateLibrary::new(
            &p.backend,
            vec![p.root.cert.clone()],
            vec![p.aa.own.cert.clone(), p.ea.own.cert.clone()],
            vec![],
        )
    };
    let n = Arc::clone(&iut.now);
    let store = TrustStore::new(vec![]).with_clock(Arc::new(move || *n.lock().unwrap()));
    (iut, store, library)
}

fn revoke_with_crl(revoked: impl Fn(&TsPki) -> [u8; 8]) -> PkiState {
    let (mut iut, mut store, mut library) = crl_iut();
    let clock = Clock::new();
    let message = {
        let p = iut.pki();
        let now = time32(*iut.now.lock().unwrap());
        let content = ToBeSignedCrl::new(
            Integer::from(1),
            Time32(Uint32(now)),
            Time32(Uint32(now + 3600)),
            vec![HashedId8(FixedOctetString::from(revoked(&p)))],
        );
        signed_list(
            &p.root,
            &p.backend,
            PSID_CRL,
            EtsiTs102941DataContent::certificateRevocationList(content),
            &clock,
        )
    };
    let backend = iut.pki().backend.clone();
    let (_, revoked) = store.process(&mut library, &backend, &message).unwrap();
    iut.client.revoke(&revoked);
    iut.client.state()
}

/// SECPKI_ITS-S_CRL_02_BV: a CRL revoking the AA of the IUT's AT switches the
/// IUT to 'enrolled'.
#[test]
fn tp_secpki_its_s_crl_02_bv() {
    assert_eq!(
        revoke_with_crl(|p| p.aa.own.as_hashedid8()),
        PkiState::Enrolled
    );
}

/// SECPKI_ITS-S_CRL_03_BV: a CRL revoking the EA of the IUT's EC switches the
/// authorized IUT to the initial state.
#[test]
fn tp_secpki_its_s_crl_03_bv() {
    assert_eq!(
        revoke_with_crl(|p| p.ea.own.as_hashedid8()),
        PkiState::Initialized
    );
}

/// SECPKI_ITS-S_CRL_04_BV: a CRL revoking the IUT's Root CA switches the
/// authorized IUT to the initial state.
#[test]
fn tp_secpki_its_s_crl_04_bv() {
    assert_eq!(
        revoke_with_crl(|p| p.root.as_hashedid8()),
        PkiState::Initialized
    );
}

/// SECPKI_ITS-S_CRL_05_BV: after a CRL revoking CERT_IUT_A_B_AA, messages signed
/// with an AT of that AA (already accepted before) are discarded; another AA
/// still works.
#[test]
fn tp_secpki_its_s_crl_05_bv() {
    let mut w = TrustWorld::new();
    let (rca, aa) = (w.rca.clone(), w.aa.clone());
    let aa_b = w.aa_of(&rca);
    let (mut iut, mut store) = w.iut(&[&rca], &[&aa, &aa_b]);
    let mut tester_b = w.tester(&aa_b, &rca, 9);
    let mut tester_a = w.tester(&aa, &rca, 10);
    assert_cam(&mut iut, &mut tester_b, &w.backend, true, 0, None);
    let crl = w.crl(&rca, &[&aa_b], 0);
    process(&mut iut, &mut store, &w.backend, &crl).unwrap();
    assert_cam(&mut iut, &mut tester_b, &w.backend, false, 1000, None); // certificate signer
    let digest_cam = tester_b.cam_sent(1100).raw; // digest signer
    let before = iut.cams;
    iut.deliver(&digest_cam, 1100);
    assert_eq!(iut.cams, before);
    assert_cam(&mut iut, &mut tester_a, &w.backend, true, 1200, None);
}

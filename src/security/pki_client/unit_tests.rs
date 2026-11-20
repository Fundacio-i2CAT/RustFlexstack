// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Unit tests of the PKI client outside the TPs: the message layer (encryption,
//! the checks applied to a response, keyTag, SSP permissions), every reason a
//! CTL / CRL is rejected, and the client (persistence, provisioning,
//! preconditions). Mirrors FlexStack `test_messages.py`, `test_trust_lists.py`
//! and `test_client.py`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use rasn::prelude::*;
use sha2::{Digest, Sha256};

use super::client::{PkiClient, PkiError, PkiState};
use super::conformance::{process, signed_list, Iut, TrustWorld, ITS_ID};
use super::enrolment::{enroll, EnrolmentError};
use super::messages::{self, PendingRequest};
use super::trust_lists::{ListInfo, ListKind, TrustListError, TrustStore};
use super::ts_pki::{psid_ssp, Transport, TsPki, PSID_CRL, PSID_CTL};
use crate::security::certificate::{encode_ieee1609_dot2_data, Certificate, OwnCertificate};
use crate::security::conformance::Clock;
use crate::security::ecdsa_backend::{EcdsaBackend, KeyAlgorithm};
use crate::security::pki_asn::etsi_ts102941_base_types::{
    CertificateSubjectAttributes, PublicKeys,
};
use crate::security::pki_asn::etsi_ts102941_messages_itss::EtsiTs102941DataContent;
use crate::security::pki_asn::etsi_ts102941_trust_lists::{
    CtlCommand, CtlDelete, CtlEntry, CtlFormat, RootCaEntry,
};
use crate::security::pki_asn::{decode, encode};
use crate::security::security_asn::ieee1609_dot2::{
    Ieee1609Dot2Content, Ieee1609Dot2Data, SymmetricCiphertext,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    BasePublicEncryptionKey, EccP256CurvePoint, HashedId8, Opaque, PublicEncryptionKey,
    PublicVerificationKey, SequenceOfPsidSsp, SymmAlgorithm, Time32, Uint32, Uint8,
};
use crate::security::verify_service::security_checks::ca_tbs;

const NOW: f64 = 1_800_000_000.0;

// ─── Helpers (test_messages.TestHelpers) ───────────────────────────────────

#[test]
fn psk_id_is_hash_of_symmetric_encryption_key() {
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let expected: [u8; 8] = Sha256::digest([&[0x80u8][..], &key].concat())[24..]
        .try_into()
        .unwrap();
    assert_eq!(messages::psk_id(&key), expected);
}

#[test]
fn request_hash() {
    assert_eq!(
        messages::request_hash(b"abc").to_vec(),
        Sha256::digest(b"abc")[..16].to_vec()
    );
}

/// Time32 / Time64 count TAI from 2004-01-01 (5 leap seconds since).
#[test]
fn times() {
    assert_eq!(messages::time32(1_072_915_200.0), 5);
    assert_eq!(messages::time64(1_072_915_200.5), 5_500_000);
}

/// keyTag over verificationKey || encryptionKey when an encryption key is requested.
#[test]
fn key_tag_with_encryption_key() {
    let keys = PublicKeys::new(
        PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_0(vec![1; 32].into())),
        Some(PublicEncryptionKey::new(
            SymmAlgorithm::aes128Ccm,
            BasePublicEncryptionKey::eciesNistP256(EccP256CurvePoint::compressed_y_1(
                vec![2; 32].into(),
            )),
        )),
    );
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&[b'k'; 32]).unwrap();
    mac.update(&encode(&keys.verification_key));
    mac.update(&encode(keys.encryption_key.as_ref().unwrap()));
    assert_eq!(
        messages::key_tag(&[b'k'; 32], &keys).to_vec(),
        mac.finalize().into_bytes()[..16].to_vec()
    );
}

#[test]
fn ssp_permits() {
    let cert = |permissions: SequenceOfPsidSsp| {
        let mut backend = EcdsaBackend::new();
        let mut tbs = ca_tbs();
        tbs.app_permissions = Some(permissions);
        OwnCertificate::initialize_self_signed(&mut backend, tbs).cert
    };
    let both = cert(SequenceOfPsidSsp(vec![psid_ssp(623, Some(&[1, 0xC0]))]));
    assert!(messages::ssp_permits(
        &both,
        messages::SSP_ENROLMENT_REQUEST
    ));
    assert!(messages::ssp_permits(
        &both,
        messages::SSP_AUTHORIZATION_REQUEST
    ));
    for permissions in [
        vec![psid_ssp(623, Some(&[1, 0x40]))], // no enrolment bit
        vec![psid_ssp(623, Some(&[2, 0xC0]))], // unknown version
        vec![psid_ssp(623, None)],
        vec![psid_ssp(36, None)],
        vec![],
    ] {
        assert!(!messages::ssp_permits(
            &cert(SequenceOfPsidSsp(permissions)),
            messages::SSP_ENROLMENT_REQUEST
        ));
    }
}

// ─── Encryption (test_messages.TestEncryption) ─────────────────────────────

fn ecies_authority(
    brainpool: bool,
    backend: &mut EcdsaBackend,
    root: &OwnCertificate,
) -> (OwnCertificate, Vec<u8>) {
    use ecdsa_v017::elliptic_curve::sec1::ToSec1Point;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let (private, compressed) = if brainpool {
        let key =
            ecdsa_v017::elliptic_curve::SecretKey::<bp256::BrainpoolP256r1>::from_slice(&[7u8; 32])
                .unwrap();
        (
            key.to_bytes().to_vec(),
            key.public_key().to_sec1_point(true).as_bytes().to_vec(),
        )
    } else {
        let key = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        (
            key.to_bytes().to_vec(),
            key.public_key().to_encoded_point(true).as_bytes().to_vec(),
        )
    };
    let x = compressed[1..].to_vec().into();
    let point = if compressed[0] == 2 {
        EccP256CurvePoint::compressed_y_0(x)
    } else {
        EccP256CurvePoint::compressed_y_1(x)
    };
    let mut tbs = ca_tbs();
    tbs.encryption_key = Some(PublicEncryptionKey::new(
        SymmAlgorithm::aes128Ccm,
        if brainpool {
            BasePublicEncryptionKey::eciesBrainpoolP256r1(point)
        } else {
            BasePublicEncryptionKey::eciesNistP256(point)
        },
    ));
    (
        OwnCertificate::initialize_issued(backend, tbs, root),
        private,
    )
}

/// ECIES with NIST P-256 and brainpoolP256r1 encryption keys (IEEE 1609.2
/// clause 5.3.5), decrypted here with the recipient key.
#[test]
fn encrypt_to_both_ecies_curves() {
    use crate::security::security_asn::ieee1609_dot2::{EncryptedDataEncryptionKey, RecipientInfo};
    use ecdsa_v017::elliptic_curve::point::AffineCoordinates;
    let pki = TsPki::new();
    let mut backend = pki.backend.clone();
    for brainpool in [false, true] {
        let (own, private) = ecies_authority(brainpool, &mut backend, &pki.root);
        let (data, session_key) = messages::encrypt_to(&own.cert, b"secret payload").unwrap();
        let Ieee1609Dot2Content::encryptedData(e) = &data.content else {
            panic!()
        };
        let RecipientInfo::certRecipInfo(r) = &e.recipients.0[0] else {
            panic!()
        };
        let (key, is_bp) = match &r.enc_key {
            EncryptedDataEncryptionKey::eciesNistP256(k) => (k, false),
            EncryptedDataEncryptionKey::eciesBrainpoolP256r1(k) => (k, true),
            _ => panic!(),
        };
        assert_eq!(is_bp, brainpool);
        let v = match &key.v {
            EccP256CurvePoint::compressed_y_0(x) => [&[2u8][..], x.as_ref()].concat(),
            EccP256CurvePoint::compressed_y_1(x) => [&[3u8][..], x.as_ref()].concat(),
            _ => panic!(),
        };
        let shared = if brainpool {
            type C = bp256::BrainpoolP256r1;
            let d = ecdsa_v017::elliptic_curve::SecretKey::<C>::from_slice(&private).unwrap();
            let p = ecdsa_v017::elliptic_curve::PublicKey::<C>::from_sec1_bytes(&v).unwrap();
            (p.to_projective() * *d.to_nonzero_scalar())
                .to_affine()
                .x()
                .to_vec()
        } else {
            let d = p256::SecretKey::from_slice(&private).unwrap();
            let p = p256::PublicKey::from_sec1_bytes(&v).unwrap();
            p256::ecdh::diffie_hellman(d.to_nonzero_scalar(), p.as_affine())
                .raw_secret_bytes()
                .to_vec()
        };
        let p1 = Sha256::digest(own.cert.to_canonical().encode());
        let k1 = Sha256::digest([&shared[..], &1u32.to_be_bytes(), &p1].concat());
        let recovered: Vec<u8> = key.c.iter().zip(&k1[..16]).map(|(a, b)| a ^ b).collect();
        assert_eq!(recovered, session_key.to_vec());
        let SymmetricCiphertext::aes128ccm(c) = &e.ciphertext else {
            panic!()
        };
        use ccm::aead::{Aead, KeyInit};
        let cipher = ccm::Ccm::<aes::Aes128, ccm::consts::U16, ccm::consts::U12>::new_from_slice(
            &session_key,
        )
        .unwrap();
        let nonce: [u8; 12] = c.nonce.as_ref().try_into().unwrap();
        assert_eq!(
            cipher
                .decrypt((&nonce).into(), c.ccm_ciphertext.0.as_ref())
                .unwrap(),
            b"secret payload"
        );
    }
}

#[test]
fn encrypt_to_certificate_without_encryption_key() {
    let pki = TsPki::new();
    assert_eq!(
        messages::encrypt_to(&pki.root.cert, b"x").unwrap_err().code,
        "invalidencryptionkey"
    );
}

// ─── Response checks (test_messages.TestResponseChecks) ────────────────────

struct Checks {
    pki: TsPki,
    backend: EcdsaBackend,
    canonical: usize,
}

impl Checks {
    fn new() -> Checks {
        let mut pki = TsPki::new();
        let mut backend = EcdsaBackend::new();
        let canonical = backend.create_key();
        pki.register(b"id", backend.get_public_key(canonical));
        Checks {
            pki,
            backend,
            canonical,
        }
    }

    fn attributes() -> CertificateSubjectAttributes {
        CertificateSubjectAttributes::new(
            None,
            None,
            None,
            None,
            Some(SequenceOfPsidSsp(vec![psid_ssp(623, Some(&[1, 0xC0]))])),
            None,
        )
    }

    fn request(&mut self) -> PendingRequest {
        messages::build_enrolment_request(
            &mut self.backend,
            &self.pki.ea.own.cert,
            b"id",
            self.canonical,
            None,
            Self::attributes(),
            NOW,
            KeyAlgorithm::NistP256,
        )
        .unwrap()
    }

    fn rejected(
        &self,
        response: &[u8],
        request: &PendingRequest,
        authority: Option<&Certificate>,
    ) -> String {
        messages::read_enrolment_response(
            response,
            request,
            authority.unwrap_or(&self.pki.ea.own.cert),
            &self.backend,
        )
        .unwrap_err()
        .code
    }
}

#[test]
fn valid_response() {
    let mut c = Checks::new();
    let request = c.request();
    let response = c.pki.enrol(&request.message);
    let inner =
        messages::read_enrolment_response(&response, &request, &c.pki.ea.own.cert, &c.backend)
            .unwrap();
    assert_eq!(inner.request_hash.as_ref(), request.request_hash());
}

#[test]
fn garbage_response() {
    let mut c = Checks::new();
    let request = c.request();
    assert_eq!(c.rejected(&[0, 1], &request, None), "cantparse");
}

#[test]
fn response_not_encrypted() {
    let mut c = Checks::new();
    let request = c.request();
    let unsecured = encode_ieee1609_dot2_data(&Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::unsecuredData(Opaque(b"x".to_vec().into())),
    ));
    assert_eq!(c.rejected(&unsecured, &request, None), "badcontenttype");
}

/// A response for another request (other AES key) is not ours.
#[test]
fn response_for_other_session_key() {
    let mut c = Checks::new();
    let (first, second) = (c.request(), c.request());
    let response = c.pki.enrol(&first.message);
    assert_eq!(c.rejected(&response, &second, None), "imnottherecipient");
}

#[test]
fn tampered_response() {
    let mut c = Checks::new();
    let request = c.request();
    let mut data: Ieee1609Dot2Data = decode(&c.pki.enrol(&request.message)).unwrap();
    if let Ieee1609Dot2Content::encryptedData(e) = &mut data.content {
        if let SymmetricCiphertext::aes128ccm(ct) = &mut e.ciphertext {
            let mut bytes = ct.ccm_ciphertext.0.to_vec();
            bytes[0] ^= 1;
            ct.ccm_ciphertext = Opaque(bytes.into());
        }
    }
    assert_eq!(
        c.rejected(&encode_ieee1609_dot2_data(&data), &request, None),
        "decryptionfailed"
    );
}

/// A response signed by the AA (not the EA the request was sent to).
#[test]
fn response_signed_by_another_authority() {
    let mut c = Checks::new();
    let request = c.request();
    let response = c.pki.enrol(&request.message);
    let aa = c.pki.aa.own.cert.clone();
    assert_eq!(
        c.rejected(&response, &request, Some(&aa)),
        "invalidsignature"
    );
}

#[test]
fn request_hash_mismatch() {
    let mut c = Checks::new();
    let request = c.request();
    let response = c.pki.enrol(&request.message);
    let mut other = request.clone();
    other.message.push(0);
    assert_eq!(c.rejected(&response, &other, None), "badcontenttype");
}

/// An EC that does not certify the requested verification key is refused.
#[test]
fn ec_for_another_key() {
    let mut c = Checks::new();
    let other = c.backend.create_key();
    c.pki.ec_key_override = Some(c.backend.get_public_key(other));
    let pki = Arc::new(Mutex::new(c.pki));
    let transport = Transport::new(Arc::clone(&pki));
    let ea = pki.lock().unwrap().ea.own.cert.clone();
    let error: EnrolmentError = enroll(
        &transport,
        &transport.ea_url,
        &ea,
        &mut c.backend,
        b"id",
        c.canonical,
        None,
        Checks::attributes(),
        NOW,
        None,
    )
    .unwrap_err();
    assert_eq!(error.code, "invalidkeys");
}

// ─── Trust lists (test_trust_lists.TestTrustListChecks) ────────────────────

struct Trust {
    w: TrustWorld,
    station: crate::security::conformance::Station,
    store: TrustStore,
}

impl Trust {
    fn new() -> Trust {
        let mut w = TrustWorld::new();
        let (rca, aa) = (w.rca.clone(), w.aa.clone());
        let (station, store) = w.iut(&[&rca], &[&aa]);
        Trust { w, station, store }
    }

    fn run(&mut self, message: &[u8]) -> Result<(ListKind, HashSet<[u8; 8]>), TrustListError> {
        let backend = self.w.backend.clone();
        process(&mut self.station, &mut self.store, &backend, message)
    }

    fn rejected(&mut self, message: &[u8]) -> String {
        self.run(message).unwrap_err().code
    }

    fn ctl(
        &self,
        issuer: &OwnCertificate,
        psid: u64,
        tlm: bool,
        commands: Vec<CtlCommand>,
        full: bool,
        sequence: u8,
    ) -> Vec<u8> {
        let content = CtlFormat::new(
            Integer::from(1),
            Time32(Uint32(self.w.now32() + 3600)),
            full,
            sequence,
            commands,
        );
        let content = if tlm {
            EtsiTs102941DataContent::certificateTrustListTlm(content)
        } else {
            EtsiTs102941DataContent::certificateTrustListRca(content)
        };
        signed_list(issuer, &self.w.backend, psid, content, &self.w.clock)
    }
}

#[test]
fn list_not_signed_data() {
    let mut t = Trust::new();
    let unsecured = encode_ieee1609_dot2_data(&Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::unsecuredData(Opaque(b"x".to_vec().into())),
    ));
    assert_eq!(t.rejected(&unsecured), "badcontenttype");
}

#[test]
fn list_garbage() {
    assert_eq!(Trust::new().rejected(&[3, 0x81]), "cantparse");
}

#[test]
fn ectl_from_untrusted_tlm() {
    let mut t = Trust::new();
    let mut tbs = ca_tbs();
    tbs.app_permissions = Some(SequenceOfPsidSsp(vec![psid_ssp(
        PSID_CTL,
        Some(&[1, 0xC8]),
    )]));
    let rogue = OwnCertificate::initialize_self_signed(&mut t.w.backend, tbs);
    let message = t.ctl(&rogue, PSID_CTL, true, vec![], true, 0);
    assert_eq!(t.rejected(&message), "unknownissuer");
}

#[test]
fn list_wrong_psid() {
    let mut t = Trust::new();
    let tlm = t.w.tlm.clone();
    let message = t.ctl(&tlm, PSID_CRL, true, vec![], true, 0);
    assert_eq!(t.rejected(&message), "badpsid");
}

/// A Root CA CTL (SSP 38h) cannot add Root CAs (bit 40h, Table B.3).
#[test]
fn rca_may_not_sign_root_entries() {
    let mut t = Trust::new();
    let other = t.w.root();
    let rca = t.w.rca.clone();
    let add = CtlCommand::add(CtlEntry::rca(RootCaEntry {
        selfsigned_root_ca: other.cert.inner.clone(),
        successor_to: None,
    }));
    let message = t.ctl(&rca, PSID_CTL, false, vec![add], true, 0);
    assert_eq!(t.rejected(&message), "deniedpermissions");
}

#[test]
fn full_ctl_without_delete() {
    let mut t = Trust::new();
    let tlm = t.w.tlm.clone();
    let delete = CtlCommand::delete(CtlDelete::cert(HashedId8(FixedOctetString::from([1; 8]))));
    let message = t.ctl(&tlm, PSID_CTL, true, vec![delete], true, 0);
    assert_eq!(t.rejected(&message), "badcontenttype");
}

/// The same ctlSequence twice, or a delta CTL not following the last CTL.
#[test]
fn ctl_sequence() {
    let mut t = Trust::new();
    let tlm = t.w.tlm.clone();
    let m = t.ctl(&tlm, PSID_CTL, true, vec![], true, 4);
    t.run(&m).unwrap();
    let m = t.ctl(&tlm, PSID_CTL, true, vec![], true, 4);
    assert_eq!(t.rejected(&m), "outdated");
    let m = t.ctl(&tlm, PSID_CTL, true, vec![], false, 6);
    assert_eq!(t.rejected(&m), "outofsequence");
    let m = t.ctl(&tlm, PSID_CTL, true, vec![], false, 5);
    t.run(&m).unwrap();
}

#[test]
fn tampered_list_signature() {
    let mut t = Trust::new();
    let tlm = t.w.tlm.clone();
    let mut message = t.ctl(&tlm, PSID_CTL, true, vec![], true, 0);
    *message.last_mut().unwrap() ^= 1;
    assert_eq!(t.rejected(&message), "invalidsignature");
}

#[test]
fn crl_issuer_without_crl_permission() {
    let mut t = Trust::new();
    let mut tbs = ca_tbs();
    tbs.app_permissions = Some(SequenceOfPsidSsp(vec![psid_ssp(
        PSID_CTL,
        Some(&[1, 0x38]),
    )]));
    let no_crl = OwnCertificate::initialize_self_signed(&mut t.w.backend, tbs);
    let backend = t.w.backend.clone();
    t.station
        .gn
        .verify_library_mut()
        .unwrap()
        .add_root_certificate(&backend, no_crl.cert.clone());
    let message = t.w.crl(&no_crl, &[], 0);
    assert_eq!(t.rejected(&message), "deniedpermissions");
}

#[test]
fn older_crl() {
    let mut t = Trust::new();
    let rca = t.w.rca.clone();
    let m = t.w.crl(&rca, &[], 0);
    t.run(&m).unwrap();
    let m = t.w.crl(&rca, &[], -10);
    assert_eq!(t.rejected(&m), "outdated");
}

/// A revoked certificate is revoked permanently (clause 6.3.3).
#[test]
fn revoked_root_cannot_return() {
    let mut t = Trust::new();
    let rca = t.w.rca.clone();
    let m = t.w.crl(&rca, &[&rca], 0);
    t.run(&m).unwrap();
    let h = rca.as_hashedid8();
    assert!(!t
        .station
        .gn
        .verify_library_mut()
        .unwrap()
        .known_root_certificates
        .contains_key(&h));
    let m = t.w.ectl(&[&rca], 3600);
    t.run(&m).unwrap();
    assert!(!t
        .station
        .gn
        .verify_library_mut()
        .unwrap()
        .known_root_certificates
        .contains_key(&h));
}

/// A list past nextUpdate whose issuer has no CPOC / DC URL is not fetched.
#[test]
fn no_download_without_access_point() {
    let clock = Clock::new();
    let c = clock.clone();
    let mut store =
        TrustStore::new(vec![]).with_clock(Arc::new(move || c.unix_ms() as f64 / 1000.0));
    let past = messages::time32(clock.unix_ms() as f64 / 1000.0) - 1;
    for (kind, h) in [(ListKind::Crl, [1u8; 8]), (ListKind::Ectl, [2u8; 8])] {
        store.lists.insert(
            (kind, h),
            ListInfo {
                issuer: h,
                kind,
                next_update: past,
                sequence: None,
                this_update: None,
                entries: HashSet::new(),
            },
        );
    }
    assert!(store.due_downloads().is_empty());
    store.dc_urls.insert([1; 8], "https://dc.ts".into());
    assert_eq!(
        store.due_downloads(),
        vec![format!("https://dc.ts/getcrl/{}", "01".repeat(8))]
    );
}

// ─── Client (test_client.TestPkiClient) ────────────────────────────────────

#[test]
fn canonical_key_from_bytes() {
    let iut = Iut::new();
    let key = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng)
        .to_bytes()
        .to_vec();
    let make = |k: Vec<u8>| {
        let p = iut.pki();
        PkiClient::new(
            "a",
            "b",
            p.ea.own.cert.clone(),
            p.aa.own.cert.clone(),
            p.root.cert.clone(),
            Some(k),
            "/tmp",
            None,
            None,
        )
    };
    assert_eq!(
        make(key.clone()).canonical_public_key(),
        make(key).canonical_public_key()
    );
}

#[test]
fn provision_enrols_once() {
    let mut iut = Iut::new();
    iut.client.provision(None, None, None).unwrap();
    iut.client.provision(None, None, None).unwrap();
    assert_eq!(iut.client.state(), PkiState::Authorized);
    let p = iut.pki();
    assert_eq!((p.enrolments.len(), p.authorizations.len()), (1, 2));
}

#[test]
fn authorize_without_ec() {
    let mut iut = Iut::new();
    assert!(matches!(iut.authorize(), Err(PkiError::InvalidState(_))));
    assert!(iut.pki().authorizations.is_empty());
}

#[test]
fn saved_and_loaded() {
    let mut iut = Iut::new();
    let at = iut.client.provision(None, None, None).unwrap();
    for name in ["ec.cert", "ec.pem", "at.cert", "at.pem"] {
        assert!(iut.client.certs_dir.join(name).exists(), "{name}");
    }
    let (ea, aa, root) = {
        let p = iut.pki();
        (
            p.ea.own.cert.clone(),
            p.aa.own.cert.clone(),
            p.root.cert.clone(),
        )
    };
    let n = Arc::clone(&iut.now);
    let mut other = PkiClient::new(
        "a",
        "b",
        ea,
        aa,
        root,
        None,
        iut.client.certs_dir.clone(),
        Some(ITS_ID),
        None,
    )
    .with_clock(Arc::new(move || *n.lock().unwrap()));
    let ec = other.load_ec_from_disk(None).unwrap();
    assert_eq!(ec.as_hashedid8(), iut.client.ec().unwrap().as_hashedid8());
    let loaded = other.load_at_from_disk(None).unwrap();
    assert_eq!(loaded.as_hashedid8(), at.as_hashedid8());
    assert_eq!(other.state(), PkiState::Authorized);
    let signature = other.backend.sign(b"data", loaded.key_id);
    assert!(other.backend.verify_with_pk(
        b"data",
        &signature,
        &loaded.cert.verification_key().unwrap()
    ));
}

#[test]
fn load_missing() {
    let mut iut = Iut::new();
    assert!(iut.client.load_at_from_disk(None).is_none());
    assert!(iut.client.load_ec_from_disk(None).is_none());
    std::fs::create_dir_all(&iut.client.certs_dir).unwrap();
    std::fs::write(iut.client.certs_dir.join("at.cert"), b"junk").unwrap();
    std::fs::write(iut.client.certs_dir.join("at.pem"), [0u8; 32]).unwrap();
    assert!(iut.client.load_at_from_disk(None).is_none());
}

// ─── Distribution (test_distribution.TestDistribution / TestPostWithRetry) ─

mod distribution {
    use super::super::conformance::TrustWorld;
    use super::super::conformance_dist::{
        crl_request, ctl_request, cxl_iut, frames, neighbour_broadcast,
    };
    use super::super::distribution::{
        DistributionConfig, TrustListDistribution, CRL_PORT, CTL_PORT,
    };
    use super::super::messages::time32;
    use super::super::transport::{post_with_retry, PkiTransport, PkiTransportError, RetryPolicy};
    use super::super::trust_lists::{ListKind, TrustStore};
    use crate::btp::btp_header::BTPBHeader;
    use crate::btp::router::Router as BtpRouter;
    use crate::geonet::mib::{GnSecurity, Mib};
    use crate::geonet::position_vector::LongPositionVector;
    use crate::geonet::service_access_point::{
        CommonNH, GNDataIndication, HeaderSubType, HeaderType, PacketTransportType,
        TopoBroadcastHST, TrafficClass,
    };
    use crate::security::header_extensions::TrustListRequest;
    use crate::security::security_asn::etsi_ts103097_extension_module::EtsiTs102941FullCtlRequest;
    use std::time::Duration;

    #[test]
    fn attach_registers_both_ports_open_to_unsecured() {
        let mut mib = Mib::new();
        mib.itsGnSecurity = GnSecurity::Enabled;
        let (btp, _gn_rx) = BtpRouter::spawn(mib);
        let cxl =
            TrustListDistribution::new(TrustStore::new(vec![]), DistributionConfig::default());
        cxl.attach(&btp);
        for port in [CTL_PORT, CRL_PORT] {
            let mut data = BTPBHeader {
                destination_port: port,
                destination_port_info: 0,
            }
            .encode()
            .to_vec();
            data.push(0x01);
            btp.send_gn_data_indication(GNDataIndication {
                upper_protocol_entity: CommonNH::BtpB,
                packet_transport_type: PacketTransportType {
                    header_type: HeaderType::Tsb,
                    header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
                },
                source_position_vector: LongPositionVector::decode([0u8; 24]),
                traffic_class: TrafficClass {
                    scf: false,
                    channel_offload: false,
                    tc_id: 0,
                },
                destination_area: None,
                destination: None,
                remaining_packet_lifetime: None,
                remaining_hop_limit: None,
                security: None,
                length: data.len() as u16,
                data,
            });
        }
        let start = std::time::Instant::now();
        while cxl.queued() < 2 && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(cxl.queued(), 2);
        btp.shutdown();
    }

    /// A broadcast list that does not verify neither stops nor starts anything.
    #[test]
    fn invalid_broadcast_ignored() {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let rca = w.rca.clone();
        let crl = w.crl(&rca, &[], 0);
        iut.receive(&w, &crl).unwrap();
        let mut tampered = crl.clone();
        *tampered.last_mut().unwrap() ^= 1;
        neighbour_broadcast(&mut w, &mut iut, &tampered, CRL_PORT);
        assert_eq!(
            iut.cxl.broadcasting(),
            vec![(ListKind::Crl, rca.as_hashedid8())]
        );
    }

    /// Full CTL broadcast (clause 5.5) is not implemented.
    #[test]
    fn full_ctl_not_broadcast_and_full_ctl_request_ignored() {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let rca = w.rca.clone();
        let ectl = w.ectl(&[&rca], 3600);
        iut.receive(&w, &ectl).unwrap();
        iut.cxl
            .on_requests(&[TrustListRequest::FullCtl(EtsiTs102941FullCtlRequest::new(
                super::super::conformance_dist::h8(w.tlm.as_hashedid8()),
                None,
                None,
            ))]);
        iut.run(&w, 2000, 100);
        assert!(frames(&iut.station, 0).is_empty());
    }

    #[test]
    fn request_for_a_list_not_held_or_not_newer() {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, false);
        let rca = w.rca.clone();
        let crl = w.crl(&rca, &[], 0);
        iut.receive(&w, &crl).unwrap();
        let t = iut
            .info((ListKind::Crl, rca.as_hashedid8()))
            .unwrap()
            .this_update;
        iut.cxl.on_requests(&[
            crl_request([0x22; 8], None),
            crl_request(rca.as_hashedid8(), t),
        ]);
        iut.station.flush_btp();
        assert!(frames(&iut.station, 0).is_empty());
    }

    /// Clause 5.3.6: the nextUpdate of the CRL reached starts a CRL request, which
    /// ends when the next CRL is received.
    #[test]
    fn crl_next_update_starts_a_request_ended_by_the_crl() {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, false);
        let rca = w.rca.clone();
        let crl = w.crl(&rca, &[], 0);
        iut.receive(&w, &crl).unwrap();
        let next = iut
            .info((ListKind::Crl, rca.as_hashedid8()))
            .unwrap()
            .next_update;
        let base = time32(w.clock.base_ms as f64 / 1000.0);
        w.clock.set((next - base + 1) as u64 * 1000);
        iut.tick();
        assert_eq!(
            iut.cxl.pending_requests(),
            vec![(ListKind::Crl, rca.as_hashedid8())]
        );
        let newer = w.crl(&rca, &[], 0);
        neighbour_broadcast(&mut w, &mut iut, &newer, CRL_PORT);
        assert!(iut.cxl.pending_requests().is_empty());
    }

    #[test]
    fn ctl_request_ends_at_next_update() {
        let mut w = TrustWorld::new();
        let mut iut = cxl_iut(&mut w, true);
        let (rca, aa) = (w.rca.clone(), w.aa.clone());
        let ctl = w.rca_ctl(&rca, &[&aa], 60);
        iut.receive(&w, &ctl).unwrap();
        iut.cxl.request_ctl(rca.as_hashedid8());
        w.clock.set(61_000);
        iut.tick();
        assert!(iut.cxl.pending_requests().is_empty());
    }

    /// One request per CAM, the pending ones in turn (clause 5.3.2).
    #[test]
    fn requests_in_turn() {
        let mut w = TrustWorld::new();
        let iut = cxl_iut(&mut w, true);
        iut.cxl.request_crl(w.rca.as_hashedid8());
        iut.cxl.request_ctl(w.tlm.as_hashedid8());
        let ids: Vec<u8> = (0..4)
            .map(|_| iut.cxl.next_request().unwrap().id())
            .collect();
        assert_eq!(ids, vec![1, 2, 1, 2]);
        assert_eq!(
            iut.cxl.next_request(),
            Some(crl_request(w.rca.as_hashedid8(), None))
        );
        assert_eq!(
            iut.cxl.next_request(),
            Some(ctl_request(w.tlm.as_hashedid8(), None))
        );
    }

    struct Down;

    impl PkiTransport for Down {
        fn post(&self, _: &str, _: &[u8], _: &str) -> Result<Vec<u8>, PkiTransportError> {
            Err(PkiTransportError("down".into()))
        }
        fn get(&self, _: &str) -> Result<Vec<u8>, PkiTransportError> {
            Err(PkiTransportError("down".into()))
        }
    }

    #[test]
    fn without_policy_one_transmission() {
        assert!(post_with_retry(&Down, "u", b"m", "t", None).is_err());
    }

    /// Clause 5.1.4: TH2 > TH1 x N1.
    #[test]
    fn policy_defaults_meet_th2_above_th1_times_n1() {
        let p = RetryPolicy::default();
        assert!(p.th2 > p.th1 * p.n1 as f64);
    }
}

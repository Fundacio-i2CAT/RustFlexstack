// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Test system PKI for the ITS-S PKI conformance tests (ETSI TS 103 525-2
//! V2.1.1 configurations CFG_ENR_ITS-S and CFG_AUTH_ITS-S): a Root CA, an EA
//! and an AA with encryption keys, written independently of the client code.
//! The EA and AA decrypt the requests (ECIES recipient side, IEEE 1609.2
//! clause 5.3.5), check every layer, record what they received, and answer as
//! TS 102 941 V2.2.1 clauses 6.2.3.2.2 and 6.2.3.3.2 specify.
//!
//! Mirrors `tests/flexstack/security/pki_client/ts_pki.py`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use aes::Aes128;
use ccm::aead::{Aead, KeyInit};
use ccm::consts::{U12, U16};
use ccm::Ccm;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use rasn::prelude::*;
use sha2::{Digest, Sha256};

use crate::security::certificate::{
    encode_ieee1609_dot2_data, encode_tbs_data, Certificate, OwnCertificate,
};
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::pki_asn::etsi_ts102941_base_types::EcSignature;
use crate::security::pki_asn::etsi_ts102941_messages_itss::{
    EtsiTs102941Data, EtsiTs102941DataContent,
};
use crate::security::pki_asn::etsi_ts102941_types_authorization::{
    AuthorizationResponseCode, InnerAtRequest, InnerAtResponse,
};
use crate::security::pki_asn::etsi_ts102941_types_enrolment::{
    EnrolmentResponseCode, InnerEcRequest, InnerEcResponse,
};
use crate::security::pki_asn::{decode, encode};
use crate::security::pki_client::transport::{PkiTransport, PkiTransportError};
use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::security_asn::ieee1609_dot2::{
    Certificate as AsnCertificate, CertificateBase, CertificateType, EncryptedData,
    EncryptedDataEncryptionKey, HashedData, HeaderInfo, Ieee1609Dot2Content, Ieee1609Dot2Data,
    IssuerIdentifier, One28BitCcmCiphertext, PreSharedKeyRecipientInfo, RecipientInfo,
    SequenceOfRecipientInfo, SignedData, SignedDataPayload, SignerIdentifier, SymmetricCiphertext,
    ToBeSignedCertificate, ToBeSignedData, VerificationKeyIndicator,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    BasePublicEncryptionKey, BitmapSsp, Duration as AsnDuration, EccP256CurvePoint, HashAlgorithm,
    HashedId8, Opaque, Psid, PsidSsp, PublicEncryptionKey, PublicVerificationKey,
    SequenceOfPsidSsp, ServiceSpecificPermissions, SymmAlgorithm, Time64, Uint16, Uint64, Uint8,
};
use crate::security::time_service::timestamp_its_microseconds;
use crate::security::verify_service::security_checks::{at_tbs, ca_tbs};

pub const PSID_CERT_REQUEST: u64 = 623;
pub const PSID_CRL: u64 = 622;
pub const PSID_CTL: u64 = 624;

type Aes128Ccm = Ccm<Aes128, U16, U12>;

pub fn psid_ssp(psid: u64, ssp: Option<&[u8]>) -> PsidSsp {
    PsidSsp::new(
        Psid(Integer::from(psid)),
        ssp.map(|s| ServiceSpecificPermissions::bitmapSsp(BitmapSsp(s.to_vec().into()))),
    )
}

/// Root CA permissions: sign CRLs (SSP version 1, clause B.3) and Root CA CTLs
/// with EA, AA and DC entries (SSP 0x38, clause B.2).
pub fn root_permissions() -> SequenceOfPsidSsp {
    SequenceOfPsidSsp(vec![
        psid_ssp(PSID_CRL, Some(&[1])),
        psid_ssp(PSID_CTL, Some(&[1, 0x38])),
    ])
}

/// Signature of an Ieee1609Dot2Data signedData over Hash(Hash(tbs) || Hash(signer)).
pub fn signed_ok(
    data: &Ieee1609Dot2Data,
    key: &PublicVerificationKey,
    signer_bytes: &[u8],
) -> bool {
    let Ieee1609Dot2Content::signedData(sd) = &data.content else {
        return false;
    };
    let sha384 = sd.hash_id == HashAlgorithm::sha384;
    let hash = |b: &[u8]| -> Vec<u8> {
        if sha384 {
            sha2::Sha384::digest(b).to_vec()
        } else {
            Sha256::digest(b).to_vec()
        }
    };
    let input = [hash(&encode_tbs_data(&sd.tbs_data)), hash(signer_bytes)].concat();
    EcdsaBackend::new().verify_with_pk(&input, &sd.signature, key)
}

pub fn signed_data(data: &Ieee1609Dot2Data) -> &SignedData {
    match &data.content {
        Ieee1609Dot2Content::signedData(sd) => sd,
        _ => panic!("not signedData"),
    }
}

pub fn unsecured(data: &Ieee1609Dot2Data) -> Vec<u8> {
    match &data.content {
        Ieee1609Dot2Content::unsecuredData(o) => o.0.to_vec(),
        Ieee1609Dot2Content::signedData(sd) => {
            match sd.tbs_data.payload.data.as_ref().map(|d| &d.content) {
                Some(Ieee1609Dot2Content::unsecuredData(o)) => o.0.to_vec(),
                _ => panic!("no unsecured payload"),
            }
        }
        _ => panic!("not unsecured / signed"),
    }
}

fn kdf2(shared: &[u8], p1: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < length {
        out.extend_from_slice(&Sha256::digest(
            [shared, &counter.to_be_bytes(), p1].concat(),
        ));
        counter += 1;
    }
    out.truncate(length);
    out
}

/// An EA or AA: its certificate (with an encryption key) and the private keys.
#[derive(Clone)]
pub struct Authority {
    pub own: OwnCertificate,
    pub encryption_private: p256::SecretKey,
}

impl Authority {
    /// ECIES + AES-CCM decryption of an EtsiTs103097Data-Encrypted for this
    /// authority (one certRecipInfo with its HashedId8); (plaintext, AES key).
    pub fn decrypt(&self, data: &Ieee1609Dot2Data) -> (Vec<u8>, [u8; 16]) {
        let Ieee1609Dot2Content::encryptedData(encrypted) = &data.content else {
            panic!("not encryptedData")
        };
        assert_eq!(encrypted.recipients.0.len(), 1);
        let RecipientInfo::certRecipInfo(recipient) = &encrypted.recipients.0[0] else {
            panic!("not certRecipInfo")
        };
        assert_eq!(recipient.recipient_id.0.as_ref(), self.own.as_hashedid8());
        let EncryptedDataEncryptionKey::eciesNistP256(key) = &recipient.enc_key else {
            panic!("not eciesNistP256")
        };
        let v = match &key.v {
            EccP256CurvePoint::compressed_y_0(x) => [&[2u8][..], x.as_ref()].concat(),
            EccP256CurvePoint::compressed_y_1(x) => [&[3u8][..], x.as_ref()].concat(),
            _ => panic!("v not compressed"),
        };
        let v = p256::PublicKey::from_sec1_bytes(&v).unwrap();
        let shared =
            p256::ecdh::diffie_hellman(self.encryption_private.to_nonzero_scalar(), v.as_affine());
        let keys = kdf2(
            shared.raw_secret_bytes(),
            &Sha256::digest(self.own.to_canonical().encode()),
            48,
        );
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&keys[16..]).unwrap();
        mac.update(key.c.as_ref());
        assert_eq!(&mac.finalize().into_bytes()[..16], key.t.as_ref(), "MAC");
        let session_key: [u8; 16] = key
            .c
            .iter()
            .zip(&keys[..16])
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let SymmetricCiphertext::aes128ccm(ciphertext) = &encrypted.ciphertext else {
            panic!("not aes128ccm")
        };
        let nonce: [u8; 12] = ciphertext.nonce.as_ref().try_into().unwrap();
        let plaintext = Aes128Ccm::new_from_slice(&session_key)
            .unwrap()
            .decrypt((&nonce).into(), ciphertext.ccm_ciphertext.0.as_ref())
            .unwrap();
        (plaintext, session_key)
    }
}

/// What an authority received, decoded layer by layer.
#[derive(Clone)]
pub struct Received {
    pub raw: Vec<u8>,
    pub encrypted: Ieee1609Dot2Data,
    pub session_key: [u8; 16],
    /// EtsiTs103097Data-Signed (or unsecured, for an AT request without POP).
    pub outer: Ieee1609Dot2Data,
    pub etsi: EtsiTs102941Data,
    pub inner_ec: Option<InnerEcRequest>,
    pub inner_at: Option<InnerAtRequest>,
    /// InnerEcRequestSignedForPop.
    pub pop: Option<Ieee1609Dot2Data>,
    /// The decrypted EtsiTs103097Data-SignedExternalPayload.
    pub ec_signature: Option<Ieee1609Dot2Data>,
    pub checks: BTreeMap<&'static str, bool>,
}

impl Received {
    pub fn ec(&self) -> &InnerEcRequest {
        self.inner_ec.as_ref().unwrap()
    }
    pub fn at(&self) -> &InnerAtRequest {
        self.inner_at.as_ref().unwrap()
    }
    pub fn ok(&self) -> bool {
        self.checks.values().all(|v| *v)
    }
}

fn authority(backend: &mut EcdsaBackend, root: &OwnCertificate) -> Authority {
    use p256::elliptic_curve::rand_core::OsRng;
    let private = p256::SecretKey::random(&mut OsRng);
    let encoded = private.public_key().to_encoded_point(true);
    let x = encoded.x().unwrap().to_vec().into();
    let point = if encoded.as_bytes()[0] == 2 {
        EccP256CurvePoint::compressed_y_0(x)
    } else {
        EccP256CurvePoint::compressed_y_1(x)
    };
    let mut tbs = ca_tbs();
    tbs.encryption_key = Some(PublicEncryptionKey::new(
        SymmAlgorithm::aes128Ccm,
        BasePublicEncryptionKey::eciesNistP256(point),
    ));
    Authority {
        own: OwnCertificate::initialize_issued(backend, tbs, root),
        encryption_private: private,
    }
}

/// Root CA, EA and AA of the test system; `enrol` / `authorize` answer requests.
pub struct TsPki {
    pub backend: EcdsaBackend,
    pub root: OwnCertificate,
    pub ea: Authority,
    pub aa: Authority,
    pub ea_code: EnrolmentResponseCode,
    pub aa_code: AuthorizationResponseCode,
    /// itsId -> canonical public key (registered out of band).
    pub canonical_keys: HashMap<Vec<u8>, PublicVerificationKey>,
    pub ec_permissions: SequenceOfPsidSsp,
    pub ec_duration: AsnDuration,
    /// Certify this key instead of the requested one (negative tests).
    pub ec_key_override: Option<PublicVerificationKey>,
    pub enrolments: Vec<Received>,
    pub authorizations: Vec<Received>,
    pub issued_ecs: Vec<Certificate>,
}

impl TsPki {
    pub fn new() -> Self {
        let mut backend = EcdsaBackend::new();
        let mut root_tbs = ca_tbs();
        root_tbs.app_permissions = Some(root_permissions());
        let root = OwnCertificate::initialize_self_signed(&mut backend, root_tbs);
        let ea = authority(&mut backend, &root);
        let aa = authority(&mut backend, &root);
        Self {
            backend,
            root,
            ea,
            aa,
            ea_code: EnrolmentResponseCode::ok,
            aa_code: AuthorizationResponseCode::ok,
            canonical_keys: HashMap::new(),
            ec_permissions: SequenceOfPsidSsp(vec![psid_ssp(PSID_CERT_REQUEST, Some(&[1, 0xC0]))]),
            ec_duration: AsnDuration::years(Uint16(1)),
            ec_key_override: None,
            enrolments: vec![],
            authorizations: vec![],
            issued_ecs: vec![],
        }
    }

    /// Register a canonical identifier and key (manufacturing, out of band).
    pub fn register(&mut self, its_id: &[u8], key: PublicVerificationKey) {
        self.canonical_keys.insert(its_id.to_vec(), key);
    }

    fn issue(
        &self,
        issuer: &OwnCertificate,
        key: &PublicVerificationKey,
        permissions: SequenceOfPsidSsp,
        duration: AsnDuration,
    ) -> Certificate {
        let mut tbs: ToBeSignedCertificate = at_tbs(-60, duration, None);
        tbs.app_permissions = Some(permissions);
        tbs.verify_key_indicator = VerificationKeyIndicator::verificationKey(key.clone());
        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            IssuerIdentifier::sha256AndDigest(HashedId8(FixedOctetString::from([0u8; 8]))),
            tbs,
            None,
        );
        let target = Certificate::from_asn(
            EtsiTs103097Certificate(AsnCertificate(base)),
            Some(issuer.cert.clone()),
        );
        issuer.issue_certificate(&self.backend, &target)
    }

    fn respond(
        &self,
        authority: &Authority,
        received: &Received,
        content: EtsiTs102941DataContent,
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
                Psid(Integer::from(PSID_CERT_REQUEST)),
                Some(Time64(Uint64(timestamp_its_microseconds()))),
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
        let signature = authority
            .own
            .sign_message(&self.backend, &encode_tbs_data(&tbs));
        let signed = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::signedData(SignedData::new(
                HashAlgorithm::sha256,
                tbs,
                SignerIdentifier::digest(HashedId8(FixedOctetString::from(
                    authority.own.as_hashedid8(),
                ))),
                signature,
            )),
        );
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = Aes128Ccm::new_from_slice(&received.session_key)
            .unwrap()
            .encrypt(
                (&nonce).into(),
                encode_ieee1609_dot2_data(&signed).as_slice(),
            )
            .unwrap();
        let psk: [u8; 8] = Sha256::digest([&[0x80u8][..], &received.session_key].concat())[24..]
            .try_into()
            .unwrap();
        encode_ieee1609_dot2_data(&Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::encryptedData(EncryptedData::new(
                SequenceOfRecipientInfo(vec![RecipientInfo::pskRecipInfo(
                    PreSharedKeyRecipientInfo(HashedId8(FixedOctetString::from(psk))),
                )]),
                SymmetricCiphertext::aes128ccm(One28BitCcmCiphertext::new(
                    nonce.to_vec().into(),
                    Opaque(ciphertext.into()),
                )),
            )),
        ))
    }

    fn request_hash(received: &Received) -> FixedOctetString<16> {
        FixedOctetString::from(<[u8; 16]>::try_from(&Sha256::digest(&received.raw)[..16]).unwrap())
    }

    /// EA: read an EnrolmentRequestMessage, check it, answer with an EC (or `ea_code`).
    pub fn enrol(&mut self, raw: &[u8]) -> Vec<u8> {
        let encrypted: Ieee1609Dot2Data = decode(raw).unwrap();
        let (plaintext, session_key) = self.ea.decrypt(&encrypted);
        let outer: Ieee1609Dot2Data = decode(&plaintext).unwrap();
        let etsi: EtsiTs102941Data = decode(&unsecured(&outer)).unwrap();
        let EtsiTs102941DataContent::enrolmentRequest(pop) = etsi.content.clone() else {
            panic!("not enrolmentRequest")
        };
        let inner: InnerEcRequest = decode(&unsecured(&pop)).unwrap();
        let new_key = inner.public_keys.verification_key.clone();
        let mut checks = BTreeMap::new();
        checks.insert("pop", signed_ok(&pop, &new_key, &[]));
        let outer_ok = match &signed_data(&outer).signer {
            SignerIdentifier::R_self(()) => self
                .canonical_keys
                .get(inner.its_id.as_ref())
                .is_some_and(|key| signed_ok(&outer, key, &[])),
            SignerIdentifier::digest(h) => self
                .issued_ecs
                .iter()
                .find(|c| c.as_hashedid8() == h.0.as_ref())
                .is_some_and(|ec| {
                    signed_ok(
                        &outer,
                        &ec.verification_key().unwrap(),
                        ec.to_canonical().encode(),
                    )
                }),
            _ => false,
        };
        checks.insert("outer", outer_ok);
        let received = Received {
            raw: raw.to_vec(),
            encrypted,
            session_key,
            outer,
            etsi,
            inner_ec: Some(inner),
            inner_at: None,
            pop: Some(pop),
            ec_signature: None,
            checks,
        };
        let code = if received.ok() {
            self.ea_code
        } else {
            EnrolmentResponseCode::invalidsignature
        };
        let certificate = (code == EnrolmentResponseCode::ok).then(|| {
            self.issue(
                &self.ea.own,
                self.ec_key_override.as_ref().unwrap_or(&new_key),
                self.ec_permissions.clone(),
                self.ec_duration.clone(),
            )
        });
        if let Some(c) = &certificate {
            self.issued_ecs.push(c.clone());
        }
        let response = self.respond(
            &self.ea,
            &received,
            EtsiTs102941DataContent::enrolmentResponse(InnerEcResponse::new(
                Self::request_hash(&received),
                code,
                certificate.map(|c| c.inner),
            )),
        );
        self.enrolments.push(received);
        response
    }

    /// AA (validating with the EA's key): read an AuthorizationRequestMessage
    /// [WithPop], check POP, keyTag and the EC signature, answer with an AT.
    pub fn authorize(&mut self, raw: &[u8]) -> Vec<u8> {
        let encrypted: Ieee1609Dot2Data = decode(raw).unwrap();
        let (plaintext, session_key) = self.aa.decrypt(&encrypted);
        let outer: Ieee1609Dot2Data = decode(&plaintext).unwrap();
        let etsi: EtsiTs102941Data = decode(&unsecured(&outer)).unwrap();
        let EtsiTs102941DataContent::authorizationRequest(inner) = etsi.content.clone() else {
            panic!("not authorizationRequest")
        };
        let mut checks = BTreeMap::new();
        let keys = &inner.public_keys;
        if matches!(outer.content, Ieee1609Dot2Content::signedData(_)) {
            checks.insert("pop", signed_ok(&outer, &keys.verification_key, &[]));
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(inner.hmac_key.as_ref()).unwrap();
        mac.update(&encode(&keys.verification_key));
        if let Some(k) = &keys.encryption_key {
            mac.update(&encode(k));
        }
        checks.insert(
            "keyTag",
            mac.finalize().into_bytes()[..16] == *inner.shared_at_request.key_tag.as_ref(),
        );
        let ec_signature = match &inner.ec_signature {
            EcSignature::encryptedEcSignature(data) => decode(&self.ea.decrypt(data).0).unwrap(),
            EcSignature::ecSignature(data) => data.clone(),
        };
        let signed = signed_data(&ec_signature);
        let expected: [u8; 32] = Sha256::digest(encode(&inner.shared_at_request)).into();
        let hash_ok = matches!(&signed.tbs_data.payload.ext_data_hash,
            Some(HashedData::sha256HashedData(h)) if h.0.as_ref() == expected);
        let ec_ok = self
            .issued_ecs
            .iter()
            .find(|c| {
                signed.signer
                    == SignerIdentifier::digest(HashedId8(FixedOctetString::from(c.as_hashedid8())))
            })
            .is_some_and(|ec| {
                signed_ok(
                    &ec_signature,
                    &ec.verification_key().unwrap(),
                    ec.to_canonical().encode(),
                )
            });
        checks.insert("ecSignature", hash_ok && ec_ok);
        let received = Received {
            raw: raw.to_vec(),
            encrypted,
            session_key,
            outer,
            etsi,
            inner_ec: None,
            inner_at: Some(inner.clone()),
            pop: None,
            ec_signature: Some(ec_signature),
            checks,
        };
        let code = if received.ok() {
            self.aa_code
        } else {
            AuthorizationResponseCode::invalidsignature
        };
        let permissions = inner
            .shared_at_request
            .requested_subject_attributes
            .app_permissions
            .clone()
            .unwrap_or(SequenceOfPsidSsp(vec![]));
        let certificate = (code == AuthorizationResponseCode::ok).then(|| {
            self.issue(
                &self.aa.own,
                &keys.verification_key,
                permissions,
                AsnDuration::hours(Uint16(1)),
            )
        });
        let response = self.respond(
            &self.aa,
            &received,
            EtsiTs102941DataContent::authorizationResponse(InnerAtResponse::new(
                Self::request_hash(&received),
                code,
                certificate.map(|c| c.inner),
            )),
        );
        self.authorizations.push(received);
        response
    }
}

/// A POST received: (url, body, content type).
pub type Post = (String, Vec<u8>, String);

/// In-memory transport to the test system: records every POST and GET.
#[derive(Clone)]
pub struct Transport {
    pub pki: Arc<Mutex<TsPki>>,
    pub ea_url: String,
    pub aa_url: String,
    pub posts: Arc<Mutex<Vec<Post>>>,
    pub gets: Arc<Mutex<Vec<String>>>,
    pub files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Clock recording the instant of every POST in `times`.
    pub clock: Arc<Mutex<Option<crate::security::pki_client::client::PkiClock>>>,
    pub times: Arc<Mutex<Vec<f64>>>,
    /// Number of the next responses lost.
    pub lose: Arc<Mutex<u32>>,
    answered: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl Transport {
    pub fn new(pki: Arc<Mutex<TsPki>>) -> Self {
        Self {
            pki,
            ea_url: "https://ea.ts/".into(),
            aa_url: "https://aa.ts/".into(),
            posts: Arc::default(),
            gets: Arc::default(),
            files: Arc::default(),
            clock: Arc::default(),
            times: Arc::default(),
            lose: Arc::default(),
            answered: Arc::default(),
        }
    }
}

impl PkiTransport for Transport {
    fn post(
        &self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<Vec<u8>, PkiTransportError> {
        self.posts
            .lock()
            .unwrap()
            .push((url.to_string(), body.to_vec(), content_type.to_string()));
        if let Some(clock) = self.clock.lock().unwrap().as_ref() {
            self.times.lock().unwrap().push(clock());
        }
        // A repeated request gets the response already generated (the EA / AA
        // side of the retry, TS 103 601 clauses 5.1.4 and 5.2.4).
        let key = Sha256::digest(body).to_vec();
        let known = self.answered.lock().unwrap().get(&key).cloned();
        let response = match known {
            Some(r) => r,
            None => {
                let r = if url == self.ea_url {
                    self.pki.lock().unwrap().enrol(body)
                } else if url == self.aa_url {
                    self.pki.lock().unwrap().authorize(body)
                } else {
                    return Err(PkiTransportError(format!("unknown {url}")));
                };
                self.answered.lock().unwrap().insert(key, r.clone());
                r
            }
        };
        let mut lose = self.lose.lock().unwrap();
        if *lose > 0 {
            *lose -= 1;
            return Err(PkiTransportError(format!("POST {url}: response lost")));
        }
        Ok(response)
    }

    fn get(&self, url: &str) -> Result<Vec<u8>, PkiTransportError> {
        self.gets.lock().unwrap().push(url.to_string());
        self.files
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| PkiTransportError(format!("no file {url}")))
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ITS-S side of the ETSI TS 102 941 V2.2.1 security management messages:
//! enrolment (clause 6.2.3.2) and authorization (clause 6.2.3.3), with the
//! official ASN.1 modules ([`crate::security::pki_asn`]).
//!
//! The functions build the request messages and read the responses; they do
//! no I/O. Times are UTC seconds (`now`) so that callers can inject a clock.
//!
//! Enrolment request (clause 6.2.3.2.1, Figure 14):
//! `EtsiTs103097Data-Encrypted` (certRecipInfo of the EA, ECIES) of an
//! `EtsiTs103097Data-Signed` (signer self with the canonical key, or digest of
//! the EC) of `EtsiTs102941Data {v1, enrolmentRequest}` whose content is the
//! `InnerEcRequestSignedForPop` (signer self, new key) of the `InnerEcRequest`.
//!
//! Authorization request (clause 6.2.3.3.1, Figures 17 and 18): encrypted to
//! the AA, the `EtsiTs102941Data {v1, authorizationRequest}` either signed
//! with the new AT key (proof of possession) or unsecured; the `InnerAtRequest`
//! carries `encryptedEcSignature` (encrypted to the EA): the
//! `EtsiTs103097Data-SignedExternalPayload` by the EC over the SHA-256 hash of
//! the `SharedAtRequest`.
//!
//! Responses (clauses 6.2.3.2.2 and 6.2.3.3.2): encrypted with the request's
//! AES key (pskRecipInfo), signed by the EA / AA (signer digest), with the
//! leftmost 16 octets of SHA-256 of the request as requestHash.

use std::fmt;

use aes::Aes128;
use ccm::aead::{Aead, KeyInit};
use ccm::consts::{U12, U16};
use ccm::Ccm;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rasn::prelude::*;
use sha2::{Digest, Sha256};

use crate::security::certificate::{
    encode_ieee1609_dot2_data, encode_tbs_data, signing_input, Certificate, OwnCertificate,
};
use crate::security::ecdsa_backend::{key_uses_sha384, EcdsaBackend, KeyAlgorithm};
use crate::security::pki_asn::etsi_ts102941_base_types::{
    CertificateSubjectAttributes, EcSignature, PublicKeys, TS103097V131,
};
use crate::security::pki_asn::etsi_ts102941_messages_itss::{
    EtsiTs102941Data, EtsiTs102941DataContent,
};
use crate::security::pki_asn::etsi_ts102941_types_authorization::{
    InnerAtRequest, InnerAtResponse, SharedAtRequest,
};
use crate::security::pki_asn::etsi_ts102941_types_enrolment::{InnerEcRequest, InnerEcResponse};
use crate::security::pki_asn::{decode, encode};
use crate::security::security_asn::ieee1609_dot2::{
    EncryptedData, EncryptedDataEncryptionKey, HashedData, HeaderInfo, Ieee1609Dot2Content,
    Ieee1609Dot2Data, One28BitCcmCiphertext, PKRecipientInfo, PreSharedKeyRecipientInfo,
    RecipientInfo, SequenceOfRecipientInfo, SignedData, SignedDataPayload, SignerIdentifier,
    SymmetricCiphertext, ToBeSignedData,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    BasePublicEncryptionKey, EccP256CurvePoint, EciesP256EncryptedKey, HashAlgorithm, HashedId32,
    HashedId8, Opaque, Psid, PublicVerificationKey, ServiceSpecificPermissions,
    SymmetricEncryptionKey, Time64, Uint64, Uint8,
};
use crate::security::time_service::{ELAPSED_SECONDS, ITS_EPOCH};

/// ITS-AID "secured certificate request" (ETSI TS 102 965).
pub const PSID_CERT_REQUEST: u64 = 623;
/// Certificate request SSP (clause B.4): version 1, then the permission bits.
pub const SSP_VERSION: u8 = 1;
pub const SSP_ENROLMENT_REQUEST: u8 = 0x80;
pub const SSP_AUTHORIZATION_REQUEST: u8 = 0x40;
/// HTTP content types (Annex C).
pub const CT_REQUEST: &str = "application/x-its-request";
pub const CT_RESPONSE: &str = "application/x-its-response";

type Aes128Ccm = Ccm<Aes128, U16, U12>;

/// A response cannot be read or does not match the request (`code` names the check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiProtocolError {
    pub code: String,
    pub message: String,
}

impl PkiProtocolError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for PkiProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PkiProtocolError {}

// ─── Time and permissions ───────────────────────────────────────────────────

/// Time32 (TAI seconds since the ITS epoch, IEEE 1609.2 clause 6.4.15).
pub fn time32(now: f64) -> u32 {
    (now as i64 - ITS_EPOCH as i64 + ELAPSED_SECONDS as i64) as u32
}

/// Time64 (TAI microseconds since the ITS epoch), as generationTime.
pub fn time64(now: f64) -> u64 {
    ((now - ITS_EPOCH as f64 + ELAPSED_SECONDS as f64) * 1e6).round() as u64
}

/// Leftmost 16 octets of SHA-256 of the request's EtsiTs103097Data-Encrypted.
pub fn request_hash(request: &[u8]) -> [u8; 16] {
    Sha256::digest(request)[..16].try_into().unwrap()
}

/// The certificate's appPermissions grant ITS-AID 623 with SSP version 1 and
/// `bit` (clause B.4: 0x80 enrolment request, 0x40 authorization request).
pub fn ssp_permits(certificate: &Certificate, bit: u8) -> bool {
    let Some(permissions) = &certificate.tbs().app_permissions else {
        return false;
    };
    for item in &permissions.0 {
        if u64::try_from(&item.psid.0).ok() != Some(PSID_CERT_REQUEST) {
            continue;
        }
        let value: Vec<u8> = match &item.ssp {
            Some(ServiceSpecificPermissions::bitmapSsp(b)) => b.0.to_vec(),
            Some(ServiceSpecificPermissions::opaque(o)) => o.to_vec(),
            _ => return false,
        };
        return value.len() >= 2 && value[0] == SSP_VERSION && value[1] & bit != 0;
    }
    false
}

/// The SSP an EC requests: version 1, enrolment and authorization requests.
pub fn certificate_ssp() -> ServiceSpecificPermissions {
    ServiceSpecificPermissions::bitmapSsp(
        crate::security::security_asn::ieee1609_dot2_base_types::BitmapSsp(
            vec![
                SSP_VERSION,
                SSP_ENROLMENT_REQUEST | SSP_AUTHORIZATION_REQUEST,
            ]
            .into(),
        ),
    )
}

// ─── Signing ────────────────────────────────────────────────────────────────

fn header_info(now: f64) -> HeaderInfo {
    HeaderInfo::new(
        Psid(Integer::from(PSID_CERT_REQUEST)),
        Some(Time64(Uint64(time64(now)))),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

/// SignedDataPayload `data` = unsecured EtsiTs103097Data containing `content`.
pub fn data_payload(content: Vec<u8>) -> SignedDataPayload {
    SignedDataPayload::new(
        Some(Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::unsecuredData(Opaque(content.into())),
        )),
        None,
        None,
    )
}

/// An EtsiTs103097Data-Signed with headerInfo {psid 623, generationTime} only.
/// The signer is `self` when `signer` is None (signature input with the empty
/// signer, IEEE 1609.2 clause 5.3.1), else the digest of `signer`.
pub fn sign(
    backend: &EcdsaBackend,
    key_id: usize,
    payload: SignedDataPayload,
    now: f64,
    signer: Option<&Certificate>,
) -> Ieee1609Dot2Data {
    let tbs = ToBeSignedData::new(Box::new(payload), header_info(now));
    let tbs_bytes = encode_tbs_data(&tbs);
    let sha384 = key_uses_sha384(&backend.get_public_key(key_id));
    let (signer_id, signer_bytes) = match signer {
        None => (SignerIdentifier::R_self(()), Vec::new()),
        Some(c) => (
            SignerIdentifier::digest(HashedId8(FixedOctetString::from(c.as_hashedid8()))),
            c.to_canonical().encode().to_vec(),
        ),
    };
    let signature = backend.sign(&signing_input(&tbs_bytes, &signer_bytes, sha384), key_id);
    let hash_id = if sha384 {
        HashAlgorithm::sha384
    } else {
        HashAlgorithm::sha256
    };
    Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::signedData(SignedData::new(hash_id, tbs, signer_id, signature)),
    )
}

fn signed(data: &Ieee1609Dot2Data) -> Result<&SignedData, PkiProtocolError> {
    match &data.content {
        Ieee1609Dot2Content::signedData(sd) => Ok(sd),
        _ => Err(PkiProtocolError::new(
            "badcontenttype",
            "expected signedData",
        )),
    }
}

/// Content of an EtsiTs103097Data-Signed by `signer` (signer digest, psid 623,
/// generationTime present, no other header, valid signature); errors otherwise.
pub fn read_signed(
    data: &Ieee1609Dot2Data,
    signer: &Certificate,
    backend: &EcdsaBackend,
) -> Result<Vec<u8>, PkiProtocolError> {
    let sd = signed(data)?;
    let expected =
        SignerIdentifier::digest(HashedId8(FixedOctetString::from(signer.as_hashedid8())));
    if sd.signer != expected {
        return Err(PkiProtocolError::new(
            "invalidsignature",
            "response not signed by the expected authority",
        ));
    }
    let header = &sd.tbs_data.header_info;
    if *header
        != HeaderInfo::new(
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
        )
        || u64::try_from(&header.psid.0).ok() != Some(PSID_CERT_REQUEST)
        || header.generation_time.is_none()
    {
        return Err(PkiProtocolError::new(
            "badcontenttype",
            "unexpected headerInfo",
        ));
    }
    let key = signer
        .verification_key()
        .ok_or_else(|| PkiProtocolError::new("invalidsignature", "no verification key"))?;
    let input = signing_input(
        &encode_tbs_data(&sd.tbs_data),
        signer.to_canonical().encode(),
        key_uses_sha384(&key),
    );
    if !backend.verify_with_pk(&input, &sd.signature, &key) {
        return Err(PkiProtocolError::new(
            "invalidsignature",
            "response signature does not verify",
        ));
    }
    match sd.tbs_data.payload.data.as_ref().map(|d| &d.content) {
        Some(Ieee1609Dot2Content::unsecuredData(o)) => Ok(o.0.to_vec()),
        _ => Err(PkiProtocolError::new(
            "badcontenttype",
            "signed payload is not unsecuredData",
        )),
    }
}

// ─── Encryption (IEEE 1609.2 clauses 5.3.5, 5.3.8; TS 103 097 clause 5.3) ───

fn kdf2(shared: &[u8], p1: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut h = Sha256::new();
        h.update(shared);
        h.update(counter.to_be_bytes());
        h.update(p1);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

fn sec1(point: &EccP256CurvePoint) -> Option<Vec<u8>> {
    match point {
        EccP256CurvePoint::compressed_y_0(x) => Some([&[2u8][..], x.as_ref()].concat()),
        EccP256CurvePoint::compressed_y_1(x) => Some([&[3u8][..], x.as_ref()].concat()),
        EccP256CurvePoint::uncompressedP256(u) => {
            Some([&[4u8][..], u.x.as_ref(), u.y.as_ref()].concat())
        }
        _ => None,
    }
}

fn point(compressed: &[u8]) -> EccP256CurvePoint {
    let x = compressed[1..33].to_vec().into();
    if compressed[0] == 2 {
        EccP256CurvePoint::compressed_y_0(x)
    } else {
        EccP256CurvePoint::compressed_y_1(x)
    }
}

/// (compressed ephemeral public key, shared x) for a NIST P-256 recipient.
fn ecdh_p256(recipient: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let public = p256::PublicKey::from_sec1_bytes(recipient).ok()?;
    let ephemeral = p256::SecretKey::random(&mut rand::thread_rng());
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), public.as_affine());
    Some((
        ephemeral
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        shared.raw_secret_bytes().to_vec(),
    ))
}

/// (compressed ephemeral public key, shared x) for a brainpoolP256r1 recipient.
fn ecdh_bp256(recipient: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    use ecdsa_v017::elliptic_curve::point::AffineCoordinates;
    use ecdsa_v017::elliptic_curve::sec1::ToSec1Point;
    use ecdsa_v017::elliptic_curve::{PublicKey, SecretKey};
    type C = bp256::BrainpoolP256r1;
    let public = PublicKey::<C>::from_sec1_bytes(recipient).ok()?;
    let ephemeral = loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::<C>::from_slice(&bytes) {
            break key;
        }
    };
    let shared = (public.to_projective() * *ephemeral.to_nonzero_scalar()).to_affine();
    Some((
        ephemeral
            .public_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
        shared.x().to_vec(),
    ))
}

/// HashedId8 of the COER SymmetricEncryptionKey {aes128Ccm} holding `key`
/// (pskRecipInfo, IEEE 1609.2 clause 6.3.34).
pub fn psk_id(key: &[u8; 16]) -> [u8; 8] {
    let encoded = encode(&SymmetricEncryptionKey::aes128Ccm(key.to_vec().into()));
    Sha256::digest(encoded)[24..].try_into().unwrap()
}

/// EtsiTs103097Data-Encrypted for the encryption key of `certificate`: one
/// certRecipInfo (its HashedId8), ECIES (fresh ephemeral key, KDF2 with P1 =
/// SHA-256 of the canonical certificate, MAC1) on the AES-128-CCM key, which
/// encrypts `plaintext` with a fresh nonce. Returns the data and the AES key.
pub fn encrypt_to(
    certificate: &Certificate,
    plaintext: &[u8],
) -> Result<(Ieee1609Dot2Data, [u8; 16]), PkiProtocolError> {
    let key = certificate.tbs().encryption_key.as_ref().ok_or_else(|| {
        PkiProtocolError::new(
            "invalidencryptionkey",
            "recipient certificate has no encryptionKey",
        )
    })?;
    let invalid = || PkiProtocolError::new("invalidencryptionkey", "invalid recipient key");
    let (brainpool, recipient) = match &key.public_key {
        BasePublicEncryptionKey::eciesNistP256(p) => (false, sec1(p).ok_or_else(invalid)?),
        BasePublicEncryptionKey::eciesBrainpoolP256r1(p) => (true, sec1(p).ok_or_else(invalid)?),
        _ => {
            return Err(PkiProtocolError::new(
                "unknownencryptionalgorithm",
                "unsupported curve",
            ))
        }
    };
    let (v, shared) = if brainpool {
        ecdh_bp256(&recipient)
    } else {
        ecdh_p256(&recipient)
    }
    .ok_or_else(invalid)?;
    let p1 = Sha256::digest(certificate.to_canonical().encode());
    let keys = kdf2(&shared, &p1, 48);
    let mut session_key = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut session_key);
    rand::thread_rng().fill_bytes(&mut nonce);
    let c: Vec<u8> = session_key
        .iter()
        .zip(&keys[..16])
        .map(|(a, b)| a ^ b)
        .collect();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&keys[16..]).expect("HMAC key");
    mac.update(&c);
    let tag = mac.finalize().into_bytes()[..16].to_vec();
    let encrypted_key = EciesP256EncryptedKey {
        v: point(&v),
        c: c.into(),
        t: tag.into(),
    };
    let enc_key = if brainpool {
        EncryptedDataEncryptionKey::eciesBrainpoolP256r1(encrypted_key)
    } else {
        EncryptedDataEncryptionKey::eciesNistP256(encrypted_key)
    };
    let ciphertext = Aes128Ccm::new_from_slice(&session_key)
        .expect("AES key")
        .encrypt((&nonce).into(), plaintext)
        .map_err(|_| PkiProtocolError::new("encryptionfailed", "AES-CCM"))?;
    let data = Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::encryptedData(EncryptedData::new(
            SequenceOfRecipientInfo(vec![RecipientInfo::certRecipInfo(PKRecipientInfo::new(
                HashedId8(FixedOctetString::from(certificate.as_hashedid8())),
                enc_key,
            ))]),
            SymmetricCiphertext::aes128ccm(One28BitCcmCiphertext::new(
                nonce.to_vec().into(),
                Opaque(ciphertext.into()),
            )),
        )),
    );
    Ok((data, session_key))
}

/// Decrypt a response encrypted with the request's AES key (exactly one
/// pskRecipInfo with [`psk_id`]); returns the decoded inner Ieee1609Dot2Data.
pub fn decrypt_psk(
    response: &[u8],
    session_key: &[u8; 16],
) -> Result<Ieee1609Dot2Data, PkiProtocolError> {
    let data: Ieee1609Dot2Data = decode(response).map_err(|e| {
        PkiProtocolError::new("cantparse", format!("cannot decode the response: {e}"))
    })?;
    let Ieee1609Dot2Content::encryptedData(encrypted) = data.content else {
        return Err(PkiProtocolError::new(
            "badcontenttype",
            "expected encryptedData",
        ));
    };
    let expected = vec![RecipientInfo::pskRecipInfo(PreSharedKeyRecipientInfo(
        HashedId8(FixedOctetString::from(psk_id(session_key))),
    ))];
    if encrypted.recipients.0 != expected {
        return Err(PkiProtocolError::new(
            "imnottherecipient",
            "no pskRecipInfo for the request's key",
        ));
    }
    let SymmetricCiphertext::aes128ccm(ciphertext) = encrypted.ciphertext else {
        return Err(PkiProtocolError::new(
            "badcontenttype",
            "expected aes128ccm",
        ));
    };
    let failed = || PkiProtocolError::new("decryptionfailed", "cannot decrypt the response");
    let nonce: [u8; 12] = ciphertext.nonce.as_ref().try_into().map_err(|_| failed())?;
    let plaintext = Aes128Ccm::new_from_slice(session_key)
        .expect("AES key")
        .decrypt((&nonce).into(), ciphertext.ccm_ciphertext.0.as_ref())
        .map_err(|_| failed())?;
    decode(&plaintext).map_err(|_| failed())
}

// ─── Requests ───────────────────────────────────────────────────────────────

/// A request sent: its encoding, AES key and the new key pair to certify.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub message: Vec<u8>,
    pub session_key: [u8; 16],
    pub key_id: usize,
}

impl PendingRequest {
    /// requestHash the response shall carry.
    pub fn request_hash(&self) -> [u8; 16] {
        request_hash(&self.message)
    }
}

/// EnrolmentRequestMessage (clause 6.2.3.2.1). Initial request (`current_ec`
/// None): itsId = canonical identifier `its_id`, outer signer self with the
/// canonical key `signer_key`. Re-keying: itsId = HashedId8(EC), outer signer
/// digest(EC) with the EC key. A new verification key pair is generated.
#[allow(clippy::too_many_arguments)]
pub fn build_enrolment_request(
    backend: &mut EcdsaBackend,
    ea: &Certificate,
    its_id: &[u8],
    signer_key: usize,
    current_ec: Option<&OwnCertificate>,
    attributes: CertificateSubjectAttributes,
    now: f64,
    algorithm: KeyAlgorithm,
) -> Result<PendingRequest, PkiProtocolError> {
    let key_id = backend.create_key_with(algorithm);
    let (its_id, signer_key) = match current_ec {
        Some(ec) => (ec.as_hashedid8().to_vec(), ec.key_id),
        None => (its_id.to_vec(), signer_key),
    };
    let inner = InnerEcRequest::new(
        its_id.into(),
        TS103097V131,
        PublicKeys::new(backend.get_public_key(key_id), None),
        attributes,
    );
    let pop = sign(backend, key_id, data_payload(encode(&inner)), now, None);
    let etsi = encode(&EtsiTs102941Data::new(
        EtsiTs102941DataContent::enrolmentRequest(pop),
    ));
    let outer = sign(
        backend,
        signer_key,
        data_payload(etsi),
        now,
        current_ec.map(|c| &c.cert),
    );
    let (encrypted, session_key) = encrypt_to(ea, &encode_ieee1609_dot2_data(&outer))?;
    Ok(PendingRequest {
        message: encode_ieee1609_dot2_data(&encrypted),
        session_key,
        key_id,
    })
}

fn read_response(
    response: &[u8],
    request: &PendingRequest,
    authority: &Certificate,
    backend: &EcdsaBackend,
) -> Result<EtsiTs102941DataContent, PkiProtocolError> {
    let signed = decrypt_psk(response, &request.session_key)?;
    let etsi: EtsiTs102941Data = decode(&read_signed(&signed, authority, backend)?)
        .map_err(|e| PkiProtocolError::new("cantparse", e.to_string()))?;
    Ok(etsi.content)
}

/// InnerEcResponse of an EnrolmentResponseMessage (clause 6.2.3.2.2).
pub fn read_enrolment_response(
    response: &[u8],
    request: &PendingRequest,
    ea: &Certificate,
    backend: &EcdsaBackend,
) -> Result<InnerEcResponse, PkiProtocolError> {
    match read_response(response, request, ea, backend)? {
        EtsiTs102941DataContent::enrolmentResponse(inner)
            if inner.request_hash.as_ref() == request.request_hash() =>
        {
            Ok(inner)
        }
        EtsiTs102941DataContent::enrolmentResponse(_) => Err(PkiProtocolError::new(
            "badcontenttype",
            "requestHash does not match the request",
        )),
        _ => Err(PkiProtocolError::new(
            "badcontenttype",
            "expected enrolmentResponse",
        )),
    }
}

/// keyTag: HMAC-SHA256 with `hmac_key` over the serialization of the
/// verificationKey and of the encryptionKey (if present), leftmost 128 bits.
pub fn key_tag(hmac_key: &[u8], public_keys: &PublicKeys) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hmac_key).expect("HMAC key");
    mac.update(&encode(&public_keys.verification_key));
    if let Some(key) = &public_keys.encryption_key {
        mac.update(&encode(key));
    }
    mac.finalize().into_bytes()[..16].try_into().unwrap()
}

/// AuthorizationRequestMessage (`pop` false) or
/// AuthorizationRequestMessageWithPop (clause 6.2.3.3.1), with privacy
/// (encryptedEcSignature to the EA). A new key pair and hmacKey are generated.
#[allow(clippy::too_many_arguments)]
pub fn build_authorization_request(
    backend: &mut EcdsaBackend,
    aa: &Certificate,
    ea: &Certificate,
    ec_own: &OwnCertificate,
    attributes: CertificateSubjectAttributes,
    now: f64,
    pop: bool,
    algorithm: KeyAlgorithm,
) -> Result<PendingRequest, PkiProtocolError> {
    let key_id = backend.create_key_with(algorithm);
    let public_keys = PublicKeys::new(backend.get_public_key(key_id), None);
    let mut hmac_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut hmac_key);
    let shared = SharedAtRequest::new(
        HashedId8(FixedOctetString::from(ea.as_hashedid8())),
        FixedOctetString::from(key_tag(&hmac_key, &public_keys)),
        TS103097V131,
        attributes,
    );
    let hash: [u8; 32] = Sha256::digest(encode(&shared)).into();
    let external = SignedDataPayload::new(
        None,
        Some(HashedData::sha256HashedData(HashedId32(
            FixedOctetString::from(hash),
        ))),
        None,
    );
    let ec_signature = sign(backend, ec_own.key_id, external, now, Some(&ec_own.cert));
    let (encrypted_signature, _) = encrypt_to(ea, &encode_ieee1609_dot2_data(&ec_signature))?;
    let inner = InnerAtRequest::new(
        public_keys,
        FixedOctetString::from(hmac_key),
        shared,
        EcSignature::encryptedEcSignature(encrypted_signature),
    );
    let etsi = encode(&EtsiTs102941Data::new(
        EtsiTs102941DataContent::authorizationRequest(inner),
    ));
    let plaintext = if pop {
        sign(backend, key_id, data_payload(etsi), now, None)
    } else {
        Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::unsecuredData(Opaque(etsi.into())),
        )
    };
    let (encrypted, session_key) = encrypt_to(aa, &encode_ieee1609_dot2_data(&plaintext))?;
    Ok(PendingRequest {
        message: encode_ieee1609_dot2_data(&encrypted),
        session_key,
        key_id,
    })
}

/// InnerAtResponse of an AuthorizationResponseMessage (clause 6.2.3.3.2).
pub fn read_authorization_response(
    response: &[u8],
    request: &PendingRequest,
    aa: &Certificate,
    backend: &EcdsaBackend,
) -> Result<InnerAtResponse, PkiProtocolError> {
    match read_response(response, request, aa, backend)? {
        EtsiTs102941DataContent::authorizationResponse(inner)
            if inner.request_hash.as_ref() == request.request_hash() =>
        {
            Ok(inner)
        }
        EtsiTs102941DataContent::authorizationResponse(_) => Err(PkiProtocolError::new(
            "badcontenttype",
            "requestHash does not match the request",
        )),
        _ => Err(PkiProtocolError::new(
            "badcontenttype",
            "expected authorizationResponse",
        )),
    }
}

/// The verification key certified by `certificate` equals `key` (both canonical).
pub fn certifies(certificate: &Certificate, key: &PublicVerificationKey) -> bool {
    use crate::security::security_asn::ieee1609_dot2::VerificationKeyIndicator;
    let mut probe = certificate.base().clone();
    probe.to_be_signed.verify_key_indicator =
        VerificationKeyIndicator::verificationKey(key.clone());
    let ours = Certificate::from_asn(
        crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate(
            crate::security::security_asn::ieee1609_dot2::Certificate(probe),
        ),
        None,
    )
    .to_canonical();
    ours.tbs().verify_key_indicator == certificate.to_canonical().tbs().verify_key_indicator
}

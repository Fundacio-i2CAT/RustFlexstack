// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! S2 Authorization protocol (ITS-S -> AA).
//!
//! Implements ETSI TS 102 941 §6.2.3.3:
//! - Generates fresh AT key pair
//! - Generates random `hmacKey` and computes `keyTag` over `PublicKeys`
//! - Builds `SharedAtRequest`
//! - Builds privacy-preserving `ecSignature` (signed by EC, ECIES-encrypted to EA)
//! - Builds `InnerAtRequest`, wraps in `EtsiTs102941Data`, signs with EC key
//! - ECIES-encrypts request to AA
//! - POSTs request to AA
//! - Decrypts `pskRecipInfo` response with session key
//! - Decodes `InnerAtResponse` and returns issued AT as [`OwnCertificate`]

use rasn::types::{FixedOctetString, Integer};
use std::fmt;

use crate::security::certificate::{Certificate, OwnCertificate};
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::pki_asn::etsi_ts102941_base_types::{
    CertificateFormat, CertificateSubjectAttributes, EcSignature, PublicKeys,
};
use crate::security::pki_asn::etsi_ts102941_messages_itss::{
    EtsiTs102941Data, EtsiTs102941DataContent,
};
use crate::security::pki_asn::etsi_ts102941_types_authorization::{
    AuthorizationResponseCode, InnerAtRequest, InnerAtResponse, SharedAtRequest,
};
use crate::security::pki_client::crypto::{
    compute_hmac_key_tag, ecies_encrypt, now_time32, psk_decrypt, public_key_from_base_enc_key,
};
use crate::security::pki_client::enrolment::{
    HttpTransport, UreqTransport, CT_REQUEST, PSID_CERT_REQUEST,
};
use crate::security::pki_client::pki_coder::PkiCoder;
use crate::security::security_asn::ieee1609_dot2::{
    EncryptedData, EncryptedDataEncryptionKey, HeaderInfo, Ieee1609Dot2Content, Ieee1609Dot2Data,
    PKRecipientInfo, RecipientInfo, SequenceOfCertificate, SequenceOfRecipientInfo, SignedData,
    SignedDataPayload, SignerIdentifier, SymmetricCiphertext, ToBeSignedData,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    Duration, HashAlgorithm, HashedId8, Opaque, Psid, PsidSsp, PublicEncryptionKey,
    SequenceOfPsidSsp, Time32, Time64, Uint16, Uint32, Uint64, Uint8, ValidityPeriod,
};

/// Raised when AA rejects authorization or a protocol error occurs.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthorizationError {
    pub code: String,
    pub message: String,
}

impl AuthorizationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthorizationError {}

/// Perform S2 authorization protocol and return the issued AT as an [`OwnCertificate`].
#[allow(clippy::too_many_arguments)]
pub fn authorize(
    aa_url: &str,
    aa_cert: &Certificate,
    ea_cert: &Certificate,
    ec_own: &OwnCertificate,
    backend: &mut EcdsaBackend,
    requested_app_permissions: Option<SequenceOfPsidSsp>,
    validity_hours: Option<u16>,
    timeout_secs: Option<u64>,
) -> Result<OwnCertificate, AuthorizationError> {
    authorize_with_transport(
        &UreqTransport,
        aa_url,
        aa_cert,
        ea_cert,
        ec_own,
        backend,
        requested_app_permissions,
        validity_hours,
        timeout_secs,
    )
}

/// Perform S2 authorization protocol with a custom [`HttpTransport`].
#[allow(clippy::too_many_arguments)]
pub fn authorize_with_transport(
    transport: &dyn HttpTransport,
    aa_url: &str,
    aa_cert: &Certificate,
    ea_cert: &Certificate,
    ec_own: &OwnCertificate,
    backend: &mut EcdsaBackend,
    requested_app_permissions: Option<SequenceOfPsidSsp>,
    validity_hours: Option<u16>,
    timeout_secs: Option<u64>,
) -> Result<OwnCertificate, AuthorizationError> {
    let validity_hours = validity_hours.unwrap_or(504); // 3 weeks
    let timeout_secs = timeout_secs.unwrap_or(30);

    // Default permissions: CAM (36) + DENM (37)
    let permissions = requested_app_permissions.unwrap_or_else(|| {
        SequenceOfPsidSsp(vec![
            PsidSsp::new(Psid(Integer::from(36)), None),
            PsidSsp::new(Psid(Integer::from(37)), None),
        ])
    });

    // Step 1: generate fresh AT key pair
    let at_key_id = backend.create_key();
    let at_verify_pk = backend.get_public_key(at_key_id);

    // Step 2: generate hmacKey and compute keyTag over PublicKeys COER
    let mut hmac_key = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut hmac_key);

    let public_keys = PublicKeys::new(at_verify_pk, None);
    let public_keys_coer = PkiCoder::encode_public_keys(&public_keys)
        .map_err(|e| AuthorizationError::new("cantencode", e.to_string()))?;
    let key_tag = compute_hmac_key_tag(&hmac_key, &public_keys_coer);

    // Step 3: build SharedAtRequest
    let start_time = now_time32();
    let gen_time_us = (start_time as u64) * 1_000_000;
    let validity = ValidityPeriod::new(
        Time32(Uint32(start_time)),
        Duration::hours(Uint16(validity_hours)),
    );
    let subject_attrs = CertificateSubjectAttributes::new(
        None,
        Some(validity),
        None,
        None,
        Some(permissions),
        None,
    );
    let shared_at_request = SharedAtRequest::new(
        HashedId8(FixedOctetString::from(ea_cert.as_hashedid8())),
        key_tag.to_vec().into(),
        CertificateFormat(Uint8(1)),
        subject_attrs,
    );

    // Step 4: build privacy-preserving ecSignature (encrypted to EA)
    let ec_sig_choice =
        build_ec_signature(&shared_at_request, ec_own, ea_cert, backend, gen_time_us)?;

    // Step 5: build InnerAtRequest
    let inner_at_request = InnerAtRequest::new(
        public_keys,
        hmac_key.to_vec().into(),
        shared_at_request,
        ec_sig_choice,
    );

    // Step 6: wrap in EtsiTs102941Data, sign with EC key, ECIES-encrypt to AA
    let etsi_data = EtsiTs102941Data::new(
        Uint8(1),
        EtsiTs102941DataContent::authorizationRequest(inner_at_request),
    );
    let payload_bytes = PkiCoder::encode_etsi102941_data(&etsi_data)
        .map_err(|e| AuthorizationError::new("cantencode", e.to_string()))?;

    let inner_dot2 = Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::unsecuredData(Opaque(payload_bytes.into())),
    );
    let payload = Box::new(SignedDataPayload::new(Some(inner_dot2), None, None));
    let header_info = HeaderInfo::new(
        Psid(Integer::from(PSID_CERT_REQUEST)),
        Some(Time64(Uint64(gen_time_us))),
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
    let tbs_data = ToBeSignedData::new(payload, header_info);
    let tbs_bytes = PkiCoder::encode_to_be_signed_data(&tbs_data)
        .map_err(|e| AuthorizationError::new("cantencode", e.to_string()))?;

    let signature = ec_own.sign_message(backend, &tbs_bytes);
    let signed_data = SignedData::new(
        HashAlgorithm::sha256,
        tbs_data,
        SignerIdentifier::certificate(SequenceOfCertificate(vec![ec_own.cert.inner.0.clone()])),
        signature,
    );
    let signed_ieee = Ieee1609Dot2Data::new(Uint8(3), Ieee1609Dot2Content::signedData(signed_data));
    let signed_bytes = PkiCoder::encode_ieee1609dot2_data(&signed_ieee)
        .map_err(|e| AuthorizationError::new("cantencode", e.to_string()))?;

    // ECIES-encrypt to AA
    let aa_enc_key = extract_enc_info(aa_cert, "AA")?;
    let aa_pub_key = public_key_from_base_enc_key(&aa_enc_key.public_key)
        .map_err(|e| AuthorizationError::new("cryptoerror", e.to_string()))?;

    let (ecies_key, aes_ccm, session_key_a, session_key_hid8) =
        ecies_encrypt(&signed_bytes, &aa_pub_key, aa_cert.encode())
            .map_err(|e| AuthorizationError::new("cryptoerror", e.to_string()))?;

    let pk_recip = PKRecipientInfo::new(
        HashedId8(FixedOctetString::from(aa_cert.as_hashedid8())),
        EncryptedDataEncryptionKey::eciesNistP256(ecies_key),
    );
    let outer_encrypted = EncryptedData::new(
        SequenceOfRecipientInfo(vec![RecipientInfo::certRecipInfo(pk_recip)]),
        SymmetricCiphertext::aes128ccm(aes_ccm),
    );
    let request_dot2 = Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::encryptedData(outer_encrypted),
    );
    let request_bytes = PkiCoder::encode_ieee1609dot2_data(&request_dot2)
        .map_err(|e| AuthorizationError::new("cantencode", e.to_string()))?;

    // Step 7: POST to AA
    let auth_url = format!("{}/aa/v1/authorization", aa_url.trim_end_matches('/'));

    let (status, resp_bytes) = transport
        .post(&auth_url, CT_REQUEST, &request_bytes, timeout_secs)
        .map_err(|e| AuthorizationError::new(e.code, e.message))?;
    if status != 200 {
        return Err(AuthorizationError::new(
            "http_error",
            format!("AA returned HTTP {status}"),
        ));
    }

    // Step 8: Decrypt pskRecipInfo response
    let inner_signed_bytes = decrypt_psk_response(&resp_bytes, &session_key_a, &session_key_hid8)?;

    // Step 9: Decode InnerAtResponse
    let inner_at_response = decode_authorization_response(&inner_signed_bytes)?;
    if inner_at_response.response_code != AuthorizationResponseCode::ok {
        return Err(AuthorizationError::new(
            format!("{:?}", inner_at_response.response_code),
            format!(
                "AA rejected authorization with responseCode={:?}",
                inner_at_response.response_code
            ),
        ));
    }

    // Step 10: Reconstruct AT as OwnCertificate
    let at_asn = inner_at_response
        .certificate
        .ok_or_else(|| AuthorizationError::new("cantparse", "Response contained no certificate"))?;
    let at_cert = Certificate::from_asn(at_asn, Some(aa_cert.clone()));
    let at_own = OwnCertificate::new(at_cert, at_key_id);
    Ok(at_own)
}

/// Extract public encryption key from certificate.
pub fn extract_enc_info(
    cert: &Certificate,
    role: &str,
) -> Result<PublicEncryptionKey, AuthorizationError> {
    match &cert.tbs().encryption_key {
        Some(k) => Ok(k.clone()),
        None => Err(AuthorizationError::new(
            "invalidcert",
            format!("{role} certificate has no encryptionKey — cannot ECIES-encrypt"),
        )),
    }
}

/// Build the privacy-preserving `ecSignature` field for `InnerAtRequest`.
pub fn build_ec_signature(
    shared_at_request: &SharedAtRequest,
    ec_own: &OwnCertificate,
    ea_cert: &Certificate,
    backend: &EcdsaBackend,
    gen_time_us: u64,
) -> Result<EcSignature, AuthorizationError> {
    // 1. Encode SharedAtRequest and sign it
    let shared_at_coer = PkiCoder::encode_shared_at_request(shared_at_request)
        .map_err(|e| AuthorizationError::new("cantencode", e.to_string()))?;

    let inner_dot2 = Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::unsecuredData(Opaque(shared_at_coer.into())),
    );
    let payload = Box::new(SignedDataPayload::new(Some(inner_dot2), None, None));
    let header_info = HeaderInfo::new(
        Psid(Integer::from(PSID_CERT_REQUEST)),
        Some(Time64(Uint64(gen_time_us))),
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
    let tbs_ec_sig = ToBeSignedData::new(payload, header_info);
    let tbs_ec_sig_bytes = PkiCoder::encode_to_be_signed_data(&tbs_ec_sig)
        .map_err(|e| AuthorizationError::new("cantencode", e.to_string()))?;

    let ec_inner_sig = ec_own.sign_message(backend, &tbs_ec_sig_bytes);

    // 2. Wrap in signed Ieee1609Dot2Data (signer = digest of EC cert)
    let ec_sig_signed = Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::signedData(SignedData::new(
            HashAlgorithm::sha256,
            tbs_ec_sig,
            SignerIdentifier::digest(HashedId8(FixedOctetString::from(ec_own.as_hashedid8()))),
            ec_inner_sig,
        )),
    );
    let ec_sig_signed_bytes = PkiCoder::encode_ieee1609dot2_data(&ec_sig_signed)
        .map_err(|e| AuthorizationError::new("cantencode", e.to_string()))?;

    // 3. ECIES-encrypt signed blob to EA
    let ea_enc_key = extract_enc_info(ea_cert, "EA")?;
    let ea_pub_key = public_key_from_base_enc_key(&ea_enc_key.public_key)
        .map_err(|e| AuthorizationError::new("cryptoerror", e.to_string()))?;

    let (ecies_key, aes_ccm, _, _) =
        ecies_encrypt(&ec_sig_signed_bytes, &ea_pub_key, ea_cert.encode())
            .map_err(|e| AuthorizationError::new("cryptoerror", e.to_string()))?;

    let pk_recip = PKRecipientInfo::new(
        HashedId8(FixedOctetString::from(ea_cert.as_hashedid8())),
        EncryptedDataEncryptionKey::eciesNistP256(ecies_key),
    );
    let encrypted_ec_sig = EncryptedData::new(
        SequenceOfRecipientInfo(vec![RecipientInfo::certRecipInfo(pk_recip)]),
        SymmetricCiphertext::aes128ccm(aes_ccm),
    );
    let encrypted_dot2 = Ieee1609Dot2Data::new(
        Uint8(3),
        Ieee1609Dot2Content::encryptedData(encrypted_ec_sig),
    );

    Ok(EcSignature::encryptedEcSignature(encrypted_dot2))
}

/// Decrypt the AA's `pskRecipInfo` response and return inner signed bytes.
pub fn decrypt_psk_response(
    resp_bytes: &[u8],
    session_key_a: &[u8; 16],
    session_key_hid8: &[u8; 8],
) -> Result<Vec<u8>, AuthorizationError> {
    let outer_resp = PkiCoder::decode_ieee1609dot2_data(resp_bytes)
        .map_err(|e| AuthorizationError::new("cantparse", e.to_string()))?;

    let enc_data = match outer_resp.content {
        Ieee1609Dot2Content::encryptedData(data) => data,
        _ => {
            return Err(AuthorizationError::new(
                "badcontenttype",
                "Expected encryptedData response",
            ))
        }
    };

    let mut found = false;
    for recip in enc_data.recipients.0.iter() {
        if let RecipientInfo::pskRecipInfo(psk) = recip {
            if psk.0 .0.as_ref() == session_key_hid8 {
                found = true;
                break;
            }
        }
    }

    if !found {
        for recip in enc_data.recipients.0.iter() {
            if let RecipientInfo::pskRecipInfo(_) = recip {
                found = true;
                break;
            }
        }
    }

    if !found {
        return Err(AuthorizationError::new(
            "badcontenttype",
            "Response has no pskRecipInfo — cannot decrypt with session key",
        ));
    }

    let aes_ccm = match enc_data.ciphertext {
        SymmetricCiphertext::aes128ccm(ccm) => ccm,
        _ => {
            return Err(AuthorizationError::new(
                "badcontenttype",
                "Expected aes128ccm ciphertext",
            ))
        }
    };

    psk_decrypt(session_key_a, &aes_ccm)
        .map_err(|e| AuthorizationError::new("decryptionfailed", e.to_string()))
}

/// Decode inner signed layer and extract `InnerAtResponse`.
pub fn decode_authorization_response(
    inner_signed_bytes: &[u8],
) -> Result<InnerAtResponse, AuthorizationError> {
    let inner_signed = PkiCoder::decode_ieee1609dot2_data(inner_signed_bytes)
        .map_err(|e| AuthorizationError::new("cantparse", e.to_string()))?;

    let signed_data = match inner_signed.content {
        Ieee1609Dot2Content::signedData(data) => data,
        _ => {
            return Err(AuthorizationError::new(
                "badcontenttype",
                "Expected signedData response",
            ))
        }
    };

    let inner_dot2 = signed_data.tbs_data.payload.data.ok_or_else(|| {
        AuthorizationError::new("badcontenttype", "No payload data in signedData")
    })?;

    let payload_bytes = match inner_dot2.content {
        Ieee1609Dot2Content::unsecuredData(opaque) => opaque.0,
        _ => {
            return Err(AuthorizationError::new(
                "badcontenttype",
                "Expected unsecuredData payload",
            ))
        }
    };

    let etsi_data = PkiCoder::decode_etsi102941_data(payload_bytes.as_ref())
        .map_err(|e| AuthorizationError::new("cantparse", e.to_string()))?;

    match etsi_data.content {
        EtsiTs102941DataContent::authorizationResponse(resp) => Ok(resp),
        _ => Err(AuthorizationError::new(
            "badcontenttype",
            "Expected authorizationResponse content",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use p256::ecdh::diffie_hellman;
    use sha2::{Digest, Sha256};

    use crate::security::pki_client::crypto::{
        aes_ccm_encrypt, compress_public_key, kdf2, public_key_from_point,
    };
    use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
    use crate::security::security_asn::ieee1609_dot2::{
        Certificate as AsnCertificate, CertificateBase, CertificateId, CertificateType,
        IssuerIdentifier, One28BitCcmCiphertext, PreSharedKeyRecipientInfo, ToBeSignedCertificate,
        VerificationKeyIndicator,
    };
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        BasePublicEncryptionKey, CrlSeries, EccP256CurvePoint, EcdsaP256Signature, HashedId3,
        PublicEncryptionKey, Signature as Ieee1609Signature, SymmAlgorithm,
    };

    fn create_mock_authority_cert(
        backend: &mut EcdsaBackend,
        psid: u64,
    ) -> (OwnCertificate, Certificate, p256::SecretKey) {
        let key_id = backend.create_key();
        let verify_pk = backend.get_public_key(key_id);

        let enc_secret = p256::SecretKey::random(&mut rand::thread_rng());
        let enc_point = compress_public_key(&enc_secret.public_key());
        let enc_key = PublicEncryptionKey::new(
            SymmAlgorithm::aes128Ccm,
            BasePublicEncryptionKey::eciesNistP256(enc_point),
        );

        let validity = ValidityPeriod::new(Time32(Uint32(0)), Duration::years(Uint16(5)));
        let app_perms = SequenceOfPsidSsp(vec![PsidSsp::new(Psid(Integer::from(psid)), None)]);

        let tbs = ToBeSignedCertificate::new(
            CertificateId::none(()),
            HashedId3(FixedOctetString::from([0u8; 3])),
            CrlSeries(Uint16(0)),
            validity,
            None,
            None,
            Some(app_perms),
            None,
            None,
            None,
            Some(enc_key),
            VerificationKeyIndicator::verificationKey(verify_pk),
            None,
            None,
            None,
            None,
        );

        let placeholder_sig = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::x_only(vec![0x01; 32].into()),
            s_sig: vec![0x02; 32].into(),
        });

        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            IssuerIdentifier::R_self(HashAlgorithm::sha256),
            tbs,
            Some(placeholder_sig),
        );

        let cert_asn = EtsiTs103097Certificate(AsnCertificate(base));
        let cert = Certificate::from_asn(cert_asn, None);
        let own = OwnCertificate::new(cert.clone(), key_id);
        (own, cert, enc_secret)
    }

    fn build_mock_authorization_response(
        aa_own: &OwnCertificate,
        backend: &EcdsaBackend,
        session_key_a: &[u8; 16],
        session_key_hid8: &[u8; 8],
        response_code: AuthorizationResponseCode,
        issued_cert: Option<EtsiTs103097Certificate>,
    ) -> Vec<u8> {
        let inner_resp = InnerAtResponse::new(vec![0x11; 16].into(), response_code, issued_cert);
        let etsi_data = EtsiTs102941Data::new(
            Uint8(1),
            EtsiTs102941DataContent::authorizationResponse(inner_resp),
        );
        let payload_bytes = PkiCoder::encode_etsi102941_data(&etsi_data).unwrap();

        let inner_dot2 = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::unsecuredData(Opaque(payload_bytes.into())),
        );
        let payload = Box::new(SignedDataPayload::new(Some(inner_dot2), None, None));
        let header_info = HeaderInfo::new(
            Psid(Integer::from(PSID_CERT_REQUEST)),
            Some(Time64(Uint64(1_000_000))),
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
        let tbs_data = ToBeSignedData::new(payload, header_info);
        let tbs_bytes = PkiCoder::encode_to_be_signed_data(&tbs_data).unwrap();

        let sig = aa_own.sign_message(backend, &tbs_bytes);
        let signed_data = SignedData::new(
            HashAlgorithm::sha256,
            tbs_data,
            SignerIdentifier::certificate(SequenceOfCertificate(vec![aa_own.cert.inner.0.clone()])),
            sig,
        );
        let signed_ieee =
            Ieee1609Dot2Data::new(Uint8(3), Ieee1609Dot2Content::signedData(signed_data));
        let signed_bytes = PkiCoder::encode_ieee1609dot2_data(&signed_ieee).unwrap();

        let nonce = [0x55u8; 12];
        let ciphertext = aes_ccm_encrypt(session_key_a, &nonce, &signed_bytes).unwrap();

        let psk_recip =
            PreSharedKeyRecipientInfo(HashedId8(FixedOctetString::from(*session_key_hid8)));
        let outer_encrypted = EncryptedData::new(
            SequenceOfRecipientInfo(vec![RecipientInfo::pskRecipInfo(psk_recip)]),
            SymmetricCiphertext::aes128ccm(One28BitCcmCiphertext::new(
                nonce.to_vec().into(),
                Opaque(ciphertext.into()),
            )),
        );
        let outer_dot2 = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::encryptedData(outer_encrypted),
        );
        PkiCoder::encode_ieee1609dot2_data(&outer_dot2).unwrap()
    }

    struct MockTransport {
        response_status: u16,
        response_body: Mutex<Option<Vec<u8>>>,
    }

    impl MockTransport {
        fn new(status: u16, body: Vec<u8>) -> Self {
            Self {
                response_status: status,
                response_body: Mutex::new(Some(body)),
            }
        }
    }

    impl HttpTransport for MockTransport {
        fn post(
            &self,
            _url: &str,
            _content_type: &str,
            _body: &[u8],
            _timeout_secs: u64,
        ) -> Result<(u16, Vec<u8>), crate::security::pki_client::enrolment::EnrolmentError>
        {
            if self.response_status != 200 {
                return Err(crate::security::pki_client::enrolment::EnrolmentError::new(
                    "http_error",
                    format!("AA returned HTTP {}", self.response_status),
                ));
            }
            let body = self
                .response_body
                .lock()
                .unwrap()
                .take()
                .unwrap_or_default();
            Ok((self.response_status, body))
        }
    }

    #[test]
    fn test_authorization_error_attributes() {
        let err = AuthorizationError::new("test_code", "error description");
        assert_eq!(err.code, "test_code");
        assert_eq!(err.message, "error description");
        assert_eq!(format!("{err}"), "test_code: error description");
    }

    #[test]
    fn test_extract_enc_info_valid() {
        let mut backend = EcdsaBackend::new();
        let (_aa_own, aa_cert, _) = create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        let enc_info = extract_enc_info(&aa_cert, "AA").unwrap();
        assert!(matches!(
            enc_info.public_key,
            BasePublicEncryptionKey::eciesNistP256(_)
        ));
    }

    #[test]
    fn test_extract_enc_info_missing() {
        let mut backend = EcdsaBackend::new();
        let (_aa_own, mut aa_cert, _) = create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        aa_cert.inner.0 .0.to_be_signed.encryption_key = None;
        let err = extract_enc_info(&aa_cert, "AA").unwrap_err();
        assert_eq!(err.code, "invalidcert");
    }

    #[test]
    fn test_build_ec_signature() {
        let mut backend = EcdsaBackend::new();
        let (ea_own, ea_cert, _) = create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        let ec_key = backend.create_key();
        let ec_own = OwnCertificate::new(ea_own.cert.clone(), ec_key);

        let shared_at = SharedAtRequest::new(
            HashedId8(FixedOctetString::from(ea_cert.as_hashedid8())),
            vec![0xAA; 16].into(),
            CertificateFormat(Uint8(1)),
            CertificateSubjectAttributes::new(None, None, None, None, None, None),
        );

        let ec_sig =
            build_ec_signature(&shared_at, &ec_own, &ea_cert, &backend, 1_000_000).unwrap();

        assert!(matches!(ec_sig, EcSignature::encryptedEcSignature(_)));
    }

    #[test]
    fn test_decrypt_psk_response_invalid_outer() {
        let dot2 = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::unsecuredData(Opaque(vec![1, 2, 3].into())),
        );
        let bytes = PkiCoder::encode_ieee1609dot2_data(&dot2).unwrap();
        let err = decrypt_psk_response(&bytes, &[0u8; 16], &[0u8; 8]).unwrap_err();
        assert_eq!(err.code, "badcontenttype");
    }

    #[test]
    fn test_decode_authorization_response() {
        let resp = InnerAtResponse::new(vec![0x99; 16].into(), AuthorizationResponseCode::ok, None);
        let etsi_data = EtsiTs102941Data::new(
            Uint8(1),
            EtsiTs102941DataContent::authorizationResponse(resp),
        );
        let payload_bytes = PkiCoder::encode_etsi102941_data(&etsi_data).unwrap();

        let inner_dot2 = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::unsecuredData(Opaque(payload_bytes.into())),
        );
        let payload = Box::new(SignedDataPayload::new(Some(inner_dot2), None, None));
        let header_info = HeaderInfo::new(
            Psid(Integer::from(PSID_CERT_REQUEST)),
            Some(Time64(Uint64(1_000_000))),
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
        let tbs_data = ToBeSignedData::new(payload, header_info);
        let mut backend = EcdsaBackend::new();
        let (aa_own, _, _) = create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        let tbs_bytes = PkiCoder::encode_to_be_signed_data(&tbs_data).unwrap();
        let sig = aa_own.sign_message(&backend, &tbs_bytes);

        let signed = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::signedData(SignedData::new(
                HashAlgorithm::sha256,
                tbs_data,
                SignerIdentifier::certificate(SequenceOfCertificate(vec![aa_own
                    .cert
                    .inner
                    .0
                    .clone()])),
                sig,
            )),
        );
        let signed_bytes = PkiCoder::encode_ieee1609dot2_data(&signed).unwrap();

        let decoded = decode_authorization_response(&signed_bytes).unwrap();
        assert_eq!(decoded.request_hash.as_ref(), &[0x99; 16]);
        assert_eq!(decoded.response_code, AuthorizationResponseCode::ok);
    }

    #[test]
    fn test_authorize_success_with_mock_transport() {
        let mut backend = EcdsaBackend::new();
        let (_ea_own, ea_cert, _) = create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        let (aa_own, aa_cert, aa_enc_secret) =
            create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);

        let ec_key = backend.create_key();
        let ec_own = OwnCertificate::new(ea_cert.clone(), ec_key);

        let issued_at = aa_own.cert.inner.clone();

        struct AutoDecryptAuthTransport {
            aa_own: OwnCertificate,
            aa_backend: EcdsaBackend,
            aa_enc_secret: p256::SecretKey,
            aa_cert_coer: Vec<u8>,
            issued_at: EtsiTs103097Certificate,
        }

        impl HttpTransport for AutoDecryptAuthTransport {
            fn post(
                &self,
                _url: &str,
                _content_type: &str,
                body: &[u8],
                _timeout_secs: u64,
            ) -> Result<(u16, Vec<u8>), crate::security::pki_client::enrolment::EnrolmentError>
            {
                let req_dot2 = PkiCoder::decode_ieee1609dot2_data(body).unwrap();
                let enc_data = match req_dot2.content {
                    Ieee1609Dot2Content::encryptedData(e) => e,
                    _ => panic!("Expected encryptedData"),
                };
                let recip = &enc_data.recipients.0[0];
                let ecies_key = match recip {
                    RecipientInfo::certRecipInfo(r) => match &r.enc_key {
                        EncryptedDataEncryptionKey::eciesNistP256(k) => k,
                        _ => panic!(),
                    },
                    _ => panic!(),
                };

                let eph_pub = public_key_from_point(&ecies_key.v).unwrap();
                let shared =
                    diffie_hellman(self.aa_enc_secret.to_nonzero_scalar(), eph_pub.as_affine());
                let (k_enc, _) = kdf2(shared.raw_secret_bytes().as_ref(), &self.aa_cert_coer);

                let mut session_key_a = [0u8; 16];
                for i in 0..16 {
                    session_key_a[i] = ecies_key.c.as_ref()[i] ^ k_enc[i];
                }
                let digest = Sha256::digest(session_key_a);
                let mut session_key_hid8 = [0u8; 8];
                session_key_hid8.copy_from_slice(&digest[24..32]);

                let mock_resp = build_mock_authorization_response(
                    &self.aa_own,
                    &self.aa_backend,
                    &session_key_a,
                    &session_key_hid8,
                    AuthorizationResponseCode::ok,
                    Some(self.issued_at.clone()),
                );
                Ok((200, mock_resp))
            }
        }

        let mut aa_backend = EcdsaBackend::new();
        let aa_key = aa_backend.import_signing_key(&backend.export_signing_key(aa_own.key_id));
        let aa_own_copy = OwnCertificate::new(aa_own.cert.clone(), aa_key);

        let transport = AutoDecryptAuthTransport {
            aa_own: aa_own_copy,
            aa_backend,
            aa_enc_secret,
            aa_cert_coer: aa_cert.encode().to_vec(),
            issued_at,
        };

        let at_own = authorize_with_transport(
            &transport,
            "http://localhost:8081",
            &aa_cert,
            &ea_cert,
            &ec_own,
            &mut backend,
            None,
            Some(504),
            Some(10),
        )
        .unwrap();

        assert_eq!(at_own.cert.as_hashedid8(), aa_own.cert.as_hashedid8());
    }

    #[test]
    fn test_authorize_http_error() {
        let mut backend = EcdsaBackend::new();
        let (_ea_own, ea_cert, _) = create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        let (_aa_own, aa_cert, _) = create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        let ec_key = backend.create_key();
        let ec_own = OwnCertificate::new(ea_cert.clone(), ec_key);

        let mock_transport = MockTransport::new(500, vec![]);
        let err = authorize_with_transport(
            &mock_transport,
            "http://localhost:8081",
            &aa_cert,
            &ea_cert,
            &ec_own,
            &mut backend,
            None,
            None,
            None,
        )
        .unwrap_err();

        assert_eq!(err.code, "http_error");
    }

    #[test]
    fn test_authorize_rejected_by_aa() {
        let mut backend = EcdsaBackend::new();
        let (_ea_own, ea_cert, _) = create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        let (aa_own, aa_cert, aa_enc_secret) =
            create_mock_authority_cert(&mut backend, PSID_CERT_REQUEST);
        let ec_key = backend.create_key();
        let ec_own = OwnCertificate::new(ea_cert.clone(), ec_key);

        struct RejectAuthTransport {
            aa_own: OwnCertificate,
            aa_backend: EcdsaBackend,
            aa_enc_secret: p256::SecretKey,
            aa_cert_coer: Vec<u8>,
        }

        impl HttpTransport for RejectAuthTransport {
            fn post(
                &self,
                _url: &str,
                _content_type: &str,
                body: &[u8],
                _timeout_secs: u64,
            ) -> Result<(u16, Vec<u8>), crate::security::pki_client::enrolment::EnrolmentError>
            {
                let req_dot2 = PkiCoder::decode_ieee1609dot2_data(body).unwrap();
                let enc_data = match req_dot2.content {
                    Ieee1609Dot2Content::encryptedData(e) => e,
                    _ => panic!("Expected encryptedData"),
                };
                let recip = &enc_data.recipients.0[0];
                let ecies_key = match recip {
                    RecipientInfo::certRecipInfo(r) => match &r.enc_key {
                        EncryptedDataEncryptionKey::eciesNistP256(k) => k,
                        _ => panic!(),
                    },
                    _ => panic!(),
                };

                let eph_pub = public_key_from_point(&ecies_key.v).unwrap();
                let shared =
                    diffie_hellman(self.aa_enc_secret.to_nonzero_scalar(), eph_pub.as_affine());
                let (k_enc, _) = kdf2(shared.raw_secret_bytes().as_ref(), &self.aa_cert_coer);

                let mut session_key_a = [0u8; 16];
                for i in 0..16 {
                    session_key_a[i] = ecies_key.c.as_ref()[i] ^ k_enc[i];
                }
                let digest = Sha256::digest(session_key_a);
                let mut session_key_hid8 = [0u8; 8];
                session_key_hid8.copy_from_slice(&digest[24..32]);

                let mock_resp = build_mock_authorization_response(
                    &self.aa_own,
                    &self.aa_backend,
                    &session_key_a,
                    &session_key_hid8,
                    AuthorizationResponseCode::deniedpermissions,
                    None,
                );
                Ok((200, mock_resp))
            }
        }

        let mut aa_backend = EcdsaBackend::new();
        let aa_key = aa_backend.import_signing_key(&backend.export_signing_key(aa_own.key_id));
        let aa_own_copy = OwnCertificate::new(aa_own.cert.clone(), aa_key);

        let transport = RejectAuthTransport {
            aa_own: aa_own_copy,
            aa_backend,
            aa_enc_secret,
            aa_cert_coer: aa_cert.encode().to_vec(),
        };

        let err = authorize_with_transport(
            &transport,
            "http://localhost:8081",
            &aa_cert,
            &ea_cert,
            &ec_own,
            &mut backend,
            None,
            None,
            None,
        )
        .unwrap_err();

        assert_eq!(err.code, "deniedpermissions");
    }
}

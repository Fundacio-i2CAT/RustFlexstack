// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! S3 Enrolment protocol (ITS-S -> EA).
//!
//! Implements ETSI TS 102 941 §6.2.3.2 enrolment:
//! - Generates fresh EC key pair
//! - Builds `InnerECRequest` and wraps it in `EtsiTs102941Data`
//! - Signs with canonical or prior EC certificate
//! - ECIES-encrypts to EA
//! - POSTs request to EA
//! - Decrypts `pskRecipInfo` response with session key
//! - Decodes `InnerECResponse` and returns issued EC as [`OwnCertificate`]

use rasn::types::{FixedOctetString, Integer};
use std::fmt;

use crate::security::certificate::{Certificate, OwnCertificate};
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::pki_asn::etsi_ts102941_base_types::{
    CertificateFormat, CertificateSubjectAttributes, PublicKeys,
};
use crate::security::pki_asn::etsi_ts102941_messages_itss::{
    EtsiTs102941Data, EtsiTs102941DataContent,
};
use crate::security::pki_asn::etsi_ts102941_types_enrolment::{
    EnrolmentResponseCode, InnerECRequest, InnerECResponse,
};
use crate::security::pki_client::crypto::{
    ecies_encrypt, now_time32, psk_decrypt, public_key_from_base_enc_key,
};
use crate::security::pki_client::pki_coder::PkiCoder;
use crate::security::security_asn::ieee1609_dot2::{
    EncryptedData, EncryptedDataEncryptionKey, HeaderInfo, Ieee1609Dot2Content, Ieee1609Dot2Data,
    PKRecipientInfo, RecipientInfo, SequenceOfCertificate, SequenceOfRecipientInfo, SignedData,
    SignedDataPayload, SignerIdentifier, SymmetricCiphertext, ToBeSignedData,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    Duration, HashAlgorithm, HashedId8, Opaque, Psid, PsidSsp, SequenceOfPsidSsp,
    ServiceSpecificPermissions, Time32, Time64, Uint16, Uint32, Uint64, Uint8, ValidityPeriod,
};

/// PSID for secured certificate request messages (ITS-AID 623 = 0x26F).
pub const PSID_CERT_REQUEST: u64 = 623;

/// HTTP content-type for ITS PKI messages.
pub const CT_REQUEST: &str = "application/x-its-request";

/// Raised when EA rejects enrolment or a protocol error occurs.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EnrolmentError {
    pub code: String,
    pub message: String,
}

impl EnrolmentError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for EnrolmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for EnrolmentError {}

/// HTTP transport trait to allow offline mocking in tests.
pub trait HttpTransport: Send + Sync {
    fn post(
        &self,
        url: &str,
        content_type: &str,
        body: &[u8],
        timeout_secs: u64,
    ) -> Result<(u16, Vec<u8>), EnrolmentError>;
}

/// Default synchronous HTTP transport using `ureq`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UreqTransport;

impl HttpTransport for UreqTransport {
    fn post(
        &self,
        url: &str,
        content_type: &str,
        body: &[u8],
        timeout_secs: u64,
    ) -> Result<(u16, Vec<u8>), EnrolmentError> {
        let resp = ureq::post(url)
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .set("Content-Type", content_type)
            .send_bytes(body);
        match resp {
            Ok(r) => {
                let status = r.status();
                let mut reader = r.into_reader();
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut reader, &mut buf)
                    .map_err(|e| EnrolmentError::new("io_error", e.to_string()))?;
                Ok((status, buf))
            }
            Err(ureq::Error::Status(code, r)) => {
                let mut reader = r.into_reader();
                let mut text = String::new();
                let _ = std::io::Read::read_to_string(&mut reader, &mut text);
                Err(EnrolmentError::new(
                    "http_error",
                    format!("EA returned HTTP {code}: {text}"),
                ))
            }
            Err(e) => Err(EnrolmentError::new("http_error", e.to_string())),
        }
    }
}

/// Perform S3 enrolment protocol and return the issued EC as an [`OwnCertificate`].
#[allow(clippy::too_many_arguments)]
pub fn enroll(
    ea_url: &str,
    ea_cert: &Certificate,
    signer_cert: &OwnCertificate,
    backend: &mut EcdsaBackend,
    its_id: Option<[u8; 8]>,
    requested_app_permissions: Option<SequenceOfPsidSsp>,
    validity_years: Option<u16>,
    timeout_secs: Option<u64>,
) -> Result<OwnCertificate, EnrolmentError> {
    enroll_with_transport(
        &UreqTransport,
        ea_url,
        ea_cert,
        signer_cert,
        backend,
        its_id,
        requested_app_permissions,
        validity_years,
        timeout_secs,
    )
}

/// Perform S3 enrolment protocol with a custom [`HttpTransport`].
#[allow(clippy::too_many_arguments)]
pub fn enroll_with_transport(
    transport: &dyn HttpTransport,
    ea_url: &str,
    ea_cert: &Certificate,
    signer_cert: &OwnCertificate,
    backend: &mut EcdsaBackend,
    its_id: Option<[u8; 8]>,
    requested_app_permissions: Option<SequenceOfPsidSsp>,
    validity_years: Option<u16>,
    timeout_secs: Option<u64>,
) -> Result<OwnCertificate, EnrolmentError> {
    let its_id = its_id.unwrap_or([0u8; 8]);
    let validity_years = validity_years.unwrap_or(1);
    let timeout_secs = timeout_secs.unwrap_or(30);

    // Default permissions: sign EnrolmentRequest + AuthorizationRequest (SSP 0xC0)
    let permissions = requested_app_permissions.unwrap_or_else(|| {
        SequenceOfPsidSsp(vec![PsidSsp::new(
            Psid(Integer::from(PSID_CERT_REQUEST)),
            Some(ServiceSpecificPermissions::opaque(vec![0x01, 0xC0].into())),
        )])
    });

    // Step 1: generate fresh EC key pair
    let ec_key_id = backend.create_key();
    let new_verify_key = backend.get_public_key(ec_key_id);

    // Step 2: build InnerECRequest
    let start_time = now_time32();
    let validity = ValidityPeriod::new(
        Time32(Uint32(start_time)),
        Duration::years(Uint16(validity_years)),
    );
    let subject_attrs = CertificateSubjectAttributes::new(
        None,
        Some(validity),
        None,
        None,
        Some(permissions),
        None,
    );
    let public_keys = PublicKeys::new(new_verify_key, None);
    let inner_ec_request = InnerECRequest::new(
        its_id.to_vec().into(),
        CertificateFormat(Uint8(1)),
        public_keys,
        subject_attrs,
    );

    // Step 3-4: wrap InnerECRequest in EtsiTs102941Data, encode payload
    let etsi_data = EtsiTs102941Data::new(
        Uint8(1),
        EtsiTs102941DataContent::enrolmentRequest(inner_ec_request),
    );
    let payload_bytes = PkiCoder::encode_etsi102941_data(&etsi_data)
        .map_err(|e| EnrolmentError::new("cantencode", e.to_string()))?;

    // Step 5: build and sign inner Ieee1609Dot2Data (outer signed layer)
    let gen_time_us = (start_time as u64) * 1_000_000;
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
        .map_err(|e| EnrolmentError::new("cantencode", e.to_string()))?;

    let signature = signer_cert.sign_message(backend, &tbs_bytes);
    let signed_data = SignedData::new(
        HashAlgorithm::sha256,
        tbs_data,
        SignerIdentifier::certificate(SequenceOfCertificate(vec![signer_cert
            .cert
            .inner
            .0
            .clone()])),
        signature,
    );
    let signed_ieee = Ieee1609Dot2Data::new(Uint8(3), Ieee1609Dot2Content::signedData(signed_data));
    let signed_bytes = PkiCoder::encode_ieee1609dot2_data(&signed_ieee)
        .map_err(|e| EnrolmentError::new("cantencode", e.to_string()))?;

    // Step 6: ECIES-encrypt to EA
    let ea_enc_key = extract_ea_enc_info(ea_cert)?;
    let ea_pub_key = public_key_from_base_enc_key(&ea_enc_key.public_key)
        .map_err(|e| EnrolmentError::new("cryptoerror", e.to_string()))?;

    let (ecies_key, aes_ccm, session_key_a, session_key_hid8) =
        ecies_encrypt(&signed_bytes, &ea_pub_key, ea_cert.encode())
            .map_err(|e| EnrolmentError::new("cryptoerror", e.to_string()))?;

    let pk_recip = PKRecipientInfo::new(
        HashedId8(FixedOctetString::from(ea_cert.as_hashedid8())),
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
        .map_err(|e| EnrolmentError::new("cantencode", e.to_string()))?;

    // Step 7: POST to EA
    let enrolment_url = format!("{}/ea/v1/enrolment", ea_url.trim_end_matches('/'));

    let (status, resp_bytes) =
        transport.post(&enrolment_url, CT_REQUEST, &request_bytes, timeout_secs)?;
    if status != 200 {
        return Err(EnrolmentError::new(
            "http_error",
            format!("EA returned HTTP {status}"),
        ));
    }

    // Step 8: Decrypt pskRecipInfo response
    let inner_signed_bytes = decrypt_psk_response(&resp_bytes, &session_key_a, &session_key_hid8)?;

    // Step 9: Decode InnerECResponse
    let inner_ec_response = decode_enrolment_response(&inner_signed_bytes)?;
    if inner_ec_response.response_code != EnrolmentResponseCode::ok {
        return Err(EnrolmentError::new(
            format!("{:?}", inner_ec_response.response_code),
            format!(
                "EA rejected enrolment with responseCode={:?}",
                inner_ec_response.response_code
            ),
        ));
    }

    // Step 10: Reconstruct OwnCertificate from issued EC
    let ec_asn = inner_ec_response
        .certificate
        .ok_or_else(|| EnrolmentError::new("cantparse", "Response contained no certificate"))?;
    let ec_cert = Certificate::from_asn(ec_asn, Some(ea_cert.clone()));
    let ec_own = OwnCertificate::new(ec_cert, ec_key_id);
    Ok(ec_own)
}

/// Extract EA encryption key info from certificate.
pub fn extract_ea_enc_info(
    ea_cert: &Certificate,
) -> Result<
    crate::security::security_asn::ieee1609_dot2_base_types::PublicEncryptionKey,
    EnrolmentError,
> {
    match &ea_cert.tbs().encryption_key {
        Some(k) => Ok(k.clone()),
        None => Err(EnrolmentError::new(
            "invalidea",
            "EA certificate has no encryptionKey — cannot perform ECIES encryption",
        )),
    }
}

/// Decrypt EA's `pskRecipInfo` response using session key.
pub fn decrypt_psk_response(
    resp_bytes: &[u8],
    session_key_a: &[u8; 16],
    session_key_hid8: &[u8; 8],
) -> Result<Vec<u8>, EnrolmentError> {
    let outer_resp = PkiCoder::decode_ieee1609dot2_data(resp_bytes)
        .map_err(|e| EnrolmentError::new("cantparse", e.to_string()))?;

    let enc_data = match outer_resp.content {
        Ieee1609Dot2Content::encryptedData(data) => data,
        _ => {
            return Err(EnrolmentError::new(
                "badcontenttype",
                "Expected encryptedData response",
            ))
        }
    };

    // Locate pskRecipInfo matching session key
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
        // Fallback: accept any pskRecipInfo
        for recip in enc_data.recipients.0.iter() {
            if let RecipientInfo::pskRecipInfo(_) = recip {
                found = true;
                break;
            }
        }
    }

    if !found {
        return Err(EnrolmentError::new(
            "badcontenttype",
            "Response has no pskRecipInfo — cannot decrypt with session key",
        ));
    }

    let aes_ccm = match enc_data.ciphertext {
        SymmetricCiphertext::aes128ccm(ccm) => ccm,
        _ => {
            return Err(EnrolmentError::new(
                "badcontenttype",
                "Expected aes128ccm ciphertext",
            ))
        }
    };

    psk_decrypt(session_key_a, &aes_ccm)
        .map_err(|e| EnrolmentError::new("decryptionfailed", e.to_string()))
}

/// Decode inner signed layer and extract `InnerECResponse`.
pub fn decode_enrolment_response(
    inner_signed_bytes: &[u8],
) -> Result<InnerECResponse, EnrolmentError> {
    let inner_signed = PkiCoder::decode_ieee1609dot2_data(inner_signed_bytes)
        .map_err(|e| EnrolmentError::new("cantparse", e.to_string()))?;

    let signed_data = match inner_signed.content {
        Ieee1609Dot2Content::signedData(data) => data,
        _ => {
            return Err(EnrolmentError::new(
                "badcontenttype",
                "Expected signedData response",
            ))
        }
    };

    let inner_dot2 =
        signed_data.tbs_data.payload.data.ok_or_else(|| {
            EnrolmentError::new("badcontenttype", "No payload data in signedData")
        })?;

    let payload_bytes = match inner_dot2.content {
        Ieee1609Dot2Content::unsecuredData(opaque) => opaque.0,
        _ => {
            return Err(EnrolmentError::new(
                "badcontenttype",
                "Expected unsecuredData payload",
            ))
        }
    };

    let etsi_data = PkiCoder::decode_etsi102941_data(payload_bytes.as_ref())
        .map_err(|e| EnrolmentError::new("cantparse", e.to_string()))?;

    match etsi_data.content {
        EtsiTs102941DataContent::enrolmentResponse(resp) => Ok(resp),
        _ => Err(EnrolmentError::new(
            "badcontenttype",
            "Expected enrolmentResponse content",
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
        PublicEncryptionKey, PublicVerificationKey, Signature as Ieee1609Signature, SymmAlgorithm,
    };

    fn create_mock_ea_cert(
        backend: &mut EcdsaBackend,
    ) -> (OwnCertificate, Certificate, p256::SecretKey) {
        let ea_key_id = backend.create_key();
        let ea_verify_pk = backend.get_public_key(ea_key_id);

        let enc_secret = p256::SecretKey::random(&mut rand::thread_rng());
        let enc_point = compress_public_key(&enc_secret.public_key());
        let enc_key = PublicEncryptionKey::new(
            SymmAlgorithm::aes128Ccm,
            BasePublicEncryptionKey::eciesNistP256(enc_point),
        );

        let validity = ValidityPeriod::new(Time32(Uint32(0)), Duration::years(Uint16(5)));
        let app_perms = SequenceOfPsidSsp(vec![PsidSsp::new(
            Psid(Integer::from(PSID_CERT_REQUEST)),
            None,
        )]);

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
            VerificationKeyIndicator::verificationKey(ea_verify_pk),
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
        let own = OwnCertificate::new(cert.clone(), ea_key_id);
        (own, cert, enc_secret)
    }

    fn build_mock_enrolment_response(
        ea_own: &OwnCertificate,
        backend: &EcdsaBackend,
        session_key_a: &[u8; 16],
        session_key_hid8: &[u8; 8],
        response_code: EnrolmentResponseCode,
        issued_cert: Option<EtsiTs103097Certificate>,
    ) -> Vec<u8> {
        let inner_resp = InnerECResponse::new(Uint8(1), response_code, issued_cert);
        let etsi_data = EtsiTs102941Data::new(
            Uint8(1),
            EtsiTs102941DataContent::enrolmentResponse(inner_resp),
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

        let sig = ea_own.sign_message(backend, &tbs_bytes);
        let signed_data = SignedData::new(
            HashAlgorithm::sha256,
            tbs_data,
            SignerIdentifier::certificate(SequenceOfCertificate(vec![ea_own.cert.inner.0.clone()])),
            sig,
        );
        let signed_ieee =
            Ieee1609Dot2Data::new(Uint8(3), Ieee1609Dot2Content::signedData(signed_data));
        let signed_bytes = PkiCoder::encode_ieee1609dot2_data(&signed_ieee).unwrap();

        let nonce = [0x77u8; 12];
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
        ) -> Result<(u16, Vec<u8>), EnrolmentError> {
            if self.response_status != 200 {
                return Err(EnrolmentError::new(
                    "http_error",
                    format!("EA returned HTTP {}", self.response_status),
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
    fn test_enrolment_error_attributes() {
        let err = EnrolmentError::new("test_code", "test_message");
        assert_eq!(err.code, "test_code");
        assert_eq!(err.message, "test_message");
        assert_eq!(format!("{err}"), "test_code: test_message");
    }

    #[test]
    fn test_extract_ea_enc_info_valid() {
        let mut backend = EcdsaBackend::new();
        let (_ea_own, ea_cert, _) = create_mock_ea_cert(&mut backend);
        let enc_info = extract_ea_enc_info(&ea_cert).unwrap();
        assert!(matches!(
            enc_info.public_key,
            BasePublicEncryptionKey::eciesNistP256(_)
        ));
    }

    #[test]
    fn test_extract_ea_enc_info_missing() {
        let mut backend = EcdsaBackend::new();
        let (_ea_own, mut ea_cert, _) = create_mock_ea_cert(&mut backend);
        ea_cert.inner.0 .0.to_be_signed.encryption_key = None;
        let err = extract_ea_enc_info(&ea_cert).unwrap_err();
        assert_eq!(err.code, "invalidea");
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

    fn make_canonical_tbs() -> ToBeSignedCertificate {
        let placeholder_pk =
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::x_only(vec![0u8; 32].into()));
        ToBeSignedCertificate::new(
            CertificateId::none(()),
            HashedId3(FixedOctetString::from([0u8; 3])),
            CrlSeries(Uint16(0)),
            ValidityPeriod::new(Time32(Uint32(0)), Duration::years(Uint16(1))),
            None,
            None,
            Some(SequenceOfPsidSsp(vec![PsidSsp::new(
                Psid(Integer::from(PSID_CERT_REQUEST)),
                None,
            )])),
            None,
            None,
            None,
            None,
            VerificationKeyIndicator::verificationKey(placeholder_pk),
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn test_enroll_success_with_mock_transport() {
        let mut backend = EcdsaBackend::new();
        let (ea_own, ea_cert, ea_enc_secret) = create_mock_ea_cert(&mut backend);

        // Canonical self-signed cert
        let canon_own = OwnCertificate::initialize_self_signed(&mut backend, make_canonical_tbs());

        let issued_ec = ea_own.cert.inner.clone();

        // Custom transport intercepting the request, extracting session key from ECIES,
        // and returning a matching response
        struct AutoDecryptTransport {
            ea_own: OwnCertificate,
            ea_backend: EcdsaBackend,
            ea_enc_secret: p256::SecretKey,
            ea_cert_coer: Vec<u8>,
            issued_ec: EtsiTs103097Certificate,
        }

        impl HttpTransport for AutoDecryptTransport {
            fn post(
                &self,
                _url: &str,
                _content_type: &str,
                body: &[u8],
                _timeout_secs: u64,
            ) -> Result<(u16, Vec<u8>), EnrolmentError> {
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

                // Decrypt session key:
                let eph_pub = public_key_from_point(&ecies_key.v).unwrap();
                let shared =
                    diffie_hellman(self.ea_enc_secret.to_nonzero_scalar(), eph_pub.as_affine());
                let (k_enc, _) = kdf2(shared.raw_secret_bytes().as_ref(), &self.ea_cert_coer);

                let mut session_key_a = [0u8; 16];
                for i in 0..16 {
                    session_key_a[i] = ecies_key.c.as_ref()[i] ^ k_enc[i];
                }
                let digest = Sha256::digest(session_key_a);
                let mut session_key_hid8 = [0u8; 8];
                session_key_hid8.copy_from_slice(&digest[24..32]);

                let mock_resp = build_mock_enrolment_response(
                    &self.ea_own,
                    &self.ea_backend,
                    &session_key_a,
                    &session_key_hid8,
                    EnrolmentResponseCode::ok,
                    Some(self.issued_ec.clone()),
                );
                Ok((200, mock_resp))
            }
        }

        let mut ea_backend = EcdsaBackend::new();
        let ea_key = ea_backend.import_signing_key(&backend.export_signing_key(ea_own.key_id));
        let ea_own_copy = OwnCertificate::new(ea_own.cert.clone(), ea_key);

        let transport = AutoDecryptTransport {
            ea_own: ea_own_copy,
            ea_backend,
            ea_enc_secret,
            ea_cert_coer: ea_cert.encode().to_vec(),
            issued_ec,
        };

        let enrolled_ec = enroll_with_transport(
            &transport,
            "http://localhost:8080",
            &ea_cert,
            &canon_own,
            &mut backend,
            Some([0x01; 8]),
            None,
            Some(1),
            Some(10),
        )
        .unwrap();

        assert_eq!(enrolled_ec.cert.as_hashedid8(), ea_own.cert.as_hashedid8());
    }

    #[test]
    fn test_enroll_http_error() {
        let mut backend = EcdsaBackend::new();
        let (_ea_own, ea_cert, _) = create_mock_ea_cert(&mut backend);
        let canon_own = OwnCertificate::initialize_self_signed(&mut backend, make_canonical_tbs());

        let mock_transport = MockTransport::new(503, vec![]);
        let err = enroll_with_transport(
            &mock_transport,
            "http://localhost:8080",
            &ea_cert,
            &canon_own,
            &mut backend,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();

        assert_eq!(err.code, "http_error");
    }

    #[test]
    fn test_enroll_rejected_by_ea() {
        let mut backend = EcdsaBackend::new();
        let (ea_own, ea_cert, ea_enc_secret) = create_mock_ea_cert(&mut backend);
        let canon_own = OwnCertificate::initialize_self_signed(&mut backend, make_canonical_tbs());

        struct RejectTransport {
            ea_own: OwnCertificate,
            ea_backend: EcdsaBackend,
            ea_enc_secret: p256::SecretKey,
            ea_cert_coer: Vec<u8>,
        }

        impl HttpTransport for RejectTransport {
            fn post(
                &self,
                _url: &str,
                _content_type: &str,
                body: &[u8],
                _timeout_secs: u64,
            ) -> Result<(u16, Vec<u8>), EnrolmentError> {
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
                    diffie_hellman(self.ea_enc_secret.to_nonzero_scalar(), eph_pub.as_affine());
                let (k_enc, _) = kdf2(shared.raw_secret_bytes().as_ref(), &self.ea_cert_coer);

                let mut session_key_a = [0u8; 16];
                for i in 0..16 {
                    session_key_a[i] = ecies_key.c.as_ref()[i] ^ k_enc[i];
                }
                let digest = Sha256::digest(session_key_a);
                let mut session_key_hid8 = [0u8; 8];
                session_key_hid8.copy_from_slice(&digest[24..32]);

                let mock_resp = build_mock_enrolment_response(
                    &self.ea_own,
                    &self.ea_backend,
                    &session_key_a,
                    &session_key_hid8,
                    EnrolmentResponseCode::incompatiblelevel,
                    None,
                );
                Ok((200, mock_resp))
            }
        }

        let mut ea_backend = EcdsaBackend::new();
        let ea_key = ea_backend.import_signing_key(&backend.export_signing_key(ea_own.key_id));
        let ea_own_copy = OwnCertificate::new(ea_own.cert.clone(), ea_key);

        let transport = RejectTransport {
            ea_own: ea_own_copy,
            ea_backend,
            ea_enc_secret,
            ea_cert_coer: ea_cert.encode().to_vec(),
        };

        let err = enroll_with_transport(
            &transport,
            "http://localhost:8080",
            &ea_cert,
            &canon_own,
            &mut backend,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();

        assert_eq!(err.code, "incompatiblelevel");
    }
}

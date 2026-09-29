// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ASN.1 COER encode/decode for ETSI TS 102 941 PKI messages (ITS-S side).
//!
//! Provides [`PkiCoder`] helpers for encoding and decoding:
//! - `Ieee1609Dot2Data` (generic signed / encrypted envelopes)
//! - `EtsiTs102941Data` (PKI protocol envelopes)
//! - `InnerECRequest` / `InnerECResponse` (enrolment messages)
//! - `SharedAtRequest` / `InnerAtRequest` / `InnerAtResponse` (authorization messages)
//! - `PublicKeys` (key container for `keyTag` HMAC computation)
//! - `EtsiTs103097Certificate` and `ToBeSignedData`

use std::fmt;

use crate::security::pki_asn::etsi_ts102941_base_types::PublicKeys;
use crate::security::pki_asn::etsi_ts102941_messages_itss::EtsiTs102941Data;
use crate::security::pki_asn::etsi_ts102941_types_authorization::{
    InnerAtRequest, InnerAtResponse, SharedAtRequest,
};
use crate::security::pki_asn::etsi_ts102941_types_enrolment::{InnerECRequest, InnerECResponse};
use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::security_asn::ieee1609_dot2::{Ieee1609Dot2Data, ToBeSignedData};

#[derive(Debug, PartialEq, Eq)]
pub enum PkiCoderError {
    EncodeError(String),
    DecodeError(String),
}

impl fmt::Display for PkiCoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkiCoderError::EncodeError(msg) => write!(f, "COER encode error: {msg}"),
            PkiCoderError::DecodeError(msg) => write!(f, "COER decode error: {msg}"),
        }
    }
}

impl std::error::Error for PkiCoderError {}

/// ASN.1 COER coder for PKI messages and data envelopes.
#[derive(Debug, Default, Clone, Copy)]
pub struct PkiCoder;

impl PkiCoder {
    /// Create a new `PkiCoder`.
    pub fn new() -> Self {
        Self
    }

    /// Encode `Ieee1609Dot2Data` to COER bytes.
    pub fn encode_ieee1609dot2_data(data: &Ieee1609Dot2Data) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(data).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `Ieee1609Dot2Data` from COER bytes.
    pub fn decode_ieee1609dot2_data(raw: &[u8]) -> Result<Ieee1609Dot2Data, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `EtsiTs102941Data` envelope to COER bytes.
    pub fn encode_etsi102941_data(data: &EtsiTs102941Data) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(data).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `EtsiTs102941Data` from COER bytes.
    pub fn decode_etsi102941_data(raw: &[u8]) -> Result<EtsiTs102941Data, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `InnerECRequest` to COER bytes.
    pub fn encode_inner_ec_request(data: &InnerECRequest) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(data).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `InnerECRequest` from COER bytes.
    pub fn decode_inner_ec_request(raw: &[u8]) -> Result<InnerECRequest, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `InnerECResponse` to COER bytes.
    pub fn encode_inner_ec_response(data: &InnerECResponse) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(data).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `InnerECResponse` from COER bytes.
    pub fn decode_inner_ec_response(raw: &[u8]) -> Result<InnerECResponse, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `SharedAtRequest` to COER bytes.
    pub fn encode_shared_at_request(data: &SharedAtRequest) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(data).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `SharedAtRequest` from COER bytes.
    pub fn decode_shared_at_request(raw: &[u8]) -> Result<SharedAtRequest, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `InnerAtRequest` to COER bytes.
    pub fn encode_inner_at_request(data: &InnerAtRequest) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(data).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `InnerAtRequest` from COER bytes.
    pub fn decode_inner_at_request(raw: &[u8]) -> Result<InnerAtRequest, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `InnerAtResponse` to COER bytes.
    pub fn encode_inner_at_response(data: &InnerAtResponse) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(data).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `InnerAtResponse` from COER bytes.
    pub fn decode_inner_at_response(raw: &[u8]) -> Result<InnerAtResponse, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `PublicKeys` to COER bytes.
    pub fn encode_public_keys(data: &PublicKeys) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(data).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `PublicKeys` from COER bytes.
    pub fn decode_public_keys(raw: &[u8]) -> Result<PublicKeys, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `EtsiTs103097Certificate` to COER bytes.
    pub fn encode_certificate(cert: &EtsiTs103097Certificate) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(cert).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `EtsiTs103097Certificate` from COER bytes.
    pub fn decode_certificate(raw: &[u8]) -> Result<EtsiTs103097Certificate, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }

    /// Encode `ToBeSignedData` to COER bytes.
    pub fn encode_to_be_signed_data(tbs: &ToBeSignedData) -> Result<Vec<u8>, PkiCoderError> {
        rasn::coer::encode(tbs).map_err(|e| PkiCoderError::EncodeError(e.to_string()))
    }

    /// Decode `ToBeSignedData` from COER bytes.
    pub fn decode_to_be_signed_data(raw: &[u8]) -> Result<ToBeSignedData, PkiCoderError> {
        rasn::coer::decode(raw).map_err(|e| PkiCoderError::DecodeError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::pki_asn::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, EcSignature,
    };
    use crate::security::pki_asn::etsi_ts102941_messages_itss::EtsiTs102941DataContent;
    use crate::security::pki_asn::etsi_ts102941_types_authorization::AuthorizationResponseCode;
    use crate::security::pki_asn::etsi_ts102941_types_enrolment::EnrolmentResponseCode;
    use crate::security::security_asn::ieee1609_dot2::Ieee1609Dot2Content;
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        EccP256CurvePoint, HashedId8, Opaque, PublicVerificationKey, Uint8,
    };
    use rasn::types::FixedOctetString;

    #[test]
    fn test_encode_decode_ieee1609dot2_data() {
        let payload = b"test_payload_123".to_vec();
        let dot2 = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::unsecuredData(Opaque(payload.clone().into())),
        );

        let encoded = PkiCoder::encode_ieee1609dot2_data(&dot2).unwrap();
        let decoded = PkiCoder::decode_ieee1609dot2_data(&encoded).unwrap();

        assert_eq!(decoded.protocol_version, Uint8(3));
        match decoded.content {
            Ieee1609Dot2Content::unsecuredData(data) => {
                assert_eq!(data.0.as_ref(), payload.as_slice());
            }
            _ => panic!("Expected unsecuredData"),
        }
    }

    #[test]
    fn test_encode_decode_etsi102941_data() {
        let its_id = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let vk = PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_0(
            vec![0u8; 32].into(),
        ));
        let public_keys = PublicKeys::new(vk, None);
        let subject_attrs = CertificateSubjectAttributes::new(None, None, None, None, None, None);

        let inner_ec = InnerECRequest::new(
            its_id.clone().into(),
            CertificateFormat(Uint8(1)),
            public_keys,
            subject_attrs,
        );

        let etsi_data = EtsiTs102941Data::new(
            Uint8(1),
            EtsiTs102941DataContent::enrolmentRequest(inner_ec),
        );

        let encoded = PkiCoder::encode_etsi102941_data(&etsi_data).unwrap();
        let decoded = PkiCoder::decode_etsi102941_data(&encoded).unwrap();

        assert_eq!(decoded.version, Uint8(1));
        match decoded.content {
            EtsiTs102941DataContent::enrolmentRequest(req) => {
                assert_eq!(req.its_id.as_ref(), its_id.as_slice());
            }
            _ => panic!("Expected enrolmentRequest"),
        }
    }

    #[test]
    fn test_encode_decode_inner_ec_response() {
        let resp = InnerECResponse::new(Uint8(1), EnrolmentResponseCode::ok, None);
        let encoded = PkiCoder::encode_inner_ec_response(&resp).unwrap();
        let decoded = PkiCoder::decode_inner_ec_response(&encoded).unwrap();

        assert_eq!(decoded.version, Uint8(1));
        assert_eq!(decoded.response_code, EnrolmentResponseCode::ok);
    }

    #[test]
    fn test_encode_decode_shared_at_request() {
        let ea_id = HashedId8(FixedOctetString::from([0xAA; 8]));
        let key_tag = vec![0xBB; 16];
        let subject_attrs = CertificateSubjectAttributes::new(None, None, None, None, None, None);

        let shared_at = SharedAtRequest::new(
            ea_id,
            key_tag.into(),
            CertificateFormat(Uint8(1)),
            subject_attrs,
        );

        let encoded = PkiCoder::encode_shared_at_request(&shared_at).unwrap();
        let decoded = PkiCoder::decode_shared_at_request(&encoded).unwrap();

        assert_eq!(decoded.ea_id.0.as_ref(), &[0xAA; 8]);
        assert_eq!(decoded.key_tag.as_ref(), &[0xBB; 16]);
    }

    #[test]
    fn test_encode_decode_inner_at_request() {
        let vk = PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_0(
            vec![0x11; 32].into(),
        ));
        let public_keys = PublicKeys::new(vk, None);
        let hmac_key = vec![0x22; 32];
        let ea_id = HashedId8(FixedOctetString::from([0xAA; 8]));
        let key_tag = vec![0xBB; 16];
        let subject_attrs = CertificateSubjectAttributes::new(None, None, None, None, None, None);

        let shared_at = SharedAtRequest::new(
            ea_id,
            key_tag.into(),
            CertificateFormat(Uint8(1)),
            subject_attrs,
        );

        let dummy_dot2 = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::unsecuredData(Opaque(vec![0u8; 4].into())),
        );
        let ec_sig = EcSignature::ecSignature(dummy_dot2);

        let inner_at = InnerAtRequest::new(public_keys, hmac_key.into(), shared_at, ec_sig);

        let encoded = PkiCoder::encode_inner_at_request(&inner_at).unwrap();
        let decoded = PkiCoder::decode_inner_at_request(&encoded).unwrap();

        assert_eq!(decoded.hmac_key.as_ref(), &[0x22; 32]);
    }

    #[test]
    fn test_encode_decode_inner_at_response() {
        let resp = InnerAtResponse::new(vec![0x33; 16].into(), AuthorizationResponseCode::ok, None);
        let encoded = PkiCoder::encode_inner_at_response(&resp).unwrap();
        let decoded = PkiCoder::decode_inner_at_response(&encoded).unwrap();

        assert_eq!(decoded.request_hash.as_ref(), &[0x33; 16]);
        assert_eq!(decoded.response_code, AuthorizationResponseCode::ok);
    }

    #[test]
    fn test_encode_decode_public_keys() {
        let vk = PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_0(
            vec![0x44; 32].into(),
        ));
        let public_keys = PublicKeys::new(vk, None);

        let encoded = PkiCoder::encode_public_keys(&public_keys).unwrap();
        let decoded = PkiCoder::decode_public_keys(&encoded).unwrap();

        match decoded.verification_key {
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_0(pt)) => {
                assert_eq!(pt.as_ref(), &[0x44; 32]);
            }
            _ => panic!("Expected compressed_y_0"),
        }
    }
}

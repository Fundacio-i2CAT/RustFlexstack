// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ASN.1 types of the ETSI TS 102 941 V2.2.1 ITS-S messages (official modules
//! of <https://forge.etsi.org/rep/ITS/asn1/pki_ts102941>, tag v2.2.1):
//! `EtsiTs102941BaseTypes`, `EtsiTs102941TypesEnrolment`,
//! `EtsiTs102941TypesAuthorization`, `EtsiTs102941TrustLists`,
//! `EtsiTs102941TypesLinkCertificate` and `EtsiTs102941MessagesItss`.
//!
//! `#[non_exhaustive]` marks the extensible types (`...`), as in the code
//! generated for the other modules. Subtype constraints (`WITH COMPONENTS`)
//! are checked by the PKI client, not by the types. The alternatives of
//! `EtsiTs102941DataContent` added for butterfly key expansion carry IEEE
//! 1609.2.1 types; butterfly is not implemented and they are kept as OCTET
//! STRINGs, as the IEEE 1609.2.1 stubs of the Python stack (rasn cannot decode
//! [`rasn::types::Any`] in OER: it panics), which does not affect the other
//! alternatives.
//! The encodings are checked against frozen vectors produced from the official
//! module text (Python stack, `test_pki_coder.py`).

#![allow(
    non_camel_case_types,
    non_snake_case,
    clippy::too_many_arguments,
    clippy::large_enum_variant
)]

use rasn::prelude::*;

use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::security_asn::ieee1609_dot2::{
    CertificateId, HashedData, Ieee1609Dot2Data, SequenceOfPsidGroupPermissions,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    GeographicRegion, HashedId8, PublicEncryptionKey, PublicVerificationKey, SequenceOfPsidSsp,
    SubjectAssurance, Time32, ValidityPeriod,
};

/// `EtsiTs102941BaseTypes`.
pub mod etsi_ts102941_base_types {
    use super::*;

    /// `CertificateFormat ::= INTEGER {ts103097v131 (1)} (1..255)`.
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("1..=255"))]
    pub struct CertificateFormat(pub u8);

    /// ts103097v131.
    pub const TS103097V131: CertificateFormat = CertificateFormat(1);

    /// `CertificateSubjectAttributes` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Default)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CertificateSubjectAttributes {
        pub id: Option<CertificateId>,
        #[rasn(identifier = "validityPeriod")]
        pub validity_period: Option<ValidityPeriod>,
        pub region: Option<GeographicRegion>,
        #[rasn(identifier = "assuranceLevel")]
        pub assurance_level: Option<SubjectAssurance>,
        #[rasn(identifier = "appPermissions")]
        pub app_permissions: Option<SequenceOfPsidSsp>,
        #[rasn(identifier = "certIssuePermissions")]
        pub cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
    }

    impl CertificateSubjectAttributes {
        pub fn new(
            id: Option<CertificateId>,
            validity_period: Option<ValidityPeriod>,
            region: Option<GeographicRegion>,
            assurance_level: Option<SubjectAssurance>,
            app_permissions: Option<SequenceOfPsidSsp>,
            cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
        ) -> Self {
            Self {
                id,
                validity_period,
                region,
                assurance_level,
                app_permissions,
                cert_issue_permissions,
            }
        }
    }

    /// `EcSignature`: the EC signature of the SharedAtRequest, encrypted for the
    /// EA (privacy) or not.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EcSignature {
        encryptedEcSignature(Ieee1609Dot2Data),
        ecSignature(Ieee1609Dot2Data),
    }

    /// `PublicKeys` (not extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PublicKeys {
        #[rasn(identifier = "verificationKey")]
        pub verification_key: PublicVerificationKey,
        #[rasn(identifier = "encryptionKey")]
        pub encryption_key: Option<PublicEncryptionKey>,
    }

    impl PublicKeys {
        pub fn new(
            verification_key: PublicVerificationKey,
            encryption_key: Option<PublicEncryptionKey>,
        ) -> Self {
            Self {
                verification_key,
                encryption_key,
            }
        }
    }
}

/// `EtsiTs102941TypesEnrolment`.
pub mod etsi_ts102941_types_enrolment {
    use super::etsi_ts102941_base_types::*;
    use super::*;

    /// `EnrolmentResponseCode` (extensible).
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum EnrolmentResponseCode {
        ok = 0,
        cantparse = 1,
        badcontenttype = 2,
        imnottherecipient = 3,
        unknownencryptionalgorithm = 4,
        decryptionfailed = 5,
        unknownits = 6,
        invalidsignature = 7,
        invalidencryptionkey = 8,
        baditsstatus = 9,
        incompleterequest = 10,
        deniedpermissions = 11,
        invalidkeys = 12,
        deniedrequest = 13,
    }

    /// `InnerEcRequestSignedForPop ::= EtsiTs103097Data-Signed{InnerEcRequest}`.
    pub type InnerEcRequestSignedForPop = Ieee1609Dot2Data;

    /// `InnerEcRequest` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerEcRequest {
        #[rasn(identifier = "itsId")]
        pub its_id: OctetString,
        #[rasn(identifier = "certificateFormat")]
        pub certificate_format: CertificateFormat,
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }

    impl InnerEcRequest {
        pub fn new(
            its_id: OctetString,
            certificate_format: CertificateFormat,
            public_keys: PublicKeys,
            requested_subject_attributes: CertificateSubjectAttributes,
        ) -> Self {
            Self {
                its_id,
                certificate_format,
                public_keys,
                requested_subject_attributes,
            }
        }
    }

    /// `InnerEcResponse` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerEcResponse {
        #[rasn(identifier = "requestHash")]
        pub request_hash: FixedOctetString<16>,
        #[rasn(identifier = "responseCode")]
        pub response_code: EnrolmentResponseCode,
        pub certificate: Option<EtsiTs103097Certificate>,
    }

    impl InnerEcResponse {
        pub fn new(
            request_hash: FixedOctetString<16>,
            response_code: EnrolmentResponseCode,
            certificate: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                certificate,
            }
        }
    }
}

/// `EtsiTs102941TypesAuthorization`.
pub mod etsi_ts102941_types_authorization {
    use super::etsi_ts102941_base_types::*;
    use super::*;

    /// `AuthorizationResponseCode` (extensible).
    #[derive(AsnType, Debug, Clone, Copy, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum AuthorizationResponseCode {
        ok = 0,
        #[rasn(identifier = "its-aa-cantparse")]
        its_aa_cantparse = 1,
        #[rasn(identifier = "its-aa-badcontenttype")]
        its_aa_badcontenttype = 2,
        #[rasn(identifier = "its-aa-imnottherecipient")]
        its_aa_imnottherecipient = 3,
        #[rasn(identifier = "its-aa-unknownencryptionalgorithm")]
        its_aa_unknownencryptionalgorithm = 4,
        #[rasn(identifier = "its-aa-decryptionfailed")]
        its_aa_decryptionfailed = 5,
        #[rasn(identifier = "its-aa-keysdontmatch")]
        its_aa_keysdontmatch = 6,
        #[rasn(identifier = "its-aa-incompleterequest")]
        its_aa_incompleterequest = 7,
        #[rasn(identifier = "its-aa-invalidencryptionkey")]
        its_aa_invalidencryptionkey = 8,
        #[rasn(identifier = "its-aa-outofsyncrequest")]
        its_aa_outofsyncrequest = 9,
        #[rasn(identifier = "its-aa-unknownea")]
        its_aa_unknownea = 10,
        #[rasn(identifier = "its-aa-invalidea")]
        its_aa_invalidea = 11,
        #[rasn(identifier = "its-aa-deniedpermissions")]
        its_aa_deniedpermissions = 12,
        #[rasn(identifier = "aa-ea-cantreachea")]
        aa_ea_cantreachea = 13,
        #[rasn(identifier = "ea-aa-cantparse")]
        ea_aa_cantparse = 14,
        #[rasn(identifier = "ea-aa-badcontenttype")]
        ea_aa_badcontenttype = 15,
        #[rasn(identifier = "ea-aa-imnottherecipient")]
        ea_aa_imnottherecipient = 16,
        #[rasn(identifier = "ea-aa-unknownencryptionalgorithm")]
        ea_aa_unknownencryptionalgorithm = 17,
        #[rasn(identifier = "ea-aa-decryptionfailed")]
        ea_aa_decryptionfailed = 18,
        invalidaa = 19,
        invalidaasignature = 20,
        wrongea = 21,
        unknownits = 22,
        invalidsignature = 23,
        invalidencryptionkey = 24,
        deniedpermissions = 25,
        deniedtoomanycerts = 26,
    }

    /// `InnerAtRequest` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerAtRequest {
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(identifier = "hmacKey")]
        pub hmac_key: FixedOctetString<32>,
        #[rasn(identifier = "sharedAtRequest")]
        pub shared_at_request: SharedAtRequest,
        #[rasn(identifier = "ecSignature")]
        pub ec_signature: EcSignature,
    }

    impl InnerAtRequest {
        pub fn new(
            public_keys: PublicKeys,
            hmac_key: FixedOctetString<32>,
            shared_at_request: SharedAtRequest,
            ec_signature: EcSignature,
        ) -> Self {
            Self {
                public_keys,
                hmac_key,
                shared_at_request,
                ec_signature,
            }
        }
    }

    /// `SharedAtRequest` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct SharedAtRequest {
        #[rasn(identifier = "eaId")]
        pub ea_id: HashedId8,
        #[rasn(identifier = "keyTag")]
        pub key_tag: FixedOctetString<16>,
        #[rasn(identifier = "certificateFormat")]
        pub certificate_format: CertificateFormat,
        #[rasn(identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }

    impl SharedAtRequest {
        pub fn new(
            ea_id: HashedId8,
            key_tag: FixedOctetString<16>,
            certificate_format: CertificateFormat,
            requested_subject_attributes: CertificateSubjectAttributes,
        ) -> Self {
            Self {
                ea_id,
                key_tag,
                certificate_format,
                requested_subject_attributes,
            }
        }
    }

    /// `InnerAtResponse` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerAtResponse {
        #[rasn(identifier = "requestHash")]
        pub request_hash: FixedOctetString<16>,
        #[rasn(identifier = "responseCode")]
        pub response_code: AuthorizationResponseCode,
        pub certificate: Option<EtsiTs103097Certificate>,
    }

    impl InnerAtResponse {
        pub fn new(
            request_hash: FixedOctetString<16>,
            response_code: AuthorizationResponseCode,
            certificate: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                certificate,
            }
        }
    }
}

/// `EtsiTs102941TrustLists`.
pub mod etsi_ts102941_trust_lists {
    use super::*;

    /// `Url ::= IA5String`.
    pub type Url = Ia5String;
    /// `CrlEntry ::= HashedId8`.
    pub type CrlEntry = HashedId8;

    /// `ToBeSignedCrl` (extensible); `version` is `Version ::= INTEGER {v1(1)}`.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedCrl {
        pub version: Integer,
        #[rasn(identifier = "thisUpdate")]
        pub this_update: Time32,
        #[rasn(identifier = "nextUpdate")]
        pub next_update: Time32,
        pub entries: SequenceOf<CrlEntry>,
    }

    impl ToBeSignedCrl {
        pub fn new(
            version: Integer,
            this_update: Time32,
            next_update: Time32,
            entries: SequenceOf<CrlEntry>,
        ) -> Self {
            Self {
                version,
                this_update,
                next_update,
                entries,
            }
        }
    }

    /// `CtlFormat` (extensible); `ToBeSignedTlmCtl` and `ToBeSignedRcaCtl` are
    /// subtypes of it (full or delta CTL, allowed entries).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CtlFormat {
        pub version: Integer,
        #[rasn(identifier = "nextUpdate")]
        pub next_update: Time32,
        #[rasn(identifier = "isFullCtl")]
        pub is_full_ctl: bool,
        #[rasn(identifier = "ctlSequence", value("0..=255"))]
        pub ctl_sequence: u8,
        #[rasn(identifier = "ctlCommands")]
        pub ctl_commands: SequenceOf<CtlCommand>,
    }

    impl CtlFormat {
        pub fn new(
            version: Integer,
            next_update: Time32,
            is_full_ctl: bool,
            ctl_sequence: u8,
            ctl_commands: SequenceOf<CtlCommand>,
        ) -> Self {
            Self {
                version,
                next_update,
                is_full_ctl,
                ctl_sequence,
                ctl_commands,
            }
        }
    }

    pub type ToBeSignedTlmCtl = CtlFormat;
    pub type ToBeSignedRcaCtl = CtlFormat;

    /// `CtlCommand` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlCommand {
        add(CtlEntry),
        delete(CtlDelete),
    }

    /// `CtlEntry` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlEntry {
        rca(RootCaEntry),
        ea(EaEntry),
        aa(AaEntry),
        dc(DcEntry),
        tlm(TlmEntry),
    }

    /// `CtlDelete` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlDelete {
        cert(HashedId8),
        dc(Url),
    }

    /// `TlmEntry`.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct TlmEntry {
        #[rasn(identifier = "selfSignedTLMCertificate")]
        pub self_signed_tlm_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "successorTo")]
        pub successor_to: Option<EtsiTs103097Certificate>,
        #[rasn(identifier = "accessPoint")]
        pub access_point: Url,
    }

    /// `RootCaEntry`.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct RootCaEntry {
        #[rasn(identifier = "selfsignedRootCa")]
        pub selfsigned_root_ca: EtsiTs103097Certificate,
        #[rasn(identifier = "successorTo")]
        pub successor_to: Option<EtsiTs103097Certificate>,
    }

    /// `EaEntry`.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EaEntry {
        #[rasn(identifier = "eaCertificate")]
        pub ea_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "aaAccessPoint")]
        pub aa_access_point: Url,
        #[rasn(identifier = "itsAccessPoint")]
        pub its_access_point: Option<Url>,
    }

    /// `AaEntry`.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct AaEntry {
        #[rasn(identifier = "aaCertificate")]
        pub aa_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "accessPoint")]
        pub access_point: Url,
    }

    /// `DcEntry`.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct DcEntry {
        pub url: Url,
        pub cert: SequenceOf<HashedId8>,
    }
}

/// `EtsiTs102941TypesLinkCertificate`.
pub mod etsi_ts102941_types_link_certificate {
    use super::*;

    /// `ToBeSignedLinkCertificate` (extensible); the TLM and RCA variants are the same type.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedLinkCertificate {
        #[rasn(identifier = "expiryTime")]
        pub expiry_time: Time32,
        #[rasn(identifier = "certificateHash")]
        pub certificate_hash: HashedData,
    }

    pub type ToBeSignedLinkCertificateTlm = ToBeSignedLinkCertificate;
}

/// `EtsiTs102941MessagesItss`.
pub mod etsi_ts102941_messages_itss {
    use super::etsi_ts102941_trust_lists::*;
    use super::etsi_ts102941_types_authorization::*;
    use super::etsi_ts102941_types_enrolment::*;
    use super::etsi_ts102941_types_link_certificate::*;
    use super::*;

    /// `EtsiTs102941Data`; `version` is `Version (v1)`, i.e. the value 1.
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941Data {
        #[rasn(value("1"))]
        pub version: u8,
        pub content: EtsiTs102941DataContent,
    }

    impl EtsiTs102941Data {
        /// Version v1 with `content`.
        pub fn new(content: EtsiTs102941DataContent) -> Self {
            Self {
                version: 1,
                content,
            }
        }
    }

    /// `EtsiTs102941DataContent` (extensible).
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EtsiTs102941DataContent {
        enrolmentRequest(InnerEcRequestSignedForPop),
        enrolmentResponse(InnerEcResponse),
        authorizationRequest(InnerAtRequest),
        authorizationResponse(InnerAtResponse),
        certificateRevocationList(ToBeSignedCrl),
        certificateTrustListTlm(ToBeSignedTlmCtl),
        certificateTrustListRca(ToBeSignedRcaCtl),
        authorizationValidationRequest(()),
        authorizationValidationResponse(()),
        caCertificateRequest(()),
        #[rasn(extension_addition)]
        linkCertificateTlm(ToBeSignedLinkCertificateTlm),
        #[rasn(extension_addition)]
        singleSignedLinkCertificateRca(()),
        #[rasn(extension_addition)]
        doubleSignedlinkCertificateRca(()),
        #[rasn(extension_addition)]
        butterflyAuthorizationRequest(OctetString),
        #[rasn(extension_addition)]
        x509SignedbutterflyAuthorizationRequest(OctetString),
        #[rasn(extension_addition)]
        butterflyAuthorizationResponse(OctetString),
        #[rasn(extension_addition)]
        butterflyCertificateRequest(()),
        #[rasn(extension_addition)]
        butterflyCertificateResponse(()),
        #[rasn(extension_addition)]
        butterflyAtDownloadRequest(OctetString),
    }
}

/// COER encoding.
pub fn encode<T: Encode>(value: &T) -> Vec<u8> {
    rasn::coer::encode(value).expect("COER encoding of a PKI type")
}

/// COER decoding.
pub fn decode<T: Decode>(data: &[u8]) -> Result<T, rasn::error::DecodeError> {
    rasn::coer::decode(data)
}

#[cfg(test)]
mod tests {
    use super::etsi_ts102941_base_types::*;
    use super::etsi_ts102941_messages_itss::*;
    use super::etsi_ts102941_trust_lists::*;
    use super::etsi_ts102941_types_authorization::*;
    use super::etsi_ts102941_types_enrolment::*;
    use super::*;
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        BasePublicEncryptionKey, BitmapSsp, Duration, EccP256CurvePoint, Psid, PsidSsp,
        ServiceSpecificPermissions, SymmAlgorithm, Uint16, Uint32,
    };

    /// Frozen COER encodings of the official types, produced by asn1tools from
    /// the forge.etsi.org module text (FlexStack `test_pki_coder.py`).
    const INNER_EC_REQUEST: &str = "000831323334353637380180808211111111111111111111111111111111111111111111111111111111111111110080832222222222222222222222222222222222222222222222222222222222222222240000006486000101018002026f81030201c0";
    const INNER_EC_RESPONSE: &str = "00abababababababababababababababab0d";
    const SHARED_AT_REQUEST: &str =
        "00aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01040102000124000125";
    const INNER_AT_RESPONSE: &str = "00cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd0a";
    const CRL: &str = "0184000101000000050000000601010101010101010101";
    const RCA_CTL: &str = "0186000101000000070003010280830b68747470733a2f2f64632f0101020202020202020281800303030303030303";
    const AT_REQUEST: &str = "0182000080834444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555500aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01040101000124800382010182666666666666666680827777777777777777777777777777777777777777777777777777777777777777888888888888888888888888888888889999999999999999999999999999999980121212121212121212121212143434343434343434343434343434343434343434";

    fn psid_ssp(psid: i64, ssp: Option<&[u8]>) -> PsidSsp {
        PsidSsp::new(
            Psid(Integer::from(psid)),
            ssp.map(|s| ServiceSpecificPermissions::bitmapSsp(BitmapSsp(s.to_vec().into()))),
        )
    }

    fn check<T: Encode + Decode + PartialEq + std::fmt::Debug>(value: T, vector: &str) {
        let encoded = encode(&value);
        assert_eq!(hex(&encoded), vector);
        assert_eq!(decode::<T>(&encoded).unwrap(), value);
    }

    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A butterfly alternative (extension addition 13) decodes, as an OCTET STRING
    /// (IEEE 1609.2.1 stub), instead of panicking as `Any` did; the encoding of the
    /// Python stack (`018d0403010203`).
    #[test]
    fn butterfly_alternative_decodes() {
        use super::etsi_ts102941_messages_itss::{EtsiTs102941Data, EtsiTs102941DataContent};
        let bytes = [0x01, 0x8d, 0x04, 0x03, 0x01, 0x02, 0x03];
        let data: EtsiTs102941Data = decode(&bytes).unwrap();
        assert!(matches!(
            &data.content,
            EtsiTs102941DataContent::butterflyAuthorizationRequest(o) if o.as_ref() == [1, 2, 3]
        ));
        assert_eq!(encode(&data), bytes);
    }

    /// The official ETSI TS 102 941 V2.2.1 encodings: extension bits in the
    /// preambles, CHOICE indexes (CRL 4, RCA CTL 6), Version length-prefixed in
    /// CtlFormat / ToBeSignedCrl and one octet in EtsiTs102941Data.
    #[test]
    fn official_encodings() {
        let attributes = CertificateSubjectAttributes::new(
            None,
            Some(ValidityPeriod::new(
                Time32(Uint32(100)),
                Duration::years(Uint16(1)),
            )),
            None,
            None,
            Some(SequenceOfPsidSsp(vec![psid_ssp(623, Some(&[1, 0xC0]))])),
            None,
        );
        check(
            InnerEcRequest::new(
                b"12345678".to_vec().into(),
                TS103097V131,
                PublicKeys::new(
                    PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_0(
                        vec![0x11; 32].into(),
                    )),
                    Some(PublicEncryptionKey::new(
                        SymmAlgorithm::aes128Ccm,
                        BasePublicEncryptionKey::eciesNistP256(EccP256CurvePoint::compressed_y_1(
                            vec![0x22; 32].into(),
                        )),
                    )),
                ),
                attributes,
            ),
            INNER_EC_REQUEST,
        );
        check(
            InnerEcResponse::new(
                FixedOctetString::from([0xAB; 16]),
                EnrolmentResponseCode::deniedrequest,
                None,
            ),
            INNER_EC_RESPONSE,
        );
        check(
            SharedAtRequest::new(
                HashedId8(FixedOctetString::from([0xAA; 8])),
                FixedOctetString::from([0xBB; 16]),
                TS103097V131,
                CertificateSubjectAttributes::new(
                    None,
                    None,
                    None,
                    None,
                    Some(SequenceOfPsidSsp(vec![
                        psid_ssp(36, None),
                        psid_ssp(37, None),
                    ])),
                    None,
                ),
            ),
            SHARED_AT_REQUEST,
        );
        check(
            InnerAtResponse::new(
                FixedOctetString::from([0xCD; 16]),
                AuthorizationResponseCode::its_aa_unknownea,
                None,
            ),
            INNER_AT_RESPONSE,
        );
        check(
            EtsiTs102941Data::new(EtsiTs102941DataContent::certificateRevocationList(
                ToBeSignedCrl::new(
                    Integer::from(1),
                    Time32(Uint32(5)),
                    Time32(Uint32(6)),
                    vec![HashedId8(FixedOctetString::from([1; 8]))],
                ),
            )),
            CRL,
        );
        check(
            EtsiTs102941Data::new(EtsiTs102941DataContent::certificateTrustListRca(
                CtlFormat::new(
                    Integer::from(1),
                    Time32(Uint32(7)),
                    false,
                    3,
                    vec![
                        CtlCommand::add(CtlEntry::dc(DcEntry {
                            url: Ia5String::try_from("https://dc/".to_string()).unwrap(),
                            cert: vec![HashedId8(FixedOctetString::from([2; 8]))],
                        })),
                        CtlCommand::delete(CtlDelete::cert(HashedId8(FixedOctetString::from(
                            [3; 8],
                        )))),
                    ],
                ),
            )),
            RCA_CTL,
        );
        // EcSignature: encryptedEcSignature is alternative 0 (80h)
        use crate::security::security_asn::ieee1609_dot2::{
            EncryptedData, EncryptedDataEncryptionKey, Ieee1609Dot2Content, One28BitCcmCiphertext,
            PKRecipientInfo, RecipientInfo, SequenceOfRecipientInfo, SymmetricCiphertext,
        };
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            EciesP256EncryptedKey, Opaque, Uint8,
        };
        let encrypted = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::encryptedData(EncryptedData::new(
                SequenceOfRecipientInfo(vec![RecipientInfo::certRecipInfo(PKRecipientInfo::new(
                    HashedId8(FixedOctetString::from([0x66; 8])),
                    EncryptedDataEncryptionKey::eciesNistP256(EciesP256EncryptedKey {
                        v: EccP256CurvePoint::compressed_y_0(vec![0x77; 32].into()),
                        c: vec![0x88; 16].into(),
                        t: vec![0x99; 16].into(),
                    }),
                ))]),
                SymmetricCiphertext::aes128ccm(One28BitCcmCiphertext::new(
                    vec![0x12; 12].into(),
                    Opaque(vec![0x34; 20].into()),
                )),
            )),
        );
        check(
            EtsiTs102941Data::new(EtsiTs102941DataContent::authorizationRequest(
                InnerAtRequest::new(
                    PublicKeys::new(
                        PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::compressed_y_1(
                            vec![0x44; 32].into(),
                        )),
                        None,
                    ),
                    FixedOctetString::from([0x55; 32]),
                    SharedAtRequest::new(
                        HashedId8(FixedOctetString::from([0xAA; 8])),
                        FixedOctetString::from([0xBB; 16]),
                        TS103097V131,
                        CertificateSubjectAttributes::new(
                            None,
                            None,
                            None,
                            None,
                            Some(SequenceOfPsidSsp(vec![psid_ssp(36, None)])),
                            None,
                        ),
                    ),
                    EcSignature::encryptedEcSignature(encrypted),
                ),
            )),
            AT_REQUEST,
        );
    }
}

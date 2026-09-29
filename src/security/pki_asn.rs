#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
use crate::security::security_asn::{
    etsi_ts103097_module, ieee1609_dot2, ieee1609_dot2_base_types,
};

pub mod etsi_ts102941_base_types {
    extern crate alloc;
    use super::etsi_ts103097_module::EtsiTs103097Certificate;
    use super::ieee1609_dot2::{CertificateId, Ieee1609Dot2Data, SequenceOfPsidGroupPermissions};
    use super::ieee1609_dot2_base_types::{
        GeographicRegion, HashedId8, PublicEncryptionKey, PublicVerificationKey, SequenceOfPsidSsp,
        SubjectAssurance, Time32, Uint8, ValidityPeriod,
    };
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[doc = " Certificate format version: 1 = ts103097v131"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct CertificateFormat(pub Uint8);
    #[doc = " Subject attributes requested in EC/AT certificate"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
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
    #[doc = " Sequential number for CTL/CRL"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct CtlSequenceNumber(pub Uint8);
    #[doc = " EC signature (over SharedAtRequest), either privacy-protected (encrypted) or plain"]
    #[doc = " The privacy case encrypts the signed structure with the EA's encryption key."]
    #[doc = " Both alternatives carry an EtsiTs103097Data structure."]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EcSignature {
        ecSignature(Ieee1609Dot2Data),
        encryptedEcSignature(Ieee1609Dot2Data),
    }
    #[doc = " HashedId10: 10-byte truncated hash used in CRL entries"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct HashedId10(pub FixedOctetString<10usize>);
    #[doc = " Container for the verification + optional encryption public keys"]
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
    #[doc = " URL type (up to 2048 UTF-8 characters)"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("0..=2048"))]
    pub struct Url(pub Utf8String);
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_messages_itss {
    extern crate alloc;
    use super::etsi_ts102941_trust_lists::{ToBeSignedCrl, ToBeSignedRcaCtl};
    use super::etsi_ts102941_types_authorization::{InnerAtRequest, InnerAtResponse};
    use super::etsi_ts102941_types_authorization_validation::{
        AuthorizationValidationRequest, AuthorizationValidationResponse,
    };
    use super::etsi_ts102941_types_enrolment::{InnerECRequest, InnerECResponse};
    use super::ieee1609_dot2_base_types::Uint8;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[doc = " TS 102 941 v2.2.1 §6.2 — Top-level ETSI TS 102 941 message envelope"]
    #[doc = " This wraps all PKI protocol messages with a version field."]
    #[doc = " Conveyed as the payload of an EtsiTs103097Data-Signed or -Encrypted structure."]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941Data {
        #[rasn(value("1"))]
        pub version: Uint8,
        pub content: EtsiTs102941DataContent,
    }
    impl EtsiTs102941Data {
        pub fn new(version: Uint8, content: EtsiTs102941DataContent) -> Self {
            Self { version, content }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum EtsiTs102941DataContent {
        enrolmentRequest(InnerECRequest),
        enrolmentResponse(InnerECResponse),
        authorizationRequest(InnerAtRequest),
        authorizationResponse(InnerAtResponse),
        authorizationValidationRequest(AuthorizationValidationRequest),
        authorizationValidationResponse(AuthorizationValidationResponse),
        certificateTrustListTlm(ToBeSignedRcaCtl),
        certificateTrustListRca(ToBeSignedRcaCtl),
        certificateRevocationList(ToBeSignedCrl),
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_trust_lists {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{CtlSequenceNumber, HashedId10, Url};
    use super::etsi_ts103097_module::EtsiTs103097Certificate;
    use super::ieee1609_dot2_base_types::{HashedId8, Time32};
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct AaEntry {
        #[rasn(identifier = "aaCertificate")]
        pub aa_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "itsAccessPoint")]
        pub its_access_point: Option<Url>,
    }
    impl AaEntry {
        pub fn new(aa_certificate: EtsiTs103097Certificate, its_access_point: Option<Url>) -> Self {
            Self {
                aa_certificate,
                its_access_point,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct CrlEntry {
        #[rasn(identifier = "revokedCertificate")]
        pub revoked_certificate: HashedId10,
        pub expiry: Time32,
    }
    impl CrlEntry {
        pub fn new(revoked_certificate: HashedId10, expiry: Time32) -> Self {
            Self {
                revoked_certificate,
                expiry,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum CtlCommand {
        add(CtlEntry),
        delete(CtlDeleteEntry),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum CtlDeleteEntry {
        ea(HashedId8),
        aa(HashedId8),
        dc(HashedId8),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum CtlEntry {
        ea(EaEntry),
        aa(AaEntry),
        dc(DcEntry),
    }
    #[doc = " TS 102 941 v2.2.1 §6.3 — Trust List structures"]
    #[doc = " Top-level CTL format: full or delta"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    pub enum CtlFormat {
        fullCtl(ToBeSignedRcaCtl),
        deltaCtl(ToBeSignedRcaCtl),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct DcEntry {
        pub url: Url,
        pub cert: Option<SequenceOf<EtsiTs103097Certificate>>,
    }
    impl DcEntry {
        pub fn new(url: Url, cert: Option<SequenceOf<EtsiTs103097Certificate>>) -> Self {
            Self { url, cert }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct EaEntry {
        #[rasn(identifier = "eaCertificate")]
        pub ea_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "aaAccessPoint")]
        pub aa_access_point: Option<Url>,
        #[rasn(identifier = "itsAccessPoint")]
        pub its_access_point: Option<Url>,
    }
    impl EaEntry {
        pub fn new(
            ea_certificate: EtsiTs103097Certificate,
            aa_access_point: Option<Url>,
            its_access_point: Option<Url>,
        ) -> Self {
            Self {
                ea_certificate,
                aa_access_point,
                its_access_point,
            }
        }
    }
    #[doc = " CRL structures (TS 102 941 v2.2.1 §6.3.5)"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ToBeSignedCrl {
        #[rasn(value("1"))]
        pub version: u8,
        #[rasn(identifier = "thisUpdate")]
        pub this_update: Time32,
        #[rasn(identifier = "nextUpdate")]
        pub next_update: Time32,
        pub entries: SequenceOf<CrlEntry>,
    }
    impl ToBeSignedCrl {
        pub fn new(
            version: u8,
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
    #[doc = " Full and delta share the same structure (distinguished by context)"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct ToBeSignedRcaCtl {
        #[rasn(value("1"))]
        pub version: u8,
        #[rasn(identifier = "nextUpdate")]
        pub next_update: Time32,
        #[rasn(identifier = "isFullCtl")]
        pub is_full_ctl: bool,
        #[rasn(identifier = "ctlSequence")]
        pub ctl_sequence: CtlSequenceNumber,
        #[rasn(identifier = "ctlCommands")]
        pub ctl_commands: SequenceOf<CtlCommand>,
    }
    impl ToBeSignedRcaCtl {
        pub fn new(
            version: u8,
            next_update: Time32,
            is_full_ctl: bool,
            ctl_sequence: CtlSequenceNumber,
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
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_authorization {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, EcSignature, PublicKeys,
    };
    use super::etsi_ts103097_module::EtsiTs103097Certificate;
    use super::ieee1609_dot2_base_types::HashedId8;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
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
    #[doc = " Inner AT request (encrypted and sent to AA)"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct InnerAtRequest {
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(size("32"), identifier = "hmacKey")]
        pub hmac_key: OctetString,
        #[rasn(identifier = "sharedAtRequest")]
        pub shared_at_request: SharedAtRequest,
        #[rasn(identifier = "ecSignature")]
        pub ec_signature: EcSignature,
    }
    impl InnerAtRequest {
        pub fn new(
            public_keys: PublicKeys,
            hmac_key: OctetString,
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
    #[doc = " NOTE: InnerAtResponse has NO version field (unlike InnerECResponse)."]
    #[doc = " Per TS 102 941 v2.2.1 EtsiTs102941TypesAuthorization ASN.1 module."]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct InnerAtResponse {
        #[rasn(size("16"), identifier = "requestHash")]
        pub request_hash: OctetString,
        #[rasn(identifier = "responseCode")]
        pub response_code: AuthorizationResponseCode,
        pub certificate: Option<EtsiTs103097Certificate>,
    }
    impl InnerAtResponse {
        pub fn new(
            request_hash: OctetString,
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
    #[doc = " TS 102 941 v2.2.1 §6.2.3.3 — Authorization"]
    #[doc = " Shared portion of the AT request (forwarded by AA to EA for validation)"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct SharedAtRequest {
        #[rasn(identifier = "eaId")]
        pub ea_id: HashedId8,
        #[rasn(size("16"), identifier = "keyTag")]
        pub key_tag: OctetString,
        #[rasn(identifier = "certificateFormat")]
        pub certificate_format: CertificateFormat,
        #[rasn(identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }
    impl SharedAtRequest {
        pub fn new(
            ea_id: HashedId8,
            key_tag: OctetString,
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
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_authorization_validation {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{CertificateSubjectAttributes, EcSignature};
    use super::etsi_ts102941_types_authorization::SharedAtRequest;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[doc = " TS 102 941 v2.2.1 §6.2.3.4 — Authorization Validation (S4: AA → EA)"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AuthorizationValidationRequest {
        #[rasn(identifier = "sharedAtRequest")]
        pub shared_at_request: SharedAtRequest,
        #[rasn(identifier = "ecSignature")]
        pub ec_signature: EcSignature,
    }
    impl AuthorizationValidationRequest {
        pub fn new(shared_at_request: SharedAtRequest, ec_signature: EcSignature) -> Self {
            Self {
                shared_at_request,
                ec_signature,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct AuthorizationValidationResponse {
        #[rasn(size("16"), identifier = "requestHash")]
        pub request_hash: OctetString,
        #[rasn(identifier = "responseCode")]
        pub response_code: AuthorizationValidationResponseCode,
        #[rasn(identifier = "confirmedSubjectAttributes")]
        pub confirmed_subject_attributes: Option<CertificateSubjectAttributes>,
    }
    impl AuthorizationValidationResponse {
        pub fn new(
            request_hash: OctetString,
            response_code: AuthorizationValidationResponseCode,
            confirmed_subject_attributes: Option<CertificateSubjectAttributes>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                confirmed_subject_attributes,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    pub enum AuthorizationValidationResponseCode {
        ok = 0,
        cantparse = 1,
        badcontenttype = 2,
        imnottherecipient = 3,
        unknownencryptionalgorithm = 4,
        decryptionfailed = 5,
        invalidaa = 6,
        invalidaasignature = 7,
        wrongea = 8,
        unknownits = 9,
        invalidsignature = 10,
        invalidencryptionkey = 11,
        deniedpermissions = 12,
        deniedtoomanycerts = 13,
        deniedrequest = 14,
    }
}
#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_enrolment {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, PublicKeys,
    };
    use super::etsi_ts103097_module::EtsiTs103097Certificate;
    use super::ieee1609_dot2_base_types::Uint8;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    pub enum EnrolmentResponseCode {
        ok = 0,
        cantparse = 1,
        badcontenttype = 2,
        imtoolate = 3,
        imtooearlyorequaltime = 4,
        unauthorizedrequest = 5,
        invalidsig = 6,
        invalidencryptionkey = 7,
        dupkey = 8,
        invalidrequestformat = 9,
        subjectnotfound = 10,
        incompatiblelevel = 11,
    }
    #[doc = " TS 102 941 v2.2.1 §6.2.3.2 — Enrolment"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct InnerECRequest {
        #[rasn(identifier = "itsId")]
        pub its_id: OctetString,
        #[rasn(identifier = "certificateFormat")]
        pub certificate_format: CertificateFormat,
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }
    impl InnerECRequest {
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
    #[doc = " InnerECRequestSignedForPOP is an EtsiTs103097Data-Signed wrapping the InnerECRequest."]
    #[doc = " Encoded as Ieee1609Dot2Data at the outer layer; handled in message_builder.py."]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct InnerECResponse {
        pub version: Uint8,
        #[rasn(identifier = "responseCode")]
        pub response_code: EnrolmentResponseCode,
        pub certificate: Option<EtsiTs103097Certificate>,
    }
    impl InnerECResponse {
        pub fn new(
            version: Uint8,
            response_code: EnrolmentResponseCode,
            certificate: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                version,
                response_code,
                certificate,
            }
        }
    }
}

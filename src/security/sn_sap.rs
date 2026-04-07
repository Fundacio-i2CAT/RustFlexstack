//! SN-SAP — Security Network Service Access Point.
//!
//! Data types for the SN-SIGN and SN-VERIFY primitives as specified in
//! ETSI TS 102 723-8 V1.1.1 (2016-04).

/// SN-SIGN.request
#[derive(Debug, Clone)]
pub struct SNSignRequest {
    pub tbs_message: Vec<u8>,
    pub its_aid: u64,
    pub permissions: Vec<u8>,
    /// Optional 3-D location for DENM headerInfo.generationLocation.
    pub generation_location: Option<GenerationLocation>,
}

/// 3-D location embedded in signed message headers.
#[derive(Debug, Clone)]
pub struct GenerationLocation {
    pub latitude: i32,
    pub longitude: i32,
    pub elevation: u16,
}

/// SN-SIGN.confirm
#[derive(Debug, Clone)]
pub struct SNSignConfirm {
    pub sec_message: Vec<u8>,
}

/// SN-VERIFY.request
#[derive(Debug, Clone)]
pub struct SNVerifyRequest {
    pub message: Vec<u8>,
}

/// Verification outcome codes (Table 5, §5.2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportVerify {
    Success,
    FalseSignature,
    InvalidCertificate,
    RevokedCertificate,
    InconsistentChain,
    InvalidTimestamp,
    DuplicateMessage,
    InvalidMobilityData,
    UnsignedMessage,
    SignerCertificateNotFound,
    UnsupportedSignerIdentifierType,
    IncompatibleProtocol,
}

/// SN-VERIFY.confirm
#[derive(Debug, Clone)]
pub struct SNVerifyConfirm {
    pub report: ReportVerify,
    pub certificate_id: Vec<u8>,
    pub its_aid: u64,
    pub permissions: Vec<u8>,
    /// The verified plain-text payload extracted from the signed message.
    pub plain_message: Vec<u8>,
}

/// Security profile selector (mirrors the Python SecurityProfile enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    NoSecurity = 0,
    CooperativeAwarenessMessage = 1,
    DecentralizedEnvironmentalNotificationMessage = 2,
    VruAwarenessMessage = 3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_profile_values() {
        assert_eq!(SecurityProfile::NoSecurity as u8, 0);
        assert_eq!(SecurityProfile::CooperativeAwarenessMessage as u8, 1);
        assert_eq!(
            SecurityProfile::DecentralizedEnvironmentalNotificationMessage as u8,
            2
        );
        assert_eq!(SecurityProfile::VruAwarenessMessage as u8, 3);
    }

    #[test]
    fn security_profile_equality() {
        assert_eq!(SecurityProfile::NoSecurity, SecurityProfile::NoSecurity);
        assert_ne!(
            SecurityProfile::NoSecurity,
            SecurityProfile::CooperativeAwarenessMessage
        );
    }

    #[test]
    fn report_verify_variants() {
        let variants = vec![
            ReportVerify::Success,
            ReportVerify::FalseSignature,
            ReportVerify::InvalidCertificate,
            ReportVerify::RevokedCertificate,
            ReportVerify::InconsistentChain,
            ReportVerify::InvalidTimestamp,
            ReportVerify::DuplicateMessage,
            ReportVerify::InvalidMobilityData,
            ReportVerify::UnsignedMessage,
            ReportVerify::SignerCertificateNotFound,
            ReportVerify::UnsupportedSignerIdentifierType,
            ReportVerify::IncompatibleProtocol,
        ];
        assert_eq!(variants.len(), 12);
    }

    #[test]
    fn report_verify_equality() {
        assert_eq!(ReportVerify::Success, ReportVerify::Success);
        assert_ne!(ReportVerify::Success, ReportVerify::FalseSignature);
    }

    #[test]
    fn sn_sign_request_construction() {
        let req = SNSignRequest {
            tbs_message: vec![1, 2, 3],
            its_aid: 36,
            permissions: vec![0xFF],
            generation_location: Some(GenerationLocation {
                latitude: 415520000,
                longitude: 21340000,
                elevation: 1200,
            }),
        };
        assert_eq!(req.its_aid, 36);
        assert!(req.generation_location.is_some());
    }

    #[test]
    fn sn_sign_request_no_location() {
        let req = SNSignRequest {
            tbs_message: vec![],
            its_aid: 37,
            permissions: vec![],
            generation_location: None,
        };
        assert!(req.generation_location.is_none());
    }

    #[test]
    fn sn_verify_confirm_construction() {
        let confirm = SNVerifyConfirm {
            report: ReportVerify::Success,
            certificate_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            its_aid: 36,
            permissions: vec![0xFF],
            plain_message: vec![0xCA, 0xFE],
        };
        assert_eq!(confirm.report, ReportVerify::Success);
        assert_eq!(confirm.plain_message.len(), 2);
    }

    #[test]
    fn generation_location_fields() {
        let loc = GenerationLocation {
            latitude: 415520000,
            longitude: 21340000,
            elevation: 0xF000,
        };
        assert_eq!(loc.latitude, 415520000);
        assert_eq!(loc.longitude, 21340000);
        assert_eq!(loc.elevation, 0xF000);
    }
}

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

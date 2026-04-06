//! Verify service — ETSI TS 103 097 message verification.
//!
//! Decodes a received `Ieee1609Dot2Data` envelope, validates the signer
//! chain, checks per-profile header constraints, and verifies the ECDSA
//! signature.

use rasn::prelude::*;

use crate::security::certificate::{decode_ieee1609_dot2_data, encode_tbs_data, Certificate};
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::security_asn::ieee1609_dot2::{
    Ieee1609Dot2Content, SignerIdentifier,
};
use crate::security::security_asn::ieee1609_dot2_base_types::PublicVerificationKey;
use crate::security::security_asn::ieee1609_dot2::VerificationKeyIndicator;
use crate::security::sign_service::SignService;
use crate::security::sn_sap::{ReportVerify, SNVerifyConfirm, SNVerifyRequest};

/// Message verification service.
pub struct VerifyService<'a> {
    pub backend: &'a EcdsaBackend,
    pub cert_library: &'a mut CertificateLibrary,
    pub sign_service: Option<&'a mut SignService>,
}

impl<'a> VerifyService<'a> {
    pub fn new(
        backend: &'a EcdsaBackend,
        cert_library: &'a mut CertificateLibrary,
        sign_service: Option<&'a mut SignService>,
    ) -> Self {
        Self {
            backend,
            cert_library,
            sign_service,
        }
    }
}

/// Stateless verification function that does not require a mutable `VerifyService`.
/// This can be called from the GN router without borrow issues.
pub fn verify_message(
    request: &SNVerifyRequest,
    backend: &EcdsaBackend,
    cert_library: &mut CertificateLibrary,
) -> (SNVerifyConfirm, Vec<VerifyEvent>) {
    let mut events = Vec::new();

    let data = decode_ieee1609_dot2_data(&request.message);
    let signed_data = match &data.content {
        Ieee1609Dot2Content::signedData(sd) => sd,
        _ => {
            return (
                SNVerifyConfirm {
                    report: ReportVerify::UnsignedMessage,
                    certificate_id: vec![],
                    its_aid: 0,
                    permissions: vec![],
                    plain_message: vec![],
                },
                events,
            );
        }
    };

    let tbs_bytes = encode_tbs_data(&signed_data.tbs_data);
    let signer = &signed_data.signer;

    // Determine PSID for per-profile checks
    let psid = u64::try_from(&signed_data.tbs_data.header_info.psid.0).unwrap_or(0);

    // §7.1.2: DENMs must use 'certificate' signer
    if psid == 37 {
        if !matches!(signer, SignerIdentifier::certificate(_)) {
            return (
                SNVerifyConfirm {
                    report: ReportVerify::UnsupportedSignerIdentifierType,
                    certificate_id: vec![],
                    its_aid: psid,
                    permissions: vec![],
                    plain_message: vec![],
                },
                events,
            );
        }
    }

    // Resolve the authorization ticket from the signer
    let authorization_ticket: Option<Certificate> = match signer {
        SignerIdentifier::certificate(seq) => {
            let certs_asn = &seq.0;
            if certs_asn.len() != 1 {
                return (
                    SNVerifyConfirm {
                        report: ReportVerify::UnsupportedSignerIdentifierType,
                        certificate_id: vec![],
                        its_aid: psid,
                        permissions: vec![],
                        plain_message: vec![],
                    },
                    events,
                );
            }
            // Build Certificate wrappers
            let cert_vec: Vec<Certificate> = certs_asn
                .iter()
                .map(|c| {
                    use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
                    Certificate::from_asn(EtsiTs103097Certificate(c.clone()), None)
                })
                .collect();
            match cert_library.verify_sequence_of_certificates(&cert_vec, backend) {
                Some(at) => Some(at),
                None => {
                    // Unknown issuer — notify sign service
                    let cert_dict = &certs_asn[0];
                    let issuer_field = &cert_dict.0.issuer;
                    match issuer_field {
                        crate::security::security_asn::ieee1609_dot2::IssuerIdentifier::sha256AndDigest(h)
                        | crate::security::security_asn::ieee1609_dot2::IssuerIdentifier::sha384AndDigest(h) => {
                            let mut h8 = [0u8; 8];
                            h8.copy_from_slice(h.0.as_ref());
                            events.push(VerifyEvent::UnknownAt(h8));
                        }
                        _ => {}
                    }
                    return (
                        SNVerifyConfirm {
                            report: ReportVerify::InconsistentChain,
                            certificate_id: vec![],
                            its_aid: psid,
                            permissions: vec![],
                            plain_message: vec![],
                        },
                        events,
                    );
                }
            }
        }
        SignerIdentifier::digest(h) => {
            let mut key = [0u8; 8];
            key.copy_from_slice(h.0.as_ref());
            match cert_library.get_authorization_ticket_by_hashedid8(&key) {
                Some(at) => Some(at.clone()),
                None => {
                    events.push(VerifyEvent::UnknownAt(key));
                    return (
                        SNVerifyConfirm {
                            report: ReportVerify::SignerCertificateNotFound,
                            certificate_id: vec![],
                            its_aid: psid,
                            permissions: vec![],
                            plain_message: vec![],
                        },
                        events,
                    );
                }
            }
        }
        _ => {
            return (
                SNVerifyConfirm {
                    report: ReportVerify::UnsupportedSignerIdentifierType,
                    certificate_id: vec![],
                    its_aid: psid,
                    permissions: vec![],
                    plain_message: vec![],
                },
                events,
            );
        }
    };

    let at = match authorization_ticket {
        Some(a) => a,
        None => {
            return (
                SNVerifyConfirm {
                    report: ReportVerify::InvalidCertificate,
                    certificate_id: vec![],
                    its_aid: psid,
                    permissions: vec![],
                    plain_message: vec![],
                },
                events,
            );
        }
    };

    // Validate: must be an AT with verificationKey
    if !at.is_authorization_ticket() {
        return (
            SNVerifyConfirm {
                report: ReportVerify::InvalidCertificate,
                certificate_id: at.as_hashedid8().to_vec(),
                its_aid: psid,
                permissions: vec![],
                plain_message: vec![],
            },
            events,
        );
    }

    let vk = match &at.tbs().verify_key_indicator {
        VerificationKeyIndicator::verificationKey(pk) => pk,
        _ => {
            return (
                SNVerifyConfirm {
                    report: ReportVerify::InvalidCertificate,
                    certificate_id: at.as_hashedid8().to_vec(),
                    its_aid: psid,
                    permissions: vec![],
                    plain_message: vec![],
                },
                events,
            );
        }
    };

    // §5.2: generationTime must be present
    if signed_data.tbs_data.header_info.generation_time.is_none() {
        return (
            SNVerifyConfirm {
                report: ReportVerify::InvalidTimestamp,
                certificate_id: at.as_hashedid8().to_vec(),
                its_aid: psid,
                permissions: vec![],
                plain_message: vec![],
            },
            events,
        );
    }

    // §5.2: p2pcdLearningRequest and missingCrlIdentifier must be absent
    if signed_data.tbs_data.header_info.p2pcd_learning_request.is_some()
        || signed_data.tbs_data.header_info.missing_crl_identifier.is_some()
    {
        return (
            SNVerifyConfirm {
                report: ReportVerify::IncompatibleProtocol,
                certificate_id: at.as_hashedid8().to_vec(),
                its_aid: psid,
                permissions: vec![],
                plain_message: vec![],
            },
            events,
        );
    }

    // §7.1.2: DENM-specific header constraints
    if psid == 37 {
        if signed_data.tbs_data.header_info.generation_location.is_none() {
            return (
                SNVerifyConfirm {
                    report: ReportVerify::IncompatibleProtocol,
                    certificate_id: at.as_hashedid8().to_vec(),
                    its_aid: psid,
                    permissions: vec![],
                    plain_message: vec![],
                },
                events,
            );
        }
        // Forbidden fields for DENM
        if signed_data.tbs_data.header_info.expiry_time.is_some()
            || signed_data.tbs_data.header_info.encryption_key.is_some()
            || signed_data.tbs_data.header_info.inline_p2pcd_request.is_some()
            || signed_data.tbs_data.header_info.requested_certificate.is_some()
        {
            return (
                SNVerifyConfirm {
                    report: ReportVerify::IncompatibleProtocol,
                    certificate_id: at.as_hashedid8().to_vec(),
                    its_aid: psid,
                    permissions: vec![],
                    plain_message: vec![],
                },
                events,
            );
        }
    }

    // Verify the signature
    let verified = backend.verify_with_pk(&tbs_bytes, &signed_data.signature, vk);
    if !verified {
        return (
            SNVerifyConfirm {
                report: ReportVerify::FalseSignature,
                certificate_id: at.as_hashedid8().to_vec(),
                its_aid: psid,
                permissions: vec![],
                plain_message: vec![],
            },
            events,
        );
    }

    // Extract the plain message
    let plain_message = match &signed_data.tbs_data.payload.data {
        Some(inner) => match &inner.content {
            Ieee1609Dot2Content::unsecuredData(opaque) => opaque.0.to_vec(),
            _ => vec![],
        },
        None => vec![],
    };

    // P2PCD events
    if let Some(ref req) = signed_data.tbs_data.header_info.inline_p2pcd_request {
        let h3s: Vec<[u8; 3]> = req
            .0
            .iter()
            .map(|h| {
                let mut arr = [0u8; 3];
                arr.copy_from_slice(h.0.as_ref());
                arr
            })
            .collect();
        events.push(VerifyEvent::InlineP2pcdRequest(h3s));
    }
    if let Some(ref cert_asn) = signed_data.tbs_data.header_info.requested_certificate {
        use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
        let c = Certificate::from_asn(EtsiTs103097Certificate(cert_asn.clone()), None);
        events.push(VerifyEvent::ReceivedCaCertificate(c));
    }

    (
        SNVerifyConfirm {
            report: ReportVerify::Success,
            certificate_id: at.as_hashedid8().to_vec(),
            its_aid: psid,
            permissions: vec![],
            plain_message,
        },
        events,
    )
}

/// Events produced during verification that should be forwarded to the
/// sign service for P2PCD handling.
#[derive(Debug)]
pub enum VerifyEvent {
    UnknownAt([u8; 8]),
    InlineP2pcdRequest(Vec<[u8; 3]>),
    ReceivedCaCertificate(Certificate),
}

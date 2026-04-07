//! Verify service — ETSI TS 103 097 message verification.
//!
//! Decodes a received `Ieee1609Dot2Data` envelope, validates the signer
//! chain, checks per-profile header constraints, and verifies the ECDSA
//! signature.

use crate::security::certificate::{decode_ieee1609_dot2_data, encode_tbs_data, Certificate};
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::security_asn::ieee1609_dot2::VerificationKeyIndicator;
use crate::security::security_asn::ieee1609_dot2::{Ieee1609Dot2Content, SignerIdentifier};
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
    if signed_data
        .tbs_data
        .header_info
        .p2pcd_learning_request
        .is_some()
        || signed_data
            .tbs_data
            .header_info
            .missing_crl_identifier
            .is_some()
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
        if signed_data
            .tbs_data
            .header_info
            .generation_location
            .is_none()
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
        // Forbidden fields for DENM
        if signed_data.tbs_data.header_info.expiry_time.is_some()
            || signed_data.tbs_data.header_info.encryption_key.is_some()
            || signed_data
                .tbs_data
                .header_info
                .inline_p2pcd_request
                .is_some()
            || signed_data
                .tbs_data
                .header_info
                .requested_certificate
                .is_some()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::certificate::OwnCertificate;
    use crate::security::certificate_library::CertificateLibrary;
    use crate::security::ecdsa_backend::EcdsaBackend;
    use crate::security::security_asn::ieee1609_dot2::{
        CertificateId, EndEntityType, PsidGroupPermissions, PsidSsp, SequenceOfAppExtensions,
        SequenceOfCertIssueExtensions, SequenceOfCertRequestExtensions,
        SequenceOfPsidGroupPermissions, SequenceOfPsidSsp, SubjectPermissions,
        ToBeSignedCertificate, VerificationKeyIndicator,
    };
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        CrlSeries, Duration as AsnDuration, EccP256CurvePoint, HashedId3, Psid,
        PublicVerificationKey, Time32, Uint16, Uint32, ValidityPeriod,
    };
    use crate::security::sign_service::SignService;
    use crate::security::sn_sap::{GenerationLocation, SNSignRequest, SNVerifyRequest};
    use rasn::prelude::*;

    fn make_root_tbs() -> ToBeSignedCertificate {
        let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(30)));
        let perms = SequenceOfPsidGroupPermissions(
            vec![PsidGroupPermissions::new(
                SubjectPermissions::all(()),
                Integer::from(1),
                Integer::from(0),
                {
                    let mut bits = FixedBitString::<8>::default();
                    bits.set(0, true);
                    EndEntityType(bits)
                },
            )]
            .into(),
        );
        let pk =
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::x_only(vec![0u8; 32].into()));
        ToBeSignedCertificate::new(
            CertificateId::none(()),
            HashedId3(FixedOctetString::from([0u8; 3])),
            CrlSeries(Uint16(0)),
            validity,
            None,
            None,
            None,
            Some(perms),
            None,
            None,
            None,
            VerificationKeyIndicator::verificationKey(pk),
            None,
            SequenceOfAppExtensions(vec![].into()),
            SequenceOfCertIssueExtensions(vec![].into()),
            SequenceOfCertRequestExtensions(vec![].into()),
        )
    }

    fn make_at_tbs(its_aid: i64) -> ToBeSignedCertificate {
        let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(1)));
        let app_perms =
            SequenceOfPsidSsp(vec![PsidSsp::new(Psid(Integer::from(its_aid)), None)].into());
        let pk =
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::x_only(vec![0u8; 32].into()));
        ToBeSignedCertificate::new(
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
            None,
            VerificationKeyIndicator::verificationKey(pk),
            None,
            SequenceOfAppExtensions(vec![].into()),
            SequenceOfCertIssueExtensions(vec![].into()),
            SequenceOfCertRequestExtensions(vec![].into()),
        )
    }

    fn sign_cam_message(svc: &mut SignService) -> Vec<u8> {
        let req = SNSignRequest {
            tbs_message: vec![0xCA, 0xFE],
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        };
        svc.sign_request(&req).sec_message
    }

    fn sign_denm_message(svc: &mut SignService) -> Vec<u8> {
        let req = SNSignRequest {
            tbs_message: vec![0xDE, 0x01],
            its_aid: 37,
            permissions: vec![],
            generation_location: Some(GenerationLocation {
                latitude: 415520000,
                longitude: 21340000,
                elevation: 0xF000,
            }),
        };
        svc.sign_request(&req).sec_message
    }

    fn setup() -> (EcdsaBackend, CertificateLibrary, SignService) {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let aa = OwnCertificate::initialize_issued(&mut backend, make_root_tbs(), &root);
        let at_cam = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(36), &aa);
        let at_denm = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(37), &aa);

        let lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![],
        );
        let mut svc = SignService::new(backend, lib);
        svc.add_own_certificate(at_cam);
        svc.add_own_certificate(at_denm);

        // Build verify library from certs stored in sign service
        let verify_lib = CertificateLibrary::new(
            &svc.backend,
            svc.cert_library
                .known_root_certificates
                .values()
                .cloned()
                .collect(),
            svc.cert_library
                .known_authorization_authorities
                .values()
                .cloned()
                .collect(),
            svc.cert_library
                .known_authorization_tickets
                .values()
                .cloned()
                .collect(),
        );

        (EcdsaBackend::new(), verify_lib, svc)
    }

    #[test]
    fn verify_cam_signed_message() {
        let (_, _, mut svc) = setup();
        let sec_msg = sign_cam_message(&mut svc);

        // Verify using sign service's own backend and cert library
        let req = SNVerifyRequest { message: sec_msg };
        let mut verify_lib = CertificateLibrary::new(
            &svc.backend,
            svc.cert_library
                .known_root_certificates
                .values()
                .cloned()
                .collect(),
            svc.cert_library
                .known_authorization_authorities
                .values()
                .cloned()
                .collect(),
            svc.cert_library
                .known_authorization_tickets
                .values()
                .cloned()
                .collect(),
        );
        let (confirm, _events) = verify_message(&req, &svc.backend, &mut verify_lib);
        assert_eq!(confirm.report, ReportVerify::Success);
        assert_eq!(confirm.its_aid, 36);
        assert_eq!(confirm.plain_message, vec![0xCA, 0xFE]);
    }

    #[test]
    fn verify_denm_signed_message() {
        let (_, _, mut svc) = setup();
        let sec_msg = sign_denm_message(&mut svc);

        let req = SNVerifyRequest { message: sec_msg };
        let mut verify_lib = CertificateLibrary::new(
            &svc.backend,
            svc.cert_library
                .known_root_certificates
                .values()
                .cloned()
                .collect(),
            svc.cert_library
                .known_authorization_authorities
                .values()
                .cloned()
                .collect(),
            svc.cert_library
                .known_authorization_tickets
                .values()
                .cloned()
                .collect(),
        );
        let (confirm, _events) = verify_message(&req, &svc.backend, &mut verify_lib);
        assert_eq!(confirm.report, ReportVerify::Success);
        assert_eq!(confirm.its_aid, 37);
    }

    #[test]
    fn verify_tampered_message_fails() {
        let (_, _, mut svc) = setup();
        let mut sec_msg = sign_cam_message(&mut svc);

        // Tamper with the message
        if let Some(b) = sec_msg.last_mut() {
            *b ^= 0xFF;
        }

        let req = SNVerifyRequest { message: sec_msg };
        let mut verify_lib = CertificateLibrary::new(
            &svc.backend,
            svc.cert_library
                .known_root_certificates
                .values()
                .cloned()
                .collect(),
            svc.cert_library
                .known_authorization_authorities
                .values()
                .cloned()
                .collect(),
            svc.cert_library
                .known_authorization_tickets
                .values()
                .cloned()
                .collect(),
        );
        let (confirm, _) = verify_message(&req, &svc.backend, &mut verify_lib);
        assert_ne!(confirm.report, ReportVerify::Success);
    }

    #[test]
    fn verify_event_variants() {
        let ev1 = VerifyEvent::UnknownAt([1; 8]);
        let ev2 = VerifyEvent::InlineP2pcdRequest(vec![[1, 2, 3]]);
        // Just ensure they can be constructed and formatted
        assert!(format!("{:?}", ev1).contains("UnknownAt"));
        assert!(format!("{:?}", ev2).contains("InlineP2pcdRequest"));
    }
}

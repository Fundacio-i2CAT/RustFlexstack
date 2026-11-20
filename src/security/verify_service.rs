//! Verify service — ETSI TS 103 097 message verification.
//!
//! Decodes a received `Ieee1609Dot2Data` envelope, validates the signer
//! chain, checks per-profile header constraints, and verifies the ECDSA
//! signature.

use crate::security::certificate::{
    encode_tbs_data, signing_input, try_decode_ieee1609_dot2_data, Certificate,
};
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::key_uses_sha384;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::header_extensions::{decode_requests, TrustListRequest};
use crate::security::security_asn::ieee1609_dot2::{Ieee1609Dot2Content, SignerIdentifier};
use crate::security::sign_service::SignService;
use crate::security::sn_sap::{ReportVerify, SNVerifyConfirm, SNVerifyRequest};
use crate::security::validity::{app_permission, location_permitted, valid_at};

/// Message verification service.
pub struct VerifyService<'a> {
    pub backend: &'a EcdsaBackend,
    pub cert_library: &'a mut CertificateLibrary,
    pub sign_service: Option<&'a mut SignService>,
    /// Receiver of the P2P CRL / CTL requests of the verified messages.
    pub trust_list_listener: Option<TrustListListener>,
}

/// Receiver of the P2P CRL / CTL requests of a verified message and its AT
/// (ETSI TS 103 601 V2.1.1 clause 5.3), set by the distribution service.
pub type TrustListListener =
    std::sync::Arc<dyn Fn(&[TrustListRequest], &Certificate) + Send + Sync>;

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
            trust_list_listener: None,
        }
    }

    /// Verify a signed message request and dispatch any P2PCD/unknown-cert events
    /// to the associated `SignService` if configured.
    pub fn verify(&mut self, request: &SNVerifyRequest) -> SNVerifyConfirm {
        let (confirm, events) = verify_message(request, self.backend, self.cert_library);
        if let Some(ref mut sign_svc) = self.sign_service {
            for event in events {
                match event {
                    VerifyEvent::UnknownAt(h8) => sign_svc.notify_unknown_at(&h8),
                    VerifyEvent::KnownAt(h8) => sign_svc.notify_known_at(&h8),
                    VerifyEvent::InlineP2pcdRequest(h3s) => {
                        sign_svc.notify_inline_p2pcd_request(&h3s);
                    }
                    VerifyEvent::ReceivedCaCertificate(cert) => {
                        sign_svc.notify_received_ca_certificate(*cert);
                    }
                    VerifyEvent::TrustListRequests(requests, at) => {
                        if let Some(listener) = &self.trust_list_listener {
                            listener(&requests, &at);
                        }
                    }
                }
            }
        }
        confirm
    }
}

const PSID_CAM: u64 = 36;
const PSID_DENM: u64 = 37;
const PROTOCOL_VERSION: u8 = 3;

fn confirm(
    report: ReportVerify,
    at: Option<&Certificate>,
    psid: u64,
    permissions: Vec<u8>,
    plain_message: Vec<u8>,
) -> SNVerifyConfirm {
    SNVerifyConfirm {
        report,
        certificate_id: at.map(|c| c.as_hashedid8().to_vec()).unwrap_or_default(),
        its_aid: psid,
        permissions,
        plain_message,
    }
}

/// Stateless verification (ETSI TS 103 097 V2.2.1 clauses 5 and 7; IEEE Std
/// 1609.2-2016 clauses 5.2.3.2.2 and 5.3.1). Checks, in order (the first
/// failing one gives the report):
///
/// 1. decodable signed data with protocolVersion 3 (clause 5.1);
/// 2. signer identifier: certificate (exactly one) or digest; DENMs always
///    use a certificate (clause 7.1.2);
/// 3. the signer certificate is a known, valid authorization ticket;
/// 4. headerInfo: generationTime present, p2pcdLearningRequest and
///    missingCrlIdentifier absent (clause 5.2); CAM (clause 7.1.1) and DENM
///    (clause 7.1.2) profiles;
/// 5. the PSID is in the appPermissions of the AT (the SSP is returned);
/// 6. the generationTime lies in the validity period of the AT chain;
/// 7. the generationLocation, when present, lies in the region of the chain;
/// 8. the signature, over Hash(Hash(tbsData) || Hash(AT)), with an algorithm
///    matching the verification key.
///
/// Mirrors `flexstack/security/verify_service.py`.
pub fn verify_message(
    request: &SNVerifyRequest,
    backend: &EcdsaBackend,
    cert_library: &mut CertificateLibrary,
) -> (SNVerifyConfirm, Vec<VerifyEvent>) {
    let mut events = Vec::new();

    // 1. Decoding and protocol version
    let Some(data) = try_decode_ieee1609_dot2_data(&request.message) else {
        return (
            confirm(ReportVerify::IncompatibleProtocol, None, 0, vec![], vec![]),
            events,
        );
    };
    let signed_data = match &data.content {
        Ieee1609Dot2Content::signedData(sd) => sd,
        _ => {
            return (
                confirm(ReportVerify::UnsignedMessage, None, 0, vec![], vec![]),
                events,
            );
        }
    };
    let inner_version_ok = signed_data
        .tbs_data
        .payload
        .data
        .as_ref()
        .is_none_or(|inner| inner.protocol_version.0 == PROTOCOL_VERSION);
    if data.protocol_version.0 != PROTOCOL_VERSION || !inner_version_ok {
        return (
            confirm(ReportVerify::IncompatibleProtocol, None, 0, vec![], vec![]),
            events,
        );
    }
    let tbs_bytes = encode_tbs_data(&signed_data.tbs_data);
    let header = &signed_data.tbs_data.header_info;
    let psid = u64::try_from(&header.psid.0).unwrap_or(0);
    let signer = &signed_data.signer;
    let fail =
        |report: ReportVerify, at: Option<&Certificate>| confirm(report, at, psid, vec![], vec![]);

    // P2PCD response (IEEE 1609.2 clause 8.2.4, TS 103 097 clause 7.1.1): a
    // requested CA certificate is learned when it verifies under a known issuer,
    // before the chain of this message is checked (the answering CAM may be
    // signed by an AT of that CA).
    if let Some(ref cert_asn) = header.requested_certificate {
        use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
        cert_library.learn_ca_certificate(
            backend,
            Certificate::from_asn(EtsiTs103097Certificate(cert_asn.clone()), None),
        );
    }

    // 2-3. Signer identifier and authorization ticket
    if psid == PSID_DENM && !matches!(signer, SignerIdentifier::certificate(_)) {
        return (
            fail(ReportVerify::UnsupportedSignerIdentifierType, None),
            events,
        );
    }
    let at: Certificate = match signer {
        SignerIdentifier::certificate(seq) => {
            let certs_asn = &seq.0;
            if certs_asn.len() != 1 {
                return (
                    fail(ReportVerify::UnsupportedSignerIdentifierType, None),
                    events,
                );
            }
            let cert_vec: Vec<Certificate> = certs_asn
                .iter()
                .map(|c| {
                    use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
                    Certificate::from_asn(EtsiTs103097Certificate(c.clone()), None)
                })
                .collect();
            match cert_library.verify_sequence_of_certificates(&cert_vec, backend) {
                Some(at) => at,
                None => {
                    use crate::security::security_asn::ieee1609_dot2::IssuerIdentifier;
                    if let IssuerIdentifier::sha256AndDigest(h)
                    | IssuerIdentifier::sha384AndDigest(h) = &certs_asn[0].0.issuer
                    {
                        let mut h8 = [0u8; 8];
                        h8.copy_from_slice(h.0.as_ref());
                        events.push(VerifyEvent::UnknownAt(h8));
                    }
                    return (fail(ReportVerify::InconsistentChain, None), events);
                }
            }
        }
        SignerIdentifier::digest(h) => {
            let mut key = [0u8; 8];
            key.copy_from_slice(h.0.as_ref());
            match cert_library.get_authorization_ticket_by_hashedid8(&key) {
                Some(at) => at.clone(),
                None => {
                    events.push(VerifyEvent::UnknownAt(key));
                    return (fail(ReportVerify::SignerCertificateNotFound, None), events);
                }
            }
        }
        // 'self' is not allowed (clause 5.2)
        _ => {
            return (
                fail(ReportVerify::UnsupportedSignerIdentifierType, None),
                events,
            )
        }
    };
    // Verification key: explicit, or reconstructed from an implicit AT
    // (IEEE 1609.2 clause 5.3.2)
    let vk_owned = match at.verification_key() {
        Some(pk) if at.is_authorization_ticket() => pk,
        _ => return (fail(ReportVerify::InvalidCertificate, Some(&at)), events),
    };
    let vk = &vk_owned;

    // 4. headerInfo (clauses 5.2, 7.1.1, 7.1.2)
    let Some(generation_time) = &header.generation_time else {
        return (fail(ReportVerify::InvalidTimestamp, Some(&at)), events);
    };
    if header.p2pcd_learning_request.is_some() || header.missing_crl_identifier.is_some() {
        return (fail(ReportVerify::IncompatibleProtocol, Some(&at)), events);
    }
    let cam_violation = psid == PSID_CAM
        && (header.generation_location.is_some()
            || header.expiry_time.is_some()
            || header.encryption_key.is_some());
    let denm_violation = psid == PSID_DENM
        && (header.generation_location.is_none()
            || header.expiry_time.is_some()
            || header.encryption_key.is_some()
            || header.inline_p2pcd_request.is_some()
            || header.requested_certificate.is_some());
    if cam_violation || denm_violation {
        return (fail(ReportVerify::IncompatibleProtocol, Some(&at)), events);
    }

    // 5. PSID permitted by the AT (IEEE 1609.2 clause 5.2.3.2.2)
    let (permitted, ssp) = app_permission(at.tbs(), psid);
    if !permitted {
        return (fail(ReportVerify::InvalidCertificate, Some(&at)), events);
    }

    // 6-7. Time and region consistency with the certificate chain
    if !valid_at(&at, generation_time.0 .0) {
        return (fail(ReportVerify::InvalidTimestamp, Some(&at)), events);
    }
    if let Some(location) = &header.generation_location {
        if !location_permitted(&at, location.latitude.0 .0, location.longitude.0 .0) {
            return (fail(ReportVerify::InvalidMobilityData, Some(&at)), events);
        }
    }

    // 8. Signature over Hash(Hash(tbsData) || Hash(AT)) (IEEE 1609.2 clause 5.3.1)
    let payload = signing_input(&tbs_bytes, at.to_canonical().encode(), key_uses_sha384(vk));
    if !backend.verify_with_pk(&payload, &signed_data.signature, vk) {
        return (fail(ReportVerify::FalseSignature, Some(&at)), events);
    }

    // Extract the plain message
    let plain_message = match &signed_data.tbs_data.payload.data {
        Some(inner) => match &inner.content {
            Ieee1609Dot2Content::unsecuredData(opaque) => opaque.0.to_vec(),
            _ => vec![],
        },
        None => vec![],
    };

    // P2PCD events. An AT received as certificate signer is now known: it is
    // no longer requested in inlineP2pcdRequest (TS 103 097 clause 7.1.1).
    if matches!(signer, SignerIdentifier::certificate(_)) {
        events.push(VerifyEvent::KnownAt(at.as_hashedid8()));
    }
    if let Some(ref req) = header.inline_p2pcd_request {
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
    if let Some(ref cert_asn) = header.requested_certificate {
        use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
        let c = Certificate::from_asn(EtsiTs103097Certificate(cert_asn.clone()), None);
        events.push(VerifyEvent::ReceivedCaCertificate(Box::new(c)));
    }
    if let Some(ref blocks) = header.contributed_extensions {
        let requests = decode_requests(blocks);
        if !requests.is_empty() {
            events.push(VerifyEvent::TrustListRequests(
                requests,
                Box::new(at.clone()),
            ));
        }
    }

    (
        confirm(
            ReportVerify::Success,
            Some(&at),
            psid,
            ssp.unwrap_or_default(),
            plain_message,
        ),
        events,
    )
}

/// Events produced during verification that should be forwarded to the
/// sign service for P2PCD handling.
#[derive(Debug)]
pub enum VerifyEvent {
    UnknownAt([u8; 8]),
    /// HashedId8 of an AT learned from a certificate signer.
    KnownAt([u8; 8]),
    InlineP2pcdRequest(Vec<[u8; 3]>),
    ReceivedCaCertificate(Box<Certificate>),
    /// P2P CRL / CTL requests in the contributedExtensions of a verified
    /// message (ETSI TS 103 601 V2.1.1 clause 5.3), with the signing AT.
    TrustListRequests(Vec<TrustListRequest>, Box<Certificate>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::certificate::OwnCertificate;
    use crate::security::certificate_library::CertificateLibrary;
    use crate::security::ecdsa_backend::EcdsaBackend;
    use crate::security::security_asn::ieee1609_dot2::{
        CertificateId, EndEntityType, PsidGroupPermissions, SequenceOfPsidGroupPermissions,
        SubjectPermissions, ToBeSignedCertificate, VerificationKeyIndicator,
    };
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        CrlSeries, Duration as AsnDuration, EccP256CurvePoint, HashedId3, Psid, PsidSsp,
        PublicVerificationKey, SequenceOfPsidSsp, Time32, Uint16, Uint32, ValidityPeriod,
    };
    use crate::security::sign_service::SignService;
    use crate::security::sn_sap::{GenerationLocation, SNSignRequest, SNVerifyRequest};
    use rasn::prelude::*;

    fn make_root_tbs() -> ToBeSignedCertificate {
        let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(30)));
        let perms = SequenceOfPsidGroupPermissions(vec![PsidGroupPermissions::new(
            SubjectPermissions::all(()),
            Integer::from(1),
            Integer::from(0),
            {
                let mut bits = FixedBitString::<8>::default();
                bits.set(0, true);
                EndEntityType(bits)
            },
        )]);
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
            None,
            None,
            None,
        )
    }

    fn make_at_tbs(its_aid: i64) -> ToBeSignedCertificate {
        // Valid now: started a minute ago, one year long
        let now_s =
            (crate::security::time_service::timestamp_its_microseconds() / 1_000_000) as u32;
        let validity =
            ValidityPeriod::new(Time32(Uint32(now_s - 60)), AsnDuration::years(Uint16(1)));
        let app_perms = SequenceOfPsidSsp(vec![PsidSsp::new(Psid(Integer::from(its_aid)), None)]);
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
            None,
            None,
            None,
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

    #[test]
    fn test_verify_service_instance_verify() {
        let (_, _, mut svc) = setup();
        let sec_msg = sign_cam_message(&mut svc);
        let req = SNVerifyRequest { message: sec_msg };
        let verify_backend = EcdsaBackend::new();
        let mut verify_lib = CertificateLibrary::new(
            &verify_backend,
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
            vec![],
        );
        let mut verifier = VerifyService::new(&verify_backend, &mut verify_lib, Some(&mut svc));
        let confirm = verifier.verify(&req);
        assert_eq!(confirm.report, ReportVerify::Success);
    }

    // ── Traced to ETSI TS 103 096-2 test purposes (mirrors Python
    //    tests/flexstack/security/test_signed_message_conformance.py) ────────

    fn receiver_library(svc: &SignService) -> CertificateLibrary {
        // Trusts the same Root CA and AA, but has never seen the AT.
        CertificateLibrary::new(
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
            vec![],
        )
    }

    fn cam_request(payload: &[u8]) -> SNSignRequest {
        SNSignRequest {
            tbs_message: payload.to_vec(),
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        }
    }

    /// ETSI TS 103 097 clause 5.1, ETSI TS 103 097 clause 7.1.1,
    /// ETSI TS 103 097 clause 7.1.1: version 3, signedData, psid AID_CAM, generationTime only,
    /// unsecured inner data carrying the CAM payload.
    #[test]
    fn signed_cam_header_conformance() {
        use crate::security::certificate::decode_ieee1609_dot2_data;
        use crate::security::security_asn::ieee1609_dot2::{Ieee1609Dot2Content, SignerIdentifier};
        let (_, _, mut svc) = setup();
        let msg = svc
            .sign_cam_at(&cam_request(&[0xCA, 0xFE]), Some(100.0))
            .sec_message;
        let dot2 = decode_ieee1609_dot2_data(&msg);
        assert_eq!(dot2.protocol_version.0, 3);
        let Ieee1609Dot2Content::signedData(sd) = dot2.content else {
            panic!("expected signedData");
        };
        let hi = &sd.tbs_data.header_info;
        assert_eq!(u64::try_from(&hi.psid.0).unwrap(), 36);
        assert!(hi.generation_time.is_some());
        assert!(hi.expiry_time.is_none());
        assert!(hi.generation_location.is_none());
        assert!(hi.encryption_key.is_none());
        assert!(hi.p2pcd_learning_request.is_none());
        assert!(hi.missing_crl_identifier.is_none());
        let inner = sd.tbs_data.payload.data.as_ref().expect("payload data");
        assert_eq!(inner.protocol_version.0, 3);
        match &inner.content {
            Ieee1609Dot2Content::unsecuredData(o) => assert_eq!(o.0.as_ref(), &[0xCA, 0xFE]),
            _ => panic!("expected unsecuredData"),
        }
        assert!(matches!(sd.signer, SignerIdentifier::certificate(_)));
    }

    /// ETSI TS 103 097 clause 7.1.2: psid AID_DENM,
    /// generationTime and generationLocation, certificate signer.
    #[test]
    fn signed_denm_header_conformance() {
        use crate::security::certificate::decode_ieee1609_dot2_data;
        use crate::security::security_asn::ieee1609_dot2::{Ieee1609Dot2Content, SignerIdentifier};
        let (_, _, mut svc) = setup();
        let msg = sign_denm_message(&mut svc);
        let dot2 = decode_ieee1609_dot2_data(&msg);
        assert_eq!(dot2.protocol_version.0, 3);
        let Ieee1609Dot2Content::signedData(sd) = dot2.content else {
            panic!("expected signedData");
        };
        let hi = &sd.tbs_data.header_info;
        assert_eq!(u64::try_from(&hi.psid.0).unwrap(), 37);
        assert!(hi.generation_time.is_some());
        assert!(hi.generation_location.is_some());
        assert!(hi.expiry_time.is_none());
        assert!(hi.encryption_key.is_none());
        assert!(hi.p2pcd_learning_request.is_none());
        assert!(hi.missing_crl_identifier.is_none());
        assert!(matches!(sd.signer, SignerIdentifier::certificate(_)));
    }

    /// ETSI TS 103 097 clause 7.1.1: an independent receiver accepts
    /// a certificate-signed CAM and then a digest-signed CAM from the same AT.
    #[test]
    fn digest_signed_cam_accepted_once_certificate_known() {
        let (_, _, mut svc) = setup();
        let mut lib = receiver_library(&svc);
        let first = svc
            .sign_cam_at(&cam_request(b"first"), Some(100.0))
            .sec_message;
        let second = svc
            .sign_cam_at(&cam_request(b"second"), Some(100.5))
            .sec_message;

        let (c1, _) = verify_message(&SNVerifyRequest { message: first }, &svc.backend, &mut lib);
        assert_eq!(c1.report, ReportVerify::Success);
        let (c2, _) = verify_message(&SNVerifyRequest { message: second }, &svc.backend, &mut lib);
        assert_eq!(c2.report, ReportVerify::Success);
        assert_eq!(c2.plain_message, b"second".to_vec());
    }

    /// ETSI TS 103 097 clause 7.1.1 (receiver side): a digest of an unknown AT
    /// cannot be verified; the signer is reported as not found.
    #[test]
    fn digest_signed_cam_from_unknown_at_not_accepted() {
        let (_, _, mut svc) = setup();
        let mut lib = receiver_library(&svc);
        let _first = svc.sign_cam_at(&cam_request(b"first"), Some(100.0)); // not delivered
        let second = svc
            .sign_cam_at(&cam_request(b"second"), Some(100.5))
            .sec_message;
        let (c, _) = verify_message(&SNVerifyRequest { message: second }, &svc.backend, &mut lib);
        assert_eq!(c.report, ReportVerify::SignerCertificateNotFound);
    }

    /// Decode a signed message, let `f` modify its headerInfo/signer, re-encode.
    /// The checks under test run before signature verification, so the stale
    /// signature does not mask the expected report.
    fn mutate_signed(
        msg: &[u8],
        f: impl FnOnce(&mut crate::security::security_asn::ieee1609_dot2::SignedData),
    ) -> Vec<u8> {
        use crate::security::certificate::{decode_ieee1609_dot2_data, encode_ieee1609_dot2_data};
        use crate::security::security_asn::ieee1609_dot2::Ieee1609Dot2Content;
        let mut dot2 = decode_ieee1609_dot2_data(msg);
        match &mut dot2.content {
            Ieee1609Dot2Content::signedData(sd) => f(sd),
            _ => panic!("expected signedData"),
        }
        encode_ieee1609_dot2_data(&dot2)
    }

    fn verify_at_receiver(svc: &SignService, msg: Vec<u8>) -> ReportVerify {
        let mut lib = CertificateLibrary::new(
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
        verify_message(&SNVerifyRequest { message: msg }, &svc.backend, &mut lib)
            .0
            .report
    }

    fn hashed_id3() -> crate::security::security_asn::ieee1609_dot2_base_types::HashedId3 {
        crate::security::security_asn::ieee1609_dot2_base_types::HashedId3(FixedOctetString::from(
            [1u8, 2, 3],
        ))
    }

    /// ETSI TS 103 097 clause 7.1.1: CAM with p2pcdLearningRequest is discarded.
    #[test]
    fn cam_with_p2pcd_learning_request_rejected() {
        let (_, _, mut svc) = setup();
        let msg = svc
            .sign_cam_at(&cam_request(b"cam"), Some(100.0))
            .sec_message;
        let bad = mutate_signed(&msg, |sd| {
            sd.tbs_data.header_info.p2pcd_learning_request = Some(hashed_id3());
        });
        assert_eq!(
            verify_at_receiver(&svc, bad),
            ReportVerify::IncompatibleProtocol
        );
    }

    /// ETSI TS 103 097 clause 7.1.2: DENM without generationLocation is discarded.
    #[test]
    fn denm_without_generation_location_rejected() {
        let (_, _, mut svc) = setup();
        let bad = mutate_signed(&sign_denm_message(&mut svc), |sd| {
            sd.tbs_data.header_info.generation_location = None;
        });
        assert_eq!(
            verify_at_receiver(&svc, bad),
            ReportVerify::IncompatibleProtocol
        );
    }

    /// ETSI TS 103 097 clause 7.1.2: DENM with expiryTime is discarded.
    #[test]
    fn denm_with_expiry_time_rejected() {
        use crate::security::security_asn::ieee1609_dot2_base_types::{Time64, Uint64};
        let (_, _, mut svc) = setup();
        let bad = mutate_signed(&sign_denm_message(&mut svc), |sd| {
            sd.tbs_data.header_info.expiry_time = Some(Time64(Uint64(1)));
        });
        assert_eq!(
            verify_at_receiver(&svc, bad),
            ReportVerify::IncompatibleProtocol
        );
    }

    /// ETSI TS 103 097 clause 5.2: DENM with p2pcdLearningRequest is discarded.
    #[test]
    fn denm_with_p2pcd_learning_request_rejected() {
        let (_, _, mut svc) = setup();
        let bad = mutate_signed(&sign_denm_message(&mut svc), |sd| {
            sd.tbs_data.header_info.p2pcd_learning_request = Some(hashed_id3());
        });
        assert_eq!(
            verify_at_receiver(&svc, bad),
            ReportVerify::IncompatibleProtocol
        );
    }

    /// ETSI TS 103 097 clause 6 (digest case): a DENM whose signer is a
    /// digest instead of a certificate is discarded.
    #[test]
    fn denm_signed_with_digest_rejected() {
        use crate::security::security_asn::ieee1609_dot2::SignerIdentifier;
        use crate::security::security_asn::ieee1609_dot2_base_types::HashedId8;
        let (_, _, mut svc) = setup();
        let bad = mutate_signed(&sign_denm_message(&mut svc), |sd| {
            sd.signer = SignerIdentifier::digest(HashedId8(FixedOctetString::from([0u8; 8])));
        });
        assert_eq!(
            verify_at_receiver(&svc, bad),
            ReportVerify::UnsupportedSignerIdentifierType
        );
    }
}

/// Receive and send checks with real certificate chains (ETSI TS 103 097
/// V2.2.1, IEEE Std 1609.2-2016 clauses 5.2.3.2.2 and 5.3.1), traced to ETSI
/// TS 103 096-2 V2.1.1. Mirrors `tests/flexstack/security/test_security_checks.py`.
#[cfg(test)]
pub(crate) mod security_checks {
    use super::*;
    use crate::security::certificate::{
        decode_ieee1609_dot2_data, encode_ieee1609_dot2_data, OwnCertificate,
    };
    use crate::security::certificate_library::CertificateLibrary;
    use crate::security::ecdsa_backend::{EcdsaBackend, KeyAlgorithm};
    use crate::security::security_asn::ieee1609_dot2::IssuerIdentifier;
    use crate::security::security_asn::ieee1609_dot2::VerificationKeyIndicator;
    use crate::security::security_asn::ieee1609_dot2::{
        CertificateId, EndEntityType, Ieee1609Dot2Content, MissingCrlIdentifier,
        PsidGroupPermissions, SequenceOfPsidGroupPermissions, SignedData, SubjectPermissions,
        ToBeSignedCertificate,
    };
    use crate::security::security_asn::ieee1609_dot2_base_types::HashAlgorithm;
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        BitmapSsp, CircularRegion, CrlSeries, Duration as AsnDuration, EccP256CurvePoint,
        Elevation, EncryptionKey, GeographicRegion, HashedId3, Latitude, Longitude,
        NinetyDegreeInt, OneEightyDegreeInt, Psid, PsidSsp, PublicVerificationKey,
        SequenceOfPsidSsp, ServiceSpecificPermissions, Signature as Ieee1609Signature,
        SymmetricEncryptionKey, ThreeDLocation, Time32, Time64, TwoDLocation, Uint16, Uint32,
        Uint64, ValidityPeriod,
    };
    use crate::security::sign_service::{SignService, SigningError};
    use crate::security::sn_sap::{GenerationLocation, SNSignRequest, SNVerifyRequest};
    use crate::security::time_service::timestamp_its_microseconds;
    use rasn::prelude::*;
    use sha2::{Digest, Sha256};

    const INSIDE: (i32, i32) = (415520000, 21340000);
    const OUTSIDE: (i32, i32) = (425520000, 21340000); // ~111 km north

    fn now_s() -> u32 {
        (timestamp_its_microseconds() / 1_000_000) as u32
    }

    fn key() -> VerificationKeyIndicator {
        VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(
            EccP256CurvePoint::x_only(vec![0u8; 32].into()),
        ))
    }

    fn tbs(
        validity: ValidityPeriod,
        region: Option<GeographicRegion>,
        app: Option<SequenceOfPsidSsp>,
        issue: Option<SequenceOfPsidGroupPermissions>,
    ) -> ToBeSignedCertificate {
        ToBeSignedCertificate::new(
            CertificateId::none(()),
            HashedId3(FixedOctetString::from([0u8; 3])),
            CrlSeries(Uint16(0)),
            validity,
            region,
            None,
            app,
            issue,
            None,
            None,
            None,
            key(),
            None,
            None,
            None,
            None,
        )
    }

    pub(crate) fn ca_tbs() -> ToBeSignedCertificate {
        let perms = SequenceOfPsidGroupPermissions(vec![PsidGroupPermissions::new(
            SubjectPermissions::all(()),
            Integer::from(1),
            Integer::from(0),
            {
                let mut bits = FixedBitString::<8>::default();
                bits.set(0, true);
                EndEntityType(bits)
            },
        )]);
        let validity =
            ValidityPeriod::new(Time32(Uint32(now_s() - 60)), AsnDuration::years(Uint16(1)));
        tbs(validity, None, None, Some(perms))
    }

    pub(crate) fn at_tbs(
        start_offset: i64,
        duration: AsnDuration,
        region: Option<GeographicRegion>,
    ) -> ToBeSignedCertificate {
        let app = SequenceOfPsidSsp(vec![
            PsidSsp::new(
                Psid(Integer::from(36)),
                Some(ServiceSpecificPermissions::bitmapSsp(BitmapSsp(
                    vec![2u8, 0x02, 0x00].into(),
                ))),
            ),
            PsidSsp::new(Psid(Integer::from(37)), None),
        ]);
        let start = (now_s() as i64 + start_offset) as u32;
        tbs(
            ValidityPeriod::new(Time32(Uint32(start)), duration),
            region,
            Some(app),
            None,
        )
    }

    fn circle() -> GeographicRegion {
        GeographicRegion::circularRegion(CircularRegion::new(
            TwoDLocation::new(
                Latitude(NinetyDegreeInt(INSIDE.0)),
                Longitude(OneEightyDegreeInt(INSIDE.1)),
            ),
            Uint16(5000),
        ))
    }

    fn ca_tbs_with_region(region: Option<GeographicRegion>) -> ToBeSignedCertificate {
        let mut tbs = ca_tbs();
        tbs.region = region;
        tbs
    }

    struct Fixture {
        svc: SignService,
        root: Certificate,
        aa: Certificate,
        aa_owner: OwnCertificate,
    }

    impl Fixture {
        fn new(at: ToBeSignedCertificate) -> Self {
            Self::chain(ca_tbs(), ca_tbs(), at)
        }

        /// Root -> AA -> AT chain with the given toBeSigned contents.
        fn chain(
            root: ToBeSignedCertificate,
            aa: ToBeSignedCertificate,
            at: ToBeSignedCertificate,
        ) -> Self {
            let mut backend = EcdsaBackend::new();
            let root = OwnCertificate::initialize_self_signed(&mut backend, root);
            let aa = OwnCertificate::initialize_issued(&mut backend, aa, &root);
            let at = OwnCertificate::initialize_issued(&mut backend, at, &aa);
            let lib = CertificateLibrary::new(
                &backend,
                vec![root.cert.clone()],
                vec![aa.cert.clone()],
                vec![],
            );
            let mut svc = SignService::new(backend, lib);
            svc.add_own_certificate(at);
            Fixture {
                svc,
                root: root.cert,
                aa: aa.cert.clone(),
                aa_owner: aa,
            }
        }

        fn valid() -> Self {
            Self::new(at_tbs(-60, AsnDuration::hours(Uint16(1)), None))
        }

        /// Root -> AA -> AT chain whose three keys are on `algorithm`.
        fn on_curve(algorithm: KeyAlgorithm) -> Self {
            let mut backend = EcdsaBackend::new();
            let root =
                OwnCertificate::initialize_self_signed_with(&mut backend, ca_tbs(), algorithm);
            let aa =
                OwnCertificate::initialize_issued_with(&mut backend, ca_tbs(), &root, algorithm);
            let at = OwnCertificate::initialize_issued_with(
                &mut backend,
                at_tbs(-60, AsnDuration::hours(Uint16(1)), None),
                &aa,
                algorithm,
            );
            let lib = CertificateLibrary::new(
                &backend,
                vec![root.cert.clone()],
                vec![aa.cert.clone()],
                vec![],
            );
            let mut svc = SignService::new(backend, lib);
            svc.add_own_certificate(at);
            Fixture {
                svc,
                root: root.cert,
                aa: aa.cert.clone(),
                aa_owner: aa,
            }
        }

        /// Chain whose AT is an implicit certificate issued with ECQV.
        fn implicit() -> Self {
            let mut backend = EcdsaBackend::new();
            let root = OwnCertificate::initialize_self_signed(&mut backend, ca_tbs());
            let aa = OwnCertificate::initialize_issued(&mut backend, ca_tbs(), &root);
            let at = aa.issue_implicit_certificate(
                &mut backend,
                at_tbs(-60, AsnDuration::hours(Uint16(1)), None),
            );
            let lib = CertificateLibrary::new(
                &backend,
                vec![root.cert.clone()],
                vec![aa.cert.clone()],
                vec![],
            );
            let mut svc = SignService::new(backend, lib);
            svc.add_own_certificate(at);
            Fixture {
                svc,
                root: root.cert,
                aa: aa.cert.clone(),
                aa_owner: aa,
            }
        }

        fn try_sign(
            &mut self,
            psid: u64,
            location: Option<(i32, i32)>,
            permissions: &[u8],
        ) -> Result<Vec<u8>, SigningError> {
            if psid == 36 {
                self.svc.cam_state_mut().requested_own_certificate = true;
            }
            self.svc
                .try_sign_request(&SNSignRequest {
                    tbs_message: b"payload".to_vec(),
                    its_aid: psid,
                    permissions: permissions.to_vec(),
                    generation_location: location.map(|(latitude, longitude)| GenerationLocation {
                        latitude,
                        longitude,
                        elevation: 0xF000,
                    }),
                })
                .map(|c| c.sec_message)
        }

        fn sign(&mut self, psid: u64) -> Vec<u8> {
            let location = (psid == 37).then_some(INSIDE);
            self.try_sign(psid, location, &[]).unwrap()
        }

        fn verify(&self, message: Vec<u8>) -> SNVerifyConfirm {
            let mut lib = CertificateLibrary::new(
                &self.svc.backend,
                vec![self.root.clone()],
                vec![self.aa.clone()],
                vec![],
            );
            verify_message(&SNVerifyRequest { message }, &self.svc.backend, &mut lib).0
        }
    }

    fn mutated(msg: &[u8], f: impl FnOnce(&mut SignedData)) -> Vec<u8> {
        let mut dot2 = decode_ieee1609_dot2_data(msg);
        match &mut dot2.content {
            Ieee1609Dot2Content::signedData(sd) => f(sd),
            _ => panic!("expected signedData"),
        }
        encode_ieee1609_dot2_data(&dot2)
    }

    fn location(lat: i32, lon: i32) -> ThreeDLocation {
        ThreeDLocation {
            latitude: Latitude(NinetyDegreeInt(lat)),
            longitude: Longitude(OneEightyDegreeInt(lon)),
            elevation: Elevation(Uint16(0xF000)),
        }
    }

    /// Own chains on every IEEE 1609.2 PublicVerificationKey curve: the
    /// issuer choice, the self-signed hash, hashId and the signature follow
    /// the curve, and the messages verify.
    #[test]
    fn chain_on_every_curve_signs_and_verifies() {
        for (algorithm, sha384) in [
            (KeyAlgorithm::NistP256, false),
            (KeyAlgorithm::BrainpoolP256r1, false),
            (KeyAlgorithm::BrainpoolP384r1, true),
            (KeyAlgorithm::NistP384, true),
        ] {
            let mut f = Fixture::on_curve(algorithm);
            assert_eq!(
                matches!(
                    f.root.base().issuer,
                    IssuerIdentifier::R_self(HashAlgorithm::sha384)
                ),
                sha384
            );
            assert_eq!(
                matches!(f.aa.base().issuer, IssuerIdentifier::sha384AndDigest(_)),
                sha384
            );
            for psid in [36, 37] {
                let msg = f.sign(psid);
                let Ieee1609Dot2Content::signedData(sd) = decode_ieee1609_dot2_data(&msg).content
                else {
                    panic!("signedData")
                };
                assert_eq!(sd.hash_id == HashAlgorithm::sha384, sha384, "{algorithm:?}");
                let expected = match algorithm {
                    KeyAlgorithm::NistP256 => {
                        matches!(sd.signature, Ieee1609Signature::ecdsaNistP256Signature(_))
                    }
                    KeyAlgorithm::BrainpoolP256r1 => matches!(
                        sd.signature,
                        Ieee1609Signature::ecdsaBrainpoolP256r1Signature(_)
                    ),
                    KeyAlgorithm::BrainpoolP384r1 => matches!(
                        sd.signature,
                        Ieee1609Signature::ecdsaBrainpoolP384r1Signature(_)
                    ),
                    KeyAlgorithm::NistP384 => {
                        matches!(sd.signature, Ieee1609Signature::ecdsaNistP384Signature(_))
                    }
                };
                assert!(expected, "{algorithm:?}");
                assert_eq!(
                    f.verify(msg).report,
                    ReportVerify::Success,
                    "{algorithm:?} {psid}"
                );
            }
        }
    }

    #[test]
    fn signing_input_is_hash_of_hashes() {
        let input = signing_input(b"data", b"cert", false);
        assert_eq!(&input[..32], &Sha256::digest(b"data")[..]);
        assert_eq!(&input[32..], &Sha256::digest(b"cert")[..]);
        assert_eq!(
            &signing_input(b"data", &[], false)[32..],
            &Sha256::digest(b"")[..]
        );
    }

    /// IEEE 1609.2 clause 5.3.1: signature over Hash(Hash(tbs) || Hash(AT)).
    #[test]
    fn message_signature_covers_the_signer_certificate() {
        let mut f = Fixture::valid();
        let msg = f.sign(36);
        let dot2 = decode_ieee1609_dot2_data(&msg);
        let Ieee1609Dot2Content::signedData(sd) = &dot2.content else {
            panic!("expected signedData")
        };
        let at = f.svc.get_present_at(36).unwrap();
        let pk = f.svc.backend.get_public_key(at.key_id);
        let tbs = encode_tbs_data(&sd.tbs_data);
        let canonical = at.to_canonical().encode().to_vec();
        assert!(f.svc.backend.verify_with_pk(
            &signing_input(&tbs, &canonical, false),
            &sd.signature,
            &pk
        ));
        assert!(!f.svc.backend.verify_with_pk(&tbs, &sd.signature, &pk));
    }

    /// ETSI TS 103 097 clause 7.1.1: ITS-AID and SSP of the signer returned.
    #[test]
    fn valid_cam_reports_its_aid_and_ssp() {
        let mut f = Fixture::valid();
        let msg = f.sign(36);
        let c = f.verify(msg);
        assert_eq!(c.report, ReportVerify::Success);
        assert_eq!(c.its_aid, 36);
        assert_eq!(c.permissions, vec![2u8, 0x02, 0x00]);
    }

    /// ETSI TS 103 097 clause 5.1.
    #[test]
    fn protocol_version_other_than_3() {
        let mut f = Fixture::valid();
        let msg = f.sign(36);
        for version in [2u8, 4] {
            let mut bad = msg.clone();
            bad[0] = version;
            assert_eq!(f.verify(bad).report, ReportVerify::IncompatibleProtocol);
        }
    }

    type HeaderMutation = Box<dyn Fn(&mut SignedData)>;

    fn header_cases() -> Vec<(&'static str, HeaderMutation)> {
        vec![
            (
                "generationLocation",
                Box::new(|sd: &mut SignedData| {
                    sd.tbs_data.header_info.generation_location = Some(location(INSIDE.0, INSIDE.1))
                }),
            ),
            (
                "expiryTime",
                Box::new(|sd: &mut SignedData| {
                    sd.tbs_data.header_info.expiry_time = Some(Time64(Uint64(1)))
                }),
            ),
            (
                "missingCrlIdentifier",
                Box::new(|sd: &mut SignedData| {
                    sd.tbs_data.header_info.missing_crl_identifier = Some(MissingCrlIdentifier {
                        craca_id: HashedId3(FixedOctetString::from([0u8; 3])),
                        crl_series: CrlSeries(Uint16(0)),
                    })
                }),
            ),
            (
                "encryptionKey",
                Box::new(|sd: &mut SignedData| {
                    sd.tbs_data.header_info.encryption_key = Some(EncryptionKey::symmetric(
                        SymmetricEncryptionKey::aes128Ccm(vec![0u8; 16].into()),
                    ))
                }),
            ),
        ]
    }

    /// ETSI TS 103 097 clause 7.1.1.
    #[test]
    fn cam_forbidden_header_fields() {
        let mut f = Fixture::valid();
        for (name, mutate) in header_cases() {
            let bad = mutated(&f.sign(36), |sd| mutate(sd));
            assert_eq!(
                f.verify(bad).report,
                ReportVerify::IncompatibleProtocol,
                "{name}"
            );
        }
    }

    /// ETSI TS 103 097 clause 5.2, ETSI TS 103 097 clause 7.1.2.
    #[test]
    fn denm_forbidden_header_fields() {
        let mut f = Fixture::valid();
        for (name, mutate) in header_cases().into_iter().skip(2) {
            let bad = mutated(&f.sign(37), |sd| mutate(sd));
            assert_eq!(
                f.verify(bad).report,
                ReportVerify::IncompatibleProtocol,
                "{name}"
            );
        }
    }

    /// IEEE 1609.2 clause 5.2.3.2.2: the AT does not permit the PSID.
    #[test]
    fn psid_not_in_app_permissions() {
        let mut f = Fixture::valid();
        let bad = mutated(&f.sign(36), |sd| {
            sd.tbs_data.header_info.psid = Psid(Integer::from(99))
        });
        assert_eq!(f.verify(bad).report, ReportVerify::InvalidCertificate);
    }

    /// IEEE 1609.2 clause 5.2.3.2.2: generationTime inside the AT validity.
    #[test]
    fn generation_time_outside_certificate_validity() {
        let mut f = Fixture::valid();
        let start_us = (now_s() as u64 - 60) * 1_000_000;
        let bad = mutated(&f.sign(36), |sd| {
            sd.tbs_data.header_info.generation_time = Some(Time64(Uint64(start_us - 10_000_000)))
        });
        assert_eq!(f.verify(bad).report, ReportVerify::InvalidTimestamp);
    }

    /// ETSI TS 103 097 clause 6.
    #[test]
    fn signer_self_is_unsupported() {
        let mut f = Fixture::valid();
        let bad = mutated(&f.sign(36), |sd| sd.signer = SignerIdentifier::R_self(()));
        assert_eq!(
            f.verify(bad).report,
            ReportVerify::UnsupportedSignerIdentifierType
        );
    }

    /// ETSI TS 103 097 clause 6.
    #[test]
    fn signature_algorithm_not_matching_the_key() {
        let mut f = Fixture::valid();
        for psid in [36, 37] {
            let bad = mutated(&f.sign(psid), |sd| {
                if let Ieee1609Signature::ecdsaNistP256Signature(s) = &sd.signature {
                    sd.signature = Ieee1609Signature::ecdsaBrainpoolP256r1Signature(s.clone());
                }
            });
            assert_eq!(f.verify(bad).report, ReportVerify::FalseSignature);
        }
    }

    /// ETSI TS 103 097 clause 6.
    #[test]
    fn altered_signature() {
        let mut f = Fixture::valid();
        let bad = mutated(&f.sign(37), |sd| {
            if let Ieee1609Signature::ecdsaNistP256Signature(s) = &mut sd.signature {
                let mut b = s.s_sig.to_vec();
                *b.last_mut().unwrap() ^= 0x01;
                s.s_sig = b.into();
            }
        });
        assert_eq!(f.verify(bad).report, ReportVerify::FalseSignature);
    }

    /// ETSI TS 103 097 clause 7.1.1: rSig as compressed-y-0 / compressed-y-1.
    #[test]
    fn compressed_r_signature_accepted() {
        let mut f = Fixture::valid();
        for y1 in [false, true] {
            let msg = mutated(&f.sign(36), |sd| {
                if let Ieee1609Signature::ecdsaNistP256Signature(s) = &mut sd.signature {
                    if let EccP256CurvePoint::x_only(r) = &s.r_sig {
                        s.r_sig = if y1 {
                            EccP256CurvePoint::compressed_y_1(r.clone())
                        } else {
                            EccP256CurvePoint::compressed_y_0(r.clone())
                        };
                    }
                }
            });
            assert_eq!(f.verify(msg).report, ReportVerify::Success);
        }
    }

    /// IEEE 1609.2 clause 5.2.3.2.2 (circular),
    /// ETSI TS 103 097 clause 7.1.2 and region consistency on reception.
    #[test]
    fn region_restriction() {
        let mut f = Fixture::new(at_tbs(-60, AsnDuration::hours(Uint16(1)), Some(circle())));
        let msg = f.try_sign(37, Some(INSIDE), &[]).unwrap();
        assert_eq!(f.verify(msg.clone()).report, ReportVerify::Success);
        assert!(f.try_sign(37, Some(OUTSIDE), &[]).is_err());
        assert!(f.try_sign(36, Some(OUTSIDE), &[]).is_err());
        let bad = mutated(&msg, |sd| {
            sd.tbs_data.header_info.generation_location = Some(location(OUTSIDE.0, OUTSIDE.1))
        });
        assert_eq!(f.verify(bad).report, ReportVerify::InvalidMobilityData);
    }

    /// IEEE 1609.2 clause 6.4.17: AT restricted to an identifiedRegion of 8
    /// entries, one containing the position (synthetic geometry registered
    /// for UnCountryId 9400..9407). The DENM is signed with the position
    /// inside that entry and accepted; outside every entry the station does
    /// not sign and a receiver rejects the location.
    #[test]
    fn identified_region_restriction() {
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            IdentifiedRegion, SequenceOfIdentifiedRegion, UnCountryId,
        };
        use crate::security::validity::{register_identified_region, RegionKey};
        for i in 0..8u16 {
            let south = 340000000 + i as i32 * 15000000;
            let north = south + 10000000;
            register_identified_region(
                RegionKey::country(9400 + i),
                &[vec![
                    (south, 0),
                    (north, 0),
                    (north, 30000000),
                    (south, 30000000),
                ]],
            );
        }
        let region = GeographicRegion::identifiedRegion(SequenceOfIdentifiedRegion(
            (0..8)
                .map(|i| IdentifiedRegion::countryOnly(UnCountryId(Uint16(9400 + i))))
                .collect(),
        ));
        let mut f = Fixture::new(at_tbs(-60, AsnDuration::hours(Uint16(1)), Some(region)));
        let msg = f.try_sign(37, Some(INSIDE), &[]).unwrap();
        let data = decode_ieee1609_dot2_data(&msg);
        let Ieee1609Dot2Content::signedData(sd) = &data.content else {
            panic!("not signed")
        };
        let loc = sd
            .tbs_data
            .header_info
            .generation_location
            .as_ref()
            .unwrap();
        assert_eq!((loc.latitude.0 .0, loc.longitude.0 .0), INSIDE);
        assert_eq!(f.verify(msg.clone()).report, ReportVerify::Success);
        assert!(f.try_sign(37, Some(OUTSIDE), &[]).is_err());
        let bad = mutated(&msg, |sd| {
            sd.tbs_data.header_info.generation_location = Some(location(OUTSIDE.0, OUTSIDE.1))
        });
        assert_eq!(f.verify(bad).report, ReportVerify::InvalidMobilityData);
    }

    /// IEEE 1609.2 clause 5.2.3.2.2 (region of the AA; region of
    /// the root, AA without region) and IEEE 1609.2 clause 5.2.3.2.2 (no DENM outside the
    /// region of the AA): an AT without region inherits the closest one in its
    /// chain, on transmission and on reception.
    #[test]
    fn region_inherited_from_aa_and_root() {
        let at = || at_tbs(-60, AsnDuration::hours(Uint16(1)), None);
        let chains = [
            (ca_tbs_with_region(Some(circle())), ca_tbs(), "root"),
            (ca_tbs(), ca_tbs_with_region(Some(circle())), "AA"),
        ];
        for (root, aa, holder) in chains {
            let mut f = Fixture::chain(root, aa, at());
            let msg = f.try_sign(37, Some(INSIDE), &[]).unwrap();
            assert_eq!(
                f.verify(msg.clone()).report,
                ReportVerify::Success,
                "{holder}"
            );
            assert!(f.try_sign(37, Some(OUTSIDE), &[]).is_err(), "{holder}");
            // IEEE 1609.2 clause 5.2.3.2.2 (region variant)
            assert!(f.try_sign(36, Some(OUTSIDE), &[]).is_err(), "{holder}");
            let bad = mutated(&msg, |sd| {
                sd.tbs_data.header_info.generation_location = Some(location(OUTSIDE.0, OUTSIDE.1))
            });
            assert_eq!(
                f.verify(bad).report,
                ReportVerify::InvalidMobilityData,
                "{holder}"
            );
        }
    }

    /// ETSI TS 103 097 clause 7.1.2: the signed payload is an
    /// Ieee1609Dot2Data (protocol version 3) of type unsecuredData holding the
    /// DENM, which the receiver returns as the plain message.
    #[test]
    fn signed_denm_payload_is_unsecured_data() {
        let mut f = Fixture::valid();
        let msg = f.sign(37);
        let dot2 = decode_ieee1609_dot2_data(&msg);
        let Ieee1609Dot2Content::signedData(sd) = &dot2.content else {
            panic!("expected signedData")
        };
        let inner = sd.tbs_data.payload.data.as_ref().expect("payload data");
        assert_eq!(inner.protocol_version.0, 3);
        let Ieee1609Dot2Content::unsecuredData(data) = &inner.content else {
            panic!("expected unsecuredData")
        };
        assert_eq!(data.0.as_ref(), b"payload");
        assert!(sd.tbs_data.payload.ext_data_hash.is_none());
        let confirm = f.verify(msg);
        assert_eq!(confirm.report, ReportVerify::Success);
        assert_eq!(confirm.plain_message, b"payload");
    }

    /// ETSI TS 103 097 clause 7.1.3: a message of another
    /// ITS-AID carries that psid and a generationTime, and is accepted.
    #[test]
    fn other_its_aid_header_has_psid_and_generation_time() {
        let mut tbs = at_tbs(-60, AsnDuration::hours(Uint16(1)), None);
        if let Some(app) = tbs.app_permissions.as_mut() {
            app.0.push(PsidSsp::new(Psid(Integer::from(139)), None));
        }
        let mut f = Fixture::new(tbs);
        let before = timestamp_its_microseconds();
        let msg = f.try_sign(139, None, &[]).unwrap();
        let dot2 = decode_ieee1609_dot2_data(&msg);
        let Ieee1609Dot2Content::signedData(sd) = &dot2.content else {
            panic!("expected signedData")
        };
        let header = &sd.tbs_data.header_info;
        assert_eq!(u64::try_from(&header.psid.0).ok(), Some(139));
        let time = header
            .generation_time
            .as_ref()
            .expect("generationTime")
            .0
             .0;
        assert!(time + 1_000_000 >= before && time <= timestamp_its_microseconds() + 1_000_000);
        // First message: the certificate, so any receiver can verify it
        assert!(matches!(&sd.signer, SignerIdentifier::certificate(_)));
        let confirm = f.verify(msg);
        assert_eq!(confirm.report, ReportVerify::Success);
        assert_eq!(confirm.its_aid, 139);
        // Within 1 s: the digest, verifiable by a receiver that knows the AT
        let msg = f.try_sign(139, None, &[]).unwrap();
        let at = f.svc.get_present_at(139).unwrap().cert.clone();
        let sd = signed_data(&msg);
        assert!(
            matches!(&sd.signer, SignerIdentifier::digest(h) if h.0.as_ref() == at.as_hashedid8())
        );
        assert_eq!(
            f.verify(msg.clone()).report,
            ReportVerify::SignerCertificateNotFound
        );
        let mut lib = CertificateLibrary::new(
            &f.svc.backend,
            vec![f.root.clone()],
            vec![f.aa.clone()],
            vec![at],
        );
        let confirm = verify_message(&SNVerifyRequest { message: msg }, &f.svc.backend, &mut lib).0;
        assert_eq!(confirm.report, ReportVerify::Success);
    }

    /// Compressed SEC1 point (02/03 || x) of the public key of scalar `d`.
    macro_rules! brainpool_sign {
        ($curve:ty, $d:expr, $k:expr, $digest:expr) => {{
            use ecdsa_v017::elliptic_curve::sec1::ToSec1Point;
            use ecdsa_v017::elliptic_curve::SecretKey;
            let d = SecretKey::<$curve>::from_slice($d)
                .unwrap()
                .to_nonzero_scalar();
            let k = SecretKey::<$curve>::from_slice($k)
                .unwrap()
                .to_nonzero_scalar();
            let public = SecretKey::<$curve>::from_slice($d)
                .unwrap()
                .public_key()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec();
            let (sig, _) = ecdsa_v017::hazmat::sign_prehashed::<$curve>(&d, &k, $digest).unwrap();
            (public, sig.to_bytes().to_vec())
        }};
    }

    /// CAM (36) or DENM (37) signed with a brainpoolP256r1 / P384r1 AT issued
    /// by the fixture's AA: the fixture's message with its signer replaced by
    /// that AT and its signature recomputed over Hash(Hash(tbs) || Hash(AT))
    /// (ECDSA with a fixed nonce, test only).
    fn brainpool_message(f: &mut Fixture, psid: u64, p384: bool) -> Vec<u8> {
        use crate::security::certificate::{encode_tbs_data, signing_input};
        use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
        use crate::security::security_asn::ieee1609_dot2::Certificate as AsnCertificate;
        use crate::security::security_asn::ieee1609_dot2::{
            CertificateBase, CertificateType, IssuerIdentifier, SequenceOfCertificate,
        };
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            EccP384CurvePoint, EcdsaP256Signature, EcdsaP384Signature, HashAlgorithm, Uint8,
        };
        use sha2::Sha384;

        // Key pair (the signature depends on the message, so it is computed
        // twice: once for the key, once over the final message).
        let size = if p384 { 48 } else { 32 };
        let (d, k) = (vec![7u8; size], vec![9u8; size]);
        let public = if p384 {
            brainpool_sign!(bp384::BrainpoolP384r1, &d, &k, &[1u8; 48]).0
        } else {
            brainpool_sign!(bp256::BrainpoolP256r1, &d, &k, &[1u8; 32]).0
        };
        let x = public[1..].to_vec();
        let key = match (p384, public[0]) {
            (false, 2) => PublicVerificationKey::ecdsaBrainpoolP256r1(
                EccP256CurvePoint::compressed_y_0(x.into()),
            ),
            (false, _) => PublicVerificationKey::ecdsaBrainpoolP256r1(
                EccP256CurvePoint::compressed_y_1(x.into()),
            ),
            (true, 2) => PublicVerificationKey::ecdsaBrainpoolP384r1(
                EccP384CurvePoint::compressed_y_0(x.into()),
            ),
            (true, _) => PublicVerificationKey::ecdsaBrainpoolP384r1(
                EccP384CurvePoint::compressed_y_1(x.into()),
            ),
        };
        let mut tbs_cert = at_tbs(-60, AsnDuration::hours(Uint16(1)), None);
        tbs_cert.verify_key_indicator = VerificationKeyIndicator::verificationKey(key);
        let unsigned = Certificate::from_asn(
            EtsiTs103097Certificate(AsnCertificate(CertificateBase::new(
                Uint8(3),
                CertificateType::explicit,
                IssuerIdentifier::R_self(HashAlgorithm::sha256),
                tbs_cert,
                None,
            ))),
            None,
        );
        let at = f.aa_owner.issue_certificate(&f.svc.backend, &unsigned);

        let location = (psid == 37).then_some(INSIDE);
        let template = f.try_sign(psid, location, &[]).unwrap();
        let mut dot2 = decode_ieee1609_dot2_data(&template);
        let Ieee1609Dot2Content::signedData(sd) = &mut dot2.content else {
            panic!("expected signedData")
        };
        sd.signer = SignerIdentifier::certificate(SequenceOfCertificate(vec![at.inner.0.clone()]));
        let input = signing_input(
            &encode_tbs_data(&sd.tbs_data),
            at.to_canonical().encode(),
            p384,
        );
        sd.signature = if p384 {
            sd.hash_id = HashAlgorithm::sha384;
            let rs = brainpool_sign!(bp384::BrainpoolP384r1, &d, &k, &Sha384::digest(&input)).1;
            Ieee1609Signature::ecdsaBrainpoolP384r1Signature(EcdsaP384Signature {
                r_sig: EccP384CurvePoint::x_only(rs[..48].to_vec().into()),
                s_sig: rs[48..].to_vec().into(),
            })
        } else {
            let rs = brainpool_sign!(bp256::BrainpoolP256r1, &d, &k, &Sha256::digest(&input)).1;
            Ieee1609Signature::ecdsaBrainpoolP256r1Signature(EcdsaP256Signature {
                r_sig: EccP256CurvePoint::x_only(rs[..32].to_vec().into()),
                s_sig: rs[32..].to_vec().into(),
            })
        };
        encode_ieee1609_dot2_data(&dot2)
    }

    /// ETSI TS 103 097 clause 7.1.1, ETSI TS 103 097 clause 7.1.2: CAMs and
    /// DENMs signed with brainpoolP256r1 / brainpoolP384r1 ATs are accepted;
    /// an altered signature is not.
    #[test]
    fn brainpool_signed_cam_and_denm_accepted() {
        let mut f = Fixture::valid();
        for p384 in [false, true] {
            for psid in [36u64, 37] {
                let msg = brainpool_message(&mut f, psid, p384);
                let confirm = f.verify(msg.clone());
                assert_eq!(
                    confirm.report,
                    ReportVerify::Success,
                    "psid {psid} p384 {p384}"
                );
                assert_eq!(confirm.plain_message, b"payload");
                let bad = mutated(&msg, |sd| {
                    if let Ieee1609Signature::ecdsaBrainpoolP256r1Signature(sig) = &mut sd.signature
                    {
                        sig.s_sig = vec![1u8; 32].into();
                    }
                    if let Ieee1609Signature::ecdsaBrainpoolP384r1Signature(sig) = &mut sd.signature
                    {
                        sig.s_sig = vec![1u8; 48].into();
                    }
                });
                assert_eq!(f.verify(bad).report, ReportVerify::FalseSignature);
            }
        }
    }

    /// Region kinds of the TP permutation tables, each with the position
    /// INSIDE in one entry and OUTSIDE in none: B circular; C rectangular
    /// with 8 entries (IEEE 1609.2 clause 6.4.17); D polygonal with 8 points
    /// (IEEE 1609.2 clause 6.4.17); E identified with 8 entries (IEEE 1609.2 clause 6.4.17,
    /// synthetic geometry for UnCountryId 9500..9507).
    fn region_kinds() -> Vec<(&'static str, GeographicRegion)> {
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            IdentifiedRegion, PolygonalRegion, RectangularRegion, SequenceOfIdentifiedRegion,
            SequenceOfRectangularRegion, UnCountryId,
        };
        use crate::security::validity::{register_identified_region, RegionKey};
        let point = |lat: i32, lon: i32| {
            TwoDLocation::new(
                Latitude(NinetyDegreeInt(lat)),
                Longitude(OneEightyDegreeInt(lon)),
            )
        };
        // 8 boxes 41.5-41.6 N, 0.2 deg wide, 0.3 deg apart; the 6th holds INSIDE
        let rects = (0..8)
            .map(|i| {
                let west = 5340000 + i * 3000000;
                RectangularRegion::new(point(416000000, west), point(415000000, west + 2000000))
            })
            .collect();
        let (c_lat, c_lon) = INSIDE;
        let octagon = [
            (1000000, -400000),
            (1000000, 400000),
            (400000, 1000000),
            (-400000, 1000000),
            (-1000000, 400000),
            (-1000000, -400000),
            (-400000, -1000000),
            (400000, -1000000),
        ]
        .iter()
        .map(|(dlat, dlon)| point(c_lat + dlat, c_lon + dlon))
        .collect();
        for i in 0..8u16 {
            let south = 340000000 + i as i32 * 15000000;
            let north = south + 10000000;
            register_identified_region(
                RegionKey::country(9500 + i),
                &[vec![
                    (south, 0),
                    (north, 0),
                    (north, 30000000),
                    (south, 30000000),
                ]],
            );
        }
        let identified = (0..8)
            .map(|i| IdentifiedRegion::countryOnly(UnCountryId(Uint16(9500 + i))))
            .collect();
        vec![
            ("B circular", circle()),
            (
                "C rectangular x8",
                GeographicRegion::rectangularRegion(SequenceOfRectangularRegion(rects)),
            ),
            (
                "D polygonal x8",
                GeographicRegion::polygonalRegion(PolygonalRegion(octagon)),
            ),
            (
                "E identified x8",
                GeographicRegion::identifiedRegion(SequenceOfIdentifiedRegion(identified)),
            ),
        ]
    }

    /// IEEE 1609.2 clause 5.2.3.2.2, IEEE 1609.2 clause 6.4.17,
    /// IEEE 1609.2 clause 6.4.17 (DENM sent with generationLocation inside the region),
    /// ETSI TS 103 097 clause 7.1.2 and ETSI TS 103 097 clause 7.1.1 (accepted by a receiver),
    /// IEEE 1609.2 clause 5.2.3.2.2 (not sent outside) for every region kind.
    #[test]
    fn every_region_kind_end_to_end() {
        for (kind, region) in region_kinds() {
            let mut f = Fixture::new(at_tbs(-60, AsnDuration::hours(Uint16(1)), Some(region)));
            let denm = f.try_sign(37, Some(INSIDE), &[]).unwrap();
            let dot2 = decode_ieee1609_dot2_data(&denm);
            let Ieee1609Dot2Content::signedData(sd) = &dot2.content else {
                panic!("not signed")
            };
            let loc = sd
                .tbs_data
                .header_info
                .generation_location
                .as_ref()
                .unwrap();
            assert_eq!((loc.latitude.0 .0, loc.longitude.0 .0), INSIDE, "{kind}");
            assert_eq!(
                f.verify(denm.clone()).report,
                ReportVerify::Success,
                "{kind}"
            );
            let cam = f.sign(36);
            assert_eq!(f.verify(cam).report, ReportVerify::Success, "{kind}");
            assert!(f.try_sign(37, Some(OUTSIDE), &[]).is_err(), "{kind}");
            let bad = mutated(&denm, |sd| {
                sd.tbs_data.header_info.generation_location = Some(location(OUTSIDE.0, OUTSIDE.1))
            });
            assert_eq!(
                f.verify(bad).report,
                ReportVerify::InvalidMobilityData,
                "{kind}"
            );
        }
    }

    // ── Content of sent CAMs / DENMs (TS 103 096-2 clauses 6.2.2, 6.2.3) ──

    /// AT valid for 1 h with the given PSIDs (no SSP).
    fn at_tbs_with_psids(psids: &[u64]) -> ToBeSignedCertificate {
        let mut tbs = at_tbs(-60, AsnDuration::hours(Uint16(1)), None);
        tbs.app_permissions = Some(SequenceOfPsidSsp(
            psids
                .iter()
                .map(|p| PsidSsp::new(Psid(Integer::from(*p)), None))
                .collect(),
        ));
        tbs
    }

    fn signed_data(msg: &[u8]) -> SignedData {
        match decode_ieee1609_dot2_data(msg).content {
            Ieee1609Dot2Content::signedData(sd) => sd,
            _ => panic!("expected signedData"),
        }
    }

    fn signer_tbs(sd: &SignedData) -> ToBeSignedCertificate {
        match &sd.signer {
            SignerIdentifier::certificate(certs) => certs.0[0].0.to_be_signed.clone(),
            _ => panic!("expected certificate signer"),
        }
    }

    /// IEEE 1609.2 clause 5.2.3.2.2: CUR_TIME - 5 min <=
    /// generationTime <= CUR_TIME + 5 min, inside the validity period of the
    /// signing AT.
    #[test]
    fn generation_time_inside_at_validity() {
        use crate::security::validity::validity_window_us;
        let mut f = Fixture::valid();
        for psid in [36u64, 37] {
            let now = timestamp_its_microseconds();
            let sd = signed_data(&f.sign(psid));
            let time = sd
                .tbs_data
                .header_info
                .generation_time
                .as_ref()
                .unwrap()
                .0
                 .0;
            assert!(time.abs_diff(now) <= 300_000_000, "psid {psid}");
            let (start, end) = validity_window_us(&signer_tbs(&sd));
            assert!(start <= time && time <= end, "psid {psid}");
        }
    }

    /// IEEE 1609.2 clause 5.2.3.2.2.
    #[test]
    fn signer_app_permissions_contain_the_psid() {
        use crate::security::validity::app_permission;
        let mut f = Fixture::valid();
        for psid in [36u64, 37] {
            let sd = signed_data(&f.sign(psid));
            assert!(app_permission(&signer_tbs(&sd), psid).0, "psid {psid}");
        }
    }

    /// IEEE 1609.2 clause 5.2.3.2.2: the only AT lacks the PSID.
    #[test]
    fn no_message_without_permitted_at() {
        let mut f = Fixture::new(at_tbs_with_psids(&[139]));
        assert!(f.try_sign(36, None, &[]).is_err());
        assert!(f.try_sign(37, Some(INSIDE), &[]).is_err());
    }

    /// IEEE 1609.2 clause 6.3.30 (A, NIST P-256).
    #[test]
    fn signature_r_is_x_only_or_compressed() {
        let mut f = Fixture::valid();
        let sd = signed_data(&f.sign(36));
        let Ieee1609Signature::ecdsaNistP256Signature(sig) = &sd.signature else {
            panic!("expected ecdsaNistP256Signature")
        };
        assert!(matches!(
            sig.r_sig,
            EccP256CurvePoint::x_only(_)
                | EccP256CurvePoint::compressed_y_0(_)
                | EccP256CurvePoint::compressed_y_1(_)
        ));
    }

    /// IEEE 1609.2 clause 5.2.3.2.2 (8 appPermissions, AID_CAM last).
    #[test]
    fn at_with_8_app_permissions() {
        let psids: Vec<u64> = (130..137).chain([36]).collect();
        let mut f = Fixture::new(at_tbs_with_psids(&psids));
        let msg = f.sign(36);
        assert_eq!(
            u64::try_from(&signed_data(&msg).tbs_data.header_info.psid.0).ok(),
            Some(36)
        );
        assert_eq!(f.verify(msg).report, ReportVerify::Success);
    }

    /// IEEE 1609.2 clause 5.2.3.2.2 (8 certIssuePermissions in the AA, AID_CAM
    /// last); without AID_CAM the AT is not a valid CAM signer.
    #[test]
    fn aa_with_8_cert_issue_permissions() {
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            PsidSspRange, SequenceOfPsidSspRange,
        };
        let aa = |psids: Vec<u64>| {
            let mut tbs = ca_tbs();
            tbs.cert_issue_permissions = Some(SequenceOfPsidGroupPermissions(
                psids
                    .into_iter()
                    .map(|p| {
                        PsidGroupPermissions::new(
                            SubjectPermissions::explicit(SequenceOfPsidSspRange(vec![
                                PsidSspRange::new(Psid(Integer::from(p)), None),
                            ])),
                            Integer::from(0),
                            Integer::from(0),
                            {
                                let mut bits = FixedBitString::<8>::default();
                                bits.set(0, true);
                                EndEntityType(bits)
                            },
                        )
                    })
                    .collect(),
            ));
            tbs
        };
        let mut f = Fixture::chain(
            ca_tbs(),
            aa((130..137).chain([36]).collect()),
            at_tbs_with_psids(&[36]),
        );
        let msg = f.sign(36);
        assert_eq!(f.verify(msg).report, ReportVerify::Success);
        let mut f = Fixture::chain(ca_tbs(), aa((130..138).collect()), at_tbs_with_psids(&[36]));
        match f.try_sign(36, None, &[]) {
            Err(_) => {}
            Ok(msg) => assert_ne!(f.verify(msg).report, ReportVerify::Success),
        }
    }

    // ── Secured Beacons (TS 103 836-4-1 clause 10.3.6.2 step 2) ──────────

    fn beacon_request() -> crate::geonet::service_access_point::GNDataRequest {
        use crate::geonet::service_access_point::*;
        GNDataRequest {
            upper_protocol_entity: CommonNH::Any,
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Beacon,
                header_sub_type: HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
            },
            communication_profile: CommunicationProfile::Unspecified,
            traffic_class: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            security_profile: crate::security::sn_sap::SecurityProfile::NoSecurity,
            its_aid: 0,
            security_permissions: vec![],
            max_hop_limit: 1,
            max_packet_lifetime: None,
            destination: None,
            length: 0,
            data: vec![],
            area: Area {
                latitude: 0,
                longitude: 0,
                a: 0,
                b: 0,
                angle: 0,
            },
        }
    }

    fn gn_station(
        n: u8,
        sign: Option<SignService>,
        verify: Option<(EcdsaBackend, CertificateLibrary)>,
    ) -> (
        crate::geonet::router::Router,
        std::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        use crate::geonet::gn_address::{GNAddress, M, MID, ST};
        use crate::geonet::mib::{GnSecurity, Mib};
        use crate::geonet::position_vector::Tst;
        let mut mib = Mib::new();
        mib.itsGnSecurity = GnSecurity::Enabled;
        mib.itsGnBeaconServiceRetransmitTimer = 0;
        mib.itsGnLocalGnAddr =
            GNAddress::new(M::GnUnicast, ST::Unknown, MID::new([2, 0, 0, 0, 0, n]));
        let (ll_tx, ll_rx) = std::sync::mpsc::channel();
        let (btp_tx, _btp_rx) = std::sync::mpsc::channel();
        let (backend, library) = verify.unzip();
        let mut router =
            crate::geonet::router::Router::new(mib, ll_tx, btp_tx, sign, backend, library);
        router.ego_position_vector.latitude = INSIDE.0 as u32;
        router.ego_position_vector.longitude = INSIDE.1 as u32;
        router.ego_position_vector.pai = true;
        router.ego_position_vector.tst = Tst::set_in_normal_timestamp_milliseconds(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
        (router, ll_rx)
    }

    /// Secured Beacons sent by one GN router and verified by another:
    /// ETSI TS 103 097 clause 7.1.3 (signedData; generationTime
    /// inside the AT validity), GENMSG_06_BV (unsecuredData payload),
    /// GENMSG_07_BV (AT appPermissions contain ITS-AID 141). Messages other
    /// than CAM and DENM carry the certificate once per second and the digest
    /// otherwise (TS 103 097 clause 7.1.3 does not constrain the signer).
    #[test]
    fn secured_beacon_sent_and_verified() {
        use crate::geonet::basic_header::{BasicHeader, BasicNH};
        use crate::geonet::gn_address::{GNAddress, M, MID, ST};
        use crate::security::validity::{app_permission, validity_window_us};
        let f = Fixture::new(at_tbs_with_psids(&[36, 37, 141]));
        let at = f.svc.get_present_at(141).unwrap().cert.clone();
        let Fixture { svc, root, aa, .. } = f;
        let backend = svc.backend.clone();
        let now = timestamp_its_microseconds();
        let (mut sender, ll_rx) = gn_station(1, Some(svc), None);
        sender.gn_data_request(beacon_request());
        let packets: Vec<Vec<u8>> = ll_rx.try_iter().collect();
        assert_eq!(packets.len(), 1);
        let basic = BasicHeader::decode(packets[0][0..4].try_into().unwrap());
        assert!(matches!(basic.nh, BasicNH::SecuredPacket));
        let sd = signed_data(&packets[0][4..]); // GENMSG_01
        let header = &sd.tbs_data.header_info;
        assert_eq!(u64::try_from(&header.psid.0).ok(), Some(141));
        let time = header.generation_time.as_ref().unwrap().0 .0; // GENMSG_05
        let (start, end) = validity_window_us(at.tbs());
        assert!(start <= time && time <= end);
        assert!(time.abs_diff(now) <= 600_000_000);
        let inner = sd.tbs_data.payload.data.as_ref().unwrap(); // GENMSG_06
        let Ieee1609Dot2Content::unsecuredData(data) = &inner.content else {
            panic!("expected unsecuredData")
        };
        assert_eq!(data.0.len(), 8 + 24);
        // GENMSG_05 / GENMSG_07: the signer certificate is the AT, valid at
        // generationTime and permitting ITS-AID 141
        let signer = signer_tbs(&sd);
        let (start, end) = validity_window_us(&signer);
        assert!(start <= time && time <= end);
        assert!(app_permission(&signer, 141).0);
        assert_eq!(signer, *at.tbs());
        let library = |ats: Vec<Certificate>| {
            CertificateLibrary::new(&backend, vec![root.clone()], vec![aa.clone()], ats)
        };
        let sender_addr = GNAddress::new(M::GnUnicast, ST::Unknown, MID::new([2, 0, 0, 0, 0, 1]));
        // A receiver that never heard from the sender verifies it
        let (mut receiver, _) = gn_station(7, None, Some((backend.clone(), library(vec![]))));
        receiver.process_basic_header(&packets[0]);
        assert!(receiver
            .location_table
            .get_entry_ref(&sender_addr)
            .is_some());
        // The next Beacon within 1 s carries the digest: a stranger cannot verify it
        sender.gn_data_request(beacon_request());
        let next: Vec<Vec<u8>> = ll_rx.try_iter().collect();
        let sd = signed_data(&next[0][4..]);
        assert!(
            matches!(&sd.signer, SignerIdentifier::digest(h) if h.0.as_ref() == at.as_hashedid8())
        );
        let (mut stranger, _) = gn_station(8, None, Some((backend.clone(), library(vec![]))));
        stranger.process_basic_header(&next[0]);
        assert!(stranger
            .location_table
            .get_entry_ref(&sender_addr)
            .is_none());
    }

    /// No AT for ITS-AID 141: no Beacon.
    #[test]
    fn no_beacon_without_gn_mgmt_permission() {
        let Fixture { svc, .. } = Fixture::valid();
        let (mut sender, ll_rx) = gn_station(1, Some(svc), None);
        sender.gn_data_request(beacon_request());
        assert!(ll_rx.try_recv().is_err());
    }

    // ── P2PCD between stations (TS 103 097 clause 7.1.1) ─────────────────
    // Mirrors TestPeerToPeerCertificateDistribution; the IUT is station `a`
    // and the 1 s certificate timer is driven explicitly (base 100 s).

    struct Pki {
        backend: EcdsaBackend,
        root: OwnCertificate,
    }

    impl Pki {
        fn new() -> Self {
            let mut backend = EcdsaBackend::new();
            let root = OwnCertificate::initialize_self_signed(&mut backend, ca_tbs());
            Pki { backend, root }
        }
        fn aa(&mut self) -> OwnCertificate {
            OwnCertificate::initialize_issued(&mut self.backend, ca_tbs(), &self.root)
        }
        fn station(&mut self, aa: &OwnCertificate, known_aas: &[&OwnCertificate]) -> Station {
            let at = OwnCertificate::initialize_issued(
                &mut self.backend,
                at_tbs(-60, AsnDuration::hours(Uint16(1)), None),
                aa,
            );
            let mut aas = vec![aa.cert.clone()];
            aas.extend(known_aas.iter().map(|k| k.cert.clone()));
            let backend = self.backend.clone();
            let library = |b: &EcdsaBackend| {
                CertificateLibrary::new(b, vec![self.root.cert.clone()], aas.clone(), vec![])
            };
            let verify_library = library(&backend);
            let mut svc = SignService::new(backend.clone(), library(&backend));
            svc.add_own_certificate(at.clone());
            Station {
                svc,
                backend,
                verify_library,
                at: at.cert,
            }
        }
    }

    struct Station {
        svc: SignService,
        backend: EcdsaBackend,
        verify_library: CertificateLibrary,
        at: Certificate,
    }

    impl Station {
        fn cam(&mut self, t: f64) -> Vec<u8> {
            let request = SNSignRequest {
                tbs_message: b"cam".to_vec(),
                its_aid: 36,
                permissions: vec![],
                generation_location: None,
            };
            self.svc
                .try_sign_cam_at(&request, Some(100.0 + t))
                .unwrap()
                .sec_message
        }
        fn receive(&mut self, message: &[u8]) -> ReportVerify {
            VerifyService::new(&self.backend, &mut self.verify_library, Some(&mut self.svc))
                .verify(&SNVerifyRequest {
                    message: message.to_vec(),
                })
                .report
        }
    }

    fn h3(certificate: &Certificate) -> [u8; 3] {
        let h8 = certificate.as_hashedid8();
        [h8[5], h8[6], h8[7]]
    }

    /// (signer is a certificate, inlineP2pcdRequest, requestedCertificate digest)
    type CamFields = (bool, Option<Vec<[u8; 3]>>, Option<[u8; 8]>);

    fn cam_fields(message: &[u8]) -> CamFields {
        use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
        let sd = signed_data(message);
        let header = &sd.tbs_data.header_info;
        let inline = header.inline_p2pcd_request.as_ref().map(|r| {
            r.0.iter()
                .map(|h| [h.0[0], h.0[1], h.0[2]])
                .collect::<Vec<_>>()
        });
        let requested = header.requested_certificate.as_ref().map(|c| {
            Certificate::from_asn(EtsiTs103097Certificate(c.clone()), None).as_hashedid8()
        });
        (
            matches!(sd.signer, SignerIdentifier::certificate(_)),
            inline,
            requested,
        )
    }

    /// ETSI TS 103 097 clause 7.1.1 (certificate in the next CAM)
    /// (inlineP2pcdRequest with the unknown digest), CAM_09_BV (timer
    /// restarted); the request stops once the AT is learned.
    #[test]
    fn p2pcd_unknown_at_signer_digest() {
        let mut pki = Pki::new();
        let (aa1, aa2) = (pki.aa(), pki.aa());
        let mut a = pki.station(&aa1, &[&aa2]);
        let mut b = pki.station(&aa2, &[&aa1]);
        assert!(cam_fields(&a.cam(0.0)).0); // TIME_1
        let b_certificate = b.cam(0.0);
        let b_digest = b.cam(0.1);
        assert!(!cam_fields(&b_digest).0);
        assert_eq!(
            a.receive(&b_digest),
            ReportVerify::SignerCertificateNotFound
        );
        let (certificate, inline, _) = cam_fields(&a.cam(0.4)); // TIME_3
        assert!(certificate); // CAM_08
        assert_eq!(inline, Some(vec![h3(&b.at)])); // CAM_10
        assert!(!cam_fields(&a.cam(1.3)).0); // CAM_09: < 1 s after TIME_3
        assert!(cam_fields(&a.cam(1.45)).0); // about 1 s after TIME_3
        assert_eq!(a.receive(&b_certificate), ReportVerify::Success);
        assert_eq!(cam_fields(&a.cam(1.5)).1, None);
    }

    /// ETSI TS 103 097 clause 7.1.1 (A, sha256AndDigest).
    #[test]
    fn p2pcd_unknown_aa_of_signer_certificate() {
        let mut pki = Pki::new();
        let (aa1, aa2) = (pki.aa(), pki.aa());
        let mut a = pki.station(&aa1, &[]);
        let mut b = pki.station(&aa2, &[&aa1]);
        assert_eq!(a.receive(&b.cam(0.0)), ReportVerify::InconsistentChain);
        assert_eq!(cam_fields(&a.cam(0.3)).1, Some(vec![h3(&aa2.cert)]));
    }

    /// ETSI TS 103 097 clause 7.1.1.
    #[test]
    fn p2pcd_request_for_own_at() {
        let mut pki = Pki::new();
        let (aa1, aa2) = (pki.aa(), pki.aa());
        let mut a = pki.station(&aa1, &[&aa2]);
        let mut b = pki.station(&aa2, &[&aa1]);
        a.cam(0.0);
        let b_first = b.cam(0.0);
        assert_eq!(a.receive(&b_first), ReportVerify::Success);
        let a_digest = a.cam(0.1);
        b.receive(&a_digest); // digest unknown to B
        let b_request = b.cam(0.15);
        assert_eq!(cam_fields(&b_request).1, Some(vec![h3(&a.at)]));
        assert_eq!(a.receive(&b_request), ReportVerify::Success);
        let sd = signed_data(&a.cam(0.3));
        let SignerIdentifier::certificate(certs) = &sd.signer else {
            panic!("expected certificate signer")
        };
        assert_eq!(certs.0[0], a.at.inner.0);
    }

    /// B, which does not know AA1, asks for it after A's certificate CAM.
    fn p2pcd_request_for_aa1(
        pki: &mut Pki,
        aa1: &OwnCertificate,
        aa2: &OwnCertificate,
        b_at: f64,
    ) -> (Station, Vec<u8>) {
        let mut a = pki.station(aa1, &[aa2]);
        let mut b = pki.station(aa2, &[]);
        let a_first = a.cam(0.0); // TIME_1
        assert_eq!(b.receive(&a_first), ReportVerify::InconsistentChain);
        let b_request = b.cam(b_at);
        assert_eq!(cam_fields(&b_request).1, Some(vec![h3(&aa1.cert)]));
        (a, b_request)
    }

    /// IEEE 1609.2 clause 8.2.4: once the requested AA arrives
    /// (requestedCertificate), the requester verifies the CAMs of its ATs. The
    /// AA is learned before the chain of the answering CAM is checked.
    #[test]
    fn p2pcd_requested_aa_is_learned_by_the_requester() {
        let mut pki = Pki::new();
        let (aa1, aa2) = (pki.aa(), pki.aa());
        let mut a = pki.station(&aa1, &[&aa2]);
        let mut b = pki.station(&aa2, &[]);
        let a_first = a.cam(0.0);
        assert_eq!(b.receive(&a_first), ReportVerify::InconsistentChain); // AA1 unknown to B
        let b_request = b.cam(0.2);
        assert_eq!(a.receive(&b_request), ReportVerify::Success); // B asks for AA1
        let answer = a.cam(0.4);
        assert_eq!(cam_fields(&answer).2, Some(aa1.cert.as_hashedid8()));
        b.receive(&answer);
        assert!(b
            .verify_library
            .known_authorization_authorities
            .contains_key(&aa1.cert.as_hashedid8()));
        let a_certificate = a.cam(1.2);
        assert_eq!(b.receive(&a_certificate), ReportVerify::Success);
    }

    /// ETSI TS 103 097 clause 7.1.1.
    #[test]
    fn p2pcd_request_for_issuing_aa() {
        let mut pki = Pki::new();
        let (aa1, aa2) = (pki.aa(), pki.aa());
        let (mut a, b_request) = p2pcd_request_for_aa1(&mut pki, &aa1, &aa2, 0.2);
        assert_eq!(a.receive(&b_request), ReportVerify::Success);
        let (certificate, _, requested) = cam_fields(&a.cam(0.4));
        assert!(!certificate);
        assert_eq!(requested, Some(aa1.cert.as_hashedid8()));
        assert_eq!(cam_fields(&a.cam(0.5)).2, None);
    }

    /// ETSI TS 103 097 clause 7.1.1.
    #[test]
    fn p2pcd_request_for_known_aa_not_issuer() {
        let mut pki = Pki::new();
        let (aa1, aa2, aa_n) = (pki.aa(), pki.aa(), pki.aa());
        let mut a = pki.station(&aa1, &[&aa2, &aa_n]);
        a.cam(0.0);
        let mut b = pki.station(&aa2, &[&aa1]);
        let mut d = pki.station(&aa_n, &[]); // AT issued by AA_N
        let d_cam = d.cam(0.0);
        b.receive(&d_cam); // B does not know AA_N
        let b_request = b.cam(0.2);
        assert_eq!(cam_fields(&b_request).1, Some(vec![h3(&aa_n.cert)]));
        assert_eq!(a.receive(&b_request), ReportVerify::Success);
        let (certificate, _, requested) = cam_fields(&a.cam(0.4));
        assert!(!certificate);
        assert_eq!(requested, Some(aa_n.cert.as_hashedid8()));
    }

    /// ETSI TS 103 097 clause 7.1.1.
    #[test]
    fn p2pcd_request_already_answered_by_another_station() {
        let mut pki = Pki::new();
        let (aa1, aa2) = (pki.aa(), pki.aa());
        let (mut a, b_request) = p2pcd_request_for_aa1(&mut pki, &aa1, &aa2, 0.2);
        let mut c = pki.station(&aa2, &[&aa1]);
        let c_first = c.cam(0.0);
        assert_eq!(a.receive(&c_first), ReportVerify::Success); // A learns C's AT
        assert_eq!(a.receive(&b_request), ReportVerify::Success); // TIME_2
        c.receive(&b_request);
        let c_answer = c.cam(0.25);
        assert_eq!(cam_fields(&c_answer).2, Some(aa1.cert.as_hashedid8()));
        assert_eq!(a.receive(&c_answer), ReportVerify::Success); // TIME_3
        assert_eq!(cam_fields(&a.cam(0.3)).2, None); // TIME_4
    }

    /// ETSI TS 103 097 clause 7.1.1.
    #[test]
    fn p2pcd_request_kept_pending_while_signer_is_certificate() {
        let mut pki = Pki::new();
        let (aa1, aa2) = (pki.aa(), pki.aa());
        let (mut a, b_request) = p2pcd_request_for_aa1(&mut pki, &aa1, &aa2, 0.9);
        assert_eq!(a.receive(&b_request), ReportVerify::Success); // TIME_2 = 0.9
        let (certificate, _, requested) = cam_fields(&a.cam(1.05));
        assert!(certificate); // CAM_16
        assert_eq!(requested, None);
        let (certificate, _, requested) = cam_fields(&a.cam(1.2));
        assert!(!certificate); // CAM_17
        assert_eq!(requested, Some(aa1.cert.as_hashedid8()));
    }

    /// IEEE 1609.2 clause 5.2.3.2.2.
    #[test]
    fn expired_and_not_yet_valid_at() {
        for start in [-7200i64, 3600] {
            let mut f = Fixture::new(at_tbs(start, AsnDuration::hours(Uint16(1)), None));
            assert!(f.try_sign(36, None, &[]).is_err());
            assert!(f.try_sign(37, Some(INSIDE), &[]).is_err());
        }
    }

    /// The CAM AT SSP grants emergency (0x02) only: a safety-car request is refused.
    #[test]
    fn ssp_not_granted() {
        let mut f = Fixture::valid();
        assert!(f.try_sign(36, None, &[0, 0x02]).is_ok());
        assert_eq!(
            f.try_sign(36, None, &[0, 0x01]),
            Err(SigningError::NoAuthorizationTicket(36))
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// ETSI TS 103 097 clause 7.1.1, ETSI TS 103 097 clause 7.1.2:
    /// brainpoolP256r1 / P384r1 signatures produced by python-ecdsa (an
    /// independent implementation) over b"flexstack-1609.2".
    #[test]
    fn brainpool_signatures_from_python_ecdsa() {
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            EccP384CurvePoint, EcdsaP256Signature, EcdsaP384Signature,
        };
        let backend = EcdsaBackend::new();
        let msg = b"flexstack-1609.2";
        let pk = hex("020344a89044af35b4b4d49dcbe0161861c295a732726b86d5369888a46e803e83");
        let sig = hex("36e847d6d97af111a3acd434994939200356ffbde0902c0d4e4ea2c79ac9b4316f5869ab9176121909db4ba988f42a75bde36e48bde3719a35837814430b0561");
        let key = PublicVerificationKey::ecdsaBrainpoolP256r1(EccP256CurvePoint::compressed_y_0(
            pk[1..].to_vec().into(),
        ));
        let signature = Ieee1609Signature::ecdsaBrainpoolP256r1Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::x_only(sig[..32].to_vec().into()),
            s_sig: sig[32..].to_vec().into(),
        });
        assert!(backend.verify_with_pk(msg, &signature, &key));
        assert!(!backend.verify_with_pk(b"other", &signature, &key));

        let pk = hex("03442e807e24c3afdeb51dad662976233534ed153a186ae7739b379738406f11c3400e7016f241bdab88b4a29d77996f6b");
        let sig = hex("53e04860c70ced9288a1ef64bb93e87fc9cdc751f0b40f077e2a9687f192b629fd7dab26ae63c60297e7ef240c6d7a3c4a3126bc4022fca8cde51a748ed391aa1d52aa4afef8fe0d2bb3992175c48dc4b4442992feda4f557e0659f6c2d0f018");
        let key = PublicVerificationKey::ecdsaBrainpoolP384r1(EccP384CurvePoint::compressed_y_1(
            pk[1..].to_vec().into(),
        ));
        let signature = Ieee1609Signature::ecdsaBrainpoolP384r1Signature(EcdsaP384Signature {
            r_sig: EccP384CurvePoint::x_only(sig[..48].to_vec().into()),
            s_sig: sig[48..].to_vec().into(),
        });
        assert!(backend.verify_with_pk(msg, &signature, &key));
        assert!(!backend.verify_with_pk(b"other", &signature, &key));
    }

    // ── Implicit certificates (IEEE Std 1609.2-2016 clause 5.3.2) ────────

    /// IEEE 1609.2 clause 5.3.2.
    #[test]
    fn signed_cam_with_unknown_implicit_at_accepted() {
        let mut f = Fixture::implicit();
        let msg = f.sign(36);
        let dot2 = decode_ieee1609_dot2_data(&msg);
        let Ieee1609Dot2Content::signedData(sd) = &dot2.content else {
            panic!("expected signedData")
        };
        let SignerIdentifier::certificate(certs) = &sd.signer else {
            panic!("expected certificate signer")
        };
        assert!(matches!(
            certs.0[0].0.r_type,
            crate::security::security_asn::ieee1609_dot2::CertificateType::implicit
        ));
        assert_eq!(f.verify(msg).report, ReportVerify::Success);
    }

    /// The reconstructed public key is the public key of the private key d_U.
    #[test]
    fn reconstructed_key_matches_private_key() {
        let f = Fixture::implicit();
        let at = f.svc.get_present_at(36).unwrap();
        let expected = f.svc.backend.get_public_key_compressed(at.key_id, false);
        assert_eq!(at.cert.verification_key(), Some(expected));
    }

    /// IEEE 1609.2 clause 5.3.2: digest signer once the implicit AT is known.
    #[test]
    fn digest_signed_cam_with_known_implicit_at_accepted() {
        let mut f = Fixture::implicit();
        let first = f.sign(36);
        let second = f
            .svc
            .try_sign_request(&SNSignRequest {
                tbs_message: b"x".to_vec(),
                its_aid: 36,
                permissions: vec![],
                generation_location: None,
            })
            .unwrap()
            .sec_message;
        let mut lib = CertificateLibrary::new(
            &f.svc.backend,
            vec![f.root.clone()],
            vec![f.aa.clone()],
            vec![],
        );
        for msg in [first, second] {
            let report =
                verify_message(&SNVerifyRequest { message: msg }, &f.svc.backend, &mut lib)
                    .0
                    .report;
            assert_eq!(report, ReportVerify::Success);
        }
    }

    /// IEEE 1609.2 clause 5.3.2: an implicit AT carrying a signature is rejected.
    #[test]
    fn implicit_at_with_signature_rejected() {
        use crate::security::security_asn::ieee1609_dot2_base_types::EcdsaP256Signature;
        let mut f = Fixture::implicit();
        let bad = mutated(&f.sign(36), |sd| {
            if let SignerIdentifier::certificate(certs) = &mut sd.signer {
                certs.0[0].0.signature = Some(Ieee1609Signature::ecdsaNistP256Signature(
                    EcdsaP256Signature {
                        r_sig: EccP256CurvePoint::x_only(vec![1u8; 32].into()),
                        s_sig: vec![1u8; 32].into(),
                    },
                ));
            }
        });
        assert_ne!(f.verify(bad).report, ReportVerify::Success);
    }

    /// Implicit AT built as ETSI itscertgen does (ecc_recvalue / ecc_reconstruct),
    /// independently of FlexStack's issuer: H = SHA-256(SHA-256(tbs) || SHA-256(issuer)),
    /// e = H >> 1, r = e*k_eph + d_CA, d_U = e*k_req + r, P_U = (k_eph + k_req)*G.
    #[test]
    fn etsi_itscertgen_construction() {
        use crate::security::certificate::encode_tbs_certificate;
        use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
        use crate::security::security_asn::ieee1609_dot2::{
            Certificate as AsnCertificate, CertificateBase, CertificateType, IssuerIdentifier,
        };
        use crate::security::security_asn::ieee1609_dot2_base_types::{HashedId8, Uint8};
        use p256::elliptic_curve::ff::PrimeField;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, ca_tbs());
        let aa = OwnCertificate::initialize_issued(&mut backend, ca_tbs(), &root);
        let scalar = |v: u64| p256::Scalar::from(v);
        let (k_req, k_eph) = (scalar(0x1234567890ABCDEF), scalar(0xFEDCBA0987654321));
        let p_u = (p256::ProjectivePoint::GENERATOR * (k_req + k_eph)).to_affine();
        let enc = p_u.to_encoded_point(true);
        let x = enc.x().unwrap().to_vec().into();
        let rv = if enc.as_bytes()[0] == 2 {
            EccP256CurvePoint::compressed_y_0(x)
        } else {
            EccP256CurvePoint::compressed_y_1(x)
        };
        let mut tbs = at_tbs(-60, AsnDuration::hours(Uint16(1)), None);
        tbs.verify_key_indicator = VerificationKeyIndicator::reconstructionValue(rv);
        let tbs_hash = Sha256::digest(encode_tbs_certificate(&tbs));
        let issuer_hash = Sha256::digest(aa.to_canonical().encode());
        let h = Sha256::digest([tbs_hash.to_vec(), issuer_hash.to_vec()].concat());
        // e = H >> 1 (BN_rshift1)
        let mut e_bytes = [0u8; 32];
        let mut carry = 0u8;
        for (i, b) in h.iter().enumerate() {
            e_bytes[i] = (b >> 1) | carry;
            carry = b << 7;
        }
        let e = p256::Scalar::from_repr(e_bytes.into()).unwrap();
        let d_ca_bytes: [u8; 32] = backend.export_signing_key(aa.key_id).try_into().unwrap();
        let d_ca = p256::Scalar::from_repr(d_ca_bytes.into()).unwrap();
        let r = e * k_eph + d_ca;
        let d_u = e * k_req + r;
        let key_id = backend.import_signing_key(&d_u.to_repr());
        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::implicit,
            IssuerIdentifier::sha256AndDigest(HashedId8(FixedOctetString::from(aa.as_hashedid8()))),
            tbs,
            None,
        );
        let at = OwnCertificate {
            cert: Certificate::from_asn(
                EtsiTs103097Certificate(AsnCertificate(base)),
                Some(aa.cert.clone()),
            ),
            key_id,
        };
        let lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![],
        );
        let mut svc = SignService::new(backend, lib);
        svc.add_own_certificate(at);
        let mut f = Fixture {
            svc,
            root: root.cert,
            aa: aa.cert.clone(),
            aa_owner: aa,
        };
        let msg = f.sign(36);
        assert_eq!(f.verify(msg).report, ReportVerify::Success);
    }

    /// Cross-stack check: an implicit AT issued and a CAM signed by the
    /// Python stack (FlexStack `issue_implicit_certificate`, frozen vector) is
    /// accepted by the Rust stack, so both compute the same ECQV hash and key.
    #[test]
    fn implicit_chain_from_python_stack_accepted() {
        let root = Certificate::from_bytes(&hex("8003008100088104726f6f7400000000002b07b1c48600010101a081010200808082287d95660dcbdc278e1b049bd352c887d38af31920b084acb38dc64db192e4ec80809b9b6cccd6007b447e049ac5b21148daa0a7f0d40ab201335873dfa37ab4f18ce1997c1376a50fead8593d332915352bf8f8ff9ec98ac17af3931b37452e000c"), None);
        let aa = Certificate::from_bytes(&hex("80030080071385b16a71bf1e088102616100000000002b07b1c48600010101208100808083805d409ad4e781e920ac8455474c86a089adfee49426e8b1b03bcba90e9ad6438080b3ecad670ff3b781f06a3610519e568bf6b105082bb72a1b123aca9f14308151a963aa37f1582199ea8daf867aaaa9ec16cd2a4ed5ab87905bf9b55efd7d895e"), Some(root.clone()));
        let msg = hex("038100400380077061796c6f6164400124000290962c1d82d881010100030180a2786da969824bec108300000000002b07b1c486000101028001248104030202000001258183575795eeeb1284dc0e22af76a9596dd98f772821af7c23f32b0ad46beb31182880804ceef7e825c48e9f9c6db614a8895bef7d23335ae3fdaa8d1ab323a4f1640a1cabde90321aba0fcb7940a3eb541f4c30201c38bb363d4621eb4062d884074e2b");
        let backend = EcdsaBackend::new();
        let mut lib = CertificateLibrary::new(&backend, vec![root], vec![aa], vec![]);
        let confirm = verify_message(&SNVerifyRequest { message: msg }, &backend, &mut lib).0;
        assert_eq!(confirm.report, ReportVerify::Success);
        assert_eq!(confirm.permissions, vec![2u8, 0x02, 0x00]);
    }
}

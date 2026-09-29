//! Sign service — ETSI TS 103 097 message signing.
//!
//! Provides [`SignService`] which wraps [`EcdsaBackend`] and
//! [`CertificateLibrary`] to produce signed `Ieee1609Dot2Data` envelopes.
//!
//! Three message profiles are supported:
//! - CAM  (ITS-AID 36) — §7.1.1
//! - DENM (ITS-AID 37) — §7.1.2
//! - Other              — §7.1.3

use rasn::prelude::*;

use crate::security::certificate::{
    encode_ieee1609_dot2_data, encode_tbs_data, Certificate, OwnCertificate,
};
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::security_asn::ieee1609_dot2::Certificate as AsnCertificate;
use crate::security::security_asn::ieee1609_dot2::HeaderInfo;
use crate::security::security_asn::ieee1609_dot2::{
    Ieee1609Dot2Content, Ieee1609Dot2Data, SequenceOfCertificate, SignedData, SignedDataPayload,
    SignerIdentifier, ToBeSignedData,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    Elevation, HashAlgorithm, HashedId8, Latitude, Longitude, NinetyDegreeInt, OneEightyDegreeInt,
    Opaque, Psid, ThreeDLocation, Time64, Uint16, Uint64, Uint8,
};
use crate::security::sn_sap::{SNSignConfirm, SNSignRequest};
use crate::security::time_service::timestamp_its_microseconds;

// ─── CAM security handler ───────────────────────────────────────────────

/// Handles the signing and signer selection of CAMs according to ETSI TS 103 097 V2.1.1 (2021-10) §7.1.1:
/// - As default, the choice digest shall be included.
/// - The choice certificate shall be included once, one second after the last inclusion of the choice certificate.
/// - If the ITS-S receives a CAM signed by a previously unknown AT, it shall include the choice certificate immediately
///   in its next CAM, instead of including the choice digest. In this case, the timer for the next inclusion of the choice
///   certificate shall be restarted.
/// - If an ITS-S receives a CAM that includes a `tbsData.headerInfo` component of type `inlineP2pcdRequest`,
///   and finds its own AT's digest in that list, it shall include the choice certificate immediately in its next CAM.
#[derive(Clone, Debug)]
pub struct CooperativeAwarenessMessageSecurityHandler {
    pub backend: EcdsaBackend,
    pub last_signer_full_certificate_time: f64,
    pub requested_own_certificate: bool,
}

pub type CamSignerState = CooperativeAwarenessMessageSecurityHandler;

impl CooperativeAwarenessMessageSecurityHandler {
    pub fn new(backend: EcdsaBackend) -> Self {
        Self {
            backend,
            last_signer_full_certificate_time: 0.0,
            requested_own_certificate: false,
        }
    }

    /// Set up the signer choice for a CAM at the given timestamp in seconds.
    ///
    /// The whole certificate is attached if:
    /// - More than 1 second has elapsed since the last full certificate attachment, or
    /// - Own certificate was explicitly requested (e.g. peer sent unknown AT or P2PCD request).
    ///
    /// Otherwise, the digest (HashedId8) is attached.
    pub fn set_up_signer_at(
        &mut self,
        cert: &OwnCertificate,
        current_time: f64,
    ) -> SignerIdentifier {
        if current_time - self.last_signer_full_certificate_time > 1.0
            || self.requested_own_certificate
        {
            self.last_signer_full_certificate_time = current_time;
            self.requested_own_certificate = false;
            let asn_cert: AsnCertificate = cert.cert.inner.0.clone();
            SignerIdentifier::certificate(SequenceOfCertificate(vec![asn_cert]))
        } else {
            let h = cert.as_hashedid8();
            SignerIdentifier::digest(HashedId8(FixedOctetString::from(h)))
        }
    }

    /// Set up the signer choice using the current system time (`time_service::unix_time_secs()`).
    pub fn set_up_signer(&mut self, cert: &OwnCertificate) -> SignerIdentifier {
        let now = crate::security::time_service::unix_time_secs();
        self.set_up_signer_at(cert, now)
    }

    /// Compatibility alias for earlier internal `choose_signer`.
    pub fn choose_signer(&mut self, cert: &OwnCertificate) -> SignerIdentifier {
        self.set_up_signer(cert)
    }
}

// ─── SignService ─────────────────────────────────────────────────────────

/// Signing service for ETSI TS 103 097-secured messages.
pub struct SignService {
    pub backend: EcdsaBackend,
    pub cert_library: CertificateLibrary,
    pub cam_handler: CooperativeAwarenessMessageSecurityHandler,
    /// HashedId3 values of unknown ATs to include in `inlineP2pcdRequest`.
    pub unknown_ats: Vec<[u8; 3]>,
    /// HashedId3 values for which we should embed `requestedCertificate`.
    pub requested_ats: Vec<[u8; 3]>,
}

impl SignService {
    pub fn new(backend: EcdsaBackend, cert_library: CertificateLibrary) -> Self {
        let cam_handler = CooperativeAwarenessMessageSecurityHandler::new(backend.clone());
        Self {
            backend,
            cert_library,
            cam_handler,
            unknown_ats: Vec::new(),
            requested_ats: Vec::new(),
        }
    }

    /// Accessor for CAM security handler (cam_state).
    pub fn cam_state(&self) -> &CooperativeAwarenessMessageSecurityHandler {
        &self.cam_handler
    }

    /// Mutable accessor for CAM security handler (cam_state).
    pub fn cam_state_mut(&mut self) -> &mut CooperativeAwarenessMessageSecurityHandler {
        &mut self.cam_handler
    }

    /// Route to the correct profile based on ITS-AID.
    pub fn sign_request(&mut self, request: &SNSignRequest) -> SNSignConfirm {
        match request.its_aid {
            36 => self.sign_cam(request),
            37 => self.sign_denm(request),
            _ => self.sign_other(request),
        }
    }

    /// Find the own certificate that covers the given ITS-AID.
    pub fn get_present_at(&self, its_aid: u64) -> Option<&OwnCertificate> {
        self.cert_library
            .own_certificates
            .values()
            .find(|&cert| cert.get_list_of_its_aid().contains(&its_aid))
            .map(|v| v as _)
    }

    /// Parity alias for Python `get_present_at_for_signging`.
    pub fn get_present_at_for_signging(&self, its_aid: u64) -> Option<&OwnCertificate> {
        self.get_present_at(its_aid)
    }

    /// Look up a known CA certificate by its HashedId3 for inclusion in `requestedCertificate`.
    pub fn get_known_at_for_request(&self, hashedid3: &[u8; 3]) -> Result<AsnCertificate, String> {
        self.cert_library
            .get_ca_certificate_by_hashedid3(hashedid3)
            .map(|c| c.inner.0.clone())
            .ok_or_else(|| format!("No CA certificate found for HashedId3 {:02x?}", hashedid3))
    }

    // ── Helper: build the Ieee1609Dot2Data envelope ──────────────────────

    fn build_signed_data(
        &self,
        payload: &[u8],
        header_info: HeaderInfo,
        signer: SignerIdentifier,
        at: &OwnCertificate,
    ) -> Vec<u8> {
        let inner_data = Ieee1609Dot2Data::new(
            Uint8(3),
            Ieee1609Dot2Content::unsecuredData(Opaque(payload.to_vec().into())),
        );

        let tbs_data = ToBeSignedData::new(
            Box::new(SignedDataPayload {
                data: Some(inner_data),
                ext_data_hash: None,
                omitted: None,
            }),
            header_info,
        );

        let tbs_bytes = encode_tbs_data(&tbs_data);
        let signature = at.sign_message(&self.backend, &tbs_bytes);

        let signed_data = SignedData::new(HashAlgorithm::sha256, tbs_data, signer, signature);

        let outer = Ieee1609Dot2Data::new(Uint8(3), Ieee1609Dot2Content::signedData(signed_data));
        encode_ieee1609_dot2_data(&outer)
    }

    // ── §7.1.3 generic signed messages ───────────────────────────────────

    pub fn sign_other(&self, request: &SNSignRequest) -> SNSignConfirm {
        let at = self
            .get_present_at(request.its_aid)
            .expect("No AT for signing");

        let h = at.as_hashedid8();
        let signer = SignerIdentifier::digest(HashedId8(FixedOctetString::from(h)));

        let header_info = HeaderInfo::new(
            Psid(Integer::from(request.its_aid as i64)),
            Some(Time64(Uint64(timestamp_its_microseconds()))),
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

        let sec_message = self.build_signed_data(&request.tbs_message, header_info, signer, at);
        SNSignConfirm { sec_message }
    }

    // ── §7.1.2 DENM ─────────────────────────────────────────────────────

    pub fn sign_denm(&self, request: &SNSignRequest) -> SNSignConfirm {
        let at = self
            .get_present_at(request.its_aid)
            .expect("No AT for signing DENM");

        let gen_loc = request
            .generation_location
            .as_ref()
            .expect("DENM requires generation_location");

        let asn_cert: AsnCertificate = at.cert.inner.0.clone();
        let signer = SignerIdentifier::certificate(SequenceOfCertificate(vec![asn_cert]));

        let header_info = HeaderInfo::new(
            Psid(Integer::from(request.its_aid as i64)),
            Some(Time64(Uint64(timestamp_its_microseconds()))),
            None,
            Some(ThreeDLocation {
                latitude: Latitude(NinetyDegreeInt(gen_loc.latitude)),
                longitude: Longitude(OneEightyDegreeInt(gen_loc.longitude)),
                elevation: Elevation(Uint16(gen_loc.elevation)),
            }),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let sec_message = self.build_signed_data(&request.tbs_message, header_info, signer, at);
        SNSignConfirm { sec_message }
    }

    // ── §7.1.1 CAM ──────────────────────────────────────────────────────

    pub fn sign_cam(&mut self, request: &SNSignRequest) -> SNSignConfirm {
        self.sign_cam_at(request, None)
    }

    /// Sign a CAM according to ETSI TS 103 097 V2.1.1 §5.2 and §7.1.1,
    /// with an optional timestamp in seconds (for deterministic testing).
    pub fn sign_cam_at(
        &mut self,
        request: &SNSignRequest,
        timestamp_secs: Option<f64>,
    ) -> SNSignConfirm {
        let at = self
            .get_present_at(request.its_aid)
            .expect("No AT for signing CAM")
            .clone();

        let signer = match timestamp_secs {
            Some(t) => self.cam_handler.set_up_signer_at(&at, t),
            None => self.cam_handler.set_up_signer(&at),
        };

        // Build P2PCD inline request if needed
        let inline_p2pcd = if !self.unknown_ats.is_empty() {
            let hashes: Vec<_> = self
                .unknown_ats
                .drain(..)
                .map(|h3| {
                    crate::security::security_asn::ieee1609_dot2_base_types::HashedId3(
                        FixedOctetString::from(h3),
                    )
                })
                .collect();
            Some(
                crate::security::security_asn::ieee1609_dot2_base_types::SequenceOfHashedId3(
                    hashes,
                ),
            )
        } else {
            None
        };

        // Embed requestedCertificate if pending
        let requested_cert = if !self.requested_ats.is_empty() {
            let h3 = self.requested_ats.remove(0);
            self.get_known_at_for_request(&h3).ok()
        } else {
            None
        };

        let header_info = HeaderInfo::new(
            Psid(Integer::from(request.its_aid as i64)),
            Some(Time64(Uint64(timestamp_its_microseconds()))),
            None,
            None,
            None,
            None,
            None,
            inline_p2pcd,
            requested_cert,
            None,
            None,
        );

        let sec_message = self.build_signed_data(&request.tbs_message, header_info, signer, &at);
        SNSignConfirm { sec_message }
    }

    // ── P2PCD notification helpers ───────────────────────────────────────

    /// Record an unknown AT HashedId3 and force own cert inclusion in next CAM.
    pub fn notify_unknown_at(&mut self, hashedid8: &[u8; 8]) {
        let h3 = [hashedid8[5], hashedid8[6], hashedid8[7]];
        if !self.unknown_ats.contains(&h3) {
            self.unknown_ats.push(h3);
        }
        self.cam_handler.requested_own_certificate = true;
    }

    /// Process a received `inlineP2pcdRequest`.
    pub fn notify_inline_p2pcd_request(&mut self, request_list: &[[u8; 3]]) {
        for own in self.cert_library.own_certificates.values() {
            let own_h3 = {
                let h8 = own.as_hashedid8();
                [h8[5], h8[6], h8[7]]
            };
            if request_list.contains(&own_h3) {
                self.cam_handler.requested_own_certificate = true;
            }
        }
        for h3 in request_list {
            if self
                .cert_library
                .get_ca_certificate_by_hashedid3(h3)
                .is_some()
                && !self.requested_ats.contains(h3)
            {
                self.requested_ats.push(*h3);
            }
        }
    }

    /// Process a received CA certificate from `requestedCertificate`.
    pub fn notify_received_ca_certificate(&mut self, cert: Certificate) {
        let h3 = cert.as_hashedid3();
        self.requested_ats.retain(|x| *x != h3);
        self.unknown_ats.retain(|x| *x != h3);
        self.cert_library
            .add_authorization_authority(&self.backend, cert);
    }

    /// Add an own certificate.
    pub fn add_own_certificate(&mut self, cert: OwnCertificate) {
        self.cert_library.add_own_certificate(&self.backend, cert);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::certificate::{decode_ieee1609_dot2_data, OwnCertificate};
    use crate::security::certificate_library::CertificateLibrary;
    use crate::security::ecdsa_backend::EcdsaBackend;
    use crate::security::security_asn::ieee1609_dot2::{
        CertificateId, EndEntityType, Ieee1609Dot2Content, PsidGroupPermissions,
        SequenceOfPsidGroupPermissions, SubjectPermissions, ToBeSignedCertificate,
        VerificationKeyIndicator,
    };
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        CrlSeries, Duration as AsnDuration, EccP256CurvePoint, HashedId3, Psid, PsidSsp,
        PublicVerificationKey, SequenceOfPsidSsp, Time32, Uint16, Uint32, ValidityPeriod,
    };
    use crate::security::sn_sap::{GenerationLocation, SNSignRequest};

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
        let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(1)));
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

    fn make_sign_service() -> SignService {
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
        svc
    }

    #[test]
    fn sign_cam_produces_nonempty_message() {
        let mut svc = make_sign_service();
        let req = SNSignRequest {
            tbs_message: vec![0xCA, 0xFE],
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        };
        let confirm = svc.sign_request(&req);
        assert!(!confirm.sec_message.is_empty());
    }

    #[test]
    fn sign_denm_produces_nonempty_message() {
        let mut svc = make_sign_service();
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
        let confirm = svc.sign_request(&req);
        assert!(!confirm.sec_message.is_empty());
    }

    #[test]
    fn sign_other_aid_produces_nonempty_message() {
        // Add a cert for a custom AID
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let aa = OwnCertificate::initialize_issued(&mut backend, make_root_tbs(), &root);
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(99), &aa);
        let lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![],
        );
        let mut svc = SignService::new(backend, lib);
        svc.add_own_certificate(at);

        let req = SNSignRequest {
            tbs_message: vec![0x01, 0x02],
            its_aid: 99,
            permissions: vec![],
            generation_location: None,
        };
        let confirm = svc.sign_request(&req);
        assert!(!confirm.sec_message.is_empty());
    }

    #[test]
    fn sign_cam_first_call_includes_certificate() {
        let mut svc = make_sign_service();
        let req = SNSignRequest {
            tbs_message: vec![0xCA],
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        };
        // First CAM should include full certificate (signer = certificate)
        let confirm1 = svc.sign_request(&req);
        assert!(!confirm1.sec_message.is_empty());
    }

    #[test]
    fn sign_cam_first_call_includes_full_certificate_decoded() {
        let mut svc = make_sign_service();
        let req = SNSignRequest {
            tbs_message: vec![0xCA, 0x01],
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        };
        let confirm1 = svc.sign_cam(&req);
        let dot2 = decode_ieee1609_dot2_data(&confirm1.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2.content {
            match sd.signer {
                SignerIdentifier::certificate(certs) => {
                    assert_eq!(certs.0.len(), 1, "Exactly one certificate attached");
                }
                _ => panic!("Expected SignerIdentifier::certificate on first call"),
            }
        } else {
            panic!("Expected signedData");
        }
    }

    #[test]
    fn sign_cam_second_call_within_one_second_includes_digest_decoded() {
        let mut svc = make_sign_service();
        let req = SNSignRequest {
            tbs_message: vec![0xCA, 0x02],
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        };
        // 1st call -> certificate
        let _confirm1 = svc.sign_cam(&req);

        // 2nd call immediately -> digest
        let confirm2 = svc.sign_cam(&req);
        let dot2 = decode_ieee1609_dot2_data(&confirm2.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2.content {
            match sd.signer {
                SignerIdentifier::digest(h8) => {
                    let at = svc.get_present_at(36).unwrap();
                    assert_eq!(h8.0.as_ref(), &at.as_hashedid8());
                }
                _ => panic!("Expected SignerIdentifier::digest on second call within 1 second"),
            }
        } else {
            panic!("Expected signedData");
        }
    }

    #[test]
    fn sign_cam_after_one_second_includes_full_certificate_again() {
        let mut svc = make_sign_service();
        let req = SNSignRequest {
            tbs_message: vec![0xCA, 0x03],
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        };

        // Call 1 at t = 100.0s -> full certificate
        let confirm1 = svc.sign_cam_at(&req, Some(100.0));
        let dot2_1 = decode_ieee1609_dot2_data(&confirm1.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2_1.content {
            assert!(
                matches!(sd.signer, SignerIdentifier::certificate(_)),
                "1st call must be certificate"
            );
        }

        // Call 2 at t = 100.5s (0.5s later) -> digest
        let confirm2 = svc.sign_cam_at(&req, Some(100.5));
        let dot2_2 = decode_ieee1609_dot2_data(&confirm2.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2_2.content {
            assert!(
                matches!(sd.signer, SignerIdentifier::digest(_)),
                "Call within 1s must be digest"
            );
        }

        // Call 3 at t = 101.0s (exactly 1.0s later) -> digest (not strictly > 1.0s)
        let confirm3 = svc.sign_cam_at(&req, Some(101.0));
        let dot2_3 = decode_ieee1609_dot2_data(&confirm3.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2_3.content {
            assert!(
                matches!(sd.signer, SignerIdentifier::digest(_)),
                "Call at exactly 1.0s is digest"
            );
        }

        // Call 4 at t = 101.05s (> 1.0s later) -> full certificate attached again!
        let confirm4 = svc.sign_cam_at(&req, Some(101.05));
        let dot2_4 = decode_ieee1609_dot2_data(&confirm4.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2_4.content {
            match sd.signer {
                SignerIdentifier::certificate(certs) => {
                    assert_eq!(certs.0.len(), 1);
                }
                _ => panic!("Call > 1s later must attach full certificate again"),
            }
        }
        assert_eq!(svc.cam_handler.last_signer_full_certificate_time, 101.05);
    }

    #[test]
    fn sign_cam_requested_own_certificate_forces_immediate_certificate() {
        let mut svc = make_sign_service();
        let req = SNSignRequest {
            tbs_message: vec![0xCA, 0x04],
            its_aid: 36,
            permissions: vec![],
            generation_location: None,
        };

        // Call 1 at t = 100.0s -> certificate
        let _confirm1 = svc.sign_cam_at(&req, Some(100.0));

        // Unknown peer AT seen at t = 100.2s -> triggers requested_own_certificate
        svc.notify_unknown_at(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(svc.cam_handler.requested_own_certificate);

        // Call 2 at t = 100.2s (only 0.2s elapsed) -> MUST include full certificate!
        let confirm2 = svc.sign_cam_at(&req, Some(100.2));
        let dot2_2 = decode_ieee1609_dot2_data(&confirm2.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2_2.content {
            assert!(
                matches!(sd.signer, SignerIdentifier::certificate(_)),
                "Forced certificate must include certificate even within 1 second"
            );
        }
        assert!(!svc.cam_handler.requested_own_certificate);
        assert_eq!(svc.cam_handler.last_signer_full_certificate_time, 100.2);
    }

    #[test]
    fn cam_handler_set_up_signer_at() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let aa = OwnCertificate::initialize_issued(&mut backend, make_root_tbs(), &root);
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(36), &aa);

        let mut handler = CooperativeAwarenessMessageSecurityHandler::new(backend);
        assert_eq!(handler.last_signer_full_certificate_time, 0.0);
        assert!(!handler.requested_own_certificate);

        // First call at 100.0 -> certificate
        let signer1 = handler.set_up_signer_at(&at, 100.0);
        assert!(matches!(signer1, SignerIdentifier::certificate(_)));
        assert_eq!(handler.last_signer_full_certificate_time, 100.0);

        // Second call at 101.0 -> digest (101.0 - 100.0 == 1.0, not > 1.0)
        let signer2 = handler.set_up_signer_at(&at, 101.0);
        assert!(matches!(signer2, SignerIdentifier::digest(_)));
        assert_eq!(handler.last_signer_full_certificate_time, 100.0);

        // Third call with requested_own_certificate = true -> certificate
        handler.requested_own_certificate = true;
        let signer3 = handler.set_up_signer_at(&at, 101.0);
        assert!(matches!(signer3, SignerIdentifier::certificate(_)));
        assert!(!handler.requested_own_certificate);
        assert_eq!(handler.last_signer_full_certificate_time, 101.0);

        // Fourth call at 102.5 -> certificate (> 1.0s elapsed)
        let signer4 = handler.set_up_signer_at(&at, 102.5);
        assert!(matches!(signer4, SignerIdentifier::certificate(_)));
        assert_eq!(handler.last_signer_full_certificate_time, 102.5);
    }

    #[test]
    fn sign_denm_always_uses_certificate() {
        let svc = make_sign_service();
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
        let confirm = svc.sign_denm(&req);
        let dot2 = decode_ieee1609_dot2_data(&confirm.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2.content {
            assert!(matches!(sd.signer, SignerIdentifier::certificate(_)));
        } else {
            panic!("Expected signedData");
        }
    }

    #[test]
    fn sign_other_always_uses_digest() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let aa = OwnCertificate::initialize_issued(&mut backend, make_root_tbs(), &root);
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(139), &aa);
        let lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![],
        );
        let mut svc = SignService::new(backend, lib);
        svc.add_own_certificate(at);

        let req = SNSignRequest {
            tbs_message: vec![0x11, 0x22],
            its_aid: 139,
            permissions: vec![],
            generation_location: None,
        };
        let confirm = svc.sign_other(&req);
        let dot2 = decode_ieee1609_dot2_data(&confirm.sec_message);
        if let Ieee1609Dot2Content::signedData(sd) = dot2.content {
            assert!(matches!(sd.signer, SignerIdentifier::digest(_)));
        } else {
            panic!("Expected signedData");
        }
    }

    #[test]
    fn notify_unknown_at() {
        let mut svc = make_sign_service();
        let h8 = [1, 2, 3, 4, 5, 6, 7, 8];
        svc.notify_unknown_at(&h8);
        assert_eq!(svc.unknown_ats.len(), 1);
        assert_eq!(svc.unknown_ats[0], [6, 7, 8]); // last 3 bytes
        assert!(svc.cam_handler.requested_own_certificate);
    }

    #[test]
    fn notify_unknown_at_no_duplicates() {
        let mut svc = make_sign_service();
        let h8 = [1, 2, 3, 4, 5, 6, 7, 8];
        svc.notify_unknown_at(&h8);
        svc.notify_unknown_at(&h8);
        assert_eq!(svc.unknown_ats.len(), 1);
    }

    #[test]
    fn notify_inline_p2pcd_request_match_own() {
        let mut svc = make_sign_service();
        let own_at = svc.get_present_at(36).unwrap();
        let own_h8 = own_at.as_hashedid8();
        let own_h3 = [own_h8[5], own_h8[6], own_h8[7]];

        svc.notify_inline_p2pcd_request(&[own_h3]);
        assert!(svc.cam_handler.requested_own_certificate);
    }

    #[test]
    fn notify_inline_p2pcd_request_ca_match() {
        let mut svc = make_sign_service();
        let aa = svc
            .cert_library
            .known_authorization_authorities
            .values()
            .next()
            .unwrap()
            .clone();
        let aa_h3 = aa.as_hashedid3();

        svc.notify_inline_p2pcd_request(&[aa_h3]);
        assert_eq!(svc.requested_ats, vec![aa_h3]);
    }

    #[test]
    fn notify_inline_p2pcd_request_no_match() {
        let mut svc = make_sign_service();
        svc.notify_inline_p2pcd_request(&[[0x99, 0x88, 0x77]]);
        assert!(!svc.cam_handler.requested_own_certificate);
        assert!(svc.requested_ats.is_empty());
    }

    #[test]
    fn notify_received_ca_certificate() {
        let mut svc = make_sign_service();
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let aa = OwnCertificate::initialize_issued(&mut backend, make_root_tbs(), &root);
        let aa_h3 = aa.cert.as_hashedid3();

        svc.requested_ats.push(aa_h3);
        svc.unknown_ats.push(aa_h3);

        svc.notify_received_ca_certificate(aa.cert.clone());
        assert!(svc.requested_ats.is_empty());
        assert!(svc.unknown_ats.is_empty());
    }

    #[test]
    fn get_known_at_for_request() {
        let svc = make_sign_service();
        let aa = svc
            .cert_library
            .known_authorization_authorities
            .values()
            .next()
            .unwrap();
        let aa_h3 = aa.as_hashedid3();

        let cert = svc.get_known_at_for_request(&aa_h3);
        assert!(cert.is_ok());

        let not_found = svc.get_known_at_for_request(&[0xFF, 0xEE, 0xDD]);
        assert!(not_found.is_err());
    }

    #[test]
    fn get_present_at_for_signging() {
        let svc = make_sign_service();
        let at_cam = svc.get_present_at_for_signging(36);
        assert!(at_cam.is_some());
        assert_eq!(at_cam.unwrap().get_list_of_its_aid(), vec![36]);

        let at_none = svc.get_present_at_for_signging(9999);
        assert!(at_none.is_none());
    }
}

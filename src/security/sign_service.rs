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

// ─── CAM signer state ────────────────────────────────────────────────────

/// Manages the CAM-specific signer selection rule (§7.1.1):
/// certificate is included once per second, otherwise digest.
struct CamSignerState {
    last_full_cert_time: f64,
    requested_own_certificate: bool,
}

impl CamSignerState {
    fn new() -> Self {
        Self {
            last_full_cert_time: 0.0,
            requested_own_certificate: false,
        }
    }

    fn choose_signer(&mut self, cert: &OwnCertificate) -> SignerIdentifier {
        let now = crate::security::time_service::unix_time_secs();
        if now - self.last_full_cert_time > 1.0 || self.requested_own_certificate {
            self.last_full_cert_time = now;
            self.requested_own_certificate = false;
            let asn_cert: AsnCertificate = cert.cert.inner.0.clone();
            SignerIdentifier::certificate(SequenceOfCertificate(vec![asn_cert]))
        } else {
            let h = cert.as_hashedid8();
            SignerIdentifier::digest(HashedId8(FixedOctetString::from(h)))
        }
    }
}

// ─── SignService ─────────────────────────────────────────────────────────

/// Signing service for ETSI TS 103 097-secured messages.
pub struct SignService {
    pub backend: EcdsaBackend,
    pub cert_library: CertificateLibrary,
    cam_state: CamSignerState,
    /// HashedId3 values of unknown ATs to include in `inlineP2pcdRequest`.
    pub unknown_ats: Vec<[u8; 3]>,
    /// HashedId3 values for which we should embed `requestedCertificate`.
    pub requested_ats: Vec<[u8; 3]>,
}

impl SignService {
    pub fn new(backend: EcdsaBackend, cert_library: CertificateLibrary) -> Self {
        Self {
            backend,
            cert_library,
            cam_state: CamSignerState::new(),
            unknown_ats: Vec::new(),
            requested_ats: Vec::new(),
        }
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
    fn get_present_at(&self, its_aid: u64) -> Option<&OwnCertificate> {
        self.cert_library
            .own_certificates
            .values()
            .find(|&cert| cert.get_list_of_its_aid().contains(&its_aid))
            .map(|v| v as _)
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

    fn sign_other(&self, request: &SNSignRequest) -> SNSignConfirm {
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

    fn sign_denm(&self, request: &SNSignRequest) -> SNSignConfirm {
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

    fn sign_cam(&mut self, request: &SNSignRequest) -> SNSignConfirm {
        let at = self
            .get_present_at(request.its_aid)
            .expect("No AT for signing CAM")
            .clone();

        let signer = self.cam_state.choose_signer(&at);

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
            self.cert_library
                .get_ca_certificate_by_hashedid3(&h3)
                .map(|c| c.inner.0.clone())
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
        self.cam_state.requested_own_certificate = true;
    }

    /// Process a received `inlineP2pcdRequest`.
    pub fn notify_inline_p2pcd_request(&mut self, request_list: &[[u8; 3]]) {
        for own in self.cert_library.own_certificates.values() {
            let own_h3 = {
                let h8 = own.as_hashedid8();
                [h8[5], h8[6], h8[7]]
            };
            if request_list.contains(&own_h3) {
                self.cam_state.requested_own_certificate = true;
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
        CrlSeries, Duration as AsnDuration, EccP256CurvePoint, HashedId3, PublicVerificationKey,
        Time32, Uint16, Uint32, ValidityPeriod,
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
            SequenceOfAppExtensions(vec![]),
            SequenceOfCertIssueExtensions(vec![]),
            SequenceOfCertRequestExtensions(vec![]),
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
            SequenceOfAppExtensions(vec![]),
            SequenceOfCertIssueExtensions(vec![]),
            SequenceOfCertRequestExtensions(vec![]),
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
    fn notify_unknown_at() {
        let mut svc = make_sign_service();
        let h8 = [1, 2, 3, 4, 5, 6, 7, 8];
        svc.notify_unknown_at(&h8);
        assert_eq!(svc.unknown_ats.len(), 1);
        assert_eq!(svc.unknown_ats[0], [6, 7, 8]); // last 3 bytes
    }

    #[test]
    fn notify_unknown_at_no_duplicates() {
        let mut svc = make_sign_service();
        let h8 = [1, 2, 3, 4, 5, 6, 7, 8];
        svc.notify_unknown_at(&h8);
        svc.notify_unknown_at(&h8);
        assert_eq!(svc.unknown_ats.len(), 1);
    }
}

//! Certificate handling — ETSI TS 103 097 V2.1.1 profiles.
//!
//! Provides [`Certificate`] (read-only wrapper) and [`OwnCertificate`]
//! (includes the private-key identifier for signing).

use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::security_asn::ieee1609_dot2::Certificate as AsnCertificate;
use crate::security::security_asn::ieee1609_dot2::{
    CertificateBase, CertificateType, Ieee1609Dot2Data, IssuerIdentifier, ToBeSignedCertificate,
    ToBeSignedData,
};
use crate::security::security_asn::ieee1609_dot2::{SubjectPermissions, VerificationKeyIndicator};
use crate::security::security_asn::ieee1609_dot2_base_types::Signature as Ieee1609Signature;
use crate::security::security_asn::ieee1609_dot2_base_types::{
    EccP256CurvePoint, EcdsaP256Signature, HashAlgorithm, HashedId8, PublicVerificationKey, Uint8,
};

// ─── COER encode / decode helpers ────────────────────────────────────────

/// COER-encode an `EtsiTs103097Certificate`.
pub fn encode_certificate(cert: &EtsiTs103097Certificate) -> Vec<u8> {
    rasn::coer::encode(cert).expect("certificate COER encode failed")
}

/// COER-decode an `EtsiTs103097Certificate`.
pub fn decode_certificate(bytes: &[u8]) -> EtsiTs103097Certificate {
    rasn::coer::decode::<EtsiTs103097Certificate>(bytes).expect("certificate COER decode failed")
}

/// COER-encode `Ieee1609Dot2Data` (signed message envelope).
pub fn encode_ieee1609_dot2_data(data: &Ieee1609Dot2Data) -> Vec<u8> {
    rasn::coer::encode(data).expect("Ieee1609Dot2Data COER encode failed")
}

/// COER-decode `Ieee1609Dot2Data`.
pub fn decode_ieee1609_dot2_data(bytes: &[u8]) -> Ieee1609Dot2Data {
    rasn::coer::decode::<Ieee1609Dot2Data>(bytes).expect("Ieee1609Dot2Data COER decode failed")
}

/// COER-encode `ToBeSignedData` (the data that is actually signed).
pub fn encode_tbs_data(tbs: &ToBeSignedData) -> Vec<u8> {
    rasn::coer::encode(tbs).expect("ToBeSignedData COER encode failed")
}

/// COER-encode `ToBeSignedCertificate`.
pub fn encode_tbs_certificate(tbs: &ToBeSignedCertificate) -> Vec<u8> {
    rasn::coer::encode(tbs).expect("ToBeSignedCertificate COER encode failed")
}

// ─── HashedId8 / HashedId3 helpers ───────────────────────────────────────

/// Compute the HashedId8 of a COER-encoded certificate.
pub fn compute_hashedid8(cert_bytes: &[u8]) -> [u8; 8] {
    EcdsaBackend::hash_to_hashedid8(cert_bytes)
}

// ─── Certificate (read-only) ─────────────────────────────────────────────

/// Immutable certificate wrapper.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The inner ASN.1 certificate.
    pub inner: EtsiTs103097Certificate,
    /// Cached COER encoding (for hashing).
    encoded: Vec<u8>,
    /// Optional issuer certificate (for chain verification).
    pub issuer: Option<Box<Certificate>>,
}

impl Certificate {
    /// Build from a decoded ASN.1 certificate.
    pub fn from_asn(asn: EtsiTs103097Certificate, issuer: Option<Certificate>) -> Self {
        let encoded = encode_certificate(&asn);
        Self {
            inner: asn,
            encoded,
            issuer: issuer.map(Box::new),
        }
    }

    /// Decode from COER bytes.
    pub fn from_bytes(bytes: &[u8], issuer: Option<Certificate>) -> Self {
        let asn = decode_certificate(bytes);
        let encoded = bytes.to_vec();
        Self {
            inner: asn,
            encoded,
            issuer: issuer.map(Box::new),
        }
    }

    /// Access the inner `CertificateBase`.
    pub fn base(&self) -> &CertificateBase {
        &(self.inner.0).0
    }

    /// Access `toBeSigned`.
    pub fn tbs(&self) -> &ToBeSignedCertificate {
        &self.base().to_be_signed
    }

    /// Return the COER encoding.
    pub fn encode(&self) -> &[u8] {
        &self.encoded
    }

    /// Compute the SHA-256 HashedId8 of the certificate.
    pub fn as_hashedid8(&self) -> [u8; 8] {
        compute_hashedid8(&self.encoded)
    }

    /// Compute the last 3 bytes of HashedId8.
    pub fn as_hashedid3(&self) -> [u8; 3] {
        let h8 = self.as_hashedid8();
        [h8[5], h8[6], h8[7]]
    }

    /// Return the list of ITS-AID (PSID) values from `appPermissions`.
    pub fn get_list_of_its_aid(&self) -> Vec<u64> {
        let mut aids = Vec::new();
        if let Some(ref perms) = self.tbs().app_permissions {
            for psid_ssp in perms.0.iter() {
                // Psid wraps an Integer — convert via i128 then u64.
                let val = u64::try_from(&psid_ssp.psid.0).unwrap_or(0);
                aids.push(val);
            }
        }
        aids
    }

    /// Get issuer HashedId8 stored inside the certificate.
    /// Returns `None` if self-signed.
    pub fn get_issuer_hashedid8(&self) -> Option<[u8; 8]> {
        match &self.base().issuer {
            IssuerIdentifier::sha256AndDigest(h) => {
                let mut out = [0u8; 8];
                out.copy_from_slice(h.0.as_ref());
                Some(out)
            }
            IssuerIdentifier::R_self(_) => None,
            IssuerIdentifier::sha384AndDigest(h) => {
                let mut out = [0u8; 8];
                out.copy_from_slice(h.0.as_ref());
                Some(out)
            }
            _ => None,
        }
    }

    /// Check whether the signature uses NIST P-256.
    pub fn signature_is_nist_p256(&self) -> bool {
        matches!(
            self.base().signature,
            Some(Ieee1609Signature::ecdsaNistP256Signature(_))
        )
    }

    /// Check whether the verification key is NIST P-256.
    pub fn verification_key_is_nist_p256(&self) -> bool {
        matches!(
            &self.tbs().verify_key_indicator,
            VerificationKeyIndicator::verificationKey(PublicVerificationKey::ecdsaNistP256(_))
        )
    }

    /// Is the certificate self-signed?
    pub fn is_self_signed(&self) -> bool {
        matches!(
            &self.base().issuer,
            IssuerIdentifier::R_self(HashAlgorithm::sha256)
        )
    }

    /// Is the certificate issued (not self-signed)?
    pub fn is_issued(&self) -> bool {
        matches!(
            &self.base().issuer,
            IssuerIdentifier::sha256AndDigest(_) | IssuerIdentifier::sha384AndDigest(_)
        )
    }

    /// Check whether the issuer's HashedId8 matches the given issuer certificate.
    pub fn check_corresponding_issuer(&self, issuer: &Certificate) -> bool {
        match self.get_issuer_hashedid8() {
            Some(h) => h == issuer.as_hashedid8(),
            None => false,
        }
    }

    /// Does `certIssuePermissions` have a subjectPermissions of `all`?
    pub fn has_all_permissions(&self) -> bool {
        if let Some(ref cip) = self.tbs().cert_issue_permissions {
            for perm in cip.0.iter() {
                if matches!(perm.subject_permissions, SubjectPermissions::all(_)) {
                    return true;
                }
            }
        }
        false
    }

    /// Get the PSID list from `certIssuePermissions.subjectPermissions.explicit`.
    pub fn get_allowed_permissions(&self) -> Vec<u64> {
        let mut out = Vec::new();
        if let Some(ref cip) = self.tbs().cert_issue_permissions {
            for perm in cip.0.iter() {
                if let SubjectPermissions::explicit(ref ranges) = perm.subject_permissions {
                    for r in ranges.0.iter() {
                        let val = u64::try_from(&r.psid.0).unwrap_or(0);
                        out.push(val);
                    }
                }
            }
        }
        out
    }

    /// Check whether the issuer has the right permissions to issue this cert.
    pub fn check_issuer_has_subject_permissions(&self, issuer: &Certificate) -> bool {
        if issuer.has_all_permissions() {
            return true;
        }
        let needed = self.get_list_of_its_aid();
        let allowed = issuer.get_allowed_permissions();
        needed.iter().all(|n| allowed.contains(n))
    }

    /// Verify the certificate signature.
    pub fn verify_signature_with(
        backend: &EcdsaBackend,
        tbs: &ToBeSignedCertificate,
        signature: &Ieee1609Signature,
        verification_key: &PublicVerificationKey,
    ) -> bool {
        let tbs_bytes = encode_tbs_certificate(tbs);
        backend.verify_with_pk(&tbs_bytes, signature, verification_key)
    }

    /// Verify an issued certificate (chain to issuer).
    fn verify_issued(&self, backend: &EcdsaBackend) -> bool {
        let issuer = match &self.issuer {
            Some(i) => i,
            None => return false,
        };
        if !self.is_issued() {
            return false;
        }
        if !self.check_corresponding_issuer(issuer) {
            return false;
        }
        if !self.check_issuer_has_subject_permissions(issuer) {
            return false;
        }
        if !self.signature_is_nist_p256() || !self.verification_key_is_nist_p256() {
            return false;
        }
        let sig = match &self.base().signature {
            Some(s) => s,
            None => return false,
        };
        let issuer_vk = match &issuer.tbs().verify_key_indicator {
            VerificationKeyIndicator::verificationKey(pk) => pk,
            _ => return false,
        };
        Certificate::verify_signature_with(backend, self.tbs(), sig, issuer_vk)
    }

    /// Verify a self-signed certificate.
    fn verify_self_signed(&self, backend: &EcdsaBackend) -> bool {
        if !self.is_self_signed() {
            return false;
        }
        if !self.signature_is_nist_p256() || !self.verification_key_is_nist_p256() {
            return false;
        }
        let sig = match &self.base().signature {
            Some(s) => s,
            None => return false,
        };
        let pk = match &self.tbs().verify_key_indicator {
            VerificationKeyIndicator::verificationKey(vk) => vk,
            _ => return false,
        };
        Certificate::verify_signature_with(backend, self.tbs(), sig, pk)
    }

    /// Full certificate verification (self-signed or chained).
    pub fn verify(&self, backend: &EcdsaBackend) -> bool {
        // §6: verifyKeyIndicator must match certificate type
        match self.base().r_type {
            CertificateType::explicit => {
                if !matches!(
                    self.tbs().verify_key_indicator,
                    VerificationKeyIndicator::verificationKey(_)
                ) {
                    return false;
                }
            }
            CertificateType::implicit => {
                if !matches!(
                    self.tbs().verify_key_indicator,
                    VerificationKeyIndicator::reconstructionValue(_)
                ) {
                    return false;
                }
            }
        }
        if self.issuer.is_some() && self.is_issued() {
            return self.verify_issued(backend);
        }
        if self.is_self_signed() {
            return self.verify_self_signed(backend);
        }
        false
    }

    // ── Profile checks (§7.2) ────────────────────────────────────────────

    /// §7.2.1 Authorization Ticket profile.
    pub fn is_authorization_ticket(&self) -> bool {
        if !self.is_issued() {
            return false;
        }
        let tbs = self.tbs();
        if !matches!(
            tbs.id,
            crate::security::security_asn::ieee1609_dot2::CertificateId::none(_)
        ) {
            return false;
        }
        if tbs.cert_issue_permissions.is_some() {
            return false;
        }
        tbs.app_permissions.is_some()
    }

    /// §7.2.3 Root CA profile.
    pub fn is_root_ca(&self) -> bool {
        if !matches!(self.base().r_type, CertificateType::explicit) {
            return false;
        }
        if !self.is_self_signed() {
            return false;
        }
        let tbs = self.tbs();
        tbs.cert_issue_permissions.is_some() && tbs.app_permissions.is_some()
    }
}

// ─── OwnCertificate ─────────────────────────────────────────────────────

/// A certificate for which we hold the private key.
#[derive(Debug, Clone)]
pub struct OwnCertificate {
    pub cert: Certificate,
    pub key_id: usize,
}

impl OwnCertificate {
    /// Wrap an existing `Certificate` together with its key id.
    pub fn new(cert: Certificate, key_id: usize) -> Self {
        Self { cert, key_id }
    }

    /// Convenience delegations.
    pub fn as_hashedid8(&self) -> [u8; 8] {
        self.cert.as_hashedid8()
    }

    pub fn get_list_of_its_aid(&self) -> Vec<u64> {
        self.cert.get_list_of_its_aid()
    }

    pub fn tbs(&self) -> &ToBeSignedCertificate {
        self.cert.tbs()
    }

    pub fn base(&self) -> &CertificateBase {
        self.cert.base()
    }

    pub fn verify(&self, backend: &EcdsaBackend) -> bool {
        self.cert.verify(backend)
    }

    /// Sign arbitrary data with this certificate's key.
    pub fn sign_message(&self, backend: &EcdsaBackend, data: &[u8]) -> Ieee1609Signature {
        backend.sign(data, self.key_id)
    }

    /// Sign (or re-sign) `target`'s `toBeSigned` and return a new `Certificate`
    /// with the updated signature.
    pub fn sign_certificate(&self, backend: &EcdsaBackend, target: &Certificate) -> Certificate {
        let tbs_bytes = encode_tbs_certificate(target.tbs());
        let sig = backend.sign(&tbs_bytes, self.key_id);

        let mut new_base = target.base().clone();
        new_base.signature = Some(sig);

        let new_asn = EtsiTs103097Certificate(AsnCertificate(new_base));
        Certificate::from_asn(new_asn, Some(self.cert.clone()))
    }

    /// Build the inner `AsnCertificate` from the wrapper's certificate dict,
    /// setting the issuer to `self`, signing, and returning the result.
    pub fn issue_certificate(&self, backend: &EcdsaBackend, target: &Certificate) -> Certificate {
        // Set issuer to our HashedId8
        let mut new_base = target.base().clone();
        let h8 = self.as_hashedid8();
        new_base.issuer =
            IssuerIdentifier::sha256AndDigest(HashedId8(rasn::types::FixedOctetString::from(h8)));

        // Sign
        let tbs_bytes = encode_tbs_certificate(&new_base.to_be_signed);
        let sig = backend.sign(&tbs_bytes, self.key_id);
        new_base.signature = Some(sig);

        let new_asn = EtsiTs103097Certificate(AsnCertificate(new_base));
        Certificate::from_asn(new_asn, Some(self.cert.clone()))
    }

    /// Create a brand-new self-signed certificate.
    pub fn initialize_self_signed(backend: &mut EcdsaBackend, tbs: ToBeSignedCertificate) -> Self {
        let key_id = backend.create_key();
        let pk = backend.get_public_key(key_id);

        let mut tbs_owned = tbs;
        tbs_owned.verify_key_indicator = VerificationKeyIndicator::verificationKey(pk);

        // Placeholder signature — will be replaced below.
        let placeholder_sig = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::x_only(vec![0u8; 32].into()),
            s_sig: vec![0u8; 32].into(),
        });

        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            IssuerIdentifier::R_self(HashAlgorithm::sha256),
            tbs_owned,
            Some(placeholder_sig),
        );

        // Sign the toBeSigned
        let tbs_bytes = encode_tbs_certificate(&base.to_be_signed);
        let sig = backend.sign(&tbs_bytes, key_id);

        let mut final_base = base;
        final_base.signature = Some(sig);

        let asn = EtsiTs103097Certificate(AsnCertificate(final_base));
        let cert = Certificate::from_asn(asn, None);
        OwnCertificate { cert, key_id }
    }

    /// Create a new certificate issued by `issuer`.
    pub fn initialize_issued(
        backend: &mut EcdsaBackend,
        tbs: ToBeSignedCertificate,
        issuer: &OwnCertificate,
    ) -> Self {
        let key_id = backend.create_key();
        let pk = backend.get_public_key(key_id);

        let mut tbs_owned = tbs;
        tbs_owned.verify_key_indicator = VerificationKeyIndicator::verificationKey(pk);

        let h8 = issuer.as_hashedid8();
        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            IssuerIdentifier::sha256AndDigest(HashedId8(rasn::types::FixedOctetString::from(h8))),
            tbs_owned,
            None, // will be filled by sign
        );

        let tbs_bytes = encode_tbs_certificate(&base.to_be_signed);
        let sig = backend.sign(&tbs_bytes, issuer.key_id);

        let mut final_base = base;
        final_base.signature = Some(sig);

        let asn = EtsiTs103097Certificate(AsnCertificate(final_base));
        let cert = Certificate::from_asn(asn, Some(issuer.cert.clone()));
        OwnCertificate { cert, key_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::ecdsa_backend::EcdsaBackend;
    use rasn::prelude::*;

    fn make_root_tbs() -> ToBeSignedCertificate {
        use crate::security::security_asn::ieee1609_dot2::{
            CertificateId, EndEntityType, PsidGroupPermissions, SequenceOfAppExtensions,
            SequenceOfCertIssueExtensions, SequenceOfCertRequestExtensions,
            SequenceOfPsidGroupPermissions,
        };
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            CrlSeries, Duration as AsnDuration, HashedId3, Time32, Uint16, Uint32, ValidityPeriod,
        };

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

        let placeholder_pk =
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
            VerificationKeyIndicator::verificationKey(placeholder_pk),
            None,
            SequenceOfAppExtensions(vec![].into()),
            SequenceOfCertIssueExtensions(vec![].into()),
            SequenceOfCertRequestExtensions(vec![].into()),
        )
    }

    fn make_at_tbs() -> ToBeSignedCertificate {
        use crate::security::security_asn::ieee1609_dot2::{
            CertificateId, PsidSsp, SequenceOfAppExtensions, SequenceOfCertIssueExtensions,
            SequenceOfCertRequestExtensions, SequenceOfPsidSsp,
        };
        use crate::security::security_asn::ieee1609_dot2_base_types::{
            CrlSeries, Duration as AsnDuration, HashedId3, Psid, Time32, Uint16, Uint32,
            ValidityPeriod,
        };

        let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(1)));

        let app_perms =
            SequenceOfPsidSsp(vec![PsidSsp::new(Psid(Integer::from(36_i64)), None)].into());

        let placeholder_pk =
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
            VerificationKeyIndicator::verificationKey(placeholder_pk),
            None,
            SequenceOfAppExtensions(vec![].into()),
            SequenceOfCertIssueExtensions(vec![].into()),
            SequenceOfCertRequestExtensions(vec![].into()),
        )
    }

    #[test]
    fn own_certificate_self_signed_roundtrip() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(own.verify(&backend));
        assert!(own.cert.is_self_signed());
        assert!(!own.cert.is_issued());
    }

    #[test]
    fn own_certificate_issued_roundtrip() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        assert!(at.verify(&backend));
        assert!(at.cert.is_issued());
        assert!(!at.cert.is_self_signed());
    }

    #[test]
    fn certificate_hashedid8_and_hashedid3() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let h8 = own.as_hashedid8();
        let h3 = own.cert.as_hashedid3();
        assert_eq!(h3, [h8[5], h8[6], h8[7]]);
    }

    #[test]
    fn certificate_encode_decode_roundtrip() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let encoded = own.cert.encode().to_vec();
        let decoded = Certificate::from_bytes(&encoded, None);
        assert_eq!(decoded.as_hashedid8(), own.as_hashedid8());
    }

    #[test]
    fn certificate_from_asn_and_from_bytes_same_hash() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let bytes = own.cert.encode().to_vec();
        let c1 = Certificate::from_bytes(&bytes, None);
        let c2 = Certificate::from_asn(own.cert.inner.clone(), None);
        assert_eq!(c1.as_hashedid8(), c2.as_hashedid8());
    }

    #[test]
    fn certificate_check_corresponding_issuer() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        assert!(at.cert.check_corresponding_issuer(&root.cert));
    }

    #[test]
    fn certificate_signature_is_nist_p256() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(own.cert.signature_is_nist_p256());
        assert!(own.cert.verification_key_is_nist_p256());
    }

    #[test]
    fn certificate_has_all_permissions() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(root.cert.has_all_permissions());
    }

    #[test]
    fn certificate_get_list_of_its_aid() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        let aids = at.get_list_of_its_aid();
        assert!(aids.contains(&36));
    }

    #[test]
    fn certificate_sign_message() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let sig = own.sign_message(&backend, b"test data");
        let pk = backend.get_public_key(own.key_id);
        assert!(backend.verify_with_pk(b"test data", &sig, &pk));
    }

    #[test]
    fn certificate_verify_type_explicit() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert_eq!(own.cert.base().r_type, CertificateType::explicit);
    }

    #[test]
    fn certificate_at_is_authorization_ticket() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        assert!(at.cert.is_authorization_ticket());
    }

    #[test]
    fn certificate_self_signed_get_issuer_hashedid8_none() {
        let mut backend = EcdsaBackend::new();
        let own = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        assert!(own.cert.get_issuer_hashedid8().is_none());
    }

    #[test]
    fn certificate_issued_get_issuer_hashedid8_some() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let at = OwnCertificate::initialize_issued(&mut backend, make_at_tbs(), &root);
        let issuer_h8 = at.cert.get_issuer_hashedid8();
        assert!(issuer_h8.is_some());
        assert_eq!(issuer_h8.unwrap(), root.as_hashedid8());
    }
}

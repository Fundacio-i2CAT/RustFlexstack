//! Certificate library — storage and chain validation.
//!
//! Manages four collections of certificates:
//! - Own certificates (can sign with them).
//! - Known authorization tickets (can verify messages from them).
//! - Known authorization authorities.
//! - Known root CA certificates.

use std::collections::HashMap;

use crate::security::certificate::{Certificate, OwnCertificate};
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::security_asn::ieee1609_dot2::IssuerIdentifier;

/// Certificate library holding all trusted and own certificates.
pub struct CertificateLibrary {
    pub own_certificates: HashMap<[u8; 8], OwnCertificate>,
    pub known_authorization_tickets: HashMap<[u8; 8], Certificate>,
    pub known_authorization_authorities: HashMap<[u8; 8], Certificate>,
    pub known_root_certificates: HashMap<[u8; 8], Certificate>,
}

impl CertificateLibrary {
    /// Create and populate a library with initial root, AA and AT certificates.
    pub fn new(
        backend: &EcdsaBackend,
        root_certificates: Vec<Certificate>,
        aa_certificates: Vec<Certificate>,
        at_certificates: Vec<Certificate>,
    ) -> Self {
        let mut lib = Self {
            own_certificates: HashMap::new(),
            known_authorization_tickets: HashMap::new(),
            known_authorization_authorities: HashMap::new(),
            known_root_certificates: HashMap::new(),
        };
        for c in root_certificates {
            lib.add_root_certificate(backend, c);
        }
        for c in aa_certificates {
            lib.add_authorization_authority(backend, c);
        }
        for c in at_certificates {
            lib.add_authorization_ticket(backend, c);
        }
        lib
    }

    /// Look up the issuer certificate (root or AA) by the HashedId8 stored
    /// inside `cert`'s `issuer` field.
    pub fn get_issuer_certificate(&self, cert: &Certificate) -> Option<&Certificate> {
        match &cert.base().issuer {
            IssuerIdentifier::R_self(_) => None,
            IssuerIdentifier::sha256AndDigest(h) | IssuerIdentifier::sha384AndDigest(h) => {
                let mut key = [0u8; 8];
                key.copy_from_slice(h.0.as_ref());
                self.known_root_certificates
                    .get(&key)
                    .or_else(|| self.known_authorization_authorities.get(&key))
            }
            _ => None,
        }
    }

    /// Add a root CA certificate if it verifies (self-signed).
    pub fn add_root_certificate(&mut self, backend: &EcdsaBackend, cert: Certificate) {
        if cert.verify(backend) {
            self.known_root_certificates
                .insert(cert.as_hashedid8(), cert);
        }
    }

    /// Add an authorization authority certificate if its issuer is known and it verifies.
    pub fn add_authorization_authority(&mut self, backend: &EcdsaBackend, cert: Certificate) {
        let h = cert.as_hashedid8();
        if self.known_authorization_authorities.contains_key(&h) {
            return;
        }
        if self.get_issuer_certificate(&cert).is_some() && cert.verify(backend) {
            self.known_authorization_authorities.insert(h, cert);
        }
    }

    /// Add an authorization ticket if its issuer is known and it verifies.
    pub fn add_authorization_ticket(&mut self, backend: &EcdsaBackend, cert: Certificate) {
        let h = cert.as_hashedid8();
        if self.known_authorization_tickets.contains_key(&h) {
            return;
        }
        if self.get_issuer_certificate(&cert).is_some() && cert.verify(backend) {
            self.known_authorization_tickets.insert(h, cert);
        }
    }

    /// Add an own certificate if its issuer is known and it verifies.
    pub fn add_own_certificate(&mut self, backend: &EcdsaBackend, cert: OwnCertificate) {
        if self.get_issuer_certificate(&cert.cert).is_some() && cert.verify(backend) {
            self.own_certificates.insert(cert.as_hashedid8(), cert);
        }
    }

    /// Retrieve an AT by HashedId8.
    pub fn get_authorization_ticket_by_hashedid8(&self, h: &[u8; 8]) -> Option<&Certificate> {
        self.known_authorization_tickets.get(h)
    }

    /// Verify a sequence of certificates as specified in IEEE 1609.2 signer
    /// identifier.  The first entry is the AT, subsequent entries form the
    /// issuer chain up to a trusted root.
    pub fn verify_sequence_of_certificates(
        &mut self,
        certs: &[Certificate],
        backend: &EcdsaBackend,
    ) -> Option<Certificate> {
        if certs.is_empty() {
            return None;
        }
        if certs.len() == 1 {
            let temp = &certs[0];
            let h = temp.as_hashedid8();
            if self.known_authorization_tickets.contains_key(&h) {
                return self.known_authorization_tickets.get(&h).cloned();
            }
            // Try to find issuer in our store
            if let Some(issuer) = self.get_issuer_certificate(temp).cloned() {
                let with_issuer = Certificate::from_asn(temp.inner.clone(), Some(issuer));
                if with_issuer.verify(backend) {
                    let h2 = with_issuer.as_hashedid8();
                    self.known_authorization_tickets
                        .insert(h2, with_issuer.clone());
                    return Some(with_issuer);
                }
            }
            return None;
        }
        if certs.len() == 2 {
            // certs[1] = AA, certs[0] = AT
            let aa_temp = &certs[1];
            if let Some(issuer_h) = aa_temp.get_issuer_hashedid8() {
                if let Some(root) = self.known_root_certificates.get(&issuer_h).cloned() {
                    let aa_with_issuer = Certificate::from_asn(aa_temp.inner.clone(), Some(root));
                    if aa_with_issuer.verify(backend) {
                        let aa_h = aa_with_issuer.as_hashedid8();
                        self.known_authorization_authorities
                            .insert(aa_h, aa_with_issuer.clone());

                        let at_with_issuer =
                            Certificate::from_asn(certs[0].inner.clone(), Some(aa_with_issuer));
                        if at_with_issuer.verify(backend) {
                            let at_h = at_with_issuer.as_hashedid8();
                            self.known_authorization_tickets
                                .insert(at_h, at_with_issuer.clone());
                            return Some(at_with_issuer);
                        }
                    }
                }
            }
            return None;
        }
        if certs.len() == 3 {
            // certs[2] = Root, certs[1] = AA, certs[0] = AT
            let root_temp = &certs[2];
            let root_h = root_temp.as_hashedid8();
            if self.known_root_certificates.contains_key(&root_h) {
                return self.verify_sequence_of_certificates(&certs[..2], backend);
            }
        }
        None
    }

    /// Look up an AA or Root CA certificate by HashedId3 (last 3 bytes of HashedId8).
    pub fn get_ca_certificate_by_hashedid3(&self, h3: &[u8; 3]) -> Option<&Certificate> {
        for (h8, cert) in &self.known_authorization_authorities {
            if h8[5..8] == *h3 {
                return Some(cert);
            }
        }
        for (h8, cert) in &self.known_root_certificates {
            if h8[5..8] == *h3 {
                return Some(cert);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::certificate::OwnCertificate;
    use crate::security::ecdsa_backend::EcdsaBackend;
    use crate::security::security_asn::ieee1609_dot2::{
        CertificateId, EndEntityType, PsidGroupPermissions, PsidSsp, SequenceOfAppExtensions,
        SequenceOfCertIssueExtensions, SequenceOfCertRequestExtensions,
        SequenceOfPsidGroupPermissions, SequenceOfPsidSsp, SubjectPermissions,
        VerificationKeyIndicator,
    };
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        CrlSeries, Duration as AsnDuration, EccP256CurvePoint, HashedId3, Psid,
        PublicVerificationKey, Time32, Uint16, Uint32, ValidityPeriod,
    };
    use rasn::prelude::*;

    fn make_root_tbs() -> crate::security::security_asn::ieee1609_dot2::ToBeSignedCertificate {
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
        crate::security::security_asn::ieee1609_dot2::ToBeSignedCertificate::new(
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

    fn make_at_tbs() -> crate::security::security_asn::ieee1609_dot2::ToBeSignedCertificate {
        let validity = ValidityPeriod::new(Time32(Uint32(0)), AsnDuration::years(Uint16(1)));
        let app_perms = SequenceOfPsidSsp(vec![PsidSsp::new(Psid(Integer::from(36_i64)), None)]);
        let pk =
            PublicVerificationKey::ecdsaNistP256(EccP256CurvePoint::x_only(vec![0u8; 32].into()));
        crate::security::security_asn::ieee1609_dot2::ToBeSignedCertificate::new(
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

    fn make_chain(backend: &mut EcdsaBackend) -> (OwnCertificate, OwnCertificate, OwnCertificate) {
        let root = OwnCertificate::initialize_self_signed(backend, make_root_tbs());
        let aa = OwnCertificate::initialize_issued(backend, make_root_tbs(), &root);
        let at = OwnCertificate::initialize_issued(backend, make_at_tbs(), &aa);
        (root, aa, at)
    }

    #[test]
    fn library_new_empty() {
        let backend = EcdsaBackend::new();
        let lib = CertificateLibrary::new(&backend, vec![], vec![], vec![]);
        assert!(lib.own_certificates.is_empty());
        assert!(lib.known_root_certificates.is_empty());
        assert!(lib.known_authorization_authorities.is_empty());
        assert!(lib.known_authorization_tickets.is_empty());
    }

    #[test]
    fn library_add_root_certificate() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let lib = CertificateLibrary::new(&backend, vec![root.cert.clone()], vec![], vec![]);
        assert_eq!(lib.known_root_certificates.len(), 1);
    }

    #[test]
    fn library_add_aa_and_at() {
        let mut backend = EcdsaBackend::new();
        let (root, aa, at) = make_chain(&mut backend);
        let lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![at.cert.clone()],
        );
        assert_eq!(lib.known_root_certificates.len(), 1);
        assert_eq!(lib.known_authorization_authorities.len(), 1);
        assert_eq!(lib.known_authorization_tickets.len(), 1);
    }

    #[test]
    fn library_get_authorization_ticket_by_hashedid8() {
        let mut backend = EcdsaBackend::new();
        let (root, aa, at) = make_chain(&mut backend);
        let lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![at.cert.clone()],
        );
        let h8 = at.as_hashedid8();
        assert!(lib.get_authorization_ticket_by_hashedid8(&h8).is_some());
    }

    #[test]
    fn library_get_ca_certificate_by_hashedid3() {
        let mut backend = EcdsaBackend::new();
        let (root, aa, _at) = make_chain(&mut backend);
        let lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![],
        );
        let h3 = aa.cert.as_hashedid3();
        assert!(lib.get_ca_certificate_by_hashedid3(&h3).is_some());
    }

    #[test]
    fn library_get_issuer_certificate() {
        let mut backend = EcdsaBackend::new();
        let (root, aa, at) = make_chain(&mut backend);
        let lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![at.cert.clone()],
        );
        let issuer = lib.get_issuer_certificate(&at.cert);
        assert!(issuer.is_some());
    }

    #[test]
    fn library_add_own_certificate() {
        let mut backend = EcdsaBackend::new();
        let (root, aa, at) = make_chain(&mut backend);
        let mut lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![],
        );
        lib.add_own_certificate(&backend, at);
        assert_eq!(lib.own_certificates.len(), 1);
    }

    #[test]
    fn library_verify_sequence_single_known_at() {
        let mut backend = EcdsaBackend::new();
        let (root, aa, at) = make_chain(&mut backend);
        let mut lib = CertificateLibrary::new(
            &backend,
            vec![root.cert.clone()],
            vec![aa.cert.clone()],
            vec![at.cert.clone()],
        );
        let result = lib.verify_sequence_of_certificates(std::slice::from_ref(&at.cert), &backend);
        assert!(result.is_some());
    }

    #[test]
    fn library_verify_sequence_empty() {
        let backend = EcdsaBackend::new();
        let mut lib = CertificateLibrary::new(&backend, vec![], vec![], vec![]);
        let result = lib.verify_sequence_of_certificates(&[], &backend);
        assert!(result.is_none());
    }

    #[test]
    fn library_duplicate_aa_not_added_twice() {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, make_root_tbs());
        let aa = OwnCertificate::initialize_issued(&mut backend, make_root_tbs(), &root);
        let mut lib = CertificateLibrary::new(&backend, vec![root.cert.clone()], vec![], vec![]);
        lib.add_authorization_authority(&backend, aa.cert.clone());
        lib.add_authorization_authority(&backend, aa.cert.clone());
        assert_eq!(lib.known_authorization_authorities.len(), 1);
    }
}

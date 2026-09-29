// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! PKI client façade: orchestrates enrolment and authorization.
//!
//! Provides [`PkiClient`], which manages:
//! - Generating or loading the canonical (bootstrap) key pair
//! - Performing S3 enrolment to obtain an EC
//! - Performing S2 authorization to obtain an AT
//! - Persisting EC and AT as `.cert` and `.pem` file pairs
//! - Loading previously issued AT certificates from disk

use rasn::types::{FixedBitString, FixedOctetString, Integer};
use std::fmt;
use std::path::PathBuf;

use crate::security::certificate::{encode_tbs_certificate, Certificate, OwnCertificate};
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::pki_client::authorization::{authorize_with_transport, AuthorizationError};
use crate::security::pki_client::crypto::now_time32;
use crate::security::pki_client::enrolment::{
    enroll_with_transport, EnrolmentError, HttpTransport, UreqTransport, PSID_CERT_REQUEST,
};
use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::security_asn::ieee1609_dot2::{
    Certificate as AsnCertificate, CertificateBase, CertificateId, CertificateType, EndEntityType,
    IssuerIdentifier, PsidGroupPermissions, SequenceOfPsidGroupPermissions, SubjectPermissions,
    ToBeSignedCertificate, VerificationKeyIndicator,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    CrlSeries, Duration, HashAlgorithm, HashedId3, Psid, PsidSsp, SequenceOfPsidSsp,
    ServiceSpecificPermissions, Time32, Uint16, Uint32, Uint8, ValidityPeriod,
};

#[derive(Debug)]
pub enum PkiError {
    Enrolment(EnrolmentError),
    Authorization(AuthorizationError),
    Io(std::io::Error),
    InvalidState(String),
}

impl fmt::Display for PkiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkiError::Enrolment(e) => write!(f, "Enrolment error: {e}"),
            PkiError::Authorization(e) => write!(f, "Authorization error: {e}"),
            PkiError::Io(e) => write!(f, "I/O error: {e}"),
            PkiError::InvalidState(s) => write!(f, "Invalid state: {s}"),
        }
    }
}

impl std::error::Error for PkiError {}

impl From<EnrolmentError> for PkiError {
    fn from(e: EnrolmentError) -> Self {
        PkiError::Enrolment(e)
    }
}

impl From<AuthorizationError> for PkiError {
    fn from(e: AuthorizationError) -> Self {
        PkiError::Authorization(e)
    }
}

impl From<std::io::Error> for PkiError {
    fn from(e: std::io::Error) -> Self {
        PkiError::Io(e)
    }
}

/// Orchestrates PKI enrolment (S3) and authorization (S2) for an ITS-S.
pub struct PkiClient {
    pub ea_url: String,
    pub aa_url: String,
    pub ea_cert: Certificate,
    pub aa_cert: Certificate,
    pub rca_cert: Certificate,
    pub certs_dir: PathBuf,
    pub its_id: [u8; 8],
    pub http_timeout_secs: u64,
    pub backend: EcdsaBackend,
    canonical_key_bytes: Option<Vec<u8>>,
    canonical_cert: Option<OwnCertificate>,
    pub ec_own: Option<OwnCertificate>,
    pub at_own: Option<OwnCertificate>,
    transport: Box<dyn HttpTransport>,
}

impl PkiClient {
    /// Create a new `PkiClient`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ea_url: impl Into<String>,
        aa_url: impl Into<String>,
        ea_cert: Certificate,
        aa_cert: Certificate,
        rca_cert: Certificate,
        canonical_key_bytes: Option<Vec<u8>>,
        certs_dir: impl Into<PathBuf>,
        its_id: Option<[u8; 8]>,
        http_timeout_secs: Option<u64>,
    ) -> Self {
        Self {
            ea_url: ea_url.into(),
            aa_url: aa_url.into(),
            ea_cert,
            aa_cert,
            rca_cert,
            certs_dir: certs_dir.into(),
            its_id: its_id.unwrap_or([0u8; 8]),
            http_timeout_secs: http_timeout_secs.unwrap_or(30),
            backend: EcdsaBackend::new(),
            canonical_key_bytes,
            canonical_cert: None,
            ec_own: None,
            at_own: None,
            transport: Box::new(UreqTransport),
        }
    }

    /// Set a custom HTTP transport (useful for offline testing or custom clients).
    pub fn with_transport(mut self, transport: Box<dyn HttpTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// Access the current canonical certificate if generated.
    pub fn canonical_cert(&self) -> Option<&OwnCertificate> {
        self.canonical_cert.as_ref()
    }

    /// Perform S3 enrolment and return the issued EC.
    ///
    /// Saves `<certs_dir>/ec.cert` and `<certs_dir>/ec.pem`.
    pub fn enroll(
        &mut self,
        app_permissions: Option<SequenceOfPsidSsp>,
        validity_years: Option<u16>,
    ) -> Result<OwnCertificate, PkiError> {
        let signer = self.get_or_create_canonical_cert()?;

        let ec = enroll_with_transport(
            self.transport.as_ref(),
            &self.ea_url,
            &self.ea_cert,
            &signer,
            &mut self.backend,
            Some(self.its_id),
            app_permissions,
            validity_years,
            Some(self.http_timeout_secs),
        )?;

        self.save_cert(&ec, "ec")?;
        self.ec_own = Some(ec.clone());
        Ok(ec)
    }

    /// Perform S2 authorization and return the issued AT.
    ///
    /// Saves `<certs_dir>/at.cert` and `<certs_dir>/at.pem`.
    pub fn authorize(
        &mut self,
        ec_own: Option<&OwnCertificate>,
        app_permissions: Option<SequenceOfPsidSsp>,
        validity_hours: Option<u16>,
    ) -> Result<OwnCertificate, PkiError> {
        let ec = match ec_own {
            Some(e) => e,
            None => self.ec_own.as_ref().ok_or_else(|| {
                PkiError::InvalidState("No EC available — call enroll() before authorize()".into())
            })?,
        };

        let at = authorize_with_transport(
            self.transport.as_ref(),
            &self.aa_url,
            &self.aa_cert,
            &self.ea_cert,
            ec,
            &mut self.backend,
            app_permissions,
            validity_hours,
            Some(self.http_timeout_secs),
        )?;

        self.save_cert(&at, "at")?;
        self.at_own = Some(at.clone());
        Ok(at)
    }

    /// Run enrolment + authorization in sequence and return the issued AT.
    pub fn provision(
        &mut self,
        app_permissions: Option<SequenceOfPsidSsp>,
        ec_validity_years: Option<u16>,
        at_validity_hours: Option<u16>,
    ) -> Result<OwnCertificate, PkiError> {
        let ec = self.enroll(None, ec_validity_years)?;
        self.authorize(Some(&ec), app_permissions, at_validity_hours)
    }

    /// Save a certificate and private key to `<certs_dir>/<name>.cert` and `<certs_dir>/<name>.pem`.
    pub fn save_cert(&self, cert: &OwnCertificate, name: &str) -> Result<(), PkiError> {
        std::fs::create_dir_all(&self.certs_dir)?;
        let cert_path = self.certs_dir.join(format!("{name}.cert"));
        let key_path = self.certs_dir.join(format!("{name}.pem"));

        std::fs::write(&cert_path, cert.cert.encode())?;
        std::fs::write(&key_path, self.backend.export_signing_key(cert.key_id))?;
        Ok(())
    }

    /// Load a previously issued AT from `<certs_dir>/<name>.cert` and `<certs_dir>/<name>.pem`.
    pub fn load_at_from_disk(&mut self, name: Option<&str>) -> Option<OwnCertificate> {
        let name = name.unwrap_or("at");
        let cert_path = self.certs_dir.join(format!("{name}.cert"));
        let key_path = self.certs_dir.join(format!("{name}.pem"));

        if !cert_path.exists() || !key_path.exists() {
            return None;
        }

        let cert_bytes = std::fs::read(&cert_path).ok()?;
        let key_bytes = std::fs::read(&key_path).ok()?;

        if key_bytes.len() != 32 {
            return None;
        }

        let key_id = self.backend.import_signing_key(&key_bytes);
        let cert = Certificate::from_bytes(&cert_bytes, Some(self.aa_cert.clone()));
        let at_own = OwnCertificate::new(cert, key_id);
        self.at_own = Some(at_own.clone());
        Some(at_own)
    }

    /// Return or lazily initialize the self-signed bootstrap canonical certificate.
    pub fn get_or_create_canonical_cert(&mut self) -> Result<OwnCertificate, PkiError> {
        if let Some(ref cert) = self.canonical_cert {
            return Ok(cert.clone());
        }

        let start = now_time32();
        let validity = ValidityPeriod::new(Time32(Uint32(start)), Duration::years(Uint16(10)));
        let app_perms = SequenceOfPsidSsp(vec![PsidSsp::new(
            Psid(Integer::from(PSID_CERT_REQUEST)),
            Some(ServiceSpecificPermissions::opaque(vec![0x01, 0xC0].into())),
        )]);
        let mut bits = FixedBitString::<8>::default();
        bits.set(0, true);
        let perms = SequenceOfPsidGroupPermissions(vec![PsidGroupPermissions::new(
            SubjectPermissions::all(()),
            Integer::from(2),
            Integer::from(0),
            EndEntityType(bits),
        )]);

        let canonical_cert = if let Some(ref pem_bytes) = self.canonical_key_bytes {
            let key_id = self.backend.import_signing_key(pem_bytes);
            let vk = self.backend.get_public_key(key_id);

            let tbs = ToBeSignedCertificate::new(
                CertificateId::none(()),
                HashedId3(FixedOctetString::from([0u8; 3])),
                CrlSeries(Uint16(0)),
                validity,
                None,
                None,
                Some(app_perms),
                Some(perms),
                None,
                None,
                None,
                VerificationKeyIndicator::verificationKey(vk),
                None,
                None,
                None,
                None,
            );

            let tbs_bytes = encode_tbs_certificate(&tbs);
            let sig = self.backend.sign(&tbs_bytes, key_id);
            let base = CertificateBase::new(
                Uint8(3),
                CertificateType::explicit,
                IssuerIdentifier::R_self(HashAlgorithm::sha256),
                tbs,
                Some(sig),
            );
            let cert_asn = EtsiTs103097Certificate(AsnCertificate(base));
            let cert = Certificate::from_asn(cert_asn, None);
            OwnCertificate::new(cert, key_id)
        } else {
            let temp_key = self.backend.create_key();
            let placeholder_pk = self.backend.get_public_key(temp_key);
            let tbs = ToBeSignedCertificate::new(
                CertificateId::none(()),
                HashedId3(FixedOctetString::from([0u8; 3])),
                CrlSeries(Uint16(0)),
                validity,
                None,
                None,
                Some(app_perms),
                Some(perms),
                None,
                None,
                None,
                VerificationKeyIndicator::verificationKey(placeholder_pk),
                None,
                None,
                None,
                None,
            );
            OwnCertificate::initialize_self_signed(&mut self.backend, tbs)
        };

        self.canonical_cert = Some(canonical_cert.clone());
        Ok(canonical_cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pki_test_{}_{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    use crate::security::security_asn::ieee1609_dot2_base_types::{
        BasePublicEncryptionKey, EccP256CurvePoint, EcdsaP256Signature, PublicEncryptionKey,
        Signature as Ieee1609Signature, SymmAlgorithm,
    };

    fn make_test_cert(backend: &mut EcdsaBackend, with_enc_key: bool) -> Certificate {
        let key_id = backend.create_key();
        let vk = backend.get_public_key(key_id);

        let enc_key = if with_enc_key {
            Some(PublicEncryptionKey::new(
                SymmAlgorithm::aes128Ccm,
                BasePublicEncryptionKey::eciesNistP256(EccP256CurvePoint::compressed_y_0(
                    vec![0x11; 32].into(),
                )),
            ))
        } else {
            None
        };

        let tbs = ToBeSignedCertificate::new(
            CertificateId::none(()),
            HashedId3(FixedOctetString::from([0u8; 3])),
            CrlSeries(Uint16(0)),
            ValidityPeriod::new(Time32(Uint32(0)), Duration::years(Uint16(5))),
            None,
            None,
            Some(SequenceOfPsidSsp(vec![PsidSsp::new(
                Psid(Integer::from(36)),
                None,
            )])),
            None,
            None,
            None,
            enc_key,
            VerificationKeyIndicator::verificationKey(vk),
            None,
            None,
            None,
            None,
        );

        let sig = Ieee1609Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r_sig: EccP256CurvePoint::x_only(vec![0x01; 32].into()),
            s_sig: vec![0x02; 32].into(),
        });

        let base = CertificateBase::new(
            Uint8(3),
            CertificateType::explicit,
            IssuerIdentifier::R_self(HashAlgorithm::sha256),
            tbs,
            Some(sig),
        );

        Certificate::from_asn(EtsiTs103097Certificate(AsnCertificate(base)), None)
    }

    #[test]
    fn test_init() {
        let mut backend = EcdsaBackend::new();
        let ea_cert = make_test_cert(&mut backend, true);
        let aa_cert = make_test_cert(&mut backend, true);
        let rca_cert = make_test_cert(&mut backend, false);
        let tmp = TestDir::new();

        let client = PkiClient::new(
            "http://localhost:8080",
            "http://localhost:8081",
            ea_cert.clone(),
            aa_cert.clone(),
            rca_cert.clone(),
            None,
            tmp.path(),
            Some([0u8; 8]),
            Some(15),
        );

        assert_eq!(client.ea_url, "http://localhost:8080");
        assert_eq!(client.aa_url, "http://localhost:8081");
        assert_eq!(client.ea_cert.as_hashedid8(), ea_cert.as_hashedid8());
        assert_eq!(client.aa_cert.as_hashedid8(), aa_cert.as_hashedid8());
        assert_eq!(client.rca_cert.as_hashedid8(), rca_cert.as_hashedid8());
        assert_eq!(client.certs_dir, tmp.path());
        assert_eq!(client.its_id, [0u8; 8]);
        assert_eq!(client.http_timeout_secs, 15);
        assert!(client.ec_own.is_none());
        assert!(client.at_own.is_none());
    }

    #[test]
    fn test_get_or_create_canonical_cert_generate() {
        let mut backend = EcdsaBackend::new();
        let ea_cert = make_test_cert(&mut backend, true);
        let aa_cert = make_test_cert(&mut backend, true);
        let rca_cert = make_test_cert(&mut backend, false);
        let tmp = TestDir::new();

        let mut client = PkiClient::new(
            "http://localhost:8080",
            "http://localhost:8081",
            ea_cert,
            aa_cert,
            rca_cert,
            None,
            tmp.path(),
            None,
            None,
        );

        let canon1 = client.get_or_create_canonical_cert().unwrap();
        let canon2 = client.get_or_create_canonical_cert().unwrap();

        assert_eq!(canon1.as_hashedid8(), canon2.as_hashedid8());
        assert!(client.canonical_cert().is_some());
    }

    #[test]
    fn test_get_or_create_canonical_cert_from_pem() {
        let mut backend = EcdsaBackend::new();
        let ea_cert = make_test_cert(&mut backend, true);
        let aa_cert = make_test_cert(&mut backend, true);
        let rca_cert = make_test_cert(&mut backend, false);
        let tmp = TestDir::new();

        let key_id = backend.create_key();
        let key_bytes = backend.export_signing_key(key_id);

        let mut client = PkiClient::new(
            "http://localhost:8080",
            "http://localhost:8081",
            ea_cert,
            aa_cert,
            rca_cert,
            Some(key_bytes),
            tmp.path(),
            None,
            None,
        );

        let canon = client.get_or_create_canonical_cert().unwrap();
        assert!(canon.verify(&client.backend));
    }

    #[test]
    fn test_save_and_load_at_from_disk() {
        let mut backend = EcdsaBackend::new();
        let ea_cert = make_test_cert(&mut backend, true);
        let aa_cert = make_test_cert(&mut backend, true);
        let rca_cert = make_test_cert(&mut backend, false);
        let tmp = TestDir::new();

        let mut client = PkiClient::new(
            "http://localhost:8080",
            "http://localhost:8081",
            ea_cert,
            aa_cert.clone(),
            rca_cert,
            None,
            tmp.path(),
            None,
            None,
        );

        // Before saving, loading should be None
        assert!(client.load_at_from_disk(Some("at")).is_none());

        let at_key = client.backend.create_key();
        let at_cert = make_test_cert(&mut client.backend, false);
        let at_own = OwnCertificate::new(at_cert, at_key);

        client.save_cert(&at_own, "at").unwrap();

        assert!(tmp.path().join("at.cert").exists());
        assert!(tmp.path().join("at.pem").exists());

        let loaded = client.load_at_from_disk(Some("at")).unwrap();
        assert_eq!(loaded.as_hashedid8(), at_own.as_hashedid8());
        assert!(client.at_own.is_some());
    }

    #[test]
    fn test_load_at_from_disk_corrupt() {
        let mut backend = EcdsaBackend::new();
        let ea_cert = make_test_cert(&mut backend, true);
        let aa_cert = make_test_cert(&mut backend, true);
        let rca_cert = make_test_cert(&mut backend, false);
        let tmp = TestDir::new();

        let mut client = PkiClient::new(
            "http://localhost:8080",
            "http://localhost:8081",
            ea_cert,
            aa_cert,
            rca_cert,
            None,
            tmp.path(),
            None,
            None,
        );

        std::fs::write(tmp.path().join("corrupt.cert"), b"corrupt").unwrap();
        std::fs::write(tmp.path().join("corrupt.pem"), b"corrupt").unwrap();

        assert!(client.load_at_from_disk(Some("corrupt")).is_none());
    }

    #[test]
    fn test_authorize_without_ec_raises() {
        let mut backend = EcdsaBackend::new();
        let ea_cert = make_test_cert(&mut backend, true);
        let aa_cert = make_test_cert(&mut backend, true);
        let rca_cert = make_test_cert(&mut backend, false);
        let tmp = TestDir::new();

        let mut client = PkiClient::new(
            "http://localhost:8080",
            "http://localhost:8081",
            ea_cert,
            aa_cert,
            rca_cert,
            None,
            tmp.path(),
            None,
            None,
        );

        let err = client.authorize(None, None, None).unwrap_err();
        match err {
            PkiError::InvalidState(s) => assert!(s.contains("No EC available")),
            _ => panic!("Expected InvalidState"),
        }
    }
}

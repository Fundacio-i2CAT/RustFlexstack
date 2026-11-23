// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! [`PkiClient`]: the ITS-S side of the ETSI TS 102 941 V2.2.1 security
//! management (enrolment with the EA, authorization with the AA).
//!
//! States (ETSI TS 103 525-2 V2.1.1 clause 4.2.1):
//! - `initialized`: no valid Enrolment Credential (EC); the next enrolment is
//!   an initial request (canonical identifier and canonical key);
//! - `enrolled`: a valid EC; the next enrolment is a re-keying request when the
//!   EC permits signing enrolment requests (SSP of ITS-AID 623, clause B.4);
//! - `authorized`: a valid EC and a valid Authorization Ticket (AT).
//!
//! A failed request leaves the state as it was; an expired EC or AT no longer
//! counts. Revocation (CRL, see [`super::trust_lists`]) of the EA, AA or Root
//! CA of the own certificates drops them ([`PkiClient::revoke`]).

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use rasn::types::Integer;

use crate::security::certificate::{Certificate, OwnCertificate};
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::pki_asn::decode;
use crate::security::pki_asn::etsi_ts102941_base_types::CertificateSubjectAttributes;
use crate::security::pki_client::authorization::{authorize, AuthorizationError};
use crate::security::pki_client::enrolment::{enroll, EnrolmentError};
use crate::security::pki_client::messages::{self, time32, time64};
use crate::security::pki_client::transport::{
    HttpTransport, PkiSleep, PkiTransport, Retry, RetryPolicy,
};
use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::security_asn::ieee1609_dot2_base_types::{
    Duration, Psid, PsidSsp, PublicVerificationKey, SequenceOfPsidSsp, Time32, Uint16, Uint32,
    ValidityPeriod,
};
use crate::security::time_service::unix_time_secs;
use crate::security::validity::valid_at;

/// UTC seconds since the Unix epoch.
pub type PkiClock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// State of the ITS-S (TS 103 525-2 clause 4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiState {
    Initialized,
    Enrolled,
    Authorized,
}

/// Error of a [`PkiClient`] operation.
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

/// ITS-S PKI client (see the module documentation).
pub struct PkiClient {
    /// Access points of the EA and the AA (the requests are POSTed to them).
    pub ea_url: String,
    pub aa_url: String,
    pub ea_cert: Certificate,
    pub aa_cert: Certificate,
    pub rca_cert: Certificate,
    pub certs_dir: PathBuf,
    /// Canonical identifier (InnerEcRequest.itsId of an initial request).
    pub its_id: Vec<u8>,
    pub backend: EcdsaBackend,
    /// Send authorization requests with proof of possession (clause 6.2.3.3.1).
    pub pop: bool,
    /// Repetition of an enrolment request without response (ETSI TS 103 601
    /// V2.1.1 clause 5.1, mandatory for every ITS-S); None sends it once.
    pub enrolment_retry: Option<RetryPolicy>,
    /// Repetition of an authorization request (clause 5.2): for an ITS-S
    /// without privacy requirements only, hence off (None) by default.
    pub authorization_retry: Option<RetryPolicy>,
    /// Wait between two transmissions (`std::thread::sleep` by default).
    pub sleep: PkiSleep,
    canonical_key: usize,
    clock: PkiClock,
    transport: Box<dyn PkiTransport>,
    ec_own: Option<OwnCertificate>,
    at_own: Option<OwnCertificate>,
}

impl PkiClient {
    /// A client; `canonical_key_bytes` is the private scalar of the canonical key
    /// registered with the EA (a key is generated without it, see
    /// [`PkiClient::canonical_public_key`]). `http_timeout_secs` configures the
    /// default HTTP transport.
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
        let mut backend = EcdsaBackend::new();
        let canonical_key = match canonical_key_bytes {
            Some(bytes) => backend.import_signing_key(&bytes),
            None => backend.create_key(),
        };
        Self {
            ea_url: ea_url.into(),
            aa_url: aa_url.into(),
            ea_cert,
            aa_cert,
            rca_cert,
            certs_dir: certs_dir.into(),
            its_id: its_id.unwrap_or([0u8; 8]).to_vec(),
            backend,
            pop: true,
            enrolment_retry: Some(RetryPolicy::default()),
            authorization_retry: None,
            sleep: Arc::new(|s| std::thread::sleep(std::time::Duration::from_secs_f64(s))),
            canonical_key,
            clock: Arc::new(unix_time_secs),
            transport: Box::new(HttpTransport::new(std::time::Duration::from_secs(
                http_timeout_secs.unwrap_or(30),
            ))),
            ec_own: None,
            at_own: None,
        }
    }

    /// Use `transport` instead of HTTP.
    pub fn with_transport(mut self, transport: Box<dyn PkiTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// Use `clock` (UTC seconds) instead of the system time.
    pub fn with_clock(mut self, clock: PkiClock) -> Self {
        self.clock = clock;
        self
    }

    /// Canonical identifier of any length (default: 8 octets given to `new`).
    pub fn with_its_id(mut self, its_id: Vec<u8>) -> Self {
        self.its_id = its_id;
        self
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    fn valid(&self, certificate: Option<&OwnCertificate>) -> bool {
        certificate.is_some_and(|c| valid_at(&c.cert, time64(self.now())))
    }

    /// The current EC, if valid.
    pub fn ec(&self) -> Option<&OwnCertificate> {
        self.ec_own
            .as_ref()
            .filter(|_| self.valid(self.ec_own.as_ref()))
    }

    /// The current AT, if valid (and the EC too).
    pub fn at(&self) -> Option<&OwnCertificate> {
        self.ec()?;
        self.at_own
            .as_ref()
            .filter(|_| self.valid(self.at_own.as_ref()))
    }

    /// `initialized`, `enrolled` or `authorized`.
    pub fn state(&self) -> PkiState {
        match (self.ec(), self.at()) {
            (None, _) => PkiState::Initialized,
            (Some(_), None) => PkiState::Enrolled,
            (Some(_), Some(_)) => PkiState::Authorized,
        }
    }

    /// The canonical verification key (to be registered with the EA).
    pub fn canonical_public_key(&self) -> PublicVerificationKey {
        self.backend.get_public_key(self.canonical_key)
    }

    /// Apply revoked CA certificates (HashedId8): an EC whose EA or Root CA is
    /// revoked is dropped (`initialized`); an AT whose AA (or Root CA) is
    /// revoked is dropped (`enrolled`).
    pub fn revoke(&mut self, revoked: &HashSet<[u8; 8]>) {
        let rca = revoked.contains(&self.rca_cert.as_hashedid8());
        if rca || revoked.contains(&self.ea_cert.as_hashedid8()) {
            self.ec_own = None;
            self.at_own = None;
        }
        if rca || revoked.contains(&self.aa_cert.as_hashedid8()) {
            self.at_own = None;
        }
    }

    fn attributes(
        &self,
        app_permissions: SequenceOfPsidSsp,
        duration: Option<Duration>,
    ) -> CertificateSubjectAttributes {
        CertificateSubjectAttributes::new(
            None,
            duration.map(|d| ValidityPeriod::new(Time32(Uint32(time32(self.now()))), d)),
            None,
            None,
            Some(app_permissions),
            None,
        )
    }

    /// Request an EC (clause 6.2.3.2): a re-keying request when the current EC
    /// is valid and permits enrolment requests, an initial request otherwise.
    /// The EC is saved to `<certs_dir>/ec.{cert,pem}`.
    pub fn enroll(
        &mut self,
        app_permissions: Option<SequenceOfPsidSsp>,
        validity_years: Option<u16>,
    ) -> Result<OwnCertificate, PkiError> {
        let permissions = app_permissions.unwrap_or_else(|| {
            SequenceOfPsidSsp(vec![PsidSsp::new(
                Psid(Integer::from(messages::PSID_CERT_REQUEST)),
                Some(messages::certificate_ssp()),
            )])
        });
        let current = self
            .ec()
            .filter(|ec| messages::ssp_permits(&ec.cert, messages::SSP_ENROLMENT_REQUEST))
            .cloned();
        let attributes = self.attributes(
            permissions,
            validity_years.map(|y| Duration::years(Uint16(y))),
        );
        let now = self.now();
        let retry = self.retry(self.enrolment_retry);
        let ec = enroll(
            self.transport.as_ref(),
            &self.ea_url,
            &self.ea_cert,
            &mut self.backend,
            &self.its_id,
            self.canonical_key,
            current.as_ref(),
            attributes,
            now,
            retry.as_ref(),
        )?;
        self.ec_own = Some(ec.clone());
        self.save_cert(&ec, "ec")?;
        Ok(ec)
    }

    /// Request an AT (clause 6.2.3.3) with the EC (ecSignature). The AT is
    /// saved to `<certs_dir>/at.{cert,pem}`.
    pub fn authorize(
        &mut self,
        ec_own: Option<&OwnCertificate>,
        app_permissions: Option<SequenceOfPsidSsp>,
        validity_hours: Option<u16>,
    ) -> Result<OwnCertificate, PkiError> {
        let ec = match ec_own {
            Some(ec) => ec.clone(),
            None => self
                .ec()
                .cloned()
                .ok_or_else(|| PkiError::InvalidState("No valid EC: enroll() first".into()))?,
        };
        if !messages::ssp_permits(&ec.cert, messages::SSP_AUTHORIZATION_REQUEST) {
            return Err(AuthorizationError::new(
                "deniedpermissions",
                "the EC does not permit authorization requests",
            )
            .into());
        }
        let permissions = app_permissions.unwrap_or_else(|| {
            SequenceOfPsidSsp(vec![
                PsidSsp::new(Psid(Integer::from(36)), None),
                PsidSsp::new(Psid(Integer::from(37)), None),
            ])
        });
        let attributes = self.attributes(
            permissions,
            validity_hours.map(|h| Duration::hours(Uint16(h))),
        );
        let now = self.now();
        let retry = self.retry(self.authorization_retry);
        let at = authorize(
            self.transport.as_ref(),
            &self.aa_url,
            &self.aa_cert,
            &self.ea_cert,
            &ec,
            &mut self.backend,
            attributes,
            now,
            self.pop,
            retry.as_ref(),
        )?;
        self.at_own = Some(at.clone());
        self.save_cert(&at, "at")?;
        Ok(at)
    }

    fn retry(&self, policy: Option<RetryPolicy>) -> Option<Retry> {
        policy.map(|policy| Retry {
            policy,
            clock: Arc::clone(&self.clock),
            sleep: Arc::clone(&self.sleep),
        })
    }

    /// Enrol (when not enrolled) and request an AT; returns the AT.
    pub fn provision(
        &mut self,
        app_permissions: Option<SequenceOfPsidSsp>,
        ec_validity_years: Option<u16>,
        at_validity_hours: Option<u16>,
    ) -> Result<OwnCertificate, PkiError> {
        if self.ec().is_none() {
            self.enroll(None, ec_validity_years)?;
        }
        self.authorize(None, app_permissions, at_validity_hours)
    }

    /// Save a certificate (COER) and its private scalar to
    /// `<certs_dir>/<name>.cert` and `<certs_dir>/<name>.pem`.
    pub fn save_cert(&self, cert: &OwnCertificate, name: &str) -> Result<(), PkiError> {
        std::fs::create_dir_all(&self.certs_dir)?;
        std::fs::write(
            self.certs_dir.join(format!("{name}.cert")),
            cert.cert.encode(),
        )?;
        std::fs::write(
            self.certs_dir.join(format!("{name}.pem")),
            self.backend.export_signing_key(cert.key_id),
        )?;
        Ok(())
    }

    fn load(&mut self, name: &str, issuer: &Certificate) -> Option<OwnCertificate> {
        let cert_bytes = std::fs::read(self.certs_dir.join(format!("{name}.cert"))).ok()?;
        let key_bytes = std::fs::read(self.certs_dir.join(format!("{name}.pem"))).ok()?;
        if key_bytes.len() != 32 || p256::SecretKey::from_slice(&key_bytes).is_err() {
            return None;
        }
        let certificate: EtsiTs103097Certificate = decode(&cert_bytes).ok()?;
        let key_id = self.backend.import_signing_key(&key_bytes);
        Some(OwnCertificate::new(
            Certificate::from_asn(certificate, Some(issuer.clone())),
            key_id,
        ))
    }

    /// Load a previously issued EC (None if absent or unreadable).
    pub fn load_ec_from_disk(&mut self, name: Option<&str>) -> Option<OwnCertificate> {
        let ea = self.ea_cert.clone();
        let ec = self.load(name.unwrap_or("ec"), &ea)?;
        self.ec_own = Some(ec.clone());
        Some(ec)
    }

    /// Load a previously issued AT (None if absent or unreadable).
    pub fn load_at_from_disk(&mut self, name: Option<&str>) -> Option<OwnCertificate> {
        let aa = self.aa_cert.clone();
        let at = self.load(name.unwrap_or("at"), &aa)?;
        self.at_own = Some(at.clone());
        Some(at)
    }
}

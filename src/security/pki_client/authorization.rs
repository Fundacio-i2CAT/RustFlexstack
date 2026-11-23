// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Authorization of an enrolled ITS-S with an AA (ETSI TS 102 941 V2.2.1
//! clause 6.2.3.3): request an Authorization Ticket (AT). The message
//! construction is in [`super::messages`]; this module sends the request and
//! checks the response.

use std::fmt;

use crate::security::certificate::{Certificate, OwnCertificate};
use crate::security::ecdsa_backend::{EcdsaBackend, KeyAlgorithm};
use crate::security::pki_asn::etsi_ts102941_base_types::CertificateSubjectAttributes;
use crate::security::pki_asn::etsi_ts102941_types_authorization::AuthorizationResponseCode;
use crate::security::pki_client::messages::{self, PkiProtocolError, CT_REQUEST};
use crate::security::pki_client::transport::{
    post_with_retry, PkiTransport, PkiTransportError, Retry,
};

/// The authorization failed: `code` is the AuthorizationResponseCode returned
/// by the AA (e.g. `its-aa-unknownea`) or the name of the failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationError {
    pub code: String,
    pub message: String,
}

impl AuthorizationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthorizationError {}

impl From<PkiProtocolError> for AuthorizationError {
    fn from(e: PkiProtocolError) -> Self {
        Self::new(e.code, e.message)
    }
}

impl From<PkiTransportError> for AuthorizationError {
    fn from(e: PkiTransportError) -> Self {
        Self::new("transport", e.0)
    }
}

/// ASN.1 name of an AuthorizationResponseCode (`its-aa-unknownea`, ...).
pub fn response_code_name(code: AuthorizationResponseCode) -> String {
    format!("{code:?}").replace('_', "-")
}

/// Send an AuthorizationRequestMessage (with POP when `pop`) to `aa_url` and
/// return the issued AT. With `retry` the same message is repeated while no
/// response is received (ETSI TS 103 601 V2.1.1 clause 5.2).
#[allow(clippy::too_many_arguments)]
pub fn authorize(
    transport: &dyn PkiTransport,
    aa_url: &str,
    aa_cert: &Certificate,
    ea_cert: &Certificate,
    ec_own: &OwnCertificate,
    backend: &mut EcdsaBackend,
    attributes: CertificateSubjectAttributes,
    now: f64,
    pop: bool,
    retry: Option<&Retry>,
) -> Result<OwnCertificate, AuthorizationError> {
    let request = messages::build_authorization_request(
        backend,
        aa_cert,
        ea_cert,
        ec_own,
        attributes,
        now,
        pop,
        KeyAlgorithm::NistP256,
    )?;
    let response = post_with_retry(transport, aa_url, &request.message, CT_REQUEST, retry)?;
    let inner = messages::read_authorization_response(&response, &request, aa_cert, backend)?;
    if inner.response_code != AuthorizationResponseCode::ok {
        let code = response_code_name(inner.response_code);
        return Err(AuthorizationError::new(
            code.clone(),
            format!("AA rejected the request: {code}"),
        ));
    }
    let certificate = inner
        .certificate
        .ok_or_else(|| AuthorizationError::new("cantparse", "positive response without AT"))?;
    let at = Certificate::from_asn(certificate, Some(aa_cert.clone()));
    if !messages::certifies(&at, &backend.get_public_key(request.key_id)) {
        return Err(AuthorizationError::new(
            "its-aa-keysdontmatch",
            "the AT does not certify the requested key",
        ));
    }
    if !at.check_corresponding_issuer(aa_cert) {
        return Err(AuthorizationError::new(
            "invalidaasignature",
            "the AT is not issued by the AA",
        ));
    }
    Ok(OwnCertificate::new(at, request.key_id))
}

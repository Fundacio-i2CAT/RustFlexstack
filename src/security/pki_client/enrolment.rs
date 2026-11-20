// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Enrolment of an ITS-S with an EA (ETSI TS 102 941 V2.2.1 clause 6.2.3.2):
//! request an Enrolment Credential (EC). The message construction is in
//! [`super::messages`]; this module sends the request and checks the response.

use std::fmt;

use crate::security::certificate::{Certificate, OwnCertificate};
use crate::security::ecdsa_backend::{EcdsaBackend, KeyAlgorithm};
use crate::security::pki_asn::etsi_ts102941_base_types::CertificateSubjectAttributes;
use crate::security::pki_asn::etsi_ts102941_types_enrolment::EnrolmentResponseCode;
use crate::security::pki_client::messages::{self, PkiProtocolError, CT_REQUEST};
use crate::security::pki_client::transport::{
    post_with_retry, PkiTransport, PkiTransportError, Retry,
};

/// The enrolment failed: `code` is the EnrolmentResponseCode returned by the EA
/// (e.g. `deniedrequest`) or the name of the failed check of the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentError {
    pub code: String,
    pub message: String,
}

impl EnrolmentError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for EnrolmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for EnrolmentError {}

impl From<PkiProtocolError> for EnrolmentError {
    fn from(e: PkiProtocolError) -> Self {
        Self::new(e.code, e.message)
    }
}

impl From<PkiTransportError> for EnrolmentError {
    fn from(e: PkiTransportError) -> Self {
        Self::new("transport", e.0)
    }
}

/// ASN.1 name of an EnrolmentResponseCode (as in the ETSI module).
pub fn response_code_name(code: EnrolmentResponseCode) -> String {
    format!("{code:?}")
}

/// Send an EnrolmentRequestMessage to `ea_url` and return the issued EC. An
/// initial request (`current_ec` None) uses the canonical identifier `its_id`
/// and the canonical key `canonical_key`; a re-keying request uses the EC
/// identifier and key (clause 6.2.3.2.1). With `retry` the same message is
/// repeated while no response is received (ETSI TS 103 601 V2.1.1 clause 5.1).
#[allow(clippy::too_many_arguments)]
pub fn enroll(
    transport: &dyn PkiTransport,
    ea_url: &str,
    ea_cert: &Certificate,
    backend: &mut EcdsaBackend,
    its_id: &[u8],
    canonical_key: usize,
    current_ec: Option<&OwnCertificate>,
    attributes: CertificateSubjectAttributes,
    now: f64,
    retry: Option<&Retry>,
) -> Result<OwnCertificate, EnrolmentError> {
    let request = messages::build_enrolment_request(
        backend,
        ea_cert,
        its_id,
        canonical_key,
        current_ec,
        attributes,
        now,
        KeyAlgorithm::NistP256,
    )?;
    let response = post_with_retry(transport, ea_url, &request.message, CT_REQUEST, retry)?;
    let inner = messages::read_enrolment_response(&response, &request, ea_cert, backend)?;
    if inner.response_code != EnrolmentResponseCode::ok {
        let code = response_code_name(inner.response_code);
        return Err(EnrolmentError::new(
            code.clone(),
            format!("EA rejected the request: {code}"),
        ));
    }
    let certificate = inner
        .certificate
        .ok_or_else(|| EnrolmentError::new("cantparse", "positive response without EC"))?;
    let ec = Certificate::from_asn(certificate, Some(ea_cert.clone()));
    if !messages::certifies(&ec, &backend.get_public_key(request.key_id)) {
        return Err(EnrolmentError::new(
            "invalidkeys",
            "the EC does not certify the requested verification key",
        ));
    }
    if !ec.check_corresponding_issuer(ea_cert) {
        return Err(EnrolmentError::new(
            "invalidsignature",
            "the EC is not issued by the EA",
        ));
    }
    Ok(OwnCertificate::new(ec, request.key_id))
}

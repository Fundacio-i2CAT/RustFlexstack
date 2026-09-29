// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! PKI client module for ETSI TS 102 941 enrolment and authorization.
//!
//! Provides the ITS-S implementation of:
//! - S3 Enrolment protocol ([`enrolment`])
//! - S2 Authorization protocol ([`authorization`])
//! - High-level façade and certificate persistence ([`client::PkiClient`])
//! - Sender-side cryptographic operations ([`crypto`])
//! - ASN.1 COER coder helpers ([`pki_coder::PkiCoder`])

pub mod authorization;
pub mod client;
pub mod crypto;
pub mod enrolment;
pub mod pki_coder;

pub use authorization::{authorize, authorize_with_transport, AuthorizationError};
pub use client::{PkiClient, PkiError};
pub use enrolment::{enroll, enroll_with_transport, EnrolmentError, HttpTransport, UreqTransport};
pub use pki_coder::PkiCoder;

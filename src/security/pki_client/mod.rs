// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ITS-S side of ETSI TS 102 941 V2.2.1 (official ASN.1, [`crate::security::pki_asn`]):
//! - enrolment with the EA, clause 6.2.3.2 ([`enrolment`]);
//! - authorization with the AA, clause 6.2.3.3 ([`authorization`]);
//! - message construction and response checks ([`messages`]);
//! - the canonical key pair kept on disk, clause 6.1.2 ([`canonical`]);
//! - the client state machine and persistence ([`client::PkiClient`]);
//! - CTL / CRL use, clause 6.3.6 ([`trust_lists::TrustStore`]);
//! - the HTTP transport, Annexes C to E ([`transport`]).

pub mod authorization;
pub mod canonical;
pub mod client;
pub mod distribution;
pub mod enrolment;
pub mod messages;
pub mod transport;
pub mod trust_lists;

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod conformance_dist;
#[cfg(test)]
pub(crate) mod ts_pki;
#[cfg(test)]
mod unit_tests;

pub use authorization::{authorize, AuthorizationError};
pub use canonical::{load_or_create_canonical_key, CanonicalKey};
pub use client::{PkiClient, PkiClock, PkiError, PkiState};
pub use enrolment::{enroll, EnrolmentError};
pub use messages::PkiProtocolError;
pub use transport::{HttpTransport, PkiTransport, PkiTransportError};
pub use trust_lists::{ListKind, TrustListError, TrustStore};

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! HTTP transport of the PKI messages.
//!
//! ETSI TS 102 941 V2.2.1 Annex C: requests are HTTP POSTs to the access point
//! of the EA / AA (`application/x-its-request`, response
//! `application/x-its-response`). Annexes D and E: CTL, CRL and ECTL are
//! fetched with HTTP GET from the DC / CPOC. The transport is a trait so that
//! tests (and other carriers) can replace it.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::security::pki_client::client::PkiClock;

/// The PKI could not be reached or answered with an HTTP error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiTransportError(pub String);

impl fmt::Display for PkiTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PkiTransportError {}

/// Carrier of the PKI messages.
pub trait PkiTransport: Send + Sync {
    /// POST `body` to `url`; returns the response body.
    fn post(
        &self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<Vec<u8>, PkiTransportError>;
    /// GET `url`; returns the response body.
    fn get(&self, url: &str) -> Result<Vec<u8>, PkiTransportError>;
}

/// `ureq` transport with a timeout.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    pub timeout: Duration,
}

impl HttpTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

fn read(
    response: Result<ureq::Response, ureq::Error>,
    what: &str,
) -> Result<Vec<u8>, PkiTransportError> {
    match response {
        Ok(r) => {
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut r.into_reader(), &mut body)
                .map_err(|e| PkiTransportError(format!("{what}: {e}")))?;
            Ok(body)
        }
        Err(ureq::Error::Status(code, _)) => Err(PkiTransportError(format!("{what}: HTTP {code}"))),
        Err(e) => Err(PkiTransportError(format!("{what}: {e}"))),
    }
}

impl PkiTransport for HttpTransport {
    fn post(
        &self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<Vec<u8>, PkiTransportError> {
        read(
            ureq::post(url)
                .timeout(self.timeout)
                .set("Content-Type", content_type)
                .send_bytes(body),
            &format!("POST {url}"),
        )
    }

    fn get(&self, url: &str) -> Result<Vec<u8>, PkiTransportError> {
        read(
            ureq::get(url).timeout(self.timeout).call(),
            &format!("GET {url}"),
        )
    }
}

/// Wait (seconds) between two transmissions of a request.
pub type PkiSleep = Arc<dyn Fn(f64) + Send + Sync>;

/// Repetition of a request whose response is not received (ETSI TS 103 601
/// V2.1.1 clauses 5.1.4 and 5.2.4): the same message is sent again `th1`
/// seconds after the previous transmission (timer T1 / T4), at most `n1` times
/// in all (N1 / N2), and not after `th2` seconds from the first one (T2 / T5,
/// TH2 > TH1 x N1; NOTE 1 recommends 60 minutes).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryPolicy {
    pub th1: f64,
    pub n1: u32,
    pub th2: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            th1: 30.0,
            n1: 3,
            th2: 3600.0,
        }
    }
}

/// A [`RetryPolicy`] with the clock and the wait it runs on.
#[derive(Clone)]
pub struct Retry {
    pub policy: RetryPolicy,
    pub clock: PkiClock,
    pub sleep: PkiSleep,
}

/// POST `body` (always the same message) until a response is received,
/// following `retry` (one transmission when None). The error when no response
/// came: the caller then drops the request and its session key (clause 5.1.2,
/// case 2).
pub fn post_with_retry(
    transport: &dyn PkiTransport,
    url: &str,
    body: &[u8],
    content_type: &str,
    retry: Option<&Retry>,
) -> Result<Vec<u8>, PkiTransportError> {
    let Some(retry) = retry else {
        return transport.post(url, body, content_type);
    };
    let policy = retry.policy;
    let first = (retry.clock)();
    for attempt in 1..=policy.n1 {
        let sent = (retry.clock)();
        if let Ok(response) = transport.post(url, body, content_type) {
            return Ok(response);
        }
        let resend = sent + policy.th1;
        if attempt == policy.n1 || resend >= first + policy.th2 {
            return Err(PkiTransportError(format!(
                "POST {url}: no response after {attempt} transmissions"
            )));
        }
        (retry.sleep)((resend - (retry.clock)()).max(0.0));
    }
    Err(PkiTransportError(format!(
        "POST {url}: no transmission allowed (n1 = {})",
        policy.n1
    )))
}

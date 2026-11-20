// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! ETSI originating HeaderInfo extensions (ETSI TS 103 097 V2.2.1 clause 4.3.2
//! and module EtsiTs103097ExtensionModule): the peer-to-peer CRL / CTL
//! requests of ETSI TS 103 601 V2.1.1 clause 5.3.4, carried in
//! `contributedExtensions`.
//!
//! A `ContributedExtensionBlock` of the ETSI contributor (2) holds a sequence
//! of open types, each the COER encoding of an
//! `EtsiOriginatingHeaderInfoExtension` (`id` and the open type `content`).
//!
//! Mirrors `flexstack/security/header_extensions.py`.

use rasn::prelude::*;

use crate::security::security_asn::etsi_ts103097_extension_module::{
    EtsiTs102941CrlRequest, EtsiTs102941CtlRequest, EtsiTs102941FullCtlRequest,
};
use crate::security::security_asn::ieee1609_dot2::{
    AnonymousContributedExtensionBlockExtns, ContributedExtensionBlock,
    ContributedExtensionBlockExtns, ContributedExtensionBlocks, HeaderInfoContributorId,
};

/// IEEE 1609.2 HeaderInfoContributorId of ETSI TC ITS (TS 103 097 clause 4.3.2).
pub const ETSI_HEADER_INFO_CONTRIBUTOR_ID: u8 = 2;
/// EtsiTs103097HeaderInfoExtensionId values (EtsiTs103097ExtensionModule).
pub const CRL_REQUEST_ID: u8 = 1;
pub const DELTA_CTL_REQUEST_ID: u8 = 2;
pub const FULL_CTL_REQUEST_ID: u8 = 3;

/// A peer-to-peer CRL / CTL request (TS 103 601 clause 5.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustListRequest {
    Crl(EtsiTs102941CrlRequest),
    DeltaCtl(EtsiTs102941CtlRequest),
    FullCtl(EtsiTs102941FullCtlRequest),
}

impl TrustListRequest {
    /// The extension id of the request.
    pub fn id(&self) -> u8 {
        match self {
            TrustListRequest::Crl(_) => CRL_REQUEST_ID,
            TrustListRequest::DeltaCtl(_) => DELTA_CTL_REQUEST_ID,
            TrustListRequest::FullCtl(_) => FULL_CTL_REQUEST_ID,
        }
    }

    /// The HashedId8 of the TLM / Root CA whose list is requested.
    pub fn issuer(&self) -> [u8; 8] {
        let h = match self {
            TrustListRequest::Crl(r) => &r.issuer_id,
            TrustListRequest::DeltaCtl(r) => &r.issuer_id,
            TrustListRequest::FullCtl(r) => &r.issuer_id,
        };
        let mut out = [0u8; 8];
        out.copy_from_slice(h.0.as_ref());
        out
    }

    fn content(&self) -> Vec<u8> {
        match self {
            TrustListRequest::Crl(r) => rasn::coer::encode(r),
            TrustListRequest::DeltaCtl(r) => rasn::coer::encode(r),
            TrustListRequest::FullCtl(r) => rasn::coer::encode(r),
        }
        .expect("COER encoding of a request")
    }
}

fn length(n: usize) -> Vec<u8> {
    if n < 128 {
        return vec![n as u8];
    }
    let bytes: Vec<u8> = n
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

/// COER of the `EtsiOriginatingHeaderInfoExtension` of `request`: id, then the
/// open type content (length determinant and COER of the request).
pub fn encode_extension(request: &TrustListRequest) -> Vec<u8> {
    let content = request.content();
    let mut out = vec![request.id()];
    out.extend(length(content.len()));
    out.extend(content);
    out
}

/// Decode an `EtsiOriginatingHeaderInfoExtension`; None for an unknown id or
/// a malformed extension.
pub fn decode_extension(bytes: &[u8]) -> Option<TrustListRequest> {
    let (&id, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 128 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
        (len, &rest[n..])
    };
    if rest.len() != len {
        return None;
    }
    match id {
        CRL_REQUEST_ID => rasn::coer::decode(rest).ok().map(TrustListRequest::Crl),
        DELTA_CTL_REQUEST_ID => rasn::coer::decode(rest)
            .ok()
            .map(TrustListRequest::DeltaCtl),
        FULL_CTL_REQUEST_ID => rasn::coer::decode(rest).ok().map(TrustListRequest::FullCtl),
        _ => None,
    }
}

/// `ContributedExtensionBlocks` with one ETSI block carrying `requests`.
pub fn encode_requests(requests: &[TrustListRequest]) -> ContributedExtensionBlocks {
    let extns = requests
        .iter()
        .map(|r| AnonymousContributedExtensionBlockExtns(OctetString::from(encode_extension(r))))
        .collect();
    ContributedExtensionBlocks(vec![ContributedExtensionBlock::new(
        HeaderInfoContributorId(ETSI_HEADER_INFO_CONTRIBUTOR_ID),
        ContributedExtensionBlockExtns(extns),
    )])
}

/// The CRL / CTL requests in received `contributedExtensions`. Blocks of other
/// contributors, unknown ids and undecodable extensions are skipped (TS 103 097
/// clause 4.3.2).
pub fn decode_requests(blocks: &ContributedExtensionBlocks) -> Vec<TrustListRequest> {
    blocks
        .0
        .iter()
        .filter(|b| b.contributor_id.0 == ETSI_HEADER_INFO_CONTRIBUTOR_ID)
        .flat_map(|b| b.extns.0.iter())
        .filter_map(|e| decode_extension(e.0.as_ref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::security_asn::ieee1609_dot2::HeaderInfo;
    use crate::security::security_asn::ieee1609_dot2_base_types::{
        HashedId8, Psid, Time32, Time64, Uint32, Uint64, Uint8,
    };

    fn to_hex(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn issuer() -> HashedId8 {
        HashedId8(FixedOctetString::from([0x11; 8]))
    }

    fn crl(last: Option<u32>) -> TrustListRequest {
        TrustListRequest::Crl(EtsiTs102941CrlRequest::new(
            issuer(),
            last.map(|t| Time32(Uint32(t))),
        ))
    }

    fn header(requests: &[TrustListRequest]) -> HeaderInfo {
        let mut h = HeaderInfo::new(
            Psid(Integer::from(36)),
            Some(Time64(Uint64(1))),
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
        h.contributed_extensions = Some(encode_requests(requests));
        h
    }

    /// COER derived by hand: id 01, content length 0d, CrlRequest = preamble 80
    /// (lastKnownUpdate present) || issuerId || Time32 00000005.
    #[test]
    fn crl_request_encoding() {
        assert_eq!(
            to_hex(encode_extension(&crl(Some(5)))),
            format!("010d80{}00000005", "11".repeat(8))
        );
        let delta = TrustListRequest::DeltaCtl(EtsiTs102941CtlRequest::new(issuer(), None));
        assert_eq!(
            to_hex(encode_extension(&delta)),
            format!("020900{}", "11".repeat(8))
        );
    }

    /// The same HeaderInfo encodings as FlexStack (frozen from
    /// `asn_coder.encode("HeaderInfo", ...)`).
    #[test]
    fn header_info_vectors() {
        let delta =
            TrustListRequest::DeltaCtl(EtsiTs102941CtlRequest::new(issuer(), Some(Uint8(7))));
        for (request, expected) in [
            (
                crl(Some(5)),
                "c0012400000000000000010204101501010201010f010d80111111111111111100000005",
            ),
            (
                delta,
                "c0012400000000000000010204101201010201010c020a80111111111111111107",
            ),
        ] {
            let encoded = rasn::coer::encode(&header(std::slice::from_ref(&request))).unwrap();
            assert_eq!(to_hex(&encoded), expected);
            let decoded: HeaderInfo = rasn::coer::decode(&encoded).unwrap();
            assert_eq!(
                decode_requests(decoded.contributed_extensions.as_ref().unwrap()),
                vec![request]
            );
        }
    }

    #[test]
    fn foreign_and_unknown_extensions_skipped() {
        let mut blocks = encode_requests(&[crl(None)]);
        blocks.0[0].extns.0.insert(
            0,
            AnonymousContributedExtensionBlockExtns(OctetString::from(vec![9, 1, 0])),
        );
        blocks.0[0].extns.0.insert(
            0,
            AnonymousContributedExtensionBlockExtns(OctetString::from(vec![0xff])),
        );
        blocks.0.insert(
            0,
            ContributedExtensionBlock::new(
                HeaderInfoContributorId(1),
                ContributedExtensionBlockExtns(vec![AnonymousContributedExtensionBlockExtns(
                    OctetString::from(encode_extension(&crl(Some(1)))),
                )]),
            ),
        );
        assert_eq!(decode_requests(&blocks), vec![crl(None)]);
    }
}

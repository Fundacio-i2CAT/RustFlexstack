// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CTL and CRL use by an ITS-S (ETSI TS 102 941 V2.2.1 clauses 6.3.1 to
//! 6.3.6, Annexes D and E).
//!
//! [`TrustStore`] reads the TLM CTL (ECTL), the Root CA CTLs and the CRLs,
//! checks that each is signed by its issuer (a trusted TLM, a trusted Root CA)
//! with the ITS-AID and SSP of the CTL / CRL service (clauses B.2, B.3), and
//! updates the trust information of a [`CertificateLibrary`]:
//! - ECTL: Root CA entries become trust anchors; a full ECTL also withdraws
//!   the Root CAs it no longer lists; TLM entries add a TLM; the TLM entry's
//!   access point is the CPOC;
//! - Root CA CTL: AA (and EA) entries of that Root CA; DC entries give the DC
//!   of the listed Root CAs; delete commands withdraw entries;
//! - CRL: the listed CA certificates are revoked; [`TrustStore::process`]
//!   returns them so that the caller can drop the own EC / AT
//!   ([`super::PkiClient::revoke`]).
//!
//! When a CTL or CRL passes its nextUpdate, [`TrustStore::due_downloads`]
//! gives the URLs to fetch from the CPOC (`getectl`) or the DC (`getctl`,
//! `getcrl`) and [`TrustStore::refresh`] fetches and applies them.

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::security::certificate::{encode_tbs_data, signing_input, Certificate};
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::{key_uses_sha384, EcdsaBackend};
use crate::security::pki_asn::decode;
use crate::security::pki_asn::etsi_ts102941_messages_itss::{
    EtsiTs102941Data, EtsiTs102941DataContent,
};
use crate::security::pki_asn::etsi_ts102941_trust_lists::{
    CtlCommand, CtlDelete, CtlEntry, CtlFormat, EaEntry, ToBeSignedCrl,
};
use crate::security::pki_client::client::PkiClock;
use crate::security::pki_client::messages::time32;
use crate::security::pki_client::transport::PkiTransport;
use crate::security::security_asn::etsi_ts103097_module::EtsiTs103097Certificate;
use crate::security::security_asn::ieee1609_dot2::{
    Ieee1609Dot2Content, Ieee1609Dot2Data, SignedData, SignerIdentifier,
};
use crate::security::security_asn::ieee1609_dot2_base_types::ServiceSpecificPermissions;
use crate::security::time_service::unix_time_secs;

/// ITS-AIDs of the CRL and CTL services (ETSI TS 102 965).
pub const PSID_CRL: u64 = 622;
pub const PSID_CTL: u64 = 624;
/// CTL SSP bits (clause B.2, Table B.2).
pub const SSP_TLM_ENTRIES: u8 = 0x80;
pub const SSP_RCA_ENTRIES: u8 = 0x40;
pub const SSP_EA_ENTRIES: u8 = 0x20;
pub const SSP_AA_ENTRIES: u8 = 0x10;
pub const SSP_DC_ENTRIES: u8 = 0x08;

/// A CTL or CRL is rejected; `code` names the failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustListError {
    pub code: String,
    pub message: String,
}

impl TrustListError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for TrustListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for TrustListError {}

/// Kind of list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListKind {
    Ectl,
    RcaCtl,
    Crl,
}

/// The last CTL or CRL applied for an issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListInfo {
    pub issuer: [u8; 8],
    pub kind: ListKind,
    /// Time32.
    pub next_update: u32,
    /// ctlSequence (CTL).
    pub sequence: Option<u8>,
    /// thisUpdate (CRL).
    pub this_update: Option<u32>,
    /// HashedId8 added by this list (CTL) or revoked (CRL).
    pub entries: HashSet<[u8; 8]>,
}

fn hex(h: &[u8; 8]) -> String {
    h.iter().map(|b| format!("{b:02X}")).collect()
}

fn hashed(h: &crate::security::security_asn::ieee1609_dot2_base_types::HashedId8) -> [u8; 8] {
    h.0.as_ref().try_into().unwrap()
}

fn certificate(asn: &EtsiTs103097Certificate) -> Certificate {
    Certificate::from_asn(asn.clone(), None)
}

/// Issuer and version of a verified CTL / CRL message ([`TrustStore::inspect`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListVersion {
    pub kind: ListKind,
    /// HashedId8 of the TLM or Root CA.
    pub issuer: [u8; 8],
    /// isFullCtl (false for a CRL).
    pub full: bool,
    /// ctlSequence (CTL).
    pub sequence: Option<u8>,
    /// thisUpdate (CRL).
    pub this_update: Option<u32>,
    /// Time32.
    pub next_update: u32,
}

enum Opened {
    Ctl(CtlFormat),
    Crl(ToBeSignedCrl),
}

/// Trust information of an ITS-S built from CTLs and CRLs (module documentation).
pub struct TrustStore {
    pub tlms: HashMap<[u8; 8], Certificate>,
    pub lists: HashMap<(ListKind, [u8; 8]), ListInfo>,
    pub cpoc_url: Option<String>,
    /// Root CA HashedId8 -> DC access point.
    pub dc_urls: HashMap<[u8; 8], String>,
    /// EA HashedId8 -> EaEntry.
    pub ea_entries: HashMap<[u8; 8], EaEntry>,
    clock: PkiClock,
}

impl TrustStore {
    /// A store trusting `tlm_certificates` (installed out of band).
    pub fn new(tlm_certificates: Vec<Certificate>) -> Self {
        Self {
            tlms: tlm_certificates
                .into_iter()
                .map(|c| (c.as_hashedid8(), c))
                .collect(),
            lists: HashMap::new(),
            cpoc_url: None,
            dc_urls: HashMap::new(),
            ea_entries: HashMap::new(),
            clock: std::sync::Arc::new(unix_time_secs),
        }
    }

    /// Use `clock` (UTC seconds) instead of the system time.
    pub fn with_clock(mut self, clock: PkiClock) -> Self {
        self.clock = clock;
        self
    }

    fn issuer(
        signed: &SignedData,
        anchors: &HashMap<[u8; 8], Certificate>,
        library: &CertificateLibrary,
    ) -> Result<Certificate, TrustListError> {
        let h = match &signed.signer {
            SignerIdentifier::certificate(seq) => {
                let first = seq
                    .0
                    .first()
                    .ok_or_else(|| TrustListError::new("invalidsigner", "empty"))?;
                certificate(&EtsiTs103097Certificate(first.clone())).as_hashedid8()
            }
            SignerIdentifier::digest(d) => hashed(d),
            _ => return Err(TrustListError::new("invalidsigner", "signer self")),
        };
        if library.revoked.contains(&h) {
            return Err(TrustListError::new(
                "unknownissuer",
                format!("issuer {} is revoked", hex(&h)),
            ));
        }
        anchors.get(&h).cloned().ok_or_else(|| {
            TrustListError::new(
                "unknownissuer",
                format!("issuer {} is not trusted", hex(&h)),
            )
        })
    }

    fn verify(
        signed: &SignedData,
        issuer: &Certificate,
        psid: u64,
        backend: &EcdsaBackend,
    ) -> Result<(), TrustListError> {
        if u64::try_from(&signed.tbs_data.header_info.psid.0).ok() != Some(psid) {
            return Err(TrustListError::new(
                "badpsid",
                format!("expected psid {psid}"),
            ));
        }
        let key = issuer
            .verification_key()
            .ok_or_else(|| TrustListError::new("invalidsignature", "no verification key"))?;
        let input = signing_input(
            &encode_tbs_data(&signed.tbs_data),
            issuer.to_canonical().encode(),
            key_uses_sha384(&key),
        );
        if backend.verify_with_pk(&input, &signed.signature, &key) {
            Ok(())
        } else {
            Err(TrustListError::new(
                "invalidsignature",
                "the signature does not verify",
            ))
        }
    }

    /// (the issuer's appPermissions contain `psid`, its SSP octets).
    fn permission(issuer: &Certificate, psid: u64) -> (bool, Vec<u8>) {
        for item in issuer.tbs().app_permissions.iter().flat_map(|p| p.0.iter()) {
            if u64::try_from(&item.psid.0).ok() == Some(psid) {
                let ssp = match &item.ssp {
                    Some(ServiceSpecificPermissions::bitmapSsp(b)) => b.0.to_vec(),
                    Some(ServiceSpecificPermissions::opaque(o)) => o.to_vec(),
                    _ => Vec::new(),
                };
                return (true, ssp);
            }
        }
        (false, Vec::new())
    }

    /// Verify and apply a TlmCertificateTrustListMessage, an
    /// RcaCertificateTrustListMessage or a CertificateRevocationListMessage to
    /// `library`; returns the kind and, for a CRL, the revoked HashedId8.
    pub fn process(
        &mut self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
        message: &[u8],
    ) -> Result<(ListKind, HashSet<[u8; 8]>), TrustListError> {
        match self.open(library, backend, message)? {
            (kind, Opened::Ctl(ctl), issuer) => {
                self.apply_ctl(library, backend, &issuer, &ctl, kind)?;
                Ok((kind, HashSet::new()))
            }
            (kind, Opened::Crl(crl), issuer) => Ok((kind, self.apply_crl(library, &issuer, &crl)?)),
        }
    }

    /// Verify the signature of a CTL / CRL message (as [`TrustStore::process`])
    /// without applying it; its issuer and version.
    pub fn inspect(
        &self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
        message: &[u8],
    ) -> Result<ListVersion, TrustListError> {
        let (kind, opened, issuer) = self.open(library, backend, message)?;
        let issuer = issuer.as_hashedid8();
        Ok(match opened {
            Opened::Ctl(ctl) => ListVersion {
                kind,
                issuer,
                full: ctl.is_full_ctl,
                sequence: Some(ctl.ctl_sequence),
                this_update: None,
                next_update: ctl.next_update.0 .0,
            },
            Opened::Crl(crl) => ListVersion {
                kind,
                issuer,
                full: false,
                sequence: None,
                this_update: Some(crl.this_update.0 .0),
                next_update: crl.next_update.0 .0,
            },
        })
    }

    /// Decode a CTL / CRL message and verify its signer and signature.
    fn open(
        &self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
        message: &[u8],
    ) -> Result<(ListKind, Opened, Certificate), TrustListError> {
        let data: Ieee1609Dot2Data =
            decode(message).map_err(|e| TrustListError::new("cantparse", e.to_string()))?;
        let Ieee1609Dot2Content::signedData(signed) = &data.content else {
            return Err(TrustListError::new("badcontenttype", "expected signedData"));
        };
        let payload = match signed.tbs_data.payload.data.as_ref().map(|d| &d.content) {
            Some(Ieee1609Dot2Content::unsecuredData(o)) => o.0.to_vec(),
            _ => {
                return Err(TrustListError::new(
                    "badcontenttype",
                    "payload is not unsecuredData",
                ))
            }
        };
        let etsi: EtsiTs102941Data =
            decode(&payload).map_err(|e| TrustListError::new("cantparse", e.to_string()))?;
        match etsi.content {
            EtsiTs102941DataContent::certificateTrustListTlm(ctl) => {
                let issuer = Self::issuer(signed, &self.tlms, library)?;
                Self::verify(signed, &issuer, PSID_CTL, backend)?;
                Ok((ListKind::Ectl, Opened::Ctl(ctl), issuer))
            }
            EtsiTs102941DataContent::certificateTrustListRca(ctl) => {
                let roots = library.known_root_certificates.clone();
                let issuer = Self::issuer(signed, &roots, library)?;
                Self::verify(signed, &issuer, PSID_CTL, backend)?;
                Ok((ListKind::RcaCtl, Opened::Ctl(ctl), issuer))
            }
            EtsiTs102941DataContent::certificateRevocationList(crl) => {
                let roots = library.known_root_certificates.clone();
                let issuer = Self::issuer(signed, &roots, library)?;
                Self::verify(signed, &issuer, PSID_CRL, backend)?;
                Ok((ListKind::Crl, Opened::Crl(crl), issuer))
            }
            _ => Err(TrustListError::new("badcontenttype", "not a CTL or CRL")),
        }
    }

    fn apply_ctl(
        &mut self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
        issuer: &Certificate,
        ctl: &CtlFormat,
        kind: ListKind,
    ) -> Result<(), TrustListError> {
        let issuer_id = issuer.as_hashedid8();
        let previous = self.lists.get(&(kind, issuer_id)).cloned();
        let full = ctl.is_full_ctl;
        if let Some(p) = &previous {
            if p.sequence == Some(ctl.ctl_sequence) {
                return Err(TrustListError::new(
                    "outdated",
                    "ctlSequence already applied",
                ));
            }
            if !full && ctl.ctl_sequence != p.sequence.unwrap_or(0).wrapping_add(1) {
                return Err(TrustListError::new(
                    "outofsequence",
                    "delta CTL does not follow the last CTL",
                ));
            }
        }
        let (_, allowed) = Self::permission(issuer, PSID_CTL);
        for command in &ctl.ctl_commands {
            match command {
                CtlCommand::add(entry) => {
                    let bit = match entry {
                        CtlEntry::tlm(_) => SSP_TLM_ENTRIES,
                        CtlEntry::rca(_) => SSP_RCA_ENTRIES,
                        CtlEntry::ea(_) => SSP_EA_ENTRIES,
                        CtlEntry::aa(_) => SSP_AA_ENTRIES,
                        CtlEntry::dc(_) => SSP_DC_ENTRIES,
                    };
                    if allowed.len() < 2 || allowed[0] != 1 || allowed[1] & bit == 0 {
                        return Err(TrustListError::new(
                            "deniedpermissions",
                            "entry not permitted by the SSP",
                        ));
                    }
                }
                CtlCommand::delete(_) if full => {
                    return Err(TrustListError::new(
                        "badcontenttype",
                        "a full CTL contains no delete command",
                    ));
                }
                _ => {}
            }
        }
        let mut entries = match (&previous, full) {
            (Some(p), false) => p.entries.clone(),
            _ => HashSet::new(),
        };
        for command in &ctl.ctl_commands {
            match command {
                CtlCommand::add(entry) => {
                    entries.extend(self.add(library, backend, issuer_id, entry))
                }
                CtlCommand::delete(delete) => {
                    if let Some(h) = self.delete(library, delete) {
                        entries.remove(&h);
                    }
                }
            }
        }
        if let (Some(p), true) = (&previous, full) {
            for h in p.entries.difference(&entries) {
                library.remove_certificate(h); // withdrawn by the full CTL
            }
        }
        self.lists.insert(
            (kind, issuer_id),
            ListInfo {
                issuer: issuer_id,
                kind,
                next_update: ctl.next_update.0 .0,
                sequence: Some(ctl.ctl_sequence),
                this_update: None,
                entries,
            },
        );
        Ok(())
    }

    fn add(
        &mut self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
        issuer_id: [u8; 8],
        entry: &CtlEntry,
    ) -> Option<[u8; 8]> {
        match entry {
            CtlEntry::rca(e) => {
                let root = certificate(&e.selfsigned_root_ca);
                let h = root.as_hashedid8();
                library.add_root_certificate(backend, root);
                library
                    .known_root_certificates
                    .contains_key(&h)
                    .then_some(h)
            }
            CtlEntry::tlm(e) => {
                let tlm = certificate(&e.self_signed_tlm_certificate);
                if tlm.verify(backend) {
                    self.tlms.insert(tlm.as_hashedid8(), tlm);
                }
                self.cpoc_url = Some(e.access_point.to_string());
                None
            }
            CtlEntry::aa(e) => {
                let root = library.known_root_certificates.get(&issuer_id).cloned();
                let aa = Certificate::from_asn(e.aa_certificate.clone(), root);
                let h = aa.as_hashedid8();
                library.add_authorization_authority(backend, aa);
                library
                    .known_authorization_authorities
                    .contains_key(&h)
                    .then_some(h)
            }
            CtlEntry::ea(e) => {
                self.ea_entries
                    .insert(certificate(&e.ea_certificate).as_hashedid8(), e.clone());
                None
            }
            CtlEntry::dc(e) => {
                for root in &e.cert {
                    self.dc_urls.insert(hashed(root), e.url.to_string());
                }
                None
            }
        }
    }

    fn delete(&mut self, library: &mut CertificateLibrary, delete: &CtlDelete) -> Option<[u8; 8]> {
        match delete {
            CtlDelete::cert(h) => {
                let h = hashed(h);
                library.remove_certificate(&h);
                self.tlms.remove(&h);
                self.ea_entries.remove(&h);
                Some(h)
            }
            CtlDelete::dc(url) => {
                let url = url.to_string();
                self.dc_urls.retain(|_, u| *u != url);
                None
            }
        }
    }

    fn apply_crl(
        &mut self,
        library: &mut CertificateLibrary,
        issuer: &Certificate,
        crl: &ToBeSignedCrl,
    ) -> Result<HashSet<[u8; 8]>, TrustListError> {
        let issuer_id = issuer.as_hashedid8();
        let (permitted, ssp) = Self::permission(issuer, PSID_CRL);
        if !permitted || ssp.first() != Some(&1) {
            return Err(TrustListError::new(
                "deniedpermissions",
                "issuer may not sign CRLs",
            ));
        }
        if let Some(p) = self.lists.get(&(ListKind::Crl, issuer_id)) {
            if crl.this_update.0 .0 <= p.this_update.unwrap_or(0) {
                return Err(TrustListError::new(
                    "outdated",
                    "not newer than the last CRL",
                ));
            }
        }
        let revoked: HashSet<[u8; 8]> = crl.entries.iter().map(hashed).collect();
        library.revoke(&revoked);
        self.lists.insert(
            (ListKind::Crl, issuer_id),
            ListInfo {
                issuer: issuer_id,
                kind: ListKind::Crl,
                next_update: crl.next_update.0 .0,
                sequence: None,
                this_update: Some(crl.this_update.0 .0),
                entries: revoked.clone(),
            },
        );
        Ok(revoked)
    }

    /// URLs of the lists past their nextUpdate: ECTL from the CPOC (Annex E.4),
    /// Root CA CTL and CRL from the Root CA's DC (Annex D).
    pub fn due_downloads(&self) -> Vec<String> {
        let now = time32((self.clock)());
        let mut urls = Vec::new();
        for ((kind, issuer), info) in &self.lists {
            if info.next_update > now {
                continue;
            }
            match kind {
                ListKind::Ectl => {
                    if let Some(cpoc) = &self.cpoc_url {
                        urls.push(format!(
                            "{}/getectl/{}",
                            cpoc.trim_end_matches('/'),
                            hex(issuer)
                        ));
                    }
                }
                ListKind::RcaCtl | ListKind::Crl => {
                    if let Some(dc) = self.dc_urls.get(issuer) {
                        let path = if *kind == ListKind::RcaCtl {
                            "getctl"
                        } else {
                            "getcrl"
                        };
                        urls.push(format!(
                            "{}/{}/{}",
                            dc.trim_end_matches('/'),
                            path,
                            hex(issuer)
                        ));
                    }
                }
            }
        }
        urls.sort();
        urls
    }

    /// Fetch and apply the due lists; returns the URLs fetched and the CA
    /// certificates revoked by the CRLs fetched.
    pub fn refresh(
        &mut self,
        library: &mut CertificateLibrary,
        backend: &EcdsaBackend,
        transport: &dyn PkiTransport,
    ) -> (Vec<String>, HashSet<[u8; 8]>) {
        let urls = self.due_downloads();
        let mut revoked = HashSet::new();
        for url in &urls {
            if let Ok(message) = transport.get(url) {
                if let Ok((_, r)) = self.process(library, backend, &message) {
                    revoked.extend(r);
                }
            }
        }
        (urls, revoked)
    }
}

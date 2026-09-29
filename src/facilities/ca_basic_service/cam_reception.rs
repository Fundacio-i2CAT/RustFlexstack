// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CAM Reception Management — ETSI TS 103 900 V2.2.1 §6.2 / Annex B.3.
//!
//! Mirrors `CAMReceptionManagement` in
//! `flexstack/facilities/ca_basic_service/cam_reception_management.py`.
//!
//! Key standard-compliance additions:
//!   - Decoding exceptions are caught and logged; the LDM/applications are NOT
//!     updated with corrupt data (Annex B.3.3.1).
//!   - Application callbacks (IF.CAM) can be registered via [`add_application_callback`].
//!   - Computes UTC timestamp from generationDeltaTime.
//!   - Dispatches received CAMs to LDM and application listeners.

use super::cam_coder::{Cam, CamCoder};
use super::cam_ldm_adaptation::CABasicServiceLDM;
use crate::btp::router::BTPRouterHandle;
use crate::btp::service_access_point::BTPDataIndication;
use crate::facilities::local_dynamic_map::LdmHandle;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// Application callback type: receives a reference to the decoded CAM and its UTC timestamp.
pub type ApplicationCallback = Arc<dyn Fn(&Cam, u64) + Send + Sync>;

/// CAM Reception Management — ETSI TS 103 900 V2.2.1 §6.2 / Annex B.3.
#[derive(Clone)]
pub struct CAMReceptionManagement {
    pub cam_coder: CamCoder,
    pub btp_handle: BTPRouterHandle,
    pub ca_basic_service_ldm: Option<CABasicServiceLDM>,
    application_callbacks: Arc<RwLock<Vec<ApplicationCallback>>>,
    cam_tx: Option<Sender<Cam>>,
}

impl CAMReceptionManagement {
    /// Create a new `CAMReceptionManagement` instance.
    pub fn new(
        btp_handle: BTPRouterHandle,
        cam_coder: CamCoder,
        ca_basic_service_ldm: Option<CABasicServiceLDM>,
    ) -> Self {
        CAMReceptionManagement {
            cam_coder,
            btp_handle,
            ca_basic_service_ldm,
            application_callbacks: Arc::new(RwLock::new(Vec::new())),
            cam_tx: None,
        }
    }

    /// Create a new `CAMReceptionManagement` instance with an outgoing MPSC channel.
    pub fn new_with_channel(
        btp_handle: BTPRouterHandle,
        cam_coder: CamCoder,
        ca_basic_service_ldm: Option<CABasicServiceLDM>,
        cam_tx: Sender<Cam>,
    ) -> Self {
        CAMReceptionManagement {
            cam_coder,
            btp_handle,
            ca_basic_service_ldm,
            application_callbacks: Arc::new(RwLock::new(Vec::new())),
            cam_tx: Some(cam_tx),
        }
    }

    /// Register an application callback (IF.CAM — §6.2).
    ///
    /// The callback receives the decoded [`Cam`] and calculated `utc_timestamp`
    /// whenever a valid CAM is received.
    pub fn add_application_callback<F>(&self, callback: F)
    where
        F: Fn(&Cam, u64) + Send + Sync + 'static,
    {
        if let Ok(mut cbs) = self.application_callbacks.write() {
            cbs.push(Arc::new(callback));
        }
    }

    /// Return the number of registered application callbacks.
    pub fn application_callbacks_len(&self) -> usize {
        self.application_callbacks
            .read()
            .map(|cbs| cbs.len())
            .unwrap_or(0)
    }

    /// BTP indication callback for received CAMs.
    ///
    /// Decoding exceptions are caught here so that the LDM and application
    /// layers are never updated with malformed data (Annex B.3.3.1).
    pub fn reception_callback(&self, btp_indication: &BTPDataIndication) -> Result<Cam, String> {
        let cam = match self.cam_coder.decode(&btp_indication.data) {
            Ok(c) => c,
            Err(e) => {
                return Err(e);
            }
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let utc_timestamp = cam
            .cam
            .generation_delta_time
            .as_timestamp_in_certain_point(now_ms);

        if let Some(ref ldm) = self.ca_basic_service_ldm {
            let _ = ldm.add_provider_data_to_ldm(&cam);
        }

        if let Ok(callbacks) = self.application_callbacks.read() {
            for cb in callbacks.iter() {
                let cb = Arc::clone(cb);
                let cam_ref = &cam;
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    cb(cam_ref, utc_timestamp);
                }));
            }
        }

        if let Some(ref tx) = self.cam_tx {
            let _ = tx.send(cam.clone());
        }

        Ok(cam)
    }

    /// Spawn the reception management thread.
    ///
    /// # Arguments
    /// * `btp_handle` — handle to the BTP router; used to register port 2001.
    /// * `coder`      — shared [`CamCoder`] instance for UPER decoding.
    /// * `cam_tx`     — sender into which decoded [`Cam`] PDUs are pushed.
    /// * `ldm`        — optional LDM handle; when `Some`, each decoded CAM is
    ///   inserted into the LDM before forwarding.
    pub fn spawn(
        btp_handle: BTPRouterHandle,
        coder: CamCoder,
        cam_tx: Sender<Cam>,
        ldm: Option<LdmHandle>,
    ) {
        let ca_basic_service_ldm = ldm.map(|l| CABasicServiceLDM::new(l, 5));
        let crm = CAMReceptionManagement::new_with_channel(
            btp_handle.clone(),
            coder,
            ca_basic_service_ldm,
            cam_tx,
        );

        let (ind_tx, ind_rx) = mpsc::channel::<BTPDataIndication>();
        btp_handle.register_port(2001, ind_tx);

        thread::spawn(move || {
            while let Ok(indication) = ind_rx.recv() {
                let _ = crm.reception_callback(&indication);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facilities::ca_basic_service::cam_coder::generate_white_cam_static;
    use crate::facilities::local_dynamic_map::LdmFacility;
    use crate::geonet::mib::Mib;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn make_test_indication(data: Vec<u8>) -> BTPDataIndication {
        let len = data.len() as u16;
        BTPDataIndication {
            destination_port: 2001,
            length: len,
            data,
            ..BTPDataIndication::new()
        }
    }

    #[test]
    fn test_crm_init_stores_components() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let ldm = LdmFacility::new(415_520_000, 21_340_000, 5_000.0);
        let ldm_adapter = CABasicServiceLDM::new(ldm, 5);

        let crm = CAMReceptionManagement::new(btp_handle, coder, Some(ldm_adapter));
        assert!(crm.ca_basic_service_ldm.is_some());
        assert_eq!(crm.application_callbacks_len(), 0);
    }

    #[test]
    fn test_reception_callback_decodes_valid_cam() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let crm = CAMReceptionManagement::new(btp_handle, coder.clone(), None);

        let white_cam = generate_white_cam_static();
        let encoded = coder.encode(&white_cam).unwrap();
        let ind = make_test_indication(encoded);

        let res = crm.reception_callback(&ind);
        assert!(res.is_ok());
        let received = res.unwrap();
        assert_eq!(received.header.protocol_version.0, 2);
    }

    #[test]
    fn test_reception_callback_updates_ldm() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let ldm = LdmFacility::new(415_520_000, 21_340_000, 50_000.0);
        let ldm_adapter = CABasicServiceLDM::new(ldm, 5);
        let crm = CAMReceptionManagement::new(btp_handle, coder.clone(), Some(ldm_adapter));

        let white_cam = generate_white_cam_static();
        let encoded = coder.encode(&white_cam).unwrap();
        let ind = make_test_indication(encoded);

        let res = crm.reception_callback(&ind);
        assert!(res.is_ok());
    }

    #[test]
    fn test_decode_exception_does_not_panic_or_call_callbacks() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let crm = CAMReceptionManagement::new(btp_handle, coder, None);

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);
        crm.add_application_callback(move |_, _| {
            called_clone.store(true, Ordering::SeqCst);
        });

        // Corrupted packet
        let ind = make_test_indication(vec![0xFF, 0xFF]);
        let res = crm.reception_callback(&ind);
        assert!(res.is_err());
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_application_callbacks_called_and_faulty_callback_isolated() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let crm = CAMReceptionManagement::new(btp_handle, coder.clone(), None);

        let count = Arc::new(AtomicUsize::new(0));

        let c1 = Arc::clone(&count);
        crm.add_application_callback(move |_, _| {
            c1.fetch_add(1, Ordering::SeqCst);
        });

        // Faulty callback that panics
        crm.add_application_callback(move |_, _| {
            panic!("Intentional test panic in callback");
        });

        let c2 = Arc::clone(&count);
        crm.add_application_callback(move |_, _| {
            c2.fetch_add(10, Ordering::SeqCst);
        });

        let white_cam = generate_white_cam_static();
        let encoded = coder.encode(&white_cam).unwrap();
        let ind = make_test_indication(encoded);

        let res = crm.reception_callback(&ind);
        assert!(res.is_ok());
        // Both non-panicking callbacks executed
        assert_eq!(count.load(Ordering::SeqCst), 11);
    }
}

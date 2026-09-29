// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Local Dynamic Map (LDM) adaptation for the CA Basic Service.
//!
//! Mirrors `CABasicServiceLDM` in
//! `flexstack/facilities/ca_basic_service/cam_ldm_adaptation.py`.
//!
//! Handles registration of the CAM data provider (ITS-AID 2) on IF.LDM.3
//! and ingestion of transmitted and received CAMs into the LDM store.

use super::cam_coder::Cam;
use crate::facilities::local_dynamic_map::{
    ldm_constants::{now_its_ms, ITS_AID_CAM},
    ldm_storage::ItsDataObject,
    ldm_types::{AddDataProviderReq, AddDataProviderResult, RegisterDataProviderReq},
    LdmHandle,
};

/// Default time validity for CAM records in the LDM (seconds).
pub const DEFAULT_CAM_TIME_VALIDITY_S: u32 = 5;

/// LDM adapter for the Cooperative Awareness Basic Service.
///
/// Simplifies registration and insertion of CAM data into the Local Dynamic Map.
#[derive(Clone)]
pub struct CABasicServiceLDM {
    pub ldm: LdmHandle,
    pub time_validity_s: u32,
}

/// Alias using standard Rust PascalCase convention.
pub type CaBasicServiceLdm = CABasicServiceLDM;

impl CABasicServiceLDM {
    /// Create and register a new CA Basic Service LDM adapter.
    ///
    /// Automatically registers the CAM provider (`ITS_AID_CAM = 2`) with the LDM.
    pub fn new(ldm: LdmHandle, time_validity_s: u32) -> Self {
        ldm.if_ldm_3
            .register_data_provider(RegisterDataProviderReq {
                application_id: ITS_AID_CAM,
            });

        CABasicServiceLDM {
            ldm,
            time_validity_s,
        }
    }

    /// Add a Cooperative Awareness Message to the LDM.
    ///
    /// Extracts the reference position (latitude, longitude, altitude) and
    /// stores the typed CAM object.
    ///
    /// Returns the assigned `record_id` on success, or an error description.
    pub fn add_provider_data_to_ldm(&self, cam: &Cam) -> Result<u64, String> {
        let ref_pos = &cam.cam.cam_parameters.basic_container.reference_position;
        let lat = ref_pos.latitude.0;
        let lon = ref_pos.longitude.0;
        let alt = ref_pos.altitude.altitude_value.0;

        let req = AddDataProviderReq {
            application_id: ITS_AID_CAM,
            timestamp_its: now_its_ms(),
            lat_etsi: lat,
            lon_etsi: lon,
            altitude_cm: alt / 10, // AltitudeValue is 0.01 m -> cm
            time_validity_s: self.time_validity_s,
            data_object: ItsDataObject::Cam(Box::new(cam.clone())),
        };

        let resp = self.ldm.if_ldm_3.add_provider_data(req);
        match resp.result {
            AddDataProviderResult::Succeed => resp
                .record_id
                .ok_or_else(|| "LDM returned Succeed without a record_id".to_string()),
            AddDataProviderResult::Failed => {
                Err("LDM add_provider_data returned Failed".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facilities::ca_basic_service::cam_coder::generate_white_cam_static;
    use crate::facilities::local_dynamic_map::LdmFacility;

    #[test]
    fn test_init_registers_data_provider() {
        let ldm = LdmFacility::new(415_520_000, 21_340_000, 5_000.0);
        let adapter = CABasicServiceLDM::new(ldm, 5);
        assert_eq!(adapter.time_validity_s, 5);
    }

    #[test]
    fn test_add_provider_data_to_ldm_success() {
        let ldm = LdmFacility::new(415_520_000, 21_340_000, 50_000.0);
        let adapter = CABasicServiceLDM::new(ldm, 5);
        let cam = generate_white_cam_static();

        let record_id = adapter
            .add_provider_data_to_ldm(&cam)
            .expect("should add CAM to LDM");
        assert!(record_id > 0);
    }
}

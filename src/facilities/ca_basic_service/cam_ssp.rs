// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CAM Service Specific Permissions (ETSI TS 103 900 V2.3.1 (2026-05),
//! clause 6.2.2.2).
//!
//! The SSP of a CAM Authorization Ticket is a BitmapSsp: octet 0 is the SSP
//! version, octets 1 and 2 hold one bit per protected CAM content (Table 3). A
//! CAM is consistent with the SSP when every protected content it carries has
//! its bit set.
//!
//! Mirrors `flexstack/facilities/ca_basic_service/cam_ssp.py`.

use super::cam_bindings::cam_pdu_descriptions::{
    HighFrequencyContainer, SpecialVehicleContainer, TwoWheelerTypeSpecificInformation,
};
use super::cam_bindings::etsi_its_cdd::TrafficRule;
use super::cam_coder::{Cam, CamCoder, ExtensionContainer, EXTENSION_CONTAINER_ID_TWO_WHEELER};

/// Station type `roadSideUnit` (ETSI TS 102 894-2).
pub const STATION_TYPE_ROAD_SIDE_UNIT: u8 = 15;
/// Table 3: the two-wheeler bits require an SSP version greater than 2.
pub const TWO_WHEELER_MIN_SSP_VERSION: u8 = 3;

/// One SSP permission: octet, bit mask and minimum SSP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    pub octet: usize,
    pub mask: u8,
    pub min_version: u8,
}

const fn perm(octet: usize, mask: u8, min_version: u8) -> Permission {
    Permission {
        octet,
        mask,
        min_version,
    }
}

/// Name of the special vehicle container of a vehicle role (clause 7.6), as
/// in the ASN.1 CHOICE; `None` for roles without a container.
pub fn role_special_container(vehicle_role: u8) -> Option<&'static str> {
    Some(match vehicle_role {
        1 => "publicTransportContainer",
        2 => "specialTransportContainer",
        3 => "dangerousGoodsContainer",
        4 => "roadWorksContainerBasic",
        5 => "rescueContainer",
        6 => "emergencyContainer",
        7 => "safetyCarContainer",
        _ => return None,
    })
}

/// ASN.1 alternative name of a special vehicle container.
pub fn special_container_name(container: &SpecialVehicleContainer) -> &'static str {
    match container {
        SpecialVehicleContainer::publicTransportContainer(_) => "publicTransportContainer",
        SpecialVehicleContainer::specialTransportContainer(_) => "specialTransportContainer",
        SpecialVehicleContainer::dangerousGoodsContainer(_) => "dangerousGoodsContainer",
        SpecialVehicleContainer::roadWorksContainerBasic(_) => "roadWorksContainerBasic",
        SpecialVehicleContainer::rescueContainer(_) => "rescueContainer",
        SpecialVehicleContainer::emergencyContainer(_) => "emergencyContainer",
        SpecialVehicleContainer::safetyCarContainer(_) => "safetyCarContainer",
        #[allow(unreachable_patterns)]
        _ => "unknown",
    }
}

/// SSP bits needed by the protected content of a CAM (Table 3). With a
/// coder, the TwoWheelerContainer is decoded for the `twoWheeler-cyclist` bit.
pub fn required_permissions(cam: &Cam, coder: Option<&CamCoder>) -> Vec<Permission> {
    let params = &cam.cam.cam_parameters;
    let mut needed = Vec::new();
    if let HighFrequencyContainer::rsuContainerHighFrequency(rsu) = &params.high_frequency_container
    {
        if params.basic_container.station_type.0 == STATION_TYPE_ROAD_SIDE_UNIT
            && rsu.protected_communication_zones_rsu.is_some()
        {
            needed.push(perm(1, 0x80, 0));
        }
    }
    if let Some(special) = &params.special_vehicle_container {
        let bit = match special {
            SpecialVehicleContainer::publicTransportContainer(_) => 0x40,
            SpecialVehicleContainer::specialTransportContainer(_) => 0x20,
            SpecialVehicleContainer::dangerousGoodsContainer(_) => 0x10,
            SpecialVehicleContainer::roadWorksContainerBasic(_) => 0x08,
            SpecialVehicleContainer::rescueContainer(_) => 0x04,
            SpecialVehicleContainer::emergencyContainer(_) => 0x02,
            SpecialVehicleContainer::safetyCarContainer(_) => 0x01,
            #[allow(unreachable_patterns)]
            _ => 0x00,
        };
        needed.push(perm(1, bit, 0));
        match special {
            SpecialVehicleContainer::roadWorksContainerBasic(c) if c.closed_lanes.is_some() => {
                needed.push(perm(2, 0x80, 0));
            }
            SpecialVehicleContainer::emergencyContainer(c) => {
                if let Some(priority) = &c.emergency_priority {
                    if priority.0[0] {
                        needed.push(perm(2, 0x40, 0)); // requestForRightOfWay
                    }
                    if priority.0[1] {
                        needed.push(perm(2, 0x20, 0)); // requestForFreeCrossingAtATrafficLight
                    }
                }
            }
            SpecialVehicleContainer::safetyCarContainer(c) => {
                match c.traffic_rule {
                    Some(TrafficRule::noPassing) => needed.push(perm(2, 0x10, 0)),
                    Some(TrafficRule::noPassingForTrucks) => needed.push(perm(2, 0x08, 0)),
                    _ => {}
                }
                if c.speed_limit.is_some() {
                    needed.push(perm(2, 0x04, 0));
                }
            }
            _ => {}
        }
    }
    if let Some(extensions) = &params.extension_containers {
        for container in extensions.0.iter() {
            if u8::try_from(&container.container_id.0) != Ok(EXTENSION_CONTAINER_ID_TWO_WHEELER) {
                continue;
            }
            needed.push(perm(2, 0x02, TWO_WHEELER_MIN_SSP_VERSION));
            if let Some(coder) = coder {
                if let Ok(ExtensionContainer::TwoWheeler(two_wheeler)) = coder
                    .decode_extension_container(
                        EXTENSION_CONTAINER_ID_TWO_WHEELER,
                        container.container_data.as_bytes(),
                    )
                {
                    if matches!(
                        two_wheeler.type_specific_information,
                        Some(TwoWheelerTypeSpecificInformation::cyclist(_))
                    ) {
                        needed.push(perm(2, 0x01, TWO_WHEELER_MIN_SSP_VERSION));
                    }
                }
            }
        }
    }
    needed
}

/// True when the SSP sets the bit. Bits defined for a later SSP version than
/// the SSP's own are not evaluated (they cannot be expressed).
pub fn ssp_permits(ssp: &[u8], permission: Permission) -> bool {
    let Some(&version) = ssp.first() else {
        return false;
    };
    if version < permission.min_version {
        return true;
    }
    permission.octet < ssp.len() && ssp[permission.octet] & permission.mask != 0
}

/// SSP check of a received CAM (clause 6.2.2.1): true when no SSP is
/// available or when every protected content of the CAM is permitted.
pub fn ssp_consistent(ssp: Option<&[u8]>, cam: &Cam, coder: Option<&CamCoder>) -> bool {
    match ssp {
        None | Some([]) => true,
        Some(ssp) => required_permissions(cam, coder)
            .into_iter()
            .all(|p| ssp_permits(ssp, p)),
    }
}

/// SSP bits a CAM needs (Table 3), as the `permissions` of the signing
/// request: the sign service only signs with an AT whose SSP grants them
/// (clause 6.2.2.1, TP/CAM/MSD/SSP/BO-02-X). Octet 0 (SSP version) is not
/// requested. The two-wheeler bits are requested whatever the SSP version of
/// the AT, so a CAM with a TwoWheelerContainer is only sent when the AT
/// grants them. With a coder, the `twoWheeler-cyclist` bit is derived too.
pub fn permissions_bitmap(cam: &Cam, coder: Option<&CamCoder>) -> Vec<u8> {
    let mut bitmap = vec![0u8; 3];
    for p in required_permissions(cam, coder) {
        bitmap[p.octet] |= p.mask;
    }
    if bitmap.iter().any(|b| *b != 0) {
        bitmap
    } else {
        vec![0]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! Mirrors tests/flexstack/facilities/ca_basic_service/test_cam_ssp.py.
    use super::super::cam_bindings::cam_pdu_descriptions::{
        DangerousGoodsContainer, EmergencyContainer, LowFrequencyContainer,
        PublicTransportContainer, RSUContainerHighFrequency, RescueContainer,
        RoadWorksContainerBasic, SafetyCarContainer, SpecialTransportContainer,
    };
    use super::super::cam_bindings::etsi_its_cdd::{
        ClosedLanes, DangerousGoodsBasic, EmbarkationStatus, EmergencyPriority, LightBarSirenInUse,
        ProtectedCommunicationZonesRSU, SpecialTransportType, SpeedLimit,
    };
    use super::super::cam_transmission::{CAMTransmissionManagement, VehicleData};
    use super::*;
    use crate::btp::service_access_point::BTPDataIndication;
    use crate::facilities::location_service::GpsFix;
    use crate::geonet::mib::Mib;
    use rasn::prelude::FixedBitString;

    pub(crate) fn siren() -> LightBarSirenInUse {
        LightBarSirenInUse(FixedBitString::<2>::default())
    }

    pub(crate) fn container(role: u8) -> SpecialVehicleContainer {
        match role {
            1 => SpecialVehicleContainer::publicTransportContainer(PublicTransportContainer::new(
                EmbarkationStatus(false),
                None,
            )),
            2 => {
                SpecialVehicleContainer::specialTransportContainer(SpecialTransportContainer::new(
                    SpecialTransportType(FixedBitString::<4>::default()),
                    siren(),
                ))
            }
            3 => SpecialVehicleContainer::dangerousGoodsContainer(DangerousGoodsContainer::new(
                DangerousGoodsBasic::explosives1,
            )),
            4 => SpecialVehicleContainer::roadWorksContainerBasic(RoadWorksContainerBasic::new(
                None,
                siren(),
                None,
            )),
            5 => SpecialVehicleContainer::rescueContainer(RescueContainer::new(siren())),
            6 => SpecialVehicleContainer::emergencyContainer(EmergencyContainer::new(
                siren(),
                None,
                None,
            )),
            _ => SpecialVehicleContainer::safetyCarContainer(SafetyCarContainer::new(
                siren(),
                None,
                None,
                None,
            )),
        }
    }

    pub(crate) fn vehicle(role: u8, special: Option<SpecialVehicleContainer>) -> VehicleData {
        VehicleData {
            station_id: 1,
            station_type: 5,
            vehicle_role: role,
            special_vehicle_data: special,
            ..VehicleData::default()
        }
    }

    /// First CAM generated by the CA service, as decoded from the wire.
    fn generated_cam(vd: VehicleData) -> Cam {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let ctm = CAMTransmissionManagement::new(btp_handle, coder.clone(), vd, None);
        let fix = GpsFix {
            latitude: 41.0,
            longitude: 2.0,
            altitude_m: 100.0,
            speed_mps: 5.0,
            heading_deg: 90.0,
            pai: true,
            fix_time_ms: None,
        };
        let cam = ctm.generate_and_send_cam(&fix, 1_000_000, 1).unwrap();
        coder.decode(&coder.encode(&cam).unwrap()).unwrap()
    }

    fn with_special(special: SpecialVehicleContainer) -> Cam {
        let mut cam = generated_cam(vehicle(0, None));
        cam.cam.cam_parameters.special_vehicle_container = Some(special);
        cam
    }

    /// Clause 7.6: the container of the vehicle role is sent.
    #[test]
    fn ina_each_role_sends_its_container() {
        for role in 1..=7u8 {
            let cam = generated_cam(vehicle(role, Some(container(role))));
            let params = &cam.cam.cam_parameters;
            let special = params.special_vehicle_container.as_ref().unwrap();
            assert_eq!(
                special_container_name(special),
                role_special_container(role).unwrap()
            );
            let Some(LowFrequencyContainer::basicVehicleContainerLowFrequency(lf)) =
                &params.low_frequency_container
            else {
                panic!("first CAM carries the LF container");
            };
            assert_eq!(lf.vehicle_role as u8, role);
        }
    }

    #[test]
    fn mismatched_container_is_rejected() {
        assert!(vehicle(6, Some(container(7))).validate().is_err());
        assert!(vehicle(0, Some(container(6))).validate().is_err());
        assert!(vehicle(9, Some(container(6))).validate().is_err());
        assert!(vehicle(6, Some(container(6))).validate().is_ok());
    }

    #[test]
    fn plain_vehicle_needs_no_permission() {
        let cam = generated_cam(vehicle(0, None));
        assert!(required_permissions(&cam, None).is_empty());
        assert!(ssp_consistent(Some(&[2, 0, 0]), &cam, None));
    }

    #[test]
    fn container_bits_of_octet_1() {
        let bits = [0x40u8, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
        for (role, bit) in (1..=7u8).zip(bits) {
            let cam = with_special(container(role));
            assert_eq!(required_permissions(&cam, None), vec![perm(1, bit, 0)]);
            assert!(ssp_consistent(Some(&[2, bit, 0]), &cam, None));
            assert!(!ssp_consistent(Some(&[2, 0xFF ^ bit, 0xFF]), &cam, None));
        }
    }

    #[test]
    fn octet_2_detailed_permissions() {
        let closed = with_special(SpecialVehicleContainer::roadWorksContainerBasic(
            RoadWorksContainerBasic::new(None, siren(), Some(ClosedLanes::new(None, None, None))),
        ));
        assert!(required_permissions(&closed, None).contains(&perm(2, 0x80, 0)));
        let mut both = FixedBitString::<2>::default();
        both.set(0, true);
        both.set(1, true);
        let priority = with_special(SpecialVehicleContainer::emergencyContainer(
            EmergencyContainer::new(siren(), None, Some(EmergencyPriority(both))),
        ));
        let needed = required_permissions(&priority, None);
        assert!(needed.contains(&perm(2, 0x40, 0)) && needed.contains(&perm(2, 0x20, 0)));
        let safety = with_special(SpecialVehicleContainer::safetyCarContainer(
            SafetyCarContainer::new(
                siren(),
                None,
                Some(TrafficRule::noPassing),
                Some(SpeedLimit(50)),
            ),
        ));
        let needed = required_permissions(&safety, None);
        assert!(needed.contains(&perm(2, 0x10, 0)) && needed.contains(&perm(2, 0x04, 0)));
        assert!(!ssp_consistent(Some(&[2, 0x01, 0x10]), &safety, None));
        assert!(ssp_consistent(Some(&[2, 0x01, 0x14]), &safety, None));
        let trucks = with_special(SpecialVehicleContainer::safetyCarContainer(
            SafetyCarContainer::new(siren(), None, Some(TrafficRule::noPassingForTrucks), None),
        ));
        assert!(required_permissions(&trucks, None).contains(&perm(2, 0x08, 0)));
    }

    #[test]
    fn rsu_protected_zones_bit() {
        let mut cam = generated_cam(vehicle(0, None));
        cam.cam.cam_parameters.basic_container.station_type.0 = STATION_TYPE_ROAD_SIDE_UNIT;
        cam.cam.cam_parameters.high_frequency_container =
            HighFrequencyContainer::rsuContainerHighFrequency(RSUContainerHighFrequency::new(
                Some(ProtectedCommunicationZonesRSU(Default::default())),
            ));
        assert_eq!(required_permissions(&cam, None), vec![perm(1, 0x80, 0)]);
    }

    #[test]
    fn two_wheeler_bits_need_ssp_version_3() {
        let cam = generated_cam(VehicleData {
            station_type: 2, // cyclist: the two-wheeler container is in every CAM
            ..vehicle(0, None)
        });
        let needed = required_permissions(&cam, Some(&CamCoder::new()));
        assert!(needed.contains(&perm(2, 0x02, TWO_WHEELER_MIN_SSP_VERSION)));
        assert!(ssp_consistent(Some(&[2, 0, 0]), &cam, None)); // not expressible in v2
        assert!(!ssp_consistent(Some(&[3, 0, 0]), &cam, None));
        assert!(ssp_consistent(Some(&[3, 0, 0x03]), &cam, None));
        // Sender side (clause 6.2.2.2): the two-wheeler bit is requested.
        assert_eq!(permissions_bitmap(&cam, None)[2] & 0x02, 0x02);
    }

    #[test]
    fn no_ssp_and_test_version() {
        let cam = with_special(container(6));
        assert!(ssp_consistent(None, &cam, None));
        assert!(ssp_consistent(Some(&[]), &cam, None));
        assert!(!ssp_consistent(Some(&[0]), &cam, None));
    }

    /// Sender-side SSP: the CA service requests the permissions its CAM needs.
    #[test]
    fn permissions_bitmap_of_protected_content() {
        assert_eq!(
            permissions_bitmap(&generated_cam(vehicle(0, None)), None),
            vec![0]
        );
        let emergency = generated_cam(vehicle(6, Some(container(6))));
        assert_eq!(permissions_bitmap(&emergency, None), vec![0, 0x02, 0]);
    }

    /// ETSI TS 103 097 clause 7.1.1: a secured CAM shall carry the CAM ITS-AID.
    #[test]
    fn reception_discards_secured_cam_with_another_its_aid() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let crm = super::super::cam_reception::CAMReceptionManagement::new(
            btp_handle,
            coder.clone(),
            None,
        );
        let data = coder
            .encode(&generated_cam(vehicle(6, Some(container(6)))))
            .unwrap();
        let indication = |aid: u64| BTPDataIndication {
            data: data.clone(),
            gn_permissions: Some(vec![2, 0x02, 0]),
            gn_its_aid: Some(aid),
            ..BTPDataIndication::new()
        };
        assert!(crm.reception_callback(&indication(37)).is_err());
        assert!(crm.reception_callback(&indication(36)).is_ok());
    }

    /// Clause 6.2.2.1: CAM not consistent with the signer's SSP is discarded.
    #[test]
    fn reception_discards_inconsistent_ssp() {
        let (btp_handle, _) = crate::btp::router::Router::spawn(Mib::new());
        let coder = CamCoder::new();
        let crm = super::super::cam_reception::CAMReceptionManagement::new(
            btp_handle,
            coder.clone(),
            None,
        );
        let data = coder
            .encode(&generated_cam(vehicle(6, Some(container(6)))))
            .unwrap();
        let indication = |ssp: Vec<u8>| BTPDataIndication {
            data: data.clone(),
            gn_permissions: Some(ssp),
            ..BTPDataIndication::new()
        };
        assert!(crm
            .reception_callback(&indication(vec![2, 0x01, 0]))
            .is_err());
        assert!(crm
            .reception_callback(&indication(vec![2, 0x02, 0]))
            .is_ok());
    }
}

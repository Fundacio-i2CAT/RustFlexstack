// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! CA basic service conformance tests: one test per Test Purpose of ETSI
//! TS 102 868-2 V2.1.1 (2025-07), against ETSI TS 103 900 V2.3.1 (2026-05).
//!
//! Each test is named after its TP and quotes the TP identifier, so that a
//! search for the identifier finds it. The tests drive a complete station
//! (CA basic service -> BTP -> GeoNetworking -> link layer) and check the
//! frames that leave the station, decoded from the wire. The CA service clock
//! is explicit; the T_CheckCamGen evaluation is run at each test instant.
//!
//! Mirrors `tests/flexstack/facilities/ca_basic_service/test_cam_conformance.py`.

use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::cam_bindings::cam_pdu_descriptions::EmergencyContainer;
use super::cam_bindings::cam_pdu_descriptions::{
    BasicVehicleContainerHighFrequency, BasicVehicleContainerLowFrequency, HighFrequencyContainer,
    LowFrequencyContainer, RSUContainerHighFrequency, RoadWorksContainerBasic, SafetyCarContainer,
    SpecialVehicleContainer,
};
use super::cam_bindings::etsi_its_cdd::{
    ClosedLanes, CurvatureConfidence, DriveDirection, EmergencyPriority, Latitude, Longitude,
    ProtectedCommunicationZone, ProtectedCommunicationZonesRSU, ProtectedZoneType, SpeedLimit,
    TrafficRule, YawRateConfidence,
};
use super::cam_coder::{
    CamCoder, ExtensionContainer, EXTENSION_CONTAINER_ID_TWO_WHEELER, EXTENSION_CONTAINER_ID_VLF,
};
use super::cam_ssp::tests::{container, siren, vehicle};
use super::cam_transmission::{
    VehicleData, ACCELERATION_CONTROL_BITS, EXTERIOR_LIGHTS_BITS, T_GEN_CAM_MAX_MS,
    T_GEN_CAM_MIN_MS,
};
use super::{Cam, CooperativeAwarenessBasicService};
use crate::btp::router::{BTPRouterHandle, Router as BtpRouter};
use crate::btp::service_access_point::BTPDataIndication;
use crate::facilities::local_dynamic_map::ldm_constants::ITS_AID_CAM;
use crate::facilities::local_dynamic_map::ldm_types::{
    RegisterDataConsumerReq, RequestDataObjectsReq,
};
use crate::facilities::local_dynamic_map::{LdmFacility, LdmHandle};
use crate::facilities::location_service::GpsFix;
use crate::geonet::basic_header::{BasicHeader, BasicNH};
use crate::geonet::common_header::CommonHeader;
use crate::geonet::gn_address::{GNAddress, M, MID, ST};
use crate::geonet::mib::{GnSecurity, Mib};
use crate::geonet::position_vector::{LongPositionVector, Tst};
use crate::geonet::router::Router as GnRouter;
use crate::geonet::service_access_point::{
    CommonNH, GNDataIndication, GNDataRequest, HeaderSubType, HeaderType, TopoBroadcastHST,
    TrafficClass,
};
use crate::security::certificate::OwnCertificate;
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::security_asn::ieee1609_dot2::{
    HeaderInfo, SequenceOfCertificate, SignerIdentifier,
};
use crate::security::security_asn::ieee1609_dot2_base_types::{
    BitmapSsp, Duration as AsnDuration, Psid, PsidSsp, SequenceOfPsidSsp,
    ServiceSpecificPermissions, Time64, Uint16, Uint64,
};
use crate::security::sign_service::SignService;
use crate::security::time_service::timestamp_its_microseconds;
use crate::security::verify_service::security_checks::{at_tbs, ca_tbs};
use rasn::prelude::{FixedBitString, Integer};

const LAT: f64 = 41.552;
const LON: f64 = 2.134;
const STATION_CYCLIST: u8 = 2;
const STATION_MOPED: u8 = 3;
const STATION_MOTORCYCLE: u8 = 4;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn addr(n: u8) -> GNAddress {
    GNAddress::new(M::GnUnicast, ST::Unknown, MID::new([2, 0, 0, 0, 0, n]))
}

fn fix() -> GpsFix {
    GpsFix {
        latitude: LAT,
        longitude: LON,
        altitude_m: 100.0,
        speed_mps: 5.0,
        heading_deg: 90.0,
        pai: true,
        fix_time_ms: None,
    }
}

/// A GeoNetworking SHB frame carrying a CAM, decoded from the wire.
struct Frame {
    raw: Vec<u8>,
    basic: BasicHeader,
    common: CommonHeader,
    destination_port: u16,
    cam: Cam,
}

impl Frame {
    fn decode(raw: &[u8]) -> Frame {
        Frame {
            raw: raw.to_vec(),
            basic: BasicHeader::decode(raw[0..4].try_into().unwrap()),
            common: CommonHeader::decode(raw[4..12].try_into().unwrap()),
            destination_port: u16::from_be_bytes([raw[40], raw[41]]),
            // fails if the CAM is not valid UPER
            cam: CamCoder::new().decode(&raw[44..]).expect("valid CAM"),
        }
    }

    fn hf(&self) -> &BasicVehicleContainerHighFrequency {
        match &self.cam.cam.cam_parameters.high_frequency_container {
            HighFrequencyContainer::basicVehicleContainerHighFrequency(hf) => hf,
            _ => panic!("expected basicVehicleContainerHighFrequency"),
        }
    }

    fn lf(&self) -> Option<&BasicVehicleContainerLowFrequency> {
        match &self.cam.cam.cam_parameters.low_frequency_container {
            Some(LowFrequencyContainer::basicVehicleContainerLowFrequency(lf)) => Some(lf),
            _ => None,
        }
    }

    fn special(&self) -> Option<&SpecialVehicleContainer> {
        self.cam
            .cam
            .cam_parameters
            .special_vehicle_container
            .as_ref()
    }

    fn extension(&self, id: u8) -> Option<ExtensionContainer> {
        let containers = self.cam.cam.cam_parameters.extension_containers.as_ref()?;
        containers
            .0
            .iter()
            .find(|c| u8::try_from(&c.container_id.0).ok() == Some(id))
            .map(|c| {
                CamCoder::new()
                    .decode_extension_container(id, c.container_data.as_bytes())
                    .expect("valid extension container")
            })
    }
}

/// A complete ITS-S: CA basic service on BTP on GeoNetworking, with the link
/// layer captured. `tick(at_ms)` runs the T_CheckCamGen evaluation at
/// `base + at_ms`.
struct Station {
    gn: GnRouter,
    ll_rx: Receiver<Vec<u8>>,
    gn_btp_rx: Receiver<GNDataIndication>,
    btp: BTPRouterHandle,
    btp_gn_rx: Receiver<GNDataRequest>,
    port_rx: Receiver<BTPDataIndication>,
    ca: CooperativeAwarenessBasicService,
    received: Arc<Mutex<Vec<Cam>>>,
    ldm: LdmHandle,
    fix: GpsFix,
    base_ms: u64,
    times: Vec<u64>,
    sent: Vec<Vec<u8>>,
}

impl Station {
    fn new(vd: VehicleData) -> Station {
        Station::build(vd, 1, None, None)
    }

    fn build(
        vd: VehicleData,
        n: u8,
        sign: Option<SignService>,
        verify: Option<(EcdsaBackend, CertificateLibrary)>,
    ) -> Station {
        let mut mib = Mib::new();
        mib.itsGnBeaconServiceRetransmitTimer = 0;
        mib.itsGnLocalGnAddr = addr(n);
        if sign.is_some() || verify.is_some() {
            mib.itsGnSecurity = GnSecurity::Enabled;
        }
        let (ll_tx, ll_rx) = mpsc::channel();
        let (gn_btp_tx, gn_btp_rx) = mpsc::channel();
        let (backend, library) = verify.unzip();
        let mut gn = GnRouter::new(mib, ll_tx, gn_btp_tx, sign, backend, library);
        gn.ego_position_vector.latitude = (LAT * 1e7) as i32 as u32;
        gn.ego_position_vector.longitude = (LON * 1e7) as i32 as u32;
        gn.ego_position_vector.pai = true;
        gn.ego_position_vector.tst = Tst::set_in_normal_timestamp_milliseconds(now_ms());
        let (btp, btp_gn_rx) = BtpRouter::spawn(mib);
        let ldm = LdmFacility::new((LAT * 1e7) as i32, (LON * 1e7) as i32, 5_000.0);
        ldm.if_ldm_4
            .register_data_consumer(RegisterDataConsumerReq {
                application_id: ITS_AID_CAM,
            });
        let (ca, _cam_rx) =
            CooperativeAwarenessBasicService::new(btp.clone(), vd, Some(ldm.clone()));
        let (port_tx, port_rx) = mpsc::channel();
        btp.register_port(2001, port_tx);
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        ca.add_application_callback(move |cam: &Cam, _ts| sink.lock().unwrap().push(cam.clone()));
        Station {
            gn,
            ll_rx,
            gn_btp_rx,
            btp,
            btp_gn_rx,
            port_rx,
            ca,
            received,
            ldm,
            fix: fix(),
            base_ms: now_ms(),
            times: vec![],
            sent: vec![],
        }
    }

    /// CA_Activation (TS 103 900 clause 5.3.1); the timer thread is not used.
    fn activate(&self) {
        self.ca.cam_transmission_management.start();
    }

    /// Run the T_CheckCamGen evaluation at `at_ms`; returns the new frame (raw), if any.
    fn tick(&mut self, at_ms: u64, update: impl FnOnce(&mut GpsFix)) -> Option<Vec<u8>> {
        update(&mut self.fix);
        self.ca.location_service_callback(self.fix);
        self.ca
            .cam_transmission_management
            .evaluate_and_maybe_send(self.base_ms + at_ms)?;
        let request = self
            .btp_gn_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("BTP request for the CAM");
        self.gn.gn_data_request(request);
        let raw = self.ll_rx.try_recv().ok()?;
        self.times.push(at_ms);
        self.sent.push(raw.clone());
        Some(raw)
    }

    fn cam_at(&mut self, at_ms: u64, update: impl FnOnce(&mut GpsFix)) -> Frame {
        Frame::decode(&self.tick(at_ms, update).expect("a CAM is sent"))
    }

    /// Pass a received frame up the stack: GN -> BTP -> CA reception.
    fn receive(&mut self, raw: &[u8]) {
        self.gn.process_basic_header(raw);
        if let Ok(indication) = self.gn_btp_rx.try_recv() {
            self.btp.send_gn_data_indication(indication);
            if let Ok(btp) = self.port_rx.recv_timeout(Duration::from_secs(2)) {
                let _ = self.ca.cam_reception_management.reception_callback(&btp);
            }
        }
    }

    fn received(&self) -> usize {
        self.received.lock().unwrap().len()
    }

    fn ldm_cams(&self) -> usize {
        self.ldm
            .if_ldm_4
            .request_data_objects(RequestDataObjectsReq {
                application_id: ITS_AID_CAM,
                data_object_types: vec![ITS_AID_CAM],
                filter: None,
                order: None,
                max_results: None,
            })
            .data_objects
            .len()
    }

    fn intervals(&self) -> Vec<u64> {
        self.times.windows(2).map(|w| w[1] - w[0]).collect()
    }
}

fn no_change(_: &mut GpsFix) {}

fn heading(deg: f64) -> impl FnOnce(&mut GpsFix) {
    move |f: &mut GpsFix| f.heading_deg = deg
}

fn two_wheeler(station_type: u8) -> VehicleData {
    VehicleData {
        station_type,
        vehicle_length_value: 20,
        vehicle_width: 8,
        ..vehicle(0, None)
    }
}

fn bit<const N: usize>(bits: &FixedBitString<N>, position: usize) -> bool {
    bits[position]
}

// ── TP/CAM/MSD/FMT: CAM format and container inclusion ──────────────────────

/// TP/CAM/MSD/FMT/BV-01: protocolVersion 2 and messageID 2 in the ITS PDU header.
#[test]
fn tp_cam_msd_fmt_bv_01() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    let frame = station.cam_at(0, no_change);
    assert_eq!(frame.cam.header.protocol_version.0, 2);
    assert_eq!(frame.cam.header.message_id.0, 2);
}

/// TP/CAM/MSD/FMT/BV-02: the first CAM since activation contains the LF container.
#[test]
fn tp_cam_msd_fmt_bv_02() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    let frame = station.cam_at(0, no_change);
    assert_eq!(station.sent.len(), 1);
    assert!(frame.lf().is_some());
}

/// TP/CAM/MSD/FMT/BV-03: LF container again when >= 500 ms elapsed since the
/// last CAM with it (and not before).
#[test]
fn tp_cam_msd_fmt_bv_03() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    assert!(station.cam_at(0, no_change).lf().is_some()); // TIME_1
    for step in 1..5u64 {
        let frame = station.cam_at(step * 100, heading(90.0 + 5.0 * step as f64));
        assert!(frame.lf().is_none(), "{step}");
    }
    assert!(station.cam_at(500, heading(120.0)).lf().is_some()); // TIME_1 + 500 ms
}

/// TP/CAM/MSD/FMT/BV-04: a special vehicle's first CAM contains the special vehicle container.
#[test]
fn tp_cam_msd_fmt_bv_04() {
    for role in 1..=7u8 {
        let mut station = Station::new(vehicle(role, Some(container(role))));
        station.activate();
        let frame = station.cam_at(0, no_change);
        assert_eq!(frame.special(), Some(&container(role)), "role {role}");
    }
}

/// TP/CAM/MSD/FMT/BV-05: special vehicle container again when >= 500 ms
/// elapsed since the last CAM with it (and not before).
#[test]
fn tp_cam_msd_fmt_bv_05() {
    let mut station = Station::new(vehicle(6, Some(container(6))));
    station.activate();
    assert!(station.cam_at(0, no_change).special().is_some());
    for step in 1..5u64 {
        let frame = station.cam_at(step * 100, heading(90.0 + 5.0 * step as f64));
        assert!(frame.special().is_none(), "{step}");
    }
    assert!(station.cam_at(500, heading(120.0)).special().is_some());
}

/// TP/CAM/MSD/FMT/BV-06: the second CAM since activation contains the VLF
/// extension container (containerId 3); the first does not.
#[test]
fn tp_cam_msd_fmt_bv_06() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    assert!(station
        .cam_at(0, no_change)
        .extension(EXTENSION_CONTAINER_ID_VLF)
        .is_none());
    let frame = station.cam_at(100, heading(95.0));
    assert!(matches!(
        frame.extension(EXTENSION_CONTAINER_ID_VLF),
        Some(ExtensionContainer::VeryLowFrequency(_))
    ));
}

/// TP/CAM/MSD/FMT/BV-07: VLF container again when >= 10 s elapsed since the
/// last CAM with it and the CAM carries neither the LF nor the special
/// vehicle container.
#[test]
fn tp_cam_msd_fmt_bv_07() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    let mut vlf_times = vec![];
    for step in 0..106u64 {
        let frame = station.cam_at(step * 100, heading((90.0 + 5.0 * step as f64) % 360.0));
        if frame.extension(EXTENSION_CONTAINER_ID_VLF).is_some() {
            vlf_times.push(step * 100);
            if step > 1 {
                assert!(frame.lf().is_none());
                assert!(frame.special().is_none());
            }
        }
    }
    assert_eq!(vlf_times[0], 100); // TIME_1 (second CAM)
    assert_eq!(vlf_times.len(), 2);
    assert!(vlf_times[1] - vlf_times[0] >= 10_000);
}

/// TP/CAM/MSD/FMT/BV-08 (both TPs with this identifier, variants cyclist,
/// moped, motorcycle): the first and the following CAMs contain the
/// TwoWheelerContainer (containerId 1); a passenger car does not send it.
#[test]
fn tp_cam_msd_fmt_bv_08() {
    for station_type in [STATION_CYCLIST, STATION_MOPED, STATION_MOTORCYCLE] {
        let mut station = Station::new(two_wheeler(station_type));
        station.activate();
        for frame in [
            station.cam_at(0, no_change),
            station.cam_at(100, heading(95.0)),
        ] {
            assert!(matches!(
                frame.extension(EXTENSION_CONTAINER_ID_TWO_WHEELER),
                Some(ExtensionContainer::TwoWheeler(_))
            ));
            assert_eq!(
                frame.cam.cam.cam_parameters.basic_container.station_type.0,
                station_type
            );
        }
    }
    let mut car = Station::new(vehicle(0, None));
    car.activate();
    assert!(car
        .cam_at(0, no_change)
        .extension(EXTENSION_CONTAINER_ID_TWO_WHEELER)
        .is_none());
}

// ── TP/CAM/MSD/INA: in-vehicle data and special vehicle containers ──────────

/// CAM at 0 ms, alert, CAM at 600 ms (LF container due again).
fn next_cam(
    station: &mut Station,
    alert: impl FnOnce(&mut super::cam_transmission::InVehicleData),
) -> Frame {
    station.activate();
    station.cam_at(0, no_change);
    station.ca.update_in_vehicle_data(alert).unwrap();
    station.cam_at(600, heading(100.0))
}

/// TP/CAM/MSD/INA/BV-01-X (variants 01-35): after the IUT is alerted about
/// new in-vehicle data, the next CAM carries the latest value.
#[test]
fn tp_cam_msd_ina_bv_01_x() {
    // 01: curvature
    let mut station = Station::new(vehicle(0, None));
    let frame = next_cam(&mut station, |d| {
        d.curvature_value = -30;
        d.curvature_confidence = CurvatureConfidence::onePerMeter_0_0001;
    });
    assert_eq!(frame.hf().curvature.curvature_value.0, -30);
    assert_eq!(
        frame.hf().curvature.curvature_confidence,
        CurvatureConfidence::onePerMeter_0_0001
    );
    // 02-15: accelerationControl bits engaged / disengaged
    for (i, name) in ACCELERATION_CONTROL_BITS.iter().enumerate() {
        for on in [true, false] {
            let variant = 2 + 2 * i + usize::from(!on);
            let mut station = Station::new(vehicle(0, None));
            station
                .ca
                .update_in_vehicle_data(|d| {
                    let mut bits = [false; 7];
                    bits[i] = !on;
                    d.acceleration_control = Some(bits);
                })
                .unwrap();
            let frame = next_cam(&mut station, |d| {
                let mut bits = [false; 7];
                bits[i] = on;
                d.acceleration_control = Some(bits);
            });
            let control = frame.hf().acceleration_control.as_ref().unwrap();
            assert_eq!(bit(&control.0, i), on, "variant {variant:02} {name}");
        }
    }
    // 16-31: exteriorLights bits on / off (LF container)
    for (i, name) in EXTERIOR_LIGHTS_BITS.iter().enumerate() {
        for on in [true, false] {
            let variant = 16 + 2 * i + usize::from(!on);
            let mut station = Station::new(vehicle(0, None));
            station
                .ca
                .update_in_vehicle_data(|d| {
                    let mut bits = [false; 8];
                    bits[i] = !on;
                    d.exterior_lights = Some(bits);
                })
                .unwrap();
            let frame = next_cam(&mut station, |d| {
                let mut bits = [false; 8];
                bits[i] = on;
                d.exterior_lights = Some(bits);
            });
            let lights = &frame.lf().expect("LF container").exterior_lights;
            assert_eq!(bit(&lights.0, i), on, "variant {variant:02} {name}");
        }
    }
    // 32: heading, 33: speed (from the position service)
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    station.cam_at(0, no_change);
    let frame = station.cam_at(600, |f| {
        f.heading_deg = 123.4;
        f.speed_mps = 17.25;
    });
    assert_eq!(frame.hf().heading.heading_value.0, 1234);
    assert_eq!(frame.hf().speed.speed_value.0, 1725);
    // 34: drive direction
    let frame = next_cam(&mut Station::new(vehicle(0, None)), |d| {
        d.drive_direction = Some(DriveDirection::backward)
    });
    assert_eq!(frame.hf().drive_direction, DriveDirection::backward);
    // 35: yaw rate
    let frame = next_cam(&mut Station::new(vehicle(0, None)), |d| {
        d.yaw_rate_value = -150;
        d.yaw_rate_confidence = YawRateConfidence::degSec_001_00;
    });
    assert_eq!(frame.hf().yaw_rate.yaw_rate_value.0, -150);
    assert_eq!(
        frame.hf().yaw_rate.yaw_rate_confidence,
        YawRateConfidence::degSec_001_00
    );
}

fn special(role: u8) {
    let mut station = Station::new(vehicle(role, Some(container(role))));
    station.activate();
    let frame = station.cam_at(0, no_change);
    assert_eq!(frame.lf().unwrap().vehicle_role as u8, role);
    assert_eq!(frame.special(), Some(&container(role)));
}

/// TP/CAM/MSD/INA/BV-02: vehicleRole publicTransport(1) -> publicTransportContainer.
#[test]
fn tp_cam_msd_ina_bv_02() {
    special(1);
}

/// TP/CAM/MSD/INA/BV-03: vehicleRole specialTransport(2) -> specialTransportContainer.
#[test]
fn tp_cam_msd_ina_bv_03() {
    special(2);
}

/// TP/CAM/MSD/INA/BV-04: vehicleRole dangerousGoods(3) -> dangerousGoodsContainer.
#[test]
fn tp_cam_msd_ina_bv_04() {
    special(3);
}

/// TP/CAM/MSD/INA/BV-05: vehicleRole roadWork(4) -> roadWorksContainerBasic.
#[test]
fn tp_cam_msd_ina_bv_05() {
    special(4);
}

/// TP/CAM/MSD/INA/BV-06: vehicleRole rescue(5) -> rescueContainer.
#[test]
fn tp_cam_msd_ina_bv_06() {
    special(5);
}

/// TP/CAM/MSD/INA/BV-07: vehicleRole emergency(6) -> emergencyContainer.
#[test]
fn tp_cam_msd_ina_bv_07() {
    special(6);
}

/// TP/CAM/MSD/INA/BV-08: vehicleRole safetyCar(7) -> safetyCarContainer.
#[test]
fn tp_cam_msd_ina_bv_08() {
    special(7);
}

// ── TP/CAM/MSD/GFQ: CAM generation frequency ────────────────────────────────

/// TP/CAM/MSD/GFQ/TI-01: no CAM before T_GenCamMin (100 ms), even when the
/// dynamics change at every 10 ms evaluation.
#[test]
fn tp_cam_msd_gfq_ti_01() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    for step in 0..200u64 {
        station.tick(step * 10, heading((90.0 + 10.0 * step as f64) % 360.0));
    }
    assert!(station.times.len() > 10);
    assert!(*station.intervals().iter().min().unwrap() >= T_GEN_CAM_MIN_MS);
}

/// TP/CAM/MSD/GFQ/TI-02: another CAM by T_GenCamMax (1000 ms) when nothing changes.
#[test]
fn tp_cam_msd_gfq_ti_02() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    for step in 0..500u64 {
        station.tick(step * 10, no_change);
    }
    assert!(station.times.len() > 3);
    assert!(*station.intervals().iter().max().unwrap() <= T_GEN_CAM_MAX_MS);
}

/// TP/CAM/MSD/GFQ/TI-03: after a CAM at TIME_1, a CAM due to condition 1 at
/// TIME_1 + INTERVAL_1 and N_GenCam - 1 (= 2) subsequent CAMs every
/// INTERVAL_1 (due to condition 2), the next CAM (the N_GenCam-th due to
/// condition 2) sets T_GenCam to T_GenCamMax: the following CAM comes
/// T_GenCamMax later.
#[test]
fn tp_cam_msd_gfq_ti_03() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    station.tick(0, no_change); // TIME_1
    assert!(station.tick(200, heading(100.0)).is_some()); // condition 1, INTERVAL_1 = 200 ms
    for step in 21..200u64 {
        station.tick(step * 10, no_change);
    }
    assert_eq!(station.times[..6], [0, 200, 400, 600, 800, 1800]);
}

/// CAM at 0; the IUT is alerted at 50 ms; with T_GenCam_DCC = 100 ms and then
/// 300 ms the CAM is sent as soon as T_GenCam_DCC expires. `unchanged` (at
/// the threshold) does not trigger a CAM.
fn condition_1(change: fn(&mut GpsFix), unchanged: fn(&mut GpsFix)) {
    for dcc_ms in [100u64, 300] {
        let mut station = Station::new(vehicle(0, None));
        station.activate();
        station.ca.set_t_gen_cam_dcc(dcc_ms);
        station.tick(0, no_change);
        for step in 5..40u64 {
            station.tick(step * 10, change);
        }
        assert_eq!(station.times[1], dcc_ms, "T_GenCam_DCC {dcc_ms}");
    }
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    station.tick(0, no_change);
    for step in 1..99u64 {
        station.tick(step * 10, unchanged);
    }
    assert_eq!(station.times, vec![0]);
}

/// TP/CAM/MSD/GFQ/BV-04: heading change > 4 deg -> CAM when T_GenCam_DCC expires.
#[test]
fn tp_cam_msd_gfq_bv_04() {
    condition_1(|f| f.heading_deg = 94.5, |f| f.heading_deg = 94.0);
}

/// TP/CAM/MSD/GFQ/BV-05: position change > 4 m -> CAM when T_GenCam_DCC expires.
#[test]
fn tp_cam_msd_gfq_bv_05() {
    condition_1(
        |f| f.latitude = LAT + 4.5 / 111_195.0,
        |f| f.latitude = LAT + 3.9 / 111_195.0,
    );
}

/// TP/CAM/MSD/GFQ/BV-06: speed change > 0,5 m/s -> CAM when T_GenCam_DCC expires.
#[test]
fn tp_cam_msd_gfq_bv_06() {
    condition_1(|f| f.speed_mps = 5.6, |f| f.speed_mps = 5.5);
}

/// TP/CAM/MSD/GFQ/TI-07: without dynamics a CAM is sent when both T_GenCam
/// and T_GenCam_DCC have expired: at T_GenCam = 1000 ms with T_GenCam_DCC =
/// 100 ms, and at T_GenCam_DCC = 500 ms when T_GenCam = 200 ms.
#[test]
fn tp_cam_msd_gfq_ti_07() {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    for step in 0..150u64 {
        station.tick(step * 10, no_change);
    }
    assert_eq!(station.times[..2], [0, 1000]);
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    station.tick(0, no_change);
    station.tick(200, heading(100.0)); // T_GenCam = 200 ms
    station.ca.set_t_gen_cam_dcc(500);
    for step in 21..100u64 {
        station.tick(step * 10, no_change);
    }
    assert_eq!(station.times[..3], [0, 200, 700]);
}

// ── TP/CAM/MSD/PAR: CAM transport ────────────────────────────────────────────

fn first_frame() -> Frame {
    let mut station = Station::new(vehicle(0, None));
    station.activate();
    station.cam_at(0, no_change)
}

/// TP/CAM/MSD/PAR/BV-01: CAM encapsulated in a BTP-B packet (destination port 2001).
#[test]
fn tp_cam_msd_par_bv_01() {
    let frame = first_frame();
    assert_eq!(frame.common.nh, CommonNH::BtpB);
    assert_eq!(frame.destination_port, 2001);
}

/// TP/CAM/MSD/PAR/BV-02: CAM encapsulated in a SHB packet.
#[test]
fn tp_cam_msd_par_bv_02() {
    let frame = first_frame();
    assert_eq!(frame.common.ht, HeaderType::Tsb);
    assert_eq!(
        frame.common.hst,
        HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop)
    );
    assert_eq!((frame.basic.rhl, frame.common.mhl), (1, 1));
}

/// TP/CAM/MSD/PAR/BV-03: Basic Header lifetime less than 1 s.
#[test]
fn tp_cam_msd_par_bv_03() {
    let frame = first_frame();
    assert!(matches!(frame.basic.nh, BasicNH::CommonHeader));
    assert!(frame.basic.lt.get_value_in_milliseconds() < 1000);
}

// ── Security (SSP) and reception ─────────────────────────────────────────────

/// Root and AA; ATs with a chosen CAM SSP.
pub(crate) struct Pki {
    pub(crate) backend: EcdsaBackend,
    root: OwnCertificate,
    aa: OwnCertificate,
}

impl Pki {
    pub(crate) fn new() -> Pki {
        let mut backend = EcdsaBackend::new();
        let root = OwnCertificate::initialize_self_signed(&mut backend, ca_tbs());
        let aa = OwnCertificate::initialize_issued(&mut backend, ca_tbs(), &root);
        Pki { backend, root, aa }
    }

    /// AT with the given (PSID, SSP) app permissions.
    pub(crate) fn at(&mut self, permissions: &[(u64, Option<Vec<u8>>)]) -> OwnCertificate {
        let mut tbs = at_tbs(-60, AsnDuration::hours(Uint16(1)), None);
        tbs.app_permissions = Some(SequenceOfPsidSsp(
            permissions
                .iter()
                .map(|(psid, ssp)| {
                    PsidSsp::new(
                        Psid(Integer::from(*psid)),
                        ssp.as_ref().map(|s| {
                            ServiceSpecificPermissions::bitmapSsp(BitmapSsp(s.clone().into()))
                        }),
                    )
                })
                .collect(),
        ));
        OwnCertificate::initialize_issued(&mut self.backend, tbs, &self.aa)
    }

    pub(crate) fn library(&self) -> CertificateLibrary {
        CertificateLibrary::new(
            &self.backend,
            vec![self.root.cert.clone()],
            vec![self.aa.cert.clone()],
            vec![],
        )
    }

    pub(crate) fn sign_service(&self, at: OwnCertificate) -> SignService {
        let mut svc = SignService::new(self.backend.clone(), self.library());
        svc.add_own_certificate(at);
        svc
    }

    fn receiver(&self) -> Station {
        Station::build(
            vehicle(0, None),
            2,
            None,
            Some((self.backend.clone(), self.library())),
        )
    }

    /// Secured SHB carrying `cam`, signed with `at` regardless of its permissions.
    pub(crate) fn secured_shb(&self, at: &OwnCertificate, cam: &[u8]) -> Vec<u8> {
        let common = CommonHeader {
            nh: CommonNH::BtpB,
            reserved: 0,
            ht: HeaderType::Tsb,
            hst: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            tc: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            flags: 0,
            pl: 4 + cam.len() as u16,
            mhl: 1,
            reserved2: 0,
        };
        let so = LongPositionVector {
            gn_addr: addr(9),
            tst: Tst::set_in_normal_timestamp_milliseconds(now_ms()),
            latitude: (LAT * 1e7) as i32 as u32,
            longitude: (LON * 1e7) as i32 as u32,
            pai: true,
            s: 0,
            h: 0,
        };
        let mut body = common.encode().to_vec();
        body.extend_from_slice(&so.encode());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&[0x07, 0xD1, 0, 0]);
        body.extend_from_slice(cam);
        let header = HeaderInfo::new(
            Psid(Integer::from(36)),
            Some(Time64(Uint64(timestamp_its_microseconds()))),
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
        let signer =
            SignerIdentifier::certificate(SequenceOfCertificate(vec![at.cert.inner.0.clone()]));
        let secured = SignService::new(self.backend.clone(), self.library())
            .build_signed_data(&body, header, signer, at);
        let mut frame = BasicHeader::initialize_with_mib(&Mib::new())
            .set_rhl(1)
            .set_nh(BasicNH::SecuredPacket)
            .encode()
            .to_vec();
        frame.extend_from_slice(&secured);
        frame
    }
}

fn cam_ssp(octet1: u8, octet2: u8, version: u8) -> Vec<(u64, Option<Vec<u8>>)> {
    vec![(36, Some(vec![version, octet1, octet2]))]
}

/// TP/CAM/MSD/SSP/BO-02-X (variant 01): the IUT does not send a CAM with a
/// TwoWheelerContainer when its AT's CAM SSP has the twoWheeler bit (octet
/// 2, 02h) at 0. TS 103 900 V2.3.1 Table 3 defines this bit for SSP versions
/// greater than 2, so the AT uses SSP version 3 (the TP, older, says version
/// 2). Variant 02 (cyclist type information) is not generated by the stacks.
#[test]
fn tp_cam_msd_ssp_bo_02_x() {
    for (granted, sent) in [(0x00u8, false), (0x02, true)] {
        let mut pki = Pki::new();
        let at = pki.at(&cam_ssp(0, granted, 3));
        let sign = pki.sign_service(at);
        let mut station = Station::build(two_wheeler(STATION_CYCLIST), 1, Some(sign), None);
        station.activate();
        station.tick(0, no_change);
        assert_eq!(
            station.sent.len(),
            usize::from(sent),
            "octet 2 {granted:#04x}"
        );
    }
}

/// TP/CAM/MSP/BV-01: a received valid CAM is passed to the applications and
/// to the other facilities (LDM).
#[test]
fn tp_cam_msp_bv_01() {
    let mut sender = Station::new(vehicle(0, None));
    sender.activate();
    let frame = sender.cam_at(0, no_change);
    let mut receiver = Station::build(vehicle(0, None), 2, None, None);
    receiver.receive(&frame.raw);
    let received = receiver.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], frame.cam);
    assert_eq!(receiver.ldm_cams(), 1);
}

fn cam_bytes(vd: VehicleData) -> Vec<u8> {
    let mut station = Station::new(vd);
    station.activate();
    station.tick(0, no_change).unwrap()[44..].to_vec()
}

/// TP/CAM/MSP/SSP/BV-02: a secured CAM whose signing AT has no CAM ITS-AID in
/// its appPermissions is discarded (not passed to applications nor to the
/// LDM); the same CAM signed with an AT permitting it is accepted.
#[test]
fn tp_cam_msp_ssp_bv_02() {
    let mut pki = Pki::new();
    let cam = cam_bytes(vehicle(0, None));
    for (permissions, accepted) in [(vec![(37u64, None)], false), (cam_ssp(0, 0, 2), true)] {
        let at = pki.at(&permissions);
        let mut receiver = pki.receiver();
        receiver.receive(&pki.secured_shb(&at, &cam));
        assert_eq!(receiver.received(), usize::from(accepted));
        assert_eq!(receiver.ldm_cams(), usize::from(accepted));
    }
}

fn special_cam(role: u8, special: SpecialVehicleContainer) -> Vec<u8> {
    cam_bytes(vehicle(role, Some(special)))
}

fn rsu_cam() -> Vec<u8> {
    let coder = CamCoder::new();
    let mut cam = coder.decode(&cam_bytes(vehicle(0, None))).unwrap();
    cam.cam.cam_parameters.basic_container.station_type.0 = 15;
    cam.cam.cam_parameters.high_frequency_container =
        HighFrequencyContainer::rsuContainerHighFrequency(RSUContainerHighFrequency::new(Some(
            ProtectedCommunicationZonesRSU(vec![ProtectedCommunicationZone::new(
                ProtectedZoneType::permanentCenDsrcTolling,
                None,
                Latitude(415_520_000),
                Longitude(21_340_000),
                None,
                None,
            )]),
        )));
    cam.cam.cam_parameters.low_frequency_container = None;
    coder.encode(&cam).unwrap()
}

fn priority(bit_index: usize) -> EmergencyPriority {
    let mut bits = FixedBitString::<2>::default();
    bits.set(bit_index, true);
    EmergencyPriority(bits)
}

/// TP/CAM/MSP/SSP/BV-02-X (variants 01-14): a secured CAM with container X
/// whose signer's CAM SSP lacks bit X is discarded; with the bit set it is
/// accepted.
#[test]
fn tp_cam_msp_ssp_bv_02_x() {
    let variants: Vec<(u8, u8, u8, u8, Vec<u8>)> = vec![
        // (number, octet, bit, octet-1 bit the octet-2 bit needs, CAM)
        (1, 1, 0x80, 0, rsu_cam()),
        (2, 1, 0x40, 0, special_cam(1, container(1))),
        (3, 1, 0x20, 0, special_cam(2, container(2))),
        (4, 1, 0x10, 0, special_cam(3, container(3))),
        (5, 1, 0x08, 0, special_cam(4, container(4))),
        (6, 1, 0x04, 0, special_cam(5, container(5))),
        (7, 1, 0x02, 0, special_cam(6, container(6))),
        (8, 1, 0x01, 0, special_cam(7, container(7))),
        (
            9,
            2,
            0x80,
            0x08,
            special_cam(
                4,
                SpecialVehicleContainer::roadWorksContainerBasic(RoadWorksContainerBasic::new(
                    None,
                    siren(),
                    Some(ClosedLanes::new(None, None, None)),
                )),
            ),
        ),
        (
            10,
            2,
            0x40,
            0x02,
            special_cam(
                6,
                SpecialVehicleContainer::emergencyContainer(EmergencyContainer::new(
                    siren(),
                    None,
                    Some(priority(0)),
                )),
            ),
        ),
        (
            11,
            2,
            0x20,
            0x02,
            special_cam(
                6,
                SpecialVehicleContainer::emergencyContainer(EmergencyContainer::new(
                    siren(),
                    None,
                    Some(priority(1)),
                )),
            ),
        ),
        (
            12,
            2,
            0x10,
            0x01,
            special_cam(
                7,
                SpecialVehicleContainer::safetyCarContainer(SafetyCarContainer::new(
                    siren(),
                    None,
                    Some(TrafficRule::noPassing),
                    None,
                )),
            ),
        ),
        (
            13,
            2,
            0x08,
            0x01,
            special_cam(
                7,
                SpecialVehicleContainer::safetyCarContainer(SafetyCarContainer::new(
                    siren(),
                    None,
                    Some(TrafficRule::noPassingForTrucks),
                    None,
                )),
            ),
        ),
        (
            14,
            2,
            0x04,
            0x01,
            special_cam(
                7,
                SpecialVehicleContainer::safetyCarContainer(SafetyCarContainer::new(
                    siren(),
                    None,
                    None,
                    Some(SpeedLimit(50)),
                )),
            ),
        ),
    ];
    let mut pki = Pki::new();
    for (number, octet, bit, octet1_needed, cam) in variants {
        let (with1, with2) = if octet == 1 {
            (bit, 0)
        } else {
            (octet1_needed, bit)
        };
        let without = if octet == 1 {
            (0, 0)
        } else {
            (octet1_needed, 0)
        };
        for (granted, accepted) in [(without, false), ((with1, with2), true)] {
            let at = pki.at(&cam_ssp(granted.0, granted.1, 2));
            let mut receiver = pki.receiver();
            receiver.receive(&pki.secured_shb(&at, &cam));
            assert_eq!(
                receiver.received(),
                usize::from(accepted),
                "variant {number:02} accepted {accepted}"
            );
            assert_eq!(receiver.ldm_cams(), usize::from(accepted));
        }
    }
}

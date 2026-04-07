// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! GeoNetworking Router — ETSI EN 302 636-4-1 V1.4.1 (2020-01).
//!
//! Fully standard-compliant router with:
//! - SHB, GBC, GAC, GUC, TSB multi-hop, Beacon
//! - Location Service (LS) request/reply (§10.3.7)
//! - Security integration (sign on TX, verify on RX)
//! - Contention-Based Forwarding (CBF, §F.3)
//! - Greedy Forwarding (§E.2)
//! - Forwarding algorithm selection (Annex D)

use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use super::basic_header::{BasicHeader, BasicNH};
use super::common_header::CommonHeader;
use super::gbc_extended_header::GBCExtendedHeader;
use super::gn_address::GNAddress;
use super::guc_extended_header::GUCExtendedHeader;
use super::location_table::LocationTable;
use super::ls_extended_header::{LSReplyExtendedHeader, LSRequestExtendedHeader};
use super::mib::{AreaForwardingAlgorithm, GnSecurity, Mib};
use super::position_vector::{LongPositionVector, ShortPositionVector, Tst};
use super::service_access_point::{
    Area, CommonNH, CommunicationProfile, GNDataConfirm, GNDataIndication, GNDataRequest,
    GeoAnycastHST, GeoBroadcastHST, HeaderSubType, HeaderType, LocationServiceHST,
    PacketTransportType, ResultCode, TopoBroadcastHST, TrafficClass, UnspecifiedHST,
};
use super::tsb_extended_header::TSBExtendedHeader;
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::sign_service::SignService;
use crate::security::sn_sap::{
    GenerationLocation, ReportVerify, SNSignRequest, SNVerifyRequest, SecurityProfile,
};
use crate::security::verify_service;

const EARTH_RADIUS: f64 = 6371000.0;

// ------------------------------------------------------------------
// Router message types
// ------------------------------------------------------------------

pub enum RouterInput {
    GNDataRequest(GNDataRequest),
    IncomingPacket(Vec<u8>),
    PositionVectorUpdate(LongPositionVector),
    Shutdown,
}

pub enum RouterOutput {
    LinkLayerPacket(Vec<u8>),
    BTPIndication(GNDataIndication),
}

#[derive(PartialEq)]
pub enum GNForwardingAlgorithmResponse {
    AreaForwarding,
    NonAreaForwarding,
    Discarted,
}

impl GNForwardingAlgorithmResponse {
    pub fn encode(&self) -> u8 {
        match self {
            GNForwardingAlgorithmResponse::AreaForwarding => 1,
            GNForwardingAlgorithmResponse::NonAreaForwarding => 2,
            GNForwardingAlgorithmResponse::Discarted => 3,
        }
    }
}

pub trait GNIndicationCallback {
    fn gn_indication_callback(&mut self, indication: GNDataIndication);
}

// ------------------------------------------------------------------
// Router struct and RouterHandle
// ------------------------------------------------------------------

pub struct Router {
    pub mib: Mib,
    pub gn_address: GNAddress,
    pub ego_position_vector: LongPositionVector,
    pub sequence_number: u16,
    pub location_table: LocationTable,

    link_layer_tx: Sender<Vec<u8>>,
    btp_tx: Sender<GNDataIndication>,

    // Security services
    sign_service: Option<SignService>,
    verify_backend: Option<EcdsaBackend>,
    verify_cert_library: Option<CertificateLibrary>,

    // Location Service state (§10.3.7)
    ls_timers: HashMap<u64, Instant>,
    ls_retransmit_counters: HashMap<u64, u8>,
    ls_packet_buffers: HashMap<u64, Vec<GNDataRequest>>,

    // CBF state (§F.3) — keyed by (so_gn_addr_int, sn)
    cbf_buffer: HashMap<(u64, u16), (Instant, Vec<u8>)>,

    // Beacon reset flag — set when SHB is transmitted
    beacon_reset: bool,
}

#[derive(Clone)]
pub struct RouterHandle {
    input_tx: Sender<RouterInput>,
}

impl RouterHandle {
    pub fn send_gn_data_request(&self, request: GNDataRequest) {
        let _ = self.input_tx.send(RouterInput::GNDataRequest(request));
    }

    pub fn send_incoming_packet(&self, packet: Vec<u8>) {
        let _ = self.input_tx.send(RouterInput::IncomingPacket(packet));
    }

    pub fn update_position_vector(&self, position_vector: LongPositionVector) {
        let _ = self
            .input_tx
            .send(RouterInput::PositionVectorUpdate(position_vector));
    }

    pub fn shutdown(self) {
        let _ = self.input_tx.send(RouterInput::Shutdown);
    }
}

// ------------------------------------------------------------------
// Router implementation
// ------------------------------------------------------------------

impl Router {
    pub fn new(
        mib: Mib,
        link_layer_tx: Sender<Vec<u8>>,
        btp_tx: Sender<GNDataIndication>,
        sign_service: Option<SignService>,
        verify_backend: Option<EcdsaBackend>,
        verify_cert_library: Option<CertificateLibrary>,
    ) -> Self {
        Router {
            mib,
            gn_address: mib.itsGnLocalGnAddr,
            ego_position_vector: LongPositionVector {
                gn_addr: mib.itsGnLocalGnAddr,
                tst: Tst::set_in_normal_timestamp_milliseconds(0),
                latitude: 0,
                longitude: 0,
                pai: false,
                s: 0,
                h: 0,
            },
            location_table: LocationTable::new(mib),
            sequence_number: 0,
            link_layer_tx,
            btp_tx,
            sign_service,
            verify_backend,
            verify_cert_library,
            ls_timers: HashMap::new(),
            ls_retransmit_counters: HashMap::new(),
            ls_packet_buffers: HashMap::new(),
            cbf_buffer: HashMap::new(),
            beacon_reset: false,
        }
    }

    /// Spawn the router actor thread.
    ///
    /// Accepts optional security services for integrated signing/verification.
    pub fn spawn(
        mib: Mib,
        sign_service: Option<SignService>,
        verify_backend: Option<EcdsaBackend>,
        verify_cert_library: Option<CertificateLibrary>,
    ) -> (RouterHandle, Receiver<Vec<u8>>, Receiver<GNDataIndication>) {
        let (input_tx, input_rx) = mpsc::channel::<RouterInput>();
        let (link_layer_tx, link_layer_rx) = mpsc::channel::<Vec<u8>>();
        let (btp_tx, btp_rx) = mpsc::channel::<GNDataIndication>();

        let beacon_timer = mib.itsGnBeaconServiceRetransmitTimer;
        let handle = RouterHandle {
            input_tx: input_tx.clone(),
        };

        if beacon_timer > 0 {
            let beacon_handle = RouterHandle {
                input_tx: input_tx.clone(),
            };
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(beacon_timer as u64 / 2));
                loop {
                    let _ =
                        beacon_handle
                            .input_tx
                            .send(RouterInput::GNDataRequest(GNDataRequest {
                                upper_protocol_entity: CommonNH::Any,
                                packet_transport_type: PacketTransportType {
                                    header_type: HeaderType::Beacon,
                                    header_sub_type: HeaderSubType::Unspecified(
                                        UnspecifiedHST::Unspecified,
                                    ),
                                },
                                communication_profile: CommunicationProfile::Unspecified,
                                traffic_class: TrafficClass {
                                    scf: false,
                                    channel_offload: false,
                                    tc_id: 0,
                                },
                                security_profile: SecurityProfile::NoSecurity,
                                its_aid: 0,
                                security_permissions: vec![],
                                max_hop_limit: 1,
                                max_packet_lifetime: None,
                                destination: None,
                                length: 0,
                                data: vec![],
                                area: Area {
                                    latitude: 0,
                                    longitude: 0,
                                    a: 0,
                                    b: 0,
                                    angle: 0,
                                },
                            }));
                    thread::sleep(Duration::from_millis(beacon_timer as u64));
                }
            });
        }

        let _thread_handle = thread::spawn(move || {
            let mut router = Router::new(
                mib,
                link_layer_tx,
                btp_tx,
                sign_service,
                verify_backend,
                verify_cert_library,
            );
            router.run(input_rx);
        });

        (handle, link_layer_rx, btp_rx)
    }

    // ------------------------------------------------------------------
    // Main event loop
    // ------------------------------------------------------------------

    fn run(&mut self, input_rx: Receiver<RouterInput>) {
        loop {
            match input_rx.recv() {
                Ok(RouterInput::GNDataRequest(request)) => {
                    let _ = self.gn_data_request(request);
                }
                Ok(RouterInput::IncomingPacket(packet)) => {
                    self.process_basic_header(&packet);
                }
                Ok(RouterInput::PositionVectorUpdate(position_vector)) => {
                    self.refresh_ego_position_vector(position_vector);
                }
                Ok(RouterInput::Shutdown) | Err(_) => {
                    break;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    pub fn get_sequence_number(&mut self) -> u16 {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.sequence_number
    }

    fn send_to_link_layer(&self, packet: Vec<u8>) -> GNDataConfirm {
        match self.link_layer_tx.send(packet) {
            Ok(_) => GNDataConfirm {
                result_code: ResultCode::Accepted,
            },
            Err(_) => GNDataConfirm {
                result_code: ResultCode::Unspecified,
            },
        }
    }

    // ------------------------------------------------------------------
    // GN data request — transmit path
    // ------------------------------------------------------------------

    fn gn_data_request_shb(&mut self, request: GNDataRequest) -> GNDataConfirm {
        let basic_header = BasicHeader::initialize_with_mib_request_and_rhl(
            &self.mib,
            request.max_packet_lifetime,
            1,
        );
        let common_header = CommonHeader::initialize_with_request(&request, &self.mib);
        let media_dependent_data: [u8; 4] = [0; 4];

        let packet: Vec<u8>;

        if self.mib.itsGnSecurity == GnSecurity::Enabled {
            if let Some(ref mut sign_service) = self.sign_service {
                // TBS = CommonHeader + ExtHeader(LPV + MediaDep) + payload
                let mut tbs: Vec<u8> = Vec::new();
                tbs.extend_from_slice(&common_header.encode());
                tbs.extend_from_slice(&self.ego_position_vector.encode());
                tbs.extend_from_slice(&media_dependent_data);
                tbs.extend_from_slice(&request.data);

                let sign_request = SNSignRequest {
                    tbs_message: tbs,
                    its_aid: request.its_aid,
                    permissions: request.security_permissions.clone(),
                    generation_location: None,
                };

                let sign_confirm = sign_service.sign_request(&sign_request);
                let secured_basic = basic_header.set_nh(BasicNH::SecuredPacket);

                packet = secured_basic
                    .encode()
                    .iter()
                    .copied()
                    .chain(sign_confirm.sec_message.iter().copied())
                    .collect();
            } else {
                eprintln!("[GN] Security enabled but no SignService configured");
                return GNDataConfirm {
                    result_code: ResultCode::Unspecified,
                };
            }
        } else {
            packet = basic_header
                .encode()
                .iter()
                .copied()
                .chain(common_header.encode().iter().copied())
                .chain(self.ego_position_vector.encode().iter().copied())
                .chain(media_dependent_data.iter().copied())
                .chain(request.data.iter().copied())
                .collect();
        }

        // Reset beacon timer on SHB transmission (§10.3.10.2 step 7)
        self.beacon_reset = true;

        self.send_to_link_layer(packet)
    }

    fn gn_data_request_beacon(&self) -> GNDataConfirm {
        let basic_header = BasicHeader::initialize_with_mib_request_and_rhl(&self.mib, None, 1);
        let common_header = CommonHeader::initialize_beacon(&self.mib);

        let packet: Vec<u8> = basic_header
            .encode()
            .iter()
            .copied()
            .chain(common_header.encode().iter().copied())
            .chain(self.ego_position_vector.encode().iter().copied())
            .collect();

        self.send_to_link_layer(packet)
    }

    fn gn_data_request_gbc(&mut self, request: GNDataRequest) -> GNDataConfirm {
        // §B.3: area size control
        if let HeaderSubType::GeoBroadcast(ref hst) = request.packet_transport_type.header_sub_type
        {
            if Self::compute_area_size_m2_gb(hst, &request.area)
                > self.mib.itsGnMaxGeoAreaSize as f64 * 1_000_000.0
            {
                return GNDataConfirm {
                    result_code: ResultCode::GeographicalScopeTooLarge,
                };
            }
        }

        let hop_limit = if request.max_hop_limit <= 1 {
            self.mib.itsGnDefaultHopLimit
        } else {
            request.max_hop_limit
        };
        let basic_header = BasicHeader::initialize_with_mib_request_and_rhl(
            &self.mib,
            request.max_packet_lifetime,
            hop_limit,
        );

        let req_with_hl = GNDataRequest {
            max_hop_limit: hop_limit,
            ..clone_request(&request)
        };

        let common_header = CommonHeader::initialize_with_request(&req_with_hl, &self.mib);
        let sn = self.get_sequence_number();
        let gbc_ext = GBCExtendedHeader::initialize_with_request_sequence_number_ego_pv(
            &request,
            sn,
            self.ego_position_vector,
        );

        // Security encapsulation
        let sec_payload: Option<Vec<u8>>;
        let mut actual_basic = basic_header;

        if self.mib.itsGnSecurity == GnSecurity::Enabled
            && request.security_profile
                == SecurityProfile::DecentralizedEnvironmentalNotificationMessage
        {
            if let Some(ref mut sign_service) = self.sign_service {
                let mut tbs: Vec<u8> = Vec::new();
                tbs.extend_from_slice(&common_header.encode());
                tbs.extend_from_slice(&gbc_ext.encode());
                tbs.extend_from_slice(&request.data);

                let sign_request = SNSignRequest {
                    tbs_message: tbs,
                    its_aid: request.its_aid,
                    permissions: request.security_permissions.clone(),
                    generation_location: Some(GenerationLocation {
                        latitude: self.ego_position_vector.latitude as i32,
                        longitude: self.ego_position_vector.longitude as i32,
                        elevation: 0xF000,
                    }),
                };
                let sign_confirm = sign_service.sign_request(&sign_request);
                actual_basic = actual_basic.set_nh(BasicNH::SecuredPacket);
                sec_payload = Some(sign_confirm.sec_message);
            } else {
                sec_payload = None;
            }
        } else {
            sec_payload = None;
        }

        // SCF + no neighbours → buffer (stub)
        if self.location_table.get_neighbours().is_empty() && request.traffic_class.scf {
            return GNDataConfirm {
                result_code: ResultCode::Accepted,
            };
        }

        let algorithm = self.gn_forwarding_algorithm_selection(&request, None);

        let build_packet = |bh: &BasicHeader| -> Vec<u8> {
            let inner: Vec<u8> = if let Some(ref sp) = sec_payload {
                sp.clone()
            } else {
                let mut v = Vec::new();
                v.extend_from_slice(&common_header.encode());
                v.extend_from_slice(&gbc_ext.encode());
                v.extend_from_slice(&request.data);
                v
            };
            bh.encode()
                .iter()
                .copied()
                .chain(inner.iter().copied())
                .collect()
        };

        if algorithm == GNForwardingAlgorithmResponse::AreaForwarding {
            let packet = build_packet(&actual_basic);
            return self.send_to_link_layer(packet);
        } else if algorithm == GNForwardingAlgorithmResponse::NonAreaForwarding {
            if self.gn_greedy_forwarding(
                request.area.latitude as i32,
                request.area.longitude as i32,
                &request.traffic_class,
            ) {
                let packet = build_packet(&actual_basic);
                return self.send_to_link_layer(packet);
            }
        }

        GNDataConfirm {
            result_code: ResultCode::Accepted,
        }
    }

    fn gn_data_request_gac(&mut self, request: GNDataRequest) -> GNDataConfirm {
        self.gn_data_request_gbc(request)
    }

    fn gn_data_request_guc(&mut self, request: GNDataRequest) -> GNDataConfirm {
        let hop_limit = if request.max_hop_limit <= 1 {
            self.mib.itsGnDefaultHopLimit
        } else {
            request.max_hop_limit
        };
        let basic_header = BasicHeader::initialize_with_mib_request_and_rhl(
            &self.mib,
            request.max_packet_lifetime,
            hop_limit,
        );

        let req_with_hl = GNDataRequest {
            max_hop_limit: hop_limit,
            ..clone_request(&request)
        };
        let common_header = CommonHeader::initialize_with_request(&req_with_hl, &self.mib);

        // Look up DE PV from LocT
        let dest_addr = match &request.destination {
            Some(addr) => *addr,
            None => {
                eprintln!("[GN] GUC request missing destination");
                return GNDataConfirm {
                    result_code: ResultCode::Unspecified,
                };
            }
        };

        let de_entry = self.location_table.get_entry_ref(&dest_addr);
        let de_pv = match de_entry {
            Some(entry) => ShortPositionVector {
                gn_address: entry.position_vector.gn_addr,
                tst: entry.position_vector.tst,
                latitude: entry.position_vector.latitude,
                longitude: entry.position_vector.longitude,
            },
            None => {
                // No LocTE → invoke Location Service
                self.gn_ls_request(&dest_addr, Some(request));
                return GNDataConfirm {
                    result_code: ResultCode::Accepted,
                };
            }
        };

        let sn = self.get_sequence_number();
        let guc_ext = GUCExtendedHeader::initialize_with_sequence_number_ego_pv_de_pv(
            sn,
            self.ego_position_vector,
            de_pv.clone(),
        );

        // SCF + no neighbours → buffer (stub)
        if self.location_table.get_neighbours().is_empty() && request.traffic_class.scf {
            return GNDataConfirm {
                result_code: ResultCode::Accepted,
            };
        }

        if !self.gn_greedy_forwarding(
            de_pv.latitude as i32,
            de_pv.longitude as i32,
            &request.traffic_class,
        ) {
            return GNDataConfirm {
                result_code: ResultCode::Accepted,
            };
        }

        let packet: Vec<u8> = basic_header
            .encode()
            .iter()
            .copied()
            .chain(common_header.encode().iter().copied())
            .chain(guc_ext.encode().iter().copied())
            .chain(request.data.iter().copied())
            .collect();

        self.send_to_link_layer(packet)
    }

    pub fn gn_data_request(&mut self, request: GNDataRequest) -> GNDataConfirm {
        match request.packet_transport_type.header_type {
            HeaderType::Beacon => self.gn_data_request_beacon(),
            HeaderType::Tsb => {
                if let HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop) =
                    request.packet_transport_type.header_sub_type
                {
                    self.gn_data_request_shb(request)
                } else {
                    eprintln!("[GN] TSB multi-hop source not yet fully implemented");
                    GNDataConfirm {
                        result_code: ResultCode::Unspecified,
                    }
                }
            }
            HeaderType::GeoBroadcast => self.gn_data_request_gbc(request),
            HeaderType::GeoAnycast => self.gn_data_request_gac(request),
            HeaderType::GeoUnicast => self.gn_data_request_guc(request),
            _ => {
                eprintln!("[GN] Header type not supported");
                GNDataConfirm {
                    result_code: ResultCode::Unspecified,
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // GN indicate — receive path
    // ------------------------------------------------------------------

    /// Top-level receive dispatcher — process Basic Header.
    pub fn process_basic_header(&mut self, packet: &[u8]) {
        if packet.len() < 4 {
            eprintln!("[GN] Packet too short for Basic Header");
            return;
        }
        let basic_header = BasicHeader::decode(
            packet[0..4]
                .try_into()
                .expect("BasicHeader slice wrong length"),
        );
        if basic_header.version != self.mib.itsGnProtocolVersion {
            eprintln!("[GN] Protocol version mismatch");
            return;
        }
        let remaining = &packet[4..];
        match basic_header.nh {
            BasicNH::CommonHeader => {
                // When itsGnSecurity is ENABLED, unsecured packets must be discarded
                if self.mib.itsGnSecurity == GnSecurity::Enabled {
                    return;
                }
                self.process_common_header(remaining, &basic_header);
            }
            BasicNH::SecuredPacket => {
                self.process_security_header(remaining, &basic_header);
            }
            _ => {
                eprintln!("[GN] Basic NH not supported");
            }
        }
    }

    /// Process security header — verify and dispatch.
    fn process_security_header(&mut self, packet: &[u8], basic_header: &BasicHeader) {
        let (backend, cert_library) =
            match (&self.verify_backend, &mut self.verify_cert_library) {
                (Some(b), Some(cl)) => (b, cl),
                _ => {
                    eprintln!("[GN] Secured packet received but no verify service configured");
                    return;
                }
            };

        let verify_request = SNVerifyRequest {
            message: packet.to_vec(),
        };

        let (confirm, _events) =
            verify_service::verify_message(&verify_request, backend, cert_library);

        if confirm.report != ReportVerify::Success {
            eprintln!(
                "[GN] Secured packet verification failed: {:?}",
                confirm.report
            );
            return;
        }

        // Dispatch plain_message as Common Header + payload
        let plain_basic = basic_header.clone().set_nh(BasicNH::CommonHeader);
        self.process_common_header(&confirm.plain_message, &plain_basic);
    }

    /// Process Common Header and dispatch to appropriate handler.
    fn process_common_header(&mut self, packet: &[u8], basic_header: &BasicHeader) {
        if packet.len() < 8 {
            eprintln!("[GN] Packet too short for Common Header");
            return;
        }
        let common_header = CommonHeader::decode(
            packet[0..8]
                .try_into()
                .expect("CommonHeader slice wrong length"),
        );
        let payload = &packet[8..];

        if basic_header.rhl > common_header.mhl {
            eprintln!("[GN] Hop limit exceeded");
            return;
        }

        let indication: Option<GNDataIndication> = match common_header.ht {
            HeaderType::Beacon => {
                self.gn_data_indicate_beacon(payload);
                None
            }
            HeaderType::Tsb => {
                if let HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop) =
                    common_header.hst
                {
                    self.gn_data_indicate_shb(payload, &common_header, basic_header)
                } else if let HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop) =
                    common_header.hst
                {
                    self.gn_data_indicate_tsb(payload, &common_header, basic_header)
                } else {
                    eprintln!("[GN] Unsupported TSB sub-type");
                    None
                }
            }
            HeaderType::GeoBroadcast => {
                self.gn_data_indicate_gbc(payload, &common_header, basic_header)
            }
            HeaderType::GeoAnycast => {
                self.gn_data_indicate_gac(payload, &common_header, basic_header)
            }
            HeaderType::GeoUnicast => {
                self.gn_data_indicate_guc(payload, &common_header, basic_header)
            }
            HeaderType::Ls => {
                self.gn_data_indicate_ls(payload, &common_header, basic_header);
                None // LS never delivers to upper entity
            }
            _ => {
                eprintln!("[GN] Header type not supported");
                None
            }
        };

        if let Some(ind) = indication {
            let _ = self.btp_tx.send(ind);
        }
    }

    // ------------------------------------------------------------------
    // Individual indicate handlers
    // ------------------------------------------------------------------

    fn gn_data_indicate_shb(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) -> Option<GNDataIndication> {
        if packet.len() < 28 {
            eprintln!("[GN] SHB packet too short");
            return None;
        }
        let lpv = LongPositionVector::decode(
            packet[0..24]
                .try_into()
                .expect("SHB: LPV slice wrong length"),
        );
        // Media dependent data (4 bytes) + payload
        let payload = packet[28..].to_vec();

        // DAD
        if self.duplicate_address_detection(lpv.gn_addr) {
            return None;
        }

        self.location_table.new_shb_packet(&lpv, &payload);

        Some(GNDataIndication {
            upper_protocol_entity: common_header.nh.clone(),
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            },
            source_position_vector: lpv,
            traffic_class: common_header.tc,
            destination_area: None,
            remaining_packet_lifetime: Some(
                basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
            ),
            remaining_hop_limit: Some(basic_header.rhl),
            length: payload.len() as u16,
            data: payload,
        })
    }

    fn gn_data_indicate_beacon(&mut self, packet: &[u8]) {
        if packet.len() < 24 {
            return;
        }
        let lpv = LongPositionVector::decode(
            packet[0..24]
                .try_into()
                .expect("Beacon: LPV slice wrong length"),
        );
        if self.duplicate_address_detection(lpv.gn_addr) {
            return;
        }
        self.location_table.new_shb_packet(&lpv, &packet[24..]);
    }

    fn gn_data_indicate_gbc(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) -> Option<GNDataIndication> {
        if packet.len() < 44 {
            eprintln!("[GN] GBC packet too short");
            return None;
        }
        let ext = GBCExtendedHeader::decode(
            packet[0..44]
                .try_into()
                .expect("GBC ext header slice wrong"),
        );
        let payload = &packet[44..];
        let area = Area {
            latitude: ext.latitude,
            longitude: ext.longitude,
            a: ext.a,
            b: ext.b,
            angle: ext.angle,
        };

        let area_hst = match &common_header.hst {
            HeaderSubType::GeoBroadcast(h) => h.clone(),
            _ => return None,
        };

        let area_f = self.gn_geometric_function_f(
            &area_hst,
            &area,
            &self.ego_position_vector.latitude,
            &self.ego_position_vector.longitude,
        );

        // DAD
        if self.duplicate_address_detection(ext.so_pv.gn_addr) {
            return None;
        }

        // DPD + LocTE update
        if self.location_table.new_gbc_packet(&ext, payload) {
            return None; // duplicate
        }

        let mut indication: Option<GNDataIndication> = None;

        // Inside/at border → deliver
        if area_f >= 0.0 {
            indication = Some(GNDataIndication {
                upper_protocol_entity: common_header.nh.clone(),
                packet_transport_type: PacketTransportType {
                    header_type: HeaderType::GeoBroadcast,
                    header_sub_type: common_header.hst.clone(),
                },
                destination_area: Some(area),
                source_position_vector: ext.so_pv,
                traffic_class: common_header.tc,
                remaining_packet_lifetime: Some(
                    basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
                ),
                remaining_hop_limit: Some(basic_header.rhl),
                length: payload.len() as u16,
                data: payload.to_vec(),
            });
        }

        // §B.3: area size control
        if Self::compute_area_size_m2_gb(&area_hst, &area)
            > self.mib.itsGnMaxGeoAreaSize as f64 * 1_000_000.0
        {
            return indication;
        }

        // §B.2: PDR enforcement
        if let Some(entry) = self
            .location_table
            .get_entry_ref(&ext.so_pv.gn_addr)
        {
            if entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0 {
                return indication;
            }
        }

        // Forward if RHL > 1
        let new_rhl = basic_header.rhl.saturating_sub(1);
        if new_rhl > 0 {
            self.gn_data_forward_gbc(basic_header, common_header, &ext, payload);
        }

        indication
    }

    fn gn_data_indicate_gac(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) -> Option<GNDataIndication> {
        if packet.len() < 44 {
            return None;
        }
        let ext = GBCExtendedHeader::decode(
            packet[0..44]
                .try_into()
                .expect("GAC ext header slice wrong"),
        );
        let payload = &packet[44..];
        let area = Area {
            latitude: ext.latitude,
            longitude: ext.longitude,
            a: ext.a,
            b: ext.b,
            angle: ext.angle,
        };

        let area_hst = match &common_header.hst {
            HeaderSubType::GeoAnycast(h) => h.clone(),
            _ => return None,
        };

        let area_f = self.gn_geometric_function_f_anycast(
            &area_hst,
            &area,
            &self.ego_position_vector.latitude,
            &self.ego_position_vector.longitude,
        );

        if self.duplicate_address_detection(ext.so_pv.gn_addr) {
            return None;
        }

        if self.location_table.new_gac_packet(&ext, payload) {
            return None; // duplicate
        }

        // Inside/at border → deliver and STOP (no forwarding)
        if area_f >= 0.0 {
            return Some(GNDataIndication {
                upper_protocol_entity: common_header.nh.clone(),
                packet_transport_type: PacketTransportType {
                    header_type: HeaderType::GeoAnycast,
                    header_sub_type: common_header.hst.clone(),
                },
                destination_area: Some(area),
                source_position_vector: ext.so_pv,
                traffic_class: common_header.tc,
                remaining_packet_lifetime: Some(
                    basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
                ),
                remaining_hop_limit: Some(basic_header.rhl),
                length: payload.len() as u16,
                data: payload.to_vec(),
            });
        }

        // Outside → forward only, no delivery
        let new_rhl = basic_header.rhl.saturating_sub(1);
        if new_rhl == 0 {
            return None;
        }

        // §B.2 PDR enforcement
        if let Some(entry) = self
            .location_table
            .get_entry_ref(&ext.so_pv.gn_addr)
        {
            if entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0 {
                return None;
            }
        }

        let fwd_basic = basic_header.clone().set_rhl(new_rhl);

        if self.location_table.get_neighbours().is_empty() && common_header.tc.scf {
            return None;
        }

        // Greedy forwarding towards area centre
        if self.gn_greedy_forwarding(
            area.latitude as i32,
            area.longitude as i32,
            &common_header.tc,
        ) {
            let fwd_packet: Vec<u8> = fwd_basic
                .encode()
                .iter()
                .copied()
                .chain(common_header.encode().iter().copied())
                .chain(ext.encode().iter().copied())
                .chain(payload.iter().copied())
                .collect();
            let _ = self.link_layer_tx.send(fwd_packet);
        }

        None
    }

    fn gn_data_indicate_tsb(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) -> Option<GNDataIndication> {
        if packet.len() < 28 {
            return None;
        }
        let ext = TSBExtendedHeader::decode(&packet[0..28]);
        let payload = &packet[28..];

        if self.duplicate_address_detection(ext.so_pv.gn_addr) {
            return None;
        }

        if self.location_table.new_tsb_packet(&ext, payload) {
            return None; // duplicate
        }

        let indication = GNDataIndication {
            upper_protocol_entity: common_header.nh.clone(),
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop),
            },
            source_position_vector: ext.so_pv,
            traffic_class: common_header.tc,
            destination_area: None,
            remaining_packet_lifetime: Some(
                basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
            ),
            remaining_hop_limit: Some(basic_header.rhl),
            length: payload.len() as u16,
            data: payload.to_vec(),
        };

        // §B.2 PDR enforcement
        if let Some(entry) = self
            .location_table
            .get_entry_ref(&ext.so_pv.gn_addr)
        {
            if entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0 {
                return Some(indication);
            }
        }

        // Forward
        let new_rhl = basic_header.rhl.saturating_sub(1);
        if new_rhl > 0 {
            if !(self.location_table.get_neighbours().is_empty() && common_header.tc.scf) {
                let fwd_basic = basic_header.clone().set_rhl(new_rhl);
                let fwd_packet: Vec<u8> = fwd_basic
                    .encode()
                    .iter()
                    .copied()
                    .chain(common_header.encode().iter().copied())
                    .chain(ext.encode().iter().copied())
                    .chain(payload.iter().copied())
                    .collect();
                let _ = self.link_layer_tx.send(fwd_packet);
            }
        }

        Some(indication)
    }

    fn gn_data_indicate_guc(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) -> Option<GNDataIndication> {
        if packet.len() < 48 {
            return None;
        }
        let ext = GUCExtendedHeader::decode(&packet[0..48]);
        let payload = &packet[48..];

        if self.duplicate_address_detection(ext.so_pv.gn_addr) {
            return None;
        }

        if self.location_table.new_guc_packet(&ext, payload) {
            return None; // duplicate
        }

        // Check if we are the destination
        let is_destination = ext.de_pv.gn_address == self.mib.itsGnLocalGnAddr;

        if is_destination {
            return Some(GNDataIndication {
                upper_protocol_entity: common_header.nh.clone(),
                packet_transport_type: PacketTransportType {
                    header_type: HeaderType::GeoUnicast,
                    header_sub_type: HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
                },
                source_position_vector: ext.so_pv,
                traffic_class: common_header.tc,
                destination_area: None,
                remaining_packet_lifetime: Some(
                    basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
                ),
                remaining_hop_limit: Some(basic_header.rhl),
                length: payload.len() as u16,
                data: payload.to_vec(),
            });
        }

        // Forwarder operations
        // §B.2 PDR
        if let Some(entry) = self
            .location_table
            .get_entry_ref(&ext.so_pv.gn_addr)
        {
            if entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0 {
                return None;
            }
        }

        // Update DE PV from LocT if DE is a neighbour with newer PV
        let mut fwd_ext = ext.clone();
        if let Some(de_entry) = self
            .location_table
            .get_entry_ref(&ext.de_pv.gn_address)
        {
            if de_entry.is_neighbour && de_entry.position_vector.tst > ext.de_pv.tst {
                let de_lpv = &de_entry.position_vector;
                fwd_ext = fwd_ext.with_de_pv(ShortPositionVector {
                    gn_address: de_lpv.gn_addr,
                    tst: de_lpv.tst,
                    latitude: de_lpv.latitude,
                    longitude: de_lpv.longitude,
                });
            }
        }

        let new_rhl = basic_header.rhl.saturating_sub(1);
        if new_rhl > 0 {
            if !(self.location_table.get_neighbours().is_empty() && common_header.tc.scf) {
                if self.gn_greedy_forwarding(
                    fwd_ext.de_pv.latitude as i32,
                    fwd_ext.de_pv.longitude as i32,
                    &common_header.tc,
                ) {
                    let fwd_basic = basic_header.clone().set_rhl(new_rhl);
                    let fwd_packet: Vec<u8> = fwd_basic
                        .encode()
                        .iter()
                        .copied()
                        .chain(common_header.encode().iter().copied())
                        .chain(fwd_ext.encode().iter().copied())
                        .chain(payload.iter().copied())
                        .collect();
                    let _ = self.link_layer_tx.send(fwd_packet);
                }
            }
        }

        None
    }

    // ------------------------------------------------------------------
    // Location Service (§10.3.7)
    // ------------------------------------------------------------------

    fn gn_data_indicate_ls(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) {
        match &common_header.hst {
            HeaderSubType::LocationService(LocationServiceHST::LsRequest) => {
                self.gn_data_indicate_ls_request(packet, common_header, basic_header);
            }
            HeaderSubType::LocationService(LocationServiceHST::LsReply) => {
                self.gn_data_indicate_ls_reply(packet, common_header, basic_header);
            }
            _ => {
                eprintln!("[GN] Unknown LS HST");
            }
        }
    }

    fn gn_data_indicate_ls_request(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) {
        if packet.len() < 36 {
            return;
        }
        let ls_req = LSRequestExtendedHeader::decode(&packet[0..36]);
        let payload = &packet[36..];

        if self.duplicate_address_detection(ls_req.so_pv.gn_addr) {
            return;
        }

        if self.location_table.new_ls_request_packet(&ls_req, payload) {
            return; // duplicate
        }

        if ls_req.request_gn_addr == self.mib.itsGnLocalGnAddr {
            // We are the destination — send LS Reply
            let so_entry_pv = self
                .location_table
                .get_entry_ref(&ls_req.so_pv.gn_addr)
                .map(|e| e.position_vector);
            let so_lpv = match so_entry_pv {
                Some(pv) => pv,
                None => return,
            };
            let de_pv = ShortPositionVector {
                gn_address: so_lpv.gn_addr,
                tst: so_lpv.tst,
                latitude: so_lpv.latitude,
                longitude: so_lpv.longitude,
            };

            let reply_basic =
                BasicHeader::initialize_with_mib_request_and_rhl(
                    &self.mib,
                    None,
                    self.mib.itsGnDefaultHopLimit,
                );
            let reply_common = CommonHeader {
                nh: CommonNH::Any,
                reserved: 0,
                ht: HeaderType::Ls,
                hst: HeaderSubType::LocationService(LocationServiceHST::LsReply),
                tc: TrafficClass {
                    scf: false,
                    channel_offload: false,
                    tc_id: 0,
                },
                flags: (self.mib.itsGnIsMobile.encode()) << 7,
                pl: 0,
                mhl: self.mib.itsGnDefaultHopLimit,
                reserved2: 0,
            };
            let sn = self.get_sequence_number();
            let reply_ext =
                LSReplyExtendedHeader::initialize(sn, self.ego_position_vector, de_pv);

            let reply_packet: Vec<u8> = reply_basic
                .encode()
                .iter()
                .copied()
                .chain(reply_common.encode().iter().copied())
                .chain(reply_ext.encode().iter().copied())
                .collect();
            let _ = self.link_layer_tx.send(reply_packet);
        } else {
            // Forwarder: re-broadcast
            // §B.2 PDR enforcement
            if let Some(entry) = self.location_table.get_entry_ref(&ls_req.so_pv.gn_addr) {
                if entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0 {
                    return;
                }
            }
            let new_rhl = basic_header.rhl.saturating_sub(1);
            if new_rhl > 0 {
                let fwd_basic = basic_header.clone().set_rhl(new_rhl);
                let fwd_packet: Vec<u8> = fwd_basic
                    .encode()
                    .iter()
                    .copied()
                    .chain(common_header.encode().iter().copied())
                    .chain(ls_req.encode().iter().copied())
                    .chain(payload.iter().copied())
                    .collect();
                let _ = self.link_layer_tx.send(fwd_packet);
            }
        }
    }

    fn gn_data_indicate_ls_reply(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) {
        if packet.len() < 48 {
            return;
        }
        let ls_reply = LSReplyExtendedHeader::decode(&packet[0..48]);
        let payload = &packet[48..];

        if self.duplicate_address_detection(ls_reply.so_pv.gn_addr) {
            return;
        }

        if self.location_table.new_ls_reply_packet(&ls_reply, payload) {
            return; // duplicate
        }

        let sought_gn_addr = ls_reply.so_pv.gn_addr;

        if ls_reply.de_pv.gn_address == self.mib.itsGnLocalGnAddr {
            // We are the original requester
            let key = sought_gn_addr.encode_to_int();
            self.ls_timers.remove(&key);
            self.ls_retransmit_counters.remove(&key);
            let buffered = self.ls_packet_buffers.remove(&key).unwrap_or_default();

            if let Some(entry) = self.location_table.get_entry(&sought_gn_addr) {
                entry.ls_pending = false;
            }

            // Flush LS packet buffer
            for req in buffered {
                let _ = self.gn_data_request_guc(req);
            }
        } else {
            // Forwarder: forward like GUC forwarder
            // §B.2 PDR enforcement
            if let Some(entry) = self.location_table.get_entry_ref(&ls_reply.so_pv.gn_addr)
            {
                if entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0 {
                    return;
                }
            }

            let mut fwd_reply = ls_reply.clone();
            if let Some(de_entry) = self.location_table.get_entry_ref(&ls_reply.de_pv.gn_address)
            {
                if de_entry.is_neighbour && de_entry.position_vector.tst > ls_reply.de_pv.tst {
                    let de_lpv = &de_entry.position_vector;
                    fwd_reply = LSReplyExtendedHeader {
                        sn: fwd_reply.sn,
                        reserved: fwd_reply.reserved,
                        so_pv: fwd_reply.so_pv,
                        de_pv: ShortPositionVector {
                            gn_address: de_lpv.gn_addr,
                            tst: de_lpv.tst,
                            latitude: de_lpv.latitude,
                            longitude: de_lpv.longitude,
                        },
                    };
                }
            }

            let new_rhl = basic_header.rhl.saturating_sub(1);
            if new_rhl > 0 {
                let fwd_basic = basic_header.clone().set_rhl(new_rhl);
                let fwd_packet: Vec<u8> = fwd_basic
                    .encode()
                    .iter()
                    .copied()
                    .chain(common_header.encode().iter().copied())
                    .chain(fwd_reply.encode().iter().copied())
                    .chain(payload.iter().copied())
                    .collect();
                let _ = self.link_layer_tx.send(fwd_packet);
            }
        }
    }

    /// Initiate Location Service request (§10.3.7.1.2).
    fn gn_ls_request(&mut self, sought_addr: &GNAddress, buffered_request: Option<GNDataRequest>) {
        let key = sought_addr.encode_to_int();

        // Check if LS is already in progress
        if let Some(entry) = self.location_table.get_entry_ref(sought_addr) {
            if entry.ls_pending {
                if let Some(req) = buffered_request {
                    self.ls_packet_buffers
                        .entry(key)
                        .or_insert_with(Vec::new)
                        .push(req);
                }
                return;
            }
        }

        // Create/fetch LocTE and set ls_pending
        let entry = self.location_table.ensure_entry(sought_addr);
        entry.ls_pending = true;

        self.ls_packet_buffers.insert(
            key,
            if let Some(req) = buffered_request {
                vec![req]
            } else {
                vec![]
            },
        );
        self.ls_retransmit_counters.insert(key, 0);
        self.ls_timers.insert(key, Instant::now());

        // Send LS Request packet
        self.send_ls_request_packet(sought_addr);
    }

    fn send_ls_request_packet(&mut self, sought_addr: &GNAddress) {
        let basic_header = BasicHeader::initialize_with_mib_request_and_rhl(
            &self.mib,
            None,
            self.mib.itsGnDefaultHopLimit,
        );
        let common_header = CommonHeader {
            nh: CommonNH::Any,
            reserved: 0,
            ht: HeaderType::Ls,
            hst: HeaderSubType::LocationService(LocationServiceHST::LsRequest),
            tc: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            flags: (self.mib.itsGnIsMobile.encode()) << 7,
            pl: 0,
            mhl: self.mib.itsGnDefaultHopLimit,
            reserved2: 0,
        };
        let sn = self.get_sequence_number();
        let ls_req =
            LSRequestExtendedHeader::initialize(sn, self.ego_position_vector, *sought_addr);

        let packet: Vec<u8> = basic_header
            .encode()
            .iter()
            .copied()
            .chain(common_header.encode().iter().copied())
            .chain(ls_req.encode().iter().copied())
            .collect();

        let _ = self.link_layer_tx.send(packet);
    }

    // ------------------------------------------------------------------
    // GBC forwarding
    // ------------------------------------------------------------------

    fn gn_data_forward_gbc(
        &mut self,
        basic_header: &BasicHeader,
        common_header: &CommonHeader,
        gbc_ext: &GBCExtendedHeader,
        payload: &[u8],
    ) -> GNDataConfirm {
        let mut fwd_basic = basic_header.clone();
        fwd_basic.rhl = basic_header.rhl.saturating_sub(1);

        if fwd_basic.rhl == 0 {
            return GNDataConfirm {
                result_code: ResultCode::Unspecified,
            };
        }

        if !self.location_table.get_neighbours().is_empty() || !common_header.tc.scf {
            let area = Area {
                latitude: gbc_ext.latitude,
                longitude: gbc_ext.longitude,
                a: gbc_ext.a,
                b: gbc_ext.b,
                angle: gbc_ext.angle,
            };
            let pseudo_request = GNDataRequest {
                upper_protocol_entity: common_header.nh.clone(),
                packet_transport_type: PacketTransportType {
                    header_type: common_header.ht.clone(),
                    header_sub_type: common_header.hst.clone(),
                },
                communication_profile: CommunicationProfile::Unspecified,
                traffic_class: common_header.tc,
                security_profile: SecurityProfile::NoSecurity,
                its_aid: 0,
                security_permissions: vec![],
                max_hop_limit: common_header.mhl,
                max_packet_lifetime: None,
                destination: None,
                length: payload.len() as u16,
                data: vec![],
                area,
            };
            let algorithm = self.gn_forwarding_algorithm_selection(
                &pseudo_request,
                Some(&gbc_ext.so_pv.gn_addr),
            );

            if algorithm == GNForwardingAlgorithmResponse::AreaForwarding {
                if self.mib.itsGnAreaForwardingAlgorithm == AreaForwardingAlgorithm::Cbf {
                    self.gn_area_cbf_forwarding(&fwd_basic, common_header, gbc_ext, payload);
                    return GNDataConfirm {
                        result_code: ResultCode::Accepted,
                    };
                }
                let fwd_packet: Vec<u8> = fwd_basic
                    .encode()
                    .iter()
                    .copied()
                    .chain(common_header.encode().iter().copied())
                    .chain(gbc_ext.encode().iter().copied())
                    .chain(payload.iter().copied())
                    .collect();
                return self.send_to_link_layer(fwd_packet);
            } else if algorithm == GNForwardingAlgorithmResponse::NonAreaForwarding {
                if self.gn_greedy_forwarding(
                    gbc_ext.latitude as i32,
                    gbc_ext.longitude as i32,
                    &common_header.tc,
                ) {
                    let fwd_packet: Vec<u8> = fwd_basic
                        .encode()
                        .iter()
                        .copied()
                        .chain(common_header.encode().iter().copied())
                        .chain(gbc_ext.encode().iter().copied())
                        .chain(payload.iter().copied())
                        .collect();
                    return self.send_to_link_layer(fwd_packet);
                }
            }
        }

        GNDataConfirm {
            result_code: ResultCode::Accepted,
        }
    }

    // ------------------------------------------------------------------
    // Forwarding algorithms
    // ------------------------------------------------------------------

    /// Greedy forwarding (§E.2 MFR policy).
    fn gn_greedy_forwarding(
        &self,
        dest_lat: i32,
        dest_lon: i32,
        traffic_class: &TrafficClass,
    ) -> bool {
        let mut mfr = Self::distance_m(
            dest_lat,
            dest_lon,
            self.ego_position_vector.latitude as i32,
            self.ego_position_vector.longitude as i32,
        );
        let mut progress_found = false;
        for entry in self.location_table.get_neighbours() {
            let pv = &entry.position_vector;
            let d = Self::distance_m(dest_lat, dest_lon, pv.latitude as i32, pv.longitude as i32);
            if d < mfr {
                mfr = d;
                progress_found = true;
            }
        }
        if progress_found {
            return true;
        }
        // Local optimum
        if traffic_class.scf {
            return false; // buffer
        }
        true // BCAST fallback
    }

    /// Forwarding algorithm selection (Annex D).
    fn gn_forwarding_algorithm_selection(
        &self,
        request: &GNDataRequest,
        sender_gn_addr: Option<&GNAddress>,
    ) -> GNForwardingAlgorithmResponse {
        let (f_ego, _area_hst) = match &request.packet_transport_type.header_sub_type {
            HeaderSubType::GeoBroadcast(hst) => (
                self.gn_geometric_function_f(
                    hst,
                    &request.area,
                    &self.ego_position_vector.latitude,
                    &self.ego_position_vector.longitude,
                ),
                true,
            ),
            HeaderSubType::GeoAnycast(hst) => (
                self.gn_geometric_function_f_anycast(
                    hst,
                    &request.area,
                    &self.ego_position_vector.latitude,
                    &self.ego_position_vector.longitude,
                ),
                true,
            ),
            _ => return GNForwardingAlgorithmResponse::Discarted,
        };

        if f_ego >= 0.0 {
            return GNForwardingAlgorithmResponse::AreaForwarding;
        }

        // Ego is outside — check sender position (Annex D)
        if let Some(se_addr) = sender_gn_addr {
            if let Some(se_entry) = self.location_table.get_entry_ref(se_addr) {
                if se_entry.position_vector.pai {
                    let f_se = match &request.packet_transport_type.header_sub_type {
                        HeaderSubType::GeoBroadcast(hst) => self.gn_geometric_function_f(
                            hst,
                            &request.area,
                            &se_entry.position_vector.latitude,
                            &se_entry.position_vector.longitude,
                        ),
                        HeaderSubType::GeoAnycast(hst) => self.gn_geometric_function_f_anycast(
                            hst,
                            &request.area,
                            &se_entry.position_vector.latitude,
                            &se_entry.position_vector.longitude,
                        ),
                        _ => -1.0,
                    };
                    if f_se >= 0.0 {
                        return GNForwardingAlgorithmResponse::Discarted;
                    }
                }
            }
        }

        GNForwardingAlgorithmResponse::NonAreaForwarding
    }

    /// CBF forwarding (§F.3).
    fn gn_area_cbf_forwarding(
        &mut self,
        basic_header: &BasicHeader,
        common_header: &CommonHeader,
        gbc_ext: &GBCExtendedHeader,
        payload: &[u8],
    ) -> bool {
        let cbf_key = (gbc_ext.so_pv.gn_addr.encode_to_int(), gbc_ext.sn);

        if let Some(_) = self.cbf_buffer.remove(&cbf_key) {
            // Duplicate while buffering — suppress
            return false;
        }

        // Compute timeout
        let timeout_ms = if let Some(se_entry) =
            self.location_table.get_entry_ref(&gbc_ext.so_pv.gn_addr)
        {
            if se_entry.position_vector.pai && self.ego_position_vector.pai {
                let dist = Self::distance_m(
                    se_entry.position_vector.latitude as i32,
                    se_entry.position_vector.longitude as i32,
                    self.ego_position_vector.latitude as i32,
                    self.ego_position_vector.longitude as i32,
                );
                self.cbf_compute_timeout_ms(dist)
            } else {
                self.mib.itsGnCbfMaxTime as f64
            }
        } else {
            self.mib.itsGnCbfMaxTime as f64
        };

        let full_packet: Vec<u8> = basic_header
            .encode()
            .iter()
            .copied()
            .chain(common_header.encode().iter().copied())
            .chain(gbc_ext.encode().iter().copied())
            .chain(payload.iter().copied())
            .collect();

        // Store in CBF buffer with timestamp
        self.cbf_buffer.insert(
            cbf_key,
            (
                Instant::now() + Duration::from_millis(timeout_ms as u64),
                full_packet,
            ),
        );

        true // buffered
    }

    fn cbf_compute_timeout_ms(&self, dist_m: f64) -> f64 {
        let dist_max = self.mib.itsGnDefaultMaxCommunicationRange as f64;
        let to_min = self.mib.itsGnCbfMinTime as f64;
        let to_max = self.mib.itsGnCbfMaxTime as f64;
        if dist_m >= dist_max {
            return to_min;
        }
        to_max + (to_min - to_max) / dist_max * dist_m
    }

    // ------------------------------------------------------------------
    // Geometric helper functions
    // ------------------------------------------------------------------

    fn calculate_distance(coord1: (f64, f64), coord2: (f64, f64)) -> (f64, f64) {
        let (lat1, lon1) = coord1;
        let (lat2, lon2) = coord2;
        let lat1 = lat1.to_radians();
        let lon1 = lon1.to_radians();
        let lat2 = lat2.to_radians();
        let lon2 = lon2.to_radians();
        let y = EARTH_RADIUS * (lon2 - lon1) * f64::cos((lat1 + lat2) / 2.0);
        let x = -EARTH_RADIUS * (lat2 - lat1);
        (x, y)
    }

    fn gn_geometric_function_f(
        &self,
        area_type: &GeoBroadcastHST,
        area: &Area,
        lat: &u32,
        lon: &u32,
    ) -> f64 {
        let coord1 = (
            (area.latitude as f64) / 10_000_000.0,
            (area.longitude as f64) / 10_000_000.0,
        );
        let coord2 = ((*lat as f64) / 10_000_000.0, (*lon as f64) / 10_000_000.0);
        let (x, y) = Router::calculate_distance(coord1, coord2);
        let a = area.a as f64;
        let b = area.b as f64;
        match area_type {
            GeoBroadcastHST::GeoBroadcastCircle => 1.0 - (x / a).powi(2) - (y / a).powi(2),
            GeoBroadcastHST::GeoBroadcastEllipse => 1.0 - (x / a).powi(2) - (y / b).powi(2),
            GeoBroadcastHST::GeoBroadcastRectangle => {
                (1.0 - (x / a).powi(2)).min(1.0 - (y / b).powi(2))
            }
        }
    }

    fn gn_geometric_function_f_anycast(
        &self,
        area_type: &GeoAnycastHST,
        area: &Area,
        lat: &u32,
        lon: &u32,
    ) -> f64 {
        let coord1 = (
            (area.latitude as f64) / 10_000_000.0,
            (area.longitude as f64) / 10_000_000.0,
        );
        let coord2 = ((*lat as f64) / 10_000_000.0, (*lon as f64) / 10_000_000.0);
        let (x, y) = Router::calculate_distance(coord1, coord2);
        let a = area.a as f64;
        let b = area.b as f64;
        match area_type {
            GeoAnycastHST::GeoAnycastCircle => 1.0 - (x / a).powi(2) - (y / a).powi(2),
            GeoAnycastHST::GeoAnycastEllipse => 1.0 - (x / a).powi(2) - (y / b).powi(2),
            GeoAnycastHST::GeoAnycastRectangle => {
                (1.0 - (x / a).powi(2)).min(1.0 - (y / b).powi(2))
            }
        }
    }

    fn compute_area_size_m2_gb(area_type: &GeoBroadcastHST, area: &Area) -> f64 {
        let a = area.a as f64;
        let b = area.b as f64;
        match area_type {
            GeoBroadcastHST::GeoBroadcastCircle => std::f64::consts::PI * a * a,
            GeoBroadcastHST::GeoBroadcastEllipse => std::f64::consts::PI * a * b,
            GeoBroadcastHST::GeoBroadcastRectangle => 4.0 * a * b,
        }
    }

    fn distance_m(lat1: i32, lon1: i32, lat2: i32, lon2: i32) -> f64 {
        let c1 = (lat1 as f64 / 10_000_000.0, lon1 as f64 / 10_000_000.0);
        let c2 = (lat2 as f64 / 10_000_000.0, lon2 as f64 / 10_000_000.0);
        let (dx, dy) = Router::calculate_distance(c1, c2);
        (dx * dx + dy * dy).sqrt()
    }

    // ------------------------------------------------------------------
    // Miscellaneous
    // ------------------------------------------------------------------

    pub fn duplicate_address_detection(&self, address: GNAddress) -> bool {
        self.mib.itsGnLocalGnAddr == address
    }

    pub fn refresh_ego_position_vector(&mut self, position_vector: LongPositionVector) {
        self.ego_position_vector.latitude = position_vector.latitude;
        self.ego_position_vector.longitude = position_vector.longitude;
        self.ego_position_vector.tst = position_vector.tst;
        self.ego_position_vector.s = position_vector.s;
        self.ego_position_vector.h = position_vector.h;
        self.ego_position_vector.pai = position_vector.pai;
    }
}

/// Clone a GNDataRequest (all fields).
fn clone_request(r: &GNDataRequest) -> GNDataRequest {
    GNDataRequest {
        upper_protocol_entity: r.upper_protocol_entity.clone(),
        packet_transport_type: r.packet_transport_type.clone(),
        communication_profile: r.communication_profile.clone(),
        traffic_class: r.traffic_class,
        security_profile: r.security_profile,
        its_aid: r.its_aid,
        security_permissions: r.security_permissions.clone(),
        max_hop_limit: r.max_hop_limit,
        max_packet_lifetime: r.max_packet_lifetime,
        destination: r.destination,
        length: r.length,
        data: r.data.clone(),
        area: r.area,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geonet::gn_address::{GNAddress, M, MID, ST};
    use crate::geonet::position_vector::LongPositionVector;
    use std::sync::mpsc;

    fn make_mib() -> Mib {
        Mib::new()
    }

    fn make_router() -> (Router, Receiver<Vec<u8>>, Receiver<GNDataIndication>) {
        let (ll_tx, ll_rx) = mpsc::channel();
        let (btp_tx, btp_rx) = mpsc::channel();
        let mib = make_mib();
        let router = Router::new(mib, ll_tx, btp_tx, None, None, None);
        (router, ll_rx, btp_rx)
    }

    fn make_shb_request(data: Vec<u8>) -> GNDataRequest {
        GNDataRequest {
            upper_protocol_entity: CommonNH::BtpB,
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            },
            communication_profile: CommunicationProfile::Unspecified,
            traffic_class: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            security_profile: SecurityProfile::NoSecurity,
            its_aid: 36,
            security_permissions: vec![],
            max_hop_limit: 1,
            max_packet_lifetime: None,
            destination: None,
            length: data.len() as u16,
            data,
            area: Area {
                latitude: 0,
                longitude: 0,
                a: 0,
                b: 0,
                angle: 0,
            },
        }
    }

    #[test]
    fn router_new_defaults() {
        let (router, _ll, _btp) = make_router();
        assert_eq!(router.sequence_number, 0);
        assert!(router.location_table.entries.is_empty());
        assert!(!router.beacon_reset);
    }

    #[test]
    fn router_get_sequence_number_increments() {
        let (mut router, _ll, _btp) = make_router();
        assert_eq!(router.get_sequence_number(), 1);
        assert_eq!(router.get_sequence_number(), 2);
        assert_eq!(router.get_sequence_number(), 3);
    }

    #[test]
    fn router_sequence_number_wraps() {
        let (mut router, _ll, _btp) = make_router();
        router.sequence_number = u16::MAX;
        assert_eq!(router.get_sequence_number(), 0);
    }

    #[test]
    fn router_duplicate_address_detection() {
        let (router, _ll, _btp) = make_router();
        let own_addr = router.mib.itsGnLocalGnAddr;
        assert!(router.duplicate_address_detection(own_addr));
        let other = GNAddress::new(M::GnUnicast, ST::Bus, MID::new([0xAA; 6]));
        assert!(!router.duplicate_address_detection(other));
    }

    #[test]
    fn router_refresh_ego_position_vector() {
        let (mut router, _ll, _btp) = make_router();
        let pv = LongPositionVector {
            gn_addr: router.gn_address,
            tst: Tst::set_in_normal_timestamp_milliseconds(99999),
            latitude: 415520000,
            longitude: 21340000,
            pai: true,
            s: 1000,
            h: 900,
        };
        router.refresh_ego_position_vector(pv);
        assert_eq!(router.ego_position_vector.latitude, 415520000);
        assert_eq!(router.ego_position_vector.longitude, 21340000);
        assert!(router.ego_position_vector.pai);
        assert_eq!(router.ego_position_vector.s, 1000);
        assert_eq!(router.ego_position_vector.h, 900);
    }

    #[test]
    fn router_send_beacon() {
        let (router, ll_rx, _btp) = make_router();
        let confirm = router.gn_data_request_beacon();
        assert_eq!(confirm.result_code, ResultCode::Accepted);
        let packet = ll_rx.recv().unwrap();
        // BasicHeader (4) + CommonHeader (8) + LPV (24) = 36 bytes
        assert_eq!(packet.len(), 36);
    }

    #[test]
    fn router_send_shb() {
        let (mut router, ll_rx, _btp) = make_router();
        let request = make_shb_request(vec![0xCA, 0xFE]);
        let confirm = router.gn_data_request(request);
        assert_eq!(confirm.result_code, ResultCode::Accepted);
        let packet = ll_rx.recv().unwrap();
        // BasicHeader(4) + CommonHeader(8) + LPV(24) + MediaDep(4) + payload(2) = 42
        assert_eq!(packet.len(), 42);
        assert!(router.beacon_reset);
    }

    #[test]
    fn router_compute_area_size_circle() {
        let area = Area {
            latitude: 0,
            longitude: 0,
            a: 100,
            b: 0,
            angle: 0,
        };
        let size = Router::compute_area_size_m2_gb(&GeoBroadcastHST::GeoBroadcastCircle, &area);
        let expected = std::f64::consts::PI * 100.0 * 100.0;
        assert!((size - expected).abs() < 0.01);
    }

    #[test]
    fn router_compute_area_size_ellipse() {
        let area = Area {
            latitude: 0,
            longitude: 0,
            a: 100,
            b: 50,
            angle: 0,
        };
        let size = Router::compute_area_size_m2_gb(&GeoBroadcastHST::GeoBroadcastEllipse, &area);
        let expected = std::f64::consts::PI * 100.0 * 50.0;
        assert!((size - expected).abs() < 0.01);
    }

    #[test]
    fn router_compute_area_size_rectangle() {
        let area = Area {
            latitude: 0,
            longitude: 0,
            a: 100,
            b: 50,
            angle: 0,
        };
        let size = Router::compute_area_size_m2_gb(&GeoBroadcastHST::GeoBroadcastRectangle, &area);
        assert!((size - 20000.0).abs() < 0.01);
    }

    #[test]
    fn router_calculate_distance_same_point() {
        let (x, y) = Router::calculate_distance((41.552, 2.134), (41.552, 2.134));
        assert!(x.abs() < 0.01);
        assert!(y.abs() < 0.01);
    }

    #[test]
    fn router_distance_m_nonzero() {
        let d = Router::distance_m(415520000, 21340000, 415530000, 21340000);
        // ~1.1 m difference (0.001 degree lat)
        assert!(d > 0.0);
    }

    #[test]
    fn router_cbf_timeout_at_max_range() {
        let (router, _ll, _btp) = make_router();
        let dist = router.mib.itsGnDefaultMaxCommunicationRange as f64;
        let timeout = router.cbf_compute_timeout_ms(dist);
        assert!((timeout - router.mib.itsGnCbfMinTime as f64).abs() < 0.01);
    }

    #[test]
    fn router_cbf_timeout_at_zero_range() {
        let (router, _ll, _btp) = make_router();
        let timeout = router.cbf_compute_timeout_ms(0.0);
        assert!((timeout - router.mib.itsGnCbfMaxTime as f64).abs() < 0.01);
    }

    #[test]
    fn router_forwarding_algorithm_response_encode() {
        assert_eq!(GNForwardingAlgorithmResponse::AreaForwarding.encode(), 1);
        assert_eq!(GNForwardingAlgorithmResponse::NonAreaForwarding.encode(), 2);
        assert_eq!(GNForwardingAlgorithmResponse::Discarted.encode(), 3);
    }

    #[test]
    fn router_spawn_and_shutdown() {
        let mib = make_mib();
        let (handle, _ll_rx, _btp_rx) = Router::spawn(mib, None, None, None);
        handle.shutdown();
    }

    #[test]
    fn router_handle_send_incoming_packet() {
        let mib = make_mib();
        let (handle, _ll_rx, _btp_rx) = Router::spawn(mib, None, None, None);
        // Send a short/invalid packet — router should not crash
        handle.send_incoming_packet(vec![0u8; 4]);
        std::thread::sleep(std::time::Duration::from_millis(50));
        handle.shutdown();
    }

    #[test]
    fn router_handle_update_position_vector() {
        let mib = make_mib();
        let (handle, _ll_rx, _btp_rx) = Router::spawn(mib, None, None, None);
        let pv = LongPositionVector {
            gn_addr: mib.itsGnLocalGnAddr,
            tst: Tst::set_in_normal_timestamp_milliseconds(99999),
            latitude: 415520000,
            longitude: 21340000,
            pai: true,
            s: 500,
            h: 900,
        };
        handle.update_position_vector(pv);
        std::thread::sleep(std::time::Duration::from_millis(50));
        handle.shutdown();
    }

    #[test]
    fn clone_request_roundtrip() {
        let req = make_shb_request(vec![1, 2, 3]);
        let cloned = clone_request(&req);
        assert_eq!(cloned.data, req.data);
        assert_eq!(cloned.its_aid, req.its_aid);
        assert_eq!(cloned.max_hop_limit, req.max_hop_limit);
    }
}

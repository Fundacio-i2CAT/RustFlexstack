// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! GeoNetworking Router — ETSI EN 302 636-4-1.
//!
//! The router is implemented as a single-threaded actor.  All interaction
//! happens through a [`RouterHandle`] that serialises messages into the
//! router's message queue.
//!
//! # Architecture
//! ```text
//!  Facilities / BTP
//!       │ GNDataRequest          GNDataIndication ↑
//!       ▼                                          │
//!  ┌─────────────────────────────────────────────┐ │
//!  │              GeoNetworking Router            │─┘
//!  │  (BasicHeader, CommonHeader, SHB/GBC/Beacon) │
//!  └─────────────────────────────────────────────┘
//!       │ Vec<u8> (raw GN packet)   Vec<u8> ↑
//!       ▼                                    │
//!             Link Layer (Ethernet / C-V2X)
//! ```
//!
//! # Concurrency
//! The router spawns **one** background thread.  The link layer, BTP layer and
//! any position-update threads all communicate with it exclusively through the
//! [`RouterHandle`] MPSC sender.  There are no shared mutable references —
//! all state lives inside the router thread.

use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::time::Duration;

use super::basic_header::{BasicHeader, BasicNH};
use super::common_header::CommonHeader;
use super::gbc_extended_header::GBCExtendedHeader;
use super::gn_address::GNAddress;
use super::location_table::LocationTable;
use super::mib::Mib;
use super::position_vector::LongPositionVector;
use super::service_access_point::{
    Area, CommunicationProfile, GNDataConfirm, GNDataIndication, GNDataRequest, GeoBroadcastHST,
    HeaderSubType, PacketTransportType, ResultCode, HeaderType, TopoBroadcastHST, CommonNH,
    UnspecifiedHST,
};


/// Approximate Earth radius used in the geographic containment function.
const EARTH_RADIUS: f32 = 6371000.0;

// ------------------------------------------------------------------
// Router message types
// ------------------------------------------------------------------

/// Messages that the router processes from its input queue.
pub enum RouterInput {
    /// A higher-layer data request (send a GN packet).
    GNDataRequest(GNDataRequest),
    /// A raw packet received from the link layer.
    IncomingPacket(Vec<u8>),
    /// Update the router's ego position vector (e.g. from a GPS fix).
    PositionVectorUpdate(LongPositionVector),
    /// Trigger a graceful shutdown of the router thread.
    Shutdown,
}

/// Response type sent from the router to the BTP layer on receive.
pub enum RouterOutput {
    /// A raw packet destined for the link layer.
    LinkLayerPacket(Vec<u8>),
    /// An indication to pass up to the BTP layer.
    BTPIndication(GNDataIndication),
}

/// Result of the GN forwarding algorithm selection.
#[derive(PartialEq)]
pub enum GNForwardingAlgorithmResponse {
    /// Node is inside the destination area — forward using area forwarding.
    AreaForwarding,
    /// Node is outside the destination area — use non-area (greedy) forwarding.
    NonAreaForwarding,
    /// Packet should be discarded.
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

/// Trait for receiving GN data indications via a callback.
pub trait GNIndicationCallback {
    fn gn_indication_callback(&mut self, indication: GNDataIndication);
}

// ------------------------------------------------------------------
// Router struct and RouterHandle
// ------------------------------------------------------------------

/// The internal GeoNetworking router state.
///
/// Instantiated and owned exclusively by the router thread — do not
/// construct this directly; use [`Router::spawn`] instead.
pub struct Router {
    /// Management Information Base — protocol parameters.
    pub mib: Mib,
    /// This node's GN address (derived from MIB + MAC).
    pub gn_address: GNAddress,
    /// Current ego Long Position Vector (updated by GPS).
    pub ego_position_vector: LongPositionVector,
    /// 16-bit sequence number, wraps at 2^16-1.
    pub sequence_number: u16,
    /// Location table (neighbours + remote stations).
    pub location_table: LocationTable,

    /// Channel to the link layer (GN → LL).
    link_layer_tx: Sender<Vec<u8>>,
    /// Channel to the BTP layer (GN → BTP).
    btp_tx: Sender<GNDataIndication>,
}

/// A clonable handle to the running GeoNetworking router.
///
/// All public interaction with the router must go through this handle.
#[derive(Clone)]
pub struct RouterHandle {
    input_tx: Sender<RouterInput>,
}

impl RouterHandle {
    /// Send a GN data request (i.e. transmit a GN packet).
    pub fn send_gn_data_request(&self, request: GNDataRequest) {
        let _ = self.input_tx.send(RouterInput::GNDataRequest(request));
    }

    /// Inject a raw packet received from the link layer into the router.
    pub fn send_incoming_packet(&self, packet: Vec<u8>) {
        let _ = self.input_tx.send(RouterInput::IncomingPacket(packet));
    }

    /// Push a new position vector update (e.g. from a GPS thread).
    pub fn update_position_vector(&self, position_vector: LongPositionVector) {
        let _ = self.input_tx.send(RouterInput::PositionVectorUpdate(position_vector));
    }

    /// Shut down the router thread.
    pub fn shutdown(self) {
        let _ = self.input_tx.send(RouterInput::Shutdown);
    }
}

// ------------------------------------------------------------------
// Router implementation
// ------------------------------------------------------------------

impl Router {
    /// Create a new router instance.  Prefer [`Router::spawn`].
    pub fn new(
        mib: Mib,
        link_layer_tx: Sender<Vec<u8>>,
        btp_tx: Sender<GNDataIndication>,
    ) -> Self {
        Router {
            mib: mib.clone(),
            gn_address: mib.itsGnLocalGnAddr,
            ego_position_vector: LongPositionVector {
                gn_addr: mib.itsGnLocalGnAddr,
                tst: super::position_vector::Tst::set_in_normal_timestamp_milliseconds(0),
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
        }
    }

    /// Spawn the router actor thread.
    ///
    /// Returns:
    /// - A [`RouterHandle`] for sending messages to the router.
    /// - A [`Receiver<Vec<u8>>`] for raw packets that the router wants to send
    ///   to the link layer.
    /// - A [`Receiver<GNDataIndication>`] for indications to forward to BTP.
    ///
    /// Also starts the Beacon service if
    /// `mib.itsGnBeaconServiceRetransmitTimer > 0`.
    pub fn spawn(
        mib: Mib,
    ) -> (RouterHandle, Receiver<Vec<u8>>, Receiver<GNDataIndication>) {
        let (input_tx, input_rx) = mpsc::channel::<RouterInput>();
        let (link_layer_tx, link_layer_rx) = mpsc::channel::<Vec<u8>>();
        let (btp_tx, btp_rx) = mpsc::channel::<GNDataIndication>();

        let beacon_timer = mib.itsGnBeaconServiceRetransmitTimer;
        let handle = RouterHandle { input_tx: input_tx.clone() };

        // Start the Beacon service before the main router thread so that the
        // handle clone used by the beacon thread is ready.
        if beacon_timer > 0 {
            let beacon_handle = RouterHandle { input_tx: input_tx.clone() };
            thread::spawn(move || {
                // Initial jitter: up to itsGnBeaconServiceMaxJitter ms
                // (simplified: just delay half the timer for the first beacon)
                thread::sleep(Duration::from_millis(beacon_timer as u64 / 2));
                loop {
                    // Send a Beacon request through the regular message queue
                    let _ = beacon_handle.input_tx.send(RouterInput::GNDataRequest(
                        GNDataRequest {
                            upper_protocol_entity: CommonNH::Any,
                            packet_transport_type: PacketTransportType {
                                header_type: HeaderType::Beacon,
                                header_sub_type: HeaderSubType::Unspecified(
                                    UnspecifiedHST::Unspecified,
                                ),
                            },
                            communication_profile: CommunicationProfile::Unspecified,
                            traffic_class: super::service_access_point::TrafficClass {
                                scf: false,
                                channel_offload: false,
                                tc_id: 0,
                            },
                            length: 0,
                            data: vec![],
                            area: Area {
                                latitude: 0,
                                longitude: 0,
                                a: 0,
                                b: 0,
                                angle: 0,
                            },
                        },
                    ));
                    thread::sleep(Duration::from_millis(beacon_timer as u64));
                }
            });
        }

        let _thread_handle = thread::spawn(move || {
            let mut router = Router::new(mib, link_layer_tx, btp_tx);
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
                    self.gn_data_indicate(packet);
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

    /// Increment and return the 16-bit sequence number, wrapping at 2^16-1.
    pub fn get_sequence_number(&mut self) -> u16 {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.sequence_number
    }

    // ------------------------------------------------------------------
    // GN data request — transmit path
    // ------------------------------------------------------------------

    /// Build and send a **Single-Hop Broadcast** (SHB / TSB) GN packet.
    fn gn_data_request_shb(&self, request: GNDataRequest) -> GNDataConfirm {
        let mut basic_header = BasicHeader::initialize_with_mib(&self.mib);
        basic_header.rhl = 1; // SHB: hop limit fixed to 1
        let common_header = CommonHeader::initialize_with_request(&request);
        let media_dependent_data: [u8; 4] = [0; 4];
        let packet: Vec<u8> = basic_header
            .encode()
            .iter()
            .copied()
            .chain(common_header.encode().iter().copied())
            .chain(self.ego_position_vector.encode().iter().copied())
            .chain(media_dependent_data.iter().copied())
            .chain(request.data.iter().copied())
            .collect();

        match self.link_layer_tx.send(packet) {
            Ok(_) => GNDataConfirm { result_code: ResultCode::Accepted },
            Err(_) => GNDataConfirm { result_code: ResultCode::Unspecified },
        }
    }

    /// Build and send a **Beacon** GN packet.
    ///
    /// A Beacon carries no payload; it just announces the node's presence and
    /// position to neighbours.
    fn gn_data_request_beacon(&self) -> GNDataConfirm {
        let mut basic_header = BasicHeader::initialize_with_mib(&self.mib);
        basic_header.rhl = 1;
        // CommonHeader for Beacon: ht = Beacon, nh = Any, pl = 0
        let beacon_bytes: [u8; 8] = {
            let ht = HeaderType::Beacon.encode() << 4;
            let nh = CommonNH::Any.encode() << 4;
            let tc = 0u8;
            let flags = 0u8;
            let pl: u16 = 0;
            let mhl: u8 = 1;
            [nh, ht, tc, flags, (pl >> 8) as u8, pl as u8, mhl, 0]
        };
        let packet: Vec<u8> = basic_header
            .encode()
            .iter()
            .copied()
            .chain(beacon_bytes.iter().copied())
            .chain(self.ego_position_vector.encode().iter().copied())
            .collect();

        match self.link_layer_tx.send(packet) {
            Ok(_) => GNDataConfirm { result_code: ResultCode::Accepted },
            Err(_) => GNDataConfirm { result_code: ResultCode::Unspecified },
        }
    }

    /// Build and send a **Geo-Broadcast** (GBC) GN packet.
    fn gn_data_request_gbc(&mut self, request: GNDataRequest) -> GNDataConfirm {
        let basic_header = BasicHeader::initialize_with_mib(&self.mib);
        let common_header = CommonHeader::initialize_with_request(&request);

        let gbc_extended_header = GBCExtendedHeader {
            sn: self.get_sequence_number(),
            reserved: 0,
            so_pv: self.ego_position_vector,
            latitude: request.area.latitude,
            longitude: request.area.longitude,
            a: request.area.a,
            b: request.area.b,
            angle: request.area.angle,
            reserved2: 0,
        };

        // Only send if we have neighbours or SCF is disabled
        if !self.location_table.get_neighbours().is_empty() || !request.traffic_class.scf {
            let algorithm = self.gn_forwarding_algorithm_selection(&request);

            if algorithm == GNForwardingAlgorithmResponse::AreaForwarding
                || algorithm == GNForwardingAlgorithmResponse::NonAreaForwarding
            {
                let packet: Vec<u8> = basic_header
                    .encode()
                    .iter()
                    .copied()
                    .chain(common_header.encode().iter().copied())
                    .chain(gbc_extended_header.encode().iter().copied())
                    .chain(request.data.iter().copied())
                    .collect();

                return match self.link_layer_tx.send(packet) {
                    Ok(_) => GNDataConfirm { result_code: ResultCode::Accepted },
                    Err(_) => GNDataConfirm { result_code: ResultCode::Unspecified },
                };
            }
        }
        GNDataConfirm { result_code: ResultCode::Unspecified }
    }

    /// Dispatch a [`GNDataRequest`] from the higher layer.
    pub fn gn_data_request(&mut self, request: GNDataRequest) -> GNDataConfirm {
        match request.packet_transport_type.header_type {
            HeaderType::Beacon => {
                return self.gn_data_request_beacon();
            }
            HeaderType::Tsb => {
                if let HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop) =
                    request.packet_transport_type.header_sub_type
                {
                    return self.gn_data_request_shb(request);
                }
                eprintln!("[GN] Unsupported TSB sub-type");
            }
            HeaderType::GeoBroadcast => {
                return self.gn_data_request_gbc(request);
            }
            _ => {
                eprintln!("[GN] Header type not supported");
            }
        }
        GNDataConfirm { result_code: ResultCode::Unspecified }
    }

    // ------------------------------------------------------------------
    // GN indicate — receive path
    // ------------------------------------------------------------------

    /// Process a received SHB packet and return a [`GNDataIndication`].
    fn gn_data_indicate_shb(
        &mut self,
        packet: Vec<u8>,
        common_header: CommonHeader,
    ) -> GNDataIndication {
        let lpv = LongPositionVector::decode(
            packet[0..24].try_into().expect("SHB: LPV slice wrong length"),
        );
        // Payload starts after LPV (24 bytes) + media-dependent field (4 bytes)
        let payload = packet[28..].to_vec();
        self.location_table.new_shb_packet(&lpv, &packet);
        GNDataIndication {
            upper_protocol_entity: common_header.nh,
            packet_transport_type: PacketTransportType {
                header_type: common_header.ht,
                header_sub_type: common_header.hst,
            },
            source_position_vector: lpv,
            traffic_class: common_header.tc,
            length: payload.len() as u16,
            data: payload,
        }
    }

    /// Process a received Beacon packet (update location table only; no indication).
    fn gn_data_indicate_beacon(&mut self, packet: Vec<u8>) {
        if packet.len() >= 24 {
            let lpv = LongPositionVector::decode(
                packet[0..24].try_into().expect("Beacon: LPV slice wrong length"),
            );
            self.location_table.new_shb_packet(&lpv, &packet);
        }
    }

    /// Process a received GBC packet.
    ///
    /// Returns `Some(indication)` if:
    /// - The packet is not a duplicate.
    /// - The node is inside the destination area.
    ///
    /// Also re-forwards the packet if the node is inside the area
    /// and `rhl > 1`.
    fn gn_data_indicate_gbc(
        &mut self,
        packet: Vec<u8>,
        common_header: CommonHeader,
        basic_header: BasicHeader,
        area_type: GeoBroadcastHST,
    ) -> Option<GNDataIndication> {
        let ext: GBCExtendedHeader = GBCExtendedHeader::decode(
            packet[0..44].try_into().expect("GBC: extended header slice wrong length"),
        );
        let area = Area {
            latitude: ext.latitude,
            longitude: ext.longitude,
            a: ext.a,
            b: ext.b,
            angle: ext.angle,
        };

        let area_f = self.gn_geometric_function_f(
            &area_type,
            &area,
            &self.ego_position_vector.latitude,
            &self.ego_position_vector.longitude,
        );

        // Duplicate address detection: drop packets originating from self
        if self.duplicate_address_detection(ext.so_pv.gn_addr) {
            return None;
        }

        self.location_table.new_gbc_packet(&ext, &packet);

        // Re-forward if inside area and hop limit allows it
        if area_f >= 0.0 && basic_header.rhl > 1 {
            self.gn_data_forward_gbc(&basic_header, &common_header, &ext, &packet);
        }

        if area_f >= 0.0 {
            let payload = packet[44..].to_vec();
            return Some(GNDataIndication {
                upper_protocol_entity: common_header.nh,
                packet_transport_type: PacketTransportType {
                    header_type: common_header.ht,
                    header_sub_type: common_header.hst,
                },
                source_position_vector: ext.so_pv,
                traffic_class: common_header.tc,
                length: payload.len() as u16,
                data: payload,
            });
        }
        None
    }

    /// Top-level receive dispatcher.
    ///
    /// Parses the Basic Header and Common Header, then dispatches to the
    /// appropriate sub-function based on header type.
    pub fn gn_data_indicate(&mut self, packet: Vec<u8>) {
        if packet.len() < 12 {
            eprintln!("[GN] Packet too short to contain headers");
            return;
        }
        let basic_header = BasicHeader::decode(
            packet[0..4].try_into().expect("BasicHeader slice wrong length"),
        );
        if basic_header.version != self.mib.itsGnProtocolVersion {
            eprintln!("[GN] Protocol version mismatch");
            return;
        }
        match basic_header.nh {
            BasicNH::CommonHeader => {
                if basic_header.rhl > self.mib.itsGnDefaultHopLimit {
                    eprintln!("[GN] Hop limit exceeded");
                    return;
                }
                let common_header = CommonHeader::decode(
                    packet[4..12].try_into().expect("CommonHeader slice wrong length"),
                );
                let payload = packet[12..].to_vec();
                match common_header.ht {
                    HeaderType::Beacon => {
                        self.gn_data_indicate_beacon(payload);
                    }
                    HeaderType::Tsb => {
                        if let HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop) =
                            common_header.hst
                        {
                            let indication =
                                self.gn_data_indicate_shb(payload, common_header);
                            let _ = self.btp_tx.send(indication);
                        } else {
                            eprintln!("[GN] Unsupported TSB sub-type");
                        }
                    }
                    HeaderType::GeoBroadcast => {
                        if let HeaderSubType::GeoBroadcast(area_type) = common_header.hst {
                            let indication = self.gn_data_indicate_gbc(
                                payload,
                                common_header,
                                basic_header,
                                area_type,
                            );
                            if let Some(ind) = indication {
                                let _ = self.btp_tx.send(ind);
                            }
                        } else {
                            eprintln!("[GN] GBC header sub-type mismatch");
                        }
                    }
                    _ => {
                        eprintln!("[GN] Header type not supported");
                    }
                }
            }
            BasicNH::SecuredPacket => {
                // Security decapsulation not implemented — drop silently
            }
            _ => {
                eprintln!("[GN] Basic NH not supported");
            }
        }
    }

    // ------------------------------------------------------------------
    // GBC forwarding
    // ------------------------------------------------------------------

    /// Re-forward a received GBC packet towards the destination area.
    ///
    /// Decrements the RHL, re-runs the forwarding algorithm, and transmits
    /// if the result is [`GNForwardingAlgorithmResponse::AreaForwarding`].
    fn gn_data_forward_gbc(
        &self,
        basic_header: &BasicHeader,
        common_header: &CommonHeader,
        gbc_extended_header: &GBCExtendedHeader,
        payload: &[u8],
    ) -> GNDataConfirm {
        let mut fwd_basic = *basic_header;
        fwd_basic.rhl = basic_header.rhl.saturating_sub(1);

        if fwd_basic.rhl == 0 {
            return GNDataConfirm { result_code: ResultCode::Unspecified };
        }

        let request = GNDataRequest {
            upper_protocol_entity: common_header.nh.clone(),
            communication_profile: CommunicationProfile::Unspecified,
            traffic_class: common_header.tc,
            length: payload.len() as u16,
            data: payload.to_vec(),
            area: Area {
                latitude: gbc_extended_header.latitude,
                longitude: gbc_extended_header.longitude,
                a: gbc_extended_header.a,
                b: gbc_extended_header.b,
                angle: gbc_extended_header.angle,
            },
            packet_transport_type: PacketTransportType {
                header_type: common_header.ht.clone(),
                header_sub_type: common_header.hst.clone(),
            },
        };

        if self.gn_forwarding_algorithm_selection(&request)
            == GNForwardingAlgorithmResponse::AreaForwarding
        {
            let fwd_packet: Vec<u8> = fwd_basic
                .encode()
                .iter()
                .copied()
                .chain(common_header.encode().iter().copied())
                .chain(gbc_extended_header.encode().iter().copied())
                .chain(payload.iter().copied())
                .collect();
            return match self.link_layer_tx.send(fwd_packet) {
                Ok(_) => GNDataConfirm { result_code: ResultCode::Accepted },
                Err(_) => GNDataConfirm { result_code: ResultCode::Unspecified },
            };
        }
        GNDataConfirm { result_code: ResultCode::Unspecified }
    }

    // ------------------------------------------------------------------
    // Geometric helper functions
    // ------------------------------------------------------------------

    fn calculate_distance(coord1: (f32, f32), coord2: (f32, f32)) -> (f32, f32) {
        let (lat1, lon1) = coord1;
        let (lat2, lon2) = coord2;
        let lat1 = lat1.to_radians();
        let lon1 = lon1.to_radians();
        let lat2 = lat2.to_radians();
        let lon2 = lon2.to_radians();
        let y = EARTH_RADIUS * (lon2 - lon1) * f32::cos((lat1 + lat2) / 2.0);
        let x = -EARTH_RADIUS * (lat2 - lat1);
        (x, y)
    }

    /// Evaluate whether a point at (`lat`, `lon`) is inside `area`.
    ///
    /// Returns a value ≥ 0 when the point is inside, < 0 when outside.
    fn gn_geometric_function_f(
        &self,
        area_type: &GeoBroadcastHST,
        area: &Area,
        lat: &u32,
        lon: &u32,
    ) -> f32 {
        let coord1 = (
            (area.latitude as f32) / 10_000_000.0,
            (area.longitude as f32) / 10_000_000.0,
        );
        let coord2 = (
            (*lat as f32) / 10_000_000.0,
            (*lon as f32) / 10_000_000.0,
        );
        let (x, y) = Router::calculate_distance(coord1, coord2);
        match area_type {
            GeoBroadcastHST::GeoBroadcastCircle => {
                1.0 - (x / area.a as f32).powi(2) - (y / area.a as f32).powi(2)
            }
            GeoBroadcastHST::GeoBroadcastRectangle => {
                1.0 - (x / area.a as f32).powi(2) - (y / area.b as f32).powi(2)
            }
            GeoBroadcastHST::GeoBroadcastEllipse => {
                (1.0 - (x / area.a as f32).powi(2))
                    .min(1.0 - (y / area.b as f32).powi(2))
            }
        }
    }

    /// Select the forwarding algorithm for a GN data request.
    fn gn_forwarding_algorithm_selection(
        &self,
        request: &GNDataRequest,
    ) -> GNForwardingAlgorithmResponse {
        if let HeaderSubType::GeoBroadcast(ref hst) =
            request.packet_transport_type.header_sub_type
        {
            let f = self.gn_geometric_function_f(
                hst,
                &request.area,
                &self.ego_position_vector.latitude,
                &self.ego_position_vector.longitude,
            );
            if f >= 0.0 {
                GNForwardingAlgorithmResponse::AreaForwarding
            } else {
                GNForwardingAlgorithmResponse::NonAreaForwarding
            }
        } else {
            GNForwardingAlgorithmResponse::Discarted
        }
    }

    // ------------------------------------------------------------------
    // Miscellaneous
    // ------------------------------------------------------------------

    /// Return `true` if `address` is this node's own GN address.
    pub fn duplicate_address_detection(&self, address: GNAddress) -> bool {
        self.mib.itsGnLocalGnAddr == address
    }

    /// Update the ego position vector from a new GPS fix.
    pub fn refresh_ego_position_vector(&mut self, position_vector: LongPositionVector) {
        self.ego_position_vector.latitude = position_vector.latitude;
        self.ego_position_vector.longitude = position_vector.longitude;
        self.ego_position_vector.tst = position_vector.tst;
        self.ego_position_vector.s = position_vector.s;
        self.ego_position_vector.h = position_vector.h;
        self.ego_position_vector.pai = position_vector.pai;
    }
}

// ------------------------------------------------------------------
// Boiler-plate trait impls needed by compiler
// ------------------------------------------------------------------

use std::convert::TryInto;


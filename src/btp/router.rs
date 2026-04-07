// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! BTP (Basic Transport Protocol) Router — ETSI EN 302 636-5-1.
//!
//! The BTP router sits between the Facilities layer (CAM, DENM, …) and the
//! GeoNetworking layer.  It adds/strips 4-byte BTP-A or BTP-B headers and
//! dispatches received packets to registered port callbacks.
//!
//! Like the GN router, this is implemented as a single-threaded actor.
//! All interaction goes through the [`BTPRouterHandle`].
//!
//! # BTP-A vs BTP-B
//! - **BTP-A** (`CommonNH::BtpA`): carries a *source port* field.  Used for
//!   connection-oriented / acknowledged communication.
//! - **BTP-B** (`CommonNH::BtpB`): carries a *destination port info* field
//!   instead of a source port.  Used for connectionless broadcast (CAM, DENM).

use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use super::btp_header::{BTPAHeader, BTPBHeader};
use super::service_access_point::{BTPDataIndication, BTPDataRequest};
use crate::geonet::mib::Mib;
use crate::geonet::service_access_point::CommonNH;
use crate::geonet::service_access_point::{GNDataIndication, GNDataRequest};

// ------------------------------------------------------------------
// Message types
// ------------------------------------------------------------------

pub enum BTPRouterInput {
    BTPDataRequest(BTPDataRequest),
    GNDataIndication(GNDataIndication),
    RegisterPort(u16, Sender<BTPDataIndication>),
    UnregisterPort(u16),
    Shutdown,
}

// ------------------------------------------------------------------
// Router and handle
// ------------------------------------------------------------------

pub struct Router {
    _mib: Mib,
    port_callbacks: HashMap<u16, Sender<BTPDataIndication>>,
    gn_request_tx: Sender<GNDataRequest>,
}

#[derive(Clone)]
pub struct BTPRouterHandle {
    input_tx: Sender<BTPRouterInput>,
}

impl BTPRouterHandle {
    pub fn send_btp_data_request(&self, request: BTPDataRequest) {
        let _ = self.input_tx.send(BTPRouterInput::BTPDataRequest(request));
    }

    pub fn send_gn_data_indication(&self, indication: GNDataIndication) {
        let _ = self
            .input_tx
            .send(BTPRouterInput::GNDataIndication(indication));
    }

    pub fn register_port(&self, port: u16, callback_tx: Sender<BTPDataIndication>) {
        let _ = self
            .input_tx
            .send(BTPRouterInput::RegisterPort(port, callback_tx));
    }

    pub fn unregister_port(&self, port: u16) {
        let _ = self.input_tx.send(BTPRouterInput::UnregisterPort(port));
    }

    pub fn shutdown(self) {
        let _ = self.input_tx.send(BTPRouterInput::Shutdown);
    }
}

// ------------------------------------------------------------------
// Router implementation
// ------------------------------------------------------------------

impl Router {
    pub fn new(mib: Mib, gn_request_tx: Sender<GNDataRequest>) -> Self {
        Router {
            _mib: mib,
            port_callbacks: HashMap::new(),
            gn_request_tx,
        }
    }

    pub fn spawn(mib: Mib) -> (BTPRouterHandle, Receiver<GNDataRequest>) {
        let (input_tx, input_rx) = mpsc::channel::<BTPRouterInput>();
        let (gn_request_tx, gn_request_rx) = mpsc::channel::<GNDataRequest>();

        thread::spawn(move || {
            let mut router = Router::new(mib, gn_request_tx);
            router.run(input_rx);
        });

        let handle = BTPRouterHandle { input_tx };
        (handle, gn_request_rx)
    }

    fn run(&mut self, input_rx: Receiver<BTPRouterInput>) {
        loop {
            match input_rx.recv() {
                Ok(BTPRouterInput::BTPDataRequest(req)) => {
                    self.btp_data_request(req);
                }
                Ok(BTPRouterInput::GNDataIndication(ind)) => {
                    self.btp_data_indication(ind);
                }
                Ok(BTPRouterInput::RegisterPort(port, tx)) => {
                    self.port_callbacks.insert(port, tx);
                }
                Ok(BTPRouterInput::UnregisterPort(port)) => {
                    self.port_callbacks.remove(&port);
                }
                Ok(BTPRouterInput::Shutdown) | Err(_) => break,
            }
        }
    }

    // ------------------------------------------------------------------
    // Transmit path
    // ------------------------------------------------------------------

    fn btp_data_request(&mut self, request: BTPDataRequest) {
        let header_bytes: [u8; 4] = match request.btp_type {
            CommonNH::BtpA => BTPAHeader::initialize_with_request(&request).encode(),
            CommonNH::BtpB => BTPBHeader::initialize_with_request(&request).encode(),
            _ => {
                eprintln!("[BTP] Unsupported BTP type in request");
                return;
            }
        };

        let payload: Vec<u8> = header_bytes
            .iter()
            .copied()
            .chain(request.data.iter().copied())
            .collect();

        let gn_request = GNDataRequest {
            upper_protocol_entity: request.btp_type.clone(),
            packet_transport_type: request.gn_packet_transport_type.clone(),
            communication_profile: request.communication_profile.clone(),
            traffic_class: request.traffic_class,
            security_profile: request.security_profile,
            its_aid: request.its_aid,
            security_permissions: request.security_permissions.clone(),
            max_hop_limit: request.gn_max_hop_limit,
            max_packet_lifetime: request.gn_max_packet_lifetime,
            destination: request.destination,
            length: payload.len() as u16,
            area: request.gn_area,
            data: payload,
        };
        let _ = self.gn_request_tx.send(gn_request);
    }

    // ------------------------------------------------------------------
    // Receive path
    // ------------------------------------------------------------------

    fn btpb_data_indication(&mut self, gn_ind: GNDataIndication) {
        if gn_ind.data.len() < 4 {
            eprintln!("[BTP] BTP-B payload too short");
            return;
        }
        let btp_bytes: [u8; 4] = gn_ind.data[0..4].try_into().unwrap();
        let header = BTPBHeader::decode(btp_bytes);

        let indication = BTPDataIndication::initialize_with_gn_data_indication(&gn_ind)
            .set_destination_port_and_info(header.destination_port, header.destination_port_info);

        match self.port_callbacks.get(&indication.destination_port) {
            Some(tx) => {
                let _ = tx.send(indication);
            }
            None => {
                eprintln!(
                    "[BTP] No sink registered for port {}",
                    indication.destination_port
                );
            }
        }
    }

    fn btpa_data_indication(&mut self, gn_ind: GNDataIndication) {
        if gn_ind.data.len() < 4 {
            eprintln!("[BTP] BTP-A payload too short");
            return;
        }
        let btp_bytes: [u8; 4] = gn_ind.data[0..4].try_into().unwrap();
        let header = BTPAHeader::decode(btp_bytes);

        let mut indication = BTPDataIndication::initialize_with_gn_data_indication(&gn_ind)
            .set_destination_port_and_info(header.destination_port(), 0);
        indication.source_port = header.source_port();

        match self.port_callbacks.get(&indication.destination_port) {
            Some(tx) => {
                let _ = tx.send(indication);
            }
            None => {
                eprintln!(
                    "[BTP] No sink registered for port {}",
                    indication.destination_port
                );
            }
        }
    }

    fn btp_data_indication(&mut self, gn_ind: GNDataIndication) {
        match gn_ind.upper_protocol_entity {
            CommonNH::BtpB => self.btpb_data_indication(gn_ind),
            CommonNH::BtpA => self.btpa_data_indication(gn_ind),
            _ => eprintln!("[BTP] Unsupported upper protocol entity in indication"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btp::btp_header::{BTPAHeader, BTPBHeader};
    use crate::geonet::position_vector::LongPositionVector;
    use crate::geonet::service_access_point::{
        CommonNH, GNDataIndication, HeaderSubType, HeaderType, PacketTransportType,
        TopoBroadcastHST, TrafficClass, UnspecifiedHST,
    };
    use std::sync::mpsc;
    use std::time::Duration;

    fn make_mib() -> Mib {
        Mib::new()
    }

    fn make_gn_data_indication(nh: CommonNH, data: Vec<u8>) -> GNDataIndication {
        GNDataIndication {
            upper_protocol_entity: nh,
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            },
            source_position_vector: LongPositionVector::decode([0u8; 24]),
            traffic_class: TrafficClass {
                scf: false,
                channel_offload: false,
                tc_id: 0,
            },
            destination_area: None,
            remaining_packet_lifetime: None,
            remaining_hop_limit: None,
            length: data.len() as u16,
            data,
        }
    }

    #[test]
    fn spawn_and_shutdown() {
        let mib = make_mib();
        let (handle, _gn_rx) = Router::spawn(mib);
        handle.shutdown();
    }

    #[test]
    fn btpb_request_produces_gn_request() {
        let mib = make_mib();
        let (handle, gn_rx) = Router::spawn(mib);

        let mut req = BTPDataRequest::new();
        req.btp_type = CommonNH::BtpB;
        req.destination_port = 2001;
        req.destination_port_info = 0;
        req.gn_packet_transport_type = PacketTransportType {
            header_type: HeaderType::Tsb,
            header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
        };
        req.data = vec![0xCA, 0xFE];
        req.length = 2;

        handle.send_btp_data_request(req);

        let gn_req = gn_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        // Payload should be 4 (BTP-B header) + 2 (data) = 6 bytes
        assert_eq!(gn_req.data.len(), 6);
        // First two bytes should be destination port 2001 = 0x07D1
        assert_eq!(gn_req.data[0], 0x07);
        assert_eq!(gn_req.data[1], 0xD1);
        // Next two bytes — port info = 0
        assert_eq!(gn_req.data[2], 0x00);
        assert_eq!(gn_req.data[3], 0x00);
        // Payload
        assert_eq!(gn_req.data[4], 0xCA);
        assert_eq!(gn_req.data[5], 0xFE);

        handle.shutdown();
    }

    #[test]
    fn btpa_request_produces_gn_request() {
        let mib = make_mib();
        let (handle, gn_rx) = Router::spawn(mib);

        let mut req = BTPDataRequest::new();
        req.btp_type = CommonNH::BtpA;
        req.destination_port = 2001;
        req.source_port = 3000;
        req.gn_packet_transport_type = PacketTransportType {
            header_type: HeaderType::GeoUnicast,
            header_sub_type: HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
        };
        req.data = vec![0xDE, 0xAD];
        req.length = 2;

        handle.send_btp_data_request(req);

        let gn_req = gn_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(gn_req.data.len(), 6);
        // BTP-A header: dest port (2001) + source port (3000)
        let btpa = BTPAHeader::decode(gn_req.data[0..4].try_into().unwrap());
        assert_eq!(btpa.destination_port(), 2001);
        assert_eq!(btpa.source_port(), 3000);

        handle.shutdown();
    }

    #[test]
    fn btpb_indication_dispatches_to_registered_port() {
        let mib = make_mib();
        let (handle, _gn_rx) = Router::spawn(mib);

        // Register a callback on port 2001
        let (port_tx, port_rx) = mpsc::channel();
        handle.register_port(2001, port_tx);

        // Small sleep to let registration take effect
        std::thread::sleep(Duration::from_millis(50));

        // Build a GN indication with BTP-B header for port 2001
        let btpb = BTPBHeader {
            destination_port: 2001,
            destination_port_info: 0,
        };
        let mut payload = btpb.encode().to_vec();
        payload.extend_from_slice(&[0xAA, 0xBB]);

        let gn_ind = make_gn_data_indication(CommonNH::BtpB, payload);
        handle.send_gn_data_indication(gn_ind);

        let ind = port_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(ind.destination_port, 2001);
        assert_eq!(ind.data, vec![0xAA, 0xBB]);

        handle.shutdown();
    }

    #[test]
    fn btpa_indication_dispatches_to_registered_port() {
        let mib = make_mib();
        let (handle, _gn_rx) = Router::spawn(mib);

        let (port_tx, port_rx) = mpsc::channel();
        handle.register_port(2001, port_tx);
        std::thread::sleep(Duration::from_millis(50));

        let btpa = BTPAHeader::decode([
            (2001u16 >> 8) as u8,
            (2001u16 & 0xFF) as u8,
            (5000u16 >> 8) as u8,
            (5000u16 & 0xFF) as u8,
        ]);
        let mut payload = btpa.encode().to_vec();
        payload.extend_from_slice(&[0xCC, 0xDD]);

        let gn_ind = make_gn_data_indication(CommonNH::BtpA, payload);
        handle.send_gn_data_indication(gn_ind);

        let ind = port_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(ind.destination_port, 2001);
        assert_eq!(ind.source_port, 5000);
        assert_eq!(ind.data, vec![0xCC, 0xDD]);

        handle.shutdown();
    }

    #[test]
    fn unregister_port_stops_dispatch() {
        let mib = make_mib();
        let (handle, _gn_rx) = Router::spawn(mib);

        let (port_tx, port_rx) = mpsc::channel();
        handle.register_port(2001, port_tx);
        std::thread::sleep(Duration::from_millis(50));

        handle.unregister_port(2001);
        std::thread::sleep(Duration::from_millis(50));

        let btpb = BTPBHeader {
            destination_port: 2001,
            destination_port_info: 0,
        };
        let gn_ind = make_gn_data_indication(CommonNH::BtpB, btpb.encode().to_vec());
        handle.send_gn_data_indication(gn_ind);

        // Should NOT receive anything
        assert!(port_rx.recv_timeout(Duration::from_millis(200)).is_err());

        handle.shutdown();
    }

    #[test]
    fn indication_with_no_registered_port_does_not_crash() {
        let mib = make_mib();
        let (handle, _gn_rx) = Router::spawn(mib);

        let btpb = BTPBHeader {
            destination_port: 9999,
            destination_port_info: 0,
        };
        let gn_ind = make_gn_data_indication(CommonNH::BtpB, btpb.encode().to_vec());
        handle.send_gn_data_indication(gn_ind);

        std::thread::sleep(Duration::from_millis(100));
        handle.shutdown();
    }
}

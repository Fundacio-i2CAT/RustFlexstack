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
    mib: Mib,
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
            mib,
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

        let indication =
            BTPDataIndication::initialize_with_gn_data_indication(&gn_ind)
                .set_destination_port_and_info(
                    header.destination_port,
                    header.destination_port_info,
                );

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

        let mut indication =
            BTPDataIndication::initialize_with_gn_data_indication(&gn_ind)
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

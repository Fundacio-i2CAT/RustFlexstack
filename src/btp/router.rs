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

use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::collections::HashMap;
use super::btp_header::{BTPAHeader, BTPBHeader};
use super::service_access_point::{BTPDataRequest, BTPDataIndication};
use crate::geonet::mib::Mib;
use crate::geonet::service_access_point::CommonNH;
use crate::geonet::service_access_point::{GNDataIndication, GNDataRequest};

// ------------------------------------------------------------------
// Message types
// ------------------------------------------------------------------

/// Messages that the BTP router processes from its input queue.
pub enum BTPRouterInput {
    /// A Facilities-layer send request.
    BTPDataRequest(BTPDataRequest),
    /// An indication from the GN router (received packet).
    GNDataIndication(GNDataIndication),
    /// Register a port sink.  Packets arriving on `port` will be forwarded to `callback_tx`.
    RegisterPort(u16, Sender<BTPDataIndication>),
    /// Remove the sink registered for `port`.
    UnregisterPort(u16),
    /// Shut down the router thread.
    Shutdown,
}

// ------------------------------------------------------------------
// Router and handle
// ------------------------------------------------------------------

/// Internal BTP router state.  Use [`BTPRouterHandle`] for all interaction.
pub struct Router {
    mib: Mib,
    /// Port → Facilities-layer channel map.
    port_callbacks: HashMap<u16, Sender<BTPDataIndication>>,
    /// Channel for sending GN data requests to the GeoNetworking layer.
    gn_request_tx: Sender<GNDataRequest>,
}

/// A clonable handle to the running BTP router.
#[derive(Clone)]
pub struct BTPRouterHandle {
    input_tx: Sender<BTPRouterInput>,
}

impl BTPRouterHandle {
    /// Submit a Facilities-layer BTP data request (transmit path).
    pub fn send_btp_data_request(&self, request: BTPDataRequest) {
        let _ = self.input_tx.send(BTPRouterInput::BTPDataRequest(request));
    }

    /// Inject a GN data indication into the BTP router (receive path).
    pub fn send_gn_data_indication(&self, indication: GNDataIndication) {
        let _ = self.input_tx.send(BTPRouterInput::GNDataIndication(indication));
    }

    /// Register `callback_tx` to receive indications for `port`.
    pub fn register_port(&self, port: u16, callback_tx: Sender<BTPDataIndication>) {
        let _ = self.input_tx.send(BTPRouterInput::RegisterPort(port, callback_tx));
    }

    /// Unregister the sink for `port`.
    pub fn unregister_port(&self, port: u16) {
        let _ = self.input_tx.send(BTPRouterInput::UnregisterPort(port));
    }

    /// Shut down the router thread.
    pub fn shutdown(self) {
        let _ = self.input_tx.send(BTPRouterInput::Shutdown);
    }
}

// ------------------------------------------------------------------
// Router implementation
// ------------------------------------------------------------------

impl Router {
    /// Create a new BTP router.  Prefer [`Router::spawn`].
    pub fn new(mib: Mib, gn_request_tx: Sender<GNDataRequest>) -> Self {
        Router {
            mib,
            port_callbacks: HashMap::new(),
            gn_request_tx,
        }
    }

    /// Spawn the BTP router actor thread.
    ///
    /// Returns:
    /// - A [`BTPRouterHandle`] for sending messages.
    /// - A [`Receiver<GNDataRequest>`] for the GN router to consume.
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

    /// Encode a BTP-A or BTP-B header and forward the packet to the GN layer.
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
            traffic_class: request.traffic_class.clone(),
            length: payload.len() as u16,
            area: request.gn_area.clone(),
            data: payload,
        };
        let _ = self.gn_request_tx.send(gn_request);
    }

    // ------------------------------------------------------------------
    // Receive path
    // ------------------------------------------------------------------

    /// Strip a BTP-B header and dispatch the payload to the registered port sink.
    fn btpb_data_indication(&mut self, gn_ind: GNDataIndication) {
        if gn_ind.data.len() < 4 {
            eprintln!("[BTP] BTP-B payload too short");
            return;
        }
        let btp_bytes: [u8; 4] = gn_ind.data[0..4].try_into().unwrap();
        let header = BTPBHeader::decode(btp_bytes);

        let indication = BTPDataIndication {
            source_port: 0, // BTP-B carries no source port
            destination_port: header.destination_port,
            destination_port_info: header.destination_port_info,
            gn_packet_transport_type: gn_ind.packet_transport_type,
            // Use the actual GN destination from the indication
            gn_destination_address: self.mib.itsGnLocalGnAddr,
            gn_source_position_vector: gn_ind.source_position_vector,
            gn_traffic_class: gn_ind.traffic_class,
            length: gn_ind.data.len().saturating_sub(4) as u16,
            data: gn_ind.data[4..].to_vec(),
        };

        match self.port_callbacks.get(&header.destination_port) {
            Some(tx) => {
                let _ = tx.send(indication);
            }
            None => {
                eprintln!("[BTP] No sink registered for port {}", header.destination_port);
            }
        }
    }

    /// Strip a BTP-A header and dispatch the payload to the registered port sink.
    fn btpa_data_indication(&mut self, gn_ind: GNDataIndication) {
        if gn_ind.data.len() < 4 {
            eprintln!("[BTP] BTP-A payload too short");
            return;
        }
        let btp_bytes: [u8; 4] = gn_ind.data[0..4].try_into().unwrap();
        let header = BTPAHeader::decode(btp_bytes);

        let indication = BTPDataIndication {
            source_port: header.source_port(),
            destination_port: header.destination_port(),
            destination_port_info: 0, // BTP-A has no port-info field
            gn_packet_transport_type: gn_ind.packet_transport_type,
            gn_destination_address: self.mib.itsGnLocalGnAddr,
            gn_source_position_vector: gn_ind.source_position_vector,
            gn_traffic_class: gn_ind.traffic_class,
            length: gn_ind.data.len().saturating_sub(4) as u16,
            data: gn_ind.data[4..].to_vec(),
        };

        match self.port_callbacks.get(&header.destination_port()) {
            Some(tx) => {
                let _ = tx.send(indication);
            }
            None => {
                eprintln!("[BTP] No sink registered for port {}", header.destination_port());
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

use std::convert::TryInto;



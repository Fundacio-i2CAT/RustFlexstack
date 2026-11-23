// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! GeoNetworking Router — ETSI TS 103 836-4-1 V2.2.1 (2026-04).
//!
//! - SHB, GBC, GAC, GUC, TSB multi-hop, Beacon (source, forwarder, receiver)
//! - Location Service (LS) request/reply with LS packet buffer (clauses 8.5, 10.3.7)
//! - UC/BC forwarding packet buffers for store-carry-forward (clause 8.6)
//! - Greedy forwarding (E.2) and segment-based non-area CBF (E.3)
//! - Simple (F.2) and segment-based area CBF (F.3)
//! - Forwarding algorithm selection (Annex D)
//! - Security integration (sign on TX, verify on RX, secured packets relayed unmodified)
//!
//! Timers (LS retransmission, CBF) run on the router clock; the actor loop
//! wakes at [`Router::next_deadline`] and calls [`Router::tick`].

use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use super::basic_header::{BasicHeader, BasicNH, LT};
use super::common_header::CommonHeader;
use super::dcc_net::DccNet;
use super::gbc_extended_header::GBCExtendedHeader;
use super::gn_address::{GNAddress, M, MID, ST};
use super::guc_extended_header::GUCExtendedHeader;
use super::location_table::LocationTable;
use super::ls_extended_header::{LSReplyExtendedHeader, LSRequestExtendedHeader};
use super::mib::{AreaForwardingAlgorithm, GnIfType, GnSecurity, Mib, NonAreaForwardingAlgorithm};
use super::packet_buffer::{cbf_timeout_ms, cbf_timeout_update_ms, CbfPacketBuffer, PacketBuffer};
use super::position_vector::{LongPositionVector, ShortPositionVector, Tst};
use super::service_access_point::SecurityIndication;
use super::service_access_point::{
    Area, CommonNH, GNDataConfirm, GNDataIndication, GNDataRequest, GeoAnycastHST, GeoBroadcastHST,
    HeaderSubType, HeaderType, LocationServiceHST, PacketTransportType, ResultCode,
    TopoBroadcastHST, TrafficClass, UnspecifiedHST,
};
use super::tsb_extended_header::TSBExtendedHeader;
use crate::security::certificate_library::CertificateLibrary;
use crate::security::ecdsa_backend::EcdsaBackend;
use crate::security::sign_service::SignService;
use crate::security::sn_sap::{
    GenerationLocation, ReportVerify, SNSignRequest, SNVerifyConfirm, SNVerifyRequest,
    SecurityProfile,
};
use crate::security::verify_service;
use crate::security::verify_service::TrustListListener;

/// Observer of the SN-VERIFY results of the router (see
/// [`Router::set_verify_observer`]): the secured message as received (the
/// Ieee1609Dot2Data after the Basic Header) and the confirm, for every secured
/// packet, verified or not.
pub type VerifyObserver = Box<dyn Fn(&[u8], &SNVerifyConfirm) + Send>;

const EARTH_RADIUS: f64 = 6371000.0;
/// Octets of a Basic + Common + GUC Extended Header, used to size LS-buffered requests.
const GUC_HEADERS_LENGTH: usize = 4 + 8 + 48;

/// How a buffered GN-PDU is forwarded when its buffer is flushed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RouteKind {
    /// SHB, TSB and LS Request: no forwarding algorithm.
    Broadcast,
    /// GBC and GAC: Annex D, then area or non-area forwarding.
    Area,
    /// GUC and LS Reply: non-area forwarding towards the DE PV.
    Unicast,
}

/// A GN-PDU together with the information needed to (re-)execute its
/// forwarding algorithm (ETSI TS 103 836-4-1 V2.2.1, clauses 8.5, 8.6 and
/// 10.3.5 NOTE 1).
///
/// `body` holds the octets that follow the Basic Header: the Common Header,
/// Extended Header and payload or, for a secured packet, the Secured Packet,
/// which forwarders relay unmodified.
#[derive(Clone, Debug)]
pub struct BufferedPacket {
    pub basic_header: BasicHeader,
    pub body: Vec<u8>,
    pub traffic_class: TrafficClass,
    pub kind: RouteKind,
    pub so_pv: Option<LongPositionVector>,
    pub sn: Option<u16>,
    pub area_type: Option<HeaderSubType>,
    pub area: Option<Area>,
    pub destination: Option<ShortPositionVector>,
    pub sender_ll_address: Option<[u8; 6]>,
    pub area_mode: bool,
    /// Originated by this router: a buffered source packet is sent as a
    /// source when flushed (clause 10.3.5 step 2 re-executes the source
    /// operation).
    pub origin: bool,
}

impl BufferedPacket {
    pub fn new(
        basic_header: BasicHeader,
        body: Vec<u8>,
        traffic_class: TrafficClass,
        kind: RouteKind,
    ) -> Self {
        BufferedPacket {
            basic_header,
            body,
            traffic_class,
            kind,
            so_pv: None,
            sn: None,
            area_type: None,
            area: None,
            destination: None,
            sender_ll_address: None,
            area_mode: false,
            origin: false,
        }
    }

    /// The GN-PDU: Basic Header followed by the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut packet = self.basic_header.encode().to_vec();
        packet.extend_from_slice(&self.body);
        packet
    }

    /// Packet identifier (source GN_ADDR, sequence number).
    fn key(&self) -> (u64, u16) {
        (
            self.so_pv.map(|pv| pv.gn_addr.encode_to_int()).unwrap_or(0),
            self.sn.unwrap_or(0),
        )
    }
}

fn accepted() -> GNDataConfirm {
    GNDataConfirm {
        result_code: ResultCode::Accepted,
    }
}

// ------------------------------------------------------------------
// Router message types
// ------------------------------------------------------------------

pub enum RouterInput {
    GNDataRequest(GNDataRequest),
    IncomingPacket(Vec<u8>),
    /// A received packet with the link-layer source address of the frame.
    IncomingPacketFrom(Vec<u8>, [u8; 6]),
    /// A secured packet already verified outside the router: the packet as
    /// received, the plain message and the verification results.
    VerifiedPacket(Vec<u8>, Vec<u8>, SecurityIndication),
    PositionVectorUpdate(LongPositionVector),
    /// Channel for GN-PDUs addressed to a next hop (see
    /// [`Router::set_unicast_sender`]).
    UnicastSender(Sender<(Vec<u8>, [u8; 6])>),
    /// See [`Router::set_verify_observer`].
    VerifyObserver(VerifyObserver),
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

/// ITS-AID of GeoNetworking management (Beacons), ETSI TS 103 836-4-1
/// V2.2.1 clause 10.3.6.2 table 22.
pub const ITS_AID_GN_MGMT: u64 = 141;

pub struct Router {
    pub mib: Mib,
    pub gn_address: GNAddress,
    pub ego_position_vector: LongPositionVector,
    pub sequence_number: u16,
    pub location_table: LocationTable,

    link_layer_tx: Sender<Vec<u8>>,
    /// GN-PDUs with the link-layer address of the next hop; unicast
    /// forwarding steps fall back to `link_layer_tx` (broadcast) when unset.
    unicast_tx: Option<Sender<(Vec<u8>, [u8; 6])>>,
    btp_tx: Sender<GNDataIndication>,
    /// See [`Router::set_address_change_callback`].
    address_change_callback: Option<Box<dyn Fn(GNAddress) + Send>>,

    // Security services
    sign_service: Option<SignService>,
    verify_backend: Option<EcdsaBackend>,
    verify_cert_library: Option<CertificateLibrary>,
    /// Receiver of the P2P CRL / CTL requests of the verified packets.
    trust_list_listener: Option<TrustListListener>,
    /// See [`Router::set_verify_observer`].
    verify_observer: Option<VerifyObserver>,

    /// Monotonic clock in milliseconds driving the LS and CBF timers.
    clock: Box<dyn Fn() -> u64 + Send>,

    // Location Service state (clauses 8.5, 10.3.7), keyed by GN_ADDR
    ls_deadlines: HashMap<u64, u64>,
    ls_retransmit_counters: HashMap<u64, u8>,
    ls_packet_buffers: HashMap<u64, PacketBuffer<GNDataRequest>>,

    // Forwarding packet buffers (clause 8.6)
    uc_buffers: HashMap<u64, PacketBuffer<BufferedPacket>>,
    bc_buffer: PacketBuffer<BufferedPacket>,
    cbf_buffer: CbfPacketBuffer<(u64, u16), BufferedPacket>,

    // Beacon reset flag — set when SHB is transmitted
    beacon_reset: bool,
    /// Expiry of the beacon timer TBeacon (clause 10.3.6.2), None when the
    /// beacon service is disabled (itsGnBeaconServiceRetransmitTimer = 0).
    beacon_deadline: Option<u64>,
    /// DCC_NET for GN over ITS-G5 (ETSI TS 103 836-4-2 clauses 5 to 7): SHBs
    /// carry the DCC-MCO field and received SHBs update the LocTEX-G5.
    /// Without it the DCC-MCO field is zero-filled.
    pub dcc_net: Option<DccNet>,
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

    /// Pass a received packet with the link-layer source address of the
    /// frame (the previous sender), used by the CBF algorithms (PV_SE).
    /// Pass a secured packet verified outside the router (e.g. by a security
    /// middleware): `packet` is the GN-PDU as received (Basic Header + Secured
    /// Packet), `plain_message` the verified Common Header and payload. The
    /// router processes the plain message, relays the Secured Packet
    /// unmodified when forwarding and attaches `security` to the indication.
    pub fn send_verified_packet(
        &self,
        packet: Vec<u8>,
        plain_message: Vec<u8>,
        security: SecurityIndication,
    ) {
        let _ = self
            .input_tx
            .send(RouterInput::VerifiedPacket(packet, plain_message, security));
    }

    pub fn send_incoming_packet_from(&self, packet: Vec<u8>, sender_ll_address: [u8; 6]) {
        let _ = self
            .input_tx
            .send(RouterInput::IncomingPacketFrom(packet, sender_ll_address));
    }

    pub fn update_position_vector(&self, position_vector: LongPositionVector) {
        let _ = self
            .input_tx
            .send(RouterInput::PositionVectorUpdate(position_vector));
    }

    /// [`Router::set_unicast_sender`] for a spawned router.
    pub fn set_unicast_sender(&self, unicast_tx: Sender<(Vec<u8>, [u8; 6])>) {
        let _ = self.input_tx.send(RouterInput::UnicastSender(unicast_tx));
    }

    /// [`Router::set_verify_observer`] for a spawned router.
    pub fn set_verify_observer(&self, observer: VerifyObserver) {
        let _ = self.input_tx.send(RouterInput::VerifyObserver(observer));
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
            unicast_tx: None,
            btp_tx,
            address_change_callback: None,
            sign_service,
            verify_backend,
            verify_cert_library,
            trust_list_listener: None,
            verify_observer: None,
            clock: {
                let start = Instant::now();
                Box::new(move || start.elapsed().as_millis() as u64)
            },
            ls_deadlines: HashMap::new(),
            ls_retransmit_counters: HashMap::new(),
            ls_packet_buffers: HashMap::new(),
            uc_buffers: HashMap::new(),
            bc_buffer: PacketBuffer::new(mib.itsGnBcForwardingPacketBufferSize as usize * 1024),
            cbf_buffer: CbfPacketBuffer::new(mib.itsGnCbfPacketBufferSize as usize * 1024),
            beacon_reset: false,
            // The first beacon is sent after half a period, as before.
            beacon_deadline: (mib.itsGnBeaconServiceRetransmitTimer > 0)
                .then_some(mib.itsGnBeaconServiceRetransmitTimer as u64 / 2),
            dcc_net: None,
        }
    }

    /// Enable DCC_NET (ETSI TS 103 836-4-2); the first CBR_G trigger is
    /// scheduled with its random offset.
    pub fn set_dcc_net(&mut self, mut dcc_net: DccNet) {
        dcc_net.next_trigger(self.now());
        self.dcc_net = Some(dcc_net);
    }

    /// DCC_NET entity of the router, e.g. to read the LocTEX-G5 or report
    /// the local CBR.
    pub fn dcc_net(&self) -> Option<&DccNet> {
        self.dcc_net.as_ref()
    }

    /// Mutable [`Router::dcc_net`].
    /// The certificate library of the verify side (trust anchors, AAs, revoked
    /// CA certificates), e.g. for a CTL / CRL trust store.
    pub fn verify_library_mut(&mut self) -> Option<&mut CertificateLibrary> {
        self.verify_cert_library.as_mut()
    }

    /// The sign service of a secured router (certificate timers, P2PCD state).
    pub fn sign_service_mut(&mut self) -> Option<&mut SignService> {
        self.sign_service.as_mut()
    }

    /// Pass the P2P CRL / CTL requests of the verified packets to `listener`
    /// (the CRL / CTL distribution service, ETSI TS 103 601 V2.1.1 clause 5.3).
    pub fn set_trust_list_listener(&mut self, listener: TrustListListener) {
        self.trust_list_listener = Some(listener);
    }

    /// Call `observer` with the outcome of every verification of a received
    /// secured packet (SN-VERIFY.confirm, ETSI TS 102 723-8), whatever the
    /// report: for logging and test instrumentation. It does not change the
    /// processing of the packet.
    pub fn set_verify_observer(&mut self, observer: VerifyObserver) {
        self.verify_observer = Some(observer);
    }

    pub fn dcc_net_mut(&mut self) -> Option<&mut DccNet> {
        self.dcc_net.as_mut()
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
        Self::spawn_with_dcc_net(mib, sign_service, verify_backend, verify_cert_library, None)
    }

    /// [`Router::spawn`] with DCC_NET for GN over ITS-G5 (ETSI TS 103 836-4-2).
    pub fn spawn_with_dcc_net(
        mib: Mib,
        sign_service: Option<SignService>,
        verify_backend: Option<EcdsaBackend>,
        verify_cert_library: Option<CertificateLibrary>,
        dcc_net: Option<DccNet>,
    ) -> (RouterHandle, Receiver<Vec<u8>>, Receiver<GNDataIndication>) {
        let (input_tx, input_rx) = mpsc::channel::<RouterInput>();
        let (link_layer_tx, link_layer_rx) = mpsc::channel::<Vec<u8>>();
        let (btp_tx, btp_rx) = mpsc::channel::<GNDataIndication>();

        let handle = RouterHandle {
            input_tx: input_tx.clone(),
        };

        let _thread_handle = thread::spawn(move || {
            let mut router = Router::new(
                mib,
                link_layer_tx,
                btp_tx,
                sign_service,
                verify_backend,
                verify_cert_library,
            );
            if let Some(dcc_net) = dcc_net {
                router.set_dcc_net(dcc_net);
            }
            router.run(input_rx);
        });

        (handle, link_layer_rx, btp_rx)
    }

    // ------------------------------------------------------------------
    // Main event loop
    // ------------------------------------------------------------------

    fn run(&mut self, input_rx: Receiver<RouterInput>) {
        loop {
            let input = match self.next_deadline() {
                Some(deadline) => {
                    let wait = deadline.saturating_sub(self.now());
                    match input_rx.recv_timeout(Duration::from_millis(wait)) {
                        Ok(input) => Some(input),
                        Err(RecvTimeoutError::Timeout) => None,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                None => match input_rx.recv() {
                    Ok(input) => Some(input),
                    Err(_) => break,
                },
            };
            match input {
                Some(RouterInput::GNDataRequest(request)) => {
                    let _ = self.gn_data_request(request);
                }
                Some(RouterInput::IncomingPacket(packet)) => {
                    self.process_incoming(&packet, None);
                }
                Some(RouterInput::IncomingPacketFrom(packet, sender)) => {
                    self.process_incoming(&packet, Some(sender));
                }
                Some(RouterInput::VerifiedPacket(packet, plain, security)) => {
                    self.process_verified(&packet, &plain, security);
                }
                Some(RouterInput::PositionVectorUpdate(position_vector)) => {
                    self.refresh_ego_position_vector(position_vector);
                }
                Some(RouterInput::UnicastSender(unicast_tx)) => {
                    self.set_unicast_sender(unicast_tx);
                }
                Some(RouterInput::VerifyObserver(observer)) => {
                    self.set_verify_observer(observer);
                }
                Some(RouterInput::Shutdown) => break,
                None => {}
            }
            let now = self.now();
            self.tick(now);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Timers (Location Service TLS and CBF timers), clock-driven
    // ------------------------------------------------------------------

    /// Replace the router clock (milliseconds, monotonic); tests drive the
    /// timers with a manual clock and [`Router::tick`].
    pub fn set_clock(&mut self, clock: Box<dyn Fn() -> u64 + Send>) {
        self.clock = clock;
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Restart TBeacon = itsGnBeaconServiceRetransmitTimer +
    /// RAND[0, itsGnBeaconServiceMaxJitter] (clause 10.3.6.2 step 5); also
    /// called when an SHB is sent (clause 10.3.10.2 step 7).
    fn restart_beacon_timer(&mut self, now_ms: u64) {
        if self.beacon_deadline.is_none() {
            return;
        }
        let jitter = rand::random::<f64>() * self.mib.itsGnBeaconServiceMaxJitter as f64;
        self.beacon_deadline =
            Some(now_ms + self.mib.itsGnBeaconServiceRetransmitTimer as u64 + jitter as u64);
    }

    /// Earliest pending LS or CBF timer expiry (ms on the router clock).
    pub fn next_deadline(&self) -> Option<u64> {
        self.ls_deadlines
            .values()
            .copied()
            .chain(self.cbf_buffer.next_deadline())
            .chain(self.beacon_deadline)
            .chain(self.dcc_net.as_ref().and_then(|d| d.scheduled_trigger()))
            .min()
    }

    /// Process the expired timers: LS Request retransmission
    /// (clause 10.3.7.1.3) and CBF timer expiry (clauses E.3.5, F.3.5).
    pub fn tick(&mut self, now_ms: u64) {
        self.location_table.set_now(now_ms);
        // DCC_NET: CBR_G every itsGNCBRGTriggerInterval (TS 103 836-4-2 clause 5.3)
        if let Some(dcc_net) = self.dcc_net.as_mut() {
            if dcc_net.next_trigger(now_ms) <= now_ms {
                dcc_net.trigger(now_ms);
            }
        }
        // Beacon service (clause 10.3.6.2): send a beacon when TBeacon expires.
        if self
            .beacon_deadline
            .is_some_and(|deadline| deadline <= now_ms)
        {
            let _ = self.gn_data_request_beacon();
            self.restart_beacon_timer(now_ms);
        }
        let due: Vec<u64> = self
            .ls_deadlines
            .iter()
            .filter(|(_, deadline)| **deadline <= now_ms)
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            self.ls_retransmit(&GNAddress::decode(&key.to_be_bytes()), now_ms);
        }
        // TO_ACC is not provided by the Access Layer (set to zero): re-broadcast.
        for (_, packet, remaining_ms) in self.cbf_buffer.pop_expired(now_ms) {
            let _ = self
                .send_to_link_layer(Self::with_remaining_lifetime(packet, remaining_ms).encode());
        }
    }

    // ------------------------------------------------------------------
    // Packet buffers (clauses 8.5, 8.6)
    // ------------------------------------------------------------------

    /// Clauses 8.5.3 / 8.6.3 step 5a: LT reduced by the queuing time.
    fn with_remaining_lifetime(mut packet: BufferedPacket, remaining_ms: u64) -> BufferedPacket {
        let lt = LT::start_in_milliseconds(remaining_ms.min(u32::MAX as u64) as u32);
        packet.basic_header = packet.basic_header.set_lt(lt);
        packet
    }

    /// Queue a packet in the UC (per destination) or BC forwarding packet buffer.
    fn buffer_packet(&mut self, packet: BufferedPacket) {
        let now = self.now();
        let lifetime = packet.basic_header.lt.get_value_in_milliseconds() as u64;
        let size = 4 + packet.body.len();
        if packet.kind == RouteKind::Unicast {
            if let Some(destination) = &packet.destination {
                let capacity = self.mib.itsGnUcForwardingPacketBufferSize as usize * 1024;
                self.uc_buffers
                    .entry(destination.gn_address.encode_to_int())
                    .or_insert_with(|| PacketBuffer::new(capacity))
                    .push(packet, size, lifetime, now);
                return;
            }
        }
        self.bc_buffer.push(packet, size, lifetime, now);
    }

    /// Clause 10.3.5 step 2: forward the BC-buffered packets, re-executing the
    /// forwarding algorithm that caused the buffering. The UC-buffered packets
    /// are re-attempted as well (clause 10.3.11.3 NOTE 6: buffered packets may
    /// be further processed when a packet is received), so that a new
    /// neighbour can serve as next hop; packets still without a next hop are
    /// buffered again with their remaining lifetime.
    fn flush_forwarding_buffers(&mut self) {
        if self.bc_buffer.is_empty() && self.uc_buffers.is_empty() {
            return;
        }
        let now = self.now();
        let mut flushed = self.bc_buffer.flush(now);
        for (_, mut buffer) in self.uc_buffers.drain() {
            flushed.extend(buffer.flush(now));
        }
        for (packet, remaining) in flushed {
            let origin = packet.origin;
            let _ = self.forward(Self::with_remaining_lifetime(packet, remaining), origin);
        }
    }

    /// Step "flush packet buffers" of the receiver/forwarder operations (e.g.
    /// clause 10.3.11.3 step 8): the LS packet buffer of SO when
    /// LS_pending(SO) is TRUE, and the UC forwarding packet buffer of SO.
    fn flush_source_buffers(&mut self, so_gn_addr: &GNAddress) {
        if self
            .location_table
            .get_entry_ref(so_gn_addr)
            .is_some_and(|entry| entry.ls_pending)
        {
            self.complete_ls(so_gn_addr);
        }
        if let Some(mut buffer) = self.uc_buffers.remove(&so_gn_addr.encode_to_int()) {
            let now = self.now();
            for (packet, remaining) in buffer.flush(now) {
                let origin = packet.origin;
                let _ = self.forward(Self::with_remaining_lifetime(packet, remaining), origin);
            }
        }
    }

    // ------------------------------------------------------------------
    // Forwarding (Annexes D, E and F)
    // ------------------------------------------------------------------

    /// PV of the previous sender (PV_SE). The sender is identified by the
    /// link-layer source address when the ALI provides it; otherwise the
    /// source (SO) is used, which is exact for packets received from the
    /// originator.
    fn sender_pv(&self, packet: &BufferedPacket) -> Option<LongPositionVector> {
        if let Some(mac) = &packet.sender_ll_address {
            return self
                .location_table
                .get_entry_by_mid(mac)
                .map(|entry| entry.position_vector);
        }
        packet.so_pv.and_then(|so| {
            self.location_table
                .get_entry_ref(&so.gn_addr)
                .map(|entry| entry.position_vector)
        })
    }

    /// PV_P: DE PV of a GUC packet, or the centre of the GBC/GAC area.
    fn destination_position(packet: &BufferedPacket) -> (i32, i32) {
        if let (RouteKind::Unicast, Some(destination)) = (packet.kind, &packet.destination) {
            return (destination.latitude as i32, destination.longitude as i32);
        }
        let area = packet.area.unwrap_or(Area {
            latitude: 0,
            longitude: 0,
            a: 0,
            b: 0,
            angle: 0,
        });
        (area.latitude as i32, area.longitude as i32)
    }

    /// Execute the forwarding procedure of a source (`origin`) or forwarder:
    /// SCF buffering when no neighbour exists, then the forwarding algorithm
    /// (Annex D, E or F) and the transmission to the ALI.
    fn forward(&mut self, packet: BufferedPacket, origin: bool) -> GNDataConfirm {
        if self.location_table.get_neighbours().is_empty() && packet.traffic_class.scf {
            let mut packet = packet;
            packet.origin = origin;
            self.buffer_packet(packet);
            return accepted();
        }
        match packet.kind {
            RouteKind::Broadcast => return self.send_to_link_layer(packet.encode()),
            RouteKind::Area => {
                let (Some(area), Some(area_type)) = (packet.area, packet.area_type.clone()) else {
                    return accepted();
                };
                let sender = if origin {
                    None
                } else {
                    self.sender_pv(&packet).map(|pv| pv.gn_addr)
                };
                match self.area_algorithm_selection(&area_type, &area, sender.as_ref()) {
                    GNForwardingAlgorithmResponse::Discarted => return accepted(),
                    GNForwardingAlgorithmResponse::AreaForwarding => {
                        if self.mib.itsGnAreaForwardingAlgorithm == AreaForwardingAlgorithm::Cbf {
                            return self.cbf_forward(packet, true, origin);
                        }
                        // F.2 Simple GeoBroadcast forwarding: re-broadcast
                        return self.send_to_link_layer(packet.encode());
                    }
                    GNForwardingAlgorithmResponse::NonAreaForwarding => {}
                }
            }
            RouteKind::Unicast => {}
        }
        // Non-area forwarding towards PV_P (Annex E)
        if self.mib.itsGnNonAreaForwardingAlgorithm == NonAreaForwardingAlgorithm::Cbf {
            return self.cbf_forward(packet, false, origin);
        }
        let (dest_lat, dest_lon) = Self::destination_position(&packet);
        if let Some(next_hop) = self.greedy_next_hop(dest_lat, dest_lon) {
            // E.2: NH_LL_ADDR = NH.LL_ADDR, the MID of the neighbour's GN
            // address (the MAC address over ITS-G5, TS 103 836-4-2 clause 6.1).
            return self.send_to_next_hop(packet.encode(), next_hop.mid.as_bytes());
        }
        if self.gn_greedy_forwarding(dest_lat, dest_lon, &packet.traffic_class) {
            return self.send_to_link_layer(packet.encode()); // E.2: BCAST at local optimum
        }
        // E.2: local optimum with SCF -> UC (GUC) or BC (GBC/GAC) forwarding buffer
        let mut packet = packet;
        packet.origin = origin;
        self.buffer_packet(packet);
        accepted()
    }

    fn cbf_timeout(&self, distance_m: f64) -> f64 {
        cbf_timeout_ms(
            distance_m,
            self.mib.itsGnCbfMinTime as f64,
            self.mib.itsGnCbfMaxTime as f64,
            self.mib.itsGnDefaultMaxCommunicationRange as f64,
            0.0,
        )
    }

    /// PROG (clause E.3.2.2), or None when PV_SE or EPV is not reliable.
    fn cbf_progress(
        &self,
        packet: &BufferedPacket,
        sender: Option<&LongPositionVector>,
    ) -> Option<f64> {
        let se = sender.filter(|se| se.pai && self.ego_position_vector.pai)?;
        let (dest_lat, dest_lon) = Self::destination_position(packet);
        let ego = &self.ego_position_vector;
        Some(
            Self::distance_m(dest_lat, dest_lon, se.latitude as i32, se.longitude as i32)
                - Self::distance_m(
                    dest_lat,
                    dest_lon,
                    ego.latitude as i32,
                    ego.longitude as i32,
                ),
        )
    }

    /// Distance between two position vectors in metres.
    fn pv_distance(a: &LongPositionVector, b: &LongPositionVector) -> f64 {
        Self::distance_m(
            a.latitude as i32,
            a.longitude as i32,
            b.latitude as i32,
            b.longitude as i32,
        )
    }

    /// Non-area (E.3.5) and area (F.3.5) CBF for a source or a newly received
    /// packet.
    fn cbf_forward(
        &mut self,
        mut packet: BufferedPacket,
        area_mode: bool,
        origin: bool,
    ) -> GNDataConfirm {
        packet.area_mode = area_mode;
        let lifetime = packet.basic_header.lt.get_value_in_milliseconds() as u64;
        let size = 4 + packet.body.len();
        let now = self.now();
        let key = packet.key();
        if origin {
            // The source broadcasts immediately and buffers its own packet with TO_CBF_MAX.
            let confirm = self.send_to_link_layer(packet.encode());
            let to_max = self.mib.itsGnCbfMaxTime as f64;
            self.cbf_buffer
                .insert(key, packet, size, lifetime, now, to_max);
            return confirm;
        }
        let sender = self.sender_pv(&packet);
        let distance = if area_mode {
            // F.3.5: F_DIST = DIST(PV_SE, EPV), or 0 when not reliable.
            match sender {
                Some(se) if se.pai && self.ego_position_vector.pai => {
                    Self::pv_distance(&se, &self.ego_position_vector)
                }
                _ => 0.0,
            }
        } else {
            // E.3.5: buffer only with forwarding progress; PROG = 0 when not reliable.
            match self.cbf_progress(&packet, sender.as_ref()) {
                Some(progress) if progress <= 0.0 => return accepted(), // discarded
                Some(progress) => progress,
                None => 0.0,
            }
        };
        let timeout = self.cbf_timeout(distance);
        self.cbf_buffer
            .insert(key, packet, size, lifetime, now, timeout);
        accepted()
    }

    /// Duplicate of a packet held in the CBF packet buffer (E.3.5 lines 18-37,
    /// F.3.5 lines 21-39): cancel the timer when the sender is a better
    /// forwarder, otherwise update the timeout with equation (E.4).
    ///
    /// Returns false when the packet is not in the CBF packet buffer.
    fn cbf_handle_duplicate(&mut self, received: &BufferedPacket) -> bool {
        let key = received.key();
        let Some(buffered) = self.cbf_buffer.get(&key).cloned() else {
            return false;
        };
        let now = self.now();
        let sender = self.sender_pv(received);
        let ego = self.ego_position_vector;
        let distance = if buffered.area_mode {
            let Some(so) = buffered.so_pv else {
                return true;
            };
            let d1 = Self::pv_distance(&ego, &so);
            let (d2, d3) = match sender {
                Some(se) if se.pai && ego.pai => {
                    (Self::pv_distance(&se, &so), Self::pv_distance(&ego, &se))
                }
                _ => (0.0, 0.0),
            };
            if d1 == 0.0 || (d1 < d2 && d2 > d3) {
                self.cbf_buffer.remove(&key); // better forwarder: discard
                return true;
            }
            d3
        } else {
            // E.3.5 line 20 reads "SE_POS_VALID = FALSE"; PROG can only be
            // computed with a valid sender position, as in line 46.
            match self.cbf_progress(&buffered, sender.as_ref()) {
                Some(progress) if progress < 0.0 => {
                    self.cbf_buffer.remove(&key); // better forwarder: discard
                    return true;
                }
                Some(progress) => progress,
                None => 0.0,
            }
        };
        let remaining = self.cbf_buffer.remaining_timeout_ms(&key, now).unwrap_or(0) as f64;
        let timeout = cbf_timeout_update_ms(
            remaining,
            self.cbf_timeout(distance),
            self.mib.itsGnCbfMaxTime as f64,
        );
        self.cbf_buffer.restart(&key, now, timeout);
        true
    }

    /// Whether CBF handles duplicates (clause 10.3.11.3 step 3 NOTEs 1a/1b).
    fn cbf_applies(&self, inside_area: bool) -> bool {
        if inside_area {
            self.mib.itsGnAreaForwardingAlgorithm == AreaForwardingAlgorithm::Cbf
        } else {
            self.mib.itsGnNonAreaForwardingAlgorithm == NonAreaForwardingAlgorithm::Cbf
        }
    }

    /// Probe used to look a received packet up in the CBF packet buffer.
    fn cbf_probe(
        basic_header: &BasicHeader,
        traffic_class: TrafficClass,
        kind: RouteKind,
        so_pv: LongPositionVector,
        sn: u16,
        sender_ll_address: Option<[u8; 6]>,
    ) -> BufferedPacket {
        let mut probe = BufferedPacket::new(*basic_header, Vec::new(), traffic_class, kind);
        probe.so_pv = Some(so_pv);
        probe.sn = Some(sn);
        probe.sender_ll_address = sender_ll_address;
        probe
    }

    // ------------------------------------------------------------------
    // Location Service (clauses 8.5, 10.3.7.1)
    // ------------------------------------------------------------------

    /// Queue a request in the LS packet buffer of the sought GN_ADDR (clause 8.5.3).
    fn ls_buffer_request(&mut self, key: u64, request: GNDataRequest) {
        let lifetime_s = request
            .max_packet_lifetime
            .unwrap_or(self.mib.itsGnDefaultPacketLifetime as f64);
        let capacity = self.mib.itsGnLocationServicePacketBufferSize as usize;
        let size = request.data.len() + GUC_HEADERS_LENGTH;
        let now = self.now();
        self.ls_packet_buffers
            .entry(key)
            .or_insert_with(|| PacketBuffer::new(capacity))
            .push(request, size, (lifetime_s * 1000.0) as u64, now);
    }

    /// LS completion (clause 10.3.7.1.4 steps 6-10): stop TLS, reset RTCLS,
    /// clear LS_pending and send the LS-buffered packets in FIFO order with
    /// their lifetime reduced by the queuing time.
    fn complete_ls(&mut self, sought_gn_addr: &GNAddress) {
        let key = sought_gn_addr.encode_to_int();
        self.ls_deadlines.remove(&key);
        self.ls_retransmit_counters.remove(&key);
        let buffer = self.ls_packet_buffers.remove(&key);
        if let Some(entry) = self.location_table.get_entry(sought_gn_addr) {
            entry.ls_pending = false;
        }
        if let Some(mut buffer) = buffer {
            let now = self.now();
            for (request, remaining_ms) in buffer.flush(now) {
                let _ = self.gn_data_request_guc(GNDataRequest {
                    max_packet_lifetime: Some(remaining_ms as f64 / 1000.0),
                    ..request
                });
            }
        }
    }

    /// Expiry of TLS for `sought_gn_addr` (clause 10.3.7.1.3): re-issue the LS
    /// Request while RTCLS < itsGnLocationServiceMaxRetrans; otherwise discard
    /// the LS-buffered packets and remove the LocTE.
    fn ls_retransmit(&mut self, sought_gn_addr: &GNAddress, now_ms: u64) {
        let key = sought_gn_addr.encode_to_int();
        let count = self.ls_retransmit_counters.get(&key).copied().unwrap_or(0);
        if count >= self.mib.itsGnLocationServiceMaxRetrans {
            self.ls_packet_buffers.remove(&key);
            self.ls_deadlines.remove(&key);
            self.ls_retransmit_counters.remove(&key);
            self.location_table.remove_entry(sought_gn_addr);
            return;
        }
        self.ls_retransmit_counters.insert(key, count + 1);
        self.ls_deadlines.insert(
            key,
            now_ms + self.mib.itsGnLocationServiceRetransmitTimer as u64,
        );
        self.send_ls_request_packet(sought_gn_addr);
    }

    /// `Mib::media_dependent_address_ok` for this router (ETSI TS 103 836-4-2
    /// clause 6.1, TS 103 836-4-3 clause 5.2); `link_layer_mid` is the MID
    /// reported by the link layer, e.g. `RawLinkLayer::media_dependent_mid`.
    pub fn media_dependent_address_ok(&self, link_layer_mid: Option<MID>) -> bool {
        self.mib.media_dependent_address_ok(link_layer_mid)
    }

    /// Sequence number of the next multi-hop packet (clause 8.4): the local
    /// SEQN, initialized to 0, then incremented modulo 2^16.
    pub fn get_sequence_number(&mut self) -> u16 {
        let sequence_number = self.sequence_number;
        self.sequence_number = sequence_number.wrapping_add(1);
        sequence_number
    }

    /// Send GN-PDUs of unicast forwarding steps with the link-layer address
    /// of the next hop (ETSI TS 103 836-4-1 clause E.2, NH_LL_ADDR), e.g. to
    /// [`crate::link_layer::raw_link_layer::RawLinkLayer::with_unicast_receiver`].
    /// Without it they are sent to `link_layer_tx`, i.e. broadcast.
    pub fn set_unicast_sender(&mut self, unicast_tx: Sender<(Vec<u8>, [u8; 6])>) {
        self.unicast_tx = Some(unicast_tx);
    }

    /// Pass a GN-PDU to the ALI with the link-layer address of the next hop.
    fn send_to_next_hop(&self, packet: Vec<u8>, next_hop: [u8; 6]) -> GNDataConfirm {
        let Some(unicast_tx) = &self.unicast_tx else {
            return self.send_to_link_layer(packet);
        };
        match unicast_tx.send((packet, next_hop)) {
            Ok(_) => GNDataConfirm {
                result_code: ResultCode::Accepted,
            },
            Err(_) => GNDataConfirm {
                result_code: ResultCode::Unspecified,
            },
        }
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

    /// ThreeDLocation of the ego position for the security header
    /// (elevation unavailable), also used to select a region-valid AT.
    fn generation_location(&self) -> GenerationLocation {
        GenerationLocation {
            latitude: self.ego_position_vector.latitude as i32,
            longitude: self.ego_position_vector.longitude as i32,
            elevation: 0xF000,
        }
    }

    fn gn_data_request_shb(&mut self, request: GNDataRequest) -> GNDataConfirm {
        let ego_location = self.generation_location();
        let basic_header = BasicHeader::initialize_with_mib_request_and_rhl(
            &self.mib,
            request.max_packet_lifetime,
            1,
        );
        let common_header = CommonHeader::initialize_with_request(&request, &self.mib);
        // DCC-MCO field (TS 103 836-4-2 clauses 6.3.3, 7.2.1); zero-filled
        // without DCC_NET.
        let media_dependent_data: [u8; 4] = self.dcc_net.as_ref().map_or([0; 4], |d| d.dcc_mco());

        let packet: Vec<u8>;

        if self.signed(&request) {
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
                    generation_location: Some(ego_location),
                };

                // No AT may sign (validity, region, permissions): not sent
                // (IEEE Std 1609.2-2016 clause 5.2.3.2.2).
                let Ok(sign_confirm) = sign_service.try_sign_request(&sign_request) else {
                    return GNDataConfirm {
                        result_code: ResultCode::Unspecified,
                    };
                };
                let secured_basic = basic_header.set_nh(BasicNH::SecuredPacket);

                packet = secured_basic
                    .encode()
                    .iter()
                    .copied()
                    .chain(sign_confirm.sec_message.iter().copied())
                    .collect();
            } else {
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

        // Step 3 (clause 10.3.10.2): no neighbour and SCF set -> BC forwarding buffer.
        if self.location_table.get_neighbours().is_empty() && request.traffic_class.scf {
            let basic = BasicHeader::decode(packet[0..4].try_into().expect("Basic Header"));
            self.buffer_packet(BufferedPacket::new(
                basic,
                packet[4..].to_vec(),
                request.traffic_class,
                RouteKind::Broadcast,
            ));
            return accepted();
        }

        // Reset beacon timer on SHB transmission (§10.3.10.2 step 7)
        self.beacon_reset = true;
        let now = self.now();
        self.restart_beacon_timer(now);

        self.send_to_link_layer(packet)
    }

    fn gn_data_request_beacon(&mut self) -> GNDataConfirm {
        let basic_header = BasicHeader::initialize_with_mib_request_and_rhl(&self.mib, None, 1);
        let common_header = CommonHeader::initialize_beacon(&self.mib);
        let body: Vec<u8> = common_header
            .encode()
            .iter()
            .copied()
            .chain(self.ego_position_vector.encode().iter().copied())
            .collect();

        // Clause 10.3.6.2 step 2: with itsGnSecurity ENABLED the Common Header
        // and Beacon Extended Header are signed with ITS-AID 141 (GN-MGMT,
        // table 22). No AT may sign: no Beacon.
        let Some((basic_header, body)) = self.sign_mgmt(basic_header, body) else {
            return GNDataConfirm {
                result_code: ResultCode::Unspecified,
            };
        };
        let mut packet = basic_header.encode().to_vec();
        packet.extend_from_slice(&body);
        self.send_to_link_layer(packet)
    }

    /// Security encapsulation of a GN management packet (Common Header and
    /// Extended Header): Beacon, LS Request and LS Reply are signed with ITS-AID
    /// 141 (GN-MGMT), SSP absent (ETSI TS 103 836-4-1 V2.2.1 tables 22, 24 and
    /// 26). Unchanged without itsGnSecurity; `None` when it is ENABLED and no AT
    /// may sign (the packet is then not sent).
    fn sign_mgmt(
        &mut self,
        basic_header: BasicHeader,
        body: Vec<u8>,
    ) -> Option<(BasicHeader, Vec<u8>)> {
        if self.mib.itsGnSecurity != GnSecurity::Enabled {
            return Some((basic_header, body));
        }
        let generation_location = Some(self.generation_location());
        let sign_service = self.sign_service.as_mut()?;
        let confirm = sign_service
            .try_sign_request(&SNSignRequest {
                tbs_message: body,
                its_aid: ITS_AID_GN_MGMT,
                permissions: vec![],
                generation_location,
            })
            .ok()?;
        Some((
            basic_header.set_nh(BasicNH::SecuredPacket),
            confirm.sec_message,
        ))
    }

    /// Security encapsulation of a GBC, GAC or GUC packet (Common Header,
    /// Extended Header and payload) when `itsGnSecurity` is enabled (ETSI TS
    /// 103 836-4-1 V2.2.1 clause 9.4). The signer profile follows the ITS-AID
    /// ([`SignService::try_sign_request`]): DENM profile (ETSI TS 103 097
    /// V2.2.1 clause 7.1.2) for ITS-AID 37, generic profile (clause 7.1.3)
    /// otherwise. `None` when the packet shall not be sent: no SignService,
    /// or no AT may sign the message (IEEE Std 1609.2-2016 clause 5.2.3.2.2).
    /// Whether the packet of `request` is secured: itsGnSecurity ENABLED and the
    /// Security profile not `Unsecured` (ETSI TS 103 836-4-1 V2.2.1 table 18: NH =
    /// Common Header when the Security profile indicates an unsecured packet).
    fn signed(&self, request: &GNDataRequest) -> bool {
        self.mib.itsGnSecurity == GnSecurity::Enabled
            && request.security_profile != SecurityProfile::Unsecured
    }

    fn secure(
        &mut self,
        basic_header: BasicHeader,
        body: Vec<u8>,
        request: &GNDataRequest,
        generation_location: GenerationLocation,
    ) -> Option<(BasicHeader, Vec<u8>)> {
        if !self.signed(request) {
            return Some((basic_header, body));
        }
        let sign_service = self.sign_service.as_mut()?;
        let sign_request = SNSignRequest {
            tbs_message: body,
            its_aid: request.its_aid,
            permissions: request.security_permissions.clone(),
            generation_location: Some(generation_location),
        };
        let confirm = sign_service.try_sign_request(&sign_request).ok()?;
        Some((
            basic_header.set_nh(BasicNH::SecuredPacket),
            confirm.sec_message,
        ))
    }

    fn gn_data_request_gbc(&mut self, request: GNDataRequest) -> GNDataConfirm {
        let ego_location = self.generation_location();
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

        // Step 2 (clauses 10.3.11.2 / 10.3.12.2): security encapsulation.
        let mut body = common_header.encode().to_vec();
        body.extend_from_slice(&gbc_ext.encode());
        body.extend_from_slice(&request.data);
        let Some((actual_basic, body)) = self.secure(basic_header, body, &request, ego_location)
        else {
            return GNDataConfirm {
                result_code: ResultCode::Unspecified,
            };
        };

        // Steps 3-8: SCF buffering, forwarding algorithm (Annex D) and transmission.
        let mut packet =
            BufferedPacket::new(actual_basic, body, request.traffic_class, RouteKind::Area);
        packet.so_pv = Some(gbc_ext.so_pv);
        packet.sn = Some(gbc_ext.sn);
        packet.area_type = Some(request.packet_transport_type.header_sub_type.clone());
        packet.area = Some(request.area);
        self.forward(packet, true)
    }

    /// Multi-hop Topologically-Scoped Broadcast source operations
    /// (ETSI TS 103 836-4-1 V2.2.1, clause 10.3.9.2).
    fn gn_data_request_tsb(&mut self, request: GNDataRequest) -> GNDataConfirm {
        let ego_location = self.generation_location();
        // Step 1: Basic Header (RHL = itsGnDefaultHopLimit unless requested),
        // Common Header and TSB Extended Header (table 30).
        let hop_limit = if request.max_hop_limit <= 1 {
            self.mib.itsGnDefaultHopLimit
        } else {
            request.max_hop_limit
        };
        let mut basic_header = BasicHeader::initialize_with_mib_request_and_rhl(
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
        let tsb_ext =
            TSBExtendedHeader::initialize_with_sequence_number_ego_pv(sn, self.ego_position_vector);
        let mut body = common_header.encode().to_vec();
        body.extend_from_slice(&tsb_ext.encode());
        body.extend_from_slice(&request.data);
        // Step 2: security encapsulation.
        if self.signed(&request) {
            let Some(ref mut sign_service) = self.sign_service else {
                return GNDataConfirm {
                    result_code: ResultCode::Unspecified,
                };
            };
            // No AT may sign (validity, region, permissions): not sent.
            let Ok(sign_confirm) = sign_service.try_sign_request(&SNSignRequest {
                tbs_message: body,
                its_aid: request.its_aid,
                permissions: request.security_permissions.clone(),
                generation_location: Some(ego_location),
            }) else {
                return GNDataConfirm {
                    result_code: ResultCode::Unspecified,
                };
            };
            basic_header = basic_header.set_nh(BasicNH::SecuredPacket);
            body = sign_confirm.sec_message;
        }
        // Steps 3-6: SCF buffering, then broadcast.
        let mut packet = BufferedPacket::new(
            basic_header,
            body,
            request.traffic_class,
            RouteKind::Broadcast,
        );
        packet.so_pv = Some(tsb_ext.so_pv);
        packet.sn = Some(sn);
        self.forward(packet, true)
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
                return GNDataConfirm {
                    result_code: ResultCode::Unspecified,
                };
            }
        };

        // No PV for the destination (no LocTE or LS pending) → Location Service
        let de_entry = self.location_table.get_entry_ref(&dest_addr);
        let de_pv = match de_entry.filter(|entry| !entry.ls_pending) {
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

        // Step 3 (clause 10.3.8.2): security encapsulation.
        let mut body = common_header.encode().to_vec();
        body.extend_from_slice(&guc_ext.encode());
        body.extend_from_slice(&request.data);
        let generation_location = self.generation_location();
        let Some((basic_header, body)) =
            self.secure(basic_header, body, &request, generation_location)
        else {
            return GNDataConfirm {
                result_code: ResultCode::Unspecified,
            };
        };

        // Steps 4-9: SCF buffering, forwarding algorithm (Annex E) and transmission.
        let mut packet = BufferedPacket::new(
            basic_header,
            body,
            request.traffic_class,
            RouteKind::Unicast,
        );
        packet.so_pv = Some(guc_ext.so_pv);
        packet.sn = Some(sn);
        packet.destination = Some(de_pv);
        self.forward(packet, true)
    }

    pub fn gn_data_request(&mut self, request: GNDataRequest) -> GNDataConfirm {
        let now = self.now();
        self.location_table.set_now(now);
        match request.packet_transport_type.header_type {
            HeaderType::Beacon => self.gn_data_request_beacon(),
            HeaderType::Tsb => match request.packet_transport_type.header_sub_type {
                HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop) => {
                    self.gn_data_request_shb(request)
                }
                HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop) => {
                    self.gn_data_request_tsb(request)
                }
                _ => GNDataConfirm {
                    result_code: ResultCode::Unspecified,
                },
            },
            HeaderType::GeoBroadcast => self.gn_data_request_gbc(request),
            HeaderType::GeoAnycast => self.gn_data_request_gac(request),
            HeaderType::GeoUnicast => self.gn_data_request_guc(request),
            _ => GNDataConfirm {
                result_code: ResultCode::Unspecified,
            },
        }
    }

    // ------------------------------------------------------------------
    // GN indicate — receive path
    // ------------------------------------------------------------------

    /// Top-level receive dispatcher — process Basic Header (clause 10.3.3).
    pub fn process_basic_header(&mut self, packet: &[u8]) {
        self.process_incoming(packet, None);
    }

    /// Receive a packet with, when the ALI provides it, the link-layer source
    /// address of the frame (the previous sender, PV_SE of the CBF algorithms).
    pub fn process_incoming(&mut self, packet: &[u8], sender_ll_address: Option<[u8; 6]>) {
        if packet.len() < 4 {
            return;
        }
        let now = self.now();
        self.location_table.set_now(now);
        // An unsecured frame with itsGnSecurity ENABLED cannot alter the GN state
        // (see `process_unsecured`).
        let unsecured_with_security =
            self.mib.itsGnSecurity == GnSecurity::Enabled && packet[0] & 0x0F == 1;
        // DAD (clause 10.2.1.5 step 1b): another station sends with our link-layer
        // address. With itsGnSecurity ENABLED only after the packet verified
        // (`process_security_header`): a forged frame cannot change our address.
        if self.mib.itsGnSecurity != GnSecurity::Enabled {
            self.link_layer_dad(sender_ll_address);
        }
        let basic_header = BasicHeader::decode(
            packet[0..4]
                .try_into()
                .expect("BasicHeader slice wrong length"),
        );
        if basic_header.version != self.mib.itsGnProtocolVersion {
            return;
        }
        let remaining = &packet[4..];
        match basic_header.nh {
            BasicNH::CommonHeader if unsecured_with_security => {
                self.process_unsecured(remaining, &basic_header);
            }
            BasicNH::CommonHeader => {
                self.process_common_header(remaining, &basic_header, None, sender_ll_address);
            }
            BasicNH::SecuredPacket => {
                self.process_security_header(remaining, &basic_header, sender_ll_address);
            }
            _ => {}
        }
    }

    /// Process a secured packet verified outside the router (see
    /// [`RouterHandle::send_verified_packet`]).
    pub fn process_verified(
        &mut self,
        packet: &[u8],
        plain_message: &[u8],
        security: SecurityIndication,
    ) {
        if packet.len() < 4 || security.report != crate::security::sn_sap::ReportVerify::Success {
            return;
        }
        let basic_header = BasicHeader::decode(packet[0..4].try_into().expect("Basic Header"));
        if basic_header.version != self.mib.itsGnProtocolVersion {
            return;
        }
        self.process_common_header_secured(
            plain_message,
            &basic_header,
            Some(&packet[4..]),
            None,
            Some(security),
        );
    }

    /// Process security header — verify and dispatch.
    fn process_security_header(
        &mut self,
        packet: &[u8],
        basic_header: &BasicHeader,
        sender_ll_address: Option<[u8; 6]>,
    ) {
        let (backend, cert_library) = match (&self.verify_backend, &mut self.verify_cert_library) {
            (Some(b), Some(cl)) => (b, cl),
            _ => {
                return;
            }
        };

        let verify_request = SNVerifyRequest {
            message: packet.to_vec(),
        };

        let (confirm, events) =
            verify_service::verify_message(&verify_request, backend, cert_library);
        if let Some(observer) = &self.verify_observer {
            observer(packet, &confirm);
        }

        if let Some(ref mut sign_service) = self.sign_service {
            for event in events {
                match event {
                    verify_service::VerifyEvent::UnknownAt(h8) => {
                        sign_service.notify_unknown_at(&h8);
                    }
                    verify_service::VerifyEvent::KnownAt(h8) => {
                        sign_service.notify_known_at(&h8);
                    }
                    verify_service::VerifyEvent::InlineP2pcdRequest(h3s) => {
                        sign_service.notify_inline_p2pcd_request(&h3s);
                    }
                    verify_service::VerifyEvent::ReceivedCaCertificate(cert) => {
                        sign_service.notify_received_ca_certificate(*cert);
                    }
                    verify_service::VerifyEvent::TrustListRequests(requests, at) => {
                        if let Some(listener) = &self.trust_list_listener {
                            listener(&requests, &at);
                        }
                    }
                }
            }
        }

        if confirm.report != ReportVerify::Success {
            return;
        }
        // DAD (clause 10.2.1.5 step 1b) on a verified packet only (see `process_incoming`).
        self.link_layer_dad(sender_ll_address);

        // Dispatch plain_message as Common Header + payload. The Secured Packet
        // is kept (and the Basic Header keeps NH = SECURED_PACKET) so that
        // forwarders relay it unmodified.
        let security = SecurityIndication {
            report: confirm.report,
            certificate_id: confirm.certificate_id.clone(),
            its_aid: confirm.its_aid,
            permissions: confirm.permissions.clone(),
        };
        self.process_common_header_secured(
            &confirm.plain_message,
            basic_header,
            Some(packet),
            sender_ll_address,
            Some(security),
        );
    }

    /// Common Header processing (clause 10.3.5) and dispatch on the HT field.
    fn process_common_header(
        &mut self,
        packet: &[u8],
        basic_header: &BasicHeader,
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
    ) {
        self.process_common_header_secured(packet, basic_header, secured, sender, None);
    }

    /// [`Router::process_common_header`] for a verified secured packet: the
    /// security results are attached to the indication (Table 38).
    fn process_common_header_secured(
        &mut self,
        packet: &[u8],
        basic_header: &BasicHeader,
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
        security: Option<SecurityIndication>,
    ) {
        if packet.len() < 8 {
            return;
        }
        let common_header = CommonHeader::decode(
            packet[0..8]
                .try_into()
                .expect("CommonHeader slice wrong length"),
        );
        let payload = &packet[8..];

        // Step 1: MHL check
        if basic_header.rhl > common_header.mhl {
            return;
        }

        let indication: Option<GNDataIndication> = match common_header.ht {
            HeaderType::Beacon => {
                self.gn_data_indicate_beacon(payload);
                None
            }
            HeaderType::Tsb => match common_header.hst {
                HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop) => {
                    self.gn_data_indicate_shb(payload, &common_header, basic_header)
                }
                HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop) => self
                    .gn_data_indicate_tsb(payload, &common_header, basic_header, secured, sender),
                _ => None,
            },
            HeaderType::GeoBroadcast => {
                self.gn_data_indicate_gbc(payload, &common_header, basic_header, secured, sender)
            }
            HeaderType::GeoAnycast => {
                self.gn_data_indicate_gac(payload, &common_header, basic_header, secured, sender)
            }
            HeaderType::GeoUnicast => {
                self.gn_data_indicate_guc(payload, &common_header, basic_header, secured, sender)
            }
            HeaderType::Ls => {
                self.gn_data_indicate_ls(payload, &common_header, basic_header, secured, sender);
                None // LS never delivers to upper entity
            }
            _ => None,
        };

        // Step 2: forward the buffered packets, re-executing their
        // forwarding algorithm. Done after the packet updated the LocT, so
        // that a new neighbour announced by this very packet is taken into
        // account.
        self.flush_forwarding_buffers();

        if let Some(mut ind) = indication {
            ind.security = security;
            let _ = self.btp_tx.send(ind);
        }
    }

    // ------------------------------------------------------------------
    // Individual indicate handlers
    // ------------------------------------------------------------------

    /// An unsecured packet received with itsGnSecurity ENABLED. Clause 10.3.3
    /// step 2a would process it like any packet; this implementation restricts
    /// it so that unauthenticated packets cannot alter the GeoNetworking state:
    /// only a SHB is accepted, and it is passed to the upper entity without DAD,
    /// LocT update, buffer flush or forwarding (no Beacon, LS, GUC, GAC, GBC or
    /// multi-hop TSB). Its GN-DATA.indication carries no security indication;
    /// BTP delivers it only to the ports open to unsecured packets (the CRL /
    /// CTL broadcast of ETSI TS 103 601 V2.1.1 clause 5.4.2, sent as SHB, CPS_003).
    fn process_unsecured(&mut self, packet: &[u8], basic_header: &BasicHeader) {
        if packet.len() < 8 + 28 {
            return;
        }
        let common_header = CommonHeader::decode(packet[0..8].try_into().unwrap());
        if common_header.ht != HeaderType::Tsb
            || common_header.hst != HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop)
            || basic_header.rhl > common_header.mhl
        {
            return;
        }
        let body = &packet[8..];
        let lpv = LongPositionVector::decode(body[0..24].try_into().unwrap());
        let indication =
            Self::shb_indication(lpv, body[28..].to_vec(), &common_header, basic_header);
        let _ = self.btp_tx.send(indication);
    }

    /// GN-DATA.indication of a SHB (table 35).
    fn shb_indication(
        lpv: LongPositionVector,
        payload: Vec<u8>,
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) -> GNDataIndication {
        GNDataIndication {
            upper_protocol_entity: common_header.nh.clone(),
            packet_transport_type: PacketTransportType {
                header_type: HeaderType::Tsb,
                header_sub_type: HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            },
            source_position_vector: lpv,
            traffic_class: common_header.tc,
            destination_area: None,
            destination: None,
            remaining_packet_lifetime: Some(
                basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
            ),
            remaining_hop_limit: Some(basic_header.rhl),
            security: None,
            length: payload.len() as u16,
            data: payload,
        }
    }

    fn gn_data_indicate_shb(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
    ) -> Option<GNDataIndication> {
        if packet.len() < 28 {
            return None;
        }
        let lpv = LongPositionVector::decode(
            packet[0..24]
                .try_into()
                .expect("SHB: LPV slice wrong length"),
        );
        // Media dependent data (4 bytes) + payload
        let payload = packet[28..].to_vec();

        // Step 3: DAD (clause 10.2.1.5): an SHB is single-hop, so an SO with
        // our address is another station.
        if self.duplicate_address_detection(lpv.gn_addr) {
            self.resolve_address_conflict();
        }

        self.location_table.new_shb_packet(&lpv, &payload);
        // TS 103 836-4-2 clause 7.2.2 (between steps 6 and 7): LocTEX-G5
        if self.mib.itsGnIfType != GnIfType::LteV2x {
            let now = self.now();
            if let Some(dcc_net) = self.dcc_net.as_mut() {
                dcc_net.update_loctex(
                    lpv.gn_addr,
                    u32::from_be_bytes(lpv.tst.encode()),
                    &packet[24..28],
                    now,
                    None,
                );
            }
        }
        // Flush the LS and UC forwarding packet buffers of SO
        self.flush_source_buffers(&lpv.gn_addr);

        Some(Self::shb_indication(
            lpv,
            payload,
            common_header,
            basic_header,
        ))
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
        // DAD (clause 10.2.1.5): a Beacon is single-hop, so an SO with our
        // address is another station.
        if self.duplicate_address_detection(lpv.gn_addr) {
            self.resolve_address_conflict();
        }
        self.location_table.new_shb_packet(&lpv, &packet[24..]);
        // Flush the LS and UC forwarding packet buffers of SO
        self.flush_source_buffers(&lpv.gn_addr);
    }

    /// GBC forwarder and receiver operations (ETSI TS 103 836-4-1 V2.2.1,
    /// clause 10.3.11.3).
    fn gn_data_indicate_gbc(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
    ) -> Option<GNDataIndication> {
        if packet.len() < 44 {
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
        if !matches!(common_header.hst, HeaderSubType::GeoBroadcast(_)) {
            return None;
        }
        let area_f = self.area_function(
            &common_header.hst,
            &area,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        );

        // Step 3: with CBF, duplicates are handled by the forwarding algorithm
        // (NOTEs 1a/1b); otherwise DPD (clause A.2) runs in the LocT update.
        if self.cbf_applies(area_f >= 0.0) {
            let probe = Self::cbf_probe(
                basic_header,
                common_header.tc,
                RouteKind::Area,
                ext.so_pv,
                ext.sn,
                sender,
            );
            if self.cbf_handle_duplicate(&probe) {
                return None;
            }
        }

        // Step 4: DAD
        if self.duplicate_address_detection(ext.so_pv.gn_addr) {
            return None;
        }

        // Steps 5-6: DPD + LocTE update
        if self.location_table.new_gbc_packet(&ext, payload) {
            return None; // duplicate
        }

        // Step 7: inside/at border → deliver
        let mut indication: Option<GNDataIndication> = None;
        if area_f >= 0.0 {
            indication = Some(GNDataIndication {
                upper_protocol_entity: common_header.nh.clone(),
                packet_transport_type: PacketTransportType {
                    header_type: HeaderType::GeoBroadcast,
                    header_sub_type: common_header.hst.clone(),
                },
                destination_area: Some(area),
                destination: None,
                source_position_vector: ext.so_pv,
                traffic_class: common_header.tc,
                remaining_packet_lifetime: Some(
                    basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
                ),
                remaining_hop_limit: Some(basic_header.rhl),
                security: None,
                length: payload.len() as u16,
                data: payload.to_vec(),
            });
        }

        // Step 8: flush the LS and UC forwarding packet buffers of SO
        self.flush_source_buffers(&ext.so_pv.gn_addr);

        // §B.3: area size control
        if Self::compute_area_size_m2(&common_header.hst, &area)
            > self.mib.itsGnMaxGeoAreaSize as f64 * 1_000_000.0
        {
            return indication;
        }

        // §B.2: PDR enforcement
        if self
            .location_table
            .get_entry_ref(&ext.so_pv.gn_addr)
            .is_some_and(|entry| entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0)
        {
            return indication;
        }

        // Steps 9-14: decrement RHL and forward
        self.gn_data_forward_gbc(basic_header, common_header, &ext, payload, secured, sender);

        indication
    }

    /// GAC forwarder and receiver operations (ETSI TS 103 836-4-1 V2.2.1,
    /// clause 10.3.12.3): inside the area the packet is delivered and not
    /// forwarded; outside it is forwarded and not delivered.
    fn gn_data_indicate_gac(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
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
        if !matches!(common_header.hst, HeaderSubType::GeoAnycast(_)) {
            return None;
        }
        let area_f = self.area_function(
            &common_header.hst,
            &area,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        );

        // Outside the area with non-area CBF, duplicates are handled by the
        // forwarding algorithm.
        if area_f < 0.0 && self.cbf_applies(false) {
            let mut probe = Self::cbf_probe(
                basic_header,
                common_header.tc,
                RouteKind::Area,
                ext.so_pv,
                ext.sn,
                sender,
            );
            probe.area = Some(area);
            if self.cbf_handle_duplicate(&probe) {
                return None;
            }
        }

        if self.duplicate_address_detection(ext.so_pv.gn_addr) {
            return None;
        }

        if self.location_table.new_gac_packet(&ext, payload) {
            return None; // duplicate
        }

        // Flush the LS and UC forwarding packet buffers of SO
        self.flush_source_buffers(&ext.so_pv.gn_addr);

        // Inside/at border → deliver and STOP (no forwarding)
        if area_f >= 0.0 {
            return Some(GNDataIndication {
                upper_protocol_entity: common_header.nh.clone(),
                packet_transport_type: PacketTransportType {
                    header_type: HeaderType::GeoAnycast,
                    header_sub_type: common_header.hst.clone(),
                },
                destination_area: Some(area),
                destination: None,
                source_position_vector: ext.so_pv,
                traffic_class: common_header.tc,
                remaining_packet_lifetime: Some(
                    basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
                ),
                remaining_hop_limit: Some(basic_header.rhl),
                security: None,
                length: payload.len() as u16,
                data: payload.to_vec(),
            });
        }

        // Outside → forward only, no delivery
        // §B.3: area size control
        if Self::compute_area_size_m2(&common_header.hst, &area)
            > self.mib.itsGnMaxGeoAreaSize as f64 * 1_000_000.0
        {
            return None;
        }

        // §B.2: PDR enforcement
        if self
            .location_table
            .get_entry_ref(&ext.so_pv.gn_addr)
            .is_some_and(|entry| entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0)
        {
            return None;
        }

        // Decrement RHL, SCF buffering, Annex D (a packet from a sender inside
        // the area is discarded) and non-area forwarding
        self.gn_data_forward_gbc(basic_header, common_header, &ext, payload, secured, sender);
        None
    }

    /// TSB forwarder and receiver operations (ETSI TS 103 836-4-1 V2.2.1,
    /// clause 10.3.9.3).
    fn gn_data_indicate_tsb(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
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
            destination: None,
            remaining_packet_lifetime: Some(
                basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
            ),
            remaining_hop_limit: Some(basic_header.rhl),
            security: None,
            length: payload.len() as u16,
            data: payload.to_vec(),
        };

        // Step 8: flush the LS and UC forwarding packet buffers of SO
        self.flush_source_buffers(&ext.so_pv.gn_addr);

        // §B.2: PDR enforcement
        if self
            .location_table
            .get_entry_ref(&ext.so_pv.gn_addr)
            .is_some_and(|entry| entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0)
        {
            return Some(indication);
        }

        // Steps 9-12: decrement RHL, SCF buffering or broadcast
        if basic_header.rhl > 1 {
            let body = match secured {
                Some(secured) => secured.to_vec(),
                None => {
                    let mut v = common_header.encode().to_vec();
                    v.extend_from_slice(&ext.encode());
                    v.extend_from_slice(payload);
                    v
                }
            };
            let mut fwd = BufferedPacket::new(
                (*basic_header).set_rhl(basic_header.rhl - 1),
                body,
                common_header.tc,
                RouteKind::Broadcast,
            );
            fwd.so_pv = Some(ext.so_pv);
            fwd.sn = Some(ext.sn);
            fwd.sender_ll_address = sender;
            let _ = self.forward(fwd, false);
        }

        Some(indication)
    }

    /// GUC forwarder (clause 10.3.8.3) and destination (clause 10.3.8.4)
    /// operations of ETSI TS 103 836-4-1 V2.2.1.
    fn gn_data_indicate_guc(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
    ) -> Option<GNDataIndication> {
        if packet.len() < 48 {
            return None;
        }
        let ext = GUCExtendedHeader::decode(&packet[0..48]);
        let payload = &packet[48..];
        let is_destination = ext.de_pv.gn_address == self.mib.itsGnLocalGnAddr;

        // Forwarder step 3: with non-area CBF, duplicates are handled by the
        // forwarding algorithm (NOTE 1).
        if !is_destination && self.cbf_applies(false) {
            let mut probe = Self::cbf_probe(
                basic_header,
                common_header.tc,
                RouteKind::Unicast,
                ext.so_pv,
                ext.sn,
                sender,
            );
            probe.destination = Some(ext.de_pv.clone());
            if self.cbf_handle_duplicate(&probe) {
                return None;
            }
        }

        if self.duplicate_address_detection(ext.so_pv.gn_addr) {
            return None;
        }

        if self.location_table.new_guc_packet(&ext, payload) {
            return None; // duplicate
        }

        // Flush the LS and UC forwarding packet buffers of SO
        self.flush_source_buffers(&ext.so_pv.gn_addr);

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
                // Clause J.4: the destination address the source generated the GUC with.
                destination: Some(ext.de_pv.gn_address),
                remaining_packet_lifetime: Some(
                    basic_header.lt.get_value_in_milliseconds() as f64 / 1000.0,
                ),
                remaining_hop_limit: Some(basic_header.rhl),
                security: None,
                length: payload.len() as u16,
                data: payload.to_vec(),
            });
        }

        // Forwarder operations
        // §B.2: PDR enforcement
        if self
            .location_table
            .get_entry_ref(&ext.so_pv.gn_addr)
            .is_some_and(|entry| entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0)
        {
            return None;
        }

        // Step 7: DE not a neighbour: update PV(DE) in the LocT from the DE PV
        if secured.is_none() {
            self.location_table.update_with_de_pv(&ext.de_pv);
        }
        // Step 8: update the DE PV of an unsecured packet from the LocT when DE
        // is a neighbour with a newer PV (signatures of forwarded packets are
        // not updated)
        let mut fwd_ext = ext.clone();
        if secured.is_none() {
            if let Some(de_entry) = self.location_table.get_entry_ref(&ext.de_pv.gn_address) {
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
        }

        // Steps 9-15: decrement RHL, SCF buffering, forwarding algorithm
        if basic_header.rhl > 1 {
            let body = match secured {
                Some(secured) => secured.to_vec(),
                None => {
                    let mut v = common_header.encode().to_vec();
                    v.extend_from_slice(&fwd_ext.encode());
                    v.extend_from_slice(payload);
                    v
                }
            };
            let mut fwd = BufferedPacket::new(
                (*basic_header).set_rhl(basic_header.rhl - 1),
                body,
                common_header.tc,
                RouteKind::Unicast,
            );
            fwd.so_pv = Some(ext.so_pv);
            fwd.sn = Some(ext.sn);
            fwd.destination = Some(fwd_ext.de_pv.clone());
            fwd.sender_ll_address = sender;
            let _ = self.forward(fwd, false);
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
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
    ) {
        match &common_header.hst {
            HeaderSubType::LocationService(LocationServiceHST::LsRequest) => {
                self.gn_data_indicate_ls_request(
                    packet,
                    common_header,
                    basic_header,
                    secured,
                    sender,
                );
            }
            HeaderSubType::LocationService(LocationServiceHST::LsReply) => {
                self.gn_data_indicate_ls_reply(
                    packet,
                    common_header,
                    basic_header,
                    secured,
                    sender,
                );
            }
            _ => {}
        }
    }

    /// LS Request forwarder (clause 10.3.7.2, as TSB without delivery) and
    /// destination (clause 10.3.7.3, answered with an LS Reply) operations.
    fn gn_data_indicate_ls_request(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
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
        self.flush_source_buffers(&ls_req.so_pv.gn_addr);

        // Clause 10.3.7.3: destination when the MID field of Request GN_ADDR matches.
        if ls_req.request_gn_addr.mid.as_bytes() == self.mib.itsGnLocalGnAddr.mid.as_bytes() {
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

            let reply_basic = BasicHeader::initialize_with_mib_request_and_rhl(
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
                LSReplyExtendedHeader::initialize(sn, self.ego_position_vector, de_pv.clone());
            let mut body = reply_common.encode().to_vec();
            body.extend_from_slice(&reply_ext.encode());
            // Step 10: security encapsulation with ITS-AID 141 (table 26).
            let Some((reply_basic, body)) = self.sign_mgmt(reply_basic, body) else {
                return;
            };
            let mut reply =
                BufferedPacket::new(reply_basic, body, reply_common.tc, RouteKind::Unicast);
            reply.so_pv = Some(self.ego_position_vector);
            reply.sn = Some(sn);
            reply.destination = Some(de_pv);
            let _ = self.forward(reply, true);
        } else {
            // Forwarder: re-broadcast
            // §B.2 PDR enforcement
            if let Some(entry) = self.location_table.get_entry_ref(&ls_req.so_pv.gn_addr) {
                if entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0 {
                    return;
                }
            }
            if basic_header.rhl > 1 {
                let body = match secured {
                    Some(secured) => secured.to_vec(),
                    None => {
                        let mut v = common_header.encode().to_vec();
                        v.extend_from_slice(&ls_req.encode());
                        v.extend_from_slice(payload);
                        v
                    }
                };
                let mut fwd = BufferedPacket::new(
                    (*basic_header).set_rhl(basic_header.rhl - 1),
                    body,
                    common_header.tc,
                    RouteKind::Broadcast,
                );
                fwd.so_pv = Some(ls_req.so_pv);
                fwd.sn = Some(ls_req.sn);
                fwd.sender_ll_address = sender;
                let _ = self.forward(fwd, false);
            }
        }
    }

    /// LS Reply at the source of the LS (clause 10.3.7.1.4) or at a forwarder
    /// (clause 10.3.7.2, handled as GUC).
    fn gn_data_indicate_ls_reply(
        &mut self,
        packet: &[u8],
        common_header: &CommonHeader,
        basic_header: &BasicHeader,
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
    ) {
        if packet.len() < 48 {
            return;
        }
        let ls_reply = LSReplyExtendedHeader::decode(&packet[0..48]);
        let payload = &packet[48..];
        let is_source = ls_reply.de_pv.gn_address == self.mib.itsGnLocalGnAddr;

        if !is_source && self.cbf_applies(false) {
            let mut probe = Self::cbf_probe(
                basic_header,
                common_header.tc,
                RouteKind::Unicast,
                ls_reply.so_pv,
                ls_reply.sn,
                sender,
            );
            probe.destination = Some(ls_reply.de_pv.clone());
            if self.cbf_handle_duplicate(&probe) {
                return;
            }
        }

        if self.duplicate_address_detection(ls_reply.so_pv.gn_addr) {
            return;
        }

        // DPD, update PV(SO) and PDR(SO)
        if self.location_table.new_ls_reply_packet(&ls_reply, payload) {
            return; // duplicate
        }

        let sought_gn_addr = ls_reply.so_pv.gn_addr;

        if is_source {
            // Steps 6-10: flush the LS buffer, stop TLS, reset RTCLS, LS_pending = FALSE
            self.complete_ls(&sought_gn_addr);
            self.flush_source_buffers(&sought_gn_addr);
            return;
        }

        // Forwarder: GUC forwarder operations
        self.flush_source_buffers(&sought_gn_addr);
        // §B.2: PDR enforcement
        if self
            .location_table
            .get_entry_ref(&sought_gn_addr)
            .is_some_and(|entry| entry.pdr > self.mib.itsGnMaxPacketDataRate as f64 * 1000.0)
        {
            return;
        }

        // GUC forwarder step 7: DE not a neighbour: update PV(DE) from the DE PV
        if secured.is_none() {
            self.location_table.update_with_de_pv(&ls_reply.de_pv);
        }
        let mut fwd_reply = ls_reply.clone();
        if secured.is_none() {
            if let Some(de_entry) = self
                .location_table
                .get_entry_ref(&ls_reply.de_pv.gn_address)
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
        }

        if basic_header.rhl > 1 {
            let body = match secured {
                Some(secured) => secured.to_vec(),
                None => {
                    let mut v = common_header.encode().to_vec();
                    v.extend_from_slice(&fwd_reply.encode());
                    v.extend_from_slice(payload);
                    v
                }
            };
            let mut fwd = BufferedPacket::new(
                (*basic_header).set_rhl(basic_header.rhl - 1),
                body,
                common_header.tc,
                RouteKind::Unicast,
            );
            fwd.so_pv = Some(ls_reply.so_pv);
            fwd.sn = Some(ls_reply.sn);
            fwd.destination = Some(fwd_reply.de_pv.clone());
            fwd.sender_ll_address = sender;
            let _ = self.forward(fwd, false);
        }
    }

    /// Initiate a Location Service request for `sought_addr`, or queue
    /// `buffered_request` while one is in progress (ETSI TS 103 836-4-1
    /// V2.2.1, clauses 10.2.4 and 10.3.7.1.2).
    fn gn_ls_request(&mut self, sought_addr: &GNAddress, buffered_request: Option<GNDataRequest>) {
        let key = sought_addr.encode_to_int();
        if self
            .location_table
            .get_entry_ref(sought_addr)
            .is_some_and(|entry| entry.ls_pending)
        {
            if let Some(request) = buffered_request {
                self.ls_buffer_request(key, request);
            }
            return;
        }
        // Step 7: LocTE for the sought GN_ADDR with LS_pending = TRUE
        self.location_table.ensure_entry(sought_addr).ls_pending = true;
        if let Some(request) = buffered_request {
            self.ls_buffer_request(key, request);
        }
        // Steps 5-6: start TLS and initialise RTCLS
        self.ls_retransmit_counters.insert(key, 0);
        let deadline = self.now() + self.mib.itsGnLocationServiceRetransmitTimer as u64;
        self.ls_deadlines.insert(key, deadline);
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
        // Request GN_ADDR: the MID of the sought router, the other bits 0
        // (the destination matches the MID, clause 10.3.7.3).
        let request_addr = GNAddress::new(M::GnUnicast, ST::Unknown, sought_addr.mid);
        let ls_req =
            LSRequestExtendedHeader::initialize(sn, self.ego_position_vector, request_addr);

        let mut body = common_header.encode().to_vec();
        body.extend_from_slice(&ls_req.encode());
        // Step 3: security encapsulation with ITS-AID 141 (table 24).
        let Some((basic_header, body)) = self.sign_mgmt(basic_header, body) else {
            return;
        };
        let mut packet = basic_header.encode().to_vec();
        packet.extend_from_slice(&body);
        let _ = self.link_layer_tx.send(packet);
    }

    // ------------------------------------------------------------------
    // GBC forwarding
    // ------------------------------------------------------------------

    /// Forwarder steps 9 to 14 of clause 10.3.11.3 (GBC) / 10.3.12.3 (GAC):
    /// decrement the RHL, buffer when no neighbour exists and SCF is set,
    /// then execute the forwarding algorithm (Annex D, E, F). A secured
    /// packet is relayed unmodified.
    fn gn_data_forward_gbc(
        &mut self,
        basic_header: &BasicHeader,
        common_header: &CommonHeader,
        gbc_ext: &GBCExtendedHeader,
        payload: &[u8],
        secured: Option<&[u8]>,
        sender: Option<[u8; 6]>,
    ) -> GNDataConfirm {
        if basic_header.rhl <= 1 {
            return accepted();
        }
        let body = match secured {
            Some(secured) => secured.to_vec(),
            None => {
                let mut v = common_header.encode().to_vec();
                v.extend_from_slice(&gbc_ext.encode());
                v.extend_from_slice(payload);
                v
            }
        };
        let mut packet = BufferedPacket::new(
            (*basic_header).set_rhl(basic_header.rhl - 1),
            body,
            common_header.tc,
            RouteKind::Area,
        );
        packet.so_pv = Some(gbc_ext.so_pv);
        packet.sn = Some(gbc_ext.sn);
        packet.area_type = Some(common_header.hst.clone());
        packet.area = Some(Area {
            latitude: gbc_ext.latitude,
            longitude: gbc_ext.longitude,
            a: gbc_ext.a,
            b: gbc_ext.b,
            angle: gbc_ext.angle,
        });
        packet.sender_ll_address = sender;
        self.forward(packet, false)
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
        if self.greedy_next_hop(dest_lat, dest_lon).is_some() {
            return true;
        }
        // Local optimum
        if traffic_class.scf {
            return false; // buffer
        }
        true // BCAST fallback
    }

    /// E.2 Most Forward within Radius: GN address of the neighbour closest
    /// to the destination, provided it is closer than the ego position;
    /// `None` at a local optimum.
    fn greedy_next_hop(&self, dest_lat: i32, dest_lon: i32) -> Option<GNAddress> {
        let mut mfr = Self::distance_m(
            dest_lat,
            dest_lon,
            self.ego_position_vector.latitude as i32,
            self.ego_position_vector.longitude as i32,
        );
        let mut best = None;
        for entry in self.location_table.get_neighbours() {
            let pv = &entry.position_vector;
            let d = Self::distance_m(dest_lat, dest_lon, pv.latitude as i32, pv.longitude as i32);
            if d < mfr {
                mfr = d;
                best = Some(pv.gn_addr);
            }
        }
        best
    }

    /// Annex D for an area: area forwarding when ego is inside or at the
    /// border; discarded when ego is outside and the (reliable) sender inside;
    /// non-area forwarding otherwise.
    fn area_algorithm_selection(
        &self,
        area_type: &HeaderSubType,
        area: &Area,
        sender_gn_addr: Option<&GNAddress>,
    ) -> GNForwardingAlgorithmResponse {
        if !matches!(
            area_type,
            HeaderSubType::GeoBroadcast(_) | HeaderSubType::GeoAnycast(_)
        ) {
            return GNForwardingAlgorithmResponse::Discarted;
        }
        let f_ego = self.area_function(
            area_type,
            area,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        );
        if f_ego >= 0.0 {
            return GNForwardingAlgorithmResponse::AreaForwarding;
        }
        // Ego is outside — SE_POS_VALID and F_SE (Annex D)
        if let Some(se_entry) = sender_gn_addr.and_then(|a| self.location_table.get_entry_ref(a)) {
            let se = &se_entry.position_vector;
            if se.pai && self.area_function(area_type, area, se.latitude, se.longitude) >= 0.0 {
                return GNForwardingAlgorithmResponse::Discarted;
            }
        }
        GNForwardingAlgorithmResponse::NonAreaForwarding
    }

    /// CBF timeout without Access Layer constraints for a progress or
    /// forwarding distance `dist_m` (equations E.1/E.2, F.1/F.2).
    #[cfg(test)]
    fn cbf_compute_timeout_ms(&self, dist_m: f64) -> f64 {
        self.cbf_timeout(dist_m)
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

    /// Geometric function F(x, y) (ETSI EN 302 931, clause 5; ETSI TS 103 899,
    /// clause 5) of a GBC area: 1 at the centre, > 0 inside, 0 at the border,
    /// < 0 outside.
    fn gn_geometric_function_f(
        &self,
        area_type: &GeoBroadcastHST,
        area: &Area,
        lat: &u32,
        lon: &u32,
    ) -> f64 {
        let (x, y) = Self::area_coordinates(area, *lat, *lon);
        let (a, b) = (area.a as f64, area.b as f64);
        match area_type {
            GeoBroadcastHST::GeoBroadcastCircle => 1.0 - (x / a).powi(2) - (y / a).powi(2),
            GeoBroadcastHST::GeoBroadcastEllipse => 1.0 - (x / a).powi(2) - (y / b).powi(2),
            GeoBroadcastHST::GeoBroadcastRectangle => {
                (1.0 - (x / a).powi(2)).min(1.0 - (y / b).powi(2))
            }
        }
    }

    /// (x, y) in metres of a point in the frame of the area: centred on the
    /// area centre, x along the long side `a`, which is rotated by
    /// `area.angle` degrees clockwise from North (azimuth).
    fn area_coordinates(area: &Area, lat: u32, lon: u32) -> (f64, f64) {
        let lat_c = (area.latitude as i32 as f64 / 1e7).to_radians();
        let lon_c = (area.longitude as i32 as f64 / 1e7).to_radians();
        let lat_p = (lat as i32 as f64 / 1e7).to_radians();
        let lon_p = (lon as i32 as f64 / 1e7).to_radians();
        let north = EARTH_RADIUS * (lat_p - lat_c);
        let east = EARTH_RADIUS * (lon_p - lon_c) * ((lat_p + lat_c) / 2.0).cos();
        let theta = (area.angle as f64).to_radians();
        (
            north * theta.cos() + east * theta.sin(),
            -north * theta.sin() + east * theta.cos(),
        )
    }

    /// F(x, y) for a GBC or GAC area subtype (negative for other subtypes).
    fn area_function(&self, area_type: &HeaderSubType, area: &Area, lat: u32, lon: u32) -> f64 {
        match area_type {
            HeaderSubType::GeoBroadcast(hst) => self.gn_geometric_function_f(hst, area, &lat, &lon),
            HeaderSubType::GeoAnycast(hst) => {
                self.gn_geometric_function_f_anycast(hst, area, &lat, &lon)
            }
            _ => -1.0,
        }
    }

    fn gn_geometric_function_f_anycast(
        &self,
        area_type: &GeoAnycastHST,
        area: &Area,
        lat: &u32,
        lon: &u32,
    ) -> f64 {
        let shape = match area_type {
            GeoAnycastHST::GeoAnycastCircle => GeoBroadcastHST::GeoBroadcastCircle,
            GeoAnycastHST::GeoAnycastEllipse => GeoBroadcastHST::GeoBroadcastEllipse,
            GeoAnycastHST::GeoAnycastRectangle => GeoBroadcastHST::GeoBroadcastRectangle,
        };
        self.gn_geometric_function_f(&shape, area, lat, lon)
    }

    /// Area size in m² of a GBC or GAC area (§B.3 area size control).
    fn compute_area_size_m2(area_type: &HeaderSubType, area: &Area) -> f64 {
        match area_type {
            HeaderSubType::GeoBroadcast(hst) => Self::compute_area_size_m2_gb(hst, area),
            HeaderSubType::GeoAnycast(GeoAnycastHST::GeoAnycastCircle) => {
                Self::compute_area_size_m2_gb(&GeoBroadcastHST::GeoBroadcastCircle, area)
            }
            HeaderSubType::GeoAnycast(GeoAnycastHST::GeoAnycastEllipse) => {
                Self::compute_area_size_m2_gb(&GeoBroadcastHST::GeoBroadcastEllipse, area)
            }
            HeaderSubType::GeoAnycast(GeoAnycastHST::GeoAnycastRectangle) => {
                Self::compute_area_size_m2_gb(&GeoBroadcastHST::GeoBroadcastRectangle, area)
            }
            _ => 0.0,
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

    /// SO address equal to the local GN address (clause 10.2.1.5 step 1a).
    /// Multi-hop packets with our address as SO are our own packets relayed
    /// back by a forwarder and are not processed; conflicts are resolved on
    /// single-hop packets and link-layer addresses
    /// ([`Router::resolve_address_conflict`]).
    pub fn duplicate_address_detection(&self, address: GNAddress) -> bool {
        self.mib.itsGnLocalGnAddr == address
    }

    /// Called with the new GN address after a duplicate address (clause
    /// 10.2.1.5 step 3), e.g. to set the ITS-G5 interface MAC to the new MID.
    pub fn set_address_change_callback(&mut self, callback: Box<dyn Fn(GNAddress) + Send>) {
        self.address_change_callback = Some(callback);
    }

    /// Duplicate address detected (clause 10.2.1.5 steps 2-3): with
    /// auto-address configuration, take a new random MID (unicast, locally
    /// administered) for the GN address, update itsGnLocalGnAddr and the ego
    /// position vector, and call the address change callback.
    /// DAD of clause 10.2.1.5 step 1b: a frame whose sender link-layer address is
    /// ours comes from another station using our address.
    fn link_layer_dad(&mut self, sender_ll_address: Option<[u8; 6]>) {
        if sender_ll_address == Some(self.mib.itsGnLocalGnAddr.mid.as_bytes()) {
            self.resolve_address_conflict();
        }
    }

    pub fn resolve_address_conflict(&mut self) {
        if self.mib.itsGnLocalGnAddrConfMethod != super::mib::LocalGnAddrConfMethod::Auto {
            return;
        }
        let mut mid: [u8; 6] = rand::random();
        mid[0] = (mid[0] | 0x02) & 0xFE;
        let mut new_addr = self.mib.itsGnLocalGnAddr;
        new_addr.mid = MID::new(mid);
        self.mib.itsGnLocalGnAddr = new_addr;
        self.gn_address = new_addr;
        self.ego_position_vector.gn_addr = new_addr;
        if let Some(callback) = &self.address_change_callback {
            callback(new_addr);
        }
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
    use crate::geonet::service_access_point::CommunicationProfile;
    use crate::security::sn_sap::SecurityProfile;
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
        // Clause 8.4.2: initialized to 0
        assert_eq!(router.get_sequence_number(), 0);
        assert_eq!(router.get_sequence_number(), 1);
        assert_eq!(router.get_sequence_number(), 2);
    }

    #[test]
    fn router_sequence_number_wraps() {
        let (mut router, _ll, _btp) = make_router();
        router.sequence_number = u16::MAX;
        assert_eq!(router.get_sequence_number(), u16::MAX);
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
        let (mut router, ll_rx, _btp) = make_router();
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

/// Forwarding with packet buffers, Location Service buffering and CBF
/// (ETSI TS 103 836-4-1 V2.2.1, clauses 8.5, 8.6, 10.3.5, 10.3.7, 10.3.9,
/// Annexes E and F). Mirrors `tests/flexstack/geonet/test_gn_forwarding.py`.
#[cfg(test)]
mod forwarding_tests {
    use super::*;
    use crate::geonet::gn_address::{M, MID, ST};
    use crate::geonet::service_access_point::CommunicationProfile;
    use crate::security::sn_sap::SecurityProfile;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::SystemTime;

    const EGO_LAT: i64 = 421255850;
    const EGO_LON: i64 = 27601710;

    fn metres_per_degree() -> f64 {
        EARTH_RADIUS * std::f64::consts::PI / 180.0
    }

    /// Latitude of a point `metres` north of the ego position.
    fn north(metres: f64) -> u32 {
        (EGO_LAT + (metres / metres_per_degree() * 1e7).round() as i64) as u32
    }

    /// Longitude of a point `metres` east of the ego position.
    fn east(metres: f64) -> u32 {
        let scale = metres_per_degree() * (EGO_LAT as f64 / 1e7).to_radians().cos();
        (EGO_LON + (metres / scale * 1e7).round() as i64) as u32
    }

    fn addr(n: u8) -> GNAddress {
        GNAddress::new(M::GnUnicast, ST::Unknown, MID::new([0x02, 0, 0, 0, 0, n]))
    }

    fn now_tst() -> Tst {
        Tst::set_in_normal_timestamp_milliseconds(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        )
    }

    /// Position vector of `addr(n)` stamped now (so that its LocTE does not expire).
    fn lpv(n: u8, lat: u32, lon: u32) -> LongPositionVector {
        LongPositionVector {
            gn_addr: addr(n),
            tst: now_tst(),
            latitude: lat,
            longitude: lon,
            pai: true,
            s: 0,
            h: 0,
        }
    }

    struct Fixture {
        router: Router,
        clock: Arc<AtomicU64>,
        ll_rx: Receiver<Vec<u8>>,
        btp_rx: Receiver<GNDataIndication>,
    }

    impl Fixture {
        fn new(mib: Mib) -> Self {
            let (ll_tx, ll_rx) = mpsc::channel();
            let (btp_tx, btp_rx) = mpsc::channel();
            let mut router = Router::new(mib, ll_tx, btp_tx, None, None, None);
            let clock = Arc::new(AtomicU64::new(0));
            let c = Arc::clone(&clock);
            router.set_clock(Box::new(move || c.load(Ordering::SeqCst)));
            router.ego_position_vector.latitude = EGO_LAT as u32;
            router.ego_position_vector.longitude = EGO_LON as u32;
            router.ego_position_vector.pai = true;
            router.beacon_deadline = None; // beacons tested separately
            Fixture {
                router,
                clock,
                ll_rx,
                btp_rx,
            }
        }

        fn set_time(&self, ms: u64) {
            self.clock.store(ms, Ordering::SeqCst);
        }

        fn tick(&mut self, ms: u64) {
            self.set_time(ms);
            self.router.tick(ms);
        }

        fn sent(&self) -> Vec<Vec<u8>> {
            self.ll_rx.try_iter().collect()
        }

        fn add_neighbour(&mut self, n: u8, lat: u32) {
            self.router
                .location_table
                .new_shb_packet(&lpv(n, lat, EGO_LON as u32), &[]);
        }

        fn basic(&self, rhl: u8) -> BasicHeader {
            BasicHeader::initialize_with_mib(&self.router.mib).set_rhl(rhl)
        }
    }

    fn common(ht: HeaderType, hst: HeaderSubType, tc: TrafficClass, mhl: u8) -> CommonHeader {
        CommonHeader {
            nh: CommonNH::BtpB,
            reserved: 0,
            ht,
            hst,
            tc,
            flags: 0,
            pl: 0,
            mhl,
            reserved2: 0,
        }
    }

    fn tc(scf: bool) -> TrafficClass {
        TrafficClass {
            scf,
            channel_offload: false,
            tc_id: 0,
        }
    }

    fn header_type(packet: &[u8]) -> HeaderType {
        CommonHeader::decode(packet[4..12].try_into().unwrap()).ht
    }

    fn beacon_from(f: &Fixture, n: u8, lat: u32) -> Vec<u8> {
        let mut p = f.basic(1).encode().to_vec();
        p.extend_from_slice(
            &common(
                HeaderType::Beacon,
                HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
                tc(false),
                1,
            )
            .encode(),
        );
        p.extend_from_slice(&lpv(n, lat, EGO_LON as u32).encode());
        p
    }

    fn area(a: u16) -> Area {
        Area {
            latitude: EGO_LAT as u32,
            longitude: EGO_LON as u32,
            a,
            b: a,
            angle: 0,
        }
    }

    fn gbc_packet(f: &Fixture, so: LongPositionVector, sn: u16, area: Area) -> Vec<u8> {
        let mut p = f.basic(5).encode().to_vec();
        p.extend_from_slice(
            &common(
                HeaderType::GeoBroadcast,
                HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle),
                tc(false),
                10,
            )
            .encode(),
        );
        p.extend_from_slice(
            &GBCExtendedHeader {
                sn,
                reserved: 0,
                so_pv: so,
                latitude: area.latitude,
                longitude: area.longitude,
                a: area.a,
                b: area.b,
                angle: area.angle,
                reserved2: 0,
            }
            .encode(),
        );
        p.extend_from_slice(b"payload");
        p
    }

    fn guc_packet(
        f: &Fixture,
        so: LongPositionVector,
        sn: u16,
        de: ShortPositionVector,
        scf: bool,
    ) -> Vec<u8> {
        let mut p = f.basic(5).encode().to_vec();
        p.extend_from_slice(
            &common(
                HeaderType::GeoUnicast,
                HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
                tc(scf),
                10,
            )
            .encode(),
        );
        p.extend_from_slice(
            &GUCExtendedHeader {
                sn,
                reserved: 0,
                so_pv: so,
                de_pv: de,
            }
            .encode(),
        );
        p.extend_from_slice(b"payload");
        p
    }

    fn request(header_type: HeaderType, hst: HeaderSubType) -> GNDataRequest {
        GNDataRequest {
            upper_protocol_entity: CommonNH::BtpB,
            packet_transport_type: PacketTransportType {
                header_type,
                header_sub_type: hst,
            },
            communication_profile: CommunicationProfile::Unspecified,
            traffic_class: tc(false),
            security_profile: SecurityProfile::NoSecurity,
            its_aid: 0,
            security_permissions: vec![],
            max_hop_limit: 0,
            max_packet_lifetime: None,
            destination: None,
            length: 3,
            data: b"req".to_vec(),
            area: area(100),
        }
    }

    fn shb_request(scf: bool, lifetime: Option<f64>) -> GNDataRequest {
        let mut r = request(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
        );
        r.traffic_class = tc(scf);
        r.max_packet_lifetime = lifetime;
        r
    }

    fn guc_request(destination: GNAddress) -> GNDataRequest {
        let mut r = request(
            HeaderType::GeoUnicast,
            HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
        );
        r.destination = Some(destination);
        r
    }

    fn gbc_request() -> GNDataRequest {
        request(
            HeaderType::GeoBroadcast,
            HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle),
        )
    }

    fn short_pv(n: u8, lat: u32) -> ShortPositionVector {
        ShortPositionVector {
            gn_address: addr(n),
            tst: now_tst(),
            latitude: lat,
            longitude: EGO_LON as u32,
        }
    }

    // ── Store-carry-forward (clauses 8.6, 10.3.5 step 2) ─────────────────

    #[test]
    fn shb_buffered_without_neighbour_and_flushed_on_reception() {
        let mut f = Fixture::new(Mib::new());
        f.router.gn_data_request(shb_request(true, None));
        assert!(f.sent().is_empty());
        f.set_time(2000);
        let beacon = beacon_from(&f, 2, north(100.0));
        f.router.process_basic_header(&beacon);
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(header_type(&sent[0]), HeaderType::Tsb);
        // LT reduced by the queuing time (60 s default lifetime, 2 s queued)
        let lt = BasicHeader::decode(sent[0][0..4].try_into().unwrap()).lt;
        assert!(lt.get_value_in_milliseconds() < 60_000);
    }

    #[test]
    fn buffered_packet_discarded_after_its_lifetime() {
        let mut f = Fixture::new(Mib::new());
        f.router.gn_data_request(shb_request(true, Some(1.0)));
        f.set_time(1500);
        let beacon = beacon_from(&f, 2, north(100.0));
        f.router.process_basic_header(&beacon);
        assert!(f.sent().is_empty());
    }

    #[test]
    fn without_scf_the_packet_is_sent() {
        let mut f = Fixture::new(Mib::new());
        f.router.gn_data_request(shb_request(false, None));
        assert_eq!(f.sent().len(), 1);
    }

    #[test]
    fn greedy_local_optimum_buffers_guc_in_uc_buffer() {
        let mut f = Fixture::new(Mib::new());
        f.add_neighbour(3, north(-200.0)); // behind ego
        let packet = guc_packet(
            &f,
            lpv(2, north(-100.0), EGO_LON as u32),
            1,
            short_pv(9, north(1000.0)),
            true,
        );
        f.router.process_basic_header(&packet);
        assert!(f.sent().is_empty());
        assert_eq!(f.router.uc_buffers[&addr(9).encode_to_int()].len(), 1);
        // A packet from the destination flushes its UC forwarding packet buffer
        let beacon = beacon_from(&f, 9, north(150.0));
        f.router.process_basic_header(&beacon);
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(header_type(&sent[0]), HeaderType::GeoUnicast);
    }

    // ── TSB source (clause 10.3.9.2) ─────────────────────────────────────

    #[test]
    fn tsb_request_sends_multi_hop_packet() {
        let mut f = Fixture::new(Mib::new());
        let confirm = f.router.gn_data_request(request(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop),
        ));
        assert_eq!(confirm.result_code, ResultCode::Accepted);
        let packet = &f.sent()[0];
        let ch = CommonHeader::decode(packet[4..12].try_into().unwrap());
        assert_eq!(ch.ht, HeaderType::Tsb);
        assert_eq!(
            ch.hst,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop)
        );
        let bh = BasicHeader::decode(packet[0..4].try_into().unwrap());
        assert_eq!(bh.rhl, f.router.mib.itsGnDefaultHopLimit);
        let ext = TSBExtendedHeader::decode(&packet[12..40]);
        assert_eq!(ext.so_pv.gn_addr, f.router.mib.itsGnLocalGnAddr);
        assert_eq!(&packet[40..], b"req");
    }

    // ── Location Service buffer (clauses 8.5, 10.3.7.1) ──────────────────

    fn ls_reply(f: &Fixture, n: u8) -> Vec<u8> {
        let mut p = f.basic(5).encode().to_vec();
        p.extend_from_slice(
            &common(
                HeaderType::Ls,
                HeaderSubType::LocationService(LocationServiceHST::LsReply),
                tc(false),
                10,
            )
            .encode(),
        );
        p.extend_from_slice(
            &LSReplyExtendedHeader {
                sn: 1,
                reserved: 0,
                so_pv: lpv(n, north(300.0), EGO_LON as u32),
                de_pv: ShortPositionVector {
                    gn_address: f.router.mib.itsGnLocalGnAddr,
                    tst: now_tst(),
                    latitude: 0,
                    longitude: 0,
                },
            }
            .encode(),
        );
        p
    }

    #[test]
    fn guc_buffered_until_ls_reply() {
        let mut f = Fixture::new(Mib::new());
        f.router.gn_data_request(guc_request(addr(7)));
        f.router.gn_data_request(guc_request(addr(7))); // LS pending: buffered too
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(header_type(&sent[0]), HeaderType::Ls);
        f.set_time(500);
        let reply = ls_reply(&f, 7);
        f.router.process_basic_header(&reply);
        let sent = f.sent();
        assert_eq!(sent.len(), 2);
        for packet in &sent {
            assert_eq!(header_type(packet), HeaderType::GeoUnicast);
            let de = GUCExtendedHeader::decode(&packet[12..60]).de_pv;
            assert_eq!(de.latitude, north(300.0));
        }
        assert_eq!(f.router.next_deadline(), None);
    }

    #[test]
    fn ls_retransmission_then_abandon() {
        let mut mib = Mib::new();
        mib.itsGnLocationServiceMaxRetrans = 2;
        let mut f = Fixture::new(mib);
        f.router.gn_data_request(guc_request(addr(7)));
        assert_eq!(f.router.next_deadline(), Some(1000));
        f.tick(1000);
        f.tick(2000);
        assert_eq!(f.sent().len(), 3);
        f.tick(3000);
        assert!(f.sent().is_empty());
        assert!(f.router.location_table.get_entry_ref(&addr(7)).is_none());
        assert!(!f
            .router
            .ls_packet_buffers
            .contains_key(&addr(7).encode_to_int()));
        assert_eq!(f.router.next_deadline(), None);
    }

    // ── Area CBF (Annex F.3) ─────────────────────────────────────────────

    #[test]
    fn source_rebroadcasts_after_to_cbf_max() {
        let mut f = Fixture::new(Mib::new());
        f.router.gn_data_request(gbc_request());
        assert_eq!(f.sent().len(), 1);
        let to_max = f.router.mib.itsGnCbfMaxTime as u64;
        assert_eq!(f.router.next_deadline(), Some(to_max));
        f.tick(to_max);
        assert_eq!(f.sent().len(), 1);
    }

    #[test]
    fn source_stops_when_a_forwarded_copy_is_heard() {
        let mut f = Fixture::new(Mib::new());
        f.router.gn_data_request(gbc_request());
        let original = f.sent().remove(0);
        let mut forwarded = BasicHeader::decode(original[0..4].try_into().unwrap())
            .set_rhl(9)
            .encode()
            .to_vec();
        forwarded.extend_from_slice(&original[4..]);
        f.router
            .process_incoming(&forwarded, Some(addr(2).mid.as_bytes()));
        f.tick(1000);
        assert!(f.sent().is_empty());
    }

    /// GBC from SO = addr(2), 500 m north, received directly from it.
    fn receive_from_source(f: &mut Fixture) -> Vec<u8> {
        f.add_neighbour(2, north(500.0));
        let packet = gbc_packet(f, lpv(2, north(500.0), EGO_LON as u32), 7, area(1500));
        f.router
            .process_incoming(&packet, Some(addr(2).mid.as_bytes()));
        packet
    }

    #[test]
    fn forwarder_timeout_from_forwarding_distance() {
        let mut f = Fixture::new(Mib::new());
        receive_from_source(&mut f);
        assert_eq!(f.btp_rx.try_iter().count(), 1);
        assert!(f.sent().is_empty());
        let expected = f.router.cbf_timeout(500.0).ceil() as u64; // F_DIST = 500 m
        assert!(f.router.next_deadline().unwrap().abs_diff(expected) <= 1);
    }

    #[test]
    fn duplicate_from_better_forwarder_cancels() {
        let mut f = Fixture::new(Mib::new());
        let packet = receive_from_source(&mut f);
        f.add_neighbour(3, north(-600.0)); // D1=500 < D2=1100, D2 > D3=600
        f.router
            .process_incoming(&packet, Some(addr(3).mid.as_bytes()));
        assert!(f.router.cbf_buffer.is_empty());
        f.tick(1000);
        assert!(f.sent().is_empty());
    }

    #[test]
    fn duplicate_from_worse_forwarder_keeps_the_packet() {
        let mut f = Fixture::new(Mib::new());
        let packet = receive_from_source(&mut f);
        let deadline = f.router.next_deadline().unwrap();
        f.add_neighbour(4, north(100.0)); // between ego and SO: D2=400 < D1
        f.set_time(10);
        f.router
            .process_incoming(&packet, Some(addr(4).mid.as_bytes()));
        assert_eq!(f.router.cbf_buffer.len(), 1);
        assert!(f.router.next_deadline().unwrap() <= deadline);
        f.tick(1000);
        assert_eq!(f.sent().len(), 1);
    }

    // ── Non-area CBF (Annex E.3) ─────────────────────────────────────────

    fn non_area_cbf() -> Fixture {
        let mut mib = Mib::new();
        mib.itsGnNonAreaForwardingAlgorithm = NonAreaForwardingAlgorithm::Cbf;
        mib.itsGnAreaForwardingAlgorithm = AreaForwardingAlgorithm::Simple;
        Fixture::new(mib)
    }

    #[test]
    fn forwarder_with_progress_buffers_with_segment_timeout() {
        let mut f = non_area_cbf();
        f.add_neighbour(2, north(-300.0));
        let packet = guc_packet(
            &f,
            lpv(2, north(-300.0), EGO_LON as u32),
            1,
            short_pv(9, north(2000.0)),
            false,
        );
        f.router
            .process_incoming(&packet, Some(addr(2).mid.as_bytes()));
        assert!(f.sent().is_empty());
        let expected = f.router.cbf_timeout(300.0).ceil() as u64;
        assert!(f.router.next_deadline().unwrap().abs_diff(expected) <= 1);
    }

    #[test]
    fn forwarder_without_progress_discards() {
        let mut f = non_area_cbf();
        f.add_neighbour(5, north(300.0));
        let packet = guc_packet(
            &f,
            lpv(5, north(300.0), EGO_LON as u32),
            1,
            short_pv(9, north(2000.0)),
            false,
        );
        f.router
            .process_incoming(&packet, Some(addr(5).mid.as_bytes()));
        assert!(f.router.cbf_buffer.is_empty());
        assert!(f.sent().is_empty());
    }

    // ── Forwarding packet buffers (CAP/FPB) ────────────

    fn guc_source_request(destination: GNAddress, scf: bool, data: &[u8]) -> GNDataRequest {
        let mut r = guc_request(destination);
        r.traffic_class = tc(scf);
        r.data = data.to_vec();
        r.length = data.len() as u16;
        r
    }

    fn sequence_number(packet: &[u8]) -> u16 {
        u16::from_be_bytes([packet[12], packet[13]])
    }

    fn lifetime_ms(packet: &[u8]) -> u32 {
        BasicHeader::decode(packet[0..4].try_into().unwrap())
            .lt
            .get_value_in_milliseconds()
    }

    /// LocTE of a non-neighbour destination, learnt from a GUC it originated.
    fn known_destination(f: &mut Fixture, n: u8) {
        f.router.location_table.new_guc_packet(
            &GUCExtendedHeader {
                sn: 99,
                reserved: 0,
                so_pv: lpv(n, north(800.0), EGO_LON as u32),
                de_pv: short_pv(1, 0),
            },
            &[],
        );
    }

    #[test]
    fn guc_source_buffered_and_sent_when_a_neighbour_appears() {
        let mut f = Fixture::new(Mib::new());
        known_destination(&mut f, 9);
        f.router
            .gn_data_request(guc_source_request(addr(9), true, b"first"));
        f.router
            .gn_data_request(guc_source_request(addr(9), true, b"second"));
        assert!(f.sent().is_empty());
        f.set_time(3000);
        let beacon = beacon_from(&f, 2, north(400.0));
        f.router.process_basic_header(&beacon);
        let sent = f.sent();
        assert!(sent[0].ends_with(b"first") && sent[1].ends_with(b"second"));
        assert!(sequence_number(&sent[0]) < sequence_number(&sent[1]));
        assert!(lifetime_ms(&sent[0]) < 60_000);
    }

    #[test]
    fn gbc_source_buffered_without_recipients() {
        let mut mib = Mib::new();
        mib.itsGnAreaForwardingAlgorithm = AreaForwardingAlgorithm::Simple;
        let mut f = Fixture::new(mib);
        for data in [b"g1", b"g2"] {
            let mut r = gbc_request();
            r.traffic_class = tc(true);
            r.data = data.to_vec();
            f.router.gn_data_request(r);
        }
        assert!(f.sent().is_empty());
        f.set_time(2000);
        let beacon = beacon_from(&f, 2, north(50.0));
        f.router.process_basic_header(&beacon);
        let sent = f.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].ends_with(b"g1") && sent[1].ends_with(b"g2"));
        assert!(lifetime_ms(&sent[0]) < 60_000);
    }

    // ── Source security encapsulation of GBC, GAC and GUC (clause 9.4) ───

    fn denm_gbc_request() -> GNDataRequest {
        let mut r = gbc_request();
        r.security_profile = SecurityProfile::DecentralizedEnvironmentalNotificationMessage;
        r.its_aid = 37;
        r
    }

    fn generic_guc_request(destination: GNAddress) -> GNDataRequest {
        let mut r = guc_request(destination);
        r.its_aid = 3;
        r
    }

    /// PSID of a secured frame; `None` when the frame is not secured.
    fn secured_psid(frame: &[u8]) -> Option<u64> {
        use crate::security::certificate::decode_ieee1609_dot2_data;
        use crate::security::security_asn::ieee1609_dot2::Ieee1609Dot2Content;
        let basic = BasicHeader::decode(frame[0..4].try_into().unwrap());
        if !matches!(basic.nh, BasicNH::SecuredPacket) {
            return None;
        }
        let Ieee1609Dot2Content::signedData(sd) = decode_ieee1609_dot2_data(&frame[4..]).content
        else {
            panic!("expected signedData");
        };
        Some(u64::try_from(&sd.tbs_data.header_info.psid.0).unwrap())
    }

    fn secured_fixture(sign: bool) -> Fixture {
        use crate::facilities::ca_basic_service::conformance::Pki;
        let mut mib = Mib::new();
        mib.itsGnSecurity = GnSecurity::Enabled;
        let mut f = Fixture::new(mib);
        if sign {
            let mut pki = Pki::new();
            let at = pki.at(&[(37, None), (3, None)]);
            f.router.sign_service = Some(pki.sign_service(at));
        }
        f.add_neighbour(9, north(50.0));
        f
    }

    /// The verify observer sees the outcome of every verification of a received
    /// secured packet, accepted or not, and does not change the processing.
    #[test]
    fn verify_observer_sees_every_verification() {
        use crate::facilities::ca_basic_service::conformance::Pki;
        use std::sync::{Arc, Mutex};
        let mut pki = Pki::new();
        let at = pki.at(&[(36, None)]);
        let good = pki.secured_shb(&at, &[0x02, 0x02]);
        let mut bad = good.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01; // signature altered

        let mut mib = Mib::new();
        mib.itsGnSecurity = GnSecurity::Enabled;
        let mut f = Fixture::new(mib);
        f.router.verify_backend = Some(pki.backend.clone());
        f.router.verify_cert_library = Some(pki.library());
        let seen: Arc<Mutex<Vec<(usize, ReportVerify)>>> = Arc::default();
        let log = Arc::clone(&seen);
        f.router
            .set_verify_observer(Box::new(move |message, confirm| {
                log.lock().unwrap().push((message.len(), confirm.report));
            }));
        f.router.process_incoming(&good, None);
        f.router.process_incoming(&bad, None);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], (good.len() - 4, ReportVerify::Success));
        assert_eq!(seen[1].0, bad.len() - 4);
        assert_ne!(seen[1].1, ReportVerify::Success);
        // Only the verified packet reached BTP.
        assert_eq!(f.btp_rx.try_iter().count(), 1);
    }

    /// Table 18: Security profile `Unsecured` gives NH = Common Header (no
    /// signature) although itsGnSecurity is ENABLED; clause 10.3.3 step 2a: a
    /// secured router processes the unsecured packet, indicated without security
    /// (BTP then filters it per port). `NoSecurity` (not set) keeps the default
    /// signing: without a sign service the SHB is not sent.
    #[test]
    fn unsecured_profile_with_security_enabled() {
        let mut f = secured_fixture(false);
        let mut request = shb_request(false, None);
        request.security_profile = crate::security::sn_sap::SecurityProfile::Unsecured;
        let data = request.data.clone();
        f.router.gn_data_request(request);
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        let basic = BasicHeader::decode(sent[0][0..4].try_into().unwrap());
        assert!(matches!(basic.nh, BasicNH::CommonHeader));
        assert!(sent[0].ends_with(&data));
        let request = shb_request(false, None); // NoSecurity: default signing
        f.router.gn_data_request(request);
        assert!(f.sent().is_empty());

        let mut receiver = secured_fixture(false);
        receiver.router.process_basic_header(&sent[0]);
        let indication = receiver.btp_rx.try_recv().expect("unsecured SHB indicated");
        assert!(indication.security.is_none());
    }

    /// With itsGnSecurity ENABLED an unsecured packet cannot alter the GN state:
    /// an unsecured SHB is indicated without LocT update (nor DAD), an unsecured
    /// Beacon, LS Request or GBC is dropped, and an unsecured frame sent with our
    /// link-layer address triggers no address change (clause 10.2.1.5 step 1b).
    #[test]
    fn unsecured_packets_do_not_alter_gn_state_with_security_enabled() {
        let mut mib = Mib::new();
        mib.itsGnLocalGnAddr = addr(7);
        let mut sender = Fixture::new(mib);
        sender.add_neighbour(1, north(50.0));
        sender.router.gn_data_request(shb_request(false, None));
        sender.router.gn_data_request_beacon();
        sender.router.send_ls_request_packet(&addr(5));
        sender.router.gn_data_request(gbc_request());
        let frames = sender.sent();
        assert_eq!(frames.len(), 4);

        let mut receiver = secured_fixture(false);
        let own = receiver.router.mib.itsGnLocalGnAddr;
        for frame in &frames {
            receiver
                .router
                .process_incoming(frame, Some(own.mid.as_bytes()));
        }
        let indications: Vec<GNDataIndication> = receiver.btp_rx.try_iter().collect();
        assert_eq!(indications.len(), 1); // the SHB only
        assert_eq!(
            indications[0].packet_transport_type.header_type,
            HeaderType::Tsb
        );
        assert!(indications[0].security.is_none());
        assert!(receiver
            .router
            .location_table
            .get_entry_ref(&addr(7))
            .is_none());
        assert_eq!(
            format!("{:?}", receiver.router.mib.itsGnLocalGnAddr),
            format!("{own:?}")
        );
        assert!(receiver.sent().is_empty()); // nothing forwarded or answered
    }

    #[test]
    fn gbc_denm_unsecured_when_security_disabled() {
        let mut f = Fixture::new(Mib::new());
        f.add_neighbour(9, north(50.0));
        let confirm = f.router.gn_data_request(denm_gbc_request());
        assert!(matches!(confirm.result_code, ResultCode::Accepted));
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(secured_psid(&sent[0]), None);
        assert_eq!(header_type(&sent[0]), HeaderType::GeoBroadcast);
    }

    #[test]
    fn gbc_gac_guc_not_sent_when_security_enabled_without_sign_service() {
        let mut f = secured_fixture(false);
        let mut gac = gbc_request();
        gac.packet_transport_type = PacketTransportType {
            header_type: HeaderType::GeoAnycast,
            header_sub_type: HeaderSubType::GeoAnycast(GeoAnycastHST::GeoAnycastCircle),
        };
        for request in [denm_gbc_request(), gac, generic_guc_request(addr(9))] {
            let confirm = f.router.gn_data_request(request);
            assert!(matches!(confirm.result_code, ResultCode::Unspecified));
        }
        assert!(f.sent().is_empty());
    }

    #[test]
    fn gbc_and_guc_signed_when_security_enabled() {
        let mut f = secured_fixture(true);
        let mut generic_gbc = gbc_request();
        generic_gbc.its_aid = 3;
        f.router.gn_data_request(denm_gbc_request());
        f.router.gn_data_request(generic_gbc);
        f.router.gn_data_request(generic_guc_request(addr(9)));
        let psids: Vec<_> = f.sent().iter().map(|p| secured_psid(p)).collect();
        assert_eq!(psids, vec![Some(37), Some(3), Some(3)]);
    }

    #[test]
    fn gbc_not_sent_when_no_at_may_sign() {
        let mut f = secured_fixture(true);
        let mut r = gbc_request();
        r.its_aid = 140; // not in the AT appPermissions
        let confirm = f.router.gn_data_request(r);
        assert!(matches!(confirm.result_code, ResultCode::Unspecified));
        assert!(f.sent().is_empty());
    }

    #[test]
    fn bc_buffer_capacity_head_drop() {
        // 440-octet SHB packets, only two fit in 1 Ko
        let mut mib = Mib::new();
        mib.itsGnBcForwardingPacketBufferSize = 1;
        let mut f = Fixture::new(mib);
        for i in 0..3u8 {
            let mut r = shb_request(true, None);
            r.data = vec![i; 400];
            f.router.gn_data_request(r);
        }
        assert!(f.router.bc_buffer.size() <= 1024);
        let beacon = beacon_from(&f, 2, north(50.0));
        f.router.process_basic_header(&beacon);
        let payloads: Vec<u8> = f.sent().iter().map(|p| *p.last().unwrap()).collect();
        assert_eq!(payloads, vec![1, 2]);
    }

    // ── LS packet buffer (CAP/LOS) ─────────────────────

    #[test]
    fn ls_buffer_flushed_by_any_packet_from_the_destination() {
        let mut f = Fixture::new(Mib::new());
        f.router
            .gn_data_request(guc_source_request(addr(7), false, b"a"));
        f.router
            .gn_data_request(guc_source_request(addr(7), false, b"b"));
        f.set_time(400);
        let beacon = beacon_from(&f, 7, north(100.0));
        f.router.process_basic_header(&beacon);
        let sent = f.sent();
        let packets = &sent[1..];
        assert!(packets[0].ends_with(b"a") && packets[1].ends_with(b"b"));
        assert!(sequence_number(&packets[0]) < sequence_number(&packets[1]));
        assert!(lifetime_ms(&packets[0]) < 60_000);
        assert!(
            !f.router
                .location_table
                .get_entry_ref(&addr(7))
                .unwrap()
                .ls_pending
        );
        assert_eq!(f.router.next_deadline(), None);
    }

    #[test]
    fn ls_buffer_expired_packets_are_not_sent() {
        let mut f = Fixture::new(Mib::new());
        let mut short = guc_source_request(addr(7), false, b"s");
        short.max_packet_lifetime = Some(1.0);
        f.router.gn_data_request(short);
        f.router
            .gn_data_request(guc_source_request(addr(7), false, b"l"));
        f.set_time(1500);
        let beacon = beacon_from(&f, 7, north(100.0));
        f.router.process_basic_header(&beacon);
        let sent = f.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent[1].ends_with(b"l"));
    }

    #[test]
    fn ls_buffer_capacity_head_drop() {
        // itsGnLocationServicePacketBufferSize = 1024 octets
        let mut f = Fixture::new(Mib::new());
        for i in 0..3u8 {
            f.router
                .gn_data_request(guc_source_request(addr(7), false, &[i; 400]));
        }
        let beacon = beacon_from(&f, 7, north(100.0));
        f.router.process_basic_header(&beacon);
        let payloads: Vec<u8> = f.sent()[1..].iter().map(|p| *p.last().unwrap()).collect();
        assert_eq!(payloads, vec![1, 2]);
    }

    // ── CBF timing and duplicates (GUC/CBF, GBC/AREA/CBF) ────────────────

    fn far_destination() -> ShortPositionVector {
        short_pv(9, north(2000.0))
    }

    #[test]
    fn cbf_guc_source_sends_immediately() {
        let mut f = non_area_cbf();
        known_destination(&mut f, 9);
        f.router
            .gn_data_request(guc_source_request(addr(9), false, b"x"));
        assert_eq!(f.sent().len(), 1);
        assert_eq!(
            f.router.next_deadline(),
            Some(f.router.mib.itsGnCbfMaxTime as u64)
        );
    }

    #[test]
    fn cbf_guc_forwarded_at_contention_timeout() {
        let mut f = non_area_cbf();
        f.add_neighbour(2, north(-300.0));
        let packet = guc_packet(
            &f,
            lpv(2, north(-300.0), EGO_LON as u32),
            1,
            far_destination(),
            false,
        );
        f.router
            .process_incoming(&packet, Some(addr(2).mid.as_bytes()));
        let deadline = f.router.next_deadline().unwrap();
        f.tick(deadline - 1);
        assert!(f.sent().is_empty());
        f.tick(deadline);
        assert_eq!(f.sent().len(), 1);
    }

    #[test]
    fn cbf_guc_duplicate_from_better_forwarder_cancels() {
        let mut f = non_area_cbf();
        f.add_neighbour(2, north(-300.0));
        let packet = guc_packet(
            &f,
            lpv(2, north(-300.0), EGO_LON as u32),
            1,
            far_destination(),
            false,
        );
        f.router
            .process_incoming(&packet, Some(addr(2).mid.as_bytes()));
        f.add_neighbour(3, north(400.0)); // closer to the destination
        f.router
            .process_incoming(&packet, Some(addr(3).mid.as_bytes()));
        f.tick(1000);
        assert!(f.sent().is_empty());
    }

    #[test]
    fn cbf_guc_minimum_delay_at_dist_max() {
        // PROG = DIST_MAX gives TO_CBF_MIN
        let mut f = non_area_cbf();
        let dist_max = f.router.mib.itsGnDefaultMaxCommunicationRange as f64;
        f.add_neighbour(2, north(-dist_max));
        let packet = guc_packet(
            &f,
            lpv(2, north(-dist_max), EGO_LON as u32),
            1,
            far_destination(),
            false,
        );
        f.router
            .process_incoming(&packet, Some(addr(2).mid.as_bytes()));
        assert!(f.router.next_deadline().unwrap() <= f.router.mib.itsGnCbfMinTime as u64 + 1);
    }

    #[test]
    fn cbf_unknown_or_uncertain_sender_uses_to_cbf_max() {
        for area_mode in [false, true] {
            for known_without_pai in [false, true] {
                let mut f = if area_mode {
                    Fixture::new(Mib::new())
                } else {
                    non_area_cbf()
                };
                if known_without_pai {
                    let mut pv = lpv(4, north(-300.0), EGO_LON as u32);
                    pv.pai = false;
                    f.router.location_table.new_shb_packet(&pv, &[]);
                }
                let so = lpv(2, north(-300.0), EGO_LON as u32);
                let packet = if area_mode {
                    gbc_packet(&f, so, 1, area(1500))
                } else {
                    guc_packet(&f, so, 1, far_destination(), false)
                };
                f.router
                    .process_incoming(&packet, Some(addr(4).mid.as_bytes()));
                assert_eq!(
                    f.router.next_deadline(),
                    Some(f.router.mib.itsGnCbfMaxTime as u64)
                );
            }
        }
    }

    // ── Non-area CBF with GBC / GAC packets (clause E.3) ─────────────────

    fn gbc_and_gac() -> [(HeaderType, HeaderSubType); 2] {
        [
            (HeaderType::GeoBroadcast, gbc()),
            (HeaderType::GeoAnycast, gac()),
        ]
    }

    /// GBC or GAC for the remote area, received from `sender` (LL address).
    fn receive_remote_area_packet(
        f: &mut Fixture,
        hst: HeaderSubType,
        so_lat: u32,
        sender: u8,
    ) -> Vec<u8> {
        let so = lpv(2, so_lat, EGO_LON as u32);
        let p = area_packet(f, hst, so, 1, remote_area(100), 5);
        f.router
            .process_incoming(&p, Some(addr(sender).mid.as_bytes()));
        p
    }

    /// a source outside the
    /// destination area broadcasts at once.
    #[test]
    fn cbf_gbc_gac_source_outside_area_broadcasts() {
        for (ht, hst) in gbc_and_gac() {
            let mut f = non_area_cbf();
            let mut r = request(ht.clone(), hst);
            r.area = remote_area(100);
            f.router.gn_data_request(r);
            let sent = f.sent();
            assert_eq!(sent.len(), 1);
            assert_eq!(header_type(&sent[0]), ht);
        }
    }

    /// forwarded (RHL - 1) at
    /// the contention timeout, not before.
    #[test]
    fn cbf_gbc_gac_forwarded_at_contention_timeout() {
        for (ht, hst) in gbc_and_gac() {
            let mut f = non_area_cbf();
            f.add_neighbour(2, north(-300.0));
            receive_remote_area_packet(&mut f, hst, north(-300.0), 2);
            let deadline = f.router.next_deadline().unwrap();
            assert!(deadline < f.router.mib.itsGnCbfMaxTime as u64);
            f.tick(deadline - 1);
            assert!(f.sent().is_empty());
            f.tick(deadline);
            let sent = f.sent();
            assert_eq!(sent.len(), 1);
            assert_eq!(header_type(&sent[0]), ht);
            assert_eq!(rhl_of(&sent[0]), 4);
            assert_eq!(f.btp_rx.try_iter().count(), 0);
        }
    }

    /// the copy from a station
    /// closer to the area cancels the contention.
    #[test]
    fn cbf_gbc_gac_duplicate_from_better_forwarder_cancels() {
        for (_, hst) in gbc_and_gac() {
            let mut f = non_area_cbf();
            f.add_neighbour(2, north(-300.0));
            let p = receive_remote_area_packet(&mut f, hst, north(-300.0), 2);
            f.add_neighbour(3, north(400.0)); // closer to the area
            f.router.process_incoming(&p, Some(addr(3).mid.as_bytes()));
            f.tick(1000);
            assert!(f.sent().is_empty());
        }
    }

    /// progress DIST_MAX gives
    /// TO_CBF_MIN.
    #[test]
    fn cbf_gbc_gac_minimum_delay_at_dist_max() {
        for (_, hst) in gbc_and_gac() {
            let mut f = non_area_cbf();
            let dist_max = f.router.mib.itsGnDefaultMaxCommunicationRange as f64;
            f.add_neighbour(2, north(-dist_max));
            receive_remote_area_packet(&mut f, hst, north(-dist_max), 2);
            assert!(f.router.next_deadline().unwrap() <= f.router.mib.itsGnCbfMinTime as u64 + 1);
        }
    }

    /// unknown
    /// sender, or known sender with PAI = 0, gives TO_CBF_MAX.
    #[test]
    fn cbf_gbc_gac_unknown_or_uncertain_sender_uses_to_cbf_max() {
        for (_, hst) in gbc_and_gac() {
            for known_without_pai in [false, true] {
                let mut f = non_area_cbf();
                if known_without_pai {
                    let mut pv = lpv(4, north(-300.0), EGO_LON as u32);
                    pv.pai = false;
                    f.router.location_table.new_shb_packet(&pv, &[]);
                }
                receive_remote_area_packet(&mut f, hst.clone(), north(-300.0), 4);
                assert_eq!(
                    f.router.next_deadline(),
                    Some(f.router.mib.itsGnCbfMaxTime as u64)
                );
            }
        }
    }

    #[test]
    fn cbf_gbc_received_again_after_forwarding_is_discarded() {
        let mut f = Fixture::new(Mib::new());
        let packet = receive_from_source(&mut f);
        f.tick(1000);
        assert_eq!(f.sent().len(), 1);
        f.router
            .process_incoming(&packet, Some(addr(2).mid.as_bytes()));
        f.tick(2000);
        assert!(f.sent().is_empty());
        assert!(f.router.cbf_buffer.is_empty());
    }

    // ── Packet handling per TS 102 871-2 test purposes ───────────────────
    // (ports of the Python router tests: TestGNDataIndicate*, TestAnnexB/D/E)

    fn packet(f: &Fixture, rhl: u8, ch: CommonHeader, ext: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut p = f.basic(rhl).encode().to_vec();
        p.extend_from_slice(&ch.encode());
        p.extend_from_slice(ext);
        p.extend_from_slice(payload);
        p
    }

    fn rhl_of(packet: &[u8]) -> u8 {
        BasicHeader::decode(packet[0..4].try_into().unwrap()).rhl
    }

    fn ls_request_packet(f: &Fixture, so: u8, sought: GNAddress, sn: u16, rhl: u8) -> Vec<u8> {
        let ext = LSRequestExtendedHeader {
            sn,
            reserved: 0,
            so_pv: lpv(so, north(200.0), EGO_LON as u32),
            request_gn_addr: sought,
        };
        let ch = common(
            HeaderType::Ls,
            HeaderSubType::LocationService(LocationServiceHST::LsRequest),
            tc(false),
            10,
        );
        packet(f, rhl, ch, &ext.encode(), &[])
    }

    #[test]
    fn ls_request_sought_address() {
        let mut f = Fixture::new(Mib::new());
        f.router.gn_data_request(guc_request(addr(7)));
        let sent = f.sent();
        let ext = LSRequestExtendedHeader::decode(&sent[0][12..48]);
        assert_eq!(ext.request_gn_addr, addr(7));
        assert_eq!(ext.so_pv.gn_addr, f.router.mib.itsGnLocalGnAddr);
    }

    #[test]
    fn ls_request_for_ego_is_answered_once() {
        let mut f = Fixture::new(Mib::new());
        let own = f.router.mib.itsGnLocalGnAddr;
        let request = ls_request_packet(&f, 2, own, 5, 5);
        f.router.process_basic_header(&request);
        f.router.process_basic_header(&request);
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        let ch = CommonHeader::decode(sent[0][4..12].try_into().unwrap());
        assert_eq!(
            ch.hst,
            HeaderSubType::LocationService(LocationServiceHST::LsReply)
        );
        let reply = LSReplyExtendedHeader::decode(&sent[0][12..60]);
        assert_eq!(reply.de_pv.gn_address, addr(2));
    }

    #[test]
    fn ls_request_and_reply_are_forwarded() {
        let mut f = Fixture::new(Mib::new());
        let request = ls_request_packet(&f, 2, addr(8), 5, 5);
        f.router.process_basic_header(&request);
        let mut reply = ls_reply(&f, 3);
        // re-target the reply to another node: DE PV GN_ADDR = addr(4)
        reply[40..48].copy_from_slice(&addr(4).encode());
        f.router.process_basic_header(&reply);
        let sent = f.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().all(|p| rhl_of(p) == 4));
        assert_eq!(f.btp_rx.try_iter().count(), 0);
    }

    #[test]
    fn guc_source_without_neighbour_or_scf_is_broadcast() {
        let mut f = Fixture::new(Mib::new());
        known_destination(&mut f, 9);
        f.router
            .gn_data_request(guc_source_request(addr(9), false, b"x"));
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(header_type(&sent[0]), HeaderType::GeoUnicast);
    }

    #[test]
    fn guc_forwarder_without_scf_broadcasts_at_local_optimum() {
        let mut f = Fixture::new(Mib::new());
        f.add_neighbour(3, north(-200.0)); // behind ego
        let packet = guc_packet(
            &f,
            lpv(2, north(-100.0), EGO_LON as u32),
            1,
            short_pv(9, north(1000.0)),
            false,
        );
        f.router.process_basic_header(&packet);
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(rhl_of(&sent[0]), 4);
        assert_eq!(f.btp_rx.try_iter().count(), 0);
    }

    #[test]
    fn guc_greedy_next_hop_forwards() {
        let mut f = Fixture::new(Mib::new());
        f.add_neighbour(3, north(500.0)); // closer to the destination
        let packet = guc_packet(
            &f,
            lpv(2, north(-100.0), EGO_LON as u32),
            1,
            short_pv(9, north(1000.0)),
            true,
        );
        f.router.process_basic_header(&packet);
        assert_eq!(f.sent().len(), 1);
    }

    #[test]
    fn guc_rhl_restriction_and_destination_delivery() {
        let mut f = Fixture::new(Mib::new());
        let mut packet = guc_packet(
            &f,
            lpv(2, north(-100.0), EGO_LON as u32),
            1,
            short_pv(9, north(1000.0)),
            false,
        );
        packet[3] = 1; // RHL = 1
        f.router.process_basic_header(&packet);
        assert!(f.sent().is_empty());
        let own = f.router.mib.itsGnLocalGnAddr;
        let mut to_ego = short_pv(1, EGO_LAT as u32);
        to_ego.gn_address = own;
        let packet = guc_packet(&f, lpv(2, north(-100.0), EGO_LON as u32), 2, to_ego, false);
        f.router.process_basic_header(&packet);
        f.router.process_basic_header(&packet); // duplicate
        let delivered: Vec<_> = f.btp_rx.try_iter().collect();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].data, b"payload");
        assert!(f.sent().is_empty());
    }

    fn remote_area(a: u16) -> Area {
        Area {
            latitude: north(3000.0),
            longitude: EGO_LON as u32,
            a,
            b: a,
            angle: 0,
        }
    }

    fn area_packet(
        f: &Fixture,
        hst: HeaderSubType,
        so: LongPositionVector,
        sn: u16,
        area: Area,
        rhl: u8,
    ) -> Vec<u8> {
        let ht = match hst {
            HeaderSubType::GeoAnycast(_) => HeaderType::GeoAnycast,
            _ => HeaderType::GeoBroadcast,
        };
        let ext = GBCExtendedHeader {
            sn,
            reserved: 0,
            so_pv: so,
            latitude: area.latitude,
            longitude: area.longitude,
            a: area.a,
            b: area.b,
            angle: area.angle,
            reserved2: 0,
        };
        packet(
            f,
            rhl,
            common(ht, hst, tc(false), 10),
            &ext.encode(),
            b"payload",
        )
    }

    fn gbc() -> HeaderSubType {
        HeaderSubType::GeoBroadcast(GeoBroadcastHST::GeoBroadcastCircle)
    }

    fn gac() -> HeaderSubType {
        HeaderSubType::GeoAnycast(GeoAnycastHST::GeoAnycastCircle)
    }

    #[test]
    fn non_area_forwarding_outside_the_area() {
        // BO-04, BV-06, GRD/BV-02
        for hst in [gbc(), gac()] {
            let mut f = Fixture::new(Mib::new());
            let so = lpv(2, north(-100.0), EGO_LON as u32);
            let p = area_packet(&f, hst.clone(), so, 1, remote_area(100), 5);
            f.router.process_basic_header(&p);
            let sent = f.sent();
            assert_eq!(sent.len(), 1);
            assert_eq!(rhl_of(&sent[0]), 4);
            assert_eq!(f.btp_rx.try_iter().count(), 0);
            let p = area_packet(&f, hst, so, 2, remote_area(100), 1);
            f.router.process_basic_header(&p);
            assert!(f.sent().is_empty());
        }
    }

    #[test]
    fn non_area_discards_too_big_area_and_sender_inside() {
        for hst in [gbc(), gac()] {
            let mut f = Fixture::new(Mib::new());
            let so = lpv(2, north(-100.0), EGO_LON as u32);
            let p = area_packet(&f, hst.clone(), so, 1, remote_area(3000), 5); // > 10 km²
            f.router.process_basic_header(&p);
            assert!(f.sent().is_empty());
            let inside = lpv(3, north(3000.0), EGO_LON as u32);
            let p = area_packet(&f, hst, inside, 1, remote_area(100), 5);
            f.router.process_basic_header(&p);
            assert!(f.sent().is_empty());
        }
    }

    #[test]
    fn source_outside_the_area_line_forwards() {
        for (ht, hst) in [
            (HeaderType::GeoBroadcast, gbc()),
            (HeaderType::GeoAnycast, gac()),
        ] {
            let mut f = Fixture::new(Mib::new());
            let mut r = request(ht, hst);
            r.area = remote_area(100);
            f.router.gn_data_request(r);
            assert_eq!(f.sent().len(), 1);
            assert_eq!(f.router.next_deadline(), None); // no CBF outside the area
        }
    }

    #[test]
    fn simple_area_forwarding_rebroadcasts_with_decremented_rhl() {
        let mut mib = Mib::new();
        mib.itsGnAreaForwardingAlgorithm = AreaForwardingAlgorithm::Simple;
        let mut f = Fixture::new(mib);
        let so = lpv(2, north(100.0), EGO_LON as u32);
        let p = area_packet(&f, gbc(), so, 1, area(1500), 5);
        f.router.process_basic_header(&p);
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(rhl_of(&sent[0]), 4);
        assert_eq!(f.btp_rx.try_iter().count(), 1);
        let p = area_packet(&f, gbc(), so, 2, area(1500), 1);
        f.router.process_basic_header(&p);
        assert!(f.sent().is_empty());
        assert_eq!(f.btp_rx.try_iter().count(), 1);
    }

    #[test]
    fn gac_inside_the_area_is_delivered_not_forwarded() {
        let mut f = Fixture::new(Mib::new());
        let mut r = request(HeaderType::GeoAnycast, gac());
        r.area = area(100);
        f.router.gn_data_request(r);
        assert_eq!(f.sent().len(), 1);
        let p = area_packet(
            &f,
            gac(),
            lpv(2, north(50.0), EGO_LON as u32),
            1,
            area(1500),
            5,
        );
        f.router.process_basic_header(&p);
        assert!(f.sent().is_empty());
        assert_eq!(f.btp_rx.try_iter().count(), 1);
    }

    #[test]
    fn tsb_forwarding_and_delivery() {
        let mut f = Fixture::new(Mib::new());
        for (sn, rhl) in [(1u16, 5u8), (2, 1)] {
            let ext = TSBExtendedHeader {
                sn,
                reserved: 0,
                so_pv: lpv(2, north(100.0), EGO_LON as u32),
            };
            let ch = common(
                HeaderType::Tsb,
                HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop),
                tc(false),
                10,
            );
            let p = packet(&f, rhl, ch, &ext.encode(), b"payload");
            f.router.process_basic_header(&p);
        }
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(rhl_of(&sent[0]), 4);
        assert_eq!(f.btp_rx.try_iter().count(), 2);
    }

    #[test]
    fn shb_is_delivered() {
        let mut f = Fixture::new(Mib::new());
        let mut ext = lpv(2, north(100.0), EGO_LON as u32).encode().to_vec();
        ext.extend_from_slice(&[0; 4]);
        let ch = common(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            tc(false),
            1,
        );
        let p = packet(&f, 1, ch, &ext, b"payload");
        f.router.process_basic_header(&p);
        let delivered: Vec<_> = f.btp_rx.try_iter().collect();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].data, b"payload");
        assert!(f.sent().is_empty());
    }

    #[test]
    fn beacon_timer_with_jitter_and_reset_by_shb() {
        // (clauses 10.3.6.2, 10.3.10.2 step 7)
        let mut f = Fixture::new(Mib::new());
        f.router.beacon_deadline = Some(0);
        let timer = f.router.mib.itsGnBeaconServiceRetransmitTimer as u64;
        let jitter = f.router.mib.itsGnBeaconServiceMaxJitter as u64;
        f.tick(0);
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(header_type(&sent[0]), HeaderType::Beacon);
        let next = f.router.next_deadline().unwrap();
        assert!((timer..=timer + jitter).contains(&next));
        // An SHB at t = 1000 restarts the timer: no beacon at the old deadline.
        f.set_time(1000);
        f.router.gn_data_request(shb_request(false, None));
        let restarted = f.router.next_deadline().unwrap();
        assert!((1000 + timer..=1000 + timer + jitter).contains(&restarted));
        f.sent();
        f.tick(next.max(1001));
        if next < restarted {
            assert!(f.sent().is_empty());
        }
        f.tick(restarted);
        assert_eq!(header_type(&f.sent()[0]), HeaderType::Beacon);
    }

    #[test]
    fn wrong_version_and_rhl_above_mhl_are_discarded() {
        let mut f = Fixture::new(Mib::new());
        let ext = TSBExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: lpv(2, north(100.0), EGO_LON as u32),
        };
        let ch = || {
            common(
                HeaderType::Tsb,
                HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop),
                tc(false),
                3,
            )
        };
        let mut p = packet(&f, 2, ch(), &ext.encode(), b"payload");
        p[0] = (p[0] & 0x0F) | 0x20; // version 2
        f.router.process_basic_header(&p);
        let p = packet(&f, 5, ch(), &ext.encode(), b"payload"); // RHL 5 > MHL 3
        f.router.process_basic_header(&p);
        assert!(f.sent().is_empty());
        assert_eq!(f.btp_rx.try_iter().count(), 0);
    }

    /// (clauses 10.3.10.3, 10.3.6.2): a Beacon from an
    /// unknown station creates its LocTE (neighbour, position from the SO PV)
    /// and is not passed up.
    #[test]
    fn beacon_inserts_location_table_entry() {
        let mut f = Fixture::new(Mib::new());
        assert!(f.router.location_table.get_entry_ref(&addr(2)).is_none());
        let beacon = beacon_from(&f, 2, north(100.0));
        f.router.process_basic_header(&beacon);
        let entry = f.router.location_table.get_entry_ref(&addr(2)).unwrap();
        assert!(entry.is_neighbour);
        assert_eq!(entry.position_vector.latitude, north(100.0));
        assert_eq!(entry.position_vector.longitude, EGO_LON as u32);
        assert_eq!(f.btp_rx.try_iter().count(), 0);
        assert!(f.sent().is_empty());
    }

    /// (clauses 10.2.1.2, 10.3.6.2): with auto address
    /// configuration the IUT uses itsGnLocalGnAddr from start-up, e.g. in the
    /// SO PV of its first Beacon.
    #[test]
    fn initial_gn_address_with_auto_configuration() {
        let mut mib = Mib::new();
        mib.itsGnLocalGnAddrConfMethod = crate::geonet::mib::LocalGnAddrConfMethod::Auto;
        mib.itsGnLocalGnAddr = addr(42);
        let mut f = Fixture::new(mib);
        assert_eq!(f.router.ego_position_vector.gn_addr, addr(42));
        f.router.beacon_deadline = Some(0);
        f.tick(0);
        let sent = f.sent();
        assert_eq!(header_type(&sent[0]), HeaderType::Beacon);
        let so = LongPositionVector::decode(sent[0][12..36].try_into().unwrap());
        assert_eq!(so.gn_addr, addr(42));
    }

    /// (clause 10.3.9.2, E.2): a duplicate GUC does
    /// not trigger greedy forwarding again.
    #[test]
    fn guc_duplicate_not_forwarded_again() {
        let mut f = Fixture::new(Mib::new());
        f.add_neighbour(3, north(500.0)); // closer to the destination
        let packet = guc_packet(
            &f,
            lpv(2, north(-100.0), EGO_LON as u32),
            1,
            short_pv(9, north(1000.0)),
            false,
        );
        f.router.process_basic_header(&packet);
        f.router.process_basic_header(&packet);
        assert_eq!(f.sent().len(), 1);
        assert_eq!(f.btp_rx.try_iter().count(), 0);
    }

    /// (clause 10.3.9.3): a duplicate TSB is
    /// neither re-broadcast nor passed up again.
    #[test]
    fn tsb_duplicate_neither_forwarded_nor_delivered() {
        let mut f = Fixture::new(Mib::new());
        let ext = TSBExtendedHeader {
            sn: 1,
            reserved: 0,
            so_pv: lpv(2, north(100.0), EGO_LON as u32),
        };
        let ch = common(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop),
            tc(false),
            10,
        );
        let p = packet(&f, 5, ch, &ext.encode(), b"payload");
        f.router.process_basic_header(&p);
        f.router.process_basic_header(&p);
        assert_eq!(f.sent().len(), 1);
        assert_eq!(f.btp_rx.try_iter().count(), 1);
    }

    /// (clause 10.3.12.3, E.2): a duplicate
    /// GAC received outside its area does not trigger line forwarding again.
    #[test]
    fn gac_duplicate_outside_area_not_forwarded_again() {
        let mut f = Fixture::new(Mib::new());
        let so = lpv(2, north(-100.0), EGO_LON as u32);
        let p = area_packet(&f, gac(), so, 1, remote_area(100), 5);
        f.router.process_basic_header(&p);
        f.router.process_basic_header(&p);
        assert_eq!(f.sent().len(), 1);
        assert_eq!(f.btp_rx.try_iter().count(), 0);
    }

    // ── Fields of the packets sent by the IUT (TS 102 871-2 FDV) ─────────
    // Mirrors TestPacketFieldValidity.

    #[test]
    fn sent_gbc_fields() {
        let mut f = Fixture::new(Mib::new());
        let beacon = beacon_from(&f, 2, north(100.0));
        f.router.process_basic_header(&beacon);
        let mut r = gbc_request();
        r.area = area(100);
        r.data = b"gbc".to_vec();
        f.router.gn_data_request(r);
        let packet = &f.sent()[0];
        let basic = BasicHeader::decode(packet[0..4].try_into().unwrap());
        assert_eq!(basic.version, f.router.mib.itsGnProtocolVersion);
        assert_eq!(basic.rhl, f.router.mib.itsGnDefaultHopLimit);
        let common = CommonHeader::decode(packet[4..12].try_into().unwrap());
        assert_eq!(common.flags >> 7, f.router.mib.itsGnIsMobile.encode());
        assert_eq!(common.mhl, f.router.mib.itsGnDefaultHopLimit);
        assert_eq!(common.ht, HeaderType::GeoBroadcast);
        let ext = GBCExtendedHeader::decode(packet[12..56].try_into().unwrap());
        assert_eq!(ext.so_pv, f.router.ego_position_vector);
        assert_eq!(ext.sn, 0);
    }

    #[test]
    fn sent_beacon_fields() {
        let mut mib = Mib::new();
        mib.itsGnLocalGnAddr = GNAddress::new(
            M::GnUnicast,
            ST::PassengerCar,
            MID::new([2, 0, 0, 0, 0, 42]),
        );
        let mut f = Fixture::new(mib);
        f.router.gn_data_request_beacon();
        let packet = &f.sent()[0];
        let common = CommonHeader::decode(packet[4..12].try_into().unwrap());
        assert_eq!(common.nh, CommonNH::Any);
        assert_eq!(common.ht, HeaderType::Beacon);
        assert_eq!(common.hst.encode(), 0);
        assert_eq!(common.pl, 0);
        assert_eq!(common.flags >> 7, f.router.mib.itsGnIsMobile.encode());
        let so = LongPositionVector::decode(packet[12..36].try_into().unwrap());
        assert_eq!(so, f.router.ego_position_vector);
        assert!(matches!(so.gn_addr.st, ST::PassengerCar));
        assert_eq!(so.gn_addr, f.router.mib.itsGnLocalGnAddr);
    }

    #[test]
    fn sent_shb_fields() {
        let mut f = Fixture::new(Mib::new());
        let beacon = beacon_from(&f, 2, north(100.0));
        f.router.process_basic_header(&beacon);
        let mut r = shb_request(false, None);
        r.data = b"shb".to_vec();
        f.router.gn_data_request(r);
        let packet = &f.sent()[0];
        let common = CommonHeader::decode(packet[4..12].try_into().unwrap());
        assert_eq!(common.ht, HeaderType::Tsb);
        assert_eq!(
            common.hst,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop)
        );
        assert_eq!(common.mhl, 1);
        assert_eq!(common.pl, 3);
        let so = LongPositionVector::decode(packet[12..36].try_into().unwrap());
        assert_eq!(so, f.router.ego_position_vector);
        assert_eq!(&packet[40..], b"shb");
    }

    /// DE PV from the LocTE of the destination.
    #[test]
    fn sent_guc_fields() {
        let mut f = Fixture::new(Mib::new());
        let beacon = beacon_from(&f, 2, north(100.0));
        f.router.process_basic_header(&beacon);
        f.router.gn_data_request(guc_request(addr(2)));
        let packet = &f.sent()[0];
        let common = CommonHeader::decode(packet[4..12].try_into().unwrap());
        assert_eq!(common.ht, HeaderType::GeoUnicast);
        assert_eq!(common.hst.encode(), 0);
        let ext = GUCExtendedHeader::decode(packet[12..60].try_into().unwrap());
        assert_eq!(ext.de_pv.gn_address, addr(2));
        assert_eq!(ext.de_pv.latitude, north(100.0));
        assert_eq!(ext.de_pv.longitude, EGO_LON as u32);
        assert_eq!(ext.so_pv, f.router.ego_position_vector);
    }

    /// latest position and the sensor
    /// acquisition time (ms) in the SO PV.
    #[test]
    fn sent_lpv_from_sensor_data() {
        let mut f = Fixture::new(Mib::new());
        let acquired = Tst::set_in_normal_timestamp_milliseconds(1_794_825_288_283);
        let mut pv = f.router.ego_position_vector;
        pv.latitude = 415520000;
        pv.longitude = 21340000;
        pv.tst = acquired;
        f.router.refresh_ego_position_vector(pv);
        f.router.gn_data_request_beacon();
        let so = LongPositionVector::decode(f.sent()[0][12..36].try_into().unwrap());
        assert_eq!((so.latitude, so.longitude), (415520000, 21340000));
        assert_eq!(so.tst, acquired);
    }

    // ── DCC_NET over ITS-G5 (TS 103 836-4-2 clause 7.2) ──────────────────
    // Mirrors TestDccNetRouter.

    fn its_g5_fixture(dcc_net: Option<crate::geonet::dcc_net::DccNet>) -> Fixture {
        let mut mib = Mib::new();
        mib.itsGnIfType = crate::geonet::mib::GnIfType::ItsG5;
        let mut f = Fixture::new(mib);
        if let Some(d) = dcc_net {
            f.router.set_dcc_net(d);
        }
        f
    }

    fn shb_with_mco(f: &Fixture, n: u8, mco: [u8; 4], tst: Tst) -> Vec<u8> {
        let mut so = lpv(n, north(10.0), EGO_LON as u32);
        so.tst = tst;
        let mut ext = so.encode().to_vec();
        ext.extend_from_slice(&mco);
        let ch = common(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            tc(false),
            1,
        );
        packet(f, 1, ch, &ext, b"payload")
    }

    fn sent_mco(f: &mut Fixture) -> Vec<u8> {
        f.router.gn_data_request(shb_request(false, None));
        f.sent().last().unwrap()[36..40].to_vec()
    }

    /// CBR_L_0_Hop, CBR_L_1_Hop and Transmit Power.
    #[test]
    fn dcc_net_shb_carries_dcc_mco() {
        use crate::geonet::dcc_net::{encode_dcc_mco, DccNet};
        use crate::management::cbr::SharedCbr;
        let local = SharedCbr::new();
        let dcc = DccNet::new(Some(Box::new(local.clone())), 20.0).with_rng(Box::new(|| 0.0));
        let mut f = its_g5_fixture(Some(dcc));
        local.report(0.5);
        let shb = shb_with_mco(&f, 2, encode_dcc_mco(0.8, 0.1, 23.0), now_tst());
        f.router.process_basic_header(&shb);
        f.tick(0); // CBR_L_0_Hop = 0.5, CBR_L_1_Hop = 0.8
        f.set_time(50);
        assert_eq!(sent_mco(&mut f), vec![127, 204, 20, 0]);
    }

    /// the LocTEX-G5 holds the received DCC-MCO and
    /// the next SHB disseminates it as CBR_L_1_Hop.
    #[test]
    fn dcc_net_loctex_updated_from_received_shb() {
        use crate::geonet::dcc_net::{encode_dcc_mco, DccNet};
        let dcc = DccNet::new(None, 20.0).with_rng(Box::new(|| 0.0));
        let mut f = its_g5_fixture(Some(dcc));
        let tst = now_tst();
        let mco = encode_dcc_mco(0.8, 0.3, 23.0);
        let shb = shb_with_mco(&f, 2, mco, tst);
        f.router.process_basic_header(&shb);
        let entry = f
            .router
            .dcc_net
            .as_ref()
            .unwrap()
            .loctex_of(&addr(2))
            .unwrap()
            .clone();
        assert_eq!(entry.tx_power_dbm, 23);
        assert_eq!(entry.tst_so_pv, u32::from_be_bytes(tst.encode()));
        assert_eq!(entry.tst_g5_ms, 0);
        assert_eq!(
            (
                (entry.cbr_r_0_hop * 255.0).round() as u8,
                (entry.cbr_r_1_hop * 255.0).round() as u8
            ),
            (204, 76)
        );
        assert!(f.router.location_table.get_entry_ref(&addr(2)).is_some());
        f.tick(0);
        assert_eq!(sent_mco(&mut f)[1], mco[0]);
        let shb = shb_with_mco(&f, 3, [0; 4], now_tst()); // no DCC-MCO
        f.router.process_basic_header(&shb);
        assert!(f
            .router
            .dcc_net
            .as_ref()
            .unwrap()
            .loctex_of(&addr(3))
            .is_none());
    }

    /// DCC-MCO received, but no DCC_NET: zeros sent.
    #[test]
    fn dcc_net_absent_field_is_zero() {
        use crate::geonet::dcc_net::encode_dcc_mco;
        let mut f = its_g5_fixture(None);
        let shb = shb_with_mco(&f, 2, encode_dcc_mco(0.8, 0.3, 23.0), now_tst());
        f.router.process_basic_header(&shb);
        assert!(f.router.location_table.get_entry_ref(&addr(2)).is_some());
        assert_eq!(sent_mco(&mut f), vec![0, 0, 0, 0]);
    }

    #[test]
    fn dcc_net_next_deadline_includes_the_cbr_g_trigger() {
        use crate::geonet::dcc_net::DccNet;
        let f = its_g5_fixture(Some(DccNet::new(None, 0.0).with_rng(Box::new(|| 0.3))));
        assert_eq!(f.router.next_deadline(), Some(30));
    }

    // ── Media-dependent GN address (TS 103 836-4-2 / -4-3) ───────────────
    // Mirrors TestMediaDependentAddress.

    fn beacon_mid(f: &mut Fixture) -> [u8; 6] {
        f.router.gn_data_request_beacon();
        LongPositionVector::decode(f.sent()[0][12..36].try_into().unwrap())
            .gn_addr
            .mid
            .as_bytes()
    }

    /// ITS-G5, MID = MAC address of the interface.
    #[test]
    fn media_dependent_its_g5_mid_is_the_mac_address() {
        use crate::geonet::mib::GnIfType;
        use crate::link_layer::raw_link_layer::RawLinkLayer;
        let mac = [0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
        let mut mib = Mib::new();
        mib.itsGnIfType = GnIfType::ItsG5;
        mib.itsGnLocalGnAddr = GNAddress::new(M::GnUnicast, ST::Unknown, MID::from_its_g5_mac(mac));
        let mut f = Fixture::new(mib);
        let raw = |mac| RawLinkLayer::new(mpsc::channel().0, mpsc::channel().1, "lo", mac);
        let link_layer = raw(mac);
        assert_eq!(link_layer.media_dependent_mid().as_bytes(), mac);
        assert!(f
            .router
            .media_dependent_address_ok(Some(link_layer.media_dependent_mid())));
        assert_eq!(beacon_mid(&mut f), mac);
        let other = raw([0x02, 0, 0, 0, 0, 1]);
        assert!(!f
            .router
            .media_dependent_address_ok(Some(other.media_dependent_mid())));
    }

    /// LTE-V2X, Layer 2 ID in octets 2-4, zero in
    /// octets 5-7.
    #[test]
    fn media_dependent_lte_v2x_mid_is_the_layer_2_id() {
        use crate::geonet::mib::GnIfType;
        let mid = MID::from_lte_v2x_l2_id(0xA1B2C3).unwrap();
        assert_eq!(mid.as_bytes(), [0xa1, 0xb2, 0xc3, 0, 0, 0]);
        let mut mib = Mib::new();
        mib.itsGnIfType = GnIfType::LteV2x;
        mib.itsGnLocalGnAddr = GNAddress::new(M::GnUnicast, ST::Unknown, mid);
        let mut f = Fixture::new(mib);
        assert!(f.router.media_dependent_address_ok(Some(mid)));
        assert!(f.router.media_dependent_address_ok(None)); // L2 ID unknown: zeros checked
        assert_eq!(beacon_mid(&mut f), [0xa1, 0xb2, 0xc3, 0, 0, 0]);
        assert!(!f
            .router
            .media_dependent_address_ok(MID::from_lte_v2x_l2_id(1)));
        mib.itsGnLocalGnAddr = GNAddress::new(
            M::GnUnicast,
            ST::Unknown,
            MID::new([0xa1, 0xb2, 0xc3, 0, 0, 1]),
        );
        assert!(!Fixture::new(mib).router.media_dependent_address_ok(None));
        assert!(MID::from_lte_v2x_l2_id(1 << 24).is_none());
    }

    #[test]
    fn media_dependent_unspecified_interface_is_not_checked() {
        let f = Fixture::new(Mib::new());
        assert!(f
            .router
            .media_dependent_address_ok(Some(MID::new([2, 0, 0, 0, 0, 1]))));
    }

    // ── UC forwarding packet buffer of a forwarder (clause 8.5.2) ────────

    fn buffer_guc(f: &mut Fixture, sn: u16, lifetime: Option<f64>, data: &[u8]) {
        let basic = BasicHeader::initialize_with_mib_request_and_rhl(&f.router.mib, lifetime, 5);
        let mut ch = common(
            HeaderType::GeoUnicast,
            HeaderSubType::Unspecified(UnspecifiedHST::Unspecified),
            tc(true),
            10,
        );
        ch.pl = data.len() as u16;
        let ext = GUCExtendedHeader {
            sn,
            reserved: 0,
            so_pv: lpv(2, north(-100.0), EGO_LON as u32),
            de_pv: short_pv(9, north(1000.0)),
        };
        let mut p = basic.encode().to_vec();
        p.extend_from_slice(&ch.encode());
        p.extend_from_slice(&ext.encode());
        p.extend_from_slice(data);
        f.router.process_basic_header(&p);
    }

    /// no next hop, SCF: buffered; a Beacon from a
    /// next hop after expiry of LT1 does not release it.
    #[test]
    fn uc_buffer_expired_packet_not_forwarded() {
        let mut f = Fixture::new(Mib::new());
        f.add_neighbour(3, north(-200.0)); // behind ego: local optimum
        buffer_guc(&mut f, 1, Some(1.0), b"x");
        assert!(f.sent().is_empty());
        f.set_time(1500);
        let beacon = beacon_from(&f, 4, north(500.0));
        f.router.process_basic_header(&beacon);
        assert!(f.sent().is_empty());
    }

    /// over itsGnUcForwardingPacketBufferSize the
    /// oldest packets are dropped; the newest are sent when a next hop appears.
    #[test]
    fn uc_buffer_capacity_head_drop() {
        let mut mib = Mib::new();
        mib.itsGnUcForwardingPacketBufferSize = 1; // 1 KiB
        let mut f = Fixture::new(mib);
        f.add_neighbour(3, north(-200.0));
        for sn in 1..5 {
            buffer_guc(&mut f, sn, None, &[0; 400]);
        }
        let beacon = beacon_from(&f, 4, north(500.0));
        f.router.process_basic_header(&beacon);
        let numbers: Vec<u16> = f.sent().iter().map(|p| sequence_number(p)).collect();
        assert_eq!(numbers, vec![3, 4]);
    }

    // ── Duplicate GBC / GAC inside the destination area ─────────────────

    fn inside_area_packet(f: &Fixture, hst: HeaderSubType, rhl: u8) -> Vec<u8> {
        let so = lpv(2, north(300.0), EGO_LON as u32);
        area_packet(f, hst, so, 1, area(1500), rhl)
    }

    #[test]
    fn duplicate_inside_area_not_passed_up() {
        for hst in [gbc(), gac()] {
            let mut f = Fixture::new(Mib::new());
            f.add_neighbour(2, north(300.0));
            f.add_neighbour(4, north(200.0));
            let p = inside_area_packet(&f, hst.clone(), 5);
            f.router.process_incoming(&p, Some(addr(2).mid.as_bytes()));
            let p = inside_area_packet(&f, hst, 4);
            f.router.process_incoming(&p, Some(addr(4).mid.as_bytes()));
            assert_eq!(f.btp_rx.try_iter().count(), 1);
        }
    }

    #[test]
    fn simple_forwarding_duplicate_not_rebroadcast() {
        let mut mib = Mib::new();
        mib.itsGnAreaForwardingAlgorithm = AreaForwardingAlgorithm::Simple;
        let mut f = Fixture::new(mib);
        f.add_neighbour(2, north(300.0));
        f.add_neighbour(4, north(200.0));
        let p = inside_area_packet(&f, gbc(), 5);
        f.router.process_incoming(&p, Some(addr(2).mid.as_bytes()));
        assert_eq!(f.sent().len(), 1);
        let p = inside_area_packet(&f, gbc(), 4);
        f.router.process_incoming(&p, Some(addr(4).mid.as_bytes()));
        assert!(f.sent().is_empty());
    }

    #[test]
    fn gac_source_header() {
        let mut f = Fixture::new(Mib::new());
        let mut r = request(HeaderType::GeoAnycast, gac());
        r.area = area(100);
        f.router.gn_data_request(r);
        let sent = f.sent();
        assert_eq!(header_type(&sent[0]), HeaderType::GeoAnycast);
        let ext = GBCExtendedHeader::decode(sent[0][12..56].try_into().unwrap());
        assert_eq!(ext.so_pv.gn_addr, f.router.mib.itsGnLocalGnAddr);
        assert_eq!(ext.so_pv.latitude, EGO_LAT as u32);
    }

    // ── Security integration ─────────────────────────────────────────────

    /// IEEE 1609.2 clause 5.2.3.2.2: the message is not sent when no AT may sign.
    #[test]
    fn no_valid_at_means_no_packet() {
        use crate::security::certificate_library::CertificateLibrary;
        use crate::security::ecdsa_backend::EcdsaBackend;
        let mut mib = Mib::new();
        mib.itsGnSecurity = GnSecurity::Enabled;
        let backend = EcdsaBackend::new();
        let library = CertificateLibrary::new(&backend, vec![], vec![], vec![]);
        let (ll_tx, ll_rx) = mpsc::channel();
        let (btp_tx, _btp_rx) = mpsc::channel();
        let mut router = Router::new(
            mib,
            ll_tx,
            btp_tx,
            Some(SignService::new(backend, library)),
            None,
            None,
        );
        let confirm = router.gn_data_request(shb_request(false, None));
        assert_eq!(confirm.result_code, ResultCode::Unspecified);
        assert!(ll_rx.try_recv().is_err());
    }

    /// Table 38: the security results reach the GN-DATA.indication.
    #[test]
    fn security_results_in_indication() {
        let mut f = Fixture::new(Mib::new());
        let mut plain = common(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::SingleHop),
            tc(false),
            1,
        )
        .encode()
        .to_vec();
        plain.extend_from_slice(&lpv(2, north(100.0), EGO_LON as u32).encode());
        plain.extend_from_slice(&[0; 4]);
        plain.extend_from_slice(b"payload");
        let security = SecurityIndication {
            report: crate::security::sn_sap::ReportVerify::Success,
            certificate_id: vec![1; 8],
            its_aid: 36,
            permissions: vec![2, 2, 0],
        };
        let basic = f.basic(1).set_nh(BasicNH::SecuredPacket);
        f.router.process_common_header_secured(
            &plain,
            &basic,
            Some(b"SECURED"),
            None,
            Some(security.clone()),
        );
        let indication = f.btp_rx.try_recv().unwrap();
        assert_eq!(indication.security, Some(security));
    }

    // ── Secured forwarding (clauses 8.6.3 NOTE 1, 10.3.8.3 step 8) ───────

    #[test]
    fn forwarded_tsb_keeps_the_secured_packet() {
        let mut f = Fixture::new(Mib::new());
        let mut plain = common(
            HeaderType::Tsb,
            HeaderSubType::TopoBroadcast(TopoBroadcastHST::MultiHop),
            tc(false),
            10,
        )
        .encode()
        .to_vec();
        plain.extend_from_slice(
            &TSBExtendedHeader {
                sn: 3,
                reserved: 0,
                so_pv: lpv(2, north(100.0), EGO_LON as u32),
            }
            .encode(),
        );
        plain.extend_from_slice(b"payload");
        let secured = b"\x03\x81\x00SIGNED-DATA".to_vec();
        let basic = f.basic(5).set_nh(BasicNH::SecuredPacket);
        f.router
            .process_common_header(&plain, &basic, Some(&secured), None);
        let packet = f.sent().remove(0);
        assert_eq!(&packet[4..], &secured[..]);
        let fwd_basic = BasicHeader::decode(packet[0..4].try_into().unwrap());
        assert!(matches!(fwd_basic.nh, BasicNH::SecuredPacket));
        assert_eq!(fwd_basic.rhl, 4);
    }

    // ── Geometric function with a rotated area ───────────────────────────

    #[test]
    fn rectangle_rotation() {
        let f = Fixture::new(Mib::new());
        let hst = GeoBroadcastHST::GeoBroadcastRectangle;
        let ego_lat = EGO_LAT as u32;
        let ego_lon = EGO_LON as u32;
        for (angle, inside, outside) in [
            (0u16, (north(50.0), ego_lon), (ego_lat, east(50.0))),
            (90u16, (ego_lat, east(50.0)), (north(50.0), ego_lon)),
        ] {
            let area = Area {
                latitude: ego_lat,
                longitude: ego_lon,
                a: 100,
                b: 10,
                angle,
            };
            assert!(
                f.router
                    .gn_geometric_function_f(&hst, &area, &inside.0, &inside.1)
                    > 0.0
            );
            assert!(
                f.router
                    .gn_geometric_function_f(&hst, &area, &outside.0, &outside.1)
                    < 0.0
            );
        }
    }
}

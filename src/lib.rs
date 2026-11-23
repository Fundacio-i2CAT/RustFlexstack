// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! # rustflexstack
//!
//! ETSI C-ITS protocol stack implemented in Rust: GeoNetworking (TS 103 836-4-1),
//! BTP (EN 302 636-5-1), security (TS 103 097, IEEE 1609.2) and the PKI client
//! (TS 102 941), CA / DEN / VRU basic services, LDM and DCC.
//!
//! ## Architecture
//!
//! The stack is built around an actor model where each layer runs in its own
//! background thread and communicates via [`std::sync::mpsc`] channels.  The
//! caller interacts with the routers through lightweight handle types that wrap
//! a [`std::sync::mpsc::Sender`].
//!
//! ## Typical usage
//!
//! An unsecured station on a raw Ethernet interface (ITS-G5 over `eth0`):
//! GeoNetworking and BTP routers wired to the link layer. With security, pass
//! a `SignService`, an `EcdsaBackend` and a `CertificateLibrary` to
//! [`geonet::router::Router::spawn`]; the facilities (CA, DEN, VRU services)
//! take the BTP handle. `examples/v2x_cli.rs` is a complete station.
//!
//! ```no_run
//! use rustflexstack::btp::router::Router as BTPRouter;
//! use rustflexstack::geonet::gn_address::{GNAddress, M, MID, ST};
//! use rustflexstack::geonet::mib::{GnIfType, Mib};
//! use rustflexstack::geonet::router::Router as GNRouter;
//! use rustflexstack::link_layer::raw_link_layer::RawLinkLayer;
//! use std::sync::mpsc;
//! use std::thread;
//!
//! // Over ITS-G5 the GN address MID is the interface MAC address.
//! let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
//! let mut mib = Mib::new();
//! mib.itsGnLocalGnAddr = GNAddress::new(M::GnMulticast, ST::PassengerCar, MID::new(mac));
//! mib.itsGnIfType = GnIfType::ItsG5;
//!
//! // Routers (no sign / verify services: unsecured).
//! let (gn_handle, gn_to_ll_rx, gn_to_btp_rx) = GNRouter::spawn(mib, None, None, None);
//! let (btp_handle, btp_to_gn_rx) = BTPRouter::spawn(mib);
//!
//! // Raw Ethernet link layer (EtherType 0x8947).
//! let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel::<Vec<u8>>();
//! let link_layer = RawLinkLayer::new(ll_to_gn_tx, gn_to_ll_rx, "eth0", mac);
//! link_layer.start();
//!
//! // Link layer -> GN, GN -> BTP, BTP -> GN.
//! let gn = gn_handle.clone();
//! thread::spawn(move || {
//!     while let Ok(packet) = ll_to_gn_rx.recv() {
//!         gn.send_incoming_packet(packet);
//!     }
//! });
//! let btp = btp_handle.clone();
//! thread::spawn(move || {
//!     while let Ok(indication) = gn_to_btp_rx.recv() {
//!         btp.send_gn_data_indication(indication);
//!     }
//! });
//! let gn = gn_handle.clone();
//! thread::spawn(move || {
//!     while let Ok(request) = btp_to_gn_rx.recv() {
//!         gn.send_gn_data_request(request);
//!     }
//! });
//! ```

pub mod btp;
pub mod facilities;
pub mod geonet;
pub mod link_layer;
pub mod management;
pub mod security;

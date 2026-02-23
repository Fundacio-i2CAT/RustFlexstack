// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! # rustflexstack
//!
//! ETSI C-ITS GeoNetworking (EN 302 636-4-1) + BTP (EN 302 636-5-1) protocol
//! stack implemented in Rust.
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
//! ```no_run
//! use rustflexstack::link_layer::raw_link_layer::RawLinkLayer;
//! use rustflexstack::geonet::router::Router;
//! use rustflexstack::geonet::mib::MIB;
//! use rustflexstack::btp::router::BTPRouter;
//! use rustflexstack::btp::service_access_point::BTPDataRequest;
//! use rustflexstack::geonet::service_access_point::{
//!     GNDataRequest, HeaderType, TopoBroadcastHST, TrafficClass,
//! };
//! use std::sync::mpsc;
//!
//! let (ll_to_gn_tx, ll_to_gn_rx) = mpsc::channel();
//! let (gn_to_ll_tx, gn_to_ll_rx) = mpsc::channel();
//! let (gn_to_btp_tx, gn_to_btp_rx) = mpsc::channel();
//! let (btp_to_gn_tx, btp_to_gn_rx) = mpsc::channel();
//!
//! let mib = MIB::new();
//! let ll = RawLinkLayer::new(ll_to_gn_tx, gn_to_ll_rx, "eth0").unwrap();
//! let gn_handle = Router::spawn(
//!     mib.clone(), ll.sender(),
//!     gn_to_ll_tx, ll_to_gn_rx,
//!     gn_to_btp_tx, btp_to_gn_rx,
//! );
//! let btp_handle = BTPRouter::spawn(mib.clone(), gn_handle.clone(), gn_to_btp_rx);
//! ```

pub mod btp;
pub mod facilities;
pub mod geonet;
pub mod link_layer;

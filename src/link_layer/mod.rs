// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Link Layer abstraction for GeoNetworking.
//!
//! The [`LinkLayer`] trait defines the interface that the GeoNetworking router
//! uses to send and receive raw packets.  Any concrete implementation
//! (Ethernet, C-V2X, loopback, …) can implement this trait.

pub mod packet_consts;
pub mod raw_link_layer;

#[cfg(feature = "cv2x")]
pub mod cv2x_ffi;
#[cfg(feature = "cv2x")]
pub mod cv2x_link_layer;

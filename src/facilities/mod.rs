// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Facilities layer — ITS applications built on top of GeoNetworking and BTP.
//!
//! # Sub-modules
//! - [`ca_basic_service`] — Cooperative Awareness Basic Service (CAM, EN 302 637-2)
//! - [`decentralized_environmental_notification_service`] — DEN Service (DENM, EN 302 637-3)
//! - [`local_dynamic_map`] — Local Dynamic Map (LDM, TS 103 301)
//! - [`location_service`] — GPS fix publisher (mirrors Python `LocationService`)
//! - [`vru_awareness_service`] — VRU Awareness Service (VAM, TS 103 300-3)

pub mod ca_basic_service;
pub mod decentralized_environmental_notification_service;
pub mod local_dynamic_map;
pub mod location_service;
pub mod vru_awareness_service;

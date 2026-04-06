// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! LDM maintenance — background garbage-collection and subscription firing.
//!
//! `LdmMaintenance::spawn` starts a 1 Hz thread that:
//! 1. Removes expired records (past their `time_validity_s` window).
//! 2. Removes records outside the local station's maintenance area
//!    (using correct Haversine distance — fixes the Python Euclidean bug).
//! 3. Calls `LdmService::fire_subscriptions` to deliver periodic push
//!    notifications to all active subscribers.
//!
//! The thread holds only `Arc` handles; it exits cleanly when all owners of
//! `LdmService` have been dropped (the `Arc` reference count reaches zero
//! and `fire_subscriptions` becomes a no-op on the last cycle before the
//! `Arc` upgrade returns `None`).

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::facilities::local_dynamic_map::ldm_service::LdmService;

/// LDM maintenance controller.
pub struct LdmMaintenance;

impl LdmMaintenance {
    /// Spawn the maintenance thread.
    ///
    /// # Arguments
    /// * `service`        — shared reference to the `LdmService`.
    /// * `area_lat_etsi`  — latitude of the LDM maintenance area centre (ETSI × 1e7).
    /// * `area_lon_etsi`  — longitude of the LDM maintenance area centre (ETSI × 1e7).
    /// * `area_radius_m`  — radius of the maintenance area in metres.
    ///
    /// Records outside the area or past their validity window are deleted on
    /// each maintenance cycle.  A zero or negative `area_radius_m` disables
    /// the spatial GC (only expiry-based GC runs).
    pub fn spawn(
        service: Arc<LdmService>,
        area_lat_etsi: i32,
        area_lon_etsi: i32,
        area_radius_m: f64,
    ) {
        // Downgrade to a Weak pointer so the maintenance thread does not
        // prevent the LDM from being dropped when all other owners are gone.
        let weak = Arc::downgrade(&service);

        thread::Builder::new()
            .name("ldm-maintenance".into())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));

                    // If all strong references are gone, exit cleanly.
                    let Some(svc) = weak.upgrade() else { break };

                    {
                        let mut store = svc.store.write().unwrap();

                        // 1. Expiry-based garbage collection.
                        let expired = store.remove_expired();
                        if expired > 0 {
                            eprintln!("[LDM Maintenance] Removed {expired} expired record(s)");
                        }

                        // 2. Spatial garbage collection (if area is defined).
                        if area_radius_m > 0.0 {
                            let out_of_area = store.remove_out_of_area(
                                area_lat_etsi,
                                area_lon_etsi,
                                area_radius_m,
                            );
                            if out_of_area > 0 {
                                eprintln!(
                                    "[LDM Maintenance] Removed {out_of_area} out-of-area record(s)"
                                );
                            }
                        }
                    } // write lock released here

                    // 3. Fire subscriptions (takes store read-lock internally).
                    svc.fire_subscriptions();
                }
                eprintln!("[LDM Maintenance] Thread exiting");
            })
            .expect("failed to spawn ldm-maintenance thread");
    }
}

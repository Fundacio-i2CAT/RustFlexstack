// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DCC entity: couples a [`CbrProvider`] (access layer) with a DCC algorithm and
//! the facilities layer.
//!
//! On each evaluation (every 200 ms, aligned to UTC-modulo-200 ms boundaries per
//! ETSI TS 102 687 V1.2.1 clause 5.2) the entity:
//! 1. polls the CBR provider;
//! 2. runs the reactive (clause 5.3) or adaptive (clause 5.4) algorithm;
//! 3. converts the result into `T_GenCam_DCC`, the minimum CAM generation
//!    interval provided to the CA basic service (ETSI TS 103 900 §6.1.3),
//!    bounded to `[T_GenCamMin, T_GenCamMax] = [100, 1000]` ms;
//! 4. notifies every registered listener with the new `T_GenCam_DCC`.
//!
//! Conversion:
//! - **Reactive**: `T_GenCam_DCC = T_off` of the current state (Annex A tables).
//! - **Adaptive**: `T_GenCam_DCC = T_on / delta` (gate interval of equation B.1).
//!
//! Mirrors `flexstack/management/dcc_entity.py`.
//!
//! # Example
//! ```no_run
//! use rustflexstack::management::{DccEntity, DccMode, SharedCbr};
//!
//! let cbr = SharedCbr::new();
//! let mut dcc = DccEntity::new(DccMode::reactive(), Box::new(cbr.clone()));
//! // let ctm = ca_service.cam_transmission_management.clone();
//! // dcc.add_t_gen_cam_dcc_listener(move |ms| ctm.set_t_gen_cam_dcc(ms));
//! let handle = dcc.spawn();
//! cbr.report(0.45); // from the access layer
//! handle.stop();
//! ```

use super::cbr::CbrProvider;
use super::dcc_adaptive::{DccAdaptive, DccAdaptiveParameters};
use super::dcc_reactive::{DccReactive, DccState};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// DCC evaluation period in milliseconds (clause 5.2).
pub const DCC_EVALUATION_PERIOD_MS: u64 = 200;
/// Lower bound of `T_GenCam_DCC` (`T_GenCamMin`, ETSI TS 103 900 §6.1.3) [ms].
pub const T_GEN_CAM_DCC_MIN_MS: u64 = 100;
/// Upper bound of `T_GenCam_DCC` (`T_GenCamMax`, ETSI TS 103 900 §6.1.3) [ms].
pub const T_GEN_CAM_DCC_MAX_MS: u64 = 1_000;

/// DCC algorithm selection.
#[derive(Debug, Clone, PartialEq)]
pub enum DccMode {
    /// Reactive DCC (clause 5.3, Annex A).
    Reactive {
        /// Maximum packet airtime in µs; `<= 500` selects Table A.2, otherwise Table A.1.
        t_on_max_us: u32,
    },
    /// Adaptive DCC / LIMERIC (clause 5.4).
    Adaptive {
        /// LIMERIC parameters (Table 3 defaults).
        parameters: DccAdaptiveParameters,
        /// Nominal CAM airtime `T_on` in ms used for `T_on / delta`.
        t_on_ms: f64,
    },
}

impl DccMode {
    /// Reactive DCC with Table A.1 (`T_on` ≤ 1 ms).
    pub fn reactive() -> Self {
        DccMode::Reactive { t_on_max_us: 1000 }
    }

    /// Adaptive DCC with Table 3 default parameters and `T_on` = 1 ms.
    pub fn adaptive() -> Self {
        DccMode::Adaptive {
            parameters: DccAdaptiveParameters::default(),
            t_on_ms: 1.0,
        }
    }
}

/// Result of one DCC entity evaluation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DccEntityOutput {
    /// CBR used for this evaluation.
    pub cbr: f64,
    /// Resulting `T_GenCam_DCC` in ms, within `[100, 1000]`.
    pub t_gen_cam_dcc_ms: u64,
    /// Reactive state (reactive mode only).
    pub state: Option<DccState>,
    /// Duty-cycle fraction `delta` (adaptive mode only).
    pub delta: Option<f64>,
}

enum Algorithm {
    Reactive(DccReactive),
    Adaptive { alg: DccAdaptive, t_on_ms: f64 },
}

type Listener = Box<dyn Fn(u64) + Send>;

/// DCC entity of the ITS-S management layer.
pub struct DccEntity {
    algorithm: Algorithm,
    provider: Box<dyn CbrProvider>,
    previous_cbr: Option<f64>,
    last_output: Option<DccEntityOutput>,
    listeners: Vec<Listener>,
}

/// Bound an interval in ms to `[T_GEN_CAM_DCC_MIN_MS, T_GEN_CAM_DCC_MAX_MS]`.
pub fn clamp_t_gen_cam_dcc(interval_ms: f64) -> u64 {
    if !interval_ms.is_finite() {
        return T_GEN_CAM_DCC_MAX_MS;
    }
    (interval_ms.round().max(0.0) as u64).clamp(T_GEN_CAM_DCC_MIN_MS, T_GEN_CAM_DCC_MAX_MS)
}

impl DccEntity {
    /// Create a DCC entity with the given algorithm and CBR source.
    pub fn new(mode: DccMode, provider: Box<dyn CbrProvider>) -> Self {
        let algorithm = match mode {
            DccMode::Reactive { t_on_max_us } => Algorithm::Reactive(DccReactive::new(t_on_max_us)),
            DccMode::Adaptive {
                parameters,
                t_on_ms,
            } => Algorithm::Adaptive {
                alg: DccAdaptive::new(parameters),
                t_on_ms,
            },
        };
        Self {
            algorithm,
            provider,
            previous_cbr: None,
            last_output: None,
            listeners: Vec::new(),
        }
    }

    /// Register a callback receiving `T_GenCam_DCC` (ms) after every evaluation,
    /// e.g. `move |ms| ctm.set_t_gen_cam_dcc(ms)`.
    pub fn add_t_gen_cam_dcc_listener<F>(&mut self, listener: F)
    where
        F: Fn(u64) + Send + 'static,
    {
        self.listeners.push(Box::new(listener));
    }

    /// Output of the most recent successful evaluation.
    pub fn last_output(&self) -> Option<DccEntityOutput> {
        self.last_output
    }

    /// Run one evaluation.
    ///
    /// Returns `None` (and leaves the previous output in place) when the provider
    /// has no measurement or returns a value outside `[0.0, 1.0]`.
    pub fn evaluate(&mut self) -> Option<DccEntityOutput> {
        let cbr = self.provider.measure_cbr()?;
        if !(0.0..=1.0).contains(&cbr) {
            return None;
        }
        let output = match &mut self.algorithm {
            Algorithm::Reactive(alg) => {
                let out = alg.update(cbr).ok()?;
                DccEntityOutput {
                    cbr,
                    t_gen_cam_dcc_ms: clamp_t_gen_cam_dcc(out.t_off_ms),
                    state: Some(out.state),
                    delta: None,
                }
            }
            Algorithm::Adaptive { alg, t_on_ms } => {
                let previous = self.previous_cbr.unwrap_or(cbr);
                let delta = alg.update_local(cbr, previous).ok()?;
                DccEntityOutput {
                    cbr,
                    t_gen_cam_dcc_ms: clamp_t_gen_cam_dcc(*t_on_ms / delta),
                    state: None,
                    delta: Some(delta),
                }
            }
        };
        self.previous_cbr = Some(cbr);
        self.last_output = Some(output);
        for listener in &self.listeners {
            listener(output.t_gen_cam_dcc_ms);
        }
        Some(output)
    }

    /// Run the entity on a background thread, evaluating at every
    /// UTC-modulo-200 ms boundary until [`DccEntityHandle::stop`] is called.
    pub fn spawn(mut self) -> DccEntityHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();
        let join = thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(ms_to_next_boundary()));
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                let _ = self.evaluate();
            }
        });
        DccEntityHandle {
            stop,
            join: Some(join),
        }
    }
}

fn ms_to_next_boundary() -> u64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    DCC_EVALUATION_PERIOD_MS - (now_ms % DCC_EVALUATION_PERIOD_MS)
}

/// Handle to a DCC entity running on a background thread.
pub struct DccEntityHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl DccEntityHandle {
    /// Stop the background thread and wait for it to finish (≤ one period).
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for DccEntityHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::cbr::SharedCbr;
    use std::sync::atomic::AtomicU64;

    fn entity(mode: DccMode) -> (DccEntity, SharedCbr) {
        let cbr = SharedCbr::new();
        (DccEntity::new(mode, Box::new(cbr.clone())), cbr)
    }

    #[test]
    fn test_clamp_t_gen_cam_dcc() {
        assert_eq!(clamp_t_gen_cam_dcc(10.0), 100);
        assert_eq!(clamp_t_gen_cam_dcc(400.4), 400);
        assert_eq!(clamp_t_gen_cam_dcc(5000.0), 1000);
        assert_eq!(clamp_t_gen_cam_dcc(f64::INFINITY), 1000);
        assert_eq!(clamp_t_gen_cam_dcc(f64::NAN), 1000);
    }

    #[test]
    fn test_no_measurement_returns_none() {
        let (mut dcc, _cbr) = entity(DccMode::reactive());
        assert_eq!(dcc.evaluate(), None);
        assert_eq!(dcc.last_output(), None);
    }

    #[test]
    fn test_reactive_relaxed_maps_to_t_gen_cam_min() {
        let (mut dcc, cbr) = entity(DccMode::reactive());
        cbr.report(0.1);
        let out = dcc.evaluate().unwrap();
        assert_eq!(out.state, Some(DccState::Relaxed));
        assert_eq!(out.t_gen_cam_dcc_ms, 100);
        assert_eq!(out.delta, None);
    }

    #[test]
    fn test_reactive_steps_one_state_per_evaluation() {
        // Table A.1 T_off: 100, 200, 400, 500, 1000 ms.
        let (mut dcc, cbr) = entity(DccMode::reactive());
        cbr.report(0.9);
        let expected = [200, 400, 500, 1000, 1000];
        for ms in expected {
            assert_eq!(dcc.evaluate().unwrap().t_gen_cam_dcc_ms, ms);
        }
        assert_eq!(
            dcc.last_output().unwrap().state,
            Some(DccState::Restrictive)
        );
        // Channel clears: one step down per evaluation.
        cbr.report(0.0);
        assert_eq!(dcc.evaluate().unwrap().t_gen_cam_dcc_ms, 500);
        assert_eq!(dcc.evaluate().unwrap().t_gen_cam_dcc_ms, 400);
    }

    #[test]
    fn test_reactive_table_a2() {
        let (mut dcc, cbr) = entity(DccMode::Reactive { t_on_max_us: 500 });
        cbr.report(0.35);
        // Table A.2 Active1 T_off = 100 ms.
        assert_eq!(dcc.evaluate().unwrap().t_gen_cam_dcc_ms, 100);
    }

    #[test]
    fn test_adaptive_low_cbr_allows_t_gen_cam_min() {
        let (mut dcc, cbr) = entity(DccMode::adaptive());
        cbr.report(0.0);
        let mut out = dcc.evaluate().unwrap();
        for _ in 0..2000 {
            out = dcc.evaluate().unwrap();
        }
        // delta converges to delta_max = 0.03 -> 1 ms / 0.03 = 33 ms -> clamped to 100 ms.
        assert!((out.delta.unwrap() - 0.03).abs() < 1e-9);
        assert_eq!(out.t_gen_cam_dcc_ms, 100);
        assert_eq!(out.state, None);
    }

    #[test]
    fn test_adaptive_high_cbr_reaches_t_gen_cam_max() {
        let (mut dcc, cbr) = entity(DccMode::adaptive());
        cbr.report(1.0);
        // The CBR_ITS_S smoothing (step 1) starts below the target, so delta
        // first rises; it then converges to delta_min under a saturated channel.
        let mut out = dcc.evaluate().unwrap();
        for _ in 0..2000 {
            out = dcc.evaluate().unwrap();
        }
        // delta = delta_min = 0.0006 -> 1 ms / 0.0006 = 1667 ms -> clamped to 1000 ms.
        assert!((out.delta.unwrap() - 0.0006).abs() < 1e-12);
        assert_eq!(out.t_gen_cam_dcc_ms, 1000);
    }

    #[test]
    fn test_adaptive_uses_previous_cbr() {
        let (mut a, cbr_a) = entity(DccMode::adaptive());
        let (mut b, _cbr_b) = entity(DccMode::adaptive());
        cbr_a.report(0.2);
        a.evaluate().unwrap();
        cbr_a.report(0.6);
        let out = a.evaluate().unwrap();
        // Same sequence through the algorithm directly.
        let mut alg = DccAdaptive::default();
        alg.update_local(0.2, 0.2).unwrap();
        let delta = alg.update_local(0.6, 0.2).unwrap();
        assert!((out.delta.unwrap() - delta).abs() < 1e-15);
        assert_eq!(b.evaluate(), None);
    }

    #[test]
    fn test_listeners_receive_t_gen_cam_dcc() {
        let (mut dcc, cbr) = entity(DccMode::reactive());
        let seen = Arc::new(AtomicU64::new(0));
        let seen2 = seen.clone();
        dcc.add_t_gen_cam_dcc_listener(move |ms| seen2.store(ms, Ordering::SeqCst));
        cbr.report(0.9);
        dcc.evaluate().unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 200);
    }

    #[test]
    fn test_spawn_evaluates_periodically_and_stops() {
        let (mut dcc, cbr) = entity(DccMode::reactive());
        let seen = Arc::new(AtomicU64::new(0));
        let seen2 = seen.clone();
        dcc.add_t_gen_cam_dcc_listener(move |ms| seen2.store(ms, Ordering::SeqCst));
        cbr.report(0.9);
        let handle = dcc.spawn();
        thread::sleep(Duration::from_millis(3 * DCC_EVALUATION_PERIOD_MS + 50));
        handle.stop();
        // At least two evaluations happened: Relaxed -> Active1 (200) -> Active2 (400) ...
        assert!(seen.load(Ordering::SeqCst) >= 400);
    }

    #[test]
    fn test_ms_to_next_boundary_in_range() {
        let ms = ms_to_next_boundary();
        assert!((1..=DCC_EVALUATION_PERIOD_MS).contains(&ms));
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Adaptive Decentralized Congestion Control (DCC) algorithm and Gate Keeper.
//!
//! Implements the adaptive approach specified in ETSI TS 102 687 V1.2.1 (2018-04)
//! clause 5.4 and the gate-keeping packet admission mechanism described in
//! Annex B.
//!
//! # Overview
//! The adaptive algorithm (LIMERIC) maintains a smoothed estimate of the local
//! Channel Busy Ratio (`cbr_its_s`) and adjusts a *duty-cycle fraction*
//! parameter `delta` so that the ITS-S's own channel occupancy converges toward
//! a configurable target CBR. `delta` represents the maximum fraction of the
//! wireless medium that this ITS-S is allowed to occupy over any given interval.
//!
//! The [`DccAdaptive`] struct implements the five algorithmic steps of
//! clause 5.4 and is intended to be called at every UTC-modulo-200 ms boundary.
//!
//! The [`GateKeeper`] struct implements the packet admission logic of Annex B.
//! It uses the current `delta` value to compute the earliest time at which the
//! next packet may be admitted to the access layer. When `delta` is updated by
//! the adaptive algorithm, the gate-opening time is recalculated according to
//! equation B.2 to avoid synchronised transmissions across stations.

use super::DccError;

/// Tunable parameters of the adaptive DCC algorithm.
///
/// Default values are taken from Table 3 of ETSI TS 102 687 V1.2.1 (2018-04)
/// clause 5.4.
#[derive(Debug, Clone, PartialEq)]
pub struct DccAdaptiveParameters {
    /// Exponential averaging coefficient used in step 3 (equation 4).
    /// Default: 0.016.
    pub alpha: f64,
    /// Proportional gain applied to the CBR error in step 2 (equations 2 and 3).
    /// Default: 0.0012.
    pub beta: f64,
    /// Target Channel Busy Ratio toward which `delta` is steered.
    /// Default: 0.68.
    pub cbr_target: f64,
    /// Hard upper bound on the duty-cycle fraction `delta` (step 4, equation 5).
    /// Corresponds to the maximum duty cycle permitted by ETSI EN 302 571.
    /// Default: 0.03.
    pub delta_max: f64,
    /// Hard lower bound on `delta` (step 5, equation 6).
    /// Prevents complete starvation under extreme congestion.
    /// Default: 0.0006.
    pub delta_min: f64,
    /// Upper clamp on the per-step offset when CBR is below the target (equation 2).
    /// Default: 0.0005.
    pub delta_up_max: f64,
    /// Lower clamp on the per-step offset when CBR is at or above the target (equation 3).
    /// Must be negative. Default: -0.00025.
    pub delta_down_max: f64,
}

impl Default for DccAdaptiveParameters {
    fn default() -> Self {
        Self {
            alpha: 0.016,
            beta: 0.0012,
            cbr_target: 0.68,
            delta_max: 0.03,
            delta_min: 0.0006,
            delta_up_max: 0.0005,
            delta_down_max: -0.00025,
        }
    }
}

/// Adaptive DCC algorithm as specified in ETSI TS 102 687 V1.2.1 (2018-04)
/// clause 5.4 (LIMERIC).
///
/// The algorithm shall be evaluated at every UTC-modulo-200 ms boundary
/// (clause 5.2). Each evaluation executes five ordered steps that update the
/// duty-cycle fraction `delta`:
///
/// - **Step 1** – Compute a smoothed CBR estimate (`cbr_its_s`) from the
///   two most recent local (or global, if available) CBR measurements.
/// - **Step 2** – Compute a signed per-step correction (`delta_offset`)
///   proportional to the distance between `cbr_target` and `cbr_its_s`,
///   clamped to `[delta_down_max, delta_up_max]`.
/// - **Step 3** – Apply an exponential filter to blend the new offset into the
///   current `delta`.
/// - **Steps 4–5** – Clamp `delta` to `[delta_min, delta_max]`.
#[derive(Debug, Clone, PartialEq)]
pub struct DccAdaptive {
    /// Algorithm tuning parameters.
    pub parameters: DccAdaptiveParameters,
    /// Current smoothed CBR estimate (initialised to 0.0).
    pub cbr_its_s: f64,
    /// Current duty-cycle fraction (initialised to `parameters.delta_min`).
    pub delta: f64,
}

impl Default for DccAdaptive {
    fn default() -> Self {
        Self::new(DccAdaptiveParameters::default())
    }
}

impl DccAdaptive {
    /// Initialise the adaptive DCC algorithm with the given parameters.
    pub fn new(parameters: DccAdaptiveParameters) -> Self {
        let delta = parameters.delta_min;
        Self {
            parameters,
            cbr_its_s: 0.0,
            delta,
        }
    }

    /// Execute one full adaptive DCC evaluation (steps 1–5 of clause 5.4).
    ///
    /// # Parameters
    /// - `cbr_local`: Most recent local CBR measurement (`CBR_L_0_Hop`).
    /// - `cbr_local_previous`: Second most recent local CBR measurement (`CBR_L_0_Hop_Previous`).
    /// - `cbr_global`: Most recent global CBR (`CBR_G`), received from a neighbouring
    ///   ITS-S via GeoNetworking header. When provided together with `cbr_global_previous`,
    ///   replaces the local values in step 1.
    /// - `cbr_global_previous`: Second most recent global CBR (`CBR_G_Previous`).
    ///
    /// # Returns
    /// Updated `delta` value after clamping.
    ///
    /// # Errors
    /// Returns [`DccError::InvalidCbr`] if any CBR argument is outside `[0.0, 1.0]`.
    pub fn update(
        &mut self,
        cbr_local: f64,
        cbr_local_previous: f64,
        cbr_global: Option<f64>,
        cbr_global_previous: Option<f64>,
    ) -> Result<f64, DccError> {
        if !(0.0..=1.0).contains(&cbr_local) {
            return Err(DccError::InvalidCbr {
                name: "cbr_local",
                value: cbr_local,
            });
        }
        if !(0.0..=1.0).contains(&cbr_local_previous) {
            return Err(DccError::InvalidCbr {
                name: "cbr_local_previous",
                value: cbr_local_previous,
            });
        }
        if let Some(cg) = cbr_global {
            if !(0.0..=1.0).contains(&cg) {
                return Err(DccError::InvalidCbr {
                    name: "cbr_global",
                    value: cg,
                });
            }
        }
        if let Some(cgp) = cbr_global_previous {
            if !(0.0..=1.0).contains(&cgp) {
                return Err(DccError::InvalidCbr {
                    name: "cbr_global_previous",
                    value: cgp,
                });
            }
        }

        let p = &self.parameters;

        // Step 1 (equation 1) – CBR averaging
        // Use global CBR if both global measurements are available (NOTE 1).
        let cbr_avg = match (cbr_global, cbr_global_previous) {
            (Some(cg), Some(cgp)) => (cg + cgp) / 2.0,
            _ => (cbr_local + cbr_local_previous) / 2.0,
        };
        self.cbr_its_s = 0.5 * self.cbr_its_s + 0.5 * cbr_avg;

        // Step 2 (equations 2–3) – compute delta_offset
        let diff = p.cbr_target - self.cbr_its_s;
        let delta_offset = if diff > 0.0 {
            // CBR below target -> increase delta (more transmission allowed)
            (p.beta * diff).min(p.delta_up_max)
        } else {
            // CBR at or above target -> decrease delta (fewer transmissions)
            (p.beta * diff).max(p.delta_down_max)
        };

        // Step 3 (equation 4) – exponential filter
        self.delta = (1.0 - p.alpha) * self.delta + delta_offset;

        // Steps 4–5 (equations 5–6) – clamp to permitted range
        if self.delta > p.delta_max {
            self.delta = p.delta_max;
        }
        if self.delta < p.delta_min {
            self.delta = p.delta_min;
        }

        Ok(self.delta)
    }

    /// Convenience wrapper for local-only CBR updates.
    pub fn update_local(
        &mut self,
        cbr_local: f64,
        cbr_local_previous: f64,
    ) -> Result<f64, DccError> {
        self.update(cbr_local, cbr_local_previous, None, None)
    }
}

/// Packet admission gate keeper as described in ETSI TS 102 687 V1.2.1 (2018-04) Annex B.
///
/// The gate keeper controls which packets may pass from the Network & Transport layer
/// to the Access layer queue. The gate is **open** when the Access layer will accept
/// a new packet and **closed** otherwise.
///
/// # Lifecycle
/// 1. A packet arrives at the gate. If the gate is open the packet is *admitted*:
///    the gate closes and a gate-opening time `t_go` is scheduled using equation B.1.
/// 2. From time `t_go` onward the gate is open again.
/// 3. Whenever `delta` is updated by the adaptive algorithm, `t_go` is recalculated
///    per equation B.2 to preserve relative ordering of gate openings without
///    introducing synchronisation artefacts.
///
/// The minimum inter-admission interval is 25 ms and the maximum is 1 s
/// (both from constraints in ETSI EN 302 571 referenced in Annex B).
#[derive(Debug, Clone, PartialEq)]
pub struct GateKeeper {
    delta: f64,
    t_pg: Option<f64>,
    t_go: Option<f64>,
}

impl GateKeeper {
    /// Minimum allowed gate-open interval in seconds (25 ms).
    pub const GATE_OPEN_MIN_INTERVAL_S: f64 = 0.025;
    /// Maximum allowed gate-open interval in seconds (1 s).
    pub const GATE_OPEN_MAX_INTERVAL_S: f64 = 1.0;
    /// 1 ns tolerance for floating-point rounding.
    pub const T_EPSILON: f64 = 1e-9;

    /// Initialise the gate keeper with an initial `delta` value.
    pub fn new(delta: f64) -> Self {
        Self {
            delta,
            t_pg: None,
            t_go: None,
        }
    }

    /// Return the currently configured `delta` duty-cycle fraction.
    pub fn delta(&self) -> f64 {
        self.delta
    }

    /// Return the time when the gate last closed (`t_pg`), if any.
    pub fn t_pg(&self) -> Option<f64> {
        self.t_pg
    }

    /// Return the scheduled gate-opening time (`t_go`), if any.
    pub fn t_go(&self) -> Option<f64> {
        self.t_go
    }

    /// Return `true` if the gate is currently open at time `t`.
    ///
    /// The gate is open on first use (before any packet has been admitted)
    /// and from `t_go` onward after each admission.
    pub fn is_open(&self, t: f64) -> bool {
        match self.t_go {
            None => true,
            Some(t_go) => t >= t_go - Self::T_EPSILON,
        }
    }

    /// Attempt to admit one packet at time `t`.
    ///
    /// If the gate is open the packet is accepted, the gate closes, and the
    /// next gate-opening time is scheduled per equation B.1:
    ///
    /// `t_go = t_pg + clamp(T_on_pp / delta, 0.025, 1.0)`
    ///
    /// # Parameters
    /// - `t`: Current time in seconds.
    /// - `t_on`: Transmission duration of this packet in seconds (`T_on_pp` in Annex B).
    ///
    /// # Returns
    /// `Ok(true)` if the packet was admitted; `Ok(false)` if the gate was closed.
    ///
    /// # Errors
    /// Returns [`DccError::InvalidTon`] if `t_on` is not positive (`<= 0.0`).
    pub fn admit_packet(&mut self, t: f64, t_on: f64) -> Result<bool, DccError> {
        if t_on <= 0.0 {
            return Err(DccError::InvalidTon(t_on));
        }
        if !self.is_open(t) {
            return Ok(false);
        }

        self.t_pg = Some(t);
        let interval = (t_on / self.delta).clamp(
            Self::GATE_OPEN_MIN_INTERVAL_S,
            Self::GATE_OPEN_MAX_INTERVAL_S,
        );
        self.t_go = Some(t + interval);
        Ok(true)
    }

    /// Update the duty-cycle fraction and reschedule the gate-opening time.
    ///
    /// When `delta` changes, the gate-opening time is recalculated per
    /// equation B.2 to avoid synchronising gate openings across stations:
    ///
    /// `t_go = t_pg + clamp((delta_old / delta_new) * (t_go - t_pg), 0.025, 1.0)`
    ///
    /// If the gate is currently open (no packet admitted yet, or `t_go` has already
    /// passed) only `delta` is updated.
    ///
    /// # Parameters
    /// - `t`: Current time in seconds.
    /// - `delta_new`: Updated duty-cycle fraction from the adaptive DCC algorithm.
    ///
    /// # Errors
    /// Returns [`DccError::InvalidDelta`] if `delta_new` is not positive (`<= 0.0`).
    pub fn update_delta(&mut self, t: f64, delta_new: f64) -> Result<(), DccError> {
        if delta_new <= 0.0 {
            return Err(DccError::InvalidDelta(delta_new));
        }

        let delta_old = self.delta;
        self.delta = delta_new;

        // Gate is already open -> no rescheduling needed
        if self.t_pg.is_none() || self.t_go.is_none() || self.is_open(t) {
            return Ok(());
        }

        // B.2 – rescale remaining closed interval by delta ratio
        let t_pg = self.t_pg.unwrap();
        let t_go = self.t_go.unwrap();
        let old_interval = t_go - t_pg;
        let new_interval = (delta_old / delta_new) * old_interval;
        let interval = new_interval.clamp(
            Self::GATE_OPEN_MIN_INTERVAL_S,
            Self::GATE_OPEN_MAX_INTERVAL_S,
        );
        self.t_go = Some(t_pg + interval);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    macro_rules! assert_almost_eq {
        ($a:expr, $b:expr) => {
            assert!(
                ($a - $b).abs() < 1e-9,
                "assertion failed: ({} - {}) < 1e-9 (left: {}, right: {})",
                stringify!($a),
                stringify!($b),
                $a,
                $b
            );
        };
        ($a:expr, $b:expr, $eps:expr) => {
            assert!(
                ($a - $b).abs() < $eps,
                "assertion failed: ({} - {}) < {} (left: {}, right: {})",
                stringify!($a),
                stringify!($b),
                stringify!($eps),
                $a,
                $b
            );
        };
    }

    // ── Initialisation ────────────────────────────────────────────────────

    #[test]
    fn test_default_parameters() {
        let alg = DccAdaptive::default();
        let p = &alg.parameters;
        assert_almost_eq!(p.alpha, 0.016);
        assert_almost_eq!(p.beta, 0.0012);
        assert_almost_eq!(p.cbr_target, 0.68);
        assert_almost_eq!(p.delta_max, 0.03);
        assert_almost_eq!(p.delta_min, 0.0006);
        assert_almost_eq!(p.delta_up_max, 0.0005);
        assert_almost_eq!(p.delta_down_max, -0.00025);
    }

    #[test]
    fn test_initial_cbr_its_s_is_zero() {
        let alg = DccAdaptive::default();
        assert_almost_eq!(alg.cbr_its_s, 0.0);
    }

    #[test]
    fn test_initial_delta_is_delta_min() {
        let alg = DccAdaptive::default();
        assert_almost_eq!(alg.delta, alg.parameters.delta_min);
    }

    #[test]
    fn test_custom_parameters_accepted() {
        let params = DccAdaptiveParameters {
            alpha: 0.1,
            beta: 0.05,
            cbr_target: 0.5,
            ..Default::default()
        };
        let alg = DccAdaptive::new(params);
        assert_almost_eq!(alg.parameters.alpha, 0.1);
        assert_almost_eq!(alg.parameters.cbr_target, 0.5);
    }

    // ── Step 1: CBR Smoothing ─────────────────────────────────────────────

    #[test]
    fn test_cbr_its_s_uses_local_average() {
        let mut alg = DccAdaptive::default();
        alg.update_local(0.4, 0.4).unwrap();
        // 0.5*0.0 + 0.5*(0.4+0.4)/2 = 0.5*0.4 = 0.2
        assert_almost_eq!(alg.cbr_its_s, 0.2);
    }

    #[test]
    fn test_cbr_its_s_accumulates_over_calls() {
        let mut alg = DccAdaptive::default();
        alg.update_local(0.4, 0.4).unwrap();
        // After first call: cbr_its_s = 0.2
        alg.update_local(0.4, 0.4).unwrap();
        // After second call: 0.5*0.2 + 0.5*0.4 = 0.1 + 0.2 = 0.3
        assert_almost_eq!(alg.cbr_its_s, 0.3);
    }

    #[test]
    fn test_cbr_its_s_uses_global_when_provided() {
        let mut alg = DccAdaptive::default();
        alg.update(0.1, 0.1, Some(0.6), Some(0.6)).unwrap();
        // 0.5*0.0 + 0.5*(0.6+0.6)/2 = 0.5*0.6 = 0.3
        assert_almost_eq!(alg.cbr_its_s, 0.3);
    }

    #[test]
    fn test_cbr_its_s_ignores_global_when_only_one_provided() {
        let mut alg = DccAdaptive::default();
        alg.update(0.4, 0.4, Some(0.9), None).unwrap();
        // Falls back to local: 0.5*(0.4+0.4)/2 = 0.2
        assert_almost_eq!(alg.cbr_its_s, 0.2);
    }

    // ── Step 2: delta_offset Clamping ─────────────────────────────────────

    #[test]
    fn test_positive_diff_uses_equation_2() {
        let mut alg = DccAdaptive {
            cbr_its_s: 0.0,
            ..Default::default()
        };
        alg.update_local(0.0, 0.0).unwrap();
        let expected_delta = (1.0 - 0.016) * 0.0006 + 0.0005;
        assert_almost_eq!(alg.delta, expected_delta, 1e-10);
    }

    #[test]
    fn test_negative_diff_uses_equation_3() {
        let mut alg = DccAdaptive {
            cbr_its_s: 1.0,
            ..Default::default()
        };
        let initial_delta = alg.delta;
        alg.update_local(1.0, 1.0).unwrap();
        let expected_delta = ((1.0 - 0.016) * initial_delta + (-0.00025_f64)).clamp(0.0006, 0.03);
        assert_almost_eq!(alg.delta, expected_delta, 1e-10);
    }

    #[test]
    fn test_small_positive_diff_not_clamped() {
        let p = DccAdaptiveParameters::default();
        let mut alg = DccAdaptive {
            parameters: p.clone(),
            cbr_its_s: 0.679,
            delta: 0.01,
        };
        alg.update_local(0.679, 0.679).unwrap();
        let diff = 0.68 - 0.679;
        let expected_offset = p.beta * diff;
        let expected_delta = (1.0 - p.alpha) * 0.01 + expected_offset;
        assert_almost_eq!(alg.delta, expected_delta, 1e-10);
    }

    #[test]
    fn test_large_negative_diff_clamped_to_down_max() {
        let mut alg = DccAdaptive {
            cbr_its_s: 0.99,
            delta: 0.02,
            ..Default::default()
        };
        alg.update_local(0.99, 0.99).unwrap();
        let expected_delta = (1.0 - 0.016) * 0.02 + (-0.00025);
        assert_almost_eq!(alg.delta, expected_delta, 1e-10);
    }

    // ── Steps 3–5: Filter and Clamping ────────────────────────────────────

    #[test]
    fn test_step3_exponential_filter() {
        let mut alg = DccAdaptive {
            cbr_its_s: 0.68,
            delta: 0.01,
            ..Default::default()
        };
        alg.update_local(0.68, 0.68).unwrap();
        let expected = (1.0 - 0.016) * 0.01 + 0.0;
        assert_almost_eq!(alg.delta, expected, 1e-10);
    }

    #[test]
    fn test_step4_clamps_delta_to_max() {
        let mut alg = DccAdaptive {
            delta: 0.029,
            cbr_its_s: 0.0,
            ..Default::default()
        };
        alg.update_local(0.0, 0.0).unwrap();
        assert!(alg.delta <= alg.parameters.delta_max);
    }

    #[test]
    fn test_step5_clamps_delta_to_min() {
        let mut alg = DccAdaptive {
            cbr_its_s: 1.0,
            ..Default::default()
        };
        alg.delta = alg.parameters.delta_min;
        alg.update_local(1.0, 1.0).unwrap();
        assert!(alg.delta >= alg.parameters.delta_min);
    }

    #[test]
    fn test_delta_converges_toward_target() {
        let mut alg = DccAdaptive::default();
        let cbr = 0.68;
        for _ in 0..500 {
            alg.update_local(cbr, cbr).unwrap();
        }
        assert!(alg.delta >= alg.parameters.delta_min);
        assert!(alg.delta <= alg.parameters.delta_max);
    }

    #[test]
    fn test_delta_increases_when_cbr_below_target() {
        let mut alg = DccAdaptive::default();
        let prev_delta = alg.delta;
        for _ in 0..50 {
            alg.update_local(0.0, 0.0).unwrap();
        }
        assert!(alg.delta > prev_delta);
    }

    #[test]
    fn test_delta_decreases_when_cbr_above_target() {
        let mut alg = DccAdaptive {
            delta: 0.02,
            ..Default::default()
        };
        for _ in 0..200 {
            alg.update_local(1.0, 1.0).unwrap();
        }
        assert_almost_eq!(alg.delta, alg.parameters.delta_min);
    }

    // ── Input Validation ──────────────────────────────────────────────────

    #[test]
    fn test_cbr_local_below_zero_raises() {
        let mut alg = DccAdaptive::default();
        let res = alg.update_local(-0.01, 0.5);
        assert!(matches!(
            res,
            Err(DccError::InvalidCbr {
                name: "cbr_local",
                ..
            })
        ));
    }

    #[test]
    fn test_cbr_local_above_one_raises() {
        let mut alg = DccAdaptive::default();
        let res = alg.update_local(1.01, 0.5);
        assert!(matches!(
            res,
            Err(DccError::InvalidCbr {
                name: "cbr_local",
                ..
            })
        ));
    }

    #[test]
    fn test_cbr_local_previous_below_zero_raises() {
        let mut alg = DccAdaptive::default();
        let res = alg.update_local(0.5, -0.01);
        assert!(matches!(
            res,
            Err(DccError::InvalidCbr {
                name: "cbr_local_previous",
                ..
            })
        ));
    }

    #[test]
    fn test_cbr_local_previous_above_one_raises() {
        let mut alg = DccAdaptive::default();
        let res = alg.update_local(0.5, 1.01);
        assert!(matches!(
            res,
            Err(DccError::InvalidCbr {
                name: "cbr_local_previous",
                ..
            })
        ));
    }

    #[test]
    fn test_boundary_values_valid() {
        let mut alg = DccAdaptive::default();
        assert!(alg.update_local(0.0, 0.0).is_ok());
        assert!(alg.update_local(1.0, 1.0).is_ok());
    }

    // ── GateKeeper Initialisation ─────────────────────────────────────────

    #[test]
    fn test_gate_is_open_initially() {
        let gk = GateKeeper::new(0.01);
        assert!(gk.is_open(0.0));
    }

    #[test]
    fn test_gate_is_open_at_any_time_initially() {
        let gk = GateKeeper::new(0.01);
        for &t in &[0.0, 100.0, -1.0] {
            assert!(gk.is_open(t));
        }
    }

    // ── GateKeeper Admission ──────────────────────────────────────────────

    #[test]
    fn test_first_packet_admitted() {
        let mut gk = GateKeeper::new(0.01);
        assert!(gk.admit_packet(0.0, 0.001).unwrap());
    }

    #[test]
    fn test_gate_closed_after_admission() {
        let mut gk = GateKeeper::new(0.01);
        gk.admit_packet(0.0, 0.001).unwrap();
        assert!(!gk.is_open(0.0));
    }

    #[test]
    fn test_second_packet_rejected_when_gate_closed() {
        let mut gk = GateKeeper::new(0.01);
        assert!(gk.admit_packet(0.0, 0.001).unwrap());
        assert!(!gk.admit_packet(0.0, 0.001).unwrap());
    }

    #[test]
    fn test_gate_opens_after_t_go() {
        let mut gk = GateKeeper::new(0.01);
        gk.admit_packet(0.0, 0.001).unwrap(); // t_go = 0.0 + 0.1 = 0.1
        assert!(!gk.is_open(0.099));
        assert!(gk.is_open(0.1));
    }

    #[test]
    fn test_minimum_interval_enforced() {
        let mut gk = GateKeeper::new(1.0);
        gk.admit_packet(0.0, 0.001).unwrap();
        assert!(!gk.is_open(0.024));
        assert!(gk.is_open(0.025));
    }

    #[test]
    fn test_maximum_interval_enforced() {
        let mut gk = GateKeeper::new(0.0006);
        gk.admit_packet(0.0, 0.001).unwrap();
        assert!(!gk.is_open(0.99));
        assert!(gk.is_open(1.0));
    }

    #[test]
    fn test_t_on_zero_raises() {
        let mut gk = GateKeeper::new(0.01);
        assert!(matches!(
            gk.admit_packet(0.0, 0.0),
            Err(DccError::InvalidTon(_))
        ));
    }

    #[test]
    fn test_t_on_negative_raises() {
        let mut gk = GateKeeper::new(0.01);
        assert!(matches!(
            gk.admit_packet(0.0, -0.001),
            Err(DccError::InvalidTon(_))
        ));
    }

    // ── GateKeeper Update Delta ───────────────────────────────────────────

    #[test]
    fn test_update_delta_when_gate_open_only_changes_delta() {
        let mut gk = GateKeeper::new(0.01);
        gk.update_delta(0.0, 0.02).unwrap();
        assert!(gk.is_open(0.0));
    }

    #[test]
    fn test_update_delta_rescales_interval_when_delta_increases() {
        let mut gk = GateKeeper::new(0.01);
        gk.admit_packet(0.0, 0.001).unwrap(); // t_go = 0.1
        gk.update_delta(0.0, 0.02).unwrap(); // t_go -> 0.05
        assert!(!gk.is_open(0.049));
        assert!(gk.is_open(0.05));
    }

    #[test]
    fn test_update_delta_rescales_interval_when_delta_decreases() {
        let mut gk = GateKeeper::new(0.02);
        gk.admit_packet(0.0, 0.001).unwrap(); // t_go = 0.05
        gk.update_delta(0.0, 0.01).unwrap(); // t_go -> 0.1
        assert!(!gk.is_open(0.099));
        assert!(gk.is_open(0.1));
    }

    #[test]
    fn test_update_delta_minimum_interval_enforced() {
        let mut gk = GateKeeper::new(0.01);
        gk.admit_packet(0.0, 0.001).unwrap();
        gk.update_delta(0.0, 0.1).unwrap();
        assert!(!gk.is_open(0.024));
        assert!(gk.is_open(0.025));
    }

    #[test]
    fn test_update_delta_maximum_interval_enforced() {
        let mut gk = GateKeeper::new(0.02);
        gk.admit_packet(0.0, 0.001).unwrap();
        gk.update_delta(0.0, 0.0001).unwrap();
        assert!(!gk.is_open(0.99));
        assert!(gk.is_open(1.0));
    }

    #[test]
    fn test_update_delta_zero_raises() {
        let mut gk = GateKeeper::new(0.01);
        assert!(matches!(
            gk.update_delta(0.0, 0.0),
            Err(DccError::InvalidDelta(_))
        ));
    }

    #[test]
    fn test_update_delta_negative_raises() {
        let mut gk = GateKeeper::new(0.01);
        assert!(matches!(
            gk.update_delta(0.0, -0.01),
            Err(DccError::InvalidDelta(_))
        ));
    }

    #[test]
    fn test_update_after_gate_reopens_no_rescheduling() {
        let mut gk = GateKeeper::new(0.01);
        gk.admit_packet(0.0, 0.001).unwrap(); // t_go = 0.1
        gk.update_delta(0.5, 0.005).unwrap();
        assert!(gk.is_open(0.5));
    }

    // ── Integration ───────────────────────────────────────────────────────

    #[test]
    fn test_gate_keeper_uses_updated_delta() {
        let mut gk = GateKeeper::new(0.01);
        gk.admit_packet(0.0, 0.001).unwrap(); // t_go = 0.1

        assert!(gk.is_open(0.1));
        gk.update_delta(0.1, 0.02).unwrap();
        gk.admit_packet(0.1, 0.001).unwrap(); // t_go = 0.1 + 0.001/0.02 = 0.1 + 0.05 = 0.15
        assert!(!gk.is_open(0.14));
        assert!(gk.is_open(0.15));
    }
}

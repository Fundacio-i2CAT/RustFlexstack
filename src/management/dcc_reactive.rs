// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Reactive Decentralized Congestion Control (DCC) algorithm.
//!
//! Implements the reactive approach specified in ETSI TS 102 687 V1.2.1 (2018-04)
//! clause 5.3 and Annex A.
//!
//! The algorithm consists of five states (Relaxed, Active 1, Active 2, Active 3,
//! Restrictive) arranged in a linear sequence. On each evaluation the state may
//! advance at most *one* step toward the state dictated by the current Channel
//! Busy Ratio (CBR), which enforces the "one state can only be reached by a
//! neighbouring state" adjacency requirement from clause 5.3. Each state maps
//! directly to a maximum allowed packet rate and a minimum inter-packet gap (T_off).
//!
//! Two parameter tables are defined in Annex A depending on the assumed maximum
//! packet transmission duration (T_on):
//! - **Table A.1** – used when T_on is at most 1 ms
//! - **Table A.2** – used when T_on is at most 500 µs

use super::DccError;

/// Ordered states of the reactive DCC algorithm.
///
/// As specified in ETSI TS 102 687 V1.2.1 (2018-04) clause 5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DccState {
    /// Lowest utilisation state. Fewest restrictions on transmissions.
    Relaxed = 0,
    /// First active state. Moderate CBR detected.
    Active1 = 1,
    /// Second active state. Elevated CBR detected.
    Active2 = 2,
    /// Third active state. High CBR detected.
    Active3 = 3,
    /// Most stringent state. Very high CBR detected.
    Restrictive = 4,
}

impl DccState {
    /// Ordered list of states used for single-step transitions.
    pub const ALL: [DccState; 5] = [
        DccState::Relaxed,
        DccState::Active1,
        DccState::Active2,
        DccState::Active3,
        DccState::Restrictive,
    ];

    /// Returns the zero-based numeric index of the state (0 = Relaxed, 4 = Restrictive).
    pub fn index(self) -> usize {
        self as usize
    }

    /// Converts a zero-based numeric index back to a [`DccState`].
    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(DccState::Relaxed),
            1 => Some(DccState::Active1),
            2 => Some(DccState::Active2),
            3 => Some(DccState::Active3),
            4 => Some(DccState::Restrictive),
            _ => None,
        }
    }
}

/// Channel Busy Ratio thresholds and output parameters for a single state.
///
/// As specified in ETSI TS 102 687 V1.2.1 (2018-04) Annex A, Tables A.1 and A.2.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DccStateConfig {
    /// Inclusive lower CBR bound for this state (0.0 for Relaxed).
    pub cbr_min: f64,
    /// Exclusive upper CBR bound for this state (1.01 for Restrictive).
    pub cbr_max: f64,
    /// Maximum allowed packet transmission rate in packets per second.
    pub packet_rate_hz: f64,
    /// Minimum required inter-packet gap in milliseconds (T_off).
    pub t_off_ms: f64,
}

impl DccStateConfig {
    pub const fn new(cbr_min: f64, cbr_max: f64, packet_rate_hz: f64, t_off_ms: f64) -> Self {
        Self {
            cbr_min,
            cbr_max,
            packet_rate_hz,
            t_off_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// Standard parameter tables (Annex A)
// ---------------------------------------------------------------------------

/// Table A.1 – T_on at most 1 ms.
/// States ordered from RELAXED to RESTRICTIVE.
pub const TABLE_A1: [DccStateConfig; 5] = [
    DccStateConfig::new(0.00, 0.30, 10.0, 100.0), // Relaxed
    DccStateConfig::new(0.30, 0.40, 5.0, 200.0),  // Active1
    DccStateConfig::new(0.40, 0.50, 2.5, 400.0),  // Active2
    DccStateConfig::new(0.50, 0.60, 2.0, 500.0),  // Active3
    DccStateConfig::new(0.60, 1.01, 1.0, 1000.0), // Restrictive
];

/// Table A.2 – T_on at most 500 µs.
pub const TABLE_A2: [DccStateConfig; 5] = [
    DccStateConfig::new(0.00, 0.30, 20.0, 50.0),  // Relaxed
    DccStateConfig::new(0.30, 0.40, 10.0, 100.0), // Active1
    DccStateConfig::new(0.40, 0.50, 5.0, 200.0),  // Active2
    DccStateConfig::new(0.50, 0.65, 4.0, 250.0),  // Active3
    DccStateConfig::new(0.65, 1.01, 1.0, 1000.0), // Restrictive
];

/// Output produced by a single reactive DCC evaluation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DccReactiveOutput {
    /// Current DCC state after the evaluation.
    pub state: DccState,
    /// Maximum allowed packet transmission rate in packets per second.
    pub packet_rate_hz: f64,
    /// Minimum required inter-packet gap in milliseconds (T_off).
    pub t_off_ms: f64,
}

/// Reactive DCC algorithm as specified in ETSI TS 102 687 V1.2.1 (2018-04)
/// clause 5.3 and Annex A.
///
/// The algorithm is evaluated periodically (at least every 200 ms, per
/// clause 5.2) by calling [`DccReactive::update`] with the most recently measured
/// Channel Busy Ratio (CBR). On each call the state may advance by at most
/// one step toward the state inferred from the CBR table, enforcing the
/// adjacency constraint of clause 5.3.
#[derive(Debug, Clone)]
pub struct DccReactive {
    /// Current algorithm state. Starts at [`DccState::Relaxed`].
    pub state: DccState,
    table: &'static [DccStateConfig; 5],
}

impl Default for DccReactive {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl DccReactive {
    /// Initialise the reactive DCC algorithm.
    ///
    /// # Parameters
    /// - `t_on_max_us`: Maximum packet transmission duration in microseconds.
    ///   Values `<= 500` select Annex A Table A.2; all other values select Table A.1.
    ///   Defaults to 1000 (1 ms) when constructed via [`Default`].
    pub fn new(t_on_max_us: u32) -> Self {
        let table = if t_on_max_us <= 500 {
            &TABLE_A2
        } else {
            &TABLE_A1
        };
        Self {
            state: DccState::Relaxed,
            table,
        }
    }

    /// Return the state whose CBR band contains `cbr`.
    fn target_state(&self, cbr: f64) -> DccState {
        for (i, cfg) in self.table.iter().enumerate() {
            if cfg.cbr_min <= cbr && cbr < cfg.cbr_max {
                return DccState::from_index(i).unwrap_or(DccState::Restrictive);
            }
        }
        // CBR == 1.0 (or floating-point rounding above 1.0) -> Restrictive
        DccState::Restrictive
    }

    /// Evaluate the algorithm with the current Channel Busy Ratio.
    ///
    /// The state advances by at most one step toward the state implied by
    /// `cbr`, satisfying the adjacency constraint from clause 5.3.
    ///
    /// # Parameters
    /// - `cbr`: Current Channel Busy Ratio value in the range `[0.0, 1.0]`.
    ///
    /// # Returns
    /// [`DccReactiveOutput`] with updated state and transmission constraints.
    ///
    /// # Errors
    /// Returns [`DccError::InvalidCbr`] if `cbr` is outside `[0.0, 1.0]`.
    pub fn update(&mut self, cbr: f64) -> Result<DccReactiveOutput, DccError> {
        if !(0.0..=1.0).contains(&cbr) {
            return Err(DccError::InvalidCbr {
                name: "cbr",
                value: cbr,
            });
        }

        let target = self.target_state(cbr);
        let mut current_idx = self.state.index();
        let target_idx = target.index();

        if target_idx > current_idx {
            current_idx += 1;
        } else if target_idx < current_idx {
            current_idx -= 1;
        }
        // else target_idx == current_idx -> no change

        self.state = DccState::from_index(current_idx).unwrap_or(DccState::Restrictive);
        let cfg = self.table[self.state.index()];
        Ok(DccReactiveOutput {
            state: self.state,
            packet_rate_hz: cfg.packet_rate_hz,
            t_off_ms: cfg.t_off_ms,
        })
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
    }

    // ── Initialisation ────────────────────────────────────────────────────

    #[test]
    fn test_initial_state_is_relaxed() {
        let dcc = DccReactive::default();
        assert_eq!(dcc.state, DccState::Relaxed);
    }

    #[test]
    fn test_table_a1_selected_by_default() {
        let mut dcc = DccReactive::new(1000);
        let out = dcc.update(0.0).unwrap();
        assert_almost_eq!(out.packet_rate_hz, 10.0);
        assert_almost_eq!(out.t_off_ms, 100.0);
    }

    #[test]
    fn test_table_a2_selected_for_500us() {
        let mut dcc = DccReactive::new(500);
        let out = dcc.update(0.0).unwrap();
        assert_almost_eq!(out.packet_rate_hz, 20.0);
        assert_almost_eq!(out.t_off_ms, 50.0);
    }

    #[test]
    fn test_table_a2_selected_for_below_500us() {
        let mut dcc = DccReactive::new(250);
        let out = dcc.update(0.0).unwrap();
        assert_almost_eq!(out.packet_rate_hz, 20.0);
    }

    // ── Table A.1 Tests ───────────────────────────────────────────────────

    fn make_dcc_a1() -> DccReactive {
        DccReactive::new(1000)
    }

    #[test]
    fn test_relaxed_output_params() {
        let mut dcc = make_dcc_a1();
        let out = dcc.update(0.0).unwrap();
        assert_eq!(out.state, DccState::Relaxed);
        assert_almost_eq!(out.packet_rate_hz, 10.0);
        assert_almost_eq!(out.t_off_ms, 100.0);
    }

    #[test]
    fn test_active1_output_params() {
        let mut dcc = make_dcc_a1();
        let out = dcc.update(0.35).unwrap();
        assert_eq!(out.state, DccState::Active1);
        assert_almost_eq!(out.packet_rate_hz, 5.0);
        assert_almost_eq!(out.t_off_ms, 200.0);
    }

    #[test]
    fn test_active2_output_params() {
        let mut dcc = make_dcc_a1();
        dcc.update(0.45).unwrap(); // Relaxed -> Active1
        let out = dcc.update(0.45).unwrap(); // Active1 -> Active2
        assert_eq!(out.state, DccState::Active2);
        assert_almost_eq!(out.packet_rate_hz, 2.5);
        assert_almost_eq!(out.t_off_ms, 400.0);
    }

    #[test]
    fn test_active3_output_params() {
        let mut dcc = make_dcc_a1();
        for _ in 0..3 {
            dcc.update(0.55).unwrap();
        }
        let out = dcc.update(0.55).unwrap();
        assert_eq!(out.state, DccState::Active3);
        assert_almost_eq!(out.packet_rate_hz, 2.0);
        assert_almost_eq!(out.t_off_ms, 500.0);
    }

    #[test]
    fn test_restrictive_output_params() {
        let mut dcc = make_dcc_a1();
        for _ in 0..4 {
            dcc.update(0.65).unwrap();
        }
        let out = dcc.update(0.65).unwrap();
        assert_eq!(out.state, DccState::Restrictive);
        assert_almost_eq!(out.packet_rate_hz, 1.0);
        assert_almost_eq!(out.t_off_ms, 1000.0);
    }

    // ── Transitions ───────────────────────────────────────────────────────

    #[test]
    fn test_low_cbr_stays_relaxed() {
        let mut dcc = make_dcc_a1();
        for _ in 0..5 {
            let out = dcc.update(0.10).unwrap();
            assert_eq!(out.state, DccState::Relaxed);
        }
    }

    #[test]
    fn test_cbr_at_lower_threshold_triggers_active1() {
        let mut dcc = make_dcc_a1();
        let out = dcc.update(0.30).unwrap();
        assert_eq!(out.state, DccState::Active1);
    }

    #[test]
    fn test_adjacent_only_from_relaxed_to_active1() {
        let mut dcc = make_dcc_a1();
        let out = dcc.update(0.99).unwrap();
        assert_eq!(out.state, DccState::Active1);
    }

    #[test]
    fn test_two_steps_from_relaxed_to_active2() {
        let mut dcc = make_dcc_a1();
        dcc.update(0.55).unwrap(); // Relaxed -> Active1
        let out = dcc.update(0.55).unwrap(); // Active1 -> Active2
        assert_eq!(out.state, DccState::Active2);
    }

    #[test]
    fn test_step_down_from_active1_to_relaxed() {
        let mut dcc = make_dcc_a1();
        dcc.update(0.35).unwrap(); // -> Active1
        let out = dcc.update(0.10).unwrap(); // -> Relaxed
        assert_eq!(out.state, DccState::Relaxed);
    }

    #[test]
    fn test_same_state_when_cbr_in_band() {
        let mut dcc = make_dcc_a1();
        dcc.update(0.35).unwrap(); // -> Active1
        let out = dcc.update(0.32).unwrap(); // still in Active1 band
        assert_eq!(out.state, DccState::Active1);
    }

    #[test]
    fn test_upward_then_downward_transition_sequence() {
        let mut dcc = make_dcc_a1();
        let states: Vec<DccState> = [0.45, 0.45, 0.10, 0.10]
            .iter()
            .map(|&cbr| dcc.update(cbr).unwrap().state)
            .collect();
        assert_eq!(
            states,
            vec![
                DccState::Active1,
                DccState::Active2,
                DccState::Active1,
                DccState::Relaxed,
            ]
        );
    }

    #[test]
    fn test_cannot_skip_states_going_up() {
        let mut dcc = make_dcc_a1();
        let mut previous_idx = 0;
        for _ in 0..6 {
            let out = dcc.update(1.0).unwrap();
            let current_idx = out.state.index();
            assert!(current_idx >= previous_idx);
            assert!(current_idx - previous_idx <= 1);
            previous_idx = current_idx;
        }
    }

    #[test]
    fn test_cannot_skip_states_going_down() {
        let mut dcc = make_dcc_a1();
        // Drive to Restrictive
        for _ in 0..5 {
            dcc.update(1.0).unwrap();
        }
        let mut previous_idx = dcc.state.index();
        for _ in 0..6 {
            let out = dcc.update(0.0).unwrap();
            let current_idx = out.state.index();
            assert!(previous_idx >= current_idx);
            assert!(previous_idx - current_idx <= 1);
            previous_idx = current_idx;
        }
    }

    #[test]
    fn test_cbr_boundary_at_060_table_a1() {
        let mut dcc = make_dcc_a1();
        // Drive to Active3 first
        for _ in 0..3 {
            dcc.update(0.65).unwrap();
        }
        let out = dcc.update(0.60).unwrap();
        assert_eq!(out.state, DccState::Restrictive);
    }

    // ── Table A.2 Tests ───────────────────────────────────────────────────

    fn make_dcc_a2() -> DccReactive {
        DccReactive::new(500)
    }

    #[test]
    fn test_relaxed_output_params_table_a2() {
        let mut dcc = make_dcc_a2();
        let out = dcc.update(0.10).unwrap();
        assert_eq!(out.state, DccState::Relaxed);
        assert_almost_eq!(out.packet_rate_hz, 20.0);
        assert_almost_eq!(out.t_off_ms, 50.0);
    }

    #[test]
    fn test_active3_output_params_table_a2() {
        let mut dcc = make_dcc_a2();
        for _ in 0..3 {
            dcc.update(0.60).unwrap();
        }
        let out = dcc.update(0.60).unwrap();
        assert_eq!(out.state, DccState::Active3);
        assert_almost_eq!(out.packet_rate_hz, 4.0);
        assert_almost_eq!(out.t_off_ms, 250.0);
    }

    #[test]
    fn test_restrictive_threshold_table_a2() {
        let mut dcc = make_dcc_a2();
        // Drive to Active3 (0.60 is still in A3 band for Table A.2)
        for _ in 0..3 {
            dcc.update(0.70).unwrap();
        }
        let out = dcc.update(0.65).unwrap();
        assert_eq!(out.state, DccState::Restrictive);
    }

    // ── Validation ────────────────────────────────────────────────────────

    #[test]
    fn test_cbr_below_zero_raises() {
        let mut dcc = DccReactive::default();
        let res = dcc.update(-0.01);
        assert!(matches!(res, Err(DccError::InvalidCbr { name: "cbr", .. })));
    }

    #[test]
    fn test_cbr_above_one_raises() {
        let mut dcc = DccReactive::default();
        let res = dcc.update(1.01);
        assert!(matches!(res, Err(DccError::InvalidCbr { name: "cbr", .. })));
    }

    #[test]
    fn test_cbr_zero_valid() {
        let mut dcc = DccReactive::default();
        let out = dcc.update(0.0).unwrap();
        assert_eq!(out.state, DccState::Relaxed);
    }

    #[test]
    fn test_cbr_one_valid() {
        let mut dcc = DccReactive::default();
        let out = dcc.update(1.0).unwrap();
        assert_eq!(out.state, DccState::Active1);
    }

    // ── Output Equality ───────────────────────────────────────────────────

    #[test]
    fn test_output_equality() {
        let a = DccReactiveOutput {
            state: DccState::Active1,
            packet_rate_hz: 5.0,
            t_off_ms: 200.0,
        };
        let b = DccReactiveOutput {
            state: DccState::Active1,
            packet_rate_hz: 5.0,
            t_off_ms: 200.0,
        };
        assert_eq!(a, b);
    }
}

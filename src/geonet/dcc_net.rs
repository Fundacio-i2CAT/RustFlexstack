// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DCC_NET: the GeoNetworking part of Decentralized Congestion Control over
//! ITS-G5 (ETSI TS 103 836-4-2 V2.1.1 (2025-04), clauses 5 to 7).
//!
//! - DCC variables CBR_L_0_Hop, CBR_L_1_Hop, CBR_L_2_Hop and the global CBR_G,
//!   calculated every `itsGNCBRGTriggerInterval` with a random start offset
//!   (clauses 5.2 and 5.3);
//! - Location Table Entry Extension for ITS-G5 (LocTEX-G5) per neighbour,
//!   soft-state with lifetime `itsGnLifetimeLocTEX` (clause 6.2);
//! - the DCC-MCO field of the SHB Extended Header (clause 6.3.3, table 3).
//!
//! The local CBR (CBR_L_0_Hop) is measured by the access layer and read from a
//! [`CbrProvider`], e.g. [`Nl80211SurveyCbr`](crate::management::cbr::Nl80211SurveyCbr)
//! on a Linux ITS-G5 interface. CBR_G is published in [`DccNet::global_cbr`] (a
//! [`SharedCbr`]) so that the DCC entity uses it as input (clause 5.3,
//! DCC_CROSS).
//!
//! Wiring on a Linux ITS-G5 interface:
//!
//! ```ignore
//! use rustflexstack::geonet::dcc_net::DccNet;
//! use rustflexstack::management::cbr::{nl80211_tx_power_dbm, Nl80211SurveyCbr};
//! use rustflexstack::management::dcc_entity::{DccEntity, DccMode};
//!
//! let dcc_net = DccNet::new(
//!     Some(Box::new(Nl80211SurveyCbr::new("wlan0"))),
//!     nl80211_tx_power_dbm("wlan0").unwrap_or(0.0),
//! );
//! let dcc = DccEntity::new(DccMode::reactive(), Box::new(dcc_net.global_cbr.clone()));
//! let (gn, ll_rx, btp_rx) = Router::spawn_with_dcc_net(mib, None, None, None, Some(dcc_net));
//! ```
//!
//! Mirrors `flexstack/geonet/dcc_net.py`.

use std::collections::HashMap;

use super::gn_address::GNAddress;
use crate::management::cbr::{CbrProvider, SharedCbr};

/// Annex A, table A.1: lifetime of the LocTEX-G5 [ms].
pub const ITS_GN_LIFETIME_LOCTEX_MS: u64 = 1000;
/// Annex A, table A.1: CBR_Target.
pub const ITS_GN_CBR_TARGET: f64 = 0.62;
/// Annex A, table A.1: T_Trig [ms].
pub const ITS_GN_CBR_G_TRIGGER_INTERVAL_MS: u64 = 100;
/// Annex A, table A.1: T_Cbr [ms].
pub const ITS_GN_CBR_LIFETIME_MS: u64 = 1000;
/// Table 3: E.I.R.P. range of the Transmit power sub-field [dBm].
const TX_POWER_MAX_DBM: f64 = 31.0;

/// DCC-MCO field (octets 40-43 of the SHB packet header, table 3): CBRs as
/// floor(CBR x 255), transmit power in dBm clamped to [0, 31], octet 43
/// reserved for MCO.
pub fn encode_dcc_mco(cbr_l_0_hop: f64, cbr_l_1_hop: f64, tx_power_dbm: f64) -> [u8; 4] {
    let cbr_octet = |cbr: f64| (cbr * 255.0).floor().clamp(0.0, 255.0) as u8;
    let power = tx_power_dbm.floor().clamp(0.0, TX_POWER_MAX_DBM) as u8;
    [
        cbr_octet(cbr_l_0_hop),
        cbr_octet(cbr_l_1_hop),
        power & 0x1F,
        0,
    ]
}

/// (CBR_R_0_Hop, CBR_R_1_Hop, transmit power [dBm]) of a received DCC-MCO
/// field, or `None` when the field is absent: a sender without DCC_NET leaves
/// the four octets zero-filled (TS 103 836-4-1 reserved field).
pub fn decode_dcc_mco(field: &[u8]) -> Option<(f64, f64, u8)> {
    if field.len() != 4 || field == [0, 0, 0, 0] {
        return None;
    }
    Some((
        field[0] as f64 / 255.0,
        field[1] as f64 / 255.0,
        field[2] & 0x1F,
    ))
}

/// Location Table Entry Extension for ITS-G5 (clause 6.2.2).
#[derive(Debug, Clone, PartialEq)]
pub struct LocTexG5 {
    /// Local time of the last update [ms].
    pub tst_g5_ms: u64,
    /// TST of the SO PV of the updating SHB [ms, mod 2^32].
    pub tst_so_pv: u32,
    pub tx_power_dbm: u8,
    pub rssi_dbm: Option<f64>,
    pub cbr_r_0_hop: f64,
    pub cbr_r_1_hop: f64,
}

/// Steps 1-2 / 3-4 of clause 5.3: the maximum when the average exceeds
/// CBR_Target, otherwise the second largest value (the only value when there
/// is one, 0 when there is none).
fn reduce(values: &[f64], target: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|a, b| b.total_cmp(a));
    let average = values.iter().sum::<f64>() / values.len() as f64;
    if average > target || ordered.len() == 1 {
        ordered[0]
    } else {
        ordered[1]
    }
}

/// DCC_NET entity of a GeoAdhoc router over ITS-G5.
pub struct DccNet {
    /// Source of CBR_L_0_Hop, polled at every trigger; `None` when the
    /// application reports it with [`DccNet::report_local_cbr`].
    pub local_cbr: Option<Box<dyn CbrProvider>>,
    /// E.I.R.P. of the transmitted packets, e.g. from
    /// [`nl80211_tx_power_dbm`](crate::management::cbr::nl80211_tx_power_dbm).
    pub tx_power_dbm: f64,
    pub cbr_target: f64,
    pub trigger_interval_ms: u64,
    pub cbr_lifetime_ms: u64,
    pub loctex_lifetime_ms: u64,
    pub cbr_l_0_hop: f64,
    pub cbr_l_1_hop: f64,
    pub cbr_l_2_hop: f64,
    pub cbr_g: f64,
    /// CBR_G for the DCC entity (DCC_CROSS); clones share the value.
    pub global_cbr: SharedCbr,
    /// LocTEX-G5 per neighbour, keyed by `GNAddress::encode_to_int`.
    pub loctex: HashMap<u64, LocTexG5>,
    rng: Box<dyn FnMut() -> f64 + Send>,
    next_trigger_ms: Option<u64>,
}

impl DccNet {
    /// DCC_NET with the annex A constants and a random trigger offset.
    pub fn new(local_cbr: Option<Box<dyn CbrProvider>>, tx_power_dbm: f64) -> Self {
        DccNet {
            local_cbr,
            tx_power_dbm,
            cbr_target: ITS_GN_CBR_TARGET,
            trigger_interval_ms: ITS_GN_CBR_G_TRIGGER_INTERVAL_MS,
            cbr_lifetime_ms: ITS_GN_CBR_LIFETIME_MS,
            loctex_lifetime_ms: ITS_GN_LIFETIME_LOCTEX_MS,
            cbr_l_0_hop: 0.0,
            cbr_l_1_hop: 0.0,
            cbr_l_2_hop: 0.0,
            cbr_g: 0.0,
            global_cbr: SharedCbr::new(),
            loctex: HashMap::new(),
            rng: Box::new(rand::random::<f64>),
            next_trigger_ms: None,
        }
    }

    /// Replace the uniform [0, 1) source of the random trigger offset.
    pub fn with_rng(mut self, rng: Box<dyn FnMut() -> f64 + Send>) -> Self {
        self.rng = rng;
        self
    }

    /// Set CBR_L_0_Hop from an access layer that pushes measurements.
    pub fn report_local_cbr(&mut self, cbr: f64) {
        if (0.0..=1.0).contains(&cbr) {
            self.cbr_l_0_hop = cbr;
        }
    }

    /// DCC-MCO field for the next SHB (clause 7.2.1).
    pub fn dcc_mco(&self) -> [u8; 4] {
        encode_dcc_mco(self.cbr_l_0_hop, self.cbr_l_1_hop, self.tx_power_dbm)
    }

    /// Update the LocTEX-G5 of a neighbour from a received, non-duplicate SHB
    /// (clauses 6.2.3 and 7.2.2). Not updated when the SHB has no DCC-MCO.
    pub fn update_loctex(
        &mut self,
        gn_addr: GNAddress,
        tst_so_pv: u32,
        field: &[u8],
        now_ms: u64,
        rssi_dbm: Option<f64>,
    ) -> bool {
        let Some((cbr_r_0_hop, cbr_r_1_hop, tx_power_dbm)) = decode_dcc_mco(field) else {
            return false;
        };
        self.loctex.insert(
            gn_addr.encode_to_int(),
            LocTexG5 {
                tst_g5_ms: now_ms,
                tst_so_pv,
                tx_power_dbm,
                rssi_dbm,
                cbr_r_0_hop,
                cbr_r_1_hop,
            },
        );
        true
    }

    /// LocTEX-G5 of a neighbour.
    pub fn loctex_of(&self, gn_addr: &GNAddress) -> Option<&LocTexG5> {
        self.loctex.get(&gn_addr.encode_to_int())
    }

    /// Next T_Trig expiry; the first one has a random offset within T_Trig.
    pub fn next_trigger(&mut self, now_ms: u64) -> u64 {
        if self.next_trigger_ms.is_none() {
            let offset = ((self.rng)() * self.trigger_interval_ms as f64) as u64;
            self.next_trigger_ms = Some(now_ms + offset);
        }
        self.next_trigger_ms.unwrap_or(now_ms)
    }

    /// Next T_Trig expiry if already scheduled (no side effects).
    pub fn scheduled_trigger(&self) -> Option<u64> {
        self.next_trigger_ms
    }

    /// Calculate CBR_G (steps 1 to 5 of clause 5.3), expire LocTEX-G5
    /// entries, read the new CBR_L_0_Hop and publish CBR_G. Returns CBR_G.
    pub fn trigger(&mut self, now_ms: u64) -> f64 {
        let local = self.local_cbr.as_mut().and_then(|p| p.measure_cbr());
        let lifetime = self.loctex_lifetime_ms;
        self.loctex
            .retain(|_, e| now_ms.saturating_sub(e.tst_g5_ms) <= lifetime);
        let recent: Vec<&LocTexG5> = self
            .loctex
            .values()
            .filter(|e| now_ms.saturating_sub(e.tst_g5_ms) <= self.cbr_lifetime_ms)
            .collect();
        let r0: Vec<f64> = recent.iter().map(|e| e.cbr_r_0_hop).collect();
        let r1: Vec<f64> = recent.iter().map(|e| e.cbr_r_1_hop).collect();
        self.cbr_l_1_hop = reduce(&r0, self.cbr_target);
        self.cbr_l_2_hop = reduce(&r1, self.cbr_target);
        // Step 5: CBR_G(n) = max(CBR_L_0_Hop(n-1), CBR_L_1_Hop(n), CBR_L_2_Hop(n))
        self.cbr_g = self.cbr_l_0_hop.max(self.cbr_l_1_hop).max(self.cbr_l_2_hop);
        if let Some(cbr) = local.filter(|c| (0.0..=1.0).contains(c)) {
            self.cbr_l_0_hop = cbr;
        }
        self.next_trigger_ms = Some(now_ms + self.trigger_interval_ms);
        self.global_cbr.report(self.cbr_g);
        self.cbr_g
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geonet::gn_address::{M, MID, ST};
    use crate::management::cbr::SharedCbr;

    fn addr(n: u8) -> GNAddress {
        GNAddress::new(M::GnUnicast, ST::Unknown, MID::new([2, 0, 0, 0, 0, n]))
    }

    fn dcc(offset: f64) -> DccNet {
        DccNet::new(None, 20.0).with_rng(Box::new(move || offset))
    }

    fn loctex(d: &mut DccNet, n: u8, r0: f64, r1: f64, now: u64) {
        d.update_loctex(addr(n), 0, &encode_dcc_mco(r0, r1, 20.0), now, None);
    }

    #[test]
    fn dcc_mco_encoding() {
        assert_eq!(encode_dcc_mco(0.5, 0.8, 20.0), [127, 204, 20, 0]);
        assert_eq!(encode_dcc_mco(1.0, 0.0, 40.0), [255, 0, 31, 0]);
        assert_eq!(encode_dcc_mco(0.0, 0.0, -3.0), [0, 0, 0, 0]);
    }

    #[test]
    fn dcc_mco_decoding() {
        assert_eq!(
            decode_dcc_mco(&[204, 51, 23, 0]),
            Some((204.0 / 255.0, 51.0 / 255.0, 23))
        );
        assert_eq!(decode_dcc_mco(&[0, 0, 0, 0]), None);
    }

    #[test]
    fn first_trigger_has_random_offset() {
        let mut d = dcc(0.5);
        assert_eq!(d.next_trigger(1000), 1050);
        d.trigger(1050);
        assert_eq!(d.next_trigger(1050), 1150);
    }

    #[test]
    fn maximum_above_target_second_largest_below() {
        let mut d = dcc(0.0);
        for (n, r0) in [(1u8, 0.9), (2, 0.8), (3, 0.7)] {
            loctex(&mut d, n, r0, 0.1 * n as f64, 0);
        }
        d.trigger(0);
        assert!((d.cbr_l_1_hop - 0.9).abs() < 0.01);
        assert!((d.cbr_l_2_hop - 0.2).abs() < 0.01);
        let mut d = dcc(0.0);
        for (n, r0) in [(1u8, 0.5), (2, 0.3), (3, 0.1)] {
            loctex(&mut d, n, r0, 0.0, 0);
        }
        d.trigger(0);
        assert!((d.cbr_l_1_hop - 0.3).abs() < 0.01);
    }

    /// Step 5: CBR_G(n) = max(CBR_L_0_Hop(n-1), CBR_L_1_Hop(n), CBR_L_2_Hop(n)).
    #[test]
    fn cbr_g_uses_previous_local_cbr() {
        let local = SharedCbr::new();
        let mut d = DccNet::new(Some(Box::new(local.clone())), 20.0).with_rng(Box::new(|| 0.0));
        local.report(0.7);
        assert_eq!(d.trigger(0), 0.0);
        assert_eq!(d.cbr_l_0_hop, 0.7);
        assert_eq!(d.trigger(100), 0.7);
        assert_eq!(d.global_cbr.latest(), Some(0.7));
    }

    /// Entries older than T_Cbr do not count; LocTEX-G5 expires.
    #[test]
    fn outdated_values_are_ignored() {
        let mut d = dcc(0.0);
        loctex(&mut d, 1, 0.9, 0.9, 0);
        d.trigger(500);
        assert!(d.cbr_l_1_hop > 0.8);
        d.trigger(1100);
        assert_eq!((d.cbr_l_1_hop, d.cbr_l_2_hop), (0.0, 0.0));
        assert!(d.loctex.is_empty());
    }

    /// DCC_CROSS: CBR_G is the input of the DCC algorithm (clause 5.3).
    #[test]
    fn global_cbr_drives_the_dcc_entity() {
        use crate::management::dcc_entity::{DccEntity, DccMode};
        let mut d = dcc(0.0);
        for n in [1u8, 2] {
            loctex(&mut d, n, 0.9, 0.0, 0);
        }
        d.trigger(0);
        let mut entity = DccEntity::new(DccMode::reactive(), Box::new(d.global_cbr.clone()));
        assert!(entity.evaluate().unwrap().t_gen_cam_dcc_ms > 100);
    }
}

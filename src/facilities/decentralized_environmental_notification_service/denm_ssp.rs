// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! DENM Service Specific Permissions (ETSI TS 103 831 V2.3.1 (2025-11),
//! clause 6.2.2.2).
//!
//! The SSP of a DENM Authorization Ticket is a BitmapSsp: octet 0 is the SSP
//! version, octets 1 to 4 hold one bit per cause code (Table 10). A DENM is
//! consistent with the SSP when the bit of its cause code is set.
//!
//! Mirrors `flexstack/facilities/decentralized_environmental_notification_service/denm_ssp.py`.

use super::denm_coder::{CauseCodeChoice, Denm};

/// Octet index and bit mask of a cause code value (Table 10).
pub fn cause_code_ssp_bit(cause_code: u8) -> Option<(usize, u8)> {
    Some(match cause_code {
        1 => (1, 0x80),
        2 => (1, 0x40),
        3 => (1, 0x20),
        6 => (1, 0x10),
        9 => (1, 0x08),
        10 => (1, 0x04),
        11 => (1, 0x02),
        12 => (1, 0x01),
        14 => (2, 0x80),
        15 => (2, 0x40),
        17 => (2, 0x20),
        18 => (2, 0x10),
        19 => (2, 0x08),
        26 => (2, 0x04),
        27 => (2, 0x02),
        91 => (2, 0x01),
        92 => (3, 0x80),
        93 => (3, 0x40),
        94 => (3, 0x20),
        95 => (3, 0x10),
        96 => (3, 0x08),
        97 => (3, 0x04),
        98 => (3, 0x02),
        99 => (3, 0x01),
        5 => (4, 0x80),
        7 => (4, 0x40),
        28 => (4, 0x20),
        100 => (4, 0x10),
        4 => (4, 0x08),
        20 => (4, 0x04),
        _ => return None,
    })
}

/// Cause code value of a CauseCodeChoice, from the alternative name, which
/// ends with the value (e.g. `accident2` -> 2), as in the Python stack.
pub fn cause_code_of_choice(choice: &CauseCodeChoice) -> Option<u8> {
    let debug = format!("{choice:?}");
    let name = debug.split('(').next().unwrap_or("");
    let digits: String = name
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

/// Cause code value of a DENM; `None` for a DENM without situation container.
pub fn cause_code_value(denm: &Denm) -> Option<u8> {
    denm.denm
        .situation
        .as_ref()
        .and_then(|s| cause_code_of_choice(&s.event_type.cc_and_scc))
}

/// True when the DENM SSP allows signing DENMs with `cause_code`. A cause
/// code without a Table 10 bit, or whose octet lies beyond the SSP length, is
/// not permitted.
pub fn ssp_permits_cause_code(ssp: &[u8], cause_code: u8) -> bool {
    match cause_code_ssp_bit(cause_code) {
        Some((octet, mask)) => octet < ssp.len() && ssp[octet] & mask != 0,
        None => false,
    }
}

/// SSP check of the receiving ITS-S (clause 8.4.2): true when no SSP is
/// available, when the DENM has no cause code (termination DENM), or when the
/// SSP permits the cause code.
pub fn ssp_consistent(ssp: Option<&[u8]>, denm: &Denm) -> bool {
    match ssp {
        None | Some([]) => true,
        Some(ssp) => match cause_code_value(denm) {
            None => true,
            Some(cause) => ssp_permits_cause_code(ssp, cause),
        },
    }
}

/// SSP bits a DENM needs (Table 10), as the `permissions` of the signing
/// request: the sign service only signs with an AT whose SSP grants them.
/// Octet 0 (SSP version) is not requested. A DENM without cause code (a
/// termination) or with a cause code without Table 10 bit requests none.
pub fn permissions_bitmap(denm: &Denm) -> Vec<u8> {
    match cause_code_value(denm).and_then(cause_code_ssp_bit) {
        Some((octet, mask)) => {
            let mut bitmap = vec![0u8; octet + 1];
            bitmap[octet] = mask;
            bitmap
        }
        None => vec![0],
    }
}

#[cfg(test)]
mod tests {
    use super::super::denm_coder::{AccidentSubCauseCode, CauseCodeChoice};
    use super::*;

    #[test]
    fn bits_of_table_10() {
        let ssp = [2u8, 0x40, 0x00, 0x10, 0x00]; // accident(2), emergencyVehicleApproaching(95)
        assert!(ssp_permits_cause_code(&ssp, 2));
        assert!(ssp_permits_cause_code(&ssp, 95));
        assert!(!ssp_permits_cause_code(&ssp, 1));
        assert!(!ssp_permits_cause_code(&ssp, 99));
    }

    #[test]
    fn release_2_code_needs_version_2_ssp() {
        let version_1 = [1u8, 0xFF, 0xFF, 0xFF];
        assert!(ssp_permits_cause_code(&version_1, 99));
        assert!(!ssp_permits_cause_code(&version_1, 5)); // octet 4
        assert!(ssp_permits_cause_code(&[1u8, 0xFF, 0xFF, 0xFF, 0x80], 5));
    }

    #[test]
    fn cause_code_from_choice_name() {
        let choice = CauseCodeChoice::accident2(AccidentSubCauseCode(3));
        assert_eq!(cause_code_of_choice(&choice), Some(2));
    }
}

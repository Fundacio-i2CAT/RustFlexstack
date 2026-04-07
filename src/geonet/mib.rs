// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use super::gn_address::{GNAddress, M, MID, ST};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LocalGnAddrConfMethod {
    Auto,
    Managed,
    Anonymous,
}

impl LocalGnAddrConfMethod {
    pub fn encode(&self) -> u8 {
        match self {
            LocalGnAddrConfMethod::Auto => 0,
            LocalGnAddrConfMethod::Managed => 1,
            LocalGnAddrConfMethod::Anonymous => 2,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => LocalGnAddrConfMethod::Auto,
            1 => LocalGnAddrConfMethod::Managed,
            2 => LocalGnAddrConfMethod::Anonymous,
            _ => panic!("Invalid LocalGnAddrConfMethod Value"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GnIsMobile {
    Stationary,
    Mobile,
}

impl GnIsMobile {
    pub fn encode(&self) -> u8 {
        match self {
            GnIsMobile::Stationary => 0,
            GnIsMobile::Mobile => 1,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => GnIsMobile::Stationary,
            1 => GnIsMobile::Mobile,
            _ => panic!("Invalid GnIsMobile Value"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GnIfType {
    Unspecified,
    ItsG5,
    LteV2x,
}

impl GnIfType {
    pub fn encode(&self) -> u8 {
        match self {
            GnIfType::Unspecified => 0,
            GnIfType::ItsG5 => 1,
            GnIfType::LteV2x => 2,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => GnIfType::Unspecified,
            1 => GnIfType::ItsG5,
            2 => GnIfType::LteV2x,
            _ => panic!("Invalid GnIfType Value"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GnSecurity {
    Disabled,
    Enabled,
}

impl GnSecurity {
    pub fn encode(&self) -> u8 {
        match self {
            GnSecurity::Disabled => 0,
            GnSecurity::Enabled => 1,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => GnSecurity::Disabled,
            1 => GnSecurity::Enabled,
            _ => panic!("Invalid GnSecurity Value"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SnDecapResultHandling {
    Strict,
    NonStrict,
}

impl SnDecapResultHandling {
    pub fn encode(&self) -> u8 {
        match self {
            SnDecapResultHandling::Strict => 0,
            SnDecapResultHandling::NonStrict => 1,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => SnDecapResultHandling::Strict,
            1 => SnDecapResultHandling::NonStrict,
            _ => panic!("Invalid SnDecapResultHandling Value"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NonAreaForwardingAlgorithm {
    Unspecified,
    Greedy,
}

impl NonAreaForwardingAlgorithm {
    pub fn encode(&self) -> u8 {
        match self {
            NonAreaForwardingAlgorithm::Unspecified => 0,
            NonAreaForwardingAlgorithm::Greedy => 1,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => NonAreaForwardingAlgorithm::Unspecified,
            1 => NonAreaForwardingAlgorithm::Greedy,
            _ => panic!("Invalid NonAreaForwardingAlgorithm Value"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AreaForwardingAlgorithm {
    Unspecified,
    Simple,
    Cbf,
}

impl AreaForwardingAlgorithm {
    pub fn encode(&self) -> u8 {
        match self {
            AreaForwardingAlgorithm::Unspecified => 0,
            AreaForwardingAlgorithm::Simple => 1,
            AreaForwardingAlgorithm::Cbf => 2,
        }
    }

    pub fn decode(value: u8) -> Self {
        match value {
            0 => AreaForwardingAlgorithm::Unspecified,
            1 => AreaForwardingAlgorithm::Simple,
            2 => AreaForwardingAlgorithm::Cbf,
            _ => panic!("Invalid AreaForwardingAlgorithm Value"),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mib {
    pub itsGnLocalGnAddr: GNAddress,
    pub itsGnLocalGnAddrConfMethod: LocalGnAddrConfMethod,
    pub itsGnProtocolVersion: u8,
    pub itsGnIsMobile: GnIsMobile,
    pub itsGnIfType: GnIfType,
    pub itsGnMinUpdateFrequencyEPV: u16,
    pub itsGnPaiInterval: u8,
    pub itsGnMaxSduSize: u16,
    pub itsGnMaxGeoNetworkingHeaderSize: u16,
    pub itsGnLifetimeLocTE: u16,
    pub itsGnSecurity: GnSecurity,
    pub itsGnSnDecapResultHandling: SnDecapResultHandling,
    pub itsGnLocationServiceMaxRetrans: u8,
    pub itsGnLocationServiceRetransmitTimer: u16,
    pub itsGnLocationServicePacketBufferSize: u16,
    pub itsGnBeaconServiceRetransmitTimer: u16,
    pub itsGnBeaconServiceMaxJitter: u16,
    pub itsGnDefaultHopLimit: u8,
    pub itsGnDPLLength: u8,
    pub itsGnMaxPacketLifetime: u16,
    pub itsGnDefaultPacketLifetime: u8,
    pub itsGnMaxPacketDataRate: u32,
    pub itsGnMaxPacketDataRateEmaBeta: u8,
    pub itsGnMaxGeoAreaSize: u16,
    pub itsGnMinPacketRepetitionInterval: u16,
    pub itsGnNonAreaForwardingAlgorithm: NonAreaForwardingAlgorithm,
    pub itsGnAreaForwardingAlgorithm: AreaForwardingAlgorithm,
    pub itsGnCbfMinTime: u16,
    pub itsGnCbfMaxTime: u16,
    pub itsGnDefaultMaxCommunicationRange: u16,
    pub itsGnBroadcastCBFDefSectorAngle: u8,
    pub itsGnUcForwardingPacketBufferSize: u16,
    pub itsGnBcForwardingPacketBufferSize: u16,
    pub itsGnCbfPacketBufferSize: u16,
    pub itsGnDefaultTrafficClass: u8,
}

impl Default for Mib {
    fn default() -> Self {
        Self::new()
    }
}

impl Mib {
    pub fn new() -> Self {
        {
            Mib {
                itsGnLocalGnAddr: GNAddress::new(
                    M::GnUnicast,
                    ST::Unknown,
                    MID::new([0, 0, 0, 0, 0, 0]),
                ),
                itsGnLocalGnAddrConfMethod: LocalGnAddrConfMethod::Auto,
                itsGnProtocolVersion: 1,
                itsGnIsMobile: GnIsMobile::Mobile,
                itsGnIfType: GnIfType::Unspecified,
                itsGnMinUpdateFrequencyEPV: 1000,
                itsGnPaiInterval: 80,
                itsGnMaxSduSize: 1398,
                itsGnMaxGeoNetworkingHeaderSize: 88,
                itsGnLifetimeLocTE: 20,
                itsGnSecurity: GnSecurity::Disabled,
                itsGnSnDecapResultHandling: SnDecapResultHandling::Strict,
                itsGnLocationServiceMaxRetrans: 10,
                itsGnLocationServiceRetransmitTimer: 1000,
                itsGnLocationServicePacketBufferSize: 1024,
                itsGnBeaconServiceRetransmitTimer: 3000,
                itsGnBeaconServiceMaxJitter: 3000 / 4,
                itsGnDefaultHopLimit: 10,
                itsGnDPLLength: 8,
                itsGnMaxPacketLifetime: 600,
                itsGnDefaultPacketLifetime: 60,
                itsGnMaxPacketDataRate: 100,
                itsGnMaxPacketDataRateEmaBeta: 90,
                itsGnMaxGeoAreaSize: 10,
                itsGnMinPacketRepetitionInterval: 100,
                itsGnNonAreaForwardingAlgorithm: NonAreaForwardingAlgorithm::Greedy,
                itsGnAreaForwardingAlgorithm: AreaForwardingAlgorithm::Cbf,
                itsGnCbfMinTime: 1,
                itsGnCbfMaxTime: 100,
                itsGnDefaultMaxCommunicationRange: 1000,
                itsGnBroadcastCBFDefSectorAngle: 30,
                itsGnUcForwardingPacketBufferSize: 256,
                itsGnBcForwardingPacketBufferSize: 1024,
                itsGnCbfPacketBufferSize: 256,
                itsGnDefaultTrafficClass: 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mib_default_values() {
        let mib = Mib::new();
        assert_eq!(mib.itsGnProtocolVersion, 1);
        assert_eq!(mib.itsGnDefaultHopLimit, 10);
        assert_eq!(mib.itsGnMaxSduSize, 1398);
        assert_eq!(mib.itsGnDefaultPacketLifetime, 60);
        assert_eq!(mib.itsGnMaxPacketLifetime, 600);
        assert_eq!(mib.itsGnBeaconServiceRetransmitTimer, 3000);
        assert!(matches!(mib.itsGnIsMobile, GnIsMobile::Mobile));
        assert!(matches!(mib.itsGnSecurity, GnSecurity::Disabled));
        assert!(matches!(
            mib.itsGnNonAreaForwardingAlgorithm,
            NonAreaForwardingAlgorithm::Greedy
        ));
        assert!(matches!(
            mib.itsGnAreaForwardingAlgorithm,
            AreaForwardingAlgorithm::Cbf
        ));
    }

    #[test]
    fn mib_copy() {
        let mib1 = Mib::new();
        let mib2 = mib1;
        assert_eq!(mib1, mib2);
    }

    #[test]
    fn local_gn_addr_conf_method_roundtrip() {
        for val in 0..3u8 {
            assert_eq!(LocalGnAddrConfMethod::decode(val).encode(), val);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid LocalGnAddrConfMethod Value")]
    fn local_gn_addr_conf_method_invalid() {
        LocalGnAddrConfMethod::decode(99);
    }

    #[test]
    fn gn_is_mobile_roundtrip() {
        assert_eq!(GnIsMobile::Stationary.encode(), 0);
        assert_eq!(GnIsMobile::Mobile.encode(), 1);
        assert_eq!(GnIsMobile::decode(0).encode(), 0);
        assert_eq!(GnIsMobile::decode(1).encode(), 1);
    }

    #[test]
    #[should_panic(expected = "Invalid GnIsMobile Value")]
    fn gn_is_mobile_invalid() {
        GnIsMobile::decode(99);
    }

    #[test]
    fn gn_if_type_roundtrip() {
        for val in 0..3u8 {
            assert_eq!(GnIfType::decode(val).encode(), val);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid GnIfType Value")]
    fn gn_if_type_invalid() {
        GnIfType::decode(99);
    }

    #[test]
    fn gn_security_roundtrip() {
        assert_eq!(GnSecurity::Disabled.encode(), 0);
        assert_eq!(GnSecurity::Enabled.encode(), 1);
    }

    #[test]
    #[should_panic(expected = "Invalid GnSecurity Value")]
    fn gn_security_invalid() {
        GnSecurity::decode(99);
    }

    #[test]
    fn sn_decap_result_handling_roundtrip() {
        assert_eq!(SnDecapResultHandling::Strict.encode(), 0);
        assert_eq!(SnDecapResultHandling::NonStrict.encode(), 1);
    }

    #[test]
    #[should_panic(expected = "Invalid SnDecapResultHandling Value")]
    fn sn_decap_result_handling_invalid() {
        SnDecapResultHandling::decode(99);
    }

    #[test]
    fn non_area_forwarding_algorithm_roundtrip() {
        assert_eq!(NonAreaForwardingAlgorithm::Unspecified.encode(), 0);
        assert_eq!(NonAreaForwardingAlgorithm::Greedy.encode(), 1);
    }

    #[test]
    #[should_panic(expected = "Invalid NonAreaForwardingAlgorithm Value")]
    fn non_area_forwarding_algorithm_invalid() {
        NonAreaForwardingAlgorithm::decode(99);
    }

    #[test]
    fn area_forwarding_algorithm_roundtrip() {
        for val in 0..3u8 {
            assert_eq!(AreaForwardingAlgorithm::decode(val).encode(), val);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid AreaForwardingAlgorithm Value")]
    fn area_forwarding_algorithm_invalid() {
        AreaForwardingAlgorithm::decode(99);
    }
}

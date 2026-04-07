// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

pub const ETH_P_GEONET: u16 = 0x8947;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eth_p_geonet_value() {
        assert_eq!(ETH_P_GEONET, 0x8947);
    }

    #[test]
    fn eth_p_geonet_big_endian_bytes() {
        let bytes = ETH_P_GEONET.to_be_bytes();
        assert_eq!(bytes, [0x89, 0x47]);
    }
}

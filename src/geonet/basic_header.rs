// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

use super::mib::Mib;

#[derive(Clone, Copy, Debug)]
pub enum BasicNH{
    Any,
    CommonHeader,
    SecuredPacket,
}

impl BasicNH{
    pub fn encode(&self) -> u8{
        match self{
            BasicNH::Any => {0},
            BasicNH::CommonHeader => {1},
            BasicNH::SecuredPacket => {2},
        }
    }

    pub fn decode(value : u8) -> Self{
        match value {
            0 => BasicNH::Any,
            1 => BasicNH::CommonHeader,
            2 => BasicNH::SecuredPacket,
            _ => panic!("Invalid BasicNH Value"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum LTBase{
    FiftyMilliseconds,
    OneSecond,
    TenSeconds,
    OneHundredSeconds,
}

impl LTBase{
    pub fn decode(value : u8) -> Self{
        match value {
            0 => LTBase::FiftyMilliseconds,
            1 => LTBase::OneSecond,
            2 => LTBase::TenSeconds,
            3 => LTBase::OneHundredSeconds,
            _ => panic!("Invalid LTBase Value"),
        }
    }

    pub fn encode(&self) -> u8{
        match self {
            LTBase::FiftyMilliseconds => {0},
            LTBase::OneSecond => {1},
            LTBase::TenSeconds => {2},
            LTBase::OneHundredSeconds => {3},
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LT{
    multiplier : u8,
    base : LTBase,
}

impl LT{
    pub fn start_in_milliseconds(value : u32) -> Self{
        if value >= 100000{
            return LT {
                multiplier : (value / 100000) as u8,
                base : LTBase::OneHundredSeconds,
            }
        }else if value >= 10000{
            return LT {
                multiplier : (value / 10000) as u8,
                base : LTBase::TenSeconds,
            }
        }else if value >= 1000{
            return LT {
                multiplier : (value / 1000) as u8,
                base : LTBase::OneSecond,
            }
        }else if value >= 50{
            return LT {
                multiplier : (value / 50) as u8,
                base : LTBase::FiftyMilliseconds,
            }
        }else{
            panic!("Invalid LT Value");
        }
    }
    pub fn start_in_seconds(value : u8) -> Self{
        LT::start_in_milliseconds(value as u32 * 1000)
    }

    pub fn get_value_in_milliseconds(&self) -> u32{
        match self.base{
            LTBase::FiftyMilliseconds => {50 * self.multiplier as u32},
            LTBase::OneSecond => {1000 * self.multiplier as u32},
            LTBase::TenSeconds => {10000 * self.multiplier as u32},
            LTBase::OneHundredSeconds => {100000 * self.multiplier as u32},
        }
    }
    pub fn get_value_in_seconds(&self) -> u8{
        (self.get_value_in_milliseconds() / 1000) as u8
    }
    pub fn encode(&self) -> u8{
        self.multiplier << 2 | (self.base.encode() & 0x3) 
    }

    pub fn decode(value : u8) -> Self{
        LT{
            multiplier : value >> 2,
            base : LTBase::decode(value & 0x3),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BasicHeader{
    pub version : u8,
    pub nh : BasicNH,
    pub reserved : u8,
    pub lt : LT,
    pub rhl : u8,

}

impl BasicHeader{
    pub fn decode(bytes : [u8; 4]) -> Self{
        BasicHeader{
            version : bytes[0] >> 4,
            nh : BasicNH::decode(bytes[0] & 0xF),
            reserved : 0,
            lt : LT::decode(bytes[2]),
            rhl : bytes[3],
        }
    }

    pub fn initialize_with_mib(mib : &Mib) -> Self{
        BasicHeader{
            version : mib.itsGnProtocolVersion.clone(),
            nh : BasicNH::CommonHeader,
            rhl : mib.itsGnDefaultHopLimit.clone(),
            reserved : 0,
            lt : LT::start_in_seconds(mib.itsGnDefaultPacketLifetime.clone())
        }
    }

    pub fn encode(&self) -> [u8; 4]{
        [self.version << 4 | self.nh.encode(), self.reserved, self.lt.encode(), self.rhl]
    }
}
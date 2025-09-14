//! User Access Privileges Configuration Registers

use bitfields::bitfield;

use super::access_flag::AccessFlag;
use super::*;

const DEFAULT_ACCESS_FLAG: AccessFlag = AccessFlag::from_bits(0b11110000);

#[bitfield(u32, default = true)]
#[derive(Clone, Copy, PartialEq)]
pub struct PairingKeyWrite {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot1: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot2: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot3: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for PairingKeyWrite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("ApplicationUap")
                .field("slot0", &self.slot0())
                .field("slot1", &self.slot1())
                .field("slot2", &self.slot2())
                .field("slot3", &self.slot3())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0: {}, slot1: {}, slot2: {}, slot3: {}",
                self.slot0(),
                self.slot1(),
                self.slot2(),
                self.slot3(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct PairingKeyRead {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot1: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot2: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot3: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for PairingKeyRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("PairingKeyRead")
                .field("slot0", &self.slot0())
                .field("slot1", &self.slot1())
                .field("slot2", &self.slot2())
                .field("slot3", &self.slot3())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0: {}, slot1: {}, slot2: {}, slot3: {}",
                self.slot0(),
                self.slot1(),
                self.slot2(),
                self.slot3(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct PairingKeyInvalidate {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot1: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot2: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot3: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for PairingKeyInvalidate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("PairingKeyInvalidate")
                .field("slot0", &self.slot0())
                .field("slot1", &self.slot1())
                .field("slot2", &self.slot2())
                .field("slot3", &self.slot3())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0: {}, slot1: {}, slot2: {}, slot3: {}",
                self.slot0(),
                self.slot1(),
                self.slot2(),
                self.slot3(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct RConfigWriteErase {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    write_erase: AccessFlag,
    #[bits(24)]
    reserved: u32,
}

#[cfg(feature = "display")]
impl core::fmt::Display for RConfigWriteErase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("RConfigWriteErase")
                .field("write_erase", &self.write_erase())
                .finish()
        } else {
            f.write_fmt(format_args!("write_erase: {}", self.write_erase()))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct RConfigRead {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    read_cfg: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    read_func: AccessFlag,
    #[bits(16)]
    reserved: u16,
}

#[cfg(feature = "display")]
impl core::fmt::Display for RConfigRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("RConfigRead")
                .field("read_cfg", &self.read_cfg())
                .field("read_func", &self.read_func())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "read_cfg: {}, read_func: {}",
                self.read_cfg(),
                self.read_func()
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct IConfigWrite {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    write_cfg: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    write_func: AccessFlag,
    #[bits(16)]
    reserved: u16,
}

#[cfg(feature = "display")]
impl core::fmt::Display for IConfigWrite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("IConfigWrite")
                .field("write_cfg", &self.write_cfg())
                .field("write_func", &self.write_func())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "write_cfg: {}, write_func: {}",
                self.write_cfg(),
                self.write_func()
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct IConfigRead {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    read_cfg: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    read_func: AccessFlag,
    #[bits(16)]
    reserved: u16,
}

#[cfg(feature = "display")]
impl core::fmt::Display for IConfigRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("IConfigRead")
                .field("read_cfg", &self.read_cfg())
                .field("read_func", &self.read_func())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "read_cfg: {}, read_func: {}",
                self.read_cfg(),
                self.read_func()
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct Ping {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    ping: AccessFlag,
    #[bits(24)]
    reserved: u32,
}

#[cfg(feature = "display")]
impl core::fmt::Display for Ping {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("Ping").field("ping", &self.ping()).finish()
        } else {
            f.write_fmt(format_args!("ping: {}", self.ping()))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct RMemDataWrite {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_127: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot128_255: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot256_383: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot384_511: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for RMemDataWrite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("RMemDataWrite")
                .field("slot0_127", &self.slot0_127())
                .field("slot128_255", &self.slot128_255())
                .field("slot256_383", &self.slot256_383())
                .field("slot384_511", &self.slot384_511())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_127: {}, slot128_255: {}, slot256_383: {}, slot384_511: {}",
                self.slot0_127(),
                self.slot128_255(),
                self.slot256_383(),
                self.slot384_511(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct RMemDataRead {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_127: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot128_255: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot256_383: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot384_511: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for RMemDataRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("RMemDataRead")
                .field("slot0_127", &self.slot0_127())
                .field("slot128_255", &self.slot128_255())
                .field("slot256_383", &self.slot256_383())
                .field("slot384_511", &self.slot384_511())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_127: {}, slot128_255: {}, slot256_383: {}, slot384_511: {}",
                self.slot0_127(),
                self.slot128_255(),
                self.slot256_383(),
                self.slot384_511(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct RMemDataErase {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_127: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot128_255: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot256_383: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot384_511: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for RMemDataErase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("RMemDataErase")
                .field("slot0_127", &self.slot0_127())
                .field("slot128_255", &self.slot128_255())
                .field("slot256_383", &self.slot256_383())
                .field("slot384_511", &self.slot384_511())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_127: {}, slot128_255: {}, slot256_383: {}, slot384_511: {}",
                self.slot0_127(),
                self.slot128_255(),
                self.slot256_383(),
                self.slot384_511(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct RandomValueGet {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    get: AccessFlag,
    #[bits(24)]
    reserved: u32,
}

#[cfg(feature = "display")]
impl core::fmt::Display for RandomValueGet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("RandomValueGet")
                .field("get", &self.get())
                .finish()
        } else {
            f.write_fmt(format_args!("get: {}", self.get(),))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct EccKeyGenerate {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot8_15: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot16_23: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot24_31: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for EccKeyGenerate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("EccKeyGenerate")
                .field("slot0_7", &self.slot0_7())
                .field("slot8_15", &self.slot8_15())
                .field("slot16_23", &self.slot16_23())
                .field("slot24_31", &self.slot24_31())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_7: {}, slot8_15: {}, slot16_23: {}, slot24_31: {}",
                self.slot0_7(),
                self.slot8_15(),
                self.slot16_23(),
                self.slot24_31(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct EccKeyStore {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot8_15: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot16_23: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot24_31: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for EccKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("EccKeyStore")
                .field("slot0_7", &self.slot0_7())
                .field("slot8_15", &self.slot8_15())
                .field("slot16_23", &self.slot16_23())
                .field("slot24_31", &self.slot24_31())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_7: {}, slot8_15: {}, slot16_23: {}, slot24_31: {}",
                self.slot0_7(),
                self.slot8_15(),
                self.slot16_23(),
                self.slot24_31(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct EccKeyRead {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot8_15: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot16_23: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot24_31: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for EccKeyRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("EccKeyRead")
                .field("slot0_7", &self.slot0_7())
                .field("slot8_15", &self.slot8_15())
                .field("slot16_23", &self.slot16_23())
                .field("slot24_31", &self.slot24_31())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_7: {}, slot8_15: {}, slot16_23: {}, slot24_31: {}",
                self.slot0_7(),
                self.slot8_15(),
                self.slot16_23(),
                self.slot24_31(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct EccKeyErase {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot8_15: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot16_23: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot24_31: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for EccKeyErase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("EccKeyErase")
                .field("slot0_7", &self.slot0_7())
                .field("slot8_15", &self.slot8_15())
                .field("slot16_23", &self.slot16_23())
                .field("slot24_31", &self.slot24_31())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_7: {}, slot8_15: {}, slot16_23: {}, slot24_31: {}",
                self.slot0_7(),
                self.slot8_15(),
                self.slot16_23(),
                self.slot24_31(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct EcdsaSign {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot8_15: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot16_23: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot24_31: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for EcdsaSign {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("EcdsaSign")
                .field("slot0_7", &self.slot0_7())
                .field("slot8_15", &self.slot8_15())
                .field("slot16_23", &self.slot16_23())
                .field("slot24_31", &self.slot24_31())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_7: {}, slot8_15: {}, slot16_23: {}, slot24_31: {}",
                self.slot0_7(),
                self.slot8_15(),
                self.slot16_23(),
                self.slot24_31(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct EddsaSign {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot0_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot8_15: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot16_23: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    slot24_31: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for EddsaSign {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("EddsaSign")
                .field("slot0_7", &self.slot0_7())
                .field("slot8_15", &self.slot8_15())
                .field("slot16_23", &self.slot16_23())
                .field("slot24_31", &self.slot24_31())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "slot0_7: {}, slot8_15: {}, slot16_23: {}, slot24_31: {}",
                self.slot0_7(),
                self.slot8_15(),
                self.slot16_23(),
                self.slot24_31(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct McounterInit {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc0_3: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc4_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc8_11: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc12_15: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for McounterInit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("McounterInit")
                .field("mc0_3", &self.mc0_3())
                .field("mc4_7", &self.mc4_7())
                .field("mc8_11", &self.mc8_11())
                .field("mc12_15", &self.mc12_15())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "mc0_3: {}, mc4_7: {}, mc8_11: {}, mc12_15: {}",
                self.mc0_3(),
                self.mc4_7(),
                self.mc8_11(),
                self.mc12_15(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct McounterGet {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc0_3: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc4_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc8_11: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc12_15: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for McounterGet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("McounterGet")
                .field("mc0_3", &self.mc0_3())
                .field("mc4_7", &self.mc4_7())
                .field("mc8_11", &self.mc8_11())
                .field("mc12_15", &self.mc12_15())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "mc0_3: {}, mc4_7: {}, mc8_11: {}, mc12_15: {}",
                self.mc0_3(),
                self.mc4_7(),
                self.mc8_11(),
                self.mc12_15(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct McounterUpdate {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc0_3: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc4_7: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc8_11: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mc12_15: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for McounterUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("McounterUpdate")
                .field("mc0_3", &self.mc0_3())
                .field("mc4_7", &self.mc4_7())
                .field("mc8_11", &self.mc8_11())
                .field("mc12_15", &self.mc12_15())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "mc0_3: {}, mc4_7: {}, mc8_11: {}, mc12_15: {}",
                self.mc0_3(),
                self.mc4_7(),
                self.mc8_11(),
                self.mc12_15(),
            ))
        }
    }
}

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct MacAndDestroy {
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mad0_31: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mad32_63: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mad64_95: AccessFlag,
    #[bits(8, default = DEFAULT_ACCESS_FLAG)]
    mad96_127: AccessFlag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for MacAndDestroy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("MacAndDestroy")
                .field("mad0_31", &self.mad0_31())
                .field("mad32_63", &self.mad32_63())
                .field("mad64_95", &self.mad64_95())
                .field("mad96_127", &self.mad96_127())
                .finish()
        } else {
            f.write_fmt(format_args!(
                "mad0_31: {}, mad32_63: {}, mad64_95: {}, mad96_127: {}",
                self.mad0_31(),
                self.mad32_63(),
                self.mad64_95(),
                self.mad96_127(),
            ))
        }
    }
}

implement_register_traits_for_bitfield!(PairingKeyWriteRegAddr, PairingKeyWrite, 0x20, 0x0);
implement_register_traits_for_bitfield!(PairingKeyReadRegAddr, PairingKeyRead, 0x24, 0x0);
implement_register_traits_for_bitfield!(
    PairingKeyInvalidateRegAddr,
    PairingKeyInvalidate,
    0x28,
    0x0
);
implement_register_traits_for_bitfield!(RConfigWriteEraseRegAddr, RConfigWriteErase, 0x30, 0x0);
implement_register_traits_for_bitfield!(RConfigReadRegAddr, RConfigRead, 0x34, 0x0);
implement_register_traits_for_bitfield!(IConfigWriteRegAddr, IConfigWrite, 0x40, 0x0);
implement_register_traits_for_bitfield!(IConfigReadRegAddr, IConfigRead, 0x44, 0x0);
implement_register_traits_for_bitfield!(PingRegAddr, Ping, 0x00, 0x01);
implement_register_traits_for_bitfield!(RMemDataWriteRegAddr, RMemDataWrite, 0x10, 0x01);
implement_register_traits_for_bitfield!(RMemDataReadRegAddr, RMemDataRead, 0x14, 0x01);
implement_register_traits_for_bitfield!(RMemDataEraseRegAddr, RMemDataErase, 0x18, 0x01);
implement_register_traits_for_bitfield!(RandomValueGetRegAddr, RandomValueGet, 0x20, 0x01);
implement_register_traits_for_bitfield!(EccKeyGenerateRegAddr, EccKeyGenerate, 0x30, 0x01);
implement_register_traits_for_bitfield!(EccKeyStoreRegAddr, EccKeyStore, 0x34, 0x01);
implement_register_traits_for_bitfield!(EccKeyReadRegAddr, EccKeyRead, 0x38, 0x01);
implement_register_traits_for_bitfield!(EccKeyEraseRegAddr, EccKeyErase, 0x3c, 0x01);
implement_register_traits_for_bitfield!(EcdsaSignRegAddr, EcdsaSign, 0x40, 0x01);
implement_register_traits_for_bitfield!(EddsaSignRegAddr, EddsaSign, 0x44, 0x01);
implement_register_traits_for_bitfield!(McounterInitRegAddr, McounterInit, 0x50, 0x01);
implement_register_traits_for_bitfield!(McounterGetRegAddr, McounterGet, 0x54, 0x01);
implement_register_traits_for_bitfield!(McounterUpdateRegAddr, McounterUpdate, 0x58, 0x01);
implement_register_traits_for_bitfield!(MacAndDestroyRegAddr, MacAndDestroy, 0x60, 0x01);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ApplicationUap {
    pub pairing_key_write: PairingKeyWrite,
    pub pairing_key_read: PairingKeyRead,
    pub pairing_key_invalidate: PairingKeyInvalidate,
    pub r_config_write_erase: RConfigWriteErase,
    pub r_config_read: RConfigRead,
    pub i_config_write: IConfigWrite,
    pub i_config_read: IConfigRead,
    pub ping: Ping,
    pub r_mem_data_write: RMemDataWrite,
    pub r_mem_data_read: RMemDataRead,
    pub r_mem_data_erase: RMemDataErase,
    pub random_value_get: RandomValueGet,
    pub ecc_key_generate: EccKeyGenerate,
    pub ecc_key_store: EccKeyStore,
    pub ecc_key_read: EccKeyRead,
    pub ecc_key_erase: EccKeyErase,
    pub ecdsa_sign: EcdsaSign,
    pub eddsa_sifn: EddsaSign,
    pub mcounter_init: McounterInit,
    pub mcounter_get: McounterGet,
    pub mcounter_update: McounterUpdate,
    pub mac_and_destroy: MacAndDestroy,
}

#[cfg(feature = "config-iter")]
impl ApplicationUap {
    pub fn iter(&self) -> ApplicationUapIter {
        ApplicationUapIter {
            index: 0,
            uap: *self,
        }
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for ApplicationUap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("ApplicationUap")
                .field("pairing_key_write", &self.pairing_key_write)
                .field("pairing_key_read", &self.pairing_key_read)
                .field("pairing_key_invalidate", &self.pairing_key_invalidate)
                .field("r_config_write_erase", &self.r_config_write_erase)
                .field("r_config_read", &self.r_config_read)
                .field("i_config_write", &self.i_config_write)
                .field("i_config_read", &self.i_config_read)
                .field("ping", &self.ping)
                .field("r_mem_data_write", &self.r_mem_data_write)
                .field("r_mem_data_read", &self.r_mem_data_read)
                .field("r_mem_data_erase", &self.r_mem_data_erase)
                .field("random_value_get", &self.random_value_get)
                .field("ecc_key_generate", &self.ecc_key_generate)
                .field("ecc_key_store", &self.ecc_key_store)
                .field("ecc_key_read", &self.ecc_key_read)
                .field("ecc_key_erase", &self.ecc_key_erase)
                .field("ecdsa_sign", &self.ecdsa_sign)
                .field("eddsa_sifn", &self.eddsa_sifn)
                .field("mcounter_init", &self.mcounter_init)
                .field("mcounter_get", &self.mcounter_get)
                .field("mcounter_update", &self.mcounter_update)
                .field("mac_and_destroy", &self.mac_and_destroy)
                .finish()
        } else {
            f.write_fmt(format_args!("pairing_key_write: {},pairing_key_read: {},pairing_key_invalidate: {},r_config_write_erase: {},r_config_read: {}, i_config_write: {}, i_config_read: {}, ping: {}, r_mem_data_write: {}, r_mem_data_read: {}, r_mem_data_erase: {}, random_value_get: {}, ecc_key_generate: {}, ecc_key_store: {}, ecc_key_read: {}, ecc_key_erase: {}, ecdsa_sign: {}, eddsa_sifn: {}, mcounter_init: {}, mcounter_get: {}, mcounter_update: {}, mac_and_destroy: {}",
                self.pairing_key_write,
                self.pairing_key_read,
                self.pairing_key_invalidate,
                self.r_config_write_erase,
                self.r_config_read,
                self.i_config_write,
                self.i_config_read,
                self.ping,
                self.r_mem_data_write,
                self.r_mem_data_read,
                self.r_mem_data_erase,
                self.random_value_get,
                self.ecc_key_generate,
                self.ecc_key_store,
                self.ecc_key_read,
                self.ecc_key_erase,
                self.ecdsa_sign,
                self.eddsa_sifn,
                self.mcounter_init,
                self.mcounter_get,
                self.mcounter_update,
                self.mac_and_destroy,))
        }
    }
}

#[cfg(feature = "config-iter")]
pub struct ApplicationUapIter {
    index: usize,
    uap: ApplicationUap,
}

#[cfg(feature = "config-iter")]
impl core::iter::Iterator for ApplicationUapIter {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        let next = match self.index {
            0 => Some(Entry {
                name: "PairingKeyWrite",
                addr: PairingKeyWriteRegAddr {}.register_addr(),
                value: self.uap.pairing_key_write.into_bits(),
            }),
            1 => Some(Entry {
                name: "PairingKeyRead",
                addr: PairingKeyReadRegAddr {}.register_addr(),
                value: self.uap.pairing_key_read.into_bits(),
            }),
            2 => Some(Entry {
                name: "PairingKeyInvalidate",
                addr: PairingKeyInvalidateRegAddr {}.register_addr(),
                value: self.uap.pairing_key_invalidate.into_bits(),
            }),
            3 => Some(Entry {
                name: "RConfigWriteErase",
                addr: RConfigWriteEraseRegAddr {}.register_addr(),
                value: self.uap.r_config_write_erase.into_bits(),
            }),
            4 => Some(Entry {
                name: "RConfigRead",
                addr: RConfigReadRegAddr {}.register_addr(),
                value: self.uap.r_config_read.into_bits(),
            }),
            5 => Some(Entry {
                name: "IConfigWrite",
                addr: IConfigWriteRegAddr {}.register_addr(),
                value: self.uap.i_config_write.into_bits(),
            }),
            6 => Some(Entry {
                name: "IConfigRead",
                addr: IConfigReadRegAddr {}.register_addr(),
                value: self.uap.i_config_read.into_bits(),
            }),
            7 => Some(Entry {
                name: "Ping",
                addr: PingRegAddr {}.register_addr(),
                value: self.uap.ping.into_bits(),
            }),
            8 => Some(Entry {
                name: "RMemDataWrite",
                addr: RMemDataWriteRegAddr {}.register_addr(),
                value: self.uap.r_mem_data_write.into_bits(),
            }),
            9 => Some(Entry {
                name: "RMemDataRead",
                addr: RMemDataReadRegAddr {}.register_addr(),
                value: self.uap.r_mem_data_read.into_bits(),
            }),
            10 => Some(Entry {
                name: "RMemDataErase",
                addr: RMemDataEraseRegAddr {}.register_addr(),
                value: self.uap.r_mem_data_erase.into_bits(),
            }),
            11 => Some(Entry {
                name: "RandomValueGet",
                addr: RandomValueGetRegAddr {}.register_addr(),
                value: self.uap.random_value_get.into_bits(),
            }),
            12 => Some(Entry {
                name: "EccKeyGenerate",
                addr: EccKeyGenerateRegAddr {}.register_addr(),
                value: self.uap.ecc_key_generate.into_bits(),
            }),
            13 => Some(Entry {
                name: "EccKeyStore",
                addr: EccKeyStoreRegAddr {}.register_addr(),
                value: self.uap.ecc_key_store.into_bits(),
            }),
            14 => Some(Entry {
                name: "EccKeyRead",
                addr: EccKeyReadRegAddr {}.register_addr(),
                value: self.uap.ecc_key_read.into_bits(),
            }),
            15 => Some(Entry {
                name: "EccKeyErase",
                addr: EccKeyEraseRegAddr {}.register_addr(),
                value: self.uap.ecc_key_erase.into_bits(),
            }),
            16 => Some(Entry {
                name: "EcdsaSign",
                addr: EcdsaSignRegAddr {}.register_addr(),
                value: self.uap.ecdsa_sign.into_bits(),
            }),
            17 => Some(Entry {
                name: "EddsaSign",
                addr: EddsaSignRegAddr {}.register_addr(),
                value: self.uap.eddsa_sifn.into_bits(),
            }),
            18 => Some(Entry {
                name: "McounterInit",
                addr: McounterInitRegAddr {}.register_addr(),
                value: self.uap.mcounter_init.into_bits(),
            }),
            19 => Some(Entry {
                name: "McounterGet",
                addr: McounterGetRegAddr {}.register_addr(),
                value: self.uap.mcounter_get.into_bits(),
            }),
            20 => Some(Entry {
                name: "McounterUpdate",
                addr: McounterUpdateRegAddr {}.register_addr(),
                value: self.uap.mcounter_update.into_bits(),
            }),
            21 => Some(Entry {
                name: "MacAndDestroy",
                addr: MacAndDestroyRegAddr {}.register_addr(),
                value: self.uap.mac_and_destroy.into_bits(),
            }),
            _ => return None,
        };
        self.index += 1;
        next
    }
}

#[cfg(test)]
mod tests {

    use crate::common::{PairingKeySlot, config::RegisterValue};

    use super::*;

    #[test]
    fn test_pairing_key_write_config() {
        let mut config = PairingKeyWrite::default();
        assert_eq!(config.0, 0b11110000111100001111000011110000);

        let access_flag = PairingKeySlot::Index0 | PairingKeySlot::Index1;
        config.set_slot0(access_flag);
        assert_eq!(config.0, 0b11110000111100001111000011110011);

        let access_flag = PairingKeySlot::Index2.into();
        config.set_slot1(access_flag);
        assert_eq!(config.0, 0b11110000111100001111010011110011);

        let access_flag = PairingKeySlot::Index3.into();
        config.set_slot2(access_flag);
        assert_eq!(config.0, 0b11110000111110001111010011110011);

        let access_flag = PairingKeySlot::Index0
            | PairingKeySlot::Index1
            | PairingKeySlot::Index2
            | PairingKeySlot::Index3;
        config.set_slot3(access_flag);
        assert_eq!(config.0, 0b11111111111110001111010011110011);
    }

    #[test]
    fn test_pairing_key_read_config2() {
        let config: PairingKeyRead = PairingKeyRead::from_u32(4059297791);
        assert_eq!(config.0, 0b11110001111100111111011111111111); // 0xf1f3f7ff

        assert_eq!(
            config.slot0(),
            PairingKeySlot::Index0
                | PairingKeySlot::Index1
                | PairingKeySlot::Index2
                | PairingKeySlot::Index3
        );

        assert_eq!(
            config.slot1(),
            PairingKeySlot::Index0 | PairingKeySlot::Index1 | PairingKeySlot::Index2
        );

        assert_eq!(
            config.slot2(),
            PairingKeySlot::Index0 | PairingKeySlot::Index1
        );

        assert_eq!(config.slot3(), PairingKeySlot::Index0.into());
    }

    #[test]
    fn test_pairing_key_read_config() {
        let mut config = PairingKeyRead::default();
        assert_eq!(config.0, 0b11110000111100001111000011110000);

        let access_flag = PairingKeySlot::Index0 | PairingKeySlot::Index1;
        config.set_slot0(access_flag);
        assert_eq!(config.0, 0b11110000111100001111000011110011);

        let access_flag = PairingKeySlot::Index2.into();
        config.set_slot1(access_flag);
        assert_eq!(config.0, 0b11110000111100001111010011110011);

        let access_flag = PairingKeySlot::Index3.into();
        config.set_slot2(access_flag);
        assert_eq!(config.0, 0b11110000111110001111010011110011);

        let access_flag = PairingKeySlot::Index0
            | PairingKeySlot::Index1
            | PairingKeySlot::Index2
            | PairingKeySlot::Index3;
        config.set_slot3(access_flag);
        assert_eq!(config.0, 0b11111111111110001111010011110011);
    }

    #[test]
    fn test_pairing_key_invalidate_config() {
        let mut config = PairingKeyInvalidate::default();
        assert_eq!(config.0, 0b11110000111100001111000011110000);

        let access_flag = PairingKeySlot::Index0 | PairingKeySlot::Index1;
        config.set_slot0(access_flag);
        assert_eq!(config.0, 0b11110000111100001111000011110011);

        let access_flag = PairingKeySlot::Index2.into();
        config.set_slot1(access_flag);
        assert_eq!(config.0, 0b11110000111100001111010011110011);

        let access_flag = PairingKeySlot::Index3.into();
        config.set_slot2(access_flag);
        assert_eq!(config.0, 0b11110000111110001111010011110011);

        let access_flag = PairingKeySlot::Index0
            | PairingKeySlot::Index1
            | PairingKeySlot::Index2
            | PairingKeySlot::Index3;
        config.set_slot3(access_flag);
        assert_eq!(config.0, 0b11111111111110001111010011110011);
    }
}

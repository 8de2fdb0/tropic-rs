//! Application Config Registers

use core::default;

use bitfields::bitfield;
use bitflag_attr::bitflag;

use super::{implement_register_addr_trait, implement_register_traits_for_bitfield};

#[bitfield(u32)]
#[derive(Clone, Copy, PartialEq)]
pub struct Gpo {
    #[bits(2, default = 0x3)]
    gpu_func: u8,
    #[bits(30, default = 0x3fffffff)]
    reserved: u32,
}

#[cfg(feature = "display")]
impl core::fmt::Display for Gpo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("gpu_func: {:#02b}", self.gpu_func()))
    }
}

#[bitflag(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SleepMode {
    Enabled = 1,
}

impl default::Default for SleepMode {
    fn default() -> Self {
        SleepMode::from_bits_retain(u32::MAX)
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for SleepMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Enabled: {}",
            self.contains(SleepMode::Enabled)
        ))
    }
}

implement_register_traits_for_bitfield!(GpoRegAddr, Gpo, 0x14, 0x0);
implement_register_addr_trait!(SleepModeRegAddr, SleepMode, 0x18, 0x0);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Application {
    pub gpo: Gpo,
    pub sleep_mode: SleepMode,
}

#[cfg(feature = "display")]
impl core::fmt::Display for Application {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            write!(f, "Application{{")?;
            write!(
                f,
                "\n gpo: {:#}\n sleep_mode: {:#}\n",
                self.gpo, self.sleep_mode
            )?;
            write!(f, "}}")
        } else {
            f.write_fmt(format_args!(
                "gpo:{}, sleep_mode:{}",
                self.gpo, self.sleep_mode
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpo_config() {
        let mut config = Gpo::default();
        assert_eq!(config.0, 0b11111111111111111111111111111111);

        config.set_gpu_func(0x1);
        assert_eq!(config.0, 0b11111111111111111111111111111101);

        config.set_gpu_func(0x2);
        assert_eq!(config.0, 0b11111111111111111111111111111110);

        config.set_gpu_func(0x3);
        assert_eq!(config.0, 0b11111111111111111111111111111111);
    }

    #[test]
    fn test_sleep_mode_config() {
        let mut config = SleepMode::default();
        assert_eq!(config.bits(), 0b11111111111111111111111111111111);

        config.toggle(SleepMode::Enabled);
        assert_eq!(config.bits(), 0b11111111111111111111111111111110);

        config.toggle(SleepMode::Enabled);
        assert_eq!(config.bits(), 0b11111111111111111111111111111111);
    }
}

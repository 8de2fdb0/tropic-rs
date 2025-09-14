//! Bootloader Config Registers

use bitflag_attr::bitflag;

use super::*;

/// CFG_START_UP register fields
#[bitflag(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StartUp {
    Rfu1 = 1,
    Mbist = 1 << 1,
    RngTestDisabled = 1 << 2,
    MaintananceEnabled = 1 << 3,
}

impl Default for StartUp {
    fn default() -> Self {
        // default is all flags to 1
        StartUp::from_bits_retain(u32::MAX)
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for StartUp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            write!(f, "StartUp: {{")?;
            write!(f, "Rfu1: {}", self.contains(StartUp::Rfu1))?;
            write!(f, ", Mbist: {}", self.contains(StartUp::Mbist))?;
            write!(
                f,
                ", RngTestDisabled: {}",
                self.contains(StartUp::RngTestDisabled)
            )?;
            write!(
                f,
                ", MaintananceEnabled: {}",
                self.contains(StartUp::MaintananceEnabled)
            )?;
            write!(f, "}}")
        } else {
            f.write_fmt(format_args!("{:032b}", self.bits()))
        }
    }
}

/// CFG_SENSORS register fields
#[bitflag(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Sensor {
    Ptrng0TestDisabled = 1,
    Ptrng1TestDisabled = 1 << 1,
    OscillatorMonDisabled = 1 << 2,
    ShieldDisabled = 1 << 3,
    VoltageMonDisabled = 1 << 4,
    GlitchDetDisabled = 1 << 5,
    TempSensDisabled = 1 << 6,
    LaserDetDisabled = 1 << 7,
    EmPulseDetDisabled = 1 << 8,
    CpuAlertDisabled = 1 << 9,
    PinVerifBitFlipDisabled = 1 << 10,
    ScbBitFlipDisabled = 1 << 11,
    CpbBitFlipDisabled = 1 << 12,
    EccBitFlipDisabled = 1 << 13,
    RMemBitFlipDisabled = 1 << 14,
    EkdbBitFlipDisabled = 1 << 15,
    IMemBitFlipDisabled = 1 << 16,
    PlatformBitFlipDisabled = 1 << 17,
}

impl Default for Sensor {
    fn default() -> Self {
        // default is all flags to 1
        Sensor::from_bits_retain(u32::MAX)
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for Sensor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            write!(f, "Sensor: {{")?;
            write!(
                f,
                "Ptrng0TestDisabled: {}, Ptrng1TestDisabled: {}, OscillatorMonDisabled: {}, ShieldDisabled: {}, ",
                self.contains(Sensor::Ptrng0TestDisabled),
                self.contains(Sensor::Ptrng1TestDisabled),
                self.contains(Sensor::OscillatorMonDisabled),
                self.contains(Sensor::ShieldDisabled)
            )?;
            write!(
                f,
                "VoltageMonDisabled: {}, GlitchDetDisabled: {}, TempSensDisabled: {}, LaserDetDisabled: {}, ",
                self.contains(Sensor::VoltageMonDisabled),
                self.contains(Sensor::GlitchDetDisabled),
                self.contains(Sensor::TempSensDisabled),
                self.contains(Sensor::LaserDetDisabled)
            )?;
            write!(
                f,
                "EmPulseDetDisabled: {}, CpuAlertDisabled: {}, PinVerifBitFlipDisabled: {}, ScbBitFlipDisabled: {}, ",
                self.contains(Sensor::EmPulseDetDisabled),
                self.contains(Sensor::CpuAlertDisabled),
                self.contains(Sensor::PinVerifBitFlipDisabled),
                self.contains(Sensor::ScbBitFlipDisabled)
            )?;
            write!(
                f,
                "CpbBitFlipDisabled: {}, EccBitFlipDisabled: {}, RMemBitFlipDisabled: {}, EkdbBitFlipDisabled: {}, ",
                self.contains(Sensor::CpbBitFlipDisabled),
                self.contains(Sensor::EccBitFlipDisabled),
                self.contains(Sensor::RMemBitFlipDisabled),
                self.contains(Sensor::EkdbBitFlipDisabled)
            )?;
            write!(
                f,
                "IMemBitFlipDisabled: {}, PlatformBitFlipDisabled: {}, ",
                self.contains(Sensor::IMemBitFlipDisabled),
                self.contains(Sensor::PlatformBitFlipDisabled)
            )?;
            write!(f, "}}")
        } else {
            write!(f, "{:032b}", self.bits())
        }
    }
}

/// CFG_DEBUG register fields
#[bitflag(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Debug {
    FwDebugLogEnabled = 1,
}

impl Default for Debug {
    fn default() -> Self {
        // default is all flags to 1
        Debug::from_bits_retain(u32::MAX)
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for Debug {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            write!(f, "Debug: {{")?;
            write!(
                f,
                "FwDebugLogEnabled: {}",
                self.contains(Debug::FwDebugLogEnabled)
            )?;
            write!(f, "}}")
        } else {
            write!(f, "{:032b}", self.bits())
        }
    }
}

implement_register_addr_trait!(StartUpRegAddr, StartUp, 0x0, 0x0);
implement_register_addr_trait!(SensorRegAddr, Sensor, 0x8, 0x0);
implement_register_addr_trait!(DebugRegAddr, Debug, 0x10, 0x0);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bootloader {
    pub start_up: StartUp,
    pub sensor: Sensor,
    pub debug: Debug,
}

#[cfg(feature = "config-iter")]
impl Bootloader {
    pub fn iter(&self) -> BootloaderIter {
        BootloaderIter {
            bootloader: *self,
            index: 0,
        }
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for Bootloader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            write!(f, "Bootloader{{")?;
            write!(f, "\n start_up: {:#}", self.start_up)?;
            write!(f, "\n sensor: {:#}", self.sensor)?;
            write!(f, "\n debug: {:#}", self.debug)?;
            write!(f, "\n}}")
        } else {
            f.write_fmt(format_args!(
                "start_up: {}, sensor: {}, debug: {}",
                self.start_up, self.sensor, self.debug
            ))
        }
    }
}

#[cfg(feature = "config-iter")]
pub struct BootloaderIter {
    bootloader: Bootloader,
    index: u8,
}

#[cfg(feature = "config-iter")]
impl core::iter::Iterator for BootloaderIter {
    type Item = super::Entry;
    fn next(&mut self) -> Option<Self::Item> {
        let entry = match self.index {
            0 => Some(Entry {
                name: "StartUp",
                addr: SensorRegAddr {}.register_addr(),
                value: self.bootloader.start_up.bits(),
            }),
            1 => Some(Entry {
                name: "Sensor",
                addr: StartUpRegAddr {}.register_addr(),
                value: self.bootloader.sensor.bits(),
            }),
            2 => Some(Entry {
                name: "Debug",
                addr: DebugRegAddr {}.register_addr(),
                value: self.bootloader.debug.bits(),
            }),
            _ => None,
        };
        self.index += 1;
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_up_config() {
        let mut config = StartUp::default();
        assert_eq!(config.bits(), 0b11111111111111111111111111111111);

        config.toggle(StartUp::Rfu1);
        assert_eq!(config.bits(), 0b11111111111111111111111111111110);

        config.toggle(StartUp::Mbist);
        assert_eq!(config.bits(), 0b11111111111111111111111111111100);

        config.toggle(StartUp::RngTestDisabled);
        assert_eq!(config.bits(), 0b11111111111111111111111111111000);

        config.toggle(StartUp::MaintananceEnabled);
        assert_eq!(config.bits(), 0b11111111111111111111111111110000);

        config.toggle(StartUp::Rfu1);
        assert_eq!(config.bits(), 0b11111111111111111111111111110001);
    }

    #[test]
    fn test_sensor_config() {
        // test setting some of the flags
        let mut config = Sensor::default();
        config.toggle(Sensor::Ptrng0TestDisabled);
        assert_eq!(config.bits(), 0b11111111111111111111111111111110);

        let mut config = Sensor::default();
        config.toggle(Sensor::Ptrng1TestDisabled);
        assert_eq!(config.bits(), 0b11111111111111111111111111111101);

        let mut config = Sensor::default();
        config.toggle(Sensor::IMemBitFlipDisabled);
        assert_eq!(config.bits(), 0b11111111111111101111111111111111);

        let mut config = Sensor::default();
        config.toggle(Sensor::PlatformBitFlipDisabled);
        assert_eq!(config.bits(), 0b11111111111111011111111111111111);

        let mut config = Sensor::default();
        assert_eq!(config.bits(), 0b11111111111111111111111111111111);

        // test toggling every second
        for (_name, flag) in config.iter_names().step_by(2) {
            config.toggle(flag);
        }
        assert_eq!(config.bits(), 0b11111111111111101010101010101010);

        // test toggling the rest
        for (_name, flag) in config.iter_names() {
            config.toggle(flag);
        }
        assert_eq!(config.bits(), 0b11111111111111000000000000000000);

        let config = Sensor::default();
        for (i, (_name, flag)) in config.iter_names().enumerate() {
            assert_eq!(flag.bits(), 1 << i);
        }
    }

    #[test]
    fn test_debug_config() {
        let mut config = Debug::default();
        assert_eq!(config.bits(), 0b11111111111111111111111111111111);
        config.toggle(Debug::FwDebugLogEnabled);
        assert_eq!(config.bits(), 0b11111111111111111111111111111110);
    }
}

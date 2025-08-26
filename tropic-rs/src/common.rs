/// Pairing key indexes corresponds to S_HiPub
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum PairingKeySlot {
    Index0 = 0,
    Index1 = 1,
    Index2 = 2,
    Index3 = 3,
}

// #[derive(Debug, Clone)]
// #[repr(u8)]
// pub enum ConfigObjectRegister {
//     StartUp = 0,
//     Sensor = 1,
//     Debug = 2,
//     Gpo = 3,
//     SleepMode = 4,
//     UapPairingKeyWrite = 5,
//     UapPairingKeyRead = 6,
//     UapPairingKeyInvalidate = 7,
//     UapRConfigWriteErase = 8,
//     UapRConfigRead = 9,
//     UapIConfigWrite = 10,
//     UapIConfigRead = 11,
//     UapPing = 12,
//     UapRMemDataWrite = 13,
//     UapRMemDataRead = 14,
//     UapRMemDataErase = 15,
//     UapRandomValueGet = 16,
//     UapEccKeyGenerate = 17,
//     UapEccKeyStore = 18,
//     UapEccKeyRead = 19,
//     UapEccKeyErase = 20,
//     UapEcdsaSign = 21,
//     UapEddsaSign = 22,
//     UapMcounterInit = 23,
//     UapMcounterGet = 24,
//     UapMcounterUpdate = 25,
//     UapMacAndDestroy = 26,
// }
pub mod config {
    use bitflag_attr::{Flags, bitflag};

    pub enum Error {
        InvalidValue,
    }

    pub trait RegisterAddr {
        type Item: Flags<Bits = u32>;
        fn to_register_addr(&self) -> [u8; 2];
        // fn set_register_value(&mut self, value: Self::Item);
    }

    macro_rules! implement_register_addr {
        (
        $struct_name:ident,
        $config_item:ty,
        $addr_hi:expr,
        $addr_lo:expr
    ) => {
            pub struct $struct_name;

            impl RegisterAddr for $struct_name {
                type Item = $config_item;

                fn to_register_addr(&self) -> [u8; 2] {
                    [$addr_hi, $addr_lo]
                }

                // fn set_register_value(&mut self, value: $config_item){
                //     self.value = value;
                // }
            }
        };
    }
    
    #[bitflag(u32)]
    #[derive(Debug, Clone, Copy)]
    pub enum StartUpConfig {
        Rfu1 = 1,
        Mbist = 2,
        RngTestDisabled = 3,
        MaintananceEnabled = 4,
    }

    impl Default for StartUpConfig {
        fn default() -> Self {
            // default is all flags to 1
            StartUpConfig::from_bits_retain(u32::MAX)
        }
    }

    #[cfg(feature = "display")]
    impl core::fmt::Display for StartUpConfig {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_fmt(format_args!(
                "Rfu1: {}, Mbist: {}, RngTestDisabled: {}, MaintananceEnabled: {}", 
                self.contains(StartUpConfig::Rfu1),
                self.contains(StartUpConfig::Mbist),
                self.contains(StartUpConfig::RngTestDisabled),
                self.contains(StartUpConfig::MaintananceEnabled),
            ))
        }
    }

    #[bitflag(u32)]
    #[derive(Debug, Clone, Copy)]
    pub enum SensorConfig {
        Ptrng0TestDisabled = 1,
        Ptrng1TestDisabled = 2,
        OscillatorMonDisabled = 3,
        ShieldDisabled = 4,
        VoltageMonDisabled = 5,
        GlitchDetDisabled = 6,
        TempSensDisabled = 7,
        LaserDetDisabled = 8,
        EmPulseDetDisabled = 9,
        CpuAlertDisabled = 10,
        PinVerifBitFlipDisabled = 11,
        ScbBitFlipDisabled = 12,
        CpbBitFlipDisabled = 13,
        EccBitFlipDisabled = 14,
        RMemBitFlipDisabled = 15,
        EkdbBitFlipDisabled = 16,
        IMemBitFlipDisabled = 17,
        PlatformBitFlipDisabled = 18,
    }

    #[cfg(feature = "display")]
    impl core::fmt::Display for SensorConfig {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_fmt(format_args!(
                "Ptrng0TestDisabled: {}, Ptrng1TestDisabled: {}, OscillatorMonDisabled: {}, ShieldDisabled: {}, ", 
                 self.contains(SensorConfig::Ptrng0TestDisabled),
                 self.contains(SensorConfig::Ptrng1TestDisabled),
                 self.contains(SensorConfig::OscillatorMonDisabled),
                 self.contains(SensorConfig::ShieldDisabled)
            ))?;
            f.write_fmt(format_args!(
                "VoltageMonDisabled: {}, GlitchDetDisabled: {}, TempSensDisabled: {}, LaserDetDisabled: {}, ", 
                 self.contains( SensorConfig::VoltageMonDisabled),
                 self.contains( SensorConfig::GlitchDetDisabled),
                 self.contains( SensorConfig::TempSensDisabled),
                 self.contains( SensorConfig::LaserDetDisabled)
            ))?;
            f.write_fmt(format_args!(  
                "EmPulseDetDisabled: {}, CpuAlertDisabled: {}, PinVerifBitFlipDisabled: {}, ScbBitFlipDisabled: {}, ", 
                 self.contains(SensorConfig::EmPulseDetDisabled),
                 self.contains(SensorConfig::CpuAlertDisabled),
                 self.contains(SensorConfig::PinVerifBitFlipDisabled),
                   self.contains(SensorConfig::ScbBitFlipDisabled)
            ))?;
            f.write_fmt(format_args!(
                "CpbBitFlipDisabled: {}, EccBitFlipDisabled: {}, RMemBitFlipDisabled: {}, EkdbBitFlipDisabled: {}, ", 
                 self.contains( SensorConfig::CpbBitFlipDisabled),
                 self.contains( SensorConfig::EccBitFlipDisabled),
                 self.contains( SensorConfig::RMemBitFlipDisabled),
                 self.contains( SensorConfig::EkdbBitFlipDisabled)
             ))?;
             f.write_fmt(format_args!(
                "IMemBitFlipDisabled: {}, PlatformBitFlipDisabled: {}, ", 
                 self.contains( SensorConfig::IMemBitFlipDisabled),
                 self.contains( SensorConfig::PlatformBitFlipDisabled)
             ))            
        }
    }

    #[bitflag(u32)]
    #[derive(Debug, Clone, Copy)]
    pub enum DebugConfig {
        FwDebugLogEnabled = 1,
    }

    #[cfg(feature = "display")]
    impl core::fmt::Display for DebugConfig {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_fmt(format_args!(
                "FwDebugLogEnabled: {}",
                self.contains(DebugConfig::FwDebugLogEnabled)
            ))
        }
    }

    implement_register_addr!(StartUp, StartUpConfig, 0x0, 0x0);
    implement_register_addr!(Sensor, SensorConfig, 0x8, 0x0);
    implement_register_addr!(Debug, DebugConfig, 0x10, 0x0);

}

// #[derive(Debug, Clone)]
// #[repr(u16)]
// pub enum ConfigObjectRegisterAddr {
//     //
//     StartUp = 0x0,
//     Sensors = 0x8,
//     Debug = 0x10,

//     UapPairingKeyWrite = 0x20,
//     UapPairingKeyRead = 0x24,
//     UapPairingKeyInvalidate = 0x28,
//     UapRConfigWriteErase = 0x30,
//     UapRConfigRead = 0x34,
//     UapIConfigWrite = 0x40,
//     UapIConfigRead = 0x44,
//     UapPing = 0x100,
//     UapRMemDataWrite = 0x110,
//     UapRMemDataRead = 0x114,
//     UapRMemDataErase = 0x118,
//     UapRandomValueGet = 0x120,
//     UapEccKeyGenerate = 0x130,
//     UapEccKeyStore = 0x134,
//     UapEccKeyRead = 0x138,
//     UapEccKeyErase = 0x13c,
//     UapEcdsaSign = 0x140,
//     UapEddsaSign = 0x144,
//     UapMcounterInit = 0x150,
//     UapMcounterGet = 0x154,
//     UapMcounterUpdate = 0x158,
//     UapMacAndDestroy = 0x160,
//     UapSerialCodeGet = 0x170,
// }

// impl From<u16> for ConfigObjectRegisterAddr {
//     fn from(value: u16) -> Self {
//         match value {
//             0x0 => Self::StartUp,
//             0x4 => Self::SleepMode,
//             0x8 => Self::Sensors,
//             0x10 => Self::Debug,
//             0x20 => Self::UapPairingKeyWrite,
//             0x24 => Self::UapPairingKeyRead,
//             0x28 => Self::UapPairingKeyInvalidate,
//             0x30 => Self::UapRConfigWriteErase,
//             0x34 => Self::UapRConfigRead,
//             0x40 => Self::UapIConfigWrite,
//             0x44 => Self::UapIConfigRead,
//             0x100 => Self::UapPing,
//             0x110 => Self::UapRMemDataWrite,
//             0x114 => Self::UapRMemDataRead,
//             0x118 => Self::UapRMemDataErase,
//             0x120 => Self::UapRandomValueGet,
//             0x130 => Self::UapEccKeyGenerate,
//             0x134 => Self::UapEccKeyStore,
//             0x138 => Self::UapEccKeyRead,
//             0x13c => Self::UapEccKeyErase,
//             0x140 => Self::UapEcdsaSign,
//             0x144 => Self::UapEddsaSign,
//             0x150 => Self::UapMcounterInit,
//             0x154 => Self::UapMcounterGet,
//             0x158 => Self::UapMcounterUpdate,
//             0x160 => Self::UapMacAndDestroy,
//             0x170 => Self::UapSerialCodeGet,
//             _ => panic!("Unknown value: {}", value),
//         }
//     }
// }

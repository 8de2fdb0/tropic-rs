pub mod access_flag;
pub mod application;
pub mod application_uap;
pub mod bootloader;

use bitflag_attr::Flags;

use crate::l3::{self, ReceiveResponseL3};

#[derive(Debug, PartialEq)]
pub enum Error {
    // InvalidValue,
    IConfigBitIndexMax,
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // Error::InvalidValue => write!(f, "Invalid value"),
            Error::IConfigBitIndexMax => write!(f, "I config bit index bigger then 31"),
        }
    }
}

pub trait RegisterValue {
    fn from_u32(value: u32) -> Self;
    fn to_u32(&self) -> u32;
    fn to_value(&self) -> [u8; 4];
}

impl<T> RegisterValue for T
where
    T: Flags<Bits = u32>,
{
    fn from_u32(value: u32) -> Self {
        T::from_bits_retain(value)
    }
    fn to_u32(&self) -> u32 {
        self.bits()
    }
    fn to_value(&self) -> [u8; 4] {
        self.bits().to_le_bytes()
    }
}

pub trait RegisterAddr {
    type Item: RegisterValue;

    fn register_addr(&self) -> [u8; 2];
}

const I_CONFIG_BIT_INDEX_MAX: u8 = 31;

/// R memory user data slot
#[derive(Debug, Clone, PartialEq)]
pub struct IConfigBitIndex(u8);

impl TryFrom<u8> for IConfigBitIndex {
    type Error = Error;
    fn try_from(index: u8) -> Result<Self, Self::Error> {
        match index {
            0..=I_CONFIG_BIT_INDEX_MAX => Ok(IConfigBitIndex(index)),
            _ => Err(Error::IConfigBitIndexMax),
        }
    }
}

impl From<IConfigBitIndex> for u8 {
    fn from(value: IConfigBitIndex) -> Self {
        value.0
    }
}

#[cfg(test)]
impl IConfigBitIndex {
    pub fn random() -> Self {
        use rand::Rng;
        let index: u8 = rand::rng().random_range(0..=I_CONFIG_BIT_INDEX_MAX);
        IConfigBitIndex(index)
    }
}

macro_rules! implement_register_addr_trait {
    (
        $struct_name:ident,
        $config_item:ty,
        $addr_hi:expr,
        $addr_lo:expr
    ) => {
        pub struct $struct_name;

        impl $crate::common::config::RegisterAddr for $struct_name {
            type Item = $config_item;

            fn register_addr(&self) -> [u8; 2] {
                [$addr_hi, $addr_lo]
            }
        }
    };
}

pub(crate) use implement_register_addr_trait;

macro_rules! implement_register_traits_for_bitfield {
    (
        $struct_name:ident,
        $config_item:ty,
        $addr_hi:expr,
        $addr_lo:expr
    ) => {
        impl $crate::common::config::RegisterValue for $config_item {
            fn from_u32(value: u32) -> Self {
                Self::from_bits(value)
            }
            fn to_u32(&self) -> u32 {
                self.0
            }
            fn to_value(&self) -> [u8; 4] {
                self.0.to_le_bytes()
            }
        }

        implement_register_addr_trait!($struct_name, $config_item, $addr_hi, $addr_lo);
    };
}

pub(crate) use implement_register_traits_for_bitfield;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Config {
    pub bootloader: bootloader::Bootloader,
    pub application: application::Application,
    pub application_uap: application_uap::ApplicationUap,
}

#[cfg(feature = "config-iter")]
impl Config {
    pub fn iter(&self) -> ConfigIter {
        ConfigIter {
            bootloader_config: self.bootloader.iter(),
            application_config: self.application.iter(),
            application_uap_config: self.application_uap.iter(),
            index: 0,
        }
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            write!(f, "Config {{")?;
            write!(f, "\n  bootloader: {:#}", self.bootloader)?;
            write!(f, "\n  application: {:#}", self.application)?;
            write!(f, "\n  application_uap: {:#}", self.application_uap)?;
            write!(f, "\n}}")
        } else {
            write!(f, "Config {{")?;
            f.write_str("ApplicationUap {\n")?;
            // Format each field on a new, indented line.
            f.write_fmt(format_args!("  bootloader: {},\n", self.bootloader))?;
            f.write_fmt(format_args!("  application: {},\n", self.application))?;
            f.write_fmt(format_args!(
                "  application_uap: {},\n",
                self.application_uap
            ))?;

            // End the output with a closing brace.
            f.write_str("}")
        }
    }
}

#[cfg(feature = "config-iter")]
pub struct Entry {
    pub name: &'static str,
    pub addr: [u8; 2],
    pub value: u32,
}

#[cfg(feature = "config-iter")]
pub struct ConfigIter {
    bootloader_config: bootloader::BootloaderIter,
    application_config: application::ApplicationIter,
    application_uap_config: application_uap::ApplicationUapIter,
    index: usize,
}

#[cfg(feature = "config-iter")]
impl core::iter::Iterator for ConfigIter {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        let result = match self.index {
            0 => match self.bootloader_config.next() {
                Some(entry) => Some(entry),
                None => {
                    self.index += 1;
                    self.next()
                }
            },
            1 => match self.application_config.next() {
                Some(entry) => Some(entry),
                None => {
                    self.index += 1;
                    self.next()
                }
            },
            2 => match self.application_uap_config.next() {
                Some(entry) => Some(entry),
                None => {
                    self.index += 1;
                    self.next()
                }
            },
            _ => None,
        };
        self.index += 1;
        result
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum ConfigType {
    Reversable,
    Irreverasable,
}

fn read_config_register<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
    R: RegisterAddr,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    session: &mut impl l3::Session,
    addr: R,
    config_type: &ConfigType,
) -> Result<R::Item, l3::Error> {
    if *config_type == ConfigType::Reversable {
        l3::send(
            spi_device,
            delay,
            l3::reversable_config::ConfigReadCmd::create(&addr),
            session,
        )?;
        let resp: l3::reversable_config::ConfigReadResp<R::Item> =
            l3::receive(spi_device, delay, session)?.try_into()?;

        Ok(resp.value)
    } else {
        l3::send(
            spi_device,
            delay,
            l3::irreversable_config::ConfigReadCmd::create(&addr),
            session,
        )?;
        let resp: l3::irreversable_config::ConfigReadResp<R::Item> =
            l3::receive(spi_device, delay, session)?.try_into()?;
        Ok(resp.value)
    }
}

pub(crate) fn read_whole_i_or_r_config<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    session: &mut impl l3::Session,
    config_type: ConfigType,
) -> Result<Config, l3::Error> {
    let start_up = read_config_register(
        spi_device,
        delay,
        session,
        bootloader::StartUpRegAddr,
        &config_type,
    )?;

    let sensor = read_config_register(
        spi_device,
        delay,
        session,
        bootloader::SensorRegAddr,
        &config_type,
    )?;
    let debug = read_config_register(
        spi_device,
        delay,
        session,
        bootloader::DebugRegAddr,
        &config_type,
    )?;

    let gpo = read_config_register(
        spi_device,
        delay,
        session,
        application::GpoRegAddr,
        &config_type,
    )?;
    let sleep_mode = read_config_register(
        spi_device,
        delay,
        session,
        application::SleepModeRegAddr,
        &config_type,
    )?;

    let pairing_key_write = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyWriteRegAddr,
        &config_type,
    )?;
    let pairing_key_read = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyReadRegAddr,
        &config_type,
    )?;
    let pairing_key_invalidate = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyInvalidateRegAddr,
        &config_type,
    )?;
    let r_config_write_erase = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::RConfigWriteEraseRegAddr,
        &config_type,
    )?;
    let r_config_read = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::RConfigReadRegAddr,
        &config_type,
    )?;
    let i_config_write = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::IConfigWriteRegAddr,
        &config_type,
    )?;
    let i_config_read = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::IConfigReadRegAddr,
        &config_type,
    )?;
    let ping = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::PingRegAddr,
        &config_type,
    )?;
    let r_mem_data_write = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataWriteRegAddr,
        &config_type,
    )?;
    let r_mem_data_read = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataReadRegAddr,
        &config_type,
    )?;
    let r_mem_data_erase = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataEraseRegAddr,
        &config_type,
    )?;
    let random_value_get = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::RandomValueGetRegAddr,
        &config_type,
    )?;
    let ecc_key_generate = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyGenerateRegAddr,
        &config_type,
    )?;

    let ecc_key_store = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyStoreRegAddr,
        &config_type,
    )?;

    let ecc_key_read = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyReadRegAddr,
        &config_type,
    )?;

    let ecc_key_erase = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyEraseRegAddr,
        &config_type,
    )?;

    let ecdsa_sign = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::EcdsaSignRegAddr,
        &config_type,
    )?;

    let eddsa_sifn = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::EddsaSignRegAddr,
        &config_type,
    )?;

    let mcounter_init = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterInitRegAddr,
        &config_type,
    )?;

    let mcounter_get = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterGetRegAddr,
        &config_type,
    )?;

    let mcounter_update = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterUpdateRegAddr,
        &config_type,
    )?;
    let mac_and_destroy = read_config_register(
        spi_device,
        delay,
        session,
        application_uap::MacAndDestroyRegAddr,
        &config_type,
    )?;

    Ok(Config {
        bootloader: bootloader::Bootloader {
            start_up,
            sensor,
            debug,
        },
        application: application::Application { gpo, sleep_mode },
        application_uap: application_uap::ApplicationUap {
            pairing_key_write,
            pairing_key_read,
            pairing_key_invalidate,
            r_config_write_erase,
            r_config_read,
            i_config_write,
            i_config_read,
            ping,
            r_mem_data_write,
            r_mem_data_read,
            r_mem_data_erase,
            random_value_get,
            ecc_key_generate,
            ecc_key_store,
            ecc_key_read,
            ecc_key_erase,
            ecdsa_sign,
            eddsa_sifn,
            mcounter_init,
            mcounter_get,
            mcounter_update,
            mac_and_destroy,
        },
    })
}

fn write_r_config_register<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
    R: RegisterAddr,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    session: &mut impl l3::Session,
    addr: R,
    value: R::Item,
) -> Result<l3::reversable_config::ConfigWriteResp, l3::Error> {
    l3::send(
        spi_device,
        delay,
        l3::reversable_config::ConfigWriteCmd::create(addr, value),
        session,
    )?;

    l3::reversable_config::ConfigWriteResp::receive_l3(spi_device, delay, session)
}

pub(crate) fn write_whole_r_config<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    session: &mut impl l3::Session,
    config: &Config,
) -> Result<l3::reversable_config::ConfigWriteResp, l3::Error> {
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        bootloader::StartUpRegAddr,
        config.bootloader.start_up,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        bootloader::SensorRegAddr,
        config.bootloader.sensor,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        bootloader::DebugRegAddr,
        config.bootloader.debug,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application::GpoRegAddr,
        config.application.gpo,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application::SleepModeRegAddr,
        config.application.sleep_mode,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyWriteRegAddr,
        config.application_uap.pairing_key_write,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyReadRegAddr,
        config.application_uap.pairing_key_read,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyInvalidateRegAddr,
        config.application_uap.pairing_key_invalidate,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::RConfigWriteEraseRegAddr,
        config.application_uap.r_config_write_erase,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::RConfigReadRegAddr,
        config.application_uap.r_config_read,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::IConfigWriteRegAddr,
        config.application_uap.i_config_write,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::IConfigReadRegAddr,
        config.application_uap.i_config_read,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::PingRegAddr,
        config.application_uap.ping,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataWriteRegAddr,
        config.application_uap.r_mem_data_write,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataReadRegAddr,
        config.application_uap.r_mem_data_read,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataEraseRegAddr,
        config.application_uap.r_mem_data_erase,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::RandomValueGetRegAddr,
        config.application_uap.random_value_get,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyGenerateRegAddr,
        config.application_uap.ecc_key_generate,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyStoreRegAddr,
        config.application_uap.ecc_key_store,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyReadRegAddr,
        config.application_uap.ecc_key_read,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyEraseRegAddr,
        config.application_uap.ecc_key_erase,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::EcdsaSignRegAddr,
        config.application_uap.ecdsa_sign,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::EddsaSignRegAddr,
        config.application_uap.eddsa_sifn,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterInitRegAddr,
        config.application_uap.mcounter_init,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterGetRegAddr,
        config.application_uap.mcounter_get,
    )?;
    let _ = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterUpdateRegAddr,
        config.application_uap.mcounter_update,
    )?;
    let last_resp = write_r_config_register(
        spi_device,
        delay,
        session,
        application_uap::MacAndDestroyRegAddr,
        config.application_uap.mac_and_destroy,
    )?;

    Ok(last_resp)
}

fn write_i_config_register<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
    R: RegisterAddr,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    session: &mut impl l3::Session,
    addr: R,
    value: R::Item,
) -> Result<Option<l3::irreversable_config::ConfigWriteResp>, l3::Error> {
    let value_u32 = value.to_u32();
    let mut last_resp = None;

    // Check that value is either 0 or 1 for each bit
    for bit_index in 0_u8..32 {
        let bit_value = ((value_u32 >> bit_index) & 0x01) as u8;
        // if bit is 0 write it (all i_config bits are 1 by default)
        if bit_value == 0 {
            l3::send(
                spi_device,
                delay,
                l3::irreversable_config::ConfigWriteCmd::create(
                    &addr,
                    bit_index.try_into().map_err(l3::Error::Config)?,
                ),
                session,
            )?;

            last_resp = Some(l3::irreversable_config::ConfigWriteResp::receive_l3(
                spi_device, delay, session,
            )?);
        }
    }
    Ok(last_resp)
}

pub(crate) fn write_whole_i_config<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    session: &mut impl l3::Session,
    config: &Config,
) -> Result<Option<l3::irreversable_config::ConfigWriteResp>, l3::Error> {
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        bootloader::StartUpRegAddr,
        config.bootloader.start_up,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        bootloader::SensorRegAddr,
        config.bootloader.sensor,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        bootloader::DebugRegAddr,
        config.bootloader.debug,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application::GpoRegAddr,
        config.application.gpo,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application::SleepModeRegAddr,
        config.application.sleep_mode,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyWriteRegAddr,
        config.application_uap.pairing_key_write,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyReadRegAddr,
        config.application_uap.pairing_key_read,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::PairingKeyInvalidateRegAddr,
        config.application_uap.pairing_key_invalidate,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::RConfigWriteEraseRegAddr,
        config.application_uap.r_config_write_erase,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::RConfigReadRegAddr,
        config.application_uap.r_config_read,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::IConfigWriteRegAddr,
        config.application_uap.i_config_write,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::IConfigReadRegAddr,
        config.application_uap.i_config_read,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::PingRegAddr,
        config.application_uap.ping,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataWriteRegAddr,
        config.application_uap.r_mem_data_write,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataReadRegAddr,
        config.application_uap.r_mem_data_read,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::RMemDataEraseRegAddr,
        config.application_uap.r_mem_data_erase,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::RandomValueGetRegAddr,
        config.application_uap.random_value_get,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyGenerateRegAddr,
        config.application_uap.ecc_key_generate,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyStoreRegAddr,
        config.application_uap.ecc_key_store,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyReadRegAddr,
        config.application_uap.ecc_key_read,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::EccKeyEraseRegAddr,
        config.application_uap.ecc_key_erase,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::EcdsaSignRegAddr,
        config.application_uap.ecdsa_sign,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::EddsaSignRegAddr,
        config.application_uap.eddsa_sifn,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterInitRegAddr,
        config.application_uap.mcounter_init,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterGetRegAddr,
        config.application_uap.mcounter_get,
    )?;
    let _ = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::McounterUpdateRegAddr,
        config.application_uap.mcounter_update,
    )?;
    let last_resp = write_i_config_register(
        spi_device,
        delay,
        session,
        application_uap::MacAndDestroyRegAddr,
        config.application_uap.mac_and_destroy,
    )?;

    Ok(last_resp)
}

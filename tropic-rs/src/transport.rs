use core::fmt::Debug;

use embedded_hal::{
    delay::DelayNs,
    digital::{Error as _, OutputPin},
    spi::{Error as _, SpiBus, SpiDevice},
};

use crate::l1::{self, Response};

#[derive(Debug, PartialEq)]
pub enum Error {
    // Spi transport
    Spi(embedded_hal::spi::ErrorKind),
    // Chip Select pin
    Pin(embedded_hal::digital::ErrorKind),
    /// Chip is in ALARM
    AlarmMode,
    /// Chip is BUSY - typically chip is still booting
    ChipBusy,
    /// Data does not have an expected length
    InvalidDataLen,
    /// Slice to error conversion failed
    TryFromSlice,
    /// Custom error type for external implementations
    Other(u8),
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spi(err) => f.write_fmt(format_args!("spi error: {}", err)),
            Self::Pin(err) => f.write_fmt(format_args!("pin error: {}", err)),
            Self::AlarmMode => f.write_str("chip is in alarm mode"),
            Self::ChipBusy => f.write_str("chip is busy"),
            Self::InvalidDataLen => f.write_str("invalid data length"),
            Self::TryFromSlice => f.write_fmt(format_args!("unable to convert slice to array")),
            Self::Other(code) => f.write_fmt(format_args!("other error, code: {}", code)),
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(_err: core::array::TryFromSliceError) -> Self {
        Self::TryFromSlice
    }
}

pub trait TropicTransport {
    fn transfer_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error>;

    fn write(&mut self, req: &[u8]) -> Result<(), Error>;

    fn read<const N: usize>(&mut self) -> Result<Response<N>, Error>;

    fn request<const N: usize>(&mut self, req: &[u8]) -> Result<Response<N>, Error> {
        self.write(req)?;
        self.read()
    }
}

pub struct SpiDeviceTransport<T, D> {
    device: T,
    delay: D,
}

impl<T, D> SpiDeviceTransport<T, D> {
    pub fn new(device: T, delay: D) -> Self {
        Self { device, delay }
    }
}

impl<T, D> TropicTransport for SpiDeviceTransport<T, D>
where
    T: SpiDevice,
    D: DelayNs,
{
    fn transfer_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.device
            .transfer_in_place(buf)
            .map_err(|e| Error::Spi(e.kind()))?;
        Ok(())
    }

    fn write(&mut self, req: &[u8]) -> Result<(), Error> {
        self.device.write(req).map_err(|e| Error::Spi(e.kind()))?;
        Ok(())
    }

    fn read<const N: usize>(&mut self) -> Result<Response<N>, Error> {
        l1::receive(&mut self.device, &mut self.delay)
    }
}

pub struct SpiBusTransport<T, D, CS> {
    bus: T,
    _delay: D,
    cs: CS,
}

impl<T, D, CS> SpiBusTransport<T, D, CS> {
    pub fn new(bus: T, delay: D, cs: CS) -> Self {
        Self {
            bus,
            _delay: delay,
            cs,
        }
    }
}

impl<T, D, CS> TropicTransport for SpiBusTransport<T, D, CS>
where
    T: SpiBus,
    D: DelayNs,
    CS: OutputPin,
{
    fn transfer_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.cs.set_low().map_err(|e| Error::Pin(e.kind()))?;
        self.bus
            .transfer_in_place(buf)
            .map_err(|e| Error::Spi(e.kind()))?;
        self.cs.set_high().map_err(|e| Error::Pin(e.kind()))?;
        Ok(())
    }

    fn write(&mut self, req: &[u8]) -> Result<(), Error> {
        self.cs.set_low().map_err(|e| Error::Pin(e.kind()))?;
        self.bus.write(req).map_err(|e| Error::Spi(e.kind()))?;
        self.cs.set_high().map_err(|e| Error::Pin(e.kind()))?;
        Ok(())
    }

    fn read<const N: usize>(&mut self) -> Result<Response<N>, Error> {
        // TODO: implement receive for SpiBusTransport
        unimplemented!()
    }
}

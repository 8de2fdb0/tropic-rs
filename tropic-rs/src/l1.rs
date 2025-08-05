use embedded_hal::spi::Error as SpiError;

/// TODO Maximal size of data field in one L2 transfer
const L2_CHUNK_MAX_DATA_SIZE: usize = 252;
/// Maximal number of data bytes in one L1 transfer
const LEN_MIN: usize = 1;
/// Maximal number of data bytes in one L1 transfer
const LEN_MAX: usize = 1 + 1 + 1 + L2_CHUNK_MAX_DATA_SIZE + 2;

/// Max number of GET_INFO requests when chip is not answering
pub const READ_MAX_TRIES: usize = 50; // Increasing from 10 to 50 to cover SPI slave convertor behaviour. TODO put back to 10 in the future
/// Number of ms to wait between each GET_INFO request
pub const READ_RETRY_DELAY: usize = 25;

/// Get response request's ID
pub const GET_RESPONSE_REQ_ID: u8 = 0xAA;
/// This bit in CHIP_STATUS byte signalizes that chip is ready to accept requests
const CHIP_MODE_READY_BIT: u8 = 0x01;
/// This bit in CHIP_STATUS byte signalizes that chip is in ALARM mode
const CHIP_MODE_ALARM_BIT: u8 = 0x02;
/// This bit in CHIP_STATUS byte signalizes that chip is in STARTUP mode
const CHIP_MODE_STARTUP_BIT: u8 = 0x04;

#[derive(Debug)]
pub enum Error {
    Spi(embedded_hal::spi::ErrorKind),
    InvalidDataLen,
    TryFromSlice(core::array::TryFromSliceError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spi(err) => f.write_fmt(format_args!("spi error: {}", err)),
            Self::InvalidDataLen => f.write_str("invalid data length"),
            Self::TryFromSlice(err) => {
                f.write_fmt(format_args!("unable to convert slice: {}", err))
            }
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(err: core::array::TryFromSliceError) -> Self {
        Self::TryFromSlice(err)
    }
}

#[derive(Debug, PartialEq)]
pub struct ChipStatus {
    /// The chip is ready to accept requests
    ready: bool,
    /// The chip is in ALARM mode
    alarm: bool,
    /// The chip is in STARTUP mode
    start: bool,
}

impl ChipStatus {
    pub fn to_mode(&self) -> ChipMode {
        self.into()
    }
}

impl From<u8> for ChipStatus {
    fn from(value: u8) -> Self {
        Self {
            ready: value & CHIP_MODE_READY_BIT > 0,
            alarm: value & CHIP_MODE_ALARM_BIT > 0,
            start: value & CHIP_MODE_STARTUP_BIT > 0,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ChipMode {
    Maintenance,
    App,
}

impl From<&ChipStatus> for ChipMode {
    fn from(status: &ChipStatus) -> Self {
        if status.start {
            Self::Maintenance
        } else {
            Self::App
        }
    }
}

pub(crate) struct Response<const N: usize> {
    pub(crate) chip_status: ChipStatus,
    pub(crate) status: u8,
    pub(crate) len: u8,
    pub(crate) data: [u8; N],
    pub(crate) crc: [u8; 2],
}

pub(crate) fn receive<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
    const N: usize,
>(
    spi_device: &mut SPI,
    delay: &mut D,
) -> Result<Response<N>, Error> {
    let mut retry = READ_MAX_TRIES;

    let req = [GET_RESPONSE_REQ_ID];
    let mut chip_status = [0_u8; 1];
    let mut status = [0_u8; 1];
    let mut len = [0_u8; 1];
    let mut data = [0_u8; N];
    let mut crc = [0_u8; 2];

    loop {
        let mut operations = [
            embedded_hal::spi::Operation::Transfer(&mut chip_status, &req),
            embedded_hal::spi::Operation::TransferInPlace(&mut status),
            embedded_hal::spi::Operation::TransferInPlace(&mut len),
            embedded_hal::spi::Operation::TransferInPlace(&mut data),
            embedded_hal::spi::Operation::TransferInPlace(&mut crc),
        ];

        spi_device
            .transaction(&mut operations)
            .map_err(|e| Error::Spi(e.kind()))?;

        let chip_status: ChipStatus = chip_status[0].into();
        if !chip_status.ready {
            if len[0] == 0xff {
                retry -= 1;
                if retry > 0 {
                    delay.delay_ms(READ_RETRY_DELAY as u32);
                    continue;
                }
                return Err(Error::InvalidDataLen);
            }
        }

        let len_s = len[0] as usize;
        if len_s != N {
            // data buffer was bigger then actual data
            // crc was appended after data[len_s]
            crc = match len_s {
                255 => crc,
                254 => [data[254], crc[1]],
                0..=253 => data[len_s..len_s + 2].try_into()?,
                _ => return Err(Error::InvalidDataLen),
            };
        }

        return Ok(Response {
            chip_status: chip_status,
            status: status[0],
            len: len[0],
            data: data,
            crc: crc,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl ChipStatus {
        pub fn from_values(ready: bool, alarm: bool, start: bool) -> Self {
            Self {
                ready,
                alarm,
                start,
            }
        }
    }
    #[test]
    fn chip_status_ready() {
        let act: ChipStatus = 0x1_u8.into();
        let exp = ChipStatus {
            ready: true,
            alarm: false,
            start: false,
        };
        assert_eq!(act, exp);
    }

    #[test]
    fn chip_status_alarm() {
        let act: ChipStatus = 0x2_u8.into();
        let exp = ChipStatus {
            ready: false,
            alarm: true,
            start: false,
        };
        assert_eq!(act, exp);
    }
    #[test]
    fn chip_status_start() {
        let act: ChipStatus = 0x4_u8.into();
        let exp = ChipStatus {
            ready: false,
            alarm: false,
            start: true,
        };
        assert_eq!(act, exp);
    }
}

use serial2::{SerialPort, Settings};
use std::vec::Vec;

use tropic_rs::transport::{self, spi};

// USB dongle specific constants
// delay before doing a read, to give the fw time to prepare the response
const _USB_DONGLE_INITIAL_READ_DELAY: u32 = 300;
const USB_DONGLE_READ_WRITE_DELAY: u32 = 10;

const HEX_CHAR_LOOKUP: [u8; 16] = *b"0123456789ABCDEF";

// Constants for usb-dongle fw communication
const CS_LOW_REQ: [u8; 5] = *b"CS=1\n";
const CS_HIGH_REQ: [u8; 5] = *b"CS=0\n";

const OK_RESP: [u8; 4] = *b"OK\r\n";

#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    ReqLen,
    InvalidHexChar,
}

impl spi::Error for Error {
    fn kind(&self) -> spi::ErrorKind {
        match self {
            Error::Io(_) => spi::ErrorKind::Other,
            Error::ReqLen => spi::ErrorKind::Other,
            Error::InvalidHexChar => spi::ErrorKind::Other,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => f.write_fmt(format_args!("io error: {}", e)),
            Self::ReqLen => f.write_str("req len error"),
            Self::InvalidHexChar => f.write_str("invalid hex char"),
        }
    }
}

impl From<Error> for u8 {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(_) => 0,
            Error::ReqLen => 1,
            Error::InvalidHexChar => 2,
        }
    }
}

impl From<Error> for transport::Error {
    fn from(err: Error) -> Self {
        transport::Error::Other(err.into())
    }
}

/// Converts bytes to hex characters
fn bytes_to_hexchars(buf: &[u8]) -> Vec<u8> {
    let mut hex_chars = Vec::with_capacity(buf.len() * 2);
    for b in buf.iter() {
        hex_chars.push(HEX_CHAR_LOOKUP[(b >> 4) as usize]);
        hex_chars.push(HEX_CHAR_LOOKUP[(b & 0xF) as usize]);
    }
    hex_chars
}

/// Converts hex characters to bytes
fn hexchars_to_bytes(hex_chars: &[u8], buf: &mut [u8]) -> Result<(), Error> {
    for (i, chunk) in hex_chars.chunks(2).enumerate() {
        let high = (chunk[0] as char)
            .to_digit(16)
            .ok_or(Error::InvalidHexChar)? as u8;
        let low = (chunk[1] as char)
            .to_digit(16)
            .ok_or(Error::InvalidHexChar)? as u8;
        buf[i] = (high << 4) | low;
    }
    Ok(())
}

pub struct UsbDongleTransport {
    port: SerialPort,
}

impl UsbDongleTransport {
    pub fn new(port: &str, baud_rate: u32) -> Result<Self, Error> {
        let port = SerialPort::open(port, |mut s: Settings| {
            s.set_raw();
            s.set_baud_rate(baud_rate)?;
            Ok(s)
        })?;

        Ok(Self { port })
    }

    fn delay_ms(&mut self, ms: u32) {
        std::thread::sleep(std::time::Duration::from_millis(ms as u64));
    }

    pub fn spi_csn_low(&mut self) -> Result<(), Error> {
        self.port.write_all(&CS_LOW_REQ)?;

        let mut resp_buf = [0u8; 4];
        self.port.read_exact(&mut resp_buf)?;

        if resp_buf != OK_RESP {
            return Err(Error::Io(std::io::Error::other("CS low failed")));
        }
        Ok(())
    }

    pub fn spi_csn_high(&mut self) -> Result<(), Error> {
        self.port.write_all(&CS_HIGH_REQ)?;

        let mut resp_buf = [0u8; 4];
        self.port.read_exact(&mut resp_buf)?;

        if resp_buf != OK_RESP {
            return Err(Error::Io(std::io::Error::other("CS high failed")));
        }
        Ok(())
    }

    fn spi_transfer(&mut self, tx_data: &[u8], rx: &mut [u8]) -> Result<(), Error> {
        let mut hex_chars = bytes_to_hexchars(tx_data);

        let read_len = hex_chars.len() + 2;

        hex_chars.push(b'\n');

        self.port.write_all(&hex_chars)?;
        let mut read_buf = vec![0; read_len];

        self.delay_ms(USB_DONGLE_READ_WRITE_DELAY);

        self.port.read_exact(&mut read_buf)?;

        read_buf.truncate(read_buf.len() - 2);
        hexchars_to_bytes(&read_buf, rx)?;
        Ok(())
    }

    fn _transfer_in_place_usb(&mut self, buf: &mut [u8], keep_cs_low: bool) -> Result<(), Error> {
        let mut hex_chars = bytes_to_hexchars(buf);

        let read_len = hex_chars.len() + 2;

        if keep_cs_low {
            hex_chars.push(b'x');
        }
        hex_chars.push(b'\n');

        self.port.write_all(&hex_chars)?;
        let mut read_buf = vec![0; read_len];

        self.delay_ms(USB_DONGLE_READ_WRITE_DELAY);

        self.port.read_exact(&mut read_buf)?;

        read_buf.truncate(read_buf.len() - 2);
        hexchars_to_bytes(&read_buf, buf)?;
        Ok(())
    }
}

impl spi::ErrorType for UsbDongleTransport {
    type Error = Error;
}

impl spi::SpiDevice for UsbDongleTransport {
    fn transaction(
        &mut self,
        operations: &mut [spi::Operation<'_, u8>],
    ) -> Result<(), Self::Error> {
        self.spi_csn_low()?;
        for op in operations {
            match op {
                spi::Operation::Read(words) => {
                    // Send zeros, receive into words
                    let tx = vec![0u8; words.len()];
                    self.spi_transfer(&tx, words)?;
                }
                spi::Operation::Write(tx) => {
                    // For pure write, transfer with dummy rx
                    let mut dummy = vec![0u8; tx.len()];
                    self.spi_transfer(tx, &mut dummy)?;
                }
                spi::Operation::Transfer(read, write) => {
                    self.spi_transfer(write, read)?;
                }
                spi::Operation::TransferInPlace(buffer) => {
                    let mut rx = vec![0u8; buffer.len()];
                    self.spi_transfer(buffer, &mut rx)?;
                    buffer.copy_from_slice(&rx);
                }
                spi::Operation::DelayNs(_ns) => {}
            }
        }
        self.spi_csn_high()?;
        Ok(())
    }
}

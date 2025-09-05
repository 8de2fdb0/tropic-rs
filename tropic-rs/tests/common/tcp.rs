//! TCP-backed implementation of embedded-hal::spi::SpiDevice

use core::fmt;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

use embedded_hal::spi::{ErrorKind, Operation, SpiDevice};
use log::{error, trace, warn};

pub const DEFAULT_TCP_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
pub const DEFAULT_TCP_PORT: u16 = 28992;

const MAX_BUFFER_LEN: usize = 1024;
const TCP_TAG_AND_LENGTH_SIZE: usize = 3;
const TX_ATTEMPTS: usize = 3;
const RX_ATTEMPTS: usize = 3;
const MAX_RECV_SIZE: usize = 1024;
const LT_L1_LEN_MAX: usize = tropic_rs::l1::LEN_MAX;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Protocol(&'static str),
    TagMismatch(u8, u8),
    InvalidResponseTag(u8),
    UnsupportedTag(u8),
    DataLenMismatch,
}

impl embedded_hal::spi::Error for Error {
    fn kind(&self) -> ErrorKind {
        match self {
            Error::Io(_) => ErrorKind::Other,
            Error::Protocol(_) => ErrorKind::Other,
            Error::TagMismatch(_, _) => ErrorKind::Other,
            Error::InvalidResponseTag(_) => ErrorKind::Other,
            Error::UnsupportedTag(_) => ErrorKind::Other,
            Error::DataLenMismatch => ErrorKind::Other,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            Error::TagMismatch(exp, got) => {
                write!(f, "Tag mismatch (expected {}, got {})", exp, got)
            }
            Error::InvalidResponseTag(tag) => write!(f, "Invalid tag: {}", tag),
            Error::UnsupportedTag(tag) => write!(f, "Unsupported tag: {}", tag),
            Error::DataLenMismatch => write!(f, "Data length mismatch"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

// Example tags, map these to your protocol
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Tag {
    SpiDriveCsnLow = 1,
    SpiDriveCsnHigh = 2,
    SpiSend = 3,
    Wait = 4,
    ErrInvalid = 0xfd,
    ErrUnsupported = 0xfe,
}

impl Tag {
    pub fn from_u8(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::SpiDriveCsnLow),
            2 => Some(Self::SpiDriveCsnHigh),
            3 => Some(Self::SpiSend),
            4 => Some(Self::Wait),
            0xfd => Some(Self::ErrInvalid),
            0xfe => Some(Self::ErrUnsupported),
            _ => None,
        }
    }
}

// Buffer structure
#[derive(Clone)]
pub struct Buffer {
    pub tag: u8,
    pub len: u16,
    pub payload: [u8; MAX_BUFFER_LEN - TCP_TAG_AND_LENGTH_SIZE], // remaining buffer
}

impl Buffer {
    pub fn new() -> Self {
        Buffer {
            tag: 0,
            len: 0,
            payload: [0u8; MAX_BUFFER_LEN - TCP_TAG_AND_LENGTH_SIZE],
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TCP_TAG_AND_LENGTH_SIZE + self.len as usize);
        v.push(self.tag);
        v.push((self.len & 0xFF) as u8);
        v.push((self.len >> 8) as u8);
        v.extend_from_slice(&self.payload[..self.len as usize]);
        v
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < TCP_TAG_AND_LENGTH_SIZE {
            return None;
        }
        let tag = buf[0];
        let len = (buf[1] as u16) | ((buf[2] as u16) << 8);
        if buf.len() < TCP_TAG_AND_LENGTH_SIZE + len as usize {
            return None;
        }
        let mut payload = [0u8; MAX_BUFFER_LEN - TCP_TAG_AND_LENGTH_SIZE];
        payload[..len as usize].copy_from_slice(&buf[3..3 + len as usize]);
        Some(Buffer { tag, len, payload })
    }
}

/// TCP SPI Device implementing embedded-hal traits
pub struct TcpSpiDevice {
    stream: TcpStream,
}

impl TcpSpiDevice {
    /// Connect to the TCP SPI server at (ip, port).
    pub fn connect(ip: Ipv4Addr, port: u16) -> Result<Self, Error> {
        let addr = SocketAddr::from((ip, port));
        let stream = TcpStream::connect(addr).map_err(Error::Io)?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
        Ok(Self { stream })
    }

    pub fn disconnect(&mut self) -> std::io::Result<()> {
        trace!("Disconnecting server");
        // TcpStream closes when dropped, but can explicitly shut down
        self.stream.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }

    // Helper to send all bytes, retrying if needed
    fn send_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        let mut attempts = 0;
        let mut sent = 0;
        while sent < buf.len() && attempts < TX_ATTEMPTS {
            trace!("Attempting to send data: attempt #{}", attempts + 1);
            let n = self.stream.write(&buf[sent..])?;
            if n == 0 {
                error!("Send failed: zero bytes sent.");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "send_all failed",
                ))?;
            }
            sent += n;
            attempts += 1;
        }
        if sent < buf.len() {
            error!(
                "Sent {} bytes instead of expected {} after {} attempts.",
                sent,
                buf.len(),
                TX_ATTEMPTS
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "send_all failed",
            ))?;
        }
        trace!("All {} bytes sent successfully.", buf.len());
        Ok(())
    }

    fn communicate(&mut self, tx_buffer: &Buffer) -> Result<Buffer, Error> {
        if tx_buffer.tag == Tag::SpiSend as u8 && tx_buffer.len == 0 {
            warn!("- Trying to send empty buffer");
        }

        let tx_buffer_bytes = tx_buffer.as_bytes();
        self.send_all(&tx_buffer_bytes)?;

        trace!("- Receiving data from target.");
        let mut rx_raw = [0u8; MAX_RECV_SIZE];
        let nb_bytes_received = self.stream.read(&mut rx_raw).map_err(|e| {
            error!("unable to read from tcp stream: {}", e);
            e
        })?;
        if nb_bytes_received < TCP_TAG_AND_LENGTH_SIZE {
            error!(
                "At least {} bytes are expected, received {}.",
                TCP_TAG_AND_LENGTH_SIZE, nb_bytes_received
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short read",
            ))?;
        }
        let mut rx_buffer = Buffer::from_bytes(&rx_raw[..nb_bytes_received]).ok_or_else(|| {
            error!("Buffer parse failed.");
            std::io::Error::new(std::io::ErrorKind::InvalidData, "parse error")
        })?;

        let nb_bytes_to_receive = TCP_TAG_AND_LENGTH_SIZE + rx_buffer.len as usize;
        if nb_bytes_received < nb_bytes_to_receive {
            let mut total_received = nb_bytes_received;
            let mut offset = nb_bytes_received;
            for attempt in 0..RX_ATTEMPTS {
                trace!(
                    "Attempting to receive remaining bytes: attempt #{}",
                    attempt + 1
                );
                let n = self.stream.read(&mut rx_raw[offset..]).map_err(|e| {
                    error!("unable to read from tcp stream: {}", e);
                    e
                })?;
                if n == 0 {
                    // error!("Receive failed: zero bytes.");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "short read",
                    ))?;
                }
                offset += n;
                total_received += n;
                if total_received >= nb_bytes_to_receive {
                    break;
                }
            }
            if total_received != nb_bytes_to_receive {
                error!(
                    "Received {} bytes in total instead of {}.",
                    total_received, nb_bytes_to_receive
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short read",
                ))?;
            }
            rx_buffer = Buffer::from_bytes(&rx_raw[..total_received]).ok_or_else(|| {
                error!("Buffer parse failed after retry.");
                std::io::Error::new(std::io::ErrorKind::InvalidData, "parse error")
            })?;
        }

        let rx_tag = Tag::from_u8(rx_buffer.tag);
        if rx_tag == Some(Tag::ErrInvalid) {
            error!("Tag {} is not known by the server.", tx_buffer.tag);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid tag",
            ))?;
        }
        if rx_tag == Some(Tag::ErrUnsupported) {
            error!("Tag {} is not supported by the server.", tx_buffer.tag);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported tag",
            ))?;
        }
        if rx_buffer.tag != tx_buffer.tag {
            error!(
                "Expected tag {}, received {}.",
                tx_buffer.tag, rx_buffer.tag
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "tag mismatch",
            ))?;
        }
        trace!("Rx tag and tx tag match: {}", rx_buffer.tag);

        Ok(rx_buffer)
    }

    // SPI chip select LOW
    pub fn spi_csn_low(&mut self) -> Result<(), Error> {
        trace!("-- Driving Chip Select to Low.");
        let mut tx_buffer = Buffer::new();
        tx_buffer.tag = Tag::SpiDriveCsnLow as u8;
        let _ = self.communicate(&tx_buffer)?;
        Ok(())
    }

    // SPI chip select HIGH
    pub fn spi_csn_high(&mut self) -> Result<(), Error> {
        trace!("-- Driving Chip Select to High.");
        let mut tx_buffer = Buffer::new();
        tx_buffer.tag = Tag::SpiDriveCsnHigh as u8;
        let _ = self.communicate(&tx_buffer)?;
        Ok(())
    }

    // SPI transfer
    pub fn spi_transfer(&mut self, tx_data: &[u8], rx: &mut [u8]) -> Result<(), Error> {
        let tx_len: usize = tx_data.len();
        if tx_len > LT_L1_LEN_MAX {
            error!(
                "Data length error: tx_data.len {} > {}",
                tx_len, LT_L1_LEN_MAX
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "data length error",
            ))?;
        }
        trace!("-- Sending data through SPI bus.");

        let mut tx_buffer = Buffer::new();

        tx_buffer.tag = Tag::SpiSend as u8;
        tx_buffer.len = tx_len as u16;
        tx_buffer.payload[..tx_len].copy_from_slice(tx_data);

        let rx_buffer = self.communicate(&tx_buffer)?;
        let rx_buffer_len = rx_buffer.len as usize;

        rx[..rx_buffer_len].copy_from_slice(&rx_buffer.payload[..rx_buffer_len]);
        Ok(())
    }
}

impl embedded_hal::spi::ErrorType for TcpSpiDevice {
    type Error = Error;
}

impl SpiDevice for TcpSpiDevice {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        self.spi_csn_low()?;
        for op in operations {
            match op {
                Operation::Read(words) => {
                    // Send zeros, receive into words
                    let tx = vec![0u8; words.len()];
                    self.spi_transfer(&tx, words)?;
                }
                Operation::Write(tx) => {
                    // For pure write, transfer with dummy rx
                    let mut dummy = vec![0u8; tx.len()];
                    self.spi_transfer(tx, &mut dummy)?;
                }
                Operation::Transfer(read, write) => {
                    self.spi_transfer(write, read)?;
                }
                Operation::TransferInPlace(buffer) => {
                    let mut rx = vec![0u8; buffer.len()];
                    self.spi_transfer(buffer, &mut rx)?;
                    buffer.copy_from_slice(&rx);
                }
                Operation::DelayNs(_ns) => {}
            }
        }
        self.spi_csn_high()?;
        Ok(())
    }
}

// // Optionally: implement SpiBus for single (not batch) transfers
// impl SpiBus for TcpSpiDevice {
//     type Error = TcpSpiError;

//     fn read(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
//         // Send zeros, receive into words
//         let tx = vec![0u8; words.len()];
//         self.transfer_bytes(&tx, words)
//     }

//     fn write(&mut self, words: &[u8]) -> Result<(), Self::Error> {
//         let mut rx = vec![0u8; words.len()];
//         self.transfer_bytes(words, &mut rx)
//     }

//     fn transfer<'w>(&mut self, words: &'w mut [u8]) -> Result<(), Self::Error> {
//         let tx = words.to_vec();
//         let mut rx = vec![0u8; words.len()];
//         self.transfer_bytes(&tx, &mut rx)?;
//         words.copy_from_slice(&rx);
//         Ok(())
//     }

//     fn transfer_in_place(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
//         self.transfer(words)
//     }

//     fn flush(&mut self) -> Result<(), Self::Error> {
//         // No buffering, nothing to do
//         Ok(())
//     }
// }

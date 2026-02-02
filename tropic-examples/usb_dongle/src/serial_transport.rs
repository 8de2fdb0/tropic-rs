extern crate std;

use serial2::{SerialPort, Settings};
use std::vec::Vec;

use tropic_rs::{
    l1::{ChipMode, ChipStatus, Response, GET_RESPONSE_REQ_ID, READ_MAX_TRIES, READ_RETRY_DELAY},
    transport::{Error as TransportError, TropicTransport},
};

// USB dongle specific constants
// delay before doing a read, to give the fw time to prepare the response
const USB_DONGE_INITIAL_READ_DELAY: u32 = 300;
// delay before retrying a read if the chip is busy
const USB_DONGLE_READ_WRITE_DELAY: u32 = 10;

//const MAX_BUFFER_LEN: usize = crate::l1::LEN_MAX * 2 + 2;
const HEX_CHAR_LOOKUP: [u8; 16] = *b"0123456789ABCDEF";

// Constants for usb-dongle fw communication
// see: https://github.com/tropicsquare/ts13-usb-dev-kit-fw
const CS_HIGH_REQ: [u8; 5] = *b"CS=0\n";
const OK_RESP: [u8; 4] = *b"OK\r\n";

#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    ReqLen,
    InvalidHexChar,
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

impl From<Error> for TransportError {
    fn from(err: Error) -> Self {
        TransportError::Other(err.into())
    }
}

/// Converts bytes to hex characters
///
/// [255] -> ['F', 'F']
fn bytes_to_hexchars(buf: &[u8]) -> Vec<u8> {
    let mut hex_chars = Vec::with_capacity(buf.len() * 2);
    for b in buf.iter() {
        hex_chars.push(HEX_CHAR_LOOKUP[(b >> 4) as usize]);
        hex_chars.push(HEX_CHAR_LOOKUP[(b & 0xF) as usize]);
    }
    hex_chars
}

/// Converts hex characters to bytes
///
/// ['F', 'F'] -> [255]
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

    #[allow(unused)]
    fn cs_high(&mut self) -> Result<(), Error> {
        self.port.write_all(&CS_HIGH_REQ)?;

        let mut resp_buf = [0u8; 4];
        self.port.read_exact(&mut resp_buf)?;

        if resp_buf != OK_RESP {
            return Err(Error::Io(std::io::Error::other("CS high failed")));
        }
        Ok(())
    }

    fn transfer_in_place_usb(&mut self, buf: &mut [u8], keep_cs_low: bool) -> Result<(), Error> {
        let mut hex_chars = bytes_to_hexchars(buf);

        // read the same amount of bytes as written, every read finalizes with [CR,LF]
        let read_len = hex_chars.len() + 2;

        if keep_cs_low {
            // add keep_cs_low_char
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

// converts a Vec<u8> to [u8; N], padding with zeros if necessary
fn vec_to_padded_array<const N: usize>(vec: Vec<u8>) -> Result<[u8; N], TransportError> {
    if vec.len() > N {
        return Err(TransportError::InvalidDataLen);
    }
    let mut array = [0u8; N];
    array[..vec.len()].copy_from_slice(&vec);
    Ok(array)
}

impl TropicTransport for UsbDongleTransport {
    fn transfer_in_place(&mut self, buf: &mut [u8]) -> Result<(), TransportError> {
        self.transfer_in_place_usb(buf, false)?;
        Ok(())
    }

    fn write(&mut self, req: &[u8]) -> Result<(), TransportError> {
        let mut req_buf = req.to_vec();
        self.transfer_in_place_usb(&mut req_buf, false)?;
        Ok(())
    }

    fn read<const N: usize>(&mut self) -> Result<Response<N>, TransportError> {
        let mut retry = READ_MAX_TRIES;

        let mut chip_status = [0_u8; 1];
        let mut data = [0_u8; N];

        // add a delay, chip switches into alarm mode if read is done too quickly
        self.delay_ms(USB_DONGE_INITIAL_READ_DELAY);

        while retry > 0 {
            retry -= 1;
            chip_status[0] = GET_RESPONSE_REQ_ID;
            self.transfer_in_place_usb(&mut chip_status, true)?;
            let chip_status: ChipStatus = chip_status[0].into();

            if chip_status.alarm {
                return Err(TransportError::AlarmMode);
            }

            if chip_status.ready {
                let mut status_len = [0_u8; 2];
                self.transfer_in_place_usb(&mut status_len, true)?;

                // status of 0xff means that the chip has no response to send.
                // TODO: should we check for uncommen status here? > 0x79
                if status_len[0] == 0xff {
                    self.delay_ms(READ_RETRY_DELAY as u32);
                    continue;
                }

                if status_len[1] > 0 {
                    // only read data if the status_len resp contains len > 0
                    let mut data_vec = vec![0_u8; status_len[1] as usize];
                    self.transfer_in_place_usb(&mut data_vec, true)?;
                    data = vec_to_padded_array(data_vec)?;
                }

                let mut crc = [0_u8; 2];
                self.transfer_in_place_usb(&mut crc, false)?;
                return Ok(Response {
                    chip_status,
                    status: status_len[0],
                    len: status_len[1],
                    data,
                    crc,
                });
            } else {
                match chip_status.chip_mode() {
                    ChipMode::Startup => {
                        self.delay_ms(READ_RETRY_DELAY as u32);
                    }
                    ChipMode::Application => {
                        // TODO: check LT_USE_INT_PIN impl
                        // seems usb dongle STM32 app doesn't expose the hardware interupt
                        self.delay_ms(READ_RETRY_DELAY as u32);
                    }
                }
            }
        }
        Err(TransportError::ChipBusy)
    }
}

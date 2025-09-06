// mod x509_parser;

pub(crate) mod cert;
pub(crate) mod cert_store;
pub mod info;

use core::fmt::Debug;

use crate::{
    common,
    crc16::{add_crc, crc16, u8_slice_to_crc},
    l1,
};

// length of the cmd id field.
pub(crate) const CMD_ID_LEN: usize = 1;

// Length of the cmd size field.
pub(crate) const CMD_SIZE_LEN: usize = 1;

// Lenght of the cmd crc field.
pub(crate) const CMD_CRC_LEN: usize = 2;

// TODO Maximal size of data field in one L2 transfer
pub(crate) const CHUNK_MAX_DATA_SIZE: usize = 252;
// Maximal size of one l2 frame
#[allow(unused)]
pub(crate) const L2_MAX_FRAME_SIZE: usize =
    CMD_ID_LEN + CMD_SIZE_LEN + CHUNK_MAX_DATA_SIZE + CMD_CRC_LEN;

#[derive(Debug, PartialEq)]
pub enum Error {
    Spi(embedded_hal::spi::ErrorKind),
    Crc(crate::crc16::Error),
    L1(crate::l1::Error),
    InvalidCRC,
    InvalidStatus(u8),
    RespErr(Status),
    RespMaxLoops,
    EncCmdReqSize(usize, usize),
    EncCmdRespSize(usize, usize),
    CertStore(cert_store::Error),
    NoSession,
    ChipMode(l1::ChipMode),
    UnknownFirmwareType(u16),
    UnknwonFirmwareHeaderSize,
    FwUpdateDataMin,
    FwUpdateDataMax,
    FwUpdateChunkLen,
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spi(err) => f.write_fmt(format_args!("spi error: {}", err)),
            Self::Crc(err) => f.write_fmt(format_args!("crc error: {}", err)),
            Self::L1(err) => f.write_fmt(format_args!("l1 error: {}", err)),
            Self::InvalidCRC => f.write_fmt(format_args!("l2: invalid crc")),
            Self::EncCmdReqSize(exp, act) => f.write_fmt(format_args!(
                "l2: invalid encrypted command length: expected {} bytes, got {}",
                exp, act
            )),
            Self::EncCmdRespSize(exp, act) => f.write_fmt(format_args!(
                "l2: invalid encrypted command response length: expected {} bytes, got {}",
                exp, act
            )),
            Self::InvalidStatus(status) => {
                f.write_fmt(format_args!("l2: invalid status: {}", status))
            }
            Self::RespErr(status) => f.write_fmt(format_args!(
                "response contained error status: {:?}",
                status
            )),
            Self::RespMaxLoops => f.write_fmt(format_args!("l2: response max loops reached")),
            Self::CertStore(err) => f.write_fmt(format_args!("cert store error: {}", err)),
            Self::NoSession => f.write_fmt(format_args!("secure session not established")),
            Self::ChipMode(mode) => {
                f.write_fmt(format_args!("chip is in wrong mode, expected: {:?}", mode))
            }
            Self::UnknownFirmwareType(fw_type) => {
                f.write_fmt(format_args!("unknown firmware type: {}", fw_type))
            }
            Self::UnknwonFirmwareHeaderSize => {
                f.write_fmt(format_args!("unknown firmware header size"))
            }
            Self::FwUpdateDataMin => {
                f.write_fmt(format_args!("invalid firmware update data size: too small"))
            }
            Self::FwUpdateDataMax => {
                f.write_fmt(format_args!("invalid firmware update data size: too large"))
            }
            Self::FwUpdateChunkLen => {
                f.write_fmt(format_args!("invalid firmware update chunk length"))
            }
        }
    }
}

impl<E: embedded_hal::spi::Error> From<E> for Error {
    fn from(err: E) -> Self {
        Self::Spi(err.kind())
    }
}

impl From<crate::crc16::Error> for Error {
    fn from(err: crate::crc16::Error) -> Self {
        Self::Crc(err)
    }
}

impl From<crate::l1::Error> for Error {
    fn from(err: crate::l1::Error) -> Self {
        Self::L1(err)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /// Request was sucessfull.
    RequestOk = 0x01,
    /// Result was successfull.
    ResultOk = 0x02,
    /// There is more than one chunk to be expected for the current request.
    RequestCont = 0x03,
    /// There is more than one chunk to be received for the current response.
    ResultCont = 0x04,
    /// Secure channel handshake failed
    /// and secure session is not established.
    HskErr = 0x79,
    /// TROPIC01 is not in secure channel mode
    /// and an [`enc_session::EncryptedCmdReq`] was sent.
    /// TROPIC01 ignores the L2 request frame.
    NoSession = 0x7A,
    /// Invalid L3 layer authentication.
    /// TROPIC01 will invalidate the current session,
    /// and move to idle mode.
    TagErr = 0x7B,
    /// Incorrect CRC-16 checksum.
    /// The associated L2 frame was ignored.
    CrcErr = 0x7C,
    /// REQ_ID of last request is not known to TROPIC01.
    UnknownReq = 0x7E,
    /// Generic error from TROPIC01.
    GenErr = 0x7F,
    /// No response on the SPI bus will read as a array full of 0xff,
    /// So if status is 0xff, that means no response.
    /// TODO: add a real check to see if the whole response is 0xff
    NoResp = 0xFF,
}

impl TryFrom<u8> for Status {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::RequestOk),
            0x02 => Ok(Self::ResultOk),
            0x03 => Ok(Self::RequestCont),
            0x04 => Ok(Self::ResultCont),
            0x79 => Ok(Self::HskErr),
            0x7A => Ok(Self::NoSession),
            0x7B => Ok(Self::TagErr),
            0x7C => Ok(Self::CrcErr),
            0x7E => Ok(Self::UnknownReq),
            0x7F => Ok(Self::GenErr),
            0xFF => Ok(Self::NoResp),
            _ => Err(Error::InvalidStatus(value)),
        }
    }
}

impl From<Status> for u8 {
    fn from(value: Status) -> Self {
        value as u8
    }
}

pub struct Response<const N: usize> {
    pub(crate) chip_status: l1::ChipStatus,
    pub(crate) status: Status,
    pub(crate) len: u8,
    pub(crate) data: [u8; N],
    pub(crate) crc: [u8; 2],
}

impl<const N: usize> Response<N> {
    pub(crate) fn check_crc(&self) -> Result<(), Error> {
        let status_and_len = [self.status.clone() as u8, self.len];
        let exp_crc = crc16(&self.data[0..self.len as usize], Some(&status_and_len));
        let act_crc = u8_slice_to_crc(&self.crc);
        if exp_crc != act_crc {
            return Err(Error::InvalidCRC);
        }
        Ok(())
    }
}

impl<const N: usize> TryFrom<l1::Response<N>> for Response<N> {
    type Error = Error;

    fn try_from(resp: l1::Response<N>) -> Result<Self, Self::Error> {
        let status = Status::try_from(resp.status)?;

        let l2_resp = Self {
            chip_status: resp.chip_status,
            status,
            len: resp.len,
            data: resp.data,
            crc: resp.crc,
        };

        match l2_resp.status {
            Status::HskErr
            | Status::TagErr
            | Status::CrcErr
            | Status::UnknownReq
            | Status::GenErr
            | Status::NoResp => {
                return Err(Error::RespErr(l2_resp.status));
            }
            Status::NoSession => return Err(Error::NoSession),
            Status::RequestOk | Status::ResultOk => l2_resp.check_crc()?,
            _ => (),
        };

        Ok(l2_resp)
    }
}

pub(crate) fn receive<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
    const N: usize,
>(
    spi_device: &mut SPI,
    delay: &mut D,
) -> Result<Response<N>, Error> {
    l1::receive(spi_device, delay)?.try_into()
}

mod sealed {
    pub trait Sealed {}
}

pub trait ReceiveResponse<const N: usize>: sealed::Sealed
where
    Self: TryFrom<Response<N>>,
    <Self as TryFrom<Response<N>>>::Error: Into<Error>,
{
    fn receive<SPI: embedded_hal::spi::SpiDevice, D: embedded_hal::delay::DelayNs>(
        spi_device: &mut SPI,
        delay: &mut D,
    ) -> Result<Self, Error> {
        let resp: Response<N> = l1::receive(spi_device, delay)?.try_into()?;
        let item = Self::try_from(resp).map_err(Into::into)?;
        Ok(item)
    }
}

const STATUS_RSP_LEN: usize = 0;

/// Common type for all responses that only return a status.
#[derive(Debug)]
pub struct StatusResp {
    /// CHIP_STATUS byte
    pub chip_status: l1::ChipStatus,
    /// L2 status byte
    pub status: Status,
    /// Length of incoming data
    pub len: u8,
    /// Checksum
    pub crc: [u8; 2],
}

impl From<Response<{ STATUS_RSP_LEN }>> for StatusResp {
    fn from(resp: Response<{ STATUS_RSP_LEN }>) -> Self {
        Self {
            chip_status: resp.chip_status,
            status: resp.status,
            len: resp.len,
            crc: resp.crc,
        }
    }
}

impl sealed::Sealed for StatusResp {}

impl ReceiveResponse<{ STATUS_RSP_LEN }> for StatusResp {}

pub mod handshake {
    use super::*;

    const HANDSHAKE_REQ_ID: u8 = 0x02;

    // KEY[32] KEY_SLOT[1]
    pub const HANDSHAKE_REQ_LEN: u8 = 33;

    // KEY[32] AUTH_TAG[16]
    pub const HANDSHAKE_RSP_LEN: usize = 48;

    const HANDSHAKE_CMD_LEN: usize =
        CMD_ID_LEN + CMD_SIZE_LEN + HANDSHAKE_REQ_LEN as usize + CMD_CRC_LEN;

    pub struct HandshakeReq;

    impl HandshakeReq {
        pub fn create(
            host_pubkey: x25519_dalek::PublicKey,
            pairing_key_slot: common::PairingKeySlot,
        ) -> Result<[u8; HANDSHAKE_CMD_LEN], Error> {
            let mut data = [0_u8; HANDSHAKE_CMD_LEN];
            data[0] = HANDSHAKE_REQ_ID;
            data[1] = HANDSHAKE_REQ_LEN;
            data[2..34].copy_from_slice(host_pubkey.as_bytes());
            data[34] = pairing_key_slot as u8;
            data[35] = 0;
            data[36] = 0;
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    pub struct HandshakeResp {
        /// CHIP_STATUS byte
        pub chip_status: l1::ChipStatus,
        /// L2 status byte
        pub status: Status,
        /// Length of incoming data
        pub len: u8,
        /// TROPIC01's X25519 Ephemeral key
        pub et_pubkey: x25519_dalek::PublicKey,
        /// The Secure Channel Handshake Authentication Tag
        pub auth_tag: [u8; 16],
        /// Checksum
        pub crc: [u8; 2],
    }

    impl From<Response<{ HANDSHAKE_RSP_LEN }>> for HandshakeResp {
        fn from(resp: Response<{ HANDSHAKE_RSP_LEN }>) -> Self {
            let mut et_pubkey = [0_u8; 32];
            et_pubkey.copy_from_slice(&resp.data[0..32]);
            let mut auth_tag = [0_u8; 16];
            auth_tag.copy_from_slice(&resp.data[32..48]);

            Self {
                chip_status: resp.chip_status,
                status: resp.status,
                len: resp.len,
                et_pubkey: et_pubkey.into(),
                auth_tag,
                crc: resp.crc,
            }
        }
    }

    impl sealed::Sealed for HandshakeResp {}

    impl ReceiveResponse<{ HANDSHAKE_RSP_LEN }> for HandshakeResp {}
}

pub mod sleep {
    use super::*;

    const SLEEP_REQ_ID: u8 = 0x20;
    const SLEEP_REQ_LEN: u8 = 0x01;

    #[allow(unused)]
    pub(crate) const SLEEP_RSP_LEN: usize = 0x00;

    #[repr(u8)]
    pub enum SleepKind {
        /// Regular Sleep Mode
        Regular = 0x0f,
        /// Deep Sleep Mode
        Deep = 0x0a,
    }

    pub struct SleepReq;
    impl SleepReq {
        pub fn create(sleep_kind: SleepKind) -> Result<[u8; 5], Error> {
            let mut data = [SLEEP_REQ_ID, SLEEP_REQ_LEN, sleep_kind as u8, 0, 0];
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    /// Response from TROPIC01 afyer requesting sleep mode.
    pub type SleepResp = StatusResp;
}

// todo: think about renaming to reboot
pub mod restart {
    use super::*;

    const STARTUP_REQ_ID: u8 = 0xb3;
    const STARTUP_REQ_LEN: u8 = 0x1;

    #[allow(unused)]
    const STARTUP_RSP_LEN: usize = 0x0;

    const STARTUP_CMD_LEN: usize =
        CMD_ID_LEN + CMD_SIZE_LEN + STARTUP_REQ_LEN as usize + CMD_CRC_LEN;

    #[repr(u8)]
    pub enum RestartMode {
        Reboot = 0x01,
        Maintanance = 0x03,
    }

    /// Request for TROPIC01 to reset.
    pub struct StartupReq;

    impl StartupReq {
        pub fn create(startup_id: RestartMode) -> Result<[u8; STARTUP_CMD_LEN], Error> {
            let mut data = [STARTUP_REQ_ID, STARTUP_REQ_LEN, startup_id as u8, 0, 0];
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    /// Response from TROPIC01 afyer requesting a reset.
    pub type StartupResp = StatusResp;
}

pub mod log {
    use super::*;

    const GET_LOG_REQ_ID: u8 = 0xa2;
    const GET_LOG_REQ_LEN: u8 = 0x00;

    #[allow(unused)]
    const GET_LOG_RSP_MIN_LEN: usize = 0x00;
    pub(crate) const GET_LOG_RSP_MAX_LEN: usize = 0xff;

    const GET_LOG_CMD_LEN: usize =
        CMD_ID_LEN + CMD_SIZE_LEN + GET_LOG_REQ_LEN as usize + CMD_CRC_LEN;

    pub struct GetLogReq;

    impl GetLogReq {
        pub fn create() -> Result<[u8; GET_LOG_CMD_LEN], Error> {
            let mut data = [GET_LOG_REQ_ID, GET_LOG_REQ_LEN, 0, 0];
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    #[derive(Debug)]
    pub struct GetLogResp {
        /// CHIP_STATUS byte
        pub chip_status: l1::ChipStatus,
        /// L2 status byte
        pub status: Status,
        /// Length of incoming data
        pub len: u8,
        /// Log message of RISCV FW
        pub log_msg: [u8; 255],
        /// Checksum
        pub crc: [u8; 2],
    }

    impl core::fmt::Display for GetLogResp {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let string_slice = &self.log_msg[..self.len as usize];

            match core::str::from_utf8(string_slice) {
                Ok(s) => f.write_str(s),
                Err(_) => f.write_str("[Invalid UTF-8]"), // Handle non-UTF-8 data gracefully
            }
        }
    }

    impl From<Response<{ GET_LOG_RSP_MAX_LEN }>> for GetLogResp {
        fn from(resp: Response<{ GET_LOG_RSP_MAX_LEN }>) -> Self {
            Self {
                chip_status: resp.chip_status,
                status: resp.status,
                len: resp.len,
                log_msg: resp.data,
                crc: resp.crc,
            }
        }
    }

    impl sealed::Sealed for GetLogResp {}

    impl ReceiveResponse<{ GET_LOG_RSP_MAX_LEN }> for GetLogResp {}
}

pub mod enc_session {
    use crate::l3;

    use super::*;

    const ENCRYPTED_CMD_REQ_ID: u8 = 0x04;

    #[allow(unused)]
    const ENCRYPTED_CMD_REQ_LEN_MIN: usize = 19;
    #[allow(unused)]
    const ENCRYPTED_CMD_REQ_CMD_CIPHERTEXT_LEN_MIN: usize = 1;

    // Maximal length of field cmd_ciphertext
    #[allow(unused)]
    const ENCRYPTED_CMD_REQ_CMD_CIPHERTEXT_LEN_MAX: usize = 4096;

    #[allow(unused)]
    const ENCRYPTED_CMD_RSP_LEN_MIN: usize = 19;

    const MAX_CHUNKS: usize = l3::FRAME_MAX_LEN.div_ceil(CHUNK_MAX_DATA_SIZE);

    const ENCRYPTED_RESP_LEN: usize = CHUNK_MAX_DATA_SIZE + 3;

    // Safety number - limit number of loops during l3 chunks reception. TROPIC01 divides data into 128B
    // chunks, length of L3 buffer is (2 + 4096 + 16).
    // Divided by typical chunk length: (2 + 4096 + 16) / 128 => 32,
    // with a few added loops it is set to 42
    //
    const MAX_LOOPS: usize = 42;

    fn process_chunk(chunk: &[u8], buf: &mut [u8; CHUNK_MAX_DATA_SIZE + 4]) -> Result<(), Error> {
        let chunk_len = chunk.len();

        buf[0] = ENCRYPTED_CMD_REQ_ID;
        buf[1] = chunk_len as u8;
        buf[2..chunk_len + 2].copy_from_slice(chunk);
        buf[chunk_len + 2] = 0;
        buf[chunk_len + 3] = 0;
        add_crc(buf)?;
        Ok(())
    }

    pub struct EncryptedCmdReq {
        pub count: usize,
        pub last_len: usize,
        pub chunks: [[u8; CHUNK_MAX_DATA_SIZE + 4]; MAX_CHUNKS],
    }

    impl EncryptedCmdReq {
        pub fn create<const N: usize>(enc_cmd: &l3::Request<N>) -> Result<Self, Error> {
            if enc_cmd.size as usize > l3::PACKET_MAX_LEN {
                return Err(Error::EncCmdReqSize(
                    l3::PACKET_MAX_LEN,
                    enc_cmd.size as usize,
                ));
            }

            let mut chunks = [[0u8; CHUNK_MAX_DATA_SIZE + 4]; MAX_CHUNKS];

            // set last chunk size to CHUNK_MAX_DATA_SIZE + 4
            // so in case l3_cmd_stream fits exactly into a multiple of
            // CHUNK_MAX_DATA_SIZE the last chunk has the correct size
            // CMD_ID[1] + REQ_LEN[1] + data_len + CRC[2]
            let mut last_chunk_len = CHUNK_MAX_DATA_SIZE + 4;
            let mut chunks_count = 0;

            let size_as_u8_arr = enc_cmd.size.to_le_bytes();

            let mut l3_cmd_stream = size_as_u8_arr
                .iter()
                .copied()
                .chain(enc_cmd.data[..enc_cmd.size as usize].iter().copied())
                .chain(enc_cmd.tag.iter().copied());

            while let Some(next_byte) = l3_cmd_stream.next() {
                let mut chunk_buffer = [0u8; CHUNK_MAX_DATA_SIZE];
                chunk_buffer[0] = next_byte;
                let mut current_len = 1;

                for (i, b) in l3_cmd_stream
                    .by_ref()
                    .take(CHUNK_MAX_DATA_SIZE - 1)
                    .enumerate()
                {
                    chunk_buffer[i + 1] = b;
                    current_len += 1;
                }

                if current_len < CHUNK_MAX_DATA_SIZE {
                    // store last chunk size
                    // CMD_ID[1] + REQ_LEN[1] + data_len + CRC[2]
                    last_chunk_len = current_len + 4;
                }

                process_chunk(&chunk_buffer[..current_len], &mut chunks[chunks_count])?;
                chunks_count += 1;
            }

            Ok(Self {
                count: chunks_count,
                last_len: last_chunk_len,
                chunks,
            })
        }
    }

    pub struct EncryptedCmdResp {
        /// CHIP_STATUS byte
        pub chip_status: l1::ChipStatus,
        /// L2 status byte
        pub status: Status,
        /// Length of incoming data
        pub len: u8,
        /// encrypted response chunk
        pub data: [u8; 255],
        /// Checksum
        pub crc: [u8; 2],
    }

    impl From<Response<{ ENCRYPTED_RESP_LEN }>> for EncryptedCmdResp {
        fn from(resp: Response<{ ENCRYPTED_RESP_LEN }>) -> Self {
            Self {
                chip_status: resp.chip_status,
                status: resp.status,
                len: resp.len,
                data: resp.data,
                crc: resp.crc,
            }
        }
    }

    pub(crate) fn receive<
        SPI: embedded_hal::spi::SpiDevice,
        D: embedded_hal::delay::DelayNs,
        const N: usize,
    >(
        spi_device: &mut SPI,
        delay: &mut D,
        buff: &mut [u8; N],
    ) -> Result<(), Error> {
        let mut offset: usize = 0;
        let mut seek: usize = 0;

        let mut loops: usize = 0;
        loop {
            loops += 1;
            if loops > MAX_LOOPS {
                return Err(Error::RespMaxLoops);
            }

            let resp: EncryptedCmdResp = super::receive(spi_device, delay)?.into();

            if buff.len() < offset + resp.len as usize {
                // make sure buff is large enough
                return Err(Error::EncCmdRespSize(
                    buff.len(),
                    offset + resp.len as usize,
                ));
            }
            match resp.status {
                Status::ResultCont => {
                    seek += resp.len as usize;
                    buff[offset..seek].copy_from_slice(&resp.data[..resp.len as usize]);
                    offset += resp.len as usize;
                }
                Status::ResultOk => {
                    seek += resp.len as usize;
                    buff[offset..seek].copy_from_slice(&resp.data[..resp.len as usize]);
                    return Ok(());
                }
                _ => return Err(Error::RespErr(resp.status)),
            }
        }
    }

    // request id
    const ENCRYPTED_SESSION_ABT_ID: u8 = 0x08;
    // request length
    const ENCRYPTED_SESSION_ABT_LEN: u8 = 0;

    //  response length
    #[allow(unused)]
    pub(crate) const ENCRYPTED_SESSION_ABT_RSP_LEN: usize = 0;

    const ENCRYPTED_SESSION_ABT_CMD_LEN: usize =
        CMD_ID_LEN + CMD_SIZE_LEN + ENCRYPTED_SESSION_ABT_LEN as usize + CMD_CRC_LEN;

    /// Request to abort current Secure Channel Session and
    /// execution of L3 command (TROPIC01 moves to Idle Mode).
    pub struct SessionAbortReq;

    impl SessionAbortReq {
        pub fn create() -> Result<[u8; ENCRYPTED_SESSION_ABT_CMD_LEN], Error> {
            let mut data = [ENCRYPTED_SESSION_ABT_ID, ENCRYPTED_SESSION_ABT_LEN, 0, 0];
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    /// Response from TROPIC01 afyer requesting a session abort.
    pub type SessionAbortResp = StatusResp;

    #[cfg(test)]
    pub(crate) mod tests {
        use super::*;

        const TEST_TAG: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        fn expected_chunk(
            prefix: &[u8],
            data: &[u8],
            suffix: &[u8],
        ) -> [u8; CHUNK_MAX_DATA_SIZE + 4] {
            let mut chunk = [0_u8; CHUNK_MAX_DATA_SIZE + 4];
            chunk[0..prefix.len()].copy_from_slice(prefix);
            chunk[prefix.len()..prefix.len() + data.len()].copy_from_slice(data);
            chunk[prefix.len() + data.len()..prefix.len() + data.len() + suffix.len()]
                .copy_from_slice(suffix);
            chunk
        }

        fn create_data<const N: usize>() -> [u8; N] {
            let mut data = [0_u8; N];
            for (i, item) in data.iter_mut().enumerate().take(N) {
                *item = i as u8;
            }
            data
        }

        fn calc_last_chunk_len(data_len: usize) -> usize {
            CMD_ID_LEN
                + CMD_SIZE_LEN
                + (l3::CMD_SIZE_LEN + data_len + l3::TAG_LEN) % CHUNK_MAX_DATA_SIZE
                + CMD_CRC_LEN
        }

        #[test]
        fn test_enc_cmd_req_create_with_one_chunk() {
            let data = create_data::<10>();

            let enc_cmd = l3::Request {
                size: 10,
                data,
                tag: TEST_TAG,
            };

            let expected = expected_chunk(
                &[4, 28, 10, 0],
                &data,
                &[
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 101, 218,
                ],
            );

            let enc_cmd_chunks = EncryptedCmdReq::create(&enc_cmd).unwrap();

            assert_eq!(enc_cmd_chunks.count, 1);
            assert_eq!(enc_cmd_chunks.last_len, calc_last_chunk_len(10));
            assert_eq!(enc_cmd_chunks.chunks[0], expected);
        }

        #[test]
        fn test_enc_cmd_req_create_with_two_chunks() {
            let data = create_data::<300>();

            let enc_cmd = l3::Request {
                size: 300,
                data,
                tag: TEST_TAG,
            };

            let expected0 = expected_chunk(&[4, 252, 44, 1], &data[..250], &[115, 127]);
            let expected1 = expected_chunk(
                &[4, 66],
                &data[250..],
                &[
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 55, 121,
                ],
            );

            let enc_cmd_chunks = EncryptedCmdReq::create(&enc_cmd).unwrap();

            assert_eq!(enc_cmd_chunks.count, 2);
            assert_eq!(enc_cmd_chunks.last_len, calc_last_chunk_len(300));
            assert_eq!(enc_cmd_chunks.chunks[0], expected0);
            assert_eq!(enc_cmd_chunks.chunks[1], expected1);
        }

        #[test]
        fn test_enc_cmd_req_create_with_three_chunks() {
            let data = create_data::<550>();

            let enc_cmd = l3::Request {
                size: 550,
                data,
                tag: TEST_TAG,
            };

            let expected0 = expected_chunk(&[4, 252, 38, 2], &data[..250], &[178, 10]);
            let expected1 = expected_chunk(&[4, 252], &data[250..502], &[200, 60]);

            let expected2 = expected_chunk(
                &[4, 64],
                &data[502..],
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 8, 13],
            );

            let enc_cmd_chunks = EncryptedCmdReq::create(&enc_cmd).unwrap();

            assert_eq!(enc_cmd_chunks.count, 3);
            assert_eq!(enc_cmd_chunks.last_len, calc_last_chunk_len(550));
            assert_eq!(enc_cmd_chunks.chunks[0], expected0);
            assert_eq!(enc_cmd_chunks.chunks[1], expected1);
            assert_eq!(enc_cmd_chunks.chunks[2], expected2);
        }

        #[test]
        fn test_enc_cmd_req_crc() {
            let data = [57, 3, 239, 186, 146];

            let test_tag = [
                90, 215, 123, 185, 236, 247, 28, 119, 1, 225, 58, 212, 192, 22, 80, 185,
            ];

            let plaintext_cmd = l3::Request {
                size: 5,
                data,
                tag: test_tag,
            };

            let expected_chunk0 = expected_chunk(
                &[4, 23, 5, 0],
                &data,
                &[
                    90, 215, 123, 185, 236, 247, 28, 119, 1, 225, 58, 212, 192, 22, 80, 185, 23, 91,
                ],
            );

            let enc_cmd_chunks = EncryptedCmdReq::create(&plaintext_cmd)
                .expect("unable to create encrypted command request");
            assert_eq!(enc_cmd_chunks.count, 1);
            assert_eq!(enc_cmd_chunks.last_len, calc_last_chunk_len(5));
            assert_eq!(enc_cmd_chunks.chunks[0], expected_chunk0);

            let mut crc_data = [
                4, 23, 5, 0, 57, 3, 239, 186, 146, 90, 215, 123, 185, 236, 247, 28, 119, 1, 225,
                58, 212, 192, 22, 80, 185, 0, 0,
            ];

            add_crc(&mut crc_data).expect("unable to create crc");
            assert_eq!(crc_data[25], 23);
            assert_eq!(crc_data[26], 91);
        }
    }
}

pub mod resend {
    use super::*;

    // request id
    const RESEND_REQ_ID: u8 = 0x10;
    // request length
    const RESEND_REQ_LEN: u8 = 0;

    // response length
    #[allow(unused)]
    pub(crate) const RESEND_RSP_LEN: usize = 0;

    const RESEND_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN + RESEND_REQ_LEN as usize + CMD_CRC_LEN;

    pub struct ResendReq;

    impl ResendReq {
        pub fn create() -> Result<[u8; RESEND_CMD_LEN], Error> {
            let mut data = [RESEND_REQ_ID, RESEND_REQ_LEN, 0, 0];
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    pub type ResendResp = StatusResp;
}

pub mod mutable_firmware {
    use super::*;

    // request id
    const ERASE_REQ_ID: u8 = 0xb2;
    // request length
    const ERASE_REQ_LEN: usize = 1;

    const ERASE_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN + ERASE_REQ_LEN + CMD_CRC_LEN;

    // Response length
    #[allow(unused)]
    const ERASE_RSP_LEN: usize = 0;

    pub struct EraseReq {}

    impl EraseReq {
        pub fn create(bank_id: info::BankId) -> Result<[u8; ERASE_CMD_LEN], Error> {
            let mut data = [ERASE_REQ_ID, ERASE_CMD_LEN as u8, bank_id as u8, 0, 0];
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    pub type EraseResp = StatusResp;

    #[cfg(feature = "abab")]
    pub mod abab {
        //! Firmware update API structs for ABAB silicon revision

        use super::super::*;

        // request id
        const UPDATE_REQ_ID: u8 = 0xb1;
        // request min length
        const UPDATE_REQ_LEN_MIN: usize = 3;
        // minimal length of field data
        const UPDATE_REQ_DATA_LEN_MIN: usize = 4;
        // maximal length of field data
        const UPDATE_REQ_DATA_LEN_MAX: usize = 248;

        const UPDATE_CMD_LEN: usize =
            CMD_ID_LEN + CMD_SIZE_LEN + UPDATE_REQ_LEN_MIN + UPDATE_REQ_DATA_LEN_MAX + CMD_CRC_LEN;

        pub struct FwUpdateReq {}

        impl FwUpdateReq {
            pub fn create(
                bank_id: info::BankId,
                offset: u16,
                update_data: &[u8],
            ) -> Result<[u8; UPDATE_CMD_LEN], Error> {
                let data_len = update_data.len();

                if data_len < UPDATE_REQ_DATA_LEN_MIN {
                    return Err(Error::FwUpdateDataMin);
                }
                if data_len > UPDATE_REQ_DATA_LEN_MAX {
                    return Err(Error::FwUpdateDataMax);
                }

                let mut data = [0_u8; UPDATE_CMD_LEN];
                data[0] = UPDATE_REQ_ID;
                data[1] = (UPDATE_REQ_LEN_MIN + data_len) as u8;
                data[2] = bank_id as u8;
                data[3..5].copy_from_slice(&offset.to_le_bytes());
                data[5..data_len + 5].copy_from_slice(update_data);
                data[data_len + 5] = 0;
                data[data_len + 6] = 0;
                add_crc(&mut data)?;
                Ok(data)
            }
        }

        pub type UpdateResp = StatusResp;

        #[cfg(test)]
        mod tests {
            extern crate alloc;

            use alloc::vec;
            use rand::RngCore;

            use crate::l2::info::BankId;

            use super::*;

            #[test]
            fn test_create_update_req() {
                let offset = 0;
                let len = rand::random_range(0..UPDATE_REQ_DATA_LEN_MAX);
                let mut data = vec![0_u8; len];
                rand::rng().fill_bytes(&mut data);

                let fw_update_req = FwUpdateReq::create(BankId::FwBankFw1, offset, &data)
                    .expect("failed to create update request");

                assert_eq!(fw_update_req[0], UPDATE_REQ_ID);
                assert_eq!(fw_update_req[1], (UPDATE_REQ_LEN_MIN + data.len()) as u8);
                assert_eq!(fw_update_req[2], BankId::FwBankFw1 as u8);
                assert_eq!(fw_update_req[3..5], offset.to_le_bytes());
                assert_eq!(fw_update_req[5..data.len() + 5], data);

                let offset = 22;
                let len = rand::random_range(0..UPDATE_REQ_DATA_LEN_MAX);
                let mut data = vec![0_u8; len];
                rand::rng().fill_bytes(&mut data);

                let fw_update_req = FwUpdateReq::create(BankId::FwBankSpect1, offset, &data)
                    .expect("failed to create update request");

                assert_eq!(fw_update_req[0], UPDATE_REQ_ID);
                assert_eq!(fw_update_req[1], (UPDATE_REQ_LEN_MIN + data.len()) as u8);
                assert_eq!(fw_update_req[2], BankId::FwBankSpect1 as u8);
                assert_eq!(fw_update_req[3..5], offset.to_le_bytes());
                assert_eq!(fw_update_req[5..data.len() + 5], data);
            }

            #[test]
            fn test_fail() {
                let offset = 0;
                let data = [0_u8; UPDATE_REQ_DATA_LEN_MIN - 1];

                let result = FwUpdateReq::create(BankId::FwBankFw1, offset, &data);
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), Error::FwUpdateDataMin);

                let data = [0_u8; UPDATE_REQ_DATA_LEN_MAX + 1];

                let result = FwUpdateReq::create(BankId::FwBankFw1, offset, &data);
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), Error::FwUpdateDataMax);
            }
        }
    }

    #[cfg(feature = "acab")]
    pub mod acab {

        use super::super::*;

        // request id
        const UPDATE_REQ_ID: u8 = 0xb0;
        // request min length
        const UPDATE_REQ_LEN: usize = 104;
        // response length
        #[allow(unused)]
        const UPDATE_RSP_LEN: usize = 0;

        const UPDATE_REQ_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN + UPDATE_REQ_LEN + CMD_CRC_LEN;

        /// Firmware header
        #[derive(Debug)]
        pub struct UpdateReqHeader {
            /// Length byte
            _len: u8,
            ///  Signature of SHA256 hash of all following data in this packet
            signature: [u8; 64],
            /// SHA256 HASH of first FW chunk of data sent using Mutable_FW_Update_Data
            hash: [u8; 32],
            /// FW type which is going to be updated
            fw_type: info::FirmwareType,
            /// Padding, zero value
            padding: u8,
            /// Version of used header
            header_version: u8,
            /// Version of FW
            version: [u8; 4],
        }

        impl TryFrom<&[u8]> for UpdateReqHeader {
            type Error = Error;

            fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
                if data.len() < UPDATE_REQ_LEN + 1 {
                    return Err(Error::FwUpdateDataMin);
                }
                if data.len() > UPDATE_DATA_MAX_LEN {
                    return Err(Error::FwUpdateDataMax);
                }
                if data[98] != 0 {
                    // since there are only 2 firware types this bit should alwasy be 0
                    return Err(Error::UnknownFirmwareType(u16::from_le_bytes(
                        data[97..99].try_into().unwrap(),
                    )));
                }
                Ok(Self {
                    _len: data[0],
                    signature: data[1..65].try_into().unwrap(),
                    hash: data[65..97].try_into().unwrap(),
                    // we only read firmwarre type from byte
                    // there are only 2 possible values
                    fw_type: data[97].try_into()?,
                    padding: data[99],
                    header_version: data[100],
                    version: data[101..105].try_into().unwrap(),
                })
            }
        }

        impl UpdateReqHeader {
            fn to_req(&self) -> [u8; UPDATE_REQ_LEN] {
                let mut data = [0_u8; UPDATE_REQ_LEN];
                data[0..64].copy_from_slice(&self.signature);
                data[64..96].copy_from_slice(&self.hash);
                data[96] = self.fw_type.clone() as u8;
                data[97] = 0;
                data[98] = self.padding;
                data[99] = self.header_version;
                data[100..104].copy_from_slice(&self.version);
                data
            }
        }

        pub struct UpdateReq {}

        impl UpdateReq {
            pub fn create(update_req: &[u8]) -> Result<[u8; UPDATE_REQ_CMD_LEN], Error> {
                let update_req_header: UpdateReqHeader = update_req.try_into()?;

                let mut data = [0_u8; UPDATE_REQ_CMD_LEN];
                data[0] = UPDATE_REQ_ID;
                data[1] = UPDATE_REQ_LEN as u8;
                data[2..UPDATE_REQ_LEN + 2].copy_from_slice(&update_req_header.to_req());
                data[UPDATE_REQ_LEN + 2] = 0;
                data[UPDATE_REQ_LEN + 3] = 0;
                add_crc(&mut data)?;
                Ok(data)
            }
        }

        pub type UpdateResp = StatusResp;

        // request id
        const UPDATE_DATA_REQ_ID: u8 = 0xb1;

        // maximum size of update data
        const UPDATE_DATA_MAX_LEN: usize = 30720;

        // maximum firmware update chunk size HASH[32] + OFFSET[2] + DATA[220]
        const UPDATE_DATA_MAX_CHUNK_LEN: usize = 32 + 2 + 220;

        // maximum amount of chunks
        const UPDATE_DATA_MAX_CHUNKS: usize =
            UPDATE_DATA_MAX_LEN.div_ceil(UPDATE_DATA_MAX_CHUNK_LEN);

        const UPDATE_DATA_CMD_MAX_LEN: usize =
            CMD_ID_LEN + CMD_SIZE_LEN + UPDATE_DATA_MAX_CHUNK_LEN + CMD_CRC_LEN;

        #[derive(Debug, Clone, Copy)]
        pub struct UpdateDataChunk {
            len: usize,
            hash: [u8; 32],
            offset: u16,
            data: [u8; 220],
        }

        impl UpdateDataChunk {
            pub(crate) fn command(&self) -> Result<[u8; UPDATE_DATA_CMD_MAX_LEN], Error> {
                let mut data = [0_u8; UPDATE_DATA_CMD_MAX_LEN];
                data[0] = UPDATE_DATA_REQ_ID;
                data[1] = self.len as u8;
                data[2..34].copy_from_slice(&self.hash);
                data[34..36].copy_from_slice(&self.offset.to_le_bytes());
                data[36..self.len + 2].copy_from_slice(&self.data[0..self.len - 34]);
                add_crc(&mut data)?;
                Ok(data)
            }
        }

        impl Default for UpdateDataChunk {
            fn default() -> Self {
                Self {
                    len: 0,
                    hash: [0_u8; 32],
                    offset: 0,
                    data: [0_u8; 220],
                }
            }
        }

        pub struct UpdateDataReq {
            pub count: usize,
            pub chunks: [UpdateDataChunk; UPDATE_DATA_MAX_CHUNKS],
        }

        impl UpdateDataReq {
            pub fn create(update_req: &[u8]) -> Result<Self, Error> {
                let update_req_len = update_req.len();
                if update_req_len > UPDATE_DATA_MAX_LEN {
                    return Err(Error::FwUpdateDataMax);
                }
                let mut chunk_idx = UPDATE_REQ_LEN + 1;
                let mut count = 0;
                let mut chunks = [UpdateDataChunk::default(); UPDATE_DATA_MAX_CHUNKS];

                while chunk_idx < update_req_len {
                    let chunk_len = update_req[chunk_idx] as usize;
                    if chunk_len > 32 + 16 + UPDATE_DATA_MAX_CHUNK_LEN {
                        return Err(Error::FwUpdateChunkLen);
                    }
                    let offset = chunk_idx + 1;
                    // let seek = chunk_idx + 1 + chunk_len;
                    chunks[count].len = chunk_len;
                    chunks[count]
                        .hash
                        .copy_from_slice(&update_req[offset..offset + 32]);
                    chunks[count].offset = u16::from_le_bytes(
                        update_req[offset + 32..offset + 34].try_into().unwrap(),
                    );
                    chunks[count].data[..chunk_len - 34]
                        .copy_from_slice(&update_req[offset + 34..offset + chunk_len]);

                    chunk_idx += chunk_len + 1;
                    count += 1;
                }

                Ok(Self { count, chunks })
            }
        }

        #[cfg(test)]
        mod tests {
            use rand::RngCore;

            use super::*;

            include!("../../tests/firmware_update_files/boot_v2_0_0/fw_v1.0.0/fw_cpu.rs");
            include!("../../tests/firmware_update_files/boot_v2_0_0/fw_v1.0.0/fw_spect.rs");

            #[test]
            fn test_create_update_req() {
                let mut data = [0_u8; UPDATE_REQ_LEN + 1];
                rand::rng().fill_bytes(&mut data);

                // set coorect firmware version
                data[97] = info::FirmwareType::Spect as u8;
                data[98] = 0;

                let update_req = UpdateReq::create(&data).expect("failed to create update request");

                assert_eq!(update_req[0], UPDATE_REQ_ID);
                assert_eq!(update_req[1], UPDATE_REQ_LEN as u8);
                assert_eq!(update_req[2..UPDATE_REQ_LEN + 2], data[1..]);

                let mut data = [0_u8; UPDATE_REQ_LEN + 1];
                rand::rng().fill_bytes(&mut data);

                // set coorect firmware version
                data[97] = info::FirmwareType::Riscv as u8;
                data[98] = 0;

                let update_req = UpdateReq::create(&data).expect("failed to create update request");

                assert_eq!(update_req[0], UPDATE_REQ_ID);
                assert_eq!(update_req[1], UPDATE_REQ_LEN as u8);
                assert_eq!(update_req[2..UPDATE_REQ_LEN + 2], data[1..]);
            }

            #[test]
            fn test_create_update_data_req() {
                // HEADER[LEN[1] + UPDATE_REQ_LEN[140]] + LEN[1] + 4 * [MAX_CHUNK[220] + LEN[1]] + LAST_CHUNK[220]
                let mut data = [0_u8;
                    (1 + UPDATE_REQ_LEN) + 1 + (4 * (UPDATE_DATA_MAX_CHUNK_LEN + 1)) + (120)];
                rand::rng().fill_bytes(&mut data);

                data[UPDATE_REQ_LEN + 1] = UPDATE_DATA_MAX_CHUNK_LEN as u8;
                data[UPDATE_REQ_LEN + (UPDATE_DATA_MAX_CHUNK_LEN + 1) + 1] =
                    UPDATE_DATA_MAX_CHUNK_LEN as u8;
                data[UPDATE_REQ_LEN + (2 * (UPDATE_DATA_MAX_CHUNK_LEN + 1)) + 1] =
                    UPDATE_DATA_MAX_CHUNK_LEN as u8;
                data[UPDATE_REQ_LEN + (3 * (UPDATE_DATA_MAX_CHUNK_LEN + 1)) + 1] =
                    UPDATE_DATA_MAX_CHUNK_LEN as u8;
                data[UPDATE_REQ_LEN + (4 * (UPDATE_DATA_MAX_CHUNK_LEN + 1)) + 1] = 120 as u8;

                let update_data_req =
                    UpdateDataReq::create(&data).expect("failed to create update data request");

                assert_eq!(update_data_req.count, 5);
            }

            #[test]
            fn test_read_fw_spect_file() {
                const EXP_FW_REQ: [u8; 108] = [
                    176, 104, 171, 240, 167, 122, 80, 206, 221, 85, 61, 176, 241, 118, 159, 203,
                    106, 103, 245, 203, 252, 36, 118, 178, 82, 160, 74, 141, 229, 45, 212, 46, 137,
                    77, 246, 189, 192, 224, 199, 149, 19, 114, 173, 204, 72, 134, 58, 125, 218,
                    107, 139, 63, 26, 134, 132, 97, 201, 19, 121, 81, 43, 63, 117, 169, 228, 12,
                    72, 93, 240, 107, 18, 20, 82, 119, 150, 51, 186, 52, 40, 235, 128, 87, 61, 148,
                    230, 52, 124, 112, 86, 168, 1, 47, 229, 15, 127, 78, 47, 28, 2, 0, 0, 1, 0, 0,
                    0, 1, 114, 168,
                ];

                let update_req =
                    UpdateReq::create(&FW_SPECT).expect("failed to create update request");

                assert_eq!(EXP_FW_REQ, update_req);

                let update_req_header: UpdateReqHeader = FW_SPECT
                    .as_slice()
                    .try_into()
                    .expect("failed to create fw update header");

                assert_eq!(update_req_header.fw_type, info::FirmwareType::Spect);

                let update_data_req =
                    UpdateDataReq::create(&FW_SPECT).expect("failed to create update data request");

                assert_eq!(update_data_req.count, 49);

                for i in 0..update_data_req.count - 1 {
                    assert_eq!(update_data_req.chunks[i].len, 250);
                    assert_eq!(update_data_req.chunks[i].offset, (i * 216) as u16);
                }

                assert_eq!(update_data_req.chunks[update_data_req.count - 1].len, 74);
                assert_eq!(
                    update_data_req.chunks[update_data_req.count - 1].offset,
                    (update_data_req.count - 1) as u16 * 216
                );
            }

            #[test]
            fn test_read_fw_spect_file_commands() {
                let update_data_req =
                    UpdateDataReq::create(&FW_SPECT).expect("failed to create update data request");

                for i in 0..update_data_req.count - 1 {
                    let cmd = update_data_req.chunks[i]
                        .command()
                        .expect("failed to create command from chunk");

                    assert_eq!(cmd[0], UPDATE_DATA_REQ_ID);
                    assert_eq!(cmd[1], 250);
                    assert_eq!(
                        u16::from_le_bytes(cmd[34..36].try_into().unwrap()),
                        (i * 216) as u16
                    );
                }

                let cmd = update_data_req.chunks[update_data_req.count - 1]
                    .command()
                    .expect("failed to create command from chunk");

                assert_eq!(cmd[0], UPDATE_DATA_REQ_ID);
                assert_eq!(cmd[1], 74);
                assert_eq!(
                    u16::from_le_bytes(cmd[34..36].try_into().unwrap()),
                    (update_data_req.count - 1) as u16 * 216
                );
            }

            #[test]
            fn test_read_fw_cpu_file() {
                const EXP_FW_REQ: [u8; 108] = [
                    176, 104, 123, 31, 95, 138, 250, 255, 177, 161, 221, 203, 119, 203, 4, 1, 168,
                    37, 157, 188, 81, 195, 38, 69, 162, 222, 85, 44, 213, 189, 156, 166, 119, 39,
                    252, 41, 173, 217, 92, 178, 35, 218, 5, 143, 75, 170, 113, 141, 99, 155, 36,
                    40, 0, 63, 244, 99, 41, 14, 66, 208, 9, 2, 116, 237, 100, 15, 15, 208, 117,
                    182, 204, 177, 148, 62, 253, 7, 70, 195, 218, 190, 95, 201, 255, 57, 132, 19,
                    90, 157, 182, 44, 101, 136, 46, 24, 3, 212, 194, 114, 1, 0, 0, 1, 0, 0, 0, 1,
                    10, 227,
                ];

                let update_req =
                    UpdateReq::create(&FW_CPU).expect("failed to create update request");

                assert_eq!(EXP_FW_REQ, update_req);

                let update_req_header: UpdateReqHeader = FW_CPU
                    .as_slice()
                    .try_into()
                    .expect("failed to create fw update header");

                assert_eq!(update_req_header.fw_type, info::FirmwareType::Riscv);

                let update_data_req =
                    UpdateDataReq::create(&FW_CPU).expect("failed to create update data request");

                assert_eq!(update_data_req.count, 109);

                for i in 0..update_data_req.count - 1 {
                    assert_eq!(update_data_req.chunks[i].len, 250);
                    assert_eq!(update_data_req.chunks[i].offset, (i * 216) as u16);
                }

                assert_eq!(update_data_req.chunks[update_data_req.count - 1].len, 46);
                assert_eq!(
                    update_data_req.chunks[update_data_req.count - 1].offset,
                    (update_data_req.count - 1) as u16 * 216
                );
            }

            #[test]
            fn test_read_fw_cpu_file_commands() {
                let update_data_req =
                    UpdateDataReq::create(&FW_CPU).expect("failed to create update data request");

                for i in 0..update_data_req.count - 1 {
                    let cmd = update_data_req.chunks[i]
                        .command()
                        .expect("failed to create command from chunk");

                    assert_eq!(cmd[0], UPDATE_DATA_REQ_ID);
                    assert_eq!(cmd[1], 250);
                    assert_eq!(
                        u16::from_le_bytes(cmd[34..36].try_into().unwrap()),
                        (i * 216) as u16
                    );
                }

                let cmd = update_data_req.chunks[update_data_req.count - 1]
                    .command()
                    .expect("failed to create command from chunk");

                assert_eq!(cmd[0], UPDATE_DATA_REQ_ID);
                assert_eq!(cmd[1], 46);
                assert_eq!(
                    u16::from_le_bytes(cmd[34..36].try_into().unwrap()),
                    (update_data_req.count - 1) as u16 * 216
                );
            }
        }
    }
}

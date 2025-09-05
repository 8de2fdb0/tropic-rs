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

#[derive(Debug)]
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
    UnknwonFirmwareHeaderSize,
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
            Self::UnknwonFirmwareHeaderSize => {
                f.write_fmt(format_args!("unknown firmware header size"))
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
    /// Request was sucessfull
    RequestOk = 0x01,
    /// Result was successfull
    ResultOk = 0x02,
    /// There is more than one chunk to be expected for a current request
    RequestCont = 0x03,
    /// There is more than one chunk to be received for a current response
    ResultCont = 0x04,
    /// There were an error during handshake establishing
    HskErr = 0x79,
    /// There is no secure session
    NoSession = 0x7A,
    /// There were error during checking message authenticity
    TagErr = 0x7B,
    /// Request contained crc error
    CrcErr = 0x7C,
    /// ID of last request is not known to TROPIC01
    UnknownErr = 0x7E,
    /// There were some other error
    GenErr = 0x7F,
    /// No response on the SPI bus will read as a array full of 0xff
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
            0x7E => Ok(Self::UnknownErr),
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

pub(crate) struct Response<const N: usize> {
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
            | Status::UnknownErr
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
}

pub mod sleep {
    use super::*;

    const SLEEP_REQ_ID: u8 = 0x20;
    const SLEEP_REQ_LEN: u8 = 0x01;

    const SLEEP_RSP_LEN: usize = 0x00;

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

    pub struct SleepResp {
        /// CHIP_STATUS byte
        pub chip_status: l1::ChipStatus,
        /// L2 status byte
        pub status: Status,
        /// Length of incoming data
        pub len: u8,
        /// Checksum
        pub crc: [u8; 2],
    }

    impl From<Response<{ SLEEP_RSP_LEN }>> for SleepResp {
        fn from(resp: Response<{ SLEEP_RSP_LEN }>) -> Self {
            Self {
                chip_status: resp.chip_status,
                status: resp.status,
                len: resp.len,
                crc: resp.crc,
            }
        }
    }
}

// todo: think about renaming to reboot
pub mod restart {
    use super::*;

    const STARTUP_REQ_ID: u8 = 0xb3;
    const STARTUP_REQ_LEN: u8 = 0x1;

    pub(crate) const STARTUP_RSP_LEN: usize = 0x0;

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
    pub struct StartupResp {
        /// CHIP_STATUS byte
        pub chip_status: l1::ChipStatus,
        /// L2 status byte
        pub status: Status,
        /// Length of incoming data
        pub len: u8,
        /// Checksum
        pub crc: [u8; 2],
    }

    impl From<Response<{ STARTUP_RSP_LEN }>> for StartupResp {
        fn from(resp: Response<{ STARTUP_RSP_LEN }>) -> Self {
            Self {
                chip_status: resp.chip_status,
                status: resp.status,
                len: resp.len,
                crc: resp.crc,
            }
        }
    }
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

    const ENCRYPTED_SESSION_ABT_ID: u8 = 0x08;
    /** @brief Request length */
    const ENCRYPTED_SESSION_ABT_LEN: u8 = 0;

    /** @brief Response length */
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

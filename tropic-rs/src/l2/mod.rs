// mod x509_parser;

pub(crate) mod cert;
pub(crate) mod cert_store;

pub use cert_store::CERT_BUFFER_LEN;

use core::fmt::Debug;

use crate::{
    common,
    crc16::{add_crc, crc16, u8_slice_to_crc},
    l1,
};

#[derive(Debug)]
pub enum Error {
    Spi(embedded_hal::spi::ErrorKind),
    Crc(crate::crc16::Error),
    L1(crate::l1::Error),
    InvalidCRC,
    InvalidStatus(u8),
    InvalidRespLen(usize, usize),
    CertStore(cert_store::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spi(err) => f.write_fmt(format_args!("spi error: {}", err)),
            Self::Crc(err) => f.write_fmt(format_args!("crc error: {}", err)),
            Self::L1(err) => f.write_fmt(format_args!("l1 error: {}", err)),
            Self::InvalidCRC => f.write_fmt(format_args!("l2: invalid crc")),
            Self::InvalidStatus(status) => {
                f.write_fmt(format_args!("l2: invalid status: {}", status))
            }
            Self::InvalidRespLen(exp, act) => f.write_fmt(format_args!(
                "l2: invalid response length: expected {} bytes, got {}",
                exp, act
            )),
            Self::CertStore(err) => f.write_fmt(format_args!("cert store error: {}", err)),
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

// pub fn receive<SPI: embedded_hal::spi::SpiDevice, const N: usize>(
//     spi_device: &mut SPI,
// ) -> Result<[u8; N], Error> {
//     let mut retry = l1::READ_MAX_TRIES;

//     let req = [l1::GET_RESPONSE_REQ_ID];
//     let mut chip_status = [0_u8; 1];
//     let mut status_and_len = [0_u8; 2];

//     let mut data = [0_u8; N];
//     let mut crc = [0_u8; 2];

//     loop {
//         let mut operations = [
//             Operation::Transfer(&mut chip_status, &req),
//             Operation::TransferInPlace(&mut status_and_len),
//             Operation::TransferInPlace(&mut data),
//             Operation::TransferInPlace(&mut crc),
//         ];

//         spi_device.transaction(&mut operations)?;

//         let len = status_and_len[1] as usize;
//         if len != data.len() {
//             retry -= 1;
//             if retry > 0 {
//                 continue;
//             }
//             return Err(Error::InvalidRespLen(N, data.len()));
//         }

//         if u8_slice_to_crc(&crc) != crc16(&data, Some(&status_and_len)) {
//             return Err(Error::InvalidCRC);
//         }

//         return Ok(data);
//     }
// }

#[repr(u8)]
#[derive(Debug, Clone)]
pub enum Status {
    /// @brief STATUS ﬁeld value
    RequestOk = 0x01,
    /// @brief STATUS ﬁeld value
    ResultOk = 0x02,
    /// @brief STATUS ﬁeld value
    RequestCont = 0x03,
    /// @brief STATUS ﬁeld value
    ResultCont = 0x04,
    /// @brief STATUS ﬁeld value
    HskErr = 0x79,
    /// @brief STATUS ﬁeld value
    NoSession = 0x7A,
    /// @brief STATUS ﬁeld value
    TagErr = 0x7B,
    /// @brief STATUS ﬁeld value
    CrcErr = 0x7C,
    /// @brief STATUS ﬁeld value
    UnknownErr = 0x7E,
    /// @brief STATUS ﬁeld value
    GenErr = 0x7F,
    /// @brief STATUS ﬁeld value
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
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let status_and_len = [self.status.clone() as u8, self.len];
        if crc16(&self.data[0..self.len as usize], Some(&status_and_len))
            != u8_slice_to_crc(&self.crc)
        {
            return Err(Error::InvalidCRC);
        }
        Ok(())
    }
}

impl<const N: usize> TryFrom<l1::Response<N>> for Response<N> {
    type Error = Error;

    fn try_from(resp: l1::Response<N>) -> Result<Self, Self::Error> {
        let l2_resp = Self {
            chip_status: resp.chip_status,
            status: Status::try_from(resp.status)?,
            len: resp.len,
            data: resp.data,
            crc: resp.crc,
        };
        l2_resp.validate()?;
        Ok(l2_resp)
    }
}

pub(crate) mod info {
    use super::*;

    const GET_INFO_REQ_ID: u8 = 0x01;
    const GET_INFO_REQ_LEN: u8 = 0x02;

    pub(crate) const GET_INFO_BLOCK_LEN: usize = 128;

    #[repr(u8)]
    pub enum GetInfoObjectId {
        /// The X.509 chip certificate read from I-Memory and signed by Tropic Square (max length of 512B).
        X509Certificate = 0x00,
        /// The chip ID - the chip silicon revision and unique device ID (max length of 128B).
        ChipId = 0x01,
        /// The RISCV current running FW version (4 Bytes)
        RiscvFwVersion = 0x02,
        /// The SPECT FW version (4 Bytes)
        SpectFwVersion = 0x04,
        ///  The FW header read from the selected bank id (shown as an index). Supported only in Start-up mode.
        FwBank = 0xbe,
    }

    #[repr(u8)]
    pub enum DataChunk {
        /// Request for data bytes 0-127 of the object.
        Bytes0_127 = 0x00,
        /// Request for data bytes 128-255 of the object (only needed for the X.509 certificate).
        Bytes128_255 = 0x01,
        /// Request for data bytes 128-383 of object (only needed for the X.509 certificate).
        Bytes256_383 = 0x02,
        /// Request for data bytes 384-511 of object (only needed for the X.509 certificate).
        Bytes384_511 = 0x03,
    }

    impl DataChunk {
        pub fn next(self) -> Option<Self> {
            match self {
                Self::Bytes0_127 => Some(Self::Bytes128_255),
                Self::Bytes128_255 => Some(Self::Bytes256_383),
                Self::Bytes256_383 => Some(Self::Bytes384_511),
                Self::Bytes384_511 => None,
            }
        }
    }

    #[repr(u8)]
    pub enum BankId {
        /// Firmware bank 1.
        FwBankFw1 = 1,
        /// Firmware bank 2.
        FwBankFw2 = 2,
        /// SPECT bank 1.
        FwBankSpect1 = 17,
        /// SPECT bank 2.
        FwBankSpect2 = 18,
    }

    pub enum BlocIndex {
        DataChunk(DataChunk),
        CeryStore(u8),
        BankId(BankId),
    }

    impl From<BlocIndex> for u8 {
        fn from(value: BlocIndex) -> Self {
            match value {
                BlocIndex::DataChunk(data_chunk) => data_chunk as u8,
                BlocIndex::CeryStore(idx) => idx,
                BlocIndex::BankId(bank_id) => bank_id as u8,
            }
        }
    }

    pub struct GetInfoReq {}

    impl GetInfoReq {
        pub fn create(
            object_id: GetInfoObjectId,
            block_index: BlocIndex,
        ) -> Result<[u8; 6], Error> {
            let mut data = [
                GET_INFO_REQ_ID,
                GET_INFO_REQ_LEN,
                object_id as u8,
                block_index.into(),
                0,
                0,
            ];
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    pub struct GetInfoResp<const N: usize> {
        /// CHIP_STATUS byte
        pub chip_status: l1::ChipStatus,
        ///  L2 status byte
        pub status: Status,
        /// Length of incoming data
        pub len: u8,
        /// The data content of the requested object block.
        pub object: [u8; N],
        /// Checksum
        pub crc: [u8; 2],
    }

    impl<const N: usize> From<Response<N>> for GetInfoResp<N> {
        fn from(resp: Response<N>) -> Self {
            let mut pubkey_bytes = [0_u8; 32];
            pubkey_bytes.copy_from_slice(&resp.data[0..32]);
            let mut auth_tag = [0_u8; 16];
            auth_tag.copy_from_slice(&resp.data[32..48]);

            Self {
                chip_status: resp.chip_status,
                status: resp.status,
                len: resp.len,
                object: resp.data,
                crc: resp.crc,
            }
        }
    }
}

pub mod handshake {
    use super::*;

    const HANDSHAKE_REQ_ID: u8 = 0x02;
    pub const HANDSHAKE_REQ_LEN: u8 = 33;
    pub const HANDSHAKE_RSP_LEN: usize = 48;
    const HANDSHAKE_L2_REQ_LEN: usize = (1 + 1 + HANDSHAKE_REQ_LEN + 2) as usize;

    pub struct HandshakeReq;

    impl HandshakeReq {
        pub fn create(
            host_pubkey: x25519_dalek::PublicKey,
            pkey_index: common::PairingKeyIndex,
        ) -> Result<[u8; HANDSHAKE_L2_REQ_LEN], Error> {
            let mut data = [0_u8; HANDSHAKE_L2_REQ_LEN];
            data[0] = HANDSHAKE_REQ_ID;
            data[1] = HANDSHAKE_REQ_LEN;
            data[2..34].copy_from_slice(host_pubkey.as_bytes());
            data[34] = pkey_index as u8;
            data[35] = 0;
            data[36] = 0;
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
        pub tropic_pubkey: x25519_dalek::PublicKey,
        /// The Secure Channel Handshake Authentication Tag
        pub auth_tag: [u8; 16],
        /// Checksum
        pub crc: [u8; 2],
    }

    impl From<Response<{ HANDSHAKE_RSP_LEN }>> for HandshakeResp {
        fn from(resp: Response<{ HANDSHAKE_RSP_LEN }>) -> Self {
            let mut pubkey_bytes = [0_u8; 32];
            pubkey_bytes.copy_from_slice(&resp.data[0..32]);
            let mut auth_tag = [0_u8; 16];
            auth_tag.copy_from_slice(&resp.data[32..48]);

            Self {
                chip_status: resp.chip_status,
                status: resp.status,
                len: resp.len,
                tropic_pubkey: pubkey_bytes.into(),
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

    const SLEEP_RSP_LEN: u8 = 0x00;

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
        pub chip_status: u8,
        /// L2 status byte
        pub status: u8,
        /// Length of incoming data
        pub len: u8,
        /// Checksum
        pub crc: [u8; 2],
    }

    impl SleepResp {
        pub fn new(chip_status: u8, status: u8, len: u8, crc: [u8; 2]) -> Result<Self, Error> {
            Ok(Self {
                chip_status,
                status,
                len,
                crc,
            })
        }

        pub fn validate(&self) -> Result<(), Error> {
            let status_and_len = [self.status, self.len];
            if crc16(&[], Some(&status_and_len)) != u8_slice_to_crc(&self.crc) {
                return Err(Error::InvalidCRC);
            }
            Ok(())
        }
    }
}

// todo: think about renaming to reboot
pub mod startup {
    use super::*;

    const STARTUP_REQ_ID: u8 = 0xb3;
    const STARTUP_REQ_LEN: u8 = 0x1;

    const _STARTUP_RSP_LEN: u8 = 0x0;

    #[repr(u8)]
    pub enum StartupId {
        Reboot = 0x01,
        Maintanance = 0x03,
    }

    /// Request for TROPIC01 to reset.
    pub struct StartupReq;

    impl StartupReq {
        pub fn create(startup_id: StartupId) -> Result<[u8; 5], Error> {
            let mut data = [STARTUP_REQ_ID, STARTUP_REQ_LEN, startup_id as u8, 0, 0];
            add_crc(&mut data)?;
            Ok(data)
        }
    }

    /// Response from TROPIC01 afyer requesting a reset.
    pub struct StartupResp {
        /// CHIP_STATUS byte
        pub chip_status: u8,
        /// L2 status byte
        pub status: u8,
        /// Length of incoming data
        pub len: u8,
        /// Checksum
        pub crc: [u8; 2],
    }
    impl StartupResp {
        pub fn new(chip_status: u8, status: u8, len: u8, crc: [u8; 2]) -> Result<Self, Error> {
            Ok(Self {
                chip_status,
                status,
                len,
                crc,
            })
        }
        pub fn validate(&self) -> Result<(), Error> {
            let status_and_len = [self.status, self.len];
            if crc16(&[], Some(&status_and_len)) != u8_slice_to_crc(&self.crc) {
                return Err(Error::InvalidCRC);
            }
            Ok(())
        }
    }
}

pub mod log {
    use super::*;

    const GET_LOG_REQ_ID: u8 = 0xa2;
    const GET_LOG_REQ_LEN: u8 = 0x00;

    pub(crate) const GET_LOG_RSP_MIN_LEN: usize = 0x00;
    pub(crate) const GET_LOG_RSP_MAX_LEN: usize = 0xff;

    pub struct GetLogReq;

    impl GetLogReq {
        pub fn create() -> Result<[u8; 4], Error> {
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

pub(crate) mod resp {
    use core::fmt;

    use crate::{
        crc16::{crc16, u8_slice_to_crc},
        l1::ChipStatus,
    };

    use super::*;

    pub const GET_INFO_CHIP_INFO_ID_SIZE: usize = 128;
    pub const GET_INFO_RISCV_FW_SIZE: usize = 4;
    pub const GET_INFO_SPECT_FW_SIZE: usize = 4;
    pub const GET_INFO_FW_HEADER_SIZE: usize = 20;

    pub struct InfoResp<const N: usize> {
        /// CHIP_STATUS byte
        pub chip_status: ChipStatus,
        ///  L2 status byte
        pub status: Status,
        /// Length of incoming data
        pub len: u8,
        /// The data content of the requested object block.
        pub object: [u8; N],
        /// Checksum
        pub crc: [u8; 2],
    }

    impl<const N: usize> InfoResp<N> {
        pub fn new(
            chip_status: u8,
            status: u8,
            len: u8,
            data: [u8; N],
            crc: [u8; 2],
        ) -> Result<Self, Error> {
            Ok(Self {
                chip_status: chip_status.into(),
                status: status.try_into()?,
                len,
                object: data,
                crc,
            })
        }

        pub fn validate(&self) -> Result<(), Error> {
            if crc16(&self.object[0..self.len as usize], None) != u8_slice_to_crc(&self.crc) {
                return Err(Error::InvalidCRC);
            }
            Ok(())
        }
    }

    pub struct SerialNumber {
        /// 8 bits for serial number
        pub sn: u8,
        /// 12 bits fab ID, 12 bits part number ID
        pub fab_data: [u8; 3],
        /// 16 bits for fabrication date
        pub fab_date: u16,
        /// 40 bits for lot ID
        pub lot_id: [u8; 5],
        /// 8 bits for wafer ID
        pub wafer_id: u8,
        /// 16 bits for x-coordinate
        pub x_coord: u16,
        /// 16 bits for y-coordinate
        pub y_coord: u16,
    }

    impl core::fmt::Display for SerialNumber {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_fmt(format_args!(
                "sn: {}, fab_date: {}, lot_id: {:?}, wafer_id: {}, x_coord: {}, y_coord: {}",
                self.sn, self.fab_date, self.lot_id, self.wafer_id, self.x_coord, self.y_coord
            ))
        }
    }

    impl From<[u8; 16]> for SerialNumber {
        fn from(data: [u8; 16]) -> Self {
            Self {
                sn: data[0],
                fab_data: [data[1], data[2], data[3]],
                fab_date: u16::from_le_bytes([data[4], data[5]]),
                lot_id: [data[6], data[7], data[8], data[9], data[10]],
                wafer_id: data[11],
                x_coord: u16::from_le_bytes([data[12], data[13]]),
                y_coord: u16::from_le_bytes([data[14], data[15]]),
            }
        }
    }

    pub struct Provisioning {
        /// Provisioning template version.
        pub prov_templ_ver: [u8; 2],
        /// Provisioning template tag.
        pub prov_templ_tag: [u8; 4],
        /// Provisioning specification version.
        pub prov_spec_ver: [u8; 2],
        /// Provisioning specification tag.
        pub prov_spec_tag: [u8; 4],
    }

    impl core::fmt::Display for Provisioning {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_fmt(format_args!(
                "prov_templ_ver: {}.{}, prov_spec_ver: {}.{}",
                self.prov_templ_ver[0],
                self.prov_templ_ver[1],
                self.prov_spec_ver[0],
                self.prov_spec_ver[1]
            ))
        }
    }

    impl From<[u8; 16]> for Provisioning {
        fn from(data: [u8; 16]) -> Self {
            Self {
                prov_templ_ver: [data[0], data[1]],
                prov_templ_tag: [data[2], data[3], data[4], data[5]],
                prov_spec_ver: [data[6], data[7]],
                prov_spec_tag: [data[8], data[9], data[10], data[11]],
            }
        }
    }

    pub struct ChipId {
        /// CHIP_ID structure versioning (32 bits), defined by Tropic Square in BP.
        pub chip_id_ver: [u8; 4], //  [0x01_u8, 0x02, 0x03, 0x04];
        /// Factory level test info (128 bits), structure retrieved from silicon provider.
        pub fl_chip_info: [u8; 16],
        /// Manufacturing level test info (128 bits), structure retrieved from test line and BP.
        pub func_test_info: [u8; 8],
        /// Silicon revision (32 bits).
        pub silicon_rev: [u8; 4],
        /// Package Type ID deﬁned by Tropic Square
        pub packg_type_id: [u8; 2],
        /// Reserved field 1 (16 bits).
        pub rfu_1: [u8; 2],
        /// Provisioning info (128 bits), filled by the provisioning station.
        /// - 8 bits: Provisioning info version.
        /// - 12 bits: Fabrication ID.
        /// - 12 bits: Part Number ID.
        pub prov_ver_fab_id_pn: [u8; 4],
        /// Provisioning date (16 bits).
        pub provisioning_date: [u8; 2],
        /// HSM version (32 bits).
        /// Byte 0: RFU, Byte 1: Major version, Byte 2: Minor version, Byte 3: Patch version
        pub hsm_ver: [u8; 4],
        /// Program version (32 bits).
        pub prog_ver: [u8; 4],
        /// Reserved field 2 (16 bits).
        pub rfu_2: [u8; 2],
        /// Serial Number (128 bits).
        pub ser_num: SerialNumber,
        ///  Part Number (128 bits), defined by Tropic Square in BP.
        pub part_num_data: [u8; 16],
        /// Provisioning Data version (96 bits).
        /// Defined by Tropic Square for each batch in BP.
        pub prov: Provisioning,
        /// Batch ID (40 bits).
        pub batch_id: [u8; 5],
        /// Reserved field 3 (24 bits).
        pub rfu_3: [u8; 3],
        /// Padding (192 bits).
        pub rfu_4: [u8; 24],
    }

    impl core::fmt::Display for ChipId {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_fmt(format_args!(
                "chip_id_ver: {}.{}.{}.{}\r\n",
                self.chip_id_ver[0], self.chip_id_ver[1], self.chip_id_ver[2], self.chip_id_ver[3]
            ))?;
            f.write_fmt(format_args!("fl_chip_info: {:?}\r\n", self.fl_chip_info))?;
            f.write_fmt(format_args!(
                "func_test_info: {:?}\r\n",
                self.func_test_info
            ))?;
            f.write_fmt(format_args!(
                "silicon_rev: {}.{}.{}.{}\r\n",
                self.silicon_rev[0], self.silicon_rev[1], self.silicon_rev[2], self.silicon_rev[3]
            ))?;
            f.write_fmt(format_args!(
                "packg_type_id: {}.{}\r\n",
                self.packg_type_id[0], self.packg_type_id[1]
            ))?;
            f.write_fmt(format_args!(
                "rfu_1: {}.{}\r\n",
                self.rfu_1[0], self.rfu_1[1]
            ))?;
            f.write_fmt(format_args!(
                "prov_ver_fab_id_pn: {}.{}.{}.{}\r\n",
                self.prov_ver_fab_id_pn[0],
                self.prov_ver_fab_id_pn[1],
                self.prov_ver_fab_id_pn[2],
                self.prov_ver_fab_id_pn[3]
            ))?;
            f.write_fmt(format_args!(
                "provisioning_date: {}.{}\r\n",
                self.provisioning_date[0], self.provisioning_date[1]
            ))?;
            f.write_fmt(format_args!(
                "hsm_ver: {}.{}.{}.{}\r\n",
                self.hsm_ver[0], self.hsm_ver[1], self.hsm_ver[2], self.hsm_ver[3]
            ))?;
            f.write_fmt(format_args!(
                "prog_ver: {}.{}.{}.{}\r\n",
                self.prog_ver[0], self.prog_ver[1], self.prog_ver[2], self.prog_ver[3]
            ))?;
            f.write_fmt(format_args!(
                "rfu_2: {}.{}\r\n",
                self.rfu_2[0], self.rfu_2[1]
            ))?;
            f.write_fmt(format_args!("ser_num: {}\r\n", self.ser_num))?;
            f.write_fmt(format_args!("part_num_data: {:?}\r\n", self.part_num_data))?;
            f.write_fmt(format_args!("prov: {}\r\n", self.prov))?;
            f.write_fmt(format_args!("batch_id: {:?}\r\n", self.batch_id))?;
            f.write_fmt(format_args!("rfu_3: {:?}\r\n", self.rfu_3))?;
            f.write_fmt(format_args!("rfu_4: {:?}\r\n", self.rfu_4))
        }
    }

    impl From<[u8; 128]> for ChipId {
        fn from(data: [u8; 128]) -> Self {
            Self {
                chip_id_ver: [data[0], data[1], data[2], data[3]],
                fl_chip_info: [
                    data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
                    data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
                ],
                func_test_info: [
                    data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
                ],
                silicon_rev: [data[28], data[29], data[30], data[31]],
                packg_type_id: [data[32], data[33]],
                rfu_1: [data[34], data[35]],
                prov_ver_fab_id_pn: [data[36], data[37], data[38], data[39]],
                provisioning_date: [data[40], data[41]],
                hsm_ver: [data[42], data[43], data[44], data[45]],
                prog_ver: [data[46], data[47], data[48], data[49]],
                rfu_2: [data[50], data[51]],
                ser_num: SerialNumber::from([
                    data[52], data[53], data[54], data[55], data[56], data[57], data[58], data[59],
                    data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
                ]),
                part_num_data: [
                    data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
                    data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
                ],
                prov: Provisioning::from([
                    data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
                    data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95],
                ]),
                batch_id: [data[96], data[97], data[98], data[99], data[100]],
                rfu_3: [data[101], data[102], data[103]],
                rfu_4: [
                    data[104], data[105], data[106], data[107], data[108], data[109], data[110],
                    data[111], data[112], data[113], data[114], data[115], data[116], data[117],
                    data[118], data[119], data[120], data[121], data[122], data[123], data[124],
                    data[125], data[126], data[127],
                ],
            }
        }
    }

    impl From<Response<{ GET_INFO_CHIP_INFO_ID_SIZE }>> for ChipId {
        fn from(resp: Response<{ GET_INFO_CHIP_INFO_ID_SIZE }>) -> Self {
            Self::from(resp.data)
        }
    }
}

use embedded_hal::spi::Error as _;

#[cfg(debug_assertions)]
pub mod keys;

pub mod session;

pub use session::{EncSession, Session};

use crate::{common, l1, l2};

// Size of l3 TAG field
pub(crate) const TAG_LEN: usize = 16;

// Size of CMD_ID field
pub(crate) const CMD_ID_LEN: usize = 1;

// Size of RES_RESULT status field
pub(crate) const RES_STATUS_LEN: usize = 1;

// Size of CMD_SIZE field
pub(crate) const CMD_SIZE_LEN: usize = 2;
// Size of RES_SIZE
pub(crate) const RES_SIZE_LEN: usize = 2;

// Maximal size of l3 RES/RSP DATA field
const CMD_DATA_SIZE_MAX: usize = 4111;
// Maximum size of l3 ciphertext (or decrypted l3 packet)
pub(crate) const PACKET_MAX_LEN: usize = CMD_ID_LEN + CMD_DATA_SIZE_MAX;

// Max size of one unit of transport on l3 layer
pub(crate) const FRAME_MAX_LEN: usize = RES_SIZE_LEN + PACKET_MAX_LEN + TAG_LEN;

const CMD_SLOT_LEN: usize = 2;

/// Length of secret key for ECC operations
pub const CMD_SECRET_KEY_LEN: usize = 32;

const RES_PUBLIC_KEY_LEN: usize = 64;

#[derive(Debug, PartialEq)]
pub enum Error {
    L2(l2::Error),
    Common(common::Error),
    Config(common::config::Error),
    PLaintextCmdSize,
    Session(session::Error),
    InvalidStatus(u8),
    RespErr(Status),
    MaxPingMsgSize,
    MaxFrameSize,
    ReadConfigBytes,
    RMemData(Status),
    Ecc(Status),
    Mcounter(Status),
    PairingKey(Status),
    UserDataLenMin,
    UserDataLenMax,
    RandomValueMin,
    RandomValueMax,
    DigestSize,
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::L2(err) => f.write_fmt(format_args!("l2 error: {}", err)),
            Self::Common(err) => f.write_fmt(format_args!("common error: {}", err)),
            Self::Config(err) => f.write_fmt(format_args!("config error: {}", err)),
            Self::PLaintextCmdSize => f.write_str("plaintext command size too big"),
            Self::Session(err) => f.write_fmt(format_args!("session error: {}", err)),
            Self::InvalidStatus(status) => f.write_fmt(format_args!("invalid status: {}", status)),
            Self::RespErr(status) => f.write_fmt(format_args!(
                "response contained error status: {:?}",
                status
            )),
            Self::MaxPingMsgSize => f.write_str("ping message size too big"),
            Self::MaxFrameSize => f.write_str("requested frame size too big"),
            Self::ReadConfigBytes => f.write_str("failed to read config bytes"),
            Self::RMemData(status) => f.write_fmt(format_args!("r_mem_data error: {:?}", status)),
            Self::Ecc(status) => f.write_fmt(format_args!("ecc error: {:?}", status)),
            Self::Mcounter(status) => f.write_fmt(format_args!("mcounter error: {:?}", status)),
            Self::PairingKey(status) => {
                f.write_fmt(format_args!("pairing key error: {:?}", status))
            }
            Self::UserDataLenMin => f.write_str("user data must be minimum 1 byte"),
            Self::UserDataLenMax => f.write_str("user data len too large"),
            Self::RandomValueMin => f.write_str("random value len must be minimum 1 byte"),
            Self::RandomValueMax => f.write_str("random value len too large"),
            Self::DigestSize => f.write_str("invalid digest size"),
        }
    }
}

impl From<l2::Error> for Error {
    fn from(err: l2::Error) -> Self {
        Self::L2(err)
    }
}

impl From<common::Error> for Error {
    fn from(err: common::Error) -> Self {
        Self::Common(err)
    }
}

impl From<session::Error> for Error {
    fn from(err: session::Error) -> Self {
        Self::Session(err)
    }
}

impl From<core::convert::Infallible> for Error {
    fn from(_: core::convert::Infallible) -> Self {
        unreachable!()
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /** Return values based on RESULT field */
    /*  API r_mem_data_write: */
    // User slot is empty.
    RMemDataReadSlotEmpty = 0xb,
    /// Write failed, because slot is already written in.
    RMemDataWriteWriteFail = 0x10,
    /// Writing operation limit is reached for a given slot.
    RMemDataWriteSlotExpired = 0x11,

    /*  API EDDSA_sign, ECDSA_sign, ecc_key_read: */
    /// The key in the requested slot does not exist, or is invalid.
    EccInvalidKey = 0x12,

    /*  API mcounter_update mcounter_get: */
    /// Failure to update the speciﬁed Monotonic Counter.
    /// The Monotonic Counter is already at 0.
    McounterUpdateUpdateErr = 0x13,
    /// The Monotonic Counter detects an attack and is locked.
    /// The counter must be reinitialized.
    CounterInvalid = 0x14,

    /*  API pairing_key_read: */
    /// The Pairing key slot is in "Blank" state.
    /// A Pairing Key has not been written to it yet.
    PairingKeyEmpty = 0x15,
    /// The Pairing key slot is in "Invalidated" state.
    /// The Pairing key has been invalidated.
    PairingKeyInvalid = 0x16,

    /* General */
    /// L3 command was received correctly.
    Ok = 0xC3,
    /// L3 command was not received correctly.
    Fail = 0x3C,
    /// Current pairing keys are not authorized for execution
    /// of the last command.
    Unauthorized = 0x01,
    /// Received L3 command is invalid.
    InvalidCmd = 0x02,
}

impl TryFrom<u8> for Status {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Unauthorized),
            0x02 => Ok(Self::InvalidCmd),

            0x0b => Ok(Self::RMemDataReadSlotEmpty),
            0x10 => Ok(Self::RMemDataWriteWriteFail),
            0x11 => Ok(Self::RMemDataWriteSlotExpired),
            0x12 => Ok(Self::EccInvalidKey),
            0x13 => Ok(Self::McounterUpdateUpdateErr),
            0x14 => Ok(Self::CounterInvalid),
            0x15 => Ok(Self::PairingKeyEmpty),
            0x16 => Ok(Self::PairingKeyInvalid),

            0xC3 => Ok(Self::Ok),
            0x3C => Ok(Self::Fail),

            _ => Err(Error::InvalidStatus(value)),
        }
    }
}

// L3 response.
//
// - len:    data length
// - status: status byte
// - data:   data, without the status byte
pub(crate) struct Response<const N: usize> {
    pub(crate) len: u16,
    pub(crate) status: Status,
    pub(crate) data: [u8; N],
}

pub(crate) fn receive<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
    const N: usize,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    session: &mut impl Session,
) -> Result<Response<N>, Error> {
    if N > FRAME_MAX_LEN {
        return Err(Error::MaxFrameSize);
    }

    let mut buf = [0_u8; FRAME_MAX_LEN];
    l2::enc_session::receive(spi_device, delay, &mut buf)?;

    // len = 1 byte status + data
    let len = u16::from_le_bytes(buf[..RES_SIZE_LEN].try_into().unwrap());

    let mut data = [0_u8; N];
    let data_seek = RES_SIZE_LEN + len as usize;
    data[..len as usize].copy_from_slice(&buf[RES_SIZE_LEN..data_seek]);

    let mut tag = [0_u8; TAG_LEN];
    tag.copy_from_slice(&buf[data_seek..data_seek + TAG_LEN]);

    session.decrypt_response(&mut data[..len as usize], &tag)?;
    let status = data[0].try_into()?;

    match status {
        Status::RMemDataReadSlotEmpty
        | Status::RMemDataWriteSlotExpired
        | Status::RMemDataWriteWriteFail => {
            return Err(Error::RMemData(status));
        }
        Status::EccInvalidKey => {
            return Err(Error::Ecc(status));
        }
        Status::McounterUpdateUpdateErr | Status::CounterInvalid => {
            return Err(Error::Mcounter(status));
        }
        Status::PairingKeyEmpty | Status::PairingKeyInvalid => {
            return Err(Error::PairingKey(status));
        }
        Status::Fail | Status::InvalidCmd | Status::Unauthorized => {
            return Err(Error::RespErr(status));
        }
        Status::Ok => {}
    }

    // shift status out of data
    for i in 0..(len as usize - 1) {
        // will be optimized by the compiler in release builds
        // see: https://godbolt.org/z/W5d1KnjGo
        data[i] = data[i + 1];
    }
    // truncate last byte after left shifting the array
    data[len as usize - 1] = 0;

    Ok(Response {
        // len without the status byte
        len: len - 1,
        status,
        data,
    })
}

pub trait PlaintextCmd<const N: usize = CMD_DATA_SIZE_MAX> {
    fn size(&self) -> u16;
    fn data(self) -> [u8; N];
}

pub struct Request<const N: usize> {
    pub size: u16,
    pub data: [u8; N],
    pub tag: [u8; TAG_LEN],
}

impl<const N: usize> Request<N> {
    pub fn create<P: PlaintextCmd<N>>(
        plaintext_cmd: P,
        session: &mut impl Session,
    ) -> Result<Self, Error> {
        let size = plaintext_cmd.size();
        let mut data = plaintext_cmd.data();

        if size as usize > N {
            return Err(Error::PLaintextCmdSize);
        }

        let tag = session.encrypt_request(&mut data[..size as usize])?;
        Ok(Self { size, data, tag })
    }
}

pub fn send<
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
    const N: usize,
    P: PlaintextCmd<N>,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    plaintext_cmd: P,
    session: &mut impl Session,
) -> Result<(), Error> {
    let enc_cmd = Request::<N>::create(plaintext_cmd, session)?;
    let enc_cmd_chunks = l2::enc_session::EncryptedCmdReq::create(&enc_cmd)?;

    for i in 0..enc_cmd_chunks.count {
        let is_last_chunk = i == enc_cmd_chunks.count - 1;

        if is_last_chunk {
            spi_device
                .write(&enc_cmd_chunks.chunks[i][..enc_cmd_chunks.last_len])
                .map_err(|err| Error::L2(l2::Error::Spi(err.kind())))?;
        } else {
            spi_device
                .write(&enc_cmd_chunks.chunks[i])
                .map_err(|err| Error::L2(l2::Error::Spi(err.kind())))?;
        }

        // verify l2 resp status
        let resp: l2::Response<{ l1::LEN_MAX }> = l1::receive(spi_device, delay)
            .map_err(|err| Error::L2(l2::Error::L1(err)))?
            .try_into()?;

        if is_last_chunk {
            if resp.status != l2::Status::RequestOk {
                return Err(Error::L2(l2::Error::RespErr(resp.status)));
            }
        } else if resp.status != l2::Status::RequestCont {
            return Err(Error::L2(l2::Error::RespErr(resp.status)));
        }
    }
    Ok(())
}

mod sealed {
    pub trait Sealed {}
}

pub(crate) trait ReceiveResponseL3<const N: usize>: sealed::Sealed
where
    Self: TryFrom<Response<N>>,
    <Self as TryFrom<Response<N>>>::Error: Into<Error>,
{
    fn receive_l3<SPI: embedded_hal::spi::SpiDevice, D: embedded_hal::delay::DelayNs>(
        spi_device: &mut SPI,
        delay: &mut D,
        session: &mut impl Session,
    ) -> Result<Self, Error> {
        receive(spi_device, delay, session)?
            .try_into()
            .map_err(Into::into)
    }
}

pub struct StatusResp {
    pub len: u16,
    pub status: Status,
}

impl From<Response<RES_STATUS_LEN>> for StatusResp {
    fn from(resp: Response<RES_STATUS_LEN>) -> Self {
        Self {
            len: resp.len,
            status: resp.status,
        }
    }
}

impl sealed::Sealed for StatusResp {}

impl ReceiveResponseL3<RES_STATUS_LEN> for StatusResp {}

pub mod ping {
    use super::*;

    // command id
    const PING_CMD_ID: u8 = 0x01;

    // minimal length of field data_in
    #[allow(unused)]
    pub const PING_CMD_DATA_LEN_MIN: usize = 0;

    // maximal length of field data_in
    pub const PING_CMD_DATA_LEN_MAX: usize = 4096;

    // command len CMD_ID[1] MSG[0-4096]
    const PING_CMD_DATE_LEN: usize = CMD_ID_LEN + PING_CMD_DATA_LEN_MAX;

    // result length STATUS[1]
    #[allow(unused)]
    const PING_RES_LEN_MIN: usize = 1;

    // result length STATUS[1]  MSG[0-4096]
    const PING_RES_LEN_MAX: usize = RES_STATUS_LEN + PING_CMD_DATA_LEN_MAX;

    pub struct PingCmd {
        size: u16,
        data: [u8; PING_CMD_DATE_LEN],
    }

    impl PingCmd {
        pub fn create(msg: &[u8]) -> Result<Self, Error> {
            let mut data = [0_u8; PING_CMD_DATE_LEN];
            let len = msg.len();
            if len > PING_CMD_DATA_LEN_MAX {
                return Err(Error::MaxPingMsgSize);
            }
            data[0] = PING_CMD_ID;
            data[1..len + 1].copy_from_slice(msg);
            let size = len as u16 + 1;

            Ok(Self { size, data })
        }
    }

    impl PlaintextCmd<PING_CMD_DATE_LEN> for PingCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; PING_CMD_DATE_LEN] {
            self.data
        }
    }

    pub struct PingResp {
        pub len: u16,
        pub status: Status,
        pub msg: [u8; PING_CMD_DATA_LEN_MAX],
    }

    impl PingResp {
        pub fn msg(&self) -> &[u8] {
            &self.msg[..self.len as usize]
        }
    }

    impl From<Response<PING_RES_LEN_MAX>> for PingResp {
        fn from(resp: Response<PING_RES_LEN_MAX>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
                msg: resp.data[..PING_CMD_DATA_LEN_MAX].try_into().unwrap(),
            }
        }
    }

    #[cfg(test)]
    pub mod tests {

        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::l3;

        #[test]
        fn test_ping_short() {
            let mut mocked_delay = CheckedDelay::new([]);

            let msg = b"ping";

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[PING_CMD_ID, b'p', b'i', b'n', b'g'],
                    &[Status::Ok as u8, b'p', b'i', b'n', b'g'],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                PingCmd::create(msg).expect("failed to create command"),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let write_result: PingResp = result.into();

            assert_eq!(write_result.status, Status::Ok);
            assert_eq!(write_result.len, 5_u16 - 1);
            assert_eq!(write_result.msg(), b"ping");

            mocked_delay.done();
            mocked_spi_device.done();
        }

        // TODO: add variant that can use l2 cmd chunks
        // #[test]
        // fn test_ping_short_long() {
        //     let mut mocked_delay = CheckedDelay::new([]);

        //     let msg = [0xb_u8; PING_CMD_DATA_LEN_MAX];
        //     let len_slice = (PING_CMD_DATA_LEN_MAX as u16).to_le_bytes();

        //     let mut exp_req = [4, 23, len_slice[0], len_slice[1], PING_CMD_ID].to_vec();
        //     exp_req.extend_from_slice(&msg);

        //     let mut resp_data = [Status::Ok as u8].to_vec();
        //     resp_data.extend_from_slice(&msg);
        //     let (mut mocked_spi_device, mut mocked_session) =
        //         super::super::tests::get_mocked_spi_device_and_session(&exp_req, &resp_data);

        //     l3::send(
        //         &mut mocked_spi_device,
        //         &mut mocked_delay,
        //         PingCmd::create(&msg).expect("failed to create command"),
        //         &mut mocked_session,
        //     )
        //     .expect("failed to send command");

        //     let result = l3::receive(
        //         &mut mocked_spi_device,
        //         &mut mocked_delay,
        //         &mut mocked_session,
        //     )
        //     .expect("failed to get result");

        //     let write_result: PingResp = result.try_into().expect("failed to parse result");

        //     assert_eq!(write_result.status, Status::Ok);
        //     assert_eq!(write_result.len, 5 as u16 - 1);

        //     mocked_delay.done();
        //     mocked_spi_device.done();
        // }
    }
}

pub mod payring_key {

    use crate::common::PairingKeySlot;

    use super::*;

    // command id
    const PAIRING_KEY_WRITE_CMD_ID: u8 = 0x10;

    // command length CMD_ID[1] KEY_SLOT[2] PADDING[1] KEY[32]
    const PAIRING_KEY_WRITE_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN + 33;

    // result length STATUS[1]
    #[allow(unused)]
    const PAIRING_KEY_WRITE_RESP_LEN: usize = RES_STATUS_LEN;

    pub struct PairingKeyWriteCmd {
        size: u16,
        data: [u8; PAIRING_KEY_WRITE_CMD_LEN],
    }

    impl PairingKeyWriteCmd {
        pub fn create(slot: PairingKeySlot, key: &x25519_dalek::PublicKey) -> Self {
            let mut data = [0_u8; PAIRING_KEY_WRITE_CMD_LEN];
            data[0] = PAIRING_KEY_WRITE_CMD_ID;
            // slot is a u16,
            // since there are only 4 pairing key slots, we only ever set the firts one
            data[1] = slot as u8;
            data[2] = 0;
            data[3] = 0; // The padding by dummy data.
            data[4..36].copy_from_slice(key.as_bytes());
            let size = (PAIRING_KEY_WRITE_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<PAIRING_KEY_WRITE_CMD_LEN> for PairingKeyWriteCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; PAIRING_KEY_WRITE_CMD_LEN] {
            self.data
        }
    }

    pub type PairingKeyWriteResp = StatusResp;

    // command id
    const PAIRING_KEY_READ_CMD_ID: u8 = 0x11;
    // command length CMD_ID[1] KEY_SLOT[2]
    pub(crate) const PAIRING_KEY_READ_CMD_LEN: usize = CMD_ID_LEN + 2;

    // result length STATUS[1] PADDING[3] KEY[32]
    pub(crate) const PAIRING_KEY_READ_RES_LEN: usize = RES_STATUS_LEN + 35;

    pub struct PairingKeyReadCmd {
        size: u16,
        data: [u8; PAIRING_KEY_READ_CMD_LEN],
    }

    impl PairingKeyReadCmd {
        pub fn create(slot: PairingKeySlot) -> Self {
            let mut data = [0_u8; PAIRING_KEY_READ_CMD_LEN];
            data[0] = PAIRING_KEY_READ_CMD_ID;
            // slot is a u16,
            // since there are only 4 pairing key slots, we only ever set the firts one
            data[1] = slot as u8;
            data[2] = 0;
            let size = (PAIRING_KEY_READ_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<PAIRING_KEY_READ_CMD_LEN> for PairingKeyReadCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; PAIRING_KEY_READ_CMD_LEN] {
            self.data
        }
    }

    pub struct PairingKeyReadResp {
        pub len: u16,
        pub status: Status,
        pub padding: [u8; 3],
        pub s_hipub: [u8; 32],
    }

    #[cfg(feature = "display")]
    impl core::fmt::Display for PairingKeyReadResp {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_fmt(format_args!(
                "status: {:?}, padding: {:?}, s_hipub: {:?}",
                self.status, self.padding, self.s_hipub
            ))
        }
    }

    impl From<Response<PAIRING_KEY_READ_RES_LEN>> for PairingKeyReadResp {
        fn from(resp: Response<PAIRING_KEY_READ_RES_LEN>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
                padding: resp.data[..3].try_into().unwrap(),
                s_hipub: resp.data[3..35].try_into().unwrap(),
            }
        }
    }

    // command id
    const PAIRING_KEY_INVALIDATE_CMD_ID: u8 = 0x12;
    // command length CMD_ID[1] KEY_SLOT[2]
    const PAIRING_KEY_INVALIDATE_CMD_LEN: usize = CMD_ID_LEN + 2;

    // result length STATUS[1]
    #[allow(unused)]
    const PAIRING_KEY_INVALIDATE_RES_LEN: usize = 1;

    pub struct PairingKeyInvalidateCmd {
        size: u16,
        data: [u8; PAIRING_KEY_INVALIDATE_CMD_LEN],
    }

    impl PairingKeyInvalidateCmd {
        pub fn create(slot: PairingKeySlot) -> Self {
            let mut data = [0_u8; PAIRING_KEY_INVALIDATE_CMD_LEN];
            data[0] = PAIRING_KEY_INVALIDATE_CMD_ID;
            // slot is a u16,
            // since there are only 4 pairing key slots, we only ever set the firts one
            data[1] = slot as u8;
            data[2] = 0;
            let size = (PAIRING_KEY_INVALIDATE_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<PAIRING_KEY_INVALIDATE_CMD_LEN> for PairingKeyInvalidateCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; PAIRING_KEY_INVALIDATE_CMD_LEN] {
            self.data
        }
    }

    pub type PairingKeyInvalidateResp = StatusResp;

    #[cfg(test)]
    pub mod tests {

        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::{common, l3};

        #[test]
        fn test_pairing_key_write() {
            let mut mocked_delay = CheckedDelay::new([]);

            let key = [0xff_u8; 32];
            let mut exp_req = [PAIRING_KEY_WRITE_CMD_ID, 1, 0, 0].to_vec();
            exp_req.extend_from_slice(&key);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &exp_req,
                    &[Status::Ok as u8],
                );

            let key = [0xff_u8; 32].into();

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                PairingKeyWriteCmd::create(common::PairingKeySlot::Index1, &key),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let write_result: PairingKeyWriteResp = result.into();

            assert_eq!(write_result.status, Status::Ok);
            assert_eq!(write_result.len, PAIRING_KEY_WRITE_RESP_LEN as u16 - 1);

            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_pairing_key_read() {
            let mut mocked_delay = CheckedDelay::new([]);

            let key = [0xff_u8; 32];

            let mut resp_data = [Status::Ok as u8, 0, 0, 0].to_vec();
            resp_data.extend_from_slice(&key);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[PAIRING_KEY_READ_CMD_ID, 1, 0],
                    &resp_data,
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                PairingKeyReadCmd::create(common::PairingKeySlot::Index1),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let read_result: PairingKeyReadResp = result.into();

            assert_eq!(read_result.status, Status::Ok);
            assert_eq!(read_result.len, PAIRING_KEY_READ_RES_LEN as u16 - 1);
            assert_eq!(read_result.s_hipub, key);

            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_pairing_key_invalidate() {
            let mut mocked_delay = CheckedDelay::new([]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[PAIRING_KEY_INVALIDATE_CMD_ID, 2, 0],
                    &[Status::Ok as u8],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                PairingKeyInvalidateCmd::create(common::PairingKeySlot::Index2),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let invalidate_result: PairingKeyInvalidateResp = result.into();

            assert_eq!(invalidate_result.status, Status::Ok);
            assert_eq!(
                invalidate_result.len,
                PAIRING_KEY_INVALIDATE_RES_LEN as u16 - 1
            );

            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

pub mod reversable_config {

    use crate::common::{
        self,
        config::{RegisterAddr, RegisterValue as _},
    };

    use super::*;

    // command id
    const R_CONFIG_WRITE_CMD_ID: u8 = 0x20;
    // command length CMD_ID[1] REG_ADDR[2] PADDING[1] VALUE[4]
    const R_CONFIG_WRITE_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN + 5;

    // result length STATUS[1]
    #[allow(unused)]
    const R_CONFIG_WRITE_RES_LEN: usize = RES_STATUS_LEN;

    pub struct ConfigWriteCmd {
        size: u16,
        data: [u8; R_CONFIG_WRITE_CMD_LEN],
    }

    impl ConfigWriteCmd {
        pub fn create<R: RegisterAddr>(addr: R, value: R::Item) -> Self {
            let mut data = [0_u8; R_CONFIG_WRITE_CMD_LEN];
            data[0] = R_CONFIG_WRITE_CMD_ID;
            data[1..3].copy_from_slice(&addr.register_addr());
            // padding
            data[3] = 0x00;
            data[4..8].copy_from_slice(&value.to_value());
            let size = (R_CONFIG_WRITE_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<R_CONFIG_WRITE_CMD_LEN> for ConfigWriteCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; R_CONFIG_WRITE_CMD_LEN] {
            self.data
        }
    }

    pub type ConfigWriteResp = StatusResp;

    // command id
    const R_CONFIG_READ_CMD_ID: u8 = 0x21;

    // command length CMD_ID[1] REG_ADDR[2]
    const R_CONFIG_READ_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN;

    // result length STATUS[1] PADDING[3] VALUE[4]
    const R_CONFIG_READ_RES_LEN: usize = RES_STATUS_LEN + 7;

    pub struct ConfigReadCmd {
        size: u16,
        data: [u8; R_CONFIG_READ_CMD_LEN],
    }

    impl ConfigReadCmd {
        pub fn create<R: RegisterAddr>(addr: &R) -> Self {
            let mut data = [0_u8; R_CONFIG_READ_CMD_LEN];
            data[0] = R_CONFIG_READ_CMD_ID;
            data[1..3].copy_from_slice(&addr.register_addr());
            let size = (R_CONFIG_READ_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<R_CONFIG_READ_CMD_LEN> for ConfigReadCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; R_CONFIG_READ_CMD_LEN] {
            self.data
        }
    }

    pub struct ConfigReadResp<T: common::config::RegisterValue> {
        pub len: u16,
        pub status: Status,
        pub padding: [u8; 3],
        pub value: T,
    }

    #[cfg(feature = "display")]
    impl<T> core::fmt::Display for ConfigReadResp<T>
    where
        // T: Flags<Bits = u32> + core::fmt::Display,
        T: common::config::RegisterValue + core::fmt::Display,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_fmt(format_args!(
                "status: {:?}, padding: {:?}, value: {}",
                self.status, self.padding, self.value
            ))
        }
    }

    impl<T: common::config::RegisterValue> TryFrom<Response<R_CONFIG_READ_RES_LEN>>
        for ConfigReadResp<T>
    {
        type Error = Error;

        fn try_from(resp: Response<R_CONFIG_READ_RES_LEN>) -> Result<Self, Self::Error> {
            let value = u32::from_le_bytes(
                resp.data[3..7]
                    .try_into()
                    .map_err(|_| Error::ReadConfigBytes)?,
            );

            let value = T::from_u32(value);

            Ok(Self {
                len: resp.len,
                status: resp.status,
                padding: resp.data[..3].try_into().unwrap(),
                value,
            })
        }
    }

    // command id
    const R_CONFIG_ERASE_CMD_ID: u8 = 0x22;

    // command length CMD_ID[1]
    const R_CONFIG_ERASE_CMD_LEN: usize = CMD_ID_LEN;

    // result length STATUS[1]
    #[allow(unused)]
    const R_CONFIG_ERASE_RES_LEN: usize = RES_STATUS_LEN;

    pub struct ConfigEraseCmd {
        size: u16,
        data: [u8; R_CONFIG_ERASE_CMD_LEN],
    }

    impl ConfigEraseCmd {
        #[allow(unused)]
        pub fn create() -> Self {
            let mut data = [0_u8; R_CONFIG_ERASE_CMD_LEN];
            data[0] = R_CONFIG_ERASE_CMD_ID;
            let size = (R_CONFIG_ERASE_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<R_CONFIG_ERASE_CMD_LEN> for ConfigEraseCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; R_CONFIG_ERASE_CMD_LEN] {
            self.data
        }
    }

    pub type ConfigEraseResp = StatusResp;

    #[cfg(test)]
    pub mod tests {

        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::{common::config::bootloader, l3};

        #[test]
        fn test_config_write() {
            let mut mocked_delay = CheckedDelay::new([]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[R_CONFIG_WRITE_CMD_ID, 0, 0, 0, 255, 255, 255, 255],
                    &[Status::Ok as u8],
                );

            let addr = bootloader::StartUpRegAddr;
            let value = bootloader::StartUp::default();

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                ConfigWriteCmd::create(addr, value),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let write_result: ConfigWriteResp = result.try_into().expect("failed to parse result");

            assert_eq!(write_result.status, Status::Ok);
            assert_eq!(write_result.len, R_CONFIG_WRITE_RES_LEN as u16 - 1);

            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_config_read() {
            let mut mocked_delay = CheckedDelay::new([]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[R_CONFIG_READ_CMD_ID, 0, 0],
                    &[Status::Ok as u8, 0, 0, 0, 255, 255, 255, 255],
                );

            let addr = bootloader::StartUpRegAddr;

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                ConfigReadCmd::create(&addr),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let read_result: ConfigReadResp<bootloader::StartUp> =
                result.try_into().expect("failed to parse result");

            assert_eq!(read_result.status, Status::Ok);
            assert_eq!(read_result.len, R_CONFIG_READ_RES_LEN as u16 - 1);
            assert_eq!(read_result.value.bits(), u32::MAX);

            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_config_erase() {
            let mut mocked_delay = CheckedDelay::new([]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[R_CONFIG_ERASE_CMD_ID],
                    &[Status::Ok as u8],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                ConfigEraseCmd::create(),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let erase_result: ConfigEraseResp = result.try_into().expect("failed to parse result");

            assert_eq!(erase_result.status, Status::Ok);
            assert_eq!(erase_result.len, R_CONFIG_ERASE_RES_LEN as u16 - 1);

            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

pub mod irreversable_config {

    use crate::common::{self, config::RegisterAddr};

    use super::*;

    // command id
    const I_CONFIG_WRITE_CMD_ID: u8 = 0x30;
    // command length CMD_ID[1] REG_ADDR[2] BIT_INDEX[1]
    const I_CONFIG_WRITE_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN + 1;

    // result length STATUS[1]
    #[allow(unused)]
    const I_CONFIG_WRITE_RES_LEN: usize = RES_STATUS_LEN;

    // Command to write a single bit of CO (from I-Config) from 1 to 0.
    pub struct ConfigWriteCmd {
        size: u16,
        data: [u8; I_CONFIG_WRITE_CMD_LEN],
    }

    impl ConfigWriteCmd {
        pub fn create<R: RegisterAddr>(
            addr: &R,
            bit_index: common::config::IConfigBitIndex,
        ) -> Self {
            let mut data = [0_u8; I_CONFIG_WRITE_CMD_LEN];
            data[0] = I_CONFIG_WRITE_CMD_ID;
            data[1..3].copy_from_slice(&addr.register_addr());
            data[3] = bit_index.into();
            let size = (I_CONFIG_WRITE_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<I_CONFIG_WRITE_CMD_LEN> for ConfigWriteCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; I_CONFIG_WRITE_CMD_LEN] {
            self.data
        }
    }

    pub type ConfigWriteResp = StatusResp;

    // command id
    const I_CONFIG_READ_CMD_ID: u8 = 0x31;

    // command length CMD_ID[1] REG_ADDR[2]
    const I_CONFIG_READ_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN;

    // result length STATUS[1] PADDING[3] VALUE[4]
    const I_CONFIG_READ_RES_LEN: usize = RES_STATUS_LEN + 7;

    /// Command to read a single CO from I-Config.
    pub struct ConfigReadCmd {
        size: u16,
        data: [u8; I_CONFIG_READ_CMD_LEN],
    }

    impl ConfigReadCmd {
        pub fn create<R: RegisterAddr>(addr: &R) -> Self {
            let mut data = [0_u8; I_CONFIG_READ_CMD_LEN];
            data[0] = I_CONFIG_READ_CMD_ID;
            data[1..3].copy_from_slice(&addr.register_addr());
            let size = (I_CONFIG_READ_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<I_CONFIG_READ_CMD_LEN> for ConfigReadCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; I_CONFIG_READ_CMD_LEN] {
            self.data
        }
    }

    pub struct ConfigReadResp<T: common::config::RegisterValue> {
        pub len: u16,
        pub status: Status,
        pub padding: [u8; 3],
        pub value: T,
    }

    #[cfg(feature = "display")]
    impl<T> core::fmt::Display for ConfigReadResp<T>
    where
        // T: Flags<Bits = u32> + core::fmt::Display,
        T: common::config::RegisterValue + core::fmt::Display,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_fmt(format_args!(
                "status: {:?}, padding: {:?}, value: {}",
                self.status, self.padding, self.value
            ))
        }
    }

    impl<T: common::config::RegisterValue> TryFrom<Response<I_CONFIG_READ_RES_LEN>>
        for ConfigReadResp<T>
    {
        type Error = Error;

        fn try_from(resp: Response<I_CONFIG_READ_RES_LEN>) -> Result<Self, Self::Error> {
            let value = u32::from_le_bytes(
                resp.data[3..7]
                    .try_into()
                    .map_err(|_| Error::ReadConfigBytes)?,
            );

            let value = T::from_u32(value);

            Ok(Self {
                len: resp.len,
                status: resp.status,
                padding: resp.data[..3].try_into().unwrap(),
                value,
            })
        }
    }

    #[cfg(test)]
    pub mod tests {

        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::{common::config::bootloader, l3};

        #[test]
        fn test_config_write() {
            let mut mocked_delay = CheckedDelay::new([]);

            let addr = bootloader::SensorRegAddr;
            let bit_index = common::config::IConfigBitIndex::random();

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[I_CONFIG_WRITE_CMD_ID, 8, 0, bit_index.clone().into()],
                    &[Status::Ok as u8],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                ConfigWriteCmd::create(&addr, bit_index),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let write_result: ConfigWriteResp = result.try_into().expect("failed to parse result");

            assert_eq!(write_result.status, Status::Ok);
            assert_eq!(write_result.len, I_CONFIG_WRITE_RES_LEN as u16 - 1);

            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_config_read() {
            let mut mocked_delay = CheckedDelay::new([]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[I_CONFIG_READ_CMD_ID, 8, 0],
                    &[Status::Ok as u8, 0, 0, 0, 255, 255, 255, 255],
                );

            let addr = bootloader::SensorRegAddr;

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                ConfigReadCmd::create(&addr),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let read_result: ConfigReadResp<bootloader::StartUp> =
                result.try_into().expect("failed to parse result");

            assert_eq!(read_result.status, Status::Ok);
            assert_eq!(read_result.len, I_CONFIG_READ_RES_LEN as u16 - 1);
            assert_eq!(read_result.value.bits(), u32::MAX);

            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

pub mod r_mem_data {

    use crate::common;

    use super::*;

    // command id
    const R_MEM_DATA_WRITE_CMD_ID: u8 = 0x40;
    // command length
    #[allow(unused)]
    const R_MEM_DATA_WRITE_CMD_LEN_MIN: usize = 5;
    // minimal length of field data
    const R_MEM_DATA_WRITE_CMD_DATA_LEN_MIN: usize = 1;

    // memory slot size
    const R_MEM_DATA_SLOT_SIZE: usize = 444;

    // maximal length of field data
    pub const R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX: usize = R_MEM_DATA_SLOT_SIZE;

    const R_MEM_DATA_WRITE_CMD_LEN: usize =
        CMD_ID_LEN + CMD_SLOT_LEN + 1 + R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX;

    pub struct RMemDataWriteCmd {
        size: u16,
        data: [u8; R_MEM_DATA_WRITE_CMD_LEN],
    }

    impl RMemDataWriteCmd {
        pub fn create(
            user_data_slot: common::UserDataSlot,
            user_data: &[u8],
        ) -> Result<Self, Error> {
            let user_data_len = user_data.len();
            if user_data_len < R_MEM_DATA_WRITE_CMD_DATA_LEN_MIN {
                return Err(Error::UserDataLenMin);
            }
            if user_data_len > R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX {
                return Err(Error::UserDataLenMax);
            }

            let mut data = [0_u8; R_MEM_DATA_WRITE_CMD_LEN];
            data[0] = R_MEM_DATA_WRITE_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(user_data_slot));
            // padding
            data[3] = 0;
            data[4..user_data.len() + 4].copy_from_slice(user_data);
            let size = (CMD_ID_LEN + CMD_SLOT_LEN + 1 + user_data_len) as u16;
            Ok(Self { size, data })
        }
    }

    impl PlaintextCmd<R_MEM_DATA_WRITE_CMD_LEN> for RMemDataWriteCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; R_MEM_DATA_WRITE_CMD_LEN] {
            self.data
        }
    }

    pub type RMemDataWriteResp = StatusResp;

    // command id
    const R_MEM_DATA_READ_CMD_ID: u8 = 0x41;

    // command length CMD_ID[1] USER_DATA_SLOT[2]
    const R_MEM_DATA_READ_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN;

    // result length
    #[allow(unused)]
    const R_MEM_DATA_READ_RES_SIZE_MIN: usize = 4;
    const R_MEM_DATA_READ_RES_SIZE_MAX: usize = 448;

    // result length STATUS[1] PADDING[3] DATA[448]
    const R_MEM_DATA_READ_RES_LEN: usize = RES_STATUS_LEN + 3 + R_MEM_DATA_READ_RES_SIZE_MAX;

    pub struct RMemDataReadCmd {
        data: [u8; R_MEM_DATA_READ_CMD_LEN],
    }

    /// Command to read the general purpose data from a slot of the User Data partition in R-Memory.
    impl RMemDataReadCmd {
        pub fn create(slot: common::UserDataSlot) -> Self {
            let mut data = [0_u8; R_MEM_DATA_READ_CMD_LEN];
            data[0] = R_MEM_DATA_READ_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(slot));
            Self { data }
        }
    }

    impl PlaintextCmd<R_MEM_DATA_READ_CMD_LEN> for RMemDataReadCmd {
        fn size(&self) -> u16 {
            R_MEM_DATA_READ_CMD_LEN as u16
        }

        fn data(self) -> [u8; R_MEM_DATA_READ_CMD_LEN] {
            self.data
        }
    }

    /// The data stream read from the slot specified in the UDATA_- SLOT L3 field.
    pub struct RMemDataReadResp {
        pub len: u16,
        pub status: Status,
        pub user_data: [u8; R_MEM_DATA_SLOT_SIZE],
    }

    impl RMemDataReadResp {
        /// Returns a slice of the user data read from the slot.
        /// If the slot is empty, the slice is empty.
        pub fn user_data(&self) -> &[u8] {
            &self.user_data[..self.len as usize]
        }
    }

    impl TryFrom<Response<R_MEM_DATA_READ_RES_LEN>> for RMemDataReadResp {
        type Error = Error;
        fn try_from(resp: Response<R_MEM_DATA_READ_RES_LEN>) -> Result<Self, Self::Error> {
            if resp.len == 3 {
                return Err(Error::RMemData(Status::RMemDataReadSlotEmpty));
            }
            Ok(Self {
                // len - padding
                len: resp.len - 3,
                status: resp.status,
                user_data: resp.data[3..R_MEM_DATA_READ_RES_SIZE_MAX - 1]
                    .try_into()
                    .unwrap(),
            })
        }
    }

    //  command id
    const R_MEM_DATA_ERASE_CMD_ID: u8 = 0x42;
    // command length
    const R_MEM_DATA_ERASE_CMD_SIZE: usize = 3;

    // result length STATUS[1]
    #[allow(unused)]
    const R_MEM_DATA_ERASE_RES_SIZE: usize = 1;

    pub struct RMemDataEraseCmd {
        size: u16,
        data: [u8; R_MEM_DATA_ERASE_CMD_SIZE],
    }

    impl RMemDataEraseCmd {
        pub fn create(slot: common::UserDataSlot) -> Self {
            let mut data = [0_u8; R_MEM_DATA_ERASE_CMD_SIZE];
            data[0] = R_MEM_DATA_ERASE_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(slot));
            let size = (R_MEM_DATA_ERASE_CMD_SIZE) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<R_MEM_DATA_ERASE_CMD_SIZE> for RMemDataEraseCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; R_MEM_DATA_ERASE_CMD_SIZE] {
            self.data
        }
    }

    pub type RMemDataEraseResp = StatusResp;

    #[cfg(test)]
    pub mod tests {
        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::{common::UserDataSlot, l3};

        #[test]
        fn test_mem_data_write_cmd() {
            let mut mocked_delay = CheckedDelay::new([]);
            let user_data_slot = UserDataSlot::random();
            let user_data = [255, 251, 255, 251, 255, 251, 255];

            let mut exp_req = [R_MEM_DATA_WRITE_CMD_ID].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(user_data_slot.clone()));
            exp_req.extend_from_slice(&[0]); // padding
            exp_req.extend_from_slice(&user_data);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &exp_req,
                    &[Status::Ok as u8],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                RMemDataWriteCmd::create(user_data_slot, &user_data)
                    .expect("failed to create command"),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let write_result: RMemDataWriteResp =
                result.try_into().expect("failed to parse result");

            assert_eq!(write_result.status, Status::Ok);
            assert_eq!(write_result.len, RES_STATUS_LEN as u16 - 1);

            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_mem_data_read_resp() {
            let mut mocked_delay = CheckedDelay::new([]);
            let user_data_slot = UserDataSlot::random();

            let mut exp_req = [R_MEM_DATA_READ_CMD_ID].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(user_data_slot.clone()));

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &exp_req,
                    &[Status::Ok as u8, 0, 0, 0, 255, 255, 255, 255, 251, 251, 251],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                RMemDataReadCmd::create(user_data_slot),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let read_result: RMemDataReadResp = result.try_into().expect("failed to parse result");

            assert_eq!(read_result.status, Status::Ok);
            assert_eq!(read_result.len, 7);
            assert_eq!(
                read_result.user_data[0..7],
                [255, 255, 255, 255, 251, 251, 251]
            );

            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_mem_data_erase() {
            let mut mocked_delay = CheckedDelay::new([]);
            let user_data_slot = UserDataSlot::random();

            let mut exp_req = [R_MEM_DATA_ERASE_CMD_ID].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(user_data_slot.clone()));

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &exp_req,
                    &[Status::Ok as u8],
                );
            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                RMemDataEraseCmd::create(user_data_slot),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");
            let erase_result: RMemDataEraseResp =
                result.try_into().expect("failed to parse result");
            assert_eq!(erase_result.status, Status::Ok);
            assert_eq!(erase_result.len, RES_STATUS_LEN as u16 - 1);

            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

pub mod random {
    use crate::l3::sealed::Sealed;

    use super::*;

    // command id
    const RANDOM_VALUE_GET_CMD_ID: u8 = 0x50;
    // command length
    const RANDOM_VALUE_GET_CMD_LEN: usize = 2;

    // max length of random data
    pub const RANDOM_VALUE_GET_LEN_MAX: usize = 255;

    // result min length STATUS[1] PADDING[3] RANDOM_DATA[1]
    #[allow(unused)]
    const RANDOM_VALUE_GET_RES_LEN_MIN: usize = 4;

    // result max length STATUS[1] PADDING[3] RANDOM_DATA[255]
    const RANDOM_VALUE_GET_RES_LEN_MAX: usize = RES_STATUS_LEN + 3 + RANDOM_VALUE_GET_LEN_MAX;

    pub struct RandomValueGetCmd {
        data: [u8; RANDOM_VALUE_GET_CMD_LEN],
    }

    impl RandomValueGetCmd {
        pub fn create(n_bytes: u8) -> Result<Self, Error> {
            match n_bytes as usize {
                0 => Err(Error::RandomValueMin),
                256.. => Err(Error::RandomValueMax),
                1..=RANDOM_VALUE_GET_LEN_MAX => {
                    let mut data = [0_u8; RANDOM_VALUE_GET_CMD_LEN];
                    data[0] = RANDOM_VALUE_GET_CMD_ID;
                    data[1] = n_bytes;
                    Ok(Self { data })
                }
            }

            // if n_bytes == 0 || n_bytes > RANDOM_VALUE_GET_LEN_MAX as u8 {
            //     return Err(Error::RandomValueMax);
            // }
            // if n_bytes > RANDOM_VALUE_GET_LEN_MAX as u8 {
            //     return Err(Error::RandomValueMax);
            // }

            // let mut data = [0_u8; RANDOM_VALUE_GET_CMD_LEN];
            // data[0] = RANDOM_VALUE_GET_CMD_ID;
            // data[1] = n_bytes;
            // Self { data }
        }
    }

    impl PlaintextCmd<RANDOM_VALUE_GET_CMD_LEN> for RandomValueGetCmd {
        fn size(&self) -> u16 {
            RANDOM_VALUE_GET_CMD_LEN as u16
        }

        fn data(self) -> [u8; RANDOM_VALUE_GET_CMD_LEN] {
            self.data
        }
    }

    pub struct RandomValueGetResp {
        pub len: u16,
        pub status: Status,
        pub random_data: [u8; 255],
    }

    impl RandomValueGetResp {
        /// Returns a slice of the random data read.
        /// The length of the slice is equal to the length requested in the command.
        pub fn random_data(&self) -> &[u8] {
            &self.random_data[..self.len as usize]
        }
    }

    impl From<Response<RANDOM_VALUE_GET_RES_LEN_MAX>> for RandomValueGetResp {
        fn from(resp: Response<RANDOM_VALUE_GET_RES_LEN_MAX>) -> Self {
            Self {
                // len - padding
                len: resp.len - 3,
                status: resp.status,
                random_data: resp.data[3..3 + 255].try_into().unwrap(),
            }
        }
    }

    impl Sealed for RandomValueGetResp {}

    impl ReceiveResponseL3<RANDOM_VALUE_GET_RES_LEN_MAX> for RandomValueGetResp {}

    #[cfg(test)]
    pub mod tests {

        extern crate alloc;

        use alloc::vec::Vec;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::l3;

        #[test]
        fn test_random_value_get() {
            let mut mocked_delay = CheckedDelay::new([]);

            let random_data: Vec<u8> = (0..32).collect();

            let mut resp_data = [Status::Ok as u8, 0, 0, 0].to_vec();
            resp_data.extend_from_slice(&random_data);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[RANDOM_VALUE_GET_CMD_ID, 32],
                    &resp_data,
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                RandomValueGetCmd::create(32).expect("failed to create command"),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let read_result = RandomValueGetResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            assert_eq!(read_result.status, Status::Ok);
            assert_eq!(read_result.len, 32);
            assert_eq!(read_result.random_data[0..32], random_data);

            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

pub mod ecc_key {
    use crate::common;

    use super::*;

    // command id
    const ECC_KEY_GENERATE_CMD_ID: u8 = 0x60;
    // command length
    const ECC_KEY_GENERATE_CMD_LEN: usize = 4;

    // result length
    #[allow(unused)]
    const ECC_KEY_GENERATE_RES_LEN: usize = 1;

    pub struct EccKeyGenerateCmd {
        data: [u8; ECC_KEY_GENERATE_CMD_LEN],
    }

    impl EccKeyGenerateCmd {
        pub fn create(ecc_key_slot: common::ecc::EccKeySlot, curve: common::ecc::EccCurve) -> Self {
            let mut data = [0_u8; ECC_KEY_GENERATE_CMD_LEN];
            data[0] = ECC_KEY_GENERATE_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot));
            data[3] = curve as u8;
            Self { data }
        }
    }

    impl PlaintextCmd<ECC_KEY_GENERATE_CMD_LEN> for EccKeyGenerateCmd {
        fn size(&self) -> u16 {
            ECC_KEY_GENERATE_CMD_LEN as u16
        }

        fn data(self) -> [u8; ECC_KEY_GENERATE_CMD_LEN] {
            self.data
        }
    }

    pub type EccKeyGenerateResp = StatusResp;

    // command id
    const ECC_KEY_STORE_CMD_ID: u8 = 0x61;
    // command length CMD_ID[1] KEY_SLOT[2] CURVE[1] PADDING[12] PUBKEY[32]
    const ECC_KEY_STORE_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN + 1 + 12 + CMD_SECRET_KEY_LEN; //48;

    // result length
    #[allow(unused)]
    const ECC_KEY_STORE_RES_LEN: usize = 1;

    pub struct EccKeyStoreCmd {
        data: [u8; ECC_KEY_STORE_CMD_LEN],
    }

    impl EccKeyStoreCmd {
        pub fn create(
            ecc_key_slot: common::ecc::EccKeySlot,
            curve: common::ecc::EccCurve,
            secret_key: &[u8; CMD_SECRET_KEY_LEN],
        ) -> Self {
            let mut data = [0_u8; ECC_KEY_STORE_CMD_LEN];
            data[0] = ECC_KEY_STORE_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot));
            data[3] = curve as u8;
            // padding
            data[4..16].copy_from_slice(&[0_u8; 12]);
            data[16..48].copy_from_slice(secret_key);
            Self { data }
        }
    }

    impl PlaintextCmd<ECC_KEY_STORE_CMD_LEN> for EccKeyStoreCmd {
        fn size(&self) -> u16 {
            ECC_KEY_STORE_CMD_LEN as u16
        }

        fn data(self) -> [u8; ECC_KEY_STORE_CMD_LEN] {
            self.data
        }
    }

    pub type EccKeyStoreResp = StatusResp;

    // command id
    const ECC_KEY_READ_CMD_ID: u8 = 0x62;
    // command length
    const ECC_KEY_READ_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN;

    // min result length for ed25519 pubkey STATUS[1] CURVE[1] ORIGIN[1] PADDING[13] PUBKEY[32]
    #[allow(unused)]
    const ECC_KEY_READ_RES_LEN_MIN: usize = RES_STATUS_LEN + 1 + 1 + 13 + (RES_PUBLIC_KEY_LEN / 2);

    // max result length for p256 pubkey STATUS[1] CURVE[1] ORIGIN[1] PADDING[13] PUBKEY[64]
    const ECC_KEY_READ_RES_LEN_MAX: usize = RES_STATUS_LEN + 1 + 1 + 13 + RES_PUBLIC_KEY_LEN;

    /// Command to read the public ECC Key from a slot of the ECC
    /// Keys partition in R-Memory.
    pub struct EccKeyReadCmd {
        data: [u8; ECC_KEY_READ_CMD_LEN],
    }

    impl EccKeyReadCmd {
        pub fn create(ecc_key_slot: common::ecc::EccKeySlot) -> Self {
            let mut data = [0_u8; ECC_KEY_READ_CMD_LEN];
            data[0] = ECC_KEY_READ_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot));
            Self { data }
        }
    }

    impl PlaintextCmd<ECC_KEY_READ_CMD_LEN> for EccKeyReadCmd {
        fn size(&self) -> u16 {
            ECC_KEY_READ_CMD_LEN as u16
        }

        fn data(self) -> [u8; ECC_KEY_READ_CMD_LEN] {
            self.data
        }
    }

    /// Response containing the public ECC Key from a slot of the ECC
    /// Keys partition in R-Memory.
    pub struct EccKeyReadResp {
        pub len: u16,
        pub status: Status,
        /// ECC curve type
        pub curve: common::ecc::EccCurve,
        /// Key origin
        pub origin: common::ecc::EccKeyOrigin,
        /// Public key
        /// - P256 (0x01): P256 Curve - 64-byte long public key.
        /// - ED25519 (0x02): Ed25519 Curve - 32-byte long public key.
        pub pubkey: [u8; RES_PUBLIC_KEY_LEN],
    }

    impl EccKeyReadResp {
        pub fn pubkey(&self) -> &[u8] {
            match self.curve {
                common::ecc::EccCurve::P256 => &self.pubkey,
                common::ecc::EccCurve::Ed25519 => &self.pubkey[0..(RES_PUBLIC_KEY_LEN / 2)],
            }
        }
    }

    impl TryFrom<Response<ECC_KEY_READ_RES_LEN_MAX>> for EccKeyReadResp {
        type Error = Error;

        fn try_from(resp: Response<ECC_KEY_READ_RES_LEN_MAX>) -> Result<Self, Self::Error> {
            Ok(Self {
                len: resp.len,
                status: resp.status,
                curve: resp.data[0].try_into()?,
                origin: resp.data[1].try_into()?,
                pubkey: resp.data[15..79].try_into().unwrap(),
            })
        }
    }

    impl sealed::Sealed for EccKeyReadResp {}

    impl ReceiveResponseL3<ECC_KEY_READ_RES_LEN_MAX> for EccKeyReadResp {}

    // command id
    const ECC_KEY_ERASE_CMD_ID: u8 = 0x63;
    // command length
    const ECC_KEY_ERASE_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN;

    // result length
    #[allow(unused)]
    const ECC_KEY_ERASE_RES_LEN: usize = 1;

    pub struct EccKeyEraseCmd {
        data: [u8; ECC_KEY_ERASE_CMD_LEN],
    }

    impl EccKeyEraseCmd {
        pub fn create(ecc_key_slot: common::ecc::EccKeySlot) -> Self {
            let mut data = [0_u8; ECC_KEY_ERASE_CMD_LEN];
            data[0] = ECC_KEY_ERASE_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot));
            Self { data }
        }
    }

    impl PlaintextCmd<ECC_KEY_ERASE_CMD_LEN> for EccKeyEraseCmd {
        fn size(&self) -> u16 {
            ECC_KEY_ERASE_CMD_LEN as u16
        }

        fn data(self) -> [u8; ECC_KEY_ERASE_CMD_LEN] {
            self.data
        }
    }

    pub type EccKeyEraseResp = StatusResp;

    #[cfg(test)]
    pub mod tests {
        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::l3;

        #[test]
        fn test_ecc_key_generate_ed25519() {
            let mut mocked_delay = CheckedDelay::new([]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[
                        ECC_KEY_GENERATE_CMD_ID,
                        1,
                        0,
                        common::ecc::EccCurve::Ed25519 as u8,
                    ],
                    &[Status::Ok as u8],
                );

            let ecc_key_slot = 1_u16.try_into().expect("failed to create ecc key slot");
            let curve = common::ecc::EccCurve::Ed25519;

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EccKeyGenerateCmd::create(ecc_key_slot, curve),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let generate_result = EccKeyGenerateResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            assert_eq!(generate_result.status, Status::Ok);
            assert_eq!(generate_result.len, ECC_KEY_GENERATE_RES_LEN as u16 - 1);

            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_ecc_key_generate_p256() {
            let mut mocked_delay = CheckedDelay::new([]);
            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[
                        ECC_KEY_GENERATE_CMD_ID,
                        31,
                        0,
                        common::ecc::EccCurve::P256 as u8,
                    ],
                    &[Status::Ok as u8],
                );
            let ecc_key_slot = 31_u16.try_into().expect("failed to create ecc key slot");
            let curve = common::ecc::EccCurve::P256;
            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EccKeyGenerateCmd::create(ecc_key_slot, curve),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let generate_result = EccKeyGenerateResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(generate_result.status, Status::Ok);
            assert_eq!(generate_result.len, ECC_KEY_GENERATE_RES_LEN as u16 - 1);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_ecc_key_store_ed25519() {
            let mut mocked_delay = CheckedDelay::new([]);
            let secret_key = [0x55_u8; CMD_SECRET_KEY_LEN];
            let padding = [0_u8; 12];
            let mut exp_req = [
                ECC_KEY_STORE_CMD_ID,
                2,
                0,
                common::ecc::EccCurve::Ed25519 as u8,
            ]
            .to_vec();
            exp_req.extend_from_slice(&padding);
            exp_req.extend_from_slice(&secret_key);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &exp_req,
                    &[Status::Ok as u8],
                );
            let ecc_key_slot = 2_u16.try_into().expect("failed to create ecc key slot");
            let curve = common::ecc::EccCurve::Ed25519;

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EccKeyStoreCmd::create(ecc_key_slot, curve, &secret_key),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let store_result = EccKeyStoreResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(store_result.status, Status::Ok);
            assert_eq!(store_result.len, ECC_KEY_STORE_RES_LEN as u16 - 1);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_ecc_key_store_p256() {
            let mut mocked_delay = CheckedDelay::new([]);
            let secret_key = [0xAA_u8; CMD_SECRET_KEY_LEN];
            let padding = [0_u8; 12];
            let mut exp_req = [
                ECC_KEY_STORE_CMD_ID,
                31,
                0,
                common::ecc::EccCurve::P256 as u8,
            ]
            .to_vec();
            exp_req.extend_from_slice(&padding);
            exp_req.extend_from_slice(&secret_key);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &exp_req,
                    &[Status::Ok as u8],
                );
            let ecc_key_slot = 31_u16.try_into().expect("failed to create ecc key slot");
            let curve = common::ecc::EccCurve::P256;

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EccKeyStoreCmd::create(ecc_key_slot, curve, &secret_key),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let store_result = EccKeyStoreResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(store_result.status, Status::Ok);
            assert_eq!(store_result.len, ECC_KEY_STORE_RES_LEN as u16 - 1);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_ecc_key_read_ed25519() {
            let mut mocked_delay = CheckedDelay::new([]);
            let pubkey = [0x55_u8; RES_PUBLIC_KEY_LEN / 2].to_vec();
            let mut resp_data = [
                Status::Ok as u8,
                common::ecc::EccCurve::Ed25519 as u8,
                common::ecc::EccKeyOrigin::Generated as u8,
            ]
            .to_vec();
            resp_data.extend_from_slice(&[0_u8; 13]);
            resp_data.extend_from_slice(&pubkey);
            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[ECC_KEY_READ_CMD_ID, 2, 0],
                    &resp_data,
                );
            let ecc_key_slot = 2_u16.try_into().expect("failed to create ecc key slot");
            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EccKeyReadCmd::create(ecc_key_slot),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let read_result = EccKeyReadResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");

            assert_eq!(read_result.status, Status::Ok);
            assert_eq!(read_result.len, resp_data.len() as u16 - 1);
            assert_eq!(read_result.curve, common::ecc::EccCurve::Ed25519);
            assert_eq!(read_result.origin, common::ecc::EccKeyOrigin::Generated);
            assert_eq!(read_result.pubkey[0..32], pubkey[..]);
            assert_eq!(read_result.pubkey[32..], [0_u8; 32]);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_ecc_key_read_p256() {
            let mut mocked_delay = CheckedDelay::new([]);
            let pubkey = [0xAA_u8; RES_PUBLIC_KEY_LEN].to_vec();
            let mut resp_data = [
                Status::Ok as u8,
                common::ecc::EccCurve::P256 as u8,
                common::ecc::EccKeyOrigin::Stored as u8,
            ]
            .to_vec();
            resp_data.extend_from_slice(&[0_u8; 13]);
            resp_data.extend_from_slice(&pubkey);
            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[ECC_KEY_READ_CMD_ID, 31, 0],
                    &resp_data,
                );
            let ecc_key_slot = 31_u16.try_into().expect("failed to create ecc key slot");
            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EccKeyReadCmd::create(ecc_key_slot),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let read_result = EccKeyReadResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(read_result.status, Status::Ok);
            assert_eq!(read_result.len, resp_data.len() as u16 - 1);
            assert_eq!(read_result.curve, common::ecc::EccCurve::P256);
            assert_eq!(read_result.origin, common::ecc::EccKeyOrigin::Stored);
            assert_eq!(read_result.pubkey[0..64], pubkey[..]);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_ecc_key_erase() {
            let mut mocked_delay = CheckedDelay::new([]);
            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[ECC_KEY_ERASE_CMD_ID, 2, 0],
                    &[Status::Ok as u8],
                );
            let ecc_key_slot = 2_u16.try_into().expect("failed to create ecc key slot");
            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EccKeyEraseCmd::create(ecc_key_slot),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let read_result = EccKeyEraseResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(read_result.status, Status::Ok);
            assert_eq!(read_result.len, ECC_KEY_ERASE_RES_LEN as u16 - 1);
            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

pub mod ecc_sign {
    use super::*;

    // command id
    const ECDSA_SIGN_CMD_ID: u8 = 0x70;
    // command length CMD_ID[1] KEY_SLOT[2] PADDING[13] DIGEST[32]
    const ECDSA_SIGN_CMD_LEN: usize = 48;

    // result length STATUS[1] PADDING[15] SIG_R[32] SIG_S[32]
    const ECDSA_SIGN_RES_LEN: usize = 80;

    pub struct EcdsaSignCmd {
        data: [u8; ECDSA_SIGN_CMD_LEN],
    }

    impl EcdsaSignCmd {
        pub fn create(ecc_key_slot: common::ecc::EccKeySlot, digest: &[u8; 32]) -> Self {
            let mut data = [0_u8; ECDSA_SIGN_CMD_LEN];
            data[0] = ECDSA_SIGN_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot));
            // padding
            data[3..16].copy_from_slice(&[0_u8; 13]);
            data[16..48].copy_from_slice(digest);
            Self { data }
        }
    }

    impl PlaintextCmd<ECDSA_SIGN_CMD_LEN> for EcdsaSignCmd {
        fn size(&self) -> u16 {
            ECDSA_SIGN_CMD_LEN as u16
        }

        fn data(self) -> [u8; ECDSA_SIGN_CMD_LEN] {
            self.data
        }
    }

    pub struct EcdsaSignResp {
        pub len: u16,
        pub status: Status,

        pub sig_r: [u8; 32],
        pub sig_s: [u8; 32],
    }

    impl EcdsaSignResp {
        /// Returns the signature as a fixed-size array of 64 bytes in the order R || S
        /// where R is the first 32 bytes and S is the last 32 bytes.
        pub fn signature(&self) -> [u8; 64] {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&self.sig_r);
            sig[32..].copy_from_slice(&self.sig_s);
            sig
        }
    }

    impl From<Response<ECDSA_SIGN_RES_LEN>> for EcdsaSignResp {
        fn from(resp: Response<ECDSA_SIGN_RES_LEN>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
                sig_r: resp.data[15..47].try_into().unwrap(),
                sig_s: resp.data[47..79].try_into().unwrap(),
            }
        }
    }

    impl sealed::Sealed for EcdsaSignResp {}

    impl ReceiveResponseL3<ECDSA_SIGN_RES_LEN> for EcdsaSignResp {}

    // command id
    const EDDSA_SIGN_CMD_ID: u8 = 0x71;
    // command length CMD_ID[1] KEY_SLOT[2] PADDING[13] MSG[1..4096]
    // TODO: verify if msg can be empty
    #[allow(unused)]
    const EDDSA_SIGN_CMD_SIZE_MIN: usize = 17;
    // maximal length of field msg
    const EDDSA_SIGN_CMD_MSG_LEN_MAX: usize = 4096;

    // command length CMD_ID[1] KEY_SLOT[2] PADDING[13] MSG[1..4096]
    const EDDSA_SIGN_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN + 13 + EDDSA_SIGN_CMD_MSG_LEN_MAX;

    // result length STATUS[1] PADDING[15] SIG_R[32] SIG_S[32]
    #[allow(unused)]
    const EDDSA_SIGN_RES_SIZE: usize = 80;

    pub struct EddsaSignCmd<const MSG_LEN: usize> {
        size: u16,
        data: [u8; EDDSA_SIGN_CMD_LEN],
    }

    impl EddsaSignCmd<0> {
        pub fn create(ecc_key_slot: common::ecc::EccKeySlot, digest: &[u8]) -> Result<Self, Error> {
            let digest_len = digest.len();
            if digest_len == 0 || digest_len > EDDSA_SIGN_CMD_MSG_LEN_MAX {
                return Err(Error::DigestSize);
            }
            let mut data = [0_u8; EDDSA_SIGN_CMD_LEN];
            data[0] = EDDSA_SIGN_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot));
            // padding
            data[3..16].copy_from_slice(&[0_u8; 13]);
            data[16..16 + digest_len].copy_from_slice(digest);
            let size = (CMD_ID_LEN + CMD_SLOT_LEN + 13 + digest_len) as u16;
            Ok(Self { size, data })
        }
    }

    impl PlaintextCmd<EDDSA_SIGN_CMD_LEN> for EddsaSignCmd<0> {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; EDDSA_SIGN_CMD_LEN] {
            self.data
        }
    }

    pub type EddsaSignResp = EcdsaSignResp;

    #[cfg(test)]
    pub mod tests {
        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::l3;

        #[test]
        fn test_ecdsa_sign() {
            let mut mocked_delay = CheckedDelay::new([]);

            let ecc_key_slot = common::ecc::EccKeySlot::random();
            let digest = [0x55_u8; 32];

            let mut exp_req = [ECDSA_SIGN_CMD_ID].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot.clone()));
            // padding
            exp_req.extend_from_slice(&[0_u8; 13]);
            exp_req.extend_from_slice(&digest);

            let mut resp_data = [Status::Ok as u8].to_vec();
            // padding
            resp_data.extend_from_slice(&[0_u8; 15]);
            resp_data.extend_from_slice(&[0xAA_u8; 64]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(&exp_req, &resp_data);

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EcdsaSignCmd::create(ecc_key_slot, &digest),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let sign_result = EcdsaSignResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(sign_result.status, Status::Ok);
            assert_eq!(sign_result.len, ECDSA_SIGN_RES_LEN as u16 - 1);
            assert_eq!(sign_result.sig_r, [0xAA_u8; 32]);
            assert_eq!(sign_result.sig_s, [0xAA_u8; 32]);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_eddsa_sign() {
            let mut mocked_delay = CheckedDelay::new([]);

            let ecc_key_slot = common::ecc::EccKeySlot::random();
            let digest = [0x55_u8; 100];

            let mut exp_req = [EDDSA_SIGN_CMD_ID].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot.clone()));
            // padding
            exp_req.extend_from_slice(&[0_u8; 13]);
            exp_req.extend_from_slice(&digest);

            let mut resp_data = [Status::Ok as u8].to_vec();
            // padding
            resp_data.extend_from_slice(&[0_u8; 15]);
            resp_data.extend_from_slice(&[0xAA_u8; 64]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(&exp_req, &resp_data);
            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                EddsaSignCmd::create(ecc_key_slot, &digest).expect("failed to create cmd"),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let sign_result = EddsaSignResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(sign_result.status, Status::Ok);
            assert_eq!(sign_result.len, ECDSA_SIGN_RES_LEN as u16 - 1);
            assert_eq!(sign_result.sig_r, [0xAA_u8; 32]);
            assert_eq!(sign_result.sig_s, [0xAA_u8; 32]);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        // TODO: add variant that can use l2 cmd chunks
        // #[test]
        // fn test_eddsa_sign_max() {
        //     let mut mocked_delay = CheckedDelay::new([]);

        //     let ecc_key_slot = common::ecc::EccKeySlot::random();
        //     let digest = [0x55_u8; EDDSA_SIGN_CMD_MSG_LEN_MAX];
        //     let mut exp_req = [EDDSA_SIGN_CMD_ID].to_vec();
        //     exp_req.extend_from_slice(&Into::<[u8; 2]>::into(ecc_key_slot.clone()));
        //     // padding
        //     exp_req.extend_from_slice(&[0_u8; 13]);
        //     exp_req.extend_from_slice(&digest);

        //     let mut resp_data = [Status::Ok as u8].to_vec();
        //     // padding
        //     resp_data.extend_from_slice(&[0_u8; 15]);
        //     resp_data.extend_from_slice(&[0xAA_u8; 64]);

        //     let (mut mocked_spi_device, mut mocked_session) =
        //         super::super::tests::get_mocked_spi_device_and_session(&exp_req, &resp_data);
        //     let ecc_key_slot = 1_u16.try_into().expect("failed to create ecc key slot");
        //     l3::send(
        //         &mut mocked_spi_device,
        //         &mut mocked_delay,
        //         EddsaSignCmd::create(ecc_key_slot, &digest).expect("failed to create cmd"),
        //         &mut mocked_session,
        //     )
        //     .expect("failed to send command");

        //     let sign_result = EddsaSignResp::receive_l3(
        //         &mut mocked_spi_device,
        //         &mut mocked_delay,
        //         &mut mocked_session,
        //     )
        //     .expect("failed to parse result");
        //     assert_eq!(sign_result.status, Status::Ok);
        //     assert_eq!(sign_result.len, ECDSA_SIGN_RES_LEN as u16 - 1);
        //     assert_eq!(sign_result.sig_r, [0xAA_u8; 32]);
        //     assert_eq!(sign_result.sig_s, [0xAA_u8; 32]);
        //     mocked_delay.done();
        //     mocked_spi_device.done();
        // }
    }
}

pub mod mcounter {
    use super::*;

    // command id
    const MCOUNTER_INIT_CMD_ID: u8 = 0x80;
    // command length CMD_ID[1] MCOUNTER_INDEX[2] PADDING[1] VALUE[4]
    const MCOUNTER_INIT_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN + 1 + 4;

    // result length STATUS[1]
    #[allow(unused)]
    const MCOUNTER_INIT_RES_LEN: usize = RES_STATUS_LEN;

    pub struct MCounterInitCmd {
        data: [u8; MCOUNTER_INIT_CMD_LEN],
    }

    impl MCounterInitCmd {
        pub fn create(index: common::MCounterIndex, value: u32) -> Self {
            let mut data = [0_u8; MCOUNTER_INIT_CMD_LEN];
            data[0] = MCOUNTER_INIT_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(index));
            // padding
            data[3] = 0;
            data[4..8].copy_from_slice(&value.to_le_bytes());
            Self { data }
        }
    }

    impl PlaintextCmd<MCOUNTER_INIT_CMD_LEN> for MCounterInitCmd {
        fn size(&self) -> u16 {
            MCOUNTER_INIT_CMD_LEN as u16
        }

        fn data(self) -> [u8; MCOUNTER_INIT_CMD_LEN] {
            self.data
        }
    }

    pub type MCounterInitResp = StatusResp;

    // command id
    const MCOUNTER_UPDATE_CMD_ID: u8 = 0x81;
    // command length CMD_ID[1] MCOUNTER_INDEX[2]
    const MCOUNTER_UPDATE_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN;

    // result length STATUS[1]
    #[allow(unused)]
    const MCOUNTER_UPDATE_RES_LEN: usize = RES_STATUS_LEN;

    pub struct MCounterUpdateCmd {
        data: [u8; MCOUNTER_UPDATE_CMD_LEN],
    }

    impl MCounterUpdateCmd {
        pub fn create(index: common::MCounterIndex) -> Self {
            let mut data = [0_u8; MCOUNTER_UPDATE_CMD_LEN];
            data[0] = MCOUNTER_UPDATE_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(index));
            Self { data }
        }
    }

    impl PlaintextCmd<MCOUNTER_UPDATE_CMD_LEN> for MCounterUpdateCmd {
        fn size(&self) -> u16 {
            MCOUNTER_UPDATE_CMD_LEN as u16
        }

        fn data(self) -> [u8; MCOUNTER_UPDATE_CMD_LEN] {
            self.data
        }
    }

    pub type MCounterUpdateResp = StatusResp;

    const MCOUNTER_GET_CMD_ID: u8 = 0x82;
    // command length CMD_ID[1] MCOUNTER_INDEX[2]
    const MCOUNTER_GET_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN;

    // result length STATUS[1] PADDING[3] MCOUNTER[4]
    const MCOUNTER_GET_RES_LEN: usize = RES_STATUS_LEN + 3 + 4;

    pub struct MCounterGetCmd {
        data: [u8; MCOUNTER_GET_CMD_LEN],
    }

    impl MCounterGetCmd {
        pub fn create(index: common::MCounterIndex) -> Self {
            let mut data = [0_u8; MCOUNTER_GET_CMD_LEN];
            data[0] = MCOUNTER_GET_CMD_ID;
            data[1..3].copy_from_slice(&Into::<[u8; 2]>::into(index));
            Self { data }
        }
    }

    impl PlaintextCmd<MCOUNTER_GET_CMD_LEN> for MCounterGetCmd {
        fn size(&self) -> u16 {
            MCOUNTER_GET_CMD_LEN as u16
        }

        fn data(self) -> [u8; MCOUNTER_GET_CMD_LEN] {
            self.data
        }
    }

    pub struct MCounterGetResp {
        pub len: u16,
        pub status: Status,
        pub mcounter: u32,
    }

    impl From<Response<MCOUNTER_GET_RES_LEN>> for MCounterGetResp {
        fn from(resp: Response<MCOUNTER_GET_RES_LEN>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
                mcounter: u32::from_le_bytes(resp.data[3..7].try_into().unwrap()),
            }
        }
    }

    impl sealed::Sealed for MCounterGetResp {}

    impl ReceiveResponseL3<MCOUNTER_GET_RES_LEN> for MCounterGetResp {}

    #[cfg(test)]
    pub mod tests {
        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::l3;

        #[test]
        fn test_mcounter_init() {
            let mut mocked_delay = CheckedDelay::new([]);

            let mcounter_index = common::MCounterIndex::random();
            let value = 42_u32;

            let mut exp_req = [MCOUNTER_INIT_CMD_ID].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(mcounter_index.clone()));
            // padding
            exp_req.push(0);
            exp_req.extend_from_slice(&value.to_le_bytes());

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &exp_req,
                    &[Status::Ok as u8],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                MCounterInitCmd::create(mcounter_index, value),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let init_result = MCounterInitResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(init_result.status, Status::Ok);
            assert_eq!(init_result.len, MCOUNTER_INIT_RES_LEN as u16 - 1);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_mcounter_update() {
            let mut mocked_delay = CheckedDelay::new([]);

            let mcounter_index = common::MCounterIndex::random();
            let mut exp_req = [MCOUNTER_UPDATE_CMD_ID].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(mcounter_index.clone()));
            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &exp_req,
                    &[Status::Ok as u8],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                MCounterUpdateCmd::create(mcounter_index),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let update_result = MCounterUpdateResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(update_result.status, Status::Ok);
            assert_eq!(update_result.len, MCOUNTER_UPDATE_RES_LEN as u16 - 1);
            mocked_delay.done();
            mocked_spi_device.done();
        }

        #[test]
        fn test_mcounter_get() {
            let mut mocked_delay = CheckedDelay::new([]);

            let mcounter_index = common::MCounterIndex::random();
            let mcounter_value = 42_u32;

            let mut exp_req = [MCOUNTER_GET_CMD_ID].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(mcounter_index.clone()));
            let mut resp_data = [Status::Ok as u8].to_vec();
            // padding
            resp_data.extend_from_slice(&[0_u8; 3]);
            resp_data.extend_from_slice(&mcounter_value.to_le_bytes());

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(&exp_req, &resp_data);

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                MCounterGetCmd::create(mcounter_index),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let get_result = MCounterGetResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(get_result.status, Status::Ok);
            assert_eq!(get_result.len, MCOUNTER_GET_RES_LEN as u16 - 1);
            assert_eq!(get_result.mcounter, mcounter_value);
            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

pub mod mac_and_destroy {
    use super::*;

    // command id
    const MAC_AND_DESTROY_CMD_ID: usize = 0x90;
    // command length CMD_ID[1] KEY_SLOT[2] PADDING[1] DATA[32]
    const MAC_AND_DESTROY_CMD_LEN: usize = CMD_ID_LEN + CMD_SLOT_LEN + 1 + 32;

    // result length STATUS[1] PADDING[3] DATA[32]
    const MAC_AND_DESTROY_RES_LEN: usize = RES_STATUS_LEN + 3 + 32;

    pub struct MacAndDestroyCmd {
        data: [u8; MAC_AND_DESTROY_CMD_LEN],
    }

    impl MacAndDestroyCmd {
        pub fn create(
            mac_and_destroy_slot: &common::MacAndDestroySlot,
            data_in: &[u8; 32],
        ) -> Self {
            let mut data_arr = [0_u8; MAC_AND_DESTROY_CMD_LEN];
            data_arr[0] = MAC_AND_DESTROY_CMD_ID as u8;
            data_arr[1..3].copy_from_slice(&Into::<[u8; 2]>::into(mac_and_destroy_slot));
            // padding
            data_arr[3] = 0;
            data_arr[4..36].copy_from_slice(data_in);
            Self { data: data_arr }
        }
    }

    impl PlaintextCmd<MAC_AND_DESTROY_CMD_LEN> for MacAndDestroyCmd {
        fn size(&self) -> u16 {
            MAC_AND_DESTROY_CMD_LEN as u16
        }

        fn data(self) -> [u8; MAC_AND_DESTROY_CMD_LEN] {
            self.data
        }
    }

    pub struct MacAndDestroyResp {
        pub len: u16,
        pub status: Status,

        pub data_out: [u8; 32],
    }

    impl From<Response<MAC_AND_DESTROY_RES_LEN>> for MacAndDestroyResp {
        fn from(resp: Response<MAC_AND_DESTROY_RES_LEN>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
                data_out: resp.data[3..35].try_into().unwrap(),
            }
        }
    }

    impl sealed::Sealed for MacAndDestroyResp {}

    impl ReceiveResponseL3<MAC_AND_DESTROY_RES_LEN> for MacAndDestroyResp {}

    #[cfg(test)]
    pub mod tests {
        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::l3;

        #[test]
        fn test_mac_and_destroy() {
            let mut mocked_delay = CheckedDelay::new([]);

            let mac_and_destroy_slot = common::MacAndDestroySlot::random();
            let data_in = [0x55_u8; 32];

            let mut exp_req = [MAC_AND_DESTROY_CMD_ID as u8].to_vec();
            exp_req.extend_from_slice(&Into::<[u8; 2]>::into(&mac_and_destroy_slot));
            // padding
            exp_req.push(0);
            exp_req.extend_from_slice(&data_in);

            let mut resp_data = [Status::Ok as u8].to_vec();
            // padding
            resp_data.extend_from_slice(&[0_u8; 3]);
            resp_data.extend_from_slice(&[0xAA_u8; 32]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(&exp_req, &resp_data);

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                MacAndDestroyCmd::create(&mac_and_destroy_slot, &data_in),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let mac_result = MacAndDestroyResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(mac_result.status, Status::Ok);
            assert_eq!(mac_result.len, MAC_AND_DESTROY_RES_LEN as u16 - 1);
            assert_eq!(mac_result.data_out, [0xAA_u8; 32]);
            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

pub mod serial_code {
    use super::*;

    // command id
    const GET_SERIAL_CMD_ID: u8 = 0xA0;
    // command length CMD_ID[1]
    const GET_SERIAL_CMD_LEN: usize = CMD_ID_LEN;

    // result length STATUS[1] PADDING[3] SERIAL[32]
    const GET_SERIAL_RES_LEN: usize = RES_STATUS_LEN + 3 + 32;

    pub struct GetSerialCodeCmd {
        data: [u8; GET_SERIAL_CMD_LEN],
    }

    impl GetSerialCodeCmd {
        pub fn create() -> Self {
            let mut data = [0_u8; GET_SERIAL_CMD_LEN];
            data[0] = GET_SERIAL_CMD_ID;
            Self { data }
        }
    }

    impl PlaintextCmd<GET_SERIAL_CMD_LEN> for GetSerialCodeCmd {
        fn size(&self) -> u16 {
            GET_SERIAL_CMD_LEN as u16
        }

        fn data(self) -> [u8; GET_SERIAL_CMD_LEN] {
            self.data
        }
    }

    pub struct GetSerialCodeResp {
        pub len: u16,
        pub status: Status,
        pub serial_code: [u8; 32],
    }

    impl From<Response<GET_SERIAL_RES_LEN>> for GetSerialCodeResp {
        fn from(resp: Response<GET_SERIAL_RES_LEN>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
                serial_code: resp.data[3..35].try_into().unwrap(),
            }
        }
    }

    impl sealed::Sealed for GetSerialCodeResp {}

    impl ReceiveResponseL3<GET_SERIAL_RES_LEN> for GetSerialCodeResp {}

    #[cfg(test)]
    pub mod tests {
        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::l3;

        #[test]
        fn test_get_serial() {
            let mut mocked_delay = CheckedDelay::new([]);

            let exp_req = [GET_SERIAL_CMD_ID].to_vec();

            let mut resp_data = [Status::Ok as u8].to_vec();
            // padding
            resp_data.extend_from_slice(&[0_u8; 3]);
            resp_data.extend_from_slice(&[0xAA_u8; 32]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(&exp_req, &resp_data);

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                GetSerialCodeCmd::create(),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let serial_result = GetSerialCodeResp::receive_l3(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to parse result");
            assert_eq!(serial_result.status, Status::Ok);
            assert_eq!(serial_result.len, GET_SERIAL_RES_LEN as u16 - 1);
            assert_eq!(serial_result.serial_code, [0xAA_u8; 32]);
            mocked_delay.done();
            mocked_spi_device.done();
        }
    }
}

#[cfg(test)]
pub mod tests {

    extern crate alloc;

    use embedded_hal_mock::{
        common::Generic,
        eh1::spi::{Mock as SpiMock, Transaction as SpiMockTransaction},
    };

    use crate::crc16;

    use super::*;

    const SESSION_ENC_TAG: [u8; 16] = [0x11; 16];
    const SESSION_DEC_TAG: [u8; 16] = [0x22; 16];

    pub(crate) fn send_resp_ok() -> [embedded_hal_mock::eh1::spi::Transaction<u8>; 7] {
        let mut request_resp_crc = 902u16.to_be_bytes().to_vec();
        request_resp_crc
            .extend_from_slice(&core::iter::repeat_n(0, 255).collect::<alloc::vec::Vec<u8>>());

        [
            SpiMockTransaction::transaction_start(),
            // chip_status
            SpiMockTransaction::transfer([l1::GET_RESPONSE_REQ_ID].to_vec(), [0x01].to_vec()),
            // l2 status
            SpiMockTransaction::transfer_in_place(
                [0].to_vec(),
                [l2::Status::RequestOk as u8].to_vec(),
            ),
            // len
            SpiMockTransaction::transfer_in_place([0].to_vec(), [0].to_vec()),
            // data[0] crc[2]
            SpiMockTransaction::transfer_in_place([0u8; 257].to_vec(), request_resp_crc),
            // crc as read from l1::receive
            SpiMockTransaction::transfer_in_place([0u8; 2].to_vec(), [0u8; 2].to_vec()),
            SpiMockTransaction::transaction_end(),
        ]
    }

    pub(crate) fn expected_spi_request_and_response(
        exp_l3_payload: &[u8],
        resp_data: &[u8],
    ) -> alloc::vec::Vec<embedded_hal_mock::eh1::spi::Transaction<u8>> {
        let l3_cmd_len = exp_l3_payload.len() as u16;
        let mut exp_l2_req = [4].to_vec();
        exp_l2_req.push((exp_l3_payload.len() + CMD_SIZE_LEN + TAG_LEN) as u8);
        exp_l2_req.extend_from_slice(&l3_cmd_len.to_le_bytes());
        exp_l2_req.extend_from_slice(&exp_l3_payload);
        exp_l2_req.extend_from_slice(&SESSION_ENC_TAG);
        exp_l2_req.extend_from_slice(&[0, 0]);
        crc16::add_crc(&mut exp_l2_req).expect("failed to add crc to request");

        let mut exp_spi_transaction = [
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::write_vec(exp_l2_req),
            SpiMockTransaction::transaction_end(),
        ]
        .to_vec();
        exp_spi_transaction.extend_from_slice(&send_resp_ok());

        let resp_l3_len = resp_data.len();
        let resp_l2_len = RES_SIZE_LEN + resp_l3_len + TAG_LEN;

        let mut respons = [
            0x01, // chip_status ready
            l2::Status::ResultOk as u8,
            resp_l2_len as u8,
        ]
        .to_vec();
        respons.extend_from_slice(&(resp_l3_len as u16).to_le_bytes());
        respons.extend_from_slice(resp_data);
        respons.extend_from_slice(&SESSION_DEC_TAG);
        respons.extend_from_slice(
            &crc16::crc16(
                &respons[3..resp_l2_len + 3],
                Some(&[l2::Status::ResultOk as u8, resp_l2_len as u8]),
            )
            .to_be_bytes(),
        );

        let vec_of_zeros: alloc::vec::Vec<u8> =
            core::iter::repeat_n(0, 255 + 3 - respons.len()).collect();
        respons.extend_from_slice(&vec_of_zeros);

        exp_spi_transaction.extend_from_slice(
            [
                SpiMockTransaction::transaction_start(),
                SpiMockTransaction::transfer(
                    [l1::GET_RESPONSE_REQ_ID].to_vec(),
                    [respons[0]].to_vec(),
                ),
                SpiMockTransaction::transfer_in_place([0].to_vec(), [respons[1]].to_vec()),
                SpiMockTransaction::transfer_in_place([0].to_vec(), [respons[2]].to_vec()),
                SpiMockTransaction::transfer_in_place(
                    [0u8; 255].to_vec(),
                    respons[3..258].to_vec(),
                ),
                SpiMockTransaction::transfer_in_place([0u8; 2].to_vec(), [0u8; 2].to_vec()),
                SpiMockTransaction::transaction_end(),
            ]
            .as_slice(),
        );

        exp_spi_transaction
    }

    pub(crate) fn get_mocked_spi_device_and_session(
        exp_l3_payload: &[u8],
        resp_data: &[u8],
    ) -> (
        Generic<embedded_hal_mock::eh1::spi::Transaction<u8>>,
        session::mock::MockSession,
    ) {
        let exp_spi_transaction = expected_spi_request_and_response(exp_l3_payload, resp_data);

        let mocked_spi_device = SpiMock::new(&exp_spi_transaction);
        let mocked_session = session::mock::MockSession {
            enc_tag: SESSION_ENC_TAG,
            dec_tag: SESSION_DEC_TAG,
        };
        (mocked_spi_device, mocked_session)
    }
}

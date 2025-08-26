use embedded_hal::spi::Error as _;

#[cfg(debug_assertions)]
pub mod keys;

pub mod session;

pub use session::{EncSession, Session};

use crate::{l1, l2};

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
const CMD_DATA_SIZE_MAX: usize = 4097;
// Maximum size of l3 ciphertext (or decrypted l3 packet)
pub(crate) const PACKET_MAX_LEN: usize = CMD_ID_LEN + CMD_DATA_SIZE_MAX;

// Max size of one unit of transport on l3 layer
pub(crate) const FRAME_MAX_LEN: usize = RES_SIZE_LEN + PACKET_MAX_LEN + TAG_LEN;

#[derive(Debug)]
pub enum Error {
    L2(l2::Error),
    PLaintextCmdSize,
    Session(session::Error),
    InvalidStatus(u8),
    MaxPingMsgSize,
    MaxFrameSize,
    ReadConfigBytes,
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::L2(err) => f.write_fmt(format_args!("l2 error: {}", err)),
            Self::PLaintextCmdSize => f.write_str("plaintext command size too big"),
            Self::Session(err) => f.write_fmt(format_args!("session error: {}", err)),
            Self::InvalidStatus(status) => {
                f.write_fmt(format_args!("l2: invalid status: {}", status))
            }
            Self::MaxPingMsgSize => f.write_str("ping message size too big"),
            Self::MaxFrameSize => f.write_str("requested frame size too big"),
            Self::ReadConfigBytes => f.write_str("failed to read config bytes"),
        }
    }
}

impl From<l2::Error> for Error {
    fn from(err: l2::Error) -> Self {
        Self::L2(err)
    }
}

impl From<session::Error> for Error {
    fn from(err: session::Error) -> Self {
        Self::Session(err)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    /** Return values based on RESULT field */
    /*  API r_mem_data_write: */
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
    l2::enc_cmd::receive(spi_device, delay, &mut buf)?;

    // len = 1 byte status + data
    let len = u16::from_le_bytes(buf[..RES_SIZE_LEN].try_into().unwrap());

    let mut data = [0_u8; N];
    let data_seek = RES_SIZE_LEN + len as usize;
    data[..len as usize].copy_from_slice(&buf[RES_SIZE_LEN..data_seek]);

    let mut tag = [0_u8; TAG_LEN];
    tag.copy_from_slice(&buf[data_seek..data_seek + TAG_LEN]);

    session.decrypt_response(&mut data[..len as usize], &tag)?;
    let status = data[0].try_into()?;

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
    let enc_cmd_chunks = l2::enc_cmd::EncryptedCmdReq::create(&enc_cmd)?;

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
        } else {
            if resp.status != l2::Status::RequestCont {
                return Err(Error::L2(l2::Error::RespErr(resp.status)));
            }
        }
    }
    Ok(())
}

pub mod ping {
    use super::*;

    // command id
    const PING_CMD_ID: u8 = 0x01;

    // minimal length of field data_in
    const PING_CMD_DATA_LEN_MIN: usize = 0;

    // maximal length of field data_in
    const PING_CMD_DATA_LEN_MAX: usize = 4096;

    // command len CMD_ID[1] MSG[0-4096]
    const PING_CMD_DATE_LEN: usize = CMD_ID_LEN + PING_CMD_DATA_LEN_MAX;

    // result length STATUS[1]
    const PING_RES_LEN_MIN: usize = 1;

    // result length STATUS[1]  MSG[0-4096]
    const PING_RES_LEN: usize = RES_STATUS_LEN + PING_LEN_MAX;

    pub(crate) const PING_LEN_MAX: usize = CMD_DATA_SIZE_MAX - CMD_ID_LEN;

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

    impl PlaintextCmd<{ PING_CMD_DATE_LEN }> for PingCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; PING_CMD_DATE_LEN] {
            self.data
        }
    }

    pub struct PingResp {
        len: u16,
        status: Status,
        msg: [u8; PING_LEN_MAX],
    }

    impl PingResp {
        pub fn msg(&self) -> &[u8] {
            &self.msg[..self.len as usize]
        }
    }

    impl From<Response<PING_LEN_MAX>> for PingResp {
        fn from(resp: Response<PING_LEN_MAX>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
                msg: resp.data,
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
                    &[4, 23, 5, 0, PING_CMD_ID, b'p', b'i', b'n', b'g'],
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

            let write_result: PingResp = result.try_into().expect("failed to parse result");

            assert_eq!(write_result.status, Status::Ok);
            assert_eq!(write_result.len, 5 as u16 - 1);
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
    const PAIRING_KEY_WRITE_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN + 33;

    // result length STATUS[1]
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

    impl PlaintextCmd<{ PAIRING_KEY_WRITE_CMD_LEN }> for PairingKeyWriteCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; PAIRING_KEY_WRITE_CMD_LEN] {
            self.data
        }
    }

    pub struct PairingKeyWriteResp {
        len: u16,
        status: Status,
    }

    impl From<Response<PAIRING_KEY_WRITE_RESP_LEN>> for PairingKeyWriteResp {
        fn from(resp: Response<PAIRING_KEY_WRITE_RESP_LEN>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
            }
        }
    }

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

    impl PlaintextCmd<{ PAIRING_KEY_READ_CMD_LEN }> for PairingKeyReadCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; PAIRING_KEY_READ_CMD_LEN] {
            self.data
        }
    }

    pub struct PairingKeyReadResp {
        len: u16,
        status: Status,
        padding: [u8; 3],
        s_hipub: [u8; 32],
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

    impl PlaintextCmd<{ PAIRING_KEY_INVALIDATE_CMD_LEN }> for PairingKeyInvalidateCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; PAIRING_KEY_INVALIDATE_CMD_LEN] {
            self.data
        }
    }

    pub struct PairingKeyInvalidateResp {
        len: u16,
        status: Status,
    }

    impl From<Response<PAIRING_KEY_INVALIDATE_RES_LEN>> for PairingKeyInvalidateResp {
        fn from(resp: Response<PAIRING_KEY_INVALIDATE_RES_LEN>) -> Self {
            Self {
                len: resp.len,
                status: resp.status,
            }
        }
    }

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
            let mut exp_req = [
                4,
                54,
                PAIRING_KEY_WRITE_CMD_LEN as u8,
                0,
                PAIRING_KEY_WRITE_CMD_ID,
                1,
                0,
                0,
            ]
            .to_vec();
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

            let write_result: PairingKeyWriteResp =
                result.try_into().expect("failed to parse result");

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
                    &[
                        4,
                        21,
                        PAIRING_KEY_READ_CMD_LEN as u8,
                        0,
                        PAIRING_KEY_READ_CMD_ID,
                        1,
                        0,
                    ],
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

            let read_result: PairingKeyReadResp =
                result.try_into().expect("failed to parse result");

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
                    &[
                        4,
                        21,
                        PAIRING_KEY_INVALIDATE_CMD_LEN as u8,
                        0,
                        PAIRING_KEY_INVALIDATE_CMD_ID,
                        2,
                        0,
                    ],
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

            let invalidate_result: PairingKeyInvalidateResp =
                result.try_into().expect("failed to parse result");

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

    use bitflag_attr::Flags;

    use crate::common::config::RegisterAddr;

    use super::*;

    // command id
    const R_CONFIG_WRITE_CMD_ID: u8 = 0x20;
    // command length CMD_ID[1] REG_ADDR[2] PADDING[1] VALUE[4]
    const R_CONFIG_WRITE_CMD_LEN: usize = CMD_ID_LEN + CMD_SIZE_LEN + 5;

    // result length STATUS[1]
    const R_CONFIG_WRITE_RES_LEN: usize = RES_STATUS_LEN;

    pub struct ConfigWriteCmd {
        size: u16,
        data: [u8; R_CONFIG_WRITE_CMD_LEN],
    }

    impl ConfigWriteCmd {
        pub fn create<R: RegisterAddr>(addr: R, value: R::Item) -> Self {
            let mut data = [0_u8; R_CONFIG_WRITE_CMD_LEN];
            let addr = addr.to_register_addr();
            data[0] = R_CONFIG_WRITE_CMD_ID;
            data[1] = addr[0];
            data[2] = addr[1];
            // padding
            data[3] = 0x00;
            data[4..8].copy_from_slice(&value.bits().to_le_bytes());
            let size = (R_CONFIG_WRITE_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<{ R_CONFIG_WRITE_CMD_LEN }> for ConfigWriteCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; R_CONFIG_WRITE_CMD_LEN] {
            self.data
        }
    }

    pub struct ConfigWriteResp {
        len: u16,
        status: Status,
    }

    impl TryFrom<Response<R_CONFIG_WRITE_RES_LEN>> for ConfigWriteResp {
        type Error = Error;

        fn try_from(resp: Response<R_CONFIG_WRITE_RES_LEN>) -> Result<Self, Self::Error> {
            Ok(Self {
                len: resp.len,
                status: resp.status,
            })
        }
    }

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
        pub fn create<R: RegisterAddr>(addr: R) -> Self {
            let mut data = [0_u8; R_CONFIG_READ_CMD_LEN];
            let addr = addr.to_register_addr();
            data[0] = R_CONFIG_READ_CMD_ID;
            data[1] = addr[0];
            data[2] = addr[1];
            let size = (R_CONFIG_READ_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<{ R_CONFIG_READ_CMD_LEN }> for ConfigReadCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; R_CONFIG_READ_CMD_LEN] {
            self.data
        }
    }

    pub struct ConfigReadResp<T: Flags<Bits = u32>> {
        len: u16,
        status: Status,
        padding: [u8; 3],
        value: T,
    }

    #[cfg(feature = "display")]
    impl<T> core::fmt::Display for ConfigReadResp<T>
    where
        T: Flags<Bits = u32> + core::fmt::Display,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_fmt(format_args!(
                "status: {:?}, padding: {:?}, value: {}",
                self.status, self.padding, self.value
            ))
        }
    }

    impl<T: Flags<Bits = u32>> TryFrom<Response<R_CONFIG_READ_RES_LEN>> for ConfigReadResp<T> {
        type Error = Error;

        fn try_from(resp: Response<R_CONFIG_READ_RES_LEN>) -> Result<Self, Self::Error> {
            let value = u32::from_le_bytes(
                resp.data[3..7]
                    .try_into()
                    .map_err(|_| Error::ReadConfigBytes)?,
            );

            let value = T::from_bits_retain(value);

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

    // command length
    const R_CONFIG_ERASE_CMD_LEN: usize = CMD_ID_LEN;

    /** @brief Result length */
    const R_CONFIG_ERASE_RES_LEN: usize = RES_STATUS_LEN;

    pub struct ConfigEraseCmd {
        size: u16,
        data: [u8; R_CONFIG_ERASE_CMD_LEN],
    }

    impl ConfigEraseCmd {
        fn create() -> Self {
            let mut data = [0_u8; R_CONFIG_ERASE_CMD_LEN];
            data[0] = R_CONFIG_ERASE_CMD_ID;
            let size = (R_CONFIG_ERASE_CMD_LEN) as u16;
            Self { data, size }
        }
    }

    impl PlaintextCmd<{ R_CONFIG_ERASE_CMD_LEN }> for ConfigEraseCmd {
        fn size(&self) -> u16 {
            self.size
        }

        fn data(self) -> [u8; R_CONFIG_ERASE_CMD_LEN] {
            self.data
        }
    }

    pub struct ConfigEraseResp {
        len: u16,
        status: Status,
    }

    impl TryFrom<Response<R_CONFIG_ERASE_RES_LEN>> for ConfigEraseResp {
        type Error = Error;

        fn try_from(resp: Response<R_CONFIG_ERASE_RES_LEN>) -> Result<Self, Self::Error> {
            Ok(Self {
                len: resp.len,
                status: resp.status,
            })
        }
    }

    #[cfg(test)]
    pub mod tests {

        extern crate alloc;

        use embedded_hal_mock::eh1::delay::CheckedDelay;

        use super::*;
        use crate::{common, l3};

        #[test]
        fn test_config_write() {
            let mut mocked_delay = CheckedDelay::new([]);

            let (mut mocked_spi_device, mut mocked_session) =
                super::super::tests::get_mocked_spi_device_and_session(
                    &[
                        4,
                        26,
                        R_CONFIG_WRITE_CMD_LEN as u8,
                        0,
                        R_CONFIG_WRITE_CMD_ID,
                        0,
                        0,
                        0,
                        255,
                        255,
                        255,
                        255,
                    ],
                    &[Status::Ok as u8],
                );

            let addr = crate::common::config::StartUp;
            let value = crate::common::config::StartUpConfig::default();

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                l3::reversable_config::ConfigWriteCmd::create(addr, value),
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
                    &[
                        4,
                        21,
                        R_CONFIG_READ_CMD_LEN as u8,
                        0,
                        R_CONFIG_READ_CMD_ID,
                        0,
                        0,
                    ],
                    &[Status::Ok as u8, 0, 0, 0, 255, 255, 255, 255],
                );

            let addr = crate::common::config::StartUp;

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                l3::reversable_config::ConfigReadCmd::create(addr),
                &mut mocked_session,
            )
            .expect("failed to send command");

            let result = l3::receive(
                &mut mocked_spi_device,
                &mut mocked_delay,
                &mut mocked_session,
            )
            .expect("failed to get result");

            let read_result: ConfigReadResp<common::config::StartUpConfig> =
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
                    &[
                        4,
                        19,
                        R_CONFIG_ERASE_CMD_LEN as u8,
                        0,
                        R_CONFIG_ERASE_CMD_ID,
                    ],
                    &[Status::Ok as u8],
                );

            l3::send(
                &mut mocked_spi_device,
                &mut mocked_delay,
                l3::reversable_config::ConfigEraseCmd::create(),
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
        request_resp_crc.extend_from_slice(
            &core::iter::repeat(0)
                .take(255)
                .collect::<alloc::vec::Vec<u8>>(),
        );

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
        exp_req: &[u8],
        resp_data: &[u8],
    ) -> alloc::vec::Vec<embedded_hal_mock::eh1::spi::Transaction<u8>> {
        let mut exp_req = exp_req.to_vec();
        exp_req.extend_from_slice(&SESSION_ENC_TAG);
        exp_req.extend_from_slice(&[0, 0]);
        crc16::add_crc(&mut exp_req).expect("failed to add crc to request");

        let mut exp_spi_transaction = [
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::write_vec(exp_req),
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

        let vec_of_zeros: alloc::vec::Vec<u8> = core::iter::repeat(0)
            .take(255 + 3 - respons.len())
            .collect();
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
        exp_req: &[u8],
        resp_data: &[u8],
    ) -> (
        Generic<embedded_hal_mock::eh1::spi::Transaction<u8>>,
        session::mock::MockSession,
    ) {
        let exp_spi_transaction = expected_spi_request_and_response(exp_req, resp_data);

        let mocked_spi_device = SpiMock::new(&exp_spi_transaction);
        let mocked_session = session::mock::MockSession {
            enc_tag: SESSION_ENC_TAG,
            dec_tag: SESSION_DEC_TAG,
        };
        (mocked_spi_device, mocked_session)
    }
}

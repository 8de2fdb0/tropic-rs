use core::fmt::Debug;
use core::marker::PhantomData;

use embedded_hal::spi::SpiDevice;
use x25519_dalek::StaticSecret;

use crate::common::{self, PairingKeySlot, config::RegisterAddr};
use crate::l1;
use crate::l2;
use crate::l3;
use crate::l3::session::EncSession;

#[derive(Debug)]
pub enum Error {
    Spi(embedded_hal::spi::ErrorKind),
    L1(crate::l1::Error),
    L2(crate::l2::Error),
    L3(crate::l3::Error),
    Tropic01(crate::error::Error),
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spi(err) => f.write_fmt(format_args!("spi error: {:?}", err)),
            Self::L1(err) => f.write_fmt(format_args!("l1 error: {:?}", err)),
            Self::L2(err) => f.write_fmt(format_args!("l2 error: {:?}", err)),
            Self::L3(err) => f.write_fmt(format_args!("l3 error: {:?}", err)),
            Self::Tropic01(err) => f.write_fmt(format_args!("tropic_01 error: {}", err)),
        }
    }
}

impl<E: embedded_hal::spi::Error> From<E> for Error {
    fn from(err: E) -> Self {
        Self::Spi(err.kind())
    }
}

impl From<crate::l1::Error> for Error {
    fn from(err: crate::l1::Error) -> Self {
        Self::L1(err)
    }
}

impl From<l2::Error> for Error {
    fn from(err: l2::Error) -> Self {
        Self::L2(err)
    }
}

impl From<l3::Error> for Error {
    fn from(err: l3::Error) -> Self {
        Self::L3(err)
    }
}

impl From<crate::error::Error> for Error {
    fn from(err: crate::error::Error) -> Self {
        Self::Tropic01(err)
    }
}

pub struct Tropic01<SPI, D, CDEC> {
    spi_device: SPI,
    delay: D,
    _cert: PhantomData<CDEC>,
    // cs is handled by SpiDevice trait
    // cs: CS,
}

impl<'a, SPI, D, CDEC> Tropic01<SPI, D, CDEC>
where
    SPI: SpiDevice,
    D: embedded_hal::delay::DelayNs,
{
    pub fn new(spi_device: SPI, delay: D) -> Self
    where
        CDEC: crate::cert_store::CertDecoder,
    {
        Self {
            spi_device,
            delay,
            _cert: PhantomData,
        }
    }
}

impl<SPI, D, CDEC> Tropic01<SPI, D, CDEC>
where
    SPI: SpiDevice,
    D: embedded_hal::delay::DelayNs,
    CDEC: crate::cert_store::CertDecoder,
{
    pub fn get_chip_status(&mut self) -> Result<l1::ChipStatus, Error> {
        let req = [l1::GET_RESPONSE_REQ_ID];
        let mut chip_status = [0_u8; 1];
        self.spi_device.transfer(&mut chip_status, &req)?;

        Ok(chip_status[0].into())
    }

    pub fn get_chip_id(&mut self) -> Result<l2::info::ChipId, Error> {
        let req = l2::info::GetInfoReq::create(
            l2::info::GetInfoObjectId::ChipId,
            l2::info::BlocIndex::DataChunk(l2::info::DataChunk::Bytes0_127),
        )?;
        self.spi_device.write(&req)?;

        let resp: l2::Response<{ l2::info::GET_INFO_CHIP_INFO_ID_SIZE }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;
        Ok(resp.into())
    }

    pub fn get_riscv_firmware_version(&mut self) -> Result<[u8; 4], Error> {
        let req = l2::info::GetInfoReq::create(
            l2::info::GetInfoObjectId::RiscvFwVersion,
            l2::info::BlocIndex::DataChunk(l2::info::DataChunk::Bytes0_127),
        )?;
        self.spi_device.write(&req)?;
        let resp: l2::Response<{ l2::info::GET_INFO_RISCV_FW_SIZE }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;
        Ok(resp.data)
    }

    pub fn get_spect_firmware_version(&mut self) -> Result<[u8; 4], Error> {
        let req = l2::info::GetInfoReq::create(
            l2::info::GetInfoObjectId::SpectFwVersion,
            l2::info::BlocIndex::DataChunk(l2::info::DataChunk::Bytes0_127),
        )?;
        self.spi_device.write(&req)?;
        let resp = l1::receive::<SPI, D, { l2::info::GET_INFO_SPECT_FW_SIZE }>(
            &mut self.spi_device,
            &mut self.delay,
        )?;
        Ok(resp.data)
    }

    pub fn get_info_fw_bank(&mut self, bank_id: l2::info::BankId) -> Result<[u8; 20], Error> {
        let req = l2::info::GetInfoReq::create(
            l2::info::GetInfoObjectId::FwBank,
            l2::info::BlocIndex::BankId(bank_id),
        )?;
        self.spi_device.write(&req)?;
        let resp = l1::receive::<SPI, D, { l2::info::GET_INFO_FW_HEADER_SIZE }>(
            &mut self.spi_device,
            &mut self.delay,
        )?;
        Ok(resp.data)
    }

    pub fn get_riscv_firmware_log(&mut self) -> Result<l2::log::GetLogResp, Error> {
        let req = l2::log::GetLogReq::create()?;
        self.spi_device.write(&req)?;

        let resp: l2::Response<{ l2::log::GET_LOG_RSP_MAX_LEN }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;
        Ok(resp.into())
    }

    pub fn restart(&mut self, mode: l2::restart::RestartMode) -> Result<l2::Status, Error> {
        let req = l2::restart::StartupReq::create(mode)?;
        self.spi_device.write(&req)?;
        let resp: l2::Response<{ l2::restart::STARTUP_RSP_LEN }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;
        Ok(resp.status)
    }

    pub fn get_cert_store<'a>(
        &mut self,
        certificate_buffer: &'a mut [u8],
    ) -> Result<l2::cert_store::CertStore<CDEC::Cert<'a>>, Error> {
        let cert_store = l2::cert_store::request_cert_store::<SPI, D, CDEC>(
            &mut self.spi_device,
            &mut self.delay,
            certificate_buffer,
        )?;

        Ok(cert_store)
    }

    pub fn get_handshake<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        mut rng: R,
        pairing_key_slot: common::PairingKeySlot,
    ) -> Result<(l2::handshake::HandshakeResp, StaticSecret), Error> {
        let (eh_secret, eh_pubkey) = l3::session::generate_key_pair(&mut rng);
        let req = l2::handshake::HandshakeReq::create(eh_pubkey, pairing_key_slot)?;
        self.spi_device.write(&req)?;

        let resp: l2::Response<{ l2::handshake::HANDSHAKE_RSP_LEN }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;

        let handshake_resp: l2::handshake::HandshakeResp = resp.into();

        Ok((handshake_resp, eh_secret))
    }

    pub fn create_session<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: R,
        sh_secret: &StaticSecret,
        pairing_key_slot: common::PairingKeySlot,
        st_pubkey: &x25519_dalek::PublicKey,
    ) -> Result<l3::session::EncSession, Error> {
        let (handshake_resp, eh_secret) = self.get_handshake(rng, pairing_key_slot.clone())?;

        let session = EncSession::create_session(
            sh_secret,
            pairing_key_slot,
            st_pubkey,
            &eh_secret,
            &handshake_resp.et_pubkey,
            &handshake_resp.auth_tag,
        )
        .map_err(l3::Error::Session)?;

        Ok(session)
    }

    pub fn ping(
        &mut self,
        session: &mut EncSession,
        msg: &[u8],
    ) -> Result<l3::ping::PingResp, Error> {
        l3::send(
            &mut self.spi_device,
            &mut self.delay,
            l3::ping::PingCmd::create(msg)?,
            session,
        )?;

        Ok(l3::receive(&mut self.spi_device, &mut self.delay, session)?.into())
    }

    pub fn pairing_key_read(
        &mut self,
        session: &mut EncSession,
        slot: PairingKeySlot,
    ) -> Result<l3::payring_key::PairingKeyReadResp, Error> {
        l3::send(
            &mut self.spi_device,
            &mut self.delay,
            l3::payring_key::PairingKeyReadCmd::create(slot),
            session,
        )?;

        Ok(l3::receive(&mut self.spi_device, &mut self.delay, session)?.into())
    }

    pub fn pairing_key_write(
        &mut self,
        session: &mut EncSession,
        slot: PairingKeySlot,
        key: &x25519_dalek::PublicKey,
    ) -> Result<l3::payring_key::PairingKeyWriteResp, Error> {
        l3::send(
            &mut self.spi_device,
            &mut self.delay,
            l3::payring_key::PairingKeyWriteCmd::create(slot, key),
            session,
        )?;

        let resp = l3::receive(&mut self.spi_device, &mut self.delay, session)?.into();
        Ok(resp)
    }

    pub fn pairing_key_invalidate(
        &mut self,
        session: &mut EncSession,
        slot: PairingKeySlot,
    ) -> Result<l3::payring_key::PairingKeyInvalidateResp, Error> {
        l3::send(
            &mut self.spi_device,
            &mut self.delay,
            l3::payring_key::PairingKeyInvalidateCmd::create(slot),
            session,
        )?;

        Ok(l3::receive(&mut self.spi_device, &mut self.delay, session)?.into())
    }

    pub fn config_read<R: RegisterAddr>(
        &mut self,
        session: &mut EncSession,
        addr: R,
    ) -> Result<l3::reversable_config::ConfigReadResp<R::Item>, Error> {
        l3::send(
            &mut self.spi_device,
            &mut self.delay,
            l3::reversable_config::ConfigReadCmd::create(addr),
            session,
        )?;

        Ok(l3::receive(&mut self.spi_device, &mut self.delay, session)?.try_into()?)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use crate::{cert_store::MockDecoder, crc16, l1::ChipStatus};

    use super::*;

    use embedded_hal_mock::eh1::{
        delay::{CheckedDelay, Transaction as CheckedDelayTransaction},
        digital::{
            Mock as DigitalMock, State as DigitalMockState, Transaction as DigitalMockTransaction,
        },
        spi::{Mock as SpiMock, Transaction as SpiMockTransaction},
    };

    #[test]
    fn get_chip_state() {
        let mut mocked_delay = CheckedDelay::new([]);
        let exp_spi_transactions = [
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::transfer([l1::GET_RESPONSE_REQ_ID].to_vec(), [0x01].to_vec()),
            SpiMockTransaction::transaction_end(),
        ];

        let mut mocked_spi_device = SpiMock::new(&exp_spi_transactions);
        let mut tropic_01 =
            Tropic01::<_, _, MockDecoder>::new(mocked_spi_device.clone(), mocked_delay.clone());

        let chip_status = tropic_01
            .get_chip_status()
            .expect("unable to get chip _status");

        let exp_chip_status = ChipStatus::from_values(true, false, false);

        assert_eq!(exp_chip_status, chip_status);

        mocked_delay.done();
        mocked_spi_device.done();
    }

    #[test]
    fn get_chip_id() {
        let mut mocked_delay = CheckedDelay::new([]);

        let request: alloc::vec::Vec<u8> = alloc::vec![1, 2, 1, 0, 43, 146];

        let resp_len = 128_u8;
        let mut resp = [
            0x01, // chip_status ready
            l2::Status::ResultOk as u8,
            resp_len,
        ]
        .to_vec();

        let chip_id_ver = [0x01_u8, 0x02, 0x03, 0x04];
        resp.extend_from_slice(&chip_id_ver);

        let fl_chip_info = [0x0_u8; 16];
        resp.extend_from_slice(&fl_chip_info);

        let func_test_info = [0x01_u8; 8];
        resp.extend_from_slice(&func_test_info);

        let silicon_rev = [0xb_u8, 0xe, 0xe, 0xf];
        resp.extend_from_slice(&silicon_rev);

        let packg_type_id = [0x0_u8; 2];
        resp.extend_from_slice(&packg_type_id);

        let rfu_1 = [0x1_u8; 2];
        resp.extend_from_slice(&rfu_1);

        let prov_ver_fab_id_pn = [0x0_u8; 4];
        resp.extend_from_slice(&prov_ver_fab_id_pn);

        let provisioning_date = [0x0_u8; 2];
        resp.extend_from_slice(&provisioning_date);

        let hsm_ver = [0x0_u8; 4];
        resp.extend_from_slice(&hsm_ver);

        let prog_ver = [0x0_u8; 4];
        resp.extend_from_slice(&prog_ver);

        let rfu_2 = [0x0_u8; 2];
        resp.extend_from_slice(&rfu_2);

        let ser_num = [0x0_u8; 16];
        resp.extend_from_slice(&ser_num);

        let part_num_data = [0x0_u8; 16];
        resp.extend_from_slice(&part_num_data);

        let prov_templ_ver = [0x0_u8; 2];
        resp.extend_from_slice(&prov_templ_ver);
        let prov_templ_tag = [0x0_u8; 4];
        resp.extend_from_slice(&prov_templ_tag);
        let prov_spec_ver = [0x0_u8; 2];
        resp.extend_from_slice(&prov_spec_ver);
        let prov_spec_tag = [0x0_u8; 4];
        resp.extend_from_slice(&prov_spec_tag);

        let batch_id = [0x0_u8; 5];
        resp.extend_from_slice(&batch_id);
        let rfu_3 = [0x0_u8; 3];
        resp.extend_from_slice(&rfu_3);

        let rfu_4 = [0x0_u8; 24];
        resp.extend_from_slice(&rfu_4);

        let crc = crc16::crc16(
            &resp[3..resp_len as usize + 3],
            Some(&[l2::Status::ResultOk as u8, resp_len]),
        )
        .to_be_bytes();

        let exp_spi_transactions = [
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::write_vec(request),
            SpiMockTransaction::transaction_end(),
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::transfer([l1::GET_RESPONSE_REQ_ID].to_vec(), [resp[0]].to_vec()),
            SpiMockTransaction::transfer_in_place([0].to_vec(), [resp[1]].to_vec()),
            SpiMockTransaction::transfer_in_place([0].to_vec(), [resp[2]].to_vec()),
            SpiMockTransaction::transfer_in_place([0u8; 128].to_vec(), resp[3..131].to_vec()),
            SpiMockTransaction::transfer_in_place([0u8; 2].to_vec(), crc.to_vec()),
            SpiMockTransaction::transaction_end(),
        ];

        let mut mocked_spi_device = SpiMock::new(&exp_spi_transactions);
        let mut tropic_01 =
            Tropic01::<_, _, MockDecoder>::new(mocked_spi_device.clone(), mocked_delay.clone());

        let chip_info = tropic_01.get_chip_id().expect("unable to get chip info");

        assert_eq!(chip_info.chip_id_ver, chip_id_ver);
        assert_eq!(chip_info.fl_chip_info, fl_chip_info);
        assert_eq!(chip_info.func_test_info, func_test_info);
        assert_eq!(chip_info.silicon_rev, silicon_rev);
        assert_eq!(chip_info.packg_type_id, packg_type_id);
        assert_eq!(chip_info.rfu_1, rfu_1);
        assert_eq!(chip_info.prov_ver_fab_id_pn, prov_ver_fab_id_pn);
        assert_eq!(chip_info.provisioning_date, provisioning_date);
        assert_eq!(chip_info.hsm_ver, hsm_ver);
        assert_eq!(chip_info.prog_ver, prog_ver);
        assert_eq!(chip_info.rfu_2, rfu_2);
        // assert_eq!(chip_info.ser_num, ser_num);
        assert_eq!(chip_info.part_num_data, part_num_data);
        assert_eq!(chip_info.prov.prov_templ_ver, prov_templ_ver);
        assert_eq!(chip_info.prov.prov_templ_tag, prov_templ_tag);
        assert_eq!(chip_info.prov.prov_spec_ver, prov_spec_ver);
        assert_eq!(chip_info.prov.prov_spec_tag, prov_spec_tag);
        assert_eq!(chip_info.batch_id, batch_id);
        assert_eq!(chip_info.rfu_3, rfu_3);
        assert_eq!(chip_info.rfu_4, rfu_4);

        mocked_delay.done();
        mocked_spi_device.done();
    }
}

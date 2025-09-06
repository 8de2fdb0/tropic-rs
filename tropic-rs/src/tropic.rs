use core::fmt::Debug;
use core::marker::PhantomData;

use embedded_hal::spi::SpiDevice;
use x25519_dalek::StaticSecret;

use crate::common::{self, PairingKeySlot, config::RegisterAddr};
use crate::l1;
use crate::l2::{self, ReceiveResponse, info};
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

impl<SPI, D, CDEC> Tropic01<SPI, D, CDEC>
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

        Ok(l2::info::ChipId::receive(
            &mut self.spi_device,
            &mut self.delay,
        )?)
    }

    pub fn get_firmware_version(
        &mut self,
        r#type: l2::info::FirmwareType,
    ) -> Result<l2::info::FirmwareVersion, Error> {
        let req = l2::info::GetInfoReq::create(
            r#type.clone().into(),
            l2::info::BlocIndex::DataChunk(l2::info::DataChunk::Bytes0_127),
        )?;
        self.spi_device.write(&req)?;

        let resp: l2::Response<{ l2::info::GET_INFO_RISCV_FW_SIZE }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;

        Ok(l2::info::FirmwareVersion {
            r#type,
            version: resp.data,
        })
    }

    pub fn get_firmware_boot_header(
        &mut self,
        bank_id: l2::info::BankId,
    ) -> Result<l2::info::FirmwareBootHeader, Error> {
        let req = l2::info::GetInfoReq::create(
            l2::info::GetInfoObjectId::FwBank,
            l2::info::BlocIndex::BankId(bank_id),
        )?;
        self.spi_device.write(&req)?;

        Ok(l2::info::FirmwareBootHeader::receive(
            &mut self.spi_device,
            &mut self.delay,
        )?)
    }

    pub fn get_riscv_firmware_log(&mut self) -> Result<l2::log::GetLogResp, Error> {
        let req = l2::log::GetLogReq::create()?;
        self.spi_device.write(&req)?;

        Ok(l2::log::GetLogResp::receive(
            &mut self.spi_device,
            &mut self.delay,
        )?)
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

    pub fn sleep(&mut self, kind: l2::sleep::SleepKind) -> Result<l2::Status, Error> {
        let req = l2::sleep::SleepReq::create(kind)?;
        self.spi_device.write(&req)?;
        Ok(l2::sleep::SleepResp::receive(&mut self.spi_device, &mut self.delay)?.status)
    }

    pub fn restart(&mut self, mode: l2::restart::RestartMode) -> Result<l2::Status, Error> {
        let req = l2::restart::StartupReq::create(mode)?;
        self.spi_device.write(&req)?;
        Ok(l2::restart::StartupResp::receive(&mut self.spi_device, &mut self.delay)?.status)
    }

    pub fn resend_response<const N: usize, T>(&mut self) -> Result<T, Error>
    where
        T: ReceiveResponse<N>,
        <T as core::convert::TryFrom<l2::Response<N>>>::Error: Into<l2::Error>,
    {
        let req = l2::resend::ResendReq::create()?;
        self.spi_device.write(&req)?;
        Ok(T::receive(&mut self.spi_device, &mut self.delay)?)
    }

    pub fn mutable_firmware_erase(
        &mut self,
        bank_id: info::BankId,
    ) -> Result<l2::mutable_firmware::EraseResp, Error> {
        let req = l2::mutable_firmware::EraseReq::create(bank_id)?;
        self.spi_device.write(&req)?;

        Ok(l2::mutable_firmware::EraseResp::receive(
            &mut self.spi_device,
            &mut self.delay,
        )?)
    }

    #[cfg(feature = "acab")]
    pub fn mutable_fiwrmware_update(
        &mut self,
        fw_update: &[u8],
    ) -> Result<l2::mutable_firmware::acab::UpdateResp, Error> {
        let req = l2::mutable_firmware::acab::UpdateReq::create(&fw_update)?;
        self.spi_device.write(&req)?;

        let mut resp =
            l2::mutable_firmware::acab::UpdateResp::receive(&mut self.spi_device, &mut self.delay)?;

        let req_chunks = l2::mutable_firmware::acab::UpdateDataReq::create(&fw_update)?;
        for i in 0..req_chunks.count {
            let next_req = req_chunks.chunks[i].command()?;
            self.spi_device.write(&next_req)?;

            resp = l2::mutable_firmware::acab::UpdateResp::receive(
                &mut self.spi_device,
                &mut self.delay,
            )?;
        }
        Ok(resp)
    }

    pub fn get_handshake<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        mut rng: R,
        pairing_key_slot: common::PairingKeySlot,
    ) -> Result<(l2::handshake::HandshakeResp, StaticSecret), Error> {
        let (eh_secret, eh_pubkey) = l3::session::generate_key_pair(&mut rng);
        let req = l2::handshake::HandshakeReq::create(eh_pubkey, pairing_key_slot)?;
        self.spi_device.write(&req)?;

        Ok((
            l2::handshake::HandshakeResp::receive(&mut self.spi_device, &mut self.delay)?,
            eh_secret,
        ))
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

    pub fn abort_session(&mut self) -> Result<l2::Status, Error> {
        let req = l2::enc_session::SessionAbortReq::create()?;
        self.spi_device.write(&req)?;

        Ok(
            l2::enc_session::SessionAbortResp::receive(&mut self.spi_device, &mut self.delay)?
                .status,
        )
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

    pub fn r_config_read_value<R: RegisterAddr>(
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
    pub fn r_config_write_value<R: RegisterAddr>(
        &mut self,
        session: &mut EncSession,
        addr: R,
        value: R::Item,
    ) -> Result<l3::reversable_config::ConfigWriteResp, Error> {
        l3::send(
            &mut self.spi_device,
            &mut self.delay,
            l3::reversable_config::ConfigWriteCmd::create(addr, value),
            session,
        )?;

        Ok(l3::receive(&mut self.spi_device, &mut self.delay, session)?.try_into()?)
    }

    pub fn r_config_read(
        &mut self,
        session: &mut EncSession,
    ) -> Result<common::config::Config, Error> {
        let whole_r_config = common::config::read_whole_i_or_r_config(
            &mut self.spi_device,
            &mut self.delay,
            session,
            common::config::ConfigType::Reversable,
        )?;
        Ok(whole_r_config)
    }

    pub fn r_config_erase(
        &mut self,
        session: &mut EncSession,
    ) -> Result<l3::reversable_config::ConfigEraseResp, Error> {
        l3::send(
            &mut self.spi_device,
            &mut self.delay,
            l3::reversable_config::ConfigEraseCmd::create(),
            session,
        )?;

        Ok(l3::receive(&mut self.spi_device, &mut self.delay, session)?.try_into()?)
    }

    pub fn r_config_write(
        &mut self,
        session: &mut EncSession,
        config: &common::config::Config,
    ) -> Result<l3::reversable_config::ConfigWriteResp, Error> {
        let resp: l3::reversable_config::ConfigWriteResp = common::config::write_whole_r_config(
            &mut self.spi_device,
            &mut self.delay,
            session,
            config,
        )?;
        Ok(resp)
    }

    pub fn i_config_read(
        &mut self,
        session: &mut EncSession,
    ) -> Result<common::config::Config, Error> {
        let whole_r_config = common::config::read_whole_i_or_r_config(
            &mut self.spi_device,
            &mut self.delay,
            session,
            common::config::ConfigType::Irreverasable,
        )?;
        Ok(whole_r_config)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use embedded_hal_mock::eh1::{
        delay::CheckedDelay,
        spi::{Mock as SpiMock, Transaction as SpiMockTransaction},
    };

    use crate::{cert_store::MockDecoder, crc16, l1::ChipStatus};

    use super::*;

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

        let manu_info = l2::info::ManufacturingInfo {
            func_test_info: [0x01_u8; 8],
            silicon_rev: [0xb_u8, 0xe, 0xe, 0xf],
            packg_type_id: [0x0_u8; 2],
            rfu_1: [0x1_u8; 2],
        };
        resp.extend_from_slice(&manu_info.func_test_info);
        resp.extend_from_slice(&manu_info.silicon_rev);
        resp.extend_from_slice(&manu_info.packg_type_id);
        resp.extend_from_slice(&manu_info.rfu_1);

        let ser_num_v1 = l2::info::SerialNumberV1 {
            prov_ver_fab_id_pn: [0x0_u8; 4],
            provisioning_date: [0x0_u8; 2],
            hsm_ver: [0x0_u8; 4],
            prog_ver: [0x0_u8; 4],
            rfu_2: [0x0_u8; 2],
        };
        resp.extend_from_slice(&ser_num_v1.prov_ver_fab_id_pn);
        resp.extend_from_slice(&ser_num_v1.provisioning_date);
        resp.extend_from_slice(&ser_num_v1.hsm_ver);
        resp.extend_from_slice(&ser_num_v1.prog_ver);
        resp.extend_from_slice(&ser_num_v1.rfu_2);

        let ser_num_v2 = l2::info::SerialNumberV2 {
            sn: 0x1,
            fab_data: [0x0_u8; 3],
            fab_date: 10,
            lot_id: [0x0_u8; 5],
            wafer_id: 0x2,
            x_coord: 100,
            y_coord: 200,
        };
        resp.extend_from_slice(&ser_num_v2.sn.to_le_bytes());
        resp.extend_from_slice(&ser_num_v2.fab_data);
        resp.extend_from_slice(&ser_num_v2.fab_date.to_le_bytes());
        resp.extend_from_slice(&ser_num_v2.lot_id);
        resp.extend_from_slice(&ser_num_v2.wafer_id.to_le_bytes());
        resp.extend_from_slice(&ser_num_v2.x_coord.to_le_bytes());
        resp.extend_from_slice(&ser_num_v2.y_coord.to_le_bytes());

        let part_num_data = [0x0_u8; 16];
        resp.extend_from_slice(&part_num_data);

        let prov_data = l2::info::ProvisioningData {
            prov_templ_ver: [0x0_u8; 2],
            prov_templ_tag: [0x0_u8; 4],
            prov_spec_ver: [0x0_u8; 2],
            prov_spec_tag: [0x0_u8; 4],
            batch_id: [0x0_u8; 5],
            rfu_3: [0x0_u8; 3],
        };
        resp.extend_from_slice(&prov_data.prov_templ_ver);
        resp.extend_from_slice(&prov_data.prov_templ_tag);
        resp.extend_from_slice(&prov_data.prov_spec_ver);
        resp.extend_from_slice(&prov_data.prov_spec_tag);
        resp.extend_from_slice(&prov_data.batch_id);
        resp.extend_from_slice(&prov_data.rfu_3);

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
        assert_eq!(chip_info.manu_info, manu_info);
        assert_eq!(chip_info.prov_info, ser_num_v1);
        assert_eq!(chip_info.prov_info_v2, ser_num_v2);
        assert_eq!(chip_info.part_number, part_num_data);
        assert_eq!(chip_info.prov_data, prov_data);
        assert_eq!(chip_info.rfu_4, rfu_4);

        mocked_delay.done();
        mocked_spi_device.done();
    }
}

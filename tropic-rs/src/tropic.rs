use core::fmt::Debug;
use core::marker::PhantomData;

use embedded_hal::spi::SpiDevice;

use crate::common;
use crate::l1;
use crate::l2;
use crate::l3;

#[derive(Debug)]
pub enum Error {
    Spi(embedded_hal::spi::ErrorKind),
    L1(crate::l1::Error),
    L2(crate::l2::Error),
    Tropic01(crate::error::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spi(err) => f.write_fmt(format_args!("spi error: {:?}", err)),
            Self::L1(err) => f.write_fmt(format_args!("l1 error: {:?}", err)),
            Self::L2(err) => f.write_fmt(format_args!("l2 error: {:?}", err)),
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

    pub fn get_chip_id(&mut self) -> Result<l2::resp::ChipId, Error> {
        let req = l2::info::GetInfoReq::create(
            l2::info::GetInfoObjectId::ChipId,
            l2::info::BlocIndex::DataChunk(l2::info::DataChunk::Bytes0_127),
        )?;
        self.spi_device.write(&req)?;

        let resp: l2::Response<{ l2::resp::GET_INFO_CHIP_INFO_ID_SIZE }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;
        Ok(resp.into())
    }

    pub fn get_x509_certificate<'a>(
        &mut self,
        certificate_buffer: &'a mut [u8],
    ) -> Result<l2::cert_store::CertificateStore<CDEC::Cert<'a>>, Error> {
        let cert_store = l2::cert_store::request_cert_store::<SPI, D, CDEC>(
            &mut self.spi_device,
            &mut self.delay,
            certificate_buffer,
        )?;

        Ok(cert_store)

        // let mut certs =
        //     [[0_u8; l2::cert_store::CERT_SIZE_SINGLE]; l2::cert_store::NUM_CERTIFICATES];
        // let mut cert_len = [0usize; l2::cert_store::NUM_CERTIFICATES];
        // let mut curr_cert = 0usize;

        // for i in 0..255 {
        //     let req = l2::info::GetInfoReq::create(
        //         l2::info::GetInfoObjectId::X509Certificate,
        //         l2::info::BlocIndex::CeryStore(i),
        //     )?;

        //     self.spi_device.write(&req)?;
        //     let resp: l2::Response<{ l2::info::GET_INFO_BLOCK_LEN }> =
        //         l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;

        //     let resp: l2::info::GetInfoResp<{ l2::info::GET_INFO_BLOCK_LEN }> = resp.into();

        //     if i == 0 {
        //         // validate cert store version
        //         if (resp.object[0] != l2::info::cert_store::CERT_STORE_VERSION) {
        //             return Err(Error::L2(l2::Error::CertStore(
        //                 l2::CertStoreError::StoreVersion,
        //             )));
        //         }
        //         // validate number of certs
        //         if (resp.object[1] as usize != l2::info::cert_store::NUM_CERTIFICATES) {
        //             return Err(Error::L2(l2::Error::CertStore(
        //                 l2::CertStoreError::NumCerts,
        //             )));
        //         }

        //         // get size of each cert
        //         for j in 00..l2::info::cert_store::NUM_CERTIFICATES {
        //             let len_high = resp.object[2 + j * 2];
        //             let len_low = resp.object[2 + j * 2 + 1];
        //             let len = u16::from_be_bytes([len_high, len_low]);
        //             if len as usize > certs[j].len() {
        //                 return Err(Error::L2(l2::Error::CertStore(
        //                     l2::CertStoreError::CertSize,
        //                 )));
        //             }
        //             cert_len[j] = len as usize;
        //         }
        //     }

        //     // let available = if i == 0 {

        //     // }
        // }

        // Ok(certs[0])
    }

    pub fn get_handshake<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        mut rng: R,
        pkey_index: common::PairingKeyIndex,
    ) -> Result<(), Error> {
        let (host_privkey, host_pubkey) = l3::generate_key_pair(&mut rng);
        let req = l2::handshake::HandshakeReq::create(host_pubkey, pkey_index)?;
        self.spi_device.write(&req)?;

        let resp: l2::Response<{ l2::handshake::HANDSHAKE_RSP_LEN }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;

        let handshake_resp: l2::handshake::HandshakeResp = resp.into();

        let shared_key = l3::get_shared_secret(host_privkey, &handshake_resp.tropic_pubkey);

        Ok(())
    }

    pub fn get_riscv_firmware_version(&mut self) -> Result<[u8; 4], Error> {
        let req = l2::info::GetInfoReq::create(
            l2::info::GetInfoObjectId::RiscvFwVersion,
            l2::info::BlocIndex::DataChunk(l2::info::DataChunk::Bytes0_127),
        )?;
        self.spi_device.write(&req)?;
        let resp: l2::Response<{ l2::resp::GET_INFO_RISCV_FW_SIZE }> =
            l1::receive(&mut self.spi_device, &mut self.delay)?.try_into()?;
        Ok(resp.data)
    }

    pub fn get_spect_firmware_version(&mut self) -> Result<[u8; 4], Error> {
        let req = l2::info::GetInfoReq::create(
            l2::info::GetInfoObjectId::SpectFwVersion,
            l2::info::BlocIndex::DataChunk(l2::info::DataChunk::Bytes0_127),
        )?;
        self.spi_device.write(&req)?;
        let resp = l1::receive::<SPI, D, { l2::resp::GET_INFO_SPECT_FW_SIZE }>(
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
        let resp = l1::receive::<SPI, D, { l2::resp::GET_INFO_FW_HEADER_SIZE }>(
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
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use crate::{
        crc16::{add_crc, crc16},
        l1::ChipStatus,
    };

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
        let delay_exp = [CheckedDelayTransaction::blocking_delay_ms(25)];

        let mut dleay_mock = CheckedDelay::new(&delay_exp);

        let digital_exp = [
            DigitalMockTransaction::set(DigitalMockState::Low),
            DigitalMockTransaction::set(DigitalMockState::High),
        ];

        let mut digital_mock = DigitalMock::new(&digital_exp);

        let spi_exp = [
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::write(0xaa),
            SpiMockTransaction::transaction_end(),
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::read(0x1),
            SpiMockTransaction::transaction_end(),
        ];

        let mut spi = SpiMock::new(&spi_exp);
        let mut tropic_01 = Tropic01::new(spi, dleay_mock);

        let chip_status = tropic_01
            .get_chip_mode()
            .expect("unable to get chip _status");

        let exp_chip_status = ChipStatus::from_values(true, false, false);

        assert_eq!(exp_chip_status, chip_status);

        digital_mock.done();
        spi.done();
    }

    #[test]
    fn get_chip_id() {
        let delay_exp = [CheckedDelayTransaction::blocking_delay_ms(25)];

        let mut dleay_mock = CheckedDelay::new(&delay_exp);

        let digital_exp = [];

        let mut digital_mock = DigitalMock::new(&digital_exp);

        let mut resp = alloc::vec![];

        let chip_status = 0x1;
        resp.push(chip_status);
        let l2_status = 0x0;
        resp.push(l2_status);
        let len = 128_u8;
        resp.push(len);

        let chip_id_ver = [0x01_u8, 0x02, 0x03, 0x04];
        resp.extend(chip_id_ver);

        let fl_chip_info = [0x0_u8; 16];
        resp.extend(fl_chip_info);

        let func_test_info = [0x01_u8; 8];
        resp.extend(func_test_info);

        let silicon_rev = [0xb_u8, 0xe, 0xe, 0xf];
        resp.extend(silicon_rev);

        let packg_type_id = [0x0_u8; 2];
        resp.extend(packg_type_id);

        let rfu_1 = [0x1_u8; 2];
        resp.extend(rfu_1);

        let prov_ver_fab_id_pn = [0x0_u8; 4];
        resp.extend(prov_ver_fab_id_pn);

        let provisioning_date = [0x0_u8; 2];
        resp.extend(provisioning_date);

        let hsm_ver = [0x0_u8; 4];
        resp.extend(hsm_ver);

        let prog_ver = [0x0_u8; 4];
        resp.extend(prog_ver);

        let rfu_2 = [0x0_u8; 2];
        resp.extend(rfu_2);

        let ser_num = [0x0_u8; 16];
        resp.extend(ser_num);

        let part_num_data = [0x0_u8; 16];
        resp.extend(part_num_data);

        let prov_templ_ver = [0x0_u8; 2];
        resp.extend(prov_templ_ver);
        let prov_templ_tag = [0x0_u8; 4];
        resp.extend(prov_templ_tag);
        let prov_spec_ver = [0x0_u8; 2];
        resp.extend(prov_spec_ver);
        let prov_spec_tag = [0x0_u8; 4];
        resp.extend(prov_spec_tag);

        let batch_id = [0x0_u8; 5];
        resp.extend(batch_id);
        let rfu_3 = [0x0_u8; 3];
        resp.extend(rfu_3);

        let rfu_4 = [0x0_u8; 24];
        resp.extend(rfu_4);

        let mut data = resp.as_slice();

        let crc = crc16(&mut data, None);
        resp.push((crc >> 8) as u8);
        resp.push((crc & 0x00FF) as u8);

        let request: alloc::vec::Vec<u8> = alloc::vec![1, 2, 1, 0, 43, 146];

        let spi_exp = [
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::write_vec(request),
            SpiMockTransaction::transaction_end(),
            SpiMockTransaction::transaction_start(),
            SpiMockTransaction::read_vec(resp),
            SpiMockTransaction::transaction_end(),
        ];

        let mut spi = SpiMock::new(&spi_exp);
        let mut tropic_01 = Tropic01::new(spi, dleay_mock);

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

        digital_mock.done();
        spi.done();
    }
}

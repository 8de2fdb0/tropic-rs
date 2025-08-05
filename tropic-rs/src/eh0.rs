
use core::{fmt::Debug, marker::PhantomData};

use eh0::{digital::v2::OutputPin, spi::FullDuplex};

use crate::l1;
use crate::l2;

#[derive(Debug)]
pub enum Error<E> {
    Spi(E),
    Tropic01(crate::error::Error),
}

impl<E> core::fmt::Display for Error<E> 
where E: Debug {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
       match self {
        Self::Spi(err) => f.write_fmt(format_args!("spi error: {:?}", err)),
        Self::Tropic01(err) => f.write_fmt(format_args!("tropic_01 error: {}", err)),
       }
    }
}

impl<E> From<crate::error::Error> for Error<E> {
    fn from(err: crate::error::Error) -> Self {
        Self::Tropic01(err)
    }
}

pub struct Tropic01<SPI, CS> {
    _spi: PhantomData<SPI>,
    cs: CS,
}

impl<SPI, CS, E> Tropic01<SPI, CS>
where
    SPI: SpiDevice<Error = E>,
    CS: OutputPin,
{
    pub fn new(cs: CS) -> Self {
        Self {
            _spi: PhantomData,
            cs,
        }
    }

    pub fn get_chip_status(&mut self, spi: &mut SPI) -> Result<l1::ChipStatus, Error<E>> {
        let _ = self.cs.set_low();
        let mut buf = [l1::GET_RESPONSE_REQ_ID];
        spi.write(&buf).map_err(|e| Error::Spi(e))?;
        spi.read(&mut buf).map_err(|e| Error::Spi(e))?;
        let _ = self.cs.set_high();
        Ok(buf[0].into())
    }

    pub fn get_chip_id(&mut self, spi: &mut SPI) -> Result<l2::resp::ChipId, Error<E>> {
        let req = l2::req::InfoRequest::create(
            l2::req::InfoObjectId::ChipId,
            l2::req::BlockIndex::DataChunk0_127,
        )?;
        let mut resp = [0_u8; 133];

        spi.write(&req).map_err(|e| Error::Spi(e))?;
        spi.read(&mut resp).map_err(|e| Error::Spi(e))?;

        let resp = l2::resp::InfoResp::try_from(resp)?;

        if resp.rsp_len != l2::resp::CHIP_INFO_ID_LEN {
            return Err(Error::Tropic01(crate::error::Error::InvalidRespLen(
                l2::resp::CHIP_INFO_ID_LEN as usize,
                resp.rsp_len as usize,
            )));
        }

        Ok(resp.object.into())
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
        digital::{
            Mock as DigitalMock, State as DigitalMockState, Transaction as DigitalMockTransaction,
        },
        spi::{Mock as SpiMock, Transaction as SpiMockTransaction},
    };

    #[test]
    fn get_chip_state() {
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

        let mut tropic_01 = Tropic01::new(digital_mock.clone());

        let chip_status = tropic_01
            .get_chip_status(&mut spi)
            .expect("unable to get chip _status");

        let exp_chip_status = ChipStatus::from_values(true, false, false);

        assert_eq!(exp_chip_status, chip_status);

        digital_mock.done();
        spi.done();
    }

    #[test]
    fn get_chip_id() {
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

        let crc = crc16(&mut data);
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

        let mut tropic_01 = Tropic01::new(digital_mock.clone());

        let chip_info = tropic_01
            .get_chip_id(&mut spi)
            .expect("unable to get chip info");

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

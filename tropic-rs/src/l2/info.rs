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
    pub fn create(object_id: GetInfoObjectId, block_index: BlocIndex) -> Result<[u8; 6], Error> {
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

pub const GET_INFO_CHIP_INFO_ID_SIZE: usize = GET_INFO_BLOCK_LEN;
pub const GET_INFO_RISCV_FW_SIZE: usize = 4;
pub const GET_INFO_SPECT_FW_SIZE: usize = 4;
pub const GET_INFO_FW_HEADER_SIZE: usize = 20;

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

#[cfg(feature = "display")]
impl core::fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

#[cfg(feature = "display")]
impl core::fmt::Display for Provisioning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

#[cfg(feature = "display")]
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
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12],
                data[13], data[14], data[15], data[16], data[17], data[18], data[19],
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

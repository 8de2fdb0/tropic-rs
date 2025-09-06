// Generator polynomial value used
const CRC16_POLYNOMIAL: u16 = 0x8005;

// Used to initialize the crc value
const CRC16_INITIAL_VAL: u16 = 0x0000;

// The final XOR value is xored to the final CRC value before being returned.
// This is done after the 'Result reflected' step.
const CRC16_FINAL_XOR_VALUE: u16 = 0x0000;

#[derive(Debug, PartialEq)]
pub enum Error {
    CrcDataLen,
    CrcDataCap(usize, usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CrcDataLen => f.write_str("data buffer must be at least 2 bytes long"),
            Self::CrcDataCap(exp, act) => f.write_fmt(format_args!(
                "insufficient data buffer capacity: expected {} bytes, got {}",
                exp, act
            )),
        }
    }
}

pub fn crc16_byte(data: u8, mut crc: u16) -> u16 {
    crc ^= (data as u16) << 8;

    for _i in 0..8 {
        if (crc & 0x8000) != 0 {
            crc <<= 1;
            crc ^= CRC16_POLYNOMIAL;
        } else {
            crc <<= 1;
        }
    }
    crc
}

pub fn crc16(data: &[u8], status_and_len: Option<&[u8; 2]>) -> u16 {
    let mut crc = CRC16_INITIAL_VAL;

    if let Some(status_and_len) = status_and_len {
        for &byte in status_and_len {
            crc = crc16_byte(byte, crc);
        }
    }

    for &byte in data {
        crc = crc16_byte(byte, crc);
    }

    crc ^= CRC16_FINAL_XOR_VALUE;
    crc.swap_bytes()
}

pub fn add_crc(data: &mut [u8]) -> Result<(), Error> {
    if data.len() < 2 {
        return Err(Error::CrcDataLen);
    }

    let data_len = data[1] as usize + 2;

    if data.len() < data_len + 2 {
        return Err(Error::CrcDataCap(data_len + 2, data.len()));
    }

    let crc = crc16(&data[0..data_len], None);

    data[data_len] = (crc >> 8) as u8;
    data[data_len + 1] = (crc & 0x00FF) as u8;
    Ok(())
}

pub fn u8_slice_to_crc(crc: &[u8; 2]) -> u16 {
    u16::from_be_bytes(*crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_crc() {
        let mut data = [1, 2, 3, 4, 0, 0];
        let crc1 = crc16(&data[0..4], None);
        add_crc(&mut data).expect("unable to add crc");

        let crc2 = u8_slice_to_crc(data[4..].try_into().unwrap());
        assert_eq!(crc1, crc2);
    }
}

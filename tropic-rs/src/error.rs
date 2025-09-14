#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidCrc,
    CrcDataLen,
    CrcDataCap(usize, usize),
    TryFromSlice,
    InvalidRespLen(usize, usize),

    AlarmMode,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidCrc => f.write_str("invalid crc"),
            Self::CrcDataLen => f.write_str("data buffer must be at least 2 bytes long"),
            Self::CrcDataCap(exp, act) => f.write_fmt(format_args!(
                "insufficient data buffer capacity: expected {} bytes, got {}",
                exp, act
            )),
            Self::TryFromSlice => f.write_fmt(format_args!("unable to convert slice")),
            Self::InvalidRespLen(exp, act) => f.write_fmt(format_args!(
                "invalid response length: expected {} bytes, got {}",
                exp, act
            )),

            Self::AlarmMode => f.write_str("chip is in allarm mode"),
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(_err: core::array::TryFromSliceError) -> Self {
        Self::TryFromSlice
    }
}

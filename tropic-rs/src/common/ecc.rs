use super::Error;

/// ECC curve type
/// P256: NIST P-256
/// Ed25519: Edwards-curve Digital Security Algorithm (EdDSA) using Twisted
#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum EccCurve {
    P256 = 1,
    Ed25519 = 2,
}

impl TryFrom<u8> for EccCurve {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EccCurve::P256),
            2 => Ok(EccCurve::Ed25519),
            _ => Err(Error::InvalidEccKeyOrigin),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum EccKeyOrigin {
    Generated = 1,
    Stored = 2,
}

impl TryFrom<u8> for EccKeyOrigin {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EccKeyOrigin::Generated),
            2 => Ok(EccKeyOrigin::Stored),
            _ => Err(Error::InvalidEccKeyOrigin),
        }
    }
}

pub const ECC_KEY_SLOT_MAX: u16 = 31;

/// R memory user data slot
#[derive(Debug, Clone, PartialEq)]
pub struct EccKeySlot(u16);

impl TryFrom<u16> for EccKeySlot {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0..=ECC_KEY_SLOT_MAX => Ok(EccKeySlot(value)),
            _ => Err(Error::RMemUserDataSlotMax),
        }
    }
}

impl From<EccKeySlot> for [u8; 2] {
    fn from(value: EccKeySlot) -> Self {
        value.0.to_le_bytes()
    }
}

#[cfg(test)]
impl EccKeySlot {
    pub fn random() -> Self {
        use rand::Rng;
        let slot: u16 = rand::rng().random_range(0..=ECC_KEY_SLOT_MAX);
        EccKeySlot(slot)
    }
}

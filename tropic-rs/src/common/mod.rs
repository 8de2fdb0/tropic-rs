use crate::common::config::access_flag::AccessFlag;

pub mod config;
pub mod ecc;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPairingKeySlot,
    RMemUserDataSlotMax,
    MCounterIndexMax,
    MacAndDestroySlotMax,
    InvalidEccCurve,
    InvalidEccKeyOrigin,
}
#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidPairingKeySlot => write!(f, "Invalid pairing key slot"),
            Error::RMemUserDataSlotMax => write!(f, "R memory user data slot bigger then 511"),
            Error::MCounterIndexMax => write!(f, "Mcounter index bigger then 15"),
            Error::MacAndDestroySlotMax => write!(f, "Mac and destroy slot bigger then 127"),
            Error::InvalidEccCurve => write!(f, "Invalid ECC curve value"),
            Error::InvalidEccKeyOrigin => write!(f, "Invalid ECC key origin"),
        }
    }
}

/// Pairing key indexes corresponds to S_HiPub
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum PairingKeySlot {
    Index0 = 0,
    Index1 = 1,
    Index2 = 2,
    Index3 = 3,
}

impl TryFrom<u8> for PairingKeySlot {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PairingKeySlot::Index0),
            1 => Ok(PairingKeySlot::Index1),
            2 => Ok(PairingKeySlot::Index2),
            3 => Ok(PairingKeySlot::Index3),
            _ => Err(Error::RMemUserDataSlotMax),
        }
    }
}

impl From<PairingKeySlot> for AccessFlag {
    fn from(slot: PairingKeySlot) -> Self {
        let mut flag = AccessFlag::new();
        flag.set_bits_with_defaults(1 << slot as u8);
        flag
    }
}

impl core::ops::BitOr for PairingKeySlot {
    type Output = config::access_flag::AccessFlag;
    fn bitor(self, rhs: Self) -> Self::Output {
        let mut flag = AccessFlag::new();
        flag.set_bits_with_defaults((1 << self as u8) | (1 << rhs as u8));
        flag
    }
}

#[cfg(test)]
impl PairingKeySlot {
    pub fn random() -> Self {
        use rand::Rng;
        let slot: u8 = rand::rng().random_range(0..=4);
        match slot {
            0 => PairingKeySlot::Index0,
            1 => PairingKeySlot::Index1,
            2 => PairingKeySlot::Index2,
            _ => PairingKeySlot::Index3,
        }
    }
}

pub const R_MEM_USER_DATA_SLOT_MAX: u16 = 511;

/// R memory user data slot
#[derive(Debug, Clone, PartialEq)]
pub struct UserDataSlot(u16);

impl TryFrom<u16> for UserDataSlot {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0..=R_MEM_USER_DATA_SLOT_MAX => Ok(UserDataSlot(value)),
            _ => Err(Error::RMemUserDataSlotMax),
        }
    }
}

impl From<UserDataSlot> for [u8; 2] {
    fn from(value: UserDataSlot) -> Self {
        value.0.to_le_bytes()
    }
}

#[cfg(test)]
impl UserDataSlot {
    pub fn random() -> Self {
        use rand::Rng;
        let slot: u16 = rand::rng().random_range(0..=R_MEM_USER_DATA_SLOT_MAX);
        UserDataSlot(slot)
    }
}

pub const MCOUNTER_INDEX_MAX: u16 = 15;

#[derive(Debug, Clone, PartialEq)]
pub struct MCounterIndex(u16);

impl TryFrom<u16> for MCounterIndex {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0..=MCOUNTER_INDEX_MAX => Ok(MCounterIndex(value)),
            _ => Err(Error::MCounterIndexMax),
        }
    }
}

impl From<MCounterIndex> for [u8; 2] {
    fn from(value: MCounterIndex) -> Self {
        value.0.to_le_bytes()
    }
}

#[cfg(test)]
impl MCounterIndex {
    pub fn random() -> Self {
        use rand::Rng;
        let index: u16 = rand::rng().random_range(0..=MCOUNTER_INDEX_MAX);
        MCounterIndex(index)
    }
}

pub const MAC_AND_DESTROY_SLOT_MAX: u16 = 127;

#[derive(Debug, Clone, PartialEq)]
pub struct MacAndDestroySlot(u16);

#[cfg(feature = "display")]
impl core::fmt::Display for MacAndDestroySlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MacAndDestroySlot({})", self.0)
    }
}

impl TryFrom<u16> for MacAndDestroySlot {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0..=MAC_AND_DESTROY_SLOT_MAX => Ok(MacAndDestroySlot(value)),
            _ => Err(Error::RMemUserDataSlotMax),
        }
    }
}

impl From<&MacAndDestroySlot> for usize {
    fn from(value: &MacAndDestroySlot) -> Self {
        value.0 as usize
    }
}

impl From<&MacAndDestroySlot> for [u8; 2] {
    fn from(value: &MacAndDestroySlot) -> Self {
        value.0.to_le_bytes()
    }
}

#[cfg(test)]
impl MacAndDestroySlot {
    pub fn random() -> Self {
        use rand::Rng;
        let slot: u16 = rand::rng().random_range(0..=MCOUNTER_INDEX_MAX);
        MacAndDestroySlot(slot)
    }
}

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

use hmac::Mac as _;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing_key_slot_into_access_flag() {
        let flag: AccessFlag = PairingKeySlot::Index0.into();
        assert!(flag.pairing_key_slot0());
        assert!(!flag.pairing_key_slot1());
        assert!(!flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());

        let flag: AccessFlag = PairingKeySlot::Index1.into();
        assert!(!flag.pairing_key_slot0());
        assert!(flag.pairing_key_slot1());
        assert!(!flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());

        let flag: AccessFlag = PairingKeySlot::Index2.into();
        assert!(!flag.pairing_key_slot0());
        assert!(!flag.pairing_key_slot1());
        assert!(flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());

        let flag: AccessFlag = PairingKeySlot::Index3.into();
        assert!(!flag.pairing_key_slot0());
        assert!(!flag.pairing_key_slot1());
        assert!(!flag.pairing_key_slot2());
        assert!(flag.pairing_key_slot3());
    }

    #[test]
    fn test_pairing_key_slot_bit_or() {
        let flag = PairingKeySlot::Index0 | PairingKeySlot::Index1;
        assert!(flag.pairing_key_slot0());
        assert!(flag.pairing_key_slot1());
        assert!(!flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());

        let flag = PairingKeySlot::Index0 | PairingKeySlot::Index2;
        assert!(flag.pairing_key_slot0());
        assert!(!flag.pairing_key_slot1());
        assert!(flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());

        let flag = PairingKeySlot::Index0 | PairingKeySlot::Index2;
        assert!(flag.pairing_key_slot0());
        assert!(!flag.pairing_key_slot1());
        assert!(flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());
    }
}

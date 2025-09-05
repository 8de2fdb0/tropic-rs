use crate::common::config::access_flag::AccessFlag;

pub mod config;

/// Pairing key indexes corresponds to S_HiPub
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum PairingKeySlot {
    Index0 = 0,
    Index1 = 1,
    Index2 = 2,
    Index3 = 3,
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

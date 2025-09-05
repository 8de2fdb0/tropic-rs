use bitfields::bitfield;

use crate::common;

#[bitfield(u8)]
#[derive(PartialEq)]
pub struct AccessFlag {
    #[bits(1)]
    pub pairing_key_slot0: bool,
    #[bits(1)]
    pub pairing_key_slot1: bool,
    #[bits(1)]
    pub pairing_key_slot2: bool,
    #[bits(1)]
    pub pairing_key_slot3: bool,
    #[bits(4, default = 0xf)]
    pub reserved: u8,
}

impl core::ops::BitOr<common::PairingKeySlot> for AccessFlag {
    type Output = Self;
    fn bitor(self, rhs: common::PairingKeySlot) -> Self::Output {
        let mut flag = AccessFlag::new();
        flag.set_bits_with_defaults(self.into_bits() | 1 << rhs as u8);
        flag
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for AccessFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_list = f.debug_list();
        if self.pairing_key_slot0() {
            debug_list.entry(&"key0");
        }
        if self.pairing_key_slot1() {
            debug_list.entry(&"key1");
        }
        if self.pairing_key_slot2() {
            debug_list.entry(&"key2");
        }
        if self.pairing_key_slot3() {
            debug_list.entry(&"key3");
        }
        debug_list.finish()
    }
}

// The main macro to create the AccessFlag struct.
// It takes a variable number of PairingKeySlot variants.
// #[macro_export]
// macro_rules! __access_flag {
//     // Matches zero or more paths, separated by commas
//     ($($slots:path),*) => {
//         {
//             let mut flag = $crate::common::config::access_flag::AccessFlag::default();
//             $(
//                 // Compare each slot's discriminant with the known variants
//                 if core::mem::discriminant(&$slots) == core::mem::discriminant(&$crate::common::PairingKeySlot::Index0) {
//                     flag.set_pairing_key_slot0(true);
//                 }
//                 if core::mem::discriminant(&$slots) == core::mem::discriminant(&$crate::common::PairingKeySlot::Index1) {
//                     flag.set_pairing_key_slot1(true);
//                 }
//                 if core::mem::discriminant(&$slots) == core::mem::discriminant(&$crate::common::PairingKeySlot::Index2) {
//                     flag.set_pairing_key_slot2(true);
//                 }
//                 if core::mem::discriminant(&$slots) == core::mem::discriminant(&$crate::common::PairingKeySlot::Index3) {
//                     flag.set_pairing_key_slot3(true);
//                 }
//             )*
//             flag
//         }
//     };
// }

#[cfg(test)]
mod tests {

    use crate::common::{PairingKeySlot, config::access_flag::AccessFlag};

    #[test]
    fn test_access_flag() {
        let flag = AccessFlag::default();
        assert!(!flag.pairing_key_slot0());
        assert!(!flag.pairing_key_slot1());
        assert!(!flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());
        assert!(flag.reserved() == 0xf);

        // Test with no prefix
        let flag = PairingKeySlot::Index0 | PairingKeySlot::Index1;
        assert!(flag.pairing_key_slot0());
        assert!(flag.pairing_key_slot1());
        assert!(!flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());

        // Test with module prefix (assuming config is a valid module)
        // mod config {
        //     pub use crate::common::PairingKeySlot;
        // }
        // let flag = __access_flag!(
        //     config::PairingKeySlot::Index0,
        //     config::PairingKeySlot::Index2
        // );
        // assert!(flag.pairing_key_slot0());
        // assert!(!flag.pairing_key_slot1());
        // assert!(flag.pairing_key_slot2());
        // assert!(!flag.pairing_key_slot3());

        // Test empty list
        let flag = AccessFlag::new();
        assert!(!flag.pairing_key_slot0());
        assert!(!flag.pairing_key_slot1());
        assert!(!flag.pairing_key_slot2());
        assert!(!flag.pairing_key_slot3());
    }
}

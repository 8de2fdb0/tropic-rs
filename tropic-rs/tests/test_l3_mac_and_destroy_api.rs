mod testing_common;

use log::info;

use tropic_rs::common::PairingKeySlot;

use crate::testing_common::*;

#[test]
fn test_l3_mac_and_destroy_api() {
    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_mac_and_destroy_api")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    const U: [u8; 32] = [
        0xd6, 0xd1, 0x55, 0xdd, 0xee, 0x13, 0x83, 0x4d, 0xf2, 0xe4, 0x54, 0x77, 0xa4, 0x9c, 0xa5,
        0xc1, 0x45, 0x29, 0x38, 0x47, 0xf8, 0xfe, 0x23, 0x21, 0x51, 0x1a, 0xc4, 0x75, 0x8e, 0xd9,
        0xd9, 0x55,
    ];

    const IGNORED_1: [u8; 32] = [
        0x2c, 0x0f, 0x8c, 0xf3, 0xee, 0x46, 0x3e, 0xa2, 0x00, 0x47, 0x5f, 0xeb, 0x6f, 0x71, 0x73,
        0x89, 0xc2, 0xab, 0x0e, 0xe6, 0xe0, 0xc7, 0x59, 0xf6, 0x4f, 0x4b, 0x92, 0x76, 0xf2, 0xc1,
        0x13, 0x40,
    ];

    let slot = 0_u16.try_into().expect("failed tro create slot");

    let ignored_1 = tropic_01
        .mac_and_destroy(&mut session, &slot, &U)
        .expect("failed to execute MAC_And_Destroy");
    assert_eq!(ignored_1.data_out, IGNORED_1);
}

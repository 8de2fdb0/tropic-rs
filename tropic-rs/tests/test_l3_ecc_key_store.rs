mod testing_common;

use log::info;

use tropic_rs::{
    common::{self, PairingKeySlot},
    l3,
};

use crate::testing_common::*;

// Pre-generated keys for testing using OpenSSL
const P256_PRIV_TEST_KEY: [u8; 32] = [
    0x7d, 0x35, 0xc5, 0x0a, 0xfe, 0x9b, 0x15, 0xeb, 0x41, 0x16, 0xcb, 0x9b, 0xaa, 0xc2, 0xcb, 0xdd,
    0xbb, 0xdc, 0xb9, 0xb8, 0x77, 0xc7, 0x0f, 0x9e, 0x21, 0x8c, 0x2c, 0xff, 0xaa, 0x8b, 0x6f, 0x72,
];
const P256_PUB_TEST_KEY: [u8; 64] = [
    0x62, 0x4e, 0xeb, 0x9d, 0x01, 0x82, 0x24, 0xdd, 0x1f, 0x2a, 0xbb, 0xdc, 0x0f, 0x8f, 0xca, 0xa3,
    0xc8, 0x9c, 0x2f, 0x9a, 0x46, 0x11, 0x73, 0x8b, 0x5f, 0xcb, 0xc5, 0x5b, 0xdb, 0x51, 0x93, 0xd7,
    0x2f, 0x2e, 0x48, 0x56, 0x1b, 0x97, 0x51, 0x16, 0xc4, 0x26, 0x6e, 0x50, 0x64, 0x30, 0xbc, 0x40,
    0xbf, 0x11, 0xb5, 0xc7, 0x51, 0x8c, 0xac, 0x64, 0xb2, 0x4c, 0xc3, 0x8b, 0x80, 0x4d, 0xa5, 0x1b,
];
const ED25519_PRIV_TEST_KEY: [u8; 32] = [
    0x73, 0x5b, 0x09, 0xb9, 0x5f, 0x4e, 0x17, 0x83, 0x4f, 0xa0, 0x7e, 0x93, 0x14, 0xa8, 0x7b, 0xa8,
    0x86, 0x36, 0x00, 0x30, 0x7f, 0x90, 0xf2, 0x3d, 0x52, 0x4c, 0xac, 0x15, 0x5f, 0x94, 0x44, 0xe0,
];
const ED25519_PUB_TEST_KEY: [u8; 32] = [
    0xde, 0x86, 0x1d, 0xac, 0xc2, 0x36, 0x4a, 0xe0, 0x5f, 0xb4, 0xef, 0x3c, 0xfc, 0xc1, 0xb2, 0x41,
    0xab, 0x51, 0xdb, 0xc6, 0x38, 0xfc, 0x84, 0xb2, 0x5f, 0x04, 0xe6, 0x58, 0x5a, 0xd5, 0x3c, 0xcd,
];

// Invalid key can be checked only for P256
const P256_INVALID_PRIV_TEST_KEY: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

#[test]
fn test_l3_ecc_key_store() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_ecc_key_store")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Testing ECC_Key_Store using P256 curve...");
    for i in 0_u16..=common::ecc::ECC_KEY_SLOT_MAX {
        info!("Testing ECC key slot {}", i);

        info!("Checking if slot is empty...");
        let result =
            tropic_01.ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"));

        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::Ecc(
                l3::Status::EccInvalidKey
            )))
        );

        info!("Storing invalid private key (should fail)...");
        let result = tropic_01.ecc_key_store(
            &mut session,
            i.try_into().expect("invalid slot"),
            common::ecc::EccCurve::P256,
            &P256_INVALID_PRIV_TEST_KEY,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );

        info!("Storing private key pre-generated using P256 curve...");
        tropic_01
            .ecc_key_store(
                &mut session,
                i.try_into().expect("invalid slot"),
                common::ecc::EccCurve::P256,
                &P256_PRIV_TEST_KEY,
            )
            .expect("failed to store ECC P256 key");

        info!("Storing private key pre-generated using P256 curve again (should fail)...");
        let result = tropic_01.ecc_key_store(
            &mut session,
            i.try_into().expect("invalid slot"),
            common::ecc::EccCurve::P256,
            &P256_PRIV_TEST_KEY,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );

        info!("Storing private key pre-generated using Ed25519 curve (should fail)...");
        let result = tropic_01.ecc_key_store(
            &mut session,
            i.try_into().expect("invalid slot"),
            common::ecc::EccCurve::Ed25519,
            &ED25519_PRIV_TEST_KEY,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );

        info!("Reading the stored public key...");
        let resp = tropic_01
            .ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read public key");

        let pubkey = resp.pubkey();
        info!("Public key: {:x?}", pubkey);
        assert_eq!(pubkey, P256_PUB_TEST_KEY);
        assert_eq!(pubkey.len(), 64);
        assert_eq!(resp.curve, common::ecc::EccCurve::P256);
        assert_eq!(resp.origin, common::ecc::EccKeyOrigin::Stored);

        info!("Erasing the slot...");
        tropic_01
            .ecc_key_erase(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to erase key");
    }

    info!("Testing ECC_Key_Store using Ed25519 curve...");
    for i in 0_u16..=common::ecc::ECC_KEY_SLOT_MAX {
        info!("Testing ECC key slot {}", i);

        info!("Checking if slot is empty...");
        let result =
            tropic_01.ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"));

        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::Ecc(
                l3::Status::EccInvalidKey
            )))
        );

        info!("Storing private key pre-generated using Ed25519 curve...");
        tropic_01
            .ecc_key_store(
                &mut session,
                i.try_into().expect("invalid slot"),
                common::ecc::EccCurve::Ed25519,
                &ED25519_PRIV_TEST_KEY,
            )
            .expect("failed to store ECC Ed25519 key");

        info!("Storing private key pre-generated using Ed25519 curve again (should fail)...");
        let result = tropic_01.ecc_key_store(
            &mut session,
            i.try_into().expect("invalid slot"),
            common::ecc::EccCurve::Ed25519,
            &ED25519_PRIV_TEST_KEY,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );

        info!("Storing private key pre-generated using P256 curve (should fail)...");
        let result = tropic_01.ecc_key_store(
            &mut session,
            i.try_into().expect("invalid slot"),
            common::ecc::EccCurve::P256,
            &P256_PRIV_TEST_KEY,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );

        info!("Reading the stored public key...");
        let resp = tropic_01
            .ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read public key");

        let pubkey = resp.pubkey();
        info!("Public key: {:x?}", pubkey);
        assert_eq!(pubkey, ED25519_PUB_TEST_KEY);
        assert_eq!(pubkey.len(), 32);
        assert_eq!(resp.curve, common::ecc::EccCurve::Ed25519);
        assert_eq!(resp.origin, common::ecc::EccKeyOrigin::Stored);

        info!("Erasing the slot...");
        tropic_01
            .ecc_key_erase(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to erase key");

        info!("Trying to read the erased slot (should fail)...");
        let result =
            tropic_01.ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"));
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::Ecc(
                l3::Status::EccInvalidKey
            )))
        );
    }

    model_server.cleanup();
}

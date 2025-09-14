mod testing_common;

use log::info;

use tropic_rs::{
    common::{self, PairingKeySlot},
    l3,
};

use crate::testing_common::*;

#[test]
fn test_l3_ecc_key_generate() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_ecc_key_generate")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Testing ECC_Key_Generate using P256 curve...");
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

        info!("Generating private key using P256 curve...");
        tropic_01
            .ecc_key_generate(
                &mut session,
                i.try_into().expect("invalid slot"),
                common::ecc::EccCurve::P256,
            )
            .expect("failed to generate ECC P256 key");

        info!("Generating private key using P256 curve again (should fail)...");
        let result = tropic_01.ecc_key_generate(
            &mut session,
            i.try_into().expect("invalid slot"),
            common::ecc::EccCurve::P256,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );

        info!("Reading the generated public key...");
        let resp = tropic_01
            .ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read public key");

        let pubkey = resp.pubkey();
        info!("Public key: {:x?}", pubkey);
        assert_ne!(pubkey, [0u8; 64]);
        assert_eq!(pubkey.len(), 64);
        assert_eq!(resp.curve, common::ecc::EccCurve::P256);
        assert_eq!(resp.origin, common::ecc::EccKeyOrigin::Generated);

        info!("Erasing the slot...");
        tropic_01
            .ecc_key_erase(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to erase key");
    }

    info!("Testing ECC_Key_Generate using Ed25519 curve...");

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

        info!("Generating private key using Ed25519 curve...");
        tropic_01
            .ecc_key_generate(
                &mut session,
                i.try_into().expect("invalid slot"),
                common::ecc::EccCurve::Ed25519,
            )
            .expect("failed to generate ECC P256 key");

        info!("Generating private key using Ed25519 curve again (should fail)...");
        let result = tropic_01.ecc_key_generate(
            &mut session,
            i.try_into().expect("invalid slot"),
            common::ecc::EccCurve::Ed25519,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );

        info!("Reading the generated public key...");
        let resp = tropic_01
            .ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read public key");

        let pubkey = resp.pubkey();
        info!("Public key: {:x?}", pubkey);
        assert_ne!(pubkey, [0u8; 32]);
        assert_eq!(pubkey.len(), 32);
        assert_eq!(resp.curve, common::ecc::EccCurve::Ed25519);
        assert_eq!(resp.origin, common::ecc::EccKeyOrigin::Generated);

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

mod testing_common;

use log::info;
use p256::{
    EncodedPoint,
    ecdsa::{self, Signature as P256Signature, VerifyingKey, signature::Verifier},
};

use tropic_rs::{
    common::{self, PairingKeySlot},
    l3,
};

use crate::testing_common::*;

const MSG_TO_SIGN_LEN_MAX: usize = 4096;

// Pre-generated keys for testing using OpenSSL
const PRIV_TEST_KEY: [u8; 32] = [
    0x5e, 0xc6, 0xf1, 0xef, 0x96, 0x1f, 0x69, 0xb5, 0xd4, 0x34, 0xe1, 0x50, 0x6e, 0xa1, 0xcc, 0x51,
    0x11, 0x91, 0x94, 0x65, 0x87, 0xcb, 0x36, 0x82, 0x24, 0x07, 0x70, 0x32, 0x10, 0x1d, 0x62, 0xd1,
];

fn ecdsa_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, ecdsa::Error> {
    let encoded_point = EncodedPoint::from_untagged_bytes(pubkey.into());
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)?;
    let signature = P256Signature::from_bytes(signature.into())?;

    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[test]
fn test_l3_ecdsa_sign() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_ecdsa_sign")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Test ECDSA_Sign with stored key...");
    for i in 0_u16..=common::ecc::ECC_KEY_SLOT_MAX {
        info!("Testing signing with ECC key slot {}...", i);

        info!("Generating random message...");
        let msg_to_sign = rand_bytes(rand::random_range(0..MSG_TO_SIGN_LEN_MAX));

        info!("Signing message with empty slot (should fail)...");
        let result = tropic_01.ecc_ecdsa_sign(
            &mut session,
            i.try_into().expect("invalid slot"),
            &msg_to_sign,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::Ecc(
                l3::Status::EccInvalidKey
            )))
        );

        info!("Storing private key using P256 curve...");
        tropic_01
            .ecc_key_store(
                &mut session,
                i.try_into().expect("invalid slot"),
                common::ecc::EccCurve::P256,
                &PRIV_TEST_KEY,
            )
            .expect("failed to store ECC P256 key");

        info!("Reading the stored public key...");
        let ecc_key_resp = tropic_01
            .ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read public key");

        info!("Signing the message...");
        let sign_resp = tropic_01
            .ecc_ecdsa_sign(
                &mut session,
                i.try_into().expect("invalid slot"),
                &msg_to_sign,
            )
            .expect("failed to sign message");

        info!("Verifying the signature...");
        ecdsa_verify(ecc_key_resp.pubkey(), &msg_to_sign, &sign_resp.signature())
            .expect("msg verification failed");

        info!("Erasing the slot...");
        tropic_01
            .ecc_key_erase(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to erase key");

        info!("Signing message with erased slot (should fail)...");
        let result = tropic_01.ecc_ecdsa_sign(
            &mut session,
            i.try_into().expect("invalid slot"),
            &msg_to_sign,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::Ecc(
                l3::Status::EccInvalidKey
            )))
        );
    }

    info!("Test ECDSA_Sign with generated key...");
    for i in 0_u16..=common::ecc::ECC_KEY_SLOT_MAX {
        info!("Testing signing with ECC key slot {}...", i);

        info!("Generating random message...");
        let msg_to_sign = rand_bytes(rand::random_range(0..MSG_TO_SIGN_LEN_MAX));

        info!("Signing message with empty slot (should fail)...");
        let result = tropic_01.ecc_ecdsa_sign(
            &mut session,
            i.try_into().expect("invalid slot"),
            &msg_to_sign,
        );
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
            .expect("failed to store ECC P256 key");

        info!("Reading the generated public key...");
        let ecc_key_resp = tropic_01
            .ecc_key_read_pubkey(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read public key");

        info!("Signing the message...");
        let sign_resp = tropic_01
            .ecc_ecdsa_sign(
                &mut session,
                i.try_into().expect("invalid slot"),
                &msg_to_sign,
            )
            .expect("failed to sign message");

        info!("Verifying the signature...");
        ecdsa_verify(ecc_key_resp.pubkey(), &msg_to_sign, &sign_resp.signature())
            .expect("msg verification failed");

        info!("Erasing the slot...");
        tropic_01
            .ecc_key_erase(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to erase key");

        info!("Signing message with erased slot (should fail)...");
        let result = tropic_01.ecc_ecdsa_sign(
            &mut session,
            i.try_into().expect("invalid slot"),
            &msg_to_sign,
        );
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

mod testing_common;

use log::info;

use tropic_rs::{
    common::PairingKeySlot,
    l3::{self},
};

use crate::testing_common::*;

#[test]
fn test_l3_pairing_key_slots() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_pairing_key_slots")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    // Read pairing keys (1,2,3 should be empty)
    info!("Reading pairing key slot 0...");
    let pairing_key0 = tropic_01
        .pairing_key_read(&mut session, PairingKeySlot::Index0)
        .expect("failed to read pairing key slot 0");
    info!("Pairing key slot 0: {}", pairing_key0);

    for i in 1..4 {
        info!("Reading pairing key slot {} (should fail)...", i);
        let result = tropic_01.pairing_key_read(&mut session, i.try_into().expect("invalid slot"));
        assert!(result.is_err());

        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::PairingKey(
                l3::Status::PairingKeyEmpty
            )))
        );
    }

    // Write pairing keys into slot 1,2,3
    for i in 1..4 {
        info!("Writing to pairing key slot {}", i);
        tropic_01
            .pairing_key_write(
                &mut session,
                i.try_into().expect("invalid slot"),
                &Into::<SamplePairingKey>::into(i).to_x25519_pubkey(),
            )
            .expect("failed to write pairing key");
    }

    // Read all pairing keys and check value
    for i in 0..4 {
        info!("Reading pairing key slot {}...", i);
        let pairing_key = tropic_01
            .pairing_key_read(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read pairing key slot");
        info!("Pairing key slot {}: {}", i, pairing_key);

        assert_eq!(
            &pairing_key.s_hipub,
            Into::<SamplePairingKey>::into(i)
                .to_x25519_pubkey()
                .as_bytes()
        );
    }

    tropic_01.abort_session().expect("failed to abort session");

    // Test secure session with slots 1,2,3
    for i in 1..4 {
        info!("Starting Secure Session with key {}", i);
        let _ = get_tropic_test_session(
            &mut tropic_01,
            Into::<SamplePairingKey>::into(i).to_x25519_secret(),
            i.try_into().expect("invalid slot"),
        );

        info!("Aborting Secure Session with slot {}", i);
        tropic_01.abort_session().expect("failed to abort session");
    }

    info!("Starting Secure Session with key 0",);
    let mut session = get_tropic_test_session(
        &mut tropic_01,
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
    );

    // Write pairing key slots again (should fail)
    for i in 0..4 {
        info!("Writing to pairing key slot {} (should fail)", i);
        let result = tropic_01.pairing_key_write(
            &mut session,
            i.try_into().expect("invalid slot"),
            &Into::<SamplePairingKey>::into(i).to_x25519_pubkey(),
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );

        info!("Reading pairing key slot {}...", i);
        let pairing_key = tropic_01
            .pairing_key_read(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read pairing key slot");
        info!("Pairing key slot {}: {}", i, pairing_key);

        info!("Comparing contents of expected key and read key...");
        assert_eq!(
            &pairing_key.s_hipub,
            Into::<SamplePairingKey>::into(i)
                .to_x25519_pubkey()
                .as_bytes()
        );
    }

    // Invalidate all slots, try reading and writing them
    for i in 0..4 {
        info!("Invalidating pairing key slot {}", i);
        tropic_01
            .pairing_key_invalidate(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to invalidate pairing key slot");

        info!("Reading pairing key slot {} (should fail)...", i);
        let result = tropic_01.pairing_key_read(&mut session, i.try_into().expect("invalid slot"));
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::PairingKey(
                l3::Status::PairingKeyInvalid
            )))
        );

        info!("Writing to pairing key slot {} (should fail)...", i);
        let result = tropic_01.pairing_key_write(
            &mut session,
            i.try_into().expect("invalid slot"),
            &Into::<SamplePairingKey>::into(i).to_x25519_pubkey(),
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(l3::Error::RespErr(l3::Status::Fail)))
        );
    }

    model_server.cleanup();
}

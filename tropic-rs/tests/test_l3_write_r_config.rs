mod common;

use log::info;

use tropic_rs::{
    common::{PairingKeySlot, config},
    l3::EncSession,
};

use crate::common::*;

fn random_config() -> config::Config {
    config::Config {
        bootloader: config::bootloader::Bootloader {
            start_up: config::bootloader::StartUp::from_bits_retain(rand::random()),
            sensor: config::bootloader::Sensor::from_bits_retain(rand::random()),
            debug: config::bootloader::Debug::from_bits_retain(rand::random()),
        },
        application: config::application::Application {
            gpo: config::application::Gpo::from_bits(rand::random()),
            sleep_mode: config::application::SleepMode::from_bits_retain(rand::random()),
        },
        application_uap: config::application_uap::ApplicationUap {
            pairing_key_write: config::application_uap::PairingKeyWrite::from_bits(rand::random()),
            pairing_key_read: config::application_uap::PairingKeyRead::from_bits(rand::random()),
            pairing_key_invalidate: config::application_uap::PairingKeyInvalidate::from_bits(
                rand::random(),
            ),
            r_config_write_erase: config::application_uap::RConfigWriteErase::from_bits(
                rand::random(),
            ),
            r_config_read: config::application_uap::RConfigRead::from_bits(rand::random()),
            i_config_write: config::application_uap::IConfigWrite::from_bits(rand::random()),
            i_config_read: config::application_uap::IConfigRead::from_bits(rand::random()),
            ping: config::application_uap::Ping::from_bits(rand::random()),
            r_mem_data_write: config::application_uap::RMemDataWrite::from_bits(rand::random()),
            r_mem_data_read: config::application_uap::RMemDataRead::from_bits(rand::random()),
            r_mem_data_erase: config::application_uap::RMemDataErase::from_bits(rand::random()),
            random_value_get: config::application_uap::RandomValueGet::from_bits(rand::random()),
            ecc_key_generate: config::application_uap::EccKeyGenerate::from_bits(rand::random()),
            ecc_key_store: config::application_uap::EccKeyStore::from_bits(rand::random()),
            ecc_key_read: config::application_uap::EccKeyRead::from_bits(rand::random()),
            ecc_key_erase: config::application_uap::EccKeyErase::from_bits(rand::random()),
            ecdsa_sign: config::application_uap::EcdsaSign::from_bits(rand::random()),
            eddsa_sifn: config::application_uap::EddsaSign::from_bits(rand::random()),
            mcounter_init: config::application_uap::McounterInit::from_bits(rand::random()),
            mcounter_get: config::application_uap::McounterGet::from_bits(rand::random()),
            mcounter_update: config::application_uap::McounterUpdate::from_bits(rand::random()),
            mac_and_destroy: config::application_uap::MacAndDestroy::from_bits(rand::random()),
        },
    }
}

fn cleanup<'a>(
    tropic_01: &'a mut Tropic01Instance,
    session: &'a mut EncSession,
    r_config_backup: config::Config,
) {
    info!("Running cleanup.");
    info!("Erasing R config, so it can be restored.");
    tropic_01
        .r_config_erase(session)
        .expect("failed to erase r config");

    info!("Writing the whole R config backup");
    tropic_01
        .r_config_write(session, &r_config_backup)
        .expect("failed to write r config");

    info!("Reading the whole R config and assering if restored correctly");
    let r_config_read = tropic_01
        .r_config_read(session)
        .expect("failed to read r config");
    assert_eq!(r_config_backup, r_config_read);

    let _ = tropic_01.abort_session().expect("failed to abort session");
}

#[test]
fn test_write_r_config() {
    setup_logging();

    info!("Creating randomized R config for testing");
    let model_cfg = ModelCfgBuilder::default()
        .r_config(
            RIConfigBuilder::default()
                // set READ_CFG and READ_FUNC to 1 so the test can actually read/write/erase the config
                .cfg_uap_r_config_read(0b11110000111100001111000111110001)
                .cfg_uap_r_config_write_erase(0b11110000111100001111000111110001)
                .build()
                .expect("failed to build r_config"),
        )
        .build()
        .expect("failed to build model_cfg");

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_write_r_config")
        .model_cfg(model_cfg.clone())
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Creating randomized R config for testing");
    let r_config_random = random_config();

    info!("Backing up the whole R config:");
    let r_config_backup = tropic_01
        .r_config_read(&mut session)
        .expect("failed to read r config");
    info!("Backed up r config: {:#}", r_config_backup);

    let mut cleanup_guard =
        CleanupGuard::new(tropic_01, session, |t, s| cleanup(t, s, r_config_backup));

    info!("Erasing R config, so it can be written.");

    cleanup_guard.run(|tropic_01, session| {
        tropic_01
            .r_config_erase(session)
            .expect("failed to erase r config");
        info!("Writing the whole R config");
        tropic_01
            .r_config_write(session, &r_config_random)
            .expect("failed to write r config");

        info!("Reading the whole R config");
        let r_config_read = tropic_01
            .r_config_read(session)
            .expect("failed to read r config");
        assert_eq!(r_config_random, r_config_read);

        info!("Writing the whole R config again (should fail)");
        let resp = tropic_01.r_config_write(session, &r_config_random);
        assert!(resp.is_err());

        info!("Reading the whole R config");
        let r_config_read = tropic_01
            .r_config_read(session)
            .expect("failed to read r config");
        assert_eq!(r_config_random, r_config_read);
    });
    cleanup_guard.disarm();

    cleanup_guard.run(|tropic_01, session| {
        cleanup(tropic_01, session, r_config_backup);
    });

    model_server.cleanup();
}

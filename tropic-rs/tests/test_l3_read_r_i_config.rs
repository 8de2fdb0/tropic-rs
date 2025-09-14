mod testing_common;

use log::info;

use tropic_rs::common::{PairingKeySlot, config::Config};

use crate::testing_common::*;

#[test]
fn test_l3_read_r_config() {
    setup_logging();

    info!("Creating randomized R config for testing");
    let model_cfg = ModelCfgBuilder::default()
        .r_config(
            RIConfigBuilder::random()
                // set READ_CFG and READ_FUNC to 1 so the test can actually read the config
                .cfg_uap_r_config_read(0b11110000111100001111000111110001)
                .build()
                .expect("failed to build r_config"),
        )
        .build()
        .expect("failed to build model_cfg");

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_read_r_config")
        .model_cfg(model_cfg.clone())
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Reading the whole R config:");
    let whole_r_config = tropic_01
        .r_config_read(&mut session)
        .expect("failed to read config");

    info!("Comparing PairingKeyWrite:");
    let expected_cfg: Config = model_cfg.r_config.unwrap_or_default().into();

    assert_eq!(expected_cfg.bootloader, whole_r_config.bootloader);
    assert_eq!(expected_cfg.application, whole_r_config.application);
    assert_eq!(expected_cfg.application_uap, whole_r_config.application_uap);

    model_server.cleanup();
}

#[test]
fn test_l3_read_i_config() {
    setup_logging();

    info!("Creating randomized R config for testing");
    let model_cfg = ModelCfgBuilder::default()
        .i_config(
            // set READ_CFG and READ_FUNC to 1 so the test can actually read the config
            RIConfigBuilder::random()
                .cfg_uap_i_config_read(0b11110000111100001111000111110001)
                .build()
                .expect("failed to build i_config"),
        )
        .build()
        .expect("failed to build model_cfg");

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_read_i_config")
        .model_cfg(model_cfg.clone())
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Reading the whole I config:");
    let whole_i_config = tropic_01
        .i_config_read(&mut session)
        .expect("failed to read config");

    info!("Comparing PairingKeyWrite:");
    let expected_cfg: Config = model_cfg.i_config.unwrap_or_default().into();

    assert_eq!(expected_cfg.bootloader, whole_i_config.bootloader);
    assert_eq!(expected_cfg.application, whole_i_config.application);
    assert_eq!(expected_cfg.application_uap, whole_i_config.application_uap);

    model_server.cleanup();
}

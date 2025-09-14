mod testing_common;

use log::info;

use tropic_rs::common::PairingKeySlot;

use crate::testing_common::*;

#[test]
fn test_l3_erase_r_config() {
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
        .test_name("test_l3_write_r_config")
        .model_cfg(model_cfg.clone())
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Erasing R config, so it can be written.");
    tropic_01
        .r_config_erase(&mut session)
        .expect("failed to erase r config");

    info!("Reading the whole R config");
    let r_config_read = tropic_01
        .r_config_read(&mut session)
        .expect("failed to read r config");

    for entry in r_config_read.iter() {
        assert_eq!(entry.value, 0xffffffff);
    }

    model_server.cleanup();
}

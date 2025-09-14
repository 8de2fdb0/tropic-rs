mod testing_common;

use log::info;

use tropic_rs::common::PairingKeySlot;

use crate::testing_common::*;

#[test]
fn test_l3_write_i_config() {
    setup_logging();

    info!("Creating randomized R config for testing");
    let model_cfg = ModelCfgBuilder::default()
        .r_config(
            RIConfigBuilder::default()
                // set READ_CFG and READ_FUNC to 1 so the test can actually read/write/erase the config
                .cfg_uap_i_config_read(0b11110000111100001111000111110001)
                .cfg_uap_i_config_write(0b11110000111100001111000111110001)
                .build()
                .expect("failed to build r_config"),
        )
        .build()
        .expect("failed to build model_cfg");

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_write_i_config")
        .model_cfg(model_cfg.clone())
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Creating randomized I config for testing");
    let i_config_random = testing_common::config::generate_random_config();

    info!("Writing the whole I config");
    tropic_01
        .i_config_write(&mut session, &i_config_random)
        .expect("failed to write i config");

    info!("Reading the whole I config");
    let i_config_read = tropic_01
        .i_config_read(&mut session)
        .expect("failed to read r config");
    assert_eq!(i_config_random, i_config_read);

    model_server.cleanup();
}

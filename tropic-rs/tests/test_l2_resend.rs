mod testing_common;

use log::info;
use tropic_rs::l2;

use crate::testing_common::*;

#[test]
fn test_l2_resend() {
    setup_logging();

    info!("Creating randomized R config for testing");
    let model_cfg = ModelCfgBuilder::default()
        .r_config(
            RIConfigBuilder::default()
                .build()
                .expect("failed to build r_config"),
        )
        .build()
        .expect("failed to build model_cfg");

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l2_resend")
        .model_cfg(model_cfg.clone())
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let mut tropic_01 = get_tropic_test_instance(model_server.port().expect("failed to get port"));

    info!("Rebooting into Application mode...");
    tropic_01
        .restart(l2::startup::RestartMode::Reboot)
        .expect("failed to reboot");

    info!("Sending L2 Get_Info_Req...");
    let info = tropic_01.get_chip_id().expect("failed to get chip id");

    let resend_info: l2::info::ChipId = tropic_01
        .resend_response()
        .expect("failed to resend response");

    assert_eq!(info, resend_info);

    info!("Rebooting into Maintanance mode...");
    tropic_01
        .restart(l2::startup::RestartMode::Maintanance)
        .expect("failed to reboot");

    info!("Sending L2 Get_Info_Req...");
    let info = tropic_01.get_chip_id().expect("failed to get chip id");

    let resend_info: l2::info::ChipId = tropic_01
        .resend_response()
        .expect("failed to resend response");

    assert_eq!(info, resend_info);

    model_server.cleanup();
}

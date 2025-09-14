mod testing_common;

use log::info;
use tropic_rs::{
    common::{PairingKeySlot, config},
    l2,
};

use crate::testing_common::*;

#[test]
fn test_l2_log_enabled() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l2_log_enabled")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let mut tropic_01 = get_tropic_test_instance(model_server.port().expect("failed to get port"));

    info!("Rebooting into Application mode...");
    tropic_01
        .restart(l2::startup::RestartMode::Reboot)
        .expect("failed to reboot");

    info!("Starting Secure Session with key 0");
    let mut session = get_tropic_test_session(
        &mut tropic_01,
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
    );

    info!("Reading CFG_DEBUG from R config...");
    let r_config_cfg_debug = tropic_01
        .r_config_read_value(&mut session, &config::bootloader::DebugRegAddr)
        .expect("failed to read i_config");

    info!("Reading CFG_DEBUG from I config...");
    let i_config_cfg_debug = tropic_01
        .i_config_read_value(&mut session, &config::bootloader::DebugRegAddr)
        .expect("failed to read i_config");

    tropic_01.abort_session().expect("failed to abort session");

    let log_resp = tropic_01
        .get_riscv_firmware_log()
        .expect("failed to get log");

    assert_eq!(
        r_config_cfg_debug.value.bits(),
        0b11111111111111111111111111111111
    );
    assert_eq!(
        i_config_cfg_debug.value.bits(),
        0b11111111111111111111111111111111
    );
    if log_resp.len > 0 {
        info!("RISC-V FW log: {}", log_resp);
    } else {
        info!("RISC-V FW log is empty");
    }

    model_server.cleanup();
}

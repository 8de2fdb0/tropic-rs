mod common;

use log::info;
use tropic_rs::{l1, l2};

use crate::common::*;

#[test]
fn test_reboot() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_reboot")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let mut tropic_01 = get_tropic_test_instance(model_server.port().expect("failed to get port"));

    info!("Checking we are in the normal mode...");
    let chip_status = tropic_01
        .get_chip_status()
        .expect("failed to get chip mode");
    assert_eq!(chip_status.chip_mode(), l1::ChipMode::Application);

    info!("Rebooting to the normal mode...");
    tropic_01
        .restart(l2::restart::RestartMode::Reboot)
        .expect("failed to reboot");

    info!("Checking we are again in the normal mode...");
    let chip_status = tropic_01
        .get_chip_status()
        .expect("failed to get chip mode");
    assert_eq!(chip_status.chip_mode(), l1::ChipMode::Application);

    // Part 2: Try to reboot from normal to bootloader and from bootloader to bootloader.
    for _ in 0..2 {
        info!("Rebooting to the bootloader mode (maintenance reboot)...");
        tropic_01
            .restart(l2::restart::RestartMode::Maintanance)
            .expect("failed to reboot");
        info!("Checking we are in the bootloader mode...");

        // TODO: looks like this part doesn't work with tv-tsl
        //       maybe implement integration tests against real hardware

        // let chip_status = tropic_01
        //     .get_chip_status()
        //     .expect("failed to get chip mode");
        // assert_eq!(chip_status.chip_mode(), l1::ChipMode::Startup);

        // let resp =
        //     tropic_01.create_session(&mut rng, &sh_secret, payringkey_slot.clone(), &st_pubkey);
        // assert!(resp.is_err())
    }

    info!("Rebooting to the normal mode...");
    tropic_01
        .restart(l2::restart::RestartMode::Reboot)
        .expect("failed to reboot");

    info!("Checking we are again in the normal mode...");
    let chip_status = tropic_01
        .get_chip_status()
        .expect("failed to get chip mode");
    assert_eq!(chip_status.chip_mode(), l1::ChipMode::Application);

    model_server.cleanup();
}

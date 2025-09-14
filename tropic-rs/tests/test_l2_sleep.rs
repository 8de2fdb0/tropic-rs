mod testing_common;

use log::info;

use tropic_rs::{common::PairingKeySlot, l2, l3};

use crate::testing_common::*;

#[test]
fn test_l2_sleep() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l2_sleep")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Sending Sleep_Req...");

    tropic_01
        .sleep(l2::sleep::SleepKind::Regular)
        .expect("failed to sleep");

    info!("Verifying we are not in Secure Session...");
    let result = tropic_01.ping(&mut session, &[b't', b'e', b's', b't']);

    assert!(result.is_err());
    assert_eq!(
        result.err(),
        Some(tropic_rs::Error::L3(l3::Error::L2(
            tropic_rs::l2::Error::NoSession
        )))
    );

    info!("Waking the chip up by sending dummy L2 request...");
    let _ = tropic_01
        .get_chip_status()
        .expect("failed to get chip mode");

    model_server.cleanup();
}

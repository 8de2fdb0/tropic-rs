mod testing_common;

use log::info;

use tropic_rs::common::PairingKeySlot;

use crate::testing_common::*;

#[test]
fn test_l3_handshake() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_handshake")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    info!("Part 1/3: Start and abort Secure Session.");
    let (mut tropic_01, _session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );
    tropic_01.abort_session().expect("failed to abort session");

    info!("Part 2/3: Start Secure Session multiple times without aborting.");
    for i in 0..3 {
        info!("Starting Secure Session attempt #{}...", i);
        let _ = get_tropic_test_session(
            &mut tropic_01,
            SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
            PairingKeySlot::Index0,
        );
    }

    info!("Part 3/3: Abort Secure Session multiple times.");
    for i in 0..3 {
        info!("Aborting Secure Session attempt #{}...", i);
        tropic_01.abort_session().expect("failed to abort session");
    }

    model_server.cleanup();
}

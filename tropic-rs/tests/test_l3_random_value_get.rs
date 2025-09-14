mod testing_common;

use log::info;

use rand::Rng;
use tropic_rs::{common::PairingKeySlot, l3::random::RANDOM_VALUE_GET_LEN_MAX};

use crate::testing_common::*;

const RANDOM_VALUE_GET_LOOPS: usize = 150;

#[test]
fn test_l3_random_value_get() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_random_value_get")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!(
        "Random_Value_Get will be executed {} times with max length {}...",
        RANDOM_VALUE_GET_LOOPS, RANDOM_VALUE_GET_LEN_MAX
    );
    for i in 0..RANDOM_VALUE_GET_LOOPS {
        info!("Getting random value... loop #{}", i);
        let resp = tropic_01
            .random_value(&mut session, RANDOM_VALUE_GET_LEN_MAX as u8)
            .expect("failed to get random value");
        assert_eq!(resp.len, RANDOM_VALUE_GET_LEN_MAX as u16);
        info!("Random value: {:02x?}", resp.random_data);
    }

    info!(
        "Random_Value_Get  will be executed {} times with length < {}...",
        RANDOM_VALUE_GET_LOOPS, RANDOM_VALUE_GET_LEN_MAX
    );
    for i in 0..RANDOM_VALUE_GET_LOOPS {
        let n_bytes = rand::rng().random_range(1..=RANDOM_VALUE_GET_LEN_MAX as u8);
        info!(
            "Getting random value... loop #{} with length {}...",
            i, n_bytes
        );
        let resp = tropic_01
            .random_value(&mut session, n_bytes)
            .expect("failed to get random value");
        assert_eq!(resp.len, n_bytes as u16);
        assert_eq!(resp.random_data().len(), n_bytes as usize);
        info!("Random value: {:02x?}", resp.random_data());
    }

    model_server.cleanup();
}

mod testing_common;

use log::info;
use rand::Rng;

use tropic_rs::common::{MCOUNTER_INDEX_MAX, PairingKeySlot};

use crate::testing_common::*;

const MAX_DECREMENTS: u32 = 100;

#[test]
fn test_l3_mcounter() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_mcounter")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    for i in 0..MCOUNTER_INDEX_MAX {
        info!("Initializing monotonic counter {} to zero...", i);
        tropic_01
            .mcounter_init(&mut session, i.try_into().expect("invalid slot"), 0)
            .expect("failed to init mcounter");
    }

    info!("Starting basic test...");
    for i in 0..MCOUNTER_INDEX_MAX {
        info!("Generating random init value...");

        let init_value = rand::rng().random::<u32>();

        info!("Initializing monotonic counter {} with {}", i, init_value);
        tropic_01
            .mcounter_init(
                &mut session,
                i.try_into().expect("invalid slot"),
                init_value,
            )
            .expect("failed to init mcounter");

        info!(
            "Initializing monotonic counter {} again (should be ok)...",
            i,
        );
        tropic_01
            .mcounter_init(
                &mut session,
                i.try_into().expect("invalid slot"),
                init_value,
            )
            .expect("failed to init mcounter again");

        info!("Trying a few decrements...");
        for j in 0..MAX_DECREMENTS {
            info!("Reading mcounter {} value...", i);

            let mc_resp = tropic_01
                .mcounter_get(&mut session, i.try_into().expect("invalid slot"))
                .expect("failed to read mcounter");
            info!("MCounter index {}: {}", i, mc_resp.mcounter);
            assert_eq!(mc_resp.mcounter, init_value - j);

            info!("Decrementing...");
            tropic_01
                .mcounter_update(&mut session, i.try_into().expect("invalid slot"))
                .expect("failed to decrement mcounter");
        }
    }

    info!("Starting decrement to zero test...");
    for i in 0..MCOUNTER_INDEX_MAX {
        info!("Generating random small init value..");
        let init_value = rand::rng().random_range(1..100);

        info!("Initializing monotonic counter {} with {}", i, init_value);
        tropic_01
            .mcounter_init(
                &mut session,
                i.try_into().expect("invalid slot"),
                init_value,
            )
            .expect("failed to init mcounter");

        info!("Decrementing to zero...");
        for j in 0..init_value {
            info!("Reading mcounter {} value...", i);
            let mc_resp = tropic_01
                .mcounter_get(&mut session, i.try_into().expect("invalid slot"))
                .expect("failed to read mcounter");
            info!("MCounter index {}: {}", i, mc_resp.mcounter);
            assert_eq!(mc_resp.mcounter, init_value - j);

            info!("Decrementing...");
            tropic_01
                .mcounter_update(&mut session, i.try_into().expect("invalid slot"))
                .expect("failed to decrement mcounter");
        }
    }

    // Assignment test: Assign each counter a known value and check
    // whether any counter was not overwritten. This will test
    // that there are no indexing problems.
    info!("Starting assignment test...");
    for i in 0..MCOUNTER_INDEX_MAX {
        info!("Initializing monotonic counter {} with {}...", i, i);
        tropic_01
            .mcounter_init(&mut session, i.try_into().expect("invalid slot"), i as u32)
            .expect("failed to init mcounter");
    }
    for i in 0..MCOUNTER_INDEX_MAX {
        let mc_resp: tropic_rs::l3::mcounter::MCounterGetResp = tropic_01
            .mcounter_get(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read mcounter");
        info!("MCounter index {}: {}", i, mc_resp.mcounter);
        assert_eq!(mc_resp.mcounter, i as u32);
    }

    model_server.cleanup();
}

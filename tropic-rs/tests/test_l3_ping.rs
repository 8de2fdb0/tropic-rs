mod common;

use log::info;

use rand::RngCore;
use tropic_rs::{
    common::PairingKeySlot,
    l2,
    l3::ping::{PING_CMD_DATA_LEN_MAX, PING_CMD_DATA_LEN_MIN},
};

use crate::common::*;

const PING_MAX_LOOPS: usize = 200;

fn rand_msg(len: usize) -> Vec<u8> {
    let mut msg = vec![0_u8; len];
    rand::rng().fill_bytes(&mut msg);
    msg
}

#[test]
fn test_ping() {
    setup_logging();

    info!("Creating randomized R config for testing");
    let model_cfg = ModelCfgBuilder::default()
        .r_config(
            RIConfigBuilder::default()
                .cfg_uap_ping(0b11110000111100001111000111110001)
                .build()
                .expect("failed to build model r_config"),
        )
        .build()
        .expect("failed to build model config");

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_ping")
        .model_cfg(model_cfg)
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Pinging... min boundary check with len: {PING_CMD_DATA_LEN_MIN}");
    let ping = rand_msg(PING_CMD_DATA_LEN_MIN);
    let pong = tropic_01.ping(&mut session, &ping).expect("Failed to ping");
    assert_eq!(ping, pong.msg[..ping.len()]);

    info!("Pinging... max boundary check with len: {PING_CMD_DATA_LEN_MAX}");
    let ping = rand_msg(PING_CMD_DATA_LEN_MAX);
    let pong = tropic_01.ping(&mut session, &ping).expect("Failed to ping");
    assert_eq!(ping, pong.msg[..ping.len()]);

    info!("Will send {PING_MAX_LOOPS} Ping commands with random data of random length");
    for i in 0..PING_MAX_LOOPS {
        let ping = rand_msg(rand::random_range(0..PING_CMD_DATA_LEN_MAX));
        info!("Pinging... {i} with message_len {}", ping.len());
        let pong = tropic_01.ping(&mut session, &ping).expect("Failed to ping");

        assert_eq!(ping, pong.msg[..ping.len()])
    }

    info!("Aborting Secure Session");
    let resp = tropic_01.abort_session().expect("failed to abort session");
    assert_eq!(resp, l2::Status::RequestOk);

    model_server.cleanup();
}

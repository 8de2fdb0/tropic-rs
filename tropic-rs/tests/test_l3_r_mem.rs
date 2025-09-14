mod testing_common;

use log::info;
use rand::Rng;

use tropic_rs::{
    common::{PairingKeySlot, R_MEM_USER_DATA_SLOT_MAX},
    l3::r_mem_data::R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX,
};

use crate::testing_common::*;

#[test]
fn test_l3_r_mem() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_r_mem")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    for i in 0..R_MEM_USER_DATA_SLOT_MAX {
        info!("Reading slot {} (should fail)....", i);
        let result = tropic_01.r_mem_data_read(&mut session, i.try_into().expect("invalid slot"));
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(tropic_rs::l3::Error::RMemData(
                tropic_rs::l3::Status::RMemDataReadSlotEmpty
            )))
        );
    }

    info!("Testing writing all slots entirely...");
    for i in 0..R_MEM_USER_DATA_SLOT_MAX {
        info!("Generating random data for slot {}...", i);

        let mut write_data = [0u8; R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX];
        rand::rng().fill(&mut write_data);

        info!("Writing to slot {}...", i);
        tropic_01
            .r_mem_data_write(
                &mut session,
                i.try_into().expect("invalid slot"),
                &write_data,
            )
            .expect("failed to write r mem");

        info!("Reading slot {}...", i);
        let resp = tropic_01
            .r_mem_data_read(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read r mem");
        info!("Checking contents...");
        assert_eq!(resp.len as usize, R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX);
        assert_eq!(resp.user_data, &write_data[..]);

        info!("Writing zeros to slot {} (should fail)...", i);
        let result = tropic_01.r_mem_data_write(
            &mut session,
            i.try_into().expect("invalid slot"),
            &[0u8; R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX],
        );
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(tropic_rs::l3::Error::RMemData(
                tropic_rs::l3::Status::RMemDataWriteWriteFail
            )))
        );

        info!("Reading slot {}...", i);
        let resp = tropic_01
            .r_mem_data_read(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read r mem");
        info!("Checking contents (should still contain original data)...");
        assert_eq!(resp.len as usize, R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX);
        assert_eq!(resp.user_data, &write_data[..]);
    }

    info!("Erasing all slots...");
    for i in 0..R_MEM_USER_DATA_SLOT_MAX {
        info!("Erasing slot {}...", i);
        tropic_01
            .r_mem_data_erase(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to erase r mem");

        info!("Reading slot {} (should fail)...", i);
        let result = tropic_01.r_mem_data_read(&mut session, i.try_into().expect("invalid slot"));
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(tropic_rs::Error::L3(tropic_rs::l3::Error::RMemData(
                tropic_rs::l3::Status::RMemDataReadSlotEmpty
            )))
        );
    }

    info!("Testing writing all slots partially...");
    for i in 0..R_MEM_USER_DATA_SLOT_MAX {
        info!(
            "Generating random data length < {} for slot {}...",
            R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX, i
        );

        let write_len: usize = rand::rng().random_range(1..=R_MEM_DATA_WRITE_CMD_DATA_LEN_MAX);
        let mut write_data = rand_bytes(write_len);
        rand::rng().fill(&mut write_data[..write_len]);

        info!("Writing {} byts of data to slot {}...", write_len, i);
        tropic_01
            .r_mem_data_write(
                &mut session,
                i.try_into().expect("invalid slot"),
                &write_data[..write_len],
            )
            .expect("failed to write r mem");

        info!("Reading slot {}...", i);
        let resp = tropic_01
            .r_mem_data_read(&mut session, i.try_into().expect("invalid slot"))
            .expect("failed to read r mem");
        info!("Checking contents...");
        assert_eq!(resp.len as usize, write_len);
        assert_eq!(resp.user_data(), &write_data[..write_len]);
    }

    model_server.cleanup();
}

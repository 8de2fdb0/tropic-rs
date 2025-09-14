use tropic_rs::common::config;

pub fn generate_random_config() -> config::Config {
    config::Config {
        bootloader: config::bootloader::Bootloader {
            start_up: config::bootloader::StartUp::from_bits_retain(rand::random()),
            sensor: config::bootloader::Sensor::from_bits_retain(rand::random()),
            debug: config::bootloader::Debug::from_bits_retain(rand::random()),
        },
        application: config::application::Application {
            gpo: config::application::Gpo::from_bits(rand::random()),
            sleep_mode: config::application::SleepMode::from_bits_retain(rand::random()),
        },
        application_uap: config::application_uap::ApplicationUap {
            pairing_key_write: config::application_uap::PairingKeyWrite::from_bits(rand::random()),
            pairing_key_read: config::application_uap::PairingKeyRead::from_bits(rand::random()),
            pairing_key_invalidate: config::application_uap::PairingKeyInvalidate::from_bits(
                rand::random(),
            ),
            r_config_write_erase: config::application_uap::RConfigWriteErase::from_bits(
                rand::random(),
            ),
            r_config_read: config::application_uap::RConfigRead::from_bits(rand::random()),
            i_config_write: config::application_uap::IConfigWrite::from_bits(rand::random()),
            i_config_read: config::application_uap::IConfigRead::from_bits(rand::random()),
            ping: config::application_uap::Ping::from_bits(rand::random()),
            r_mem_data_write: config::application_uap::RMemDataWrite::from_bits(rand::random()),
            r_mem_data_read: config::application_uap::RMemDataRead::from_bits(rand::random()),
            r_mem_data_erase: config::application_uap::RMemDataErase::from_bits(rand::random()),
            random_value_get: config::application_uap::RandomValueGet::from_bits(rand::random()),
            ecc_key_generate: config::application_uap::EccKeyGenerate::from_bits(rand::random()),
            ecc_key_store: config::application_uap::EccKeyStore::from_bits(rand::random()),
            ecc_key_read: config::application_uap::EccKeyRead::from_bits(rand::random()),
            ecc_key_erase: config::application_uap::EccKeyErase::from_bits(rand::random()),
            ecdsa_sign: config::application_uap::EcdsaSign::from_bits(rand::random()),
            eddsa_sifn: config::application_uap::EddsaSign::from_bits(rand::random()),
            mcounter_init: config::application_uap::McounterInit::from_bits(rand::random()),
            mcounter_get: config::application_uap::McounterGet::from_bits(rand::random()),
            mcounter_update: config::application_uap::McounterUpdate::from_bits(rand::random()),
            mac_and_destroy: config::application_uap::MacAndDestroy::from_bits(rand::random()),
        },
    }
}

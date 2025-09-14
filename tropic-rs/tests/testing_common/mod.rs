#![allow(dead_code, unused_imports)]

pub mod config;
pub mod keys;
pub mod mocks;
pub mod tcp;
pub mod tvl_model;

pub use keys::SamplePairingKey;
pub use tvl_model::{
    logging_cfg::{LogLevel, LoggingCfg},
    model_cfg::{ModelCfg, ModelCfgBuilder, RIConfig, RIConfigBuilder},
    model_server::{ModelServer, ModelServerBuilder},
};

use std::sync::Once;
use std::{env, mem};

use log::info;
use rand::RngCore;
use x25519_dalek::StaticSecret;

use tropic_cert_store::nom_decoder::NomDecoder;
use tropic_rs::{
    Tropic01, cert_store, common,
    l3::{EncSession, session},
};

use mocks::delay::MockDelay;
use tcp::{DEFAULT_TCP_ADDR, DEFAULT_TCP_PORT, TcpSpiDevice};

pub type Tropic01TestInstance = Tropic01<TcpSpiDevice, MockDelay, NomDecoder>;

static LOGGER_INIT: Once = Once::new();

pub fn setup_logging() {
    LOGGER_INIT.call_once(|| {
        let default_level = "info";
        let default_log_level = env::var("RUST_LOG").unwrap_or_else(|_| default_level.to_string());

        env_logger::builder()
            .parse_filters(&default_log_level)
            .init();
    });
}

pub struct CleanupGuard<F: FnOnce(&mut Tropic01TestInstance, &mut EncSession)> {
    tropic: Tropic01TestInstance,
    session: EncSession,
    cleanup_fn: Option<F>,
}

impl<F> CleanupGuard<F>
where
    F: FnOnce(&mut Tropic01TestInstance, &mut EncSession),
{
    pub(crate) fn new(tropic: Tropic01TestInstance, session: EncSession, cleanup_fn: F) -> Self {
        Self {
            tropic,
            session,
            cleanup_fn: Some(cleanup_fn),
        }
    }

    pub fn run<F2: FnOnce(&mut Tropic01TestInstance, &mut EncSession)>(&mut self, f: F2) {
        f(&mut self.tropic, &mut self.session);
    }

    pub fn disarm(&mut self) {
        self.cleanup_fn = None;
    }
}

impl<F> Drop for CleanupGuard<F>
where
    F: FnOnce(&mut Tropic01TestInstance, &mut EncSession),
{
    fn drop(&mut self) {
        if let Some(f) = mem::take(&mut self.cleanup_fn) {
            f(&mut self.tropic, &mut self.session);
        }
    }
}

pub fn get_tropic_test_instance(port: u16) -> Tropic01TestInstance {
    info!("creating tropic test instance, connected to model server");
    let spi_device =
        TcpSpiDevice::connect(DEFAULT_TCP_ADDR, port).expect("failed to connect to model server");

    Tropic01::<_, _, NomDecoder>::new(spi_device, MockDelay)
}

pub fn get_tropic_test_session(
    tropic_01: &mut Tropic01TestInstance,
    sh_secret: StaticSecret,
    pairing_key_slot: common::PairingKeySlot,
) -> EncSession {
    info!(
        "creating secure session with pairing_key_slot: {:?}",
        pairing_key_slot
    );

    let mut cert_buffer = [0u8; cert_store::CERT_BUFFER_LEN];

    let cert_store = tropic_01
        .get_cert_store(&mut cert_buffer)
        .expect("failed to get cert store");

    let st_pubkey = cert_store
        .get_pubkey(tropic_rs::cert_store::CertKind::Device)
        .expect("failed to get device pubkey");

    let rng = rand::rng();
    let session = tropic_01
        .create_session(rng, &sh_secret, pairing_key_slot, &st_pubkey)
        .expect("msg failed to create session");

    session
}

pub fn get_tropic_test_instance_with_session(
    sh_secret: StaticSecret,
    pairing_key_slot: common::PairingKeySlot,
    port: u16,
) -> (Tropic01TestInstance, EncSession) {
    info!(
        "creating secure session with pairing_key_slot: {:?}",
        pairing_key_slot
    );

    let mut tropic_01 = get_tropic_test_instance(port);
    let session = get_tropic_test_session(&mut tropic_01, sh_secret, pairing_key_slot);

    (tropic_01, session)
}

pub fn rand_bytes(len: usize) -> Vec<u8> {
    let mut msg = vec![0_u8; len];
    rand::rng().fill_bytes(&mut msg);
    msg
}

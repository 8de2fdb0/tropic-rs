use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use tropic_rs::l3::keys::SamplePairingKey;

#[derive(Debug, Clone, ValueEnum)]
pub enum BankId {
    /// Firmware bank 1.
    FwBankFw1 = 1,
    /// Firmware bank 2.
    FwBankFw2 = 2,
    /// SPECT bank 1.
    FwBankSpect1 = 17,
    /// SPECT bank 2.
    FwBankSpect2 = 18,
}

impl From<BankId> for tropic_rs::l2::info::BankId {
    fn from(value: BankId) -> Self {
        match value {
            BankId::FwBankFw1 => tropic_rs::l2::info::BankId::FwBankFw1,
            BankId::FwBankFw2 => tropic_rs::l2::info::BankId::FwBankFw2,
            BankId::FwBankSpect1 => tropic_rs::l2::info::BankId::FwBankSpect1,
            BankId::FwBankSpect2 => tropic_rs::l2::info::BankId::FwBankSpect2,
        }
    }
}

#[derive(Debug, Default, Clone, ValueEnum)]
pub enum SleepKind {
    /// Regular Sleep Mode
    #[default]
    Regular = 0x05,
    /// Deep Sleep Mode
    Deep = 0x0a,
}

impl From<SleepKind> for tropic_rs::l2::sleep::SleepKind {
    fn from(value: SleepKind) -> Self {
        match value {
            SleepKind::Regular => tropic_rs::l2::sleep::SleepKind::Regular,
            SleepKind::Deep => tropic_rs::l2::sleep::SleepKind::Deep,
        }
    }
}

#[derive(Debug, Default, Clone, ValueEnum)]
pub enum RestartMode {
    /// Soft Reboot
    #[default]
    Reboot = 0x01,

    /// Reboot into Firmware Update Mode
    Maintanance = 0x03,
}

impl From<RestartMode> for tropic_rs::l2::startup::RestartMode {
    fn from(value: RestartMode) -> Self {
        match value {
            RestartMode::Reboot => tropic_rs::l2::startup::RestartMode::Reboot,
            RestartMode::Maintanance => tropic_rs::l2::startup::RestartMode::Maintanance,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Handshake {
    /// TROPIC01's X25519 Ephemeral key
    pub et_pubkey: tropic_rs::external::x25519_dalek::PublicKey,
    /// The Secure Channel Handshake Authentication Tag
    pub auth_tag: [u8; 16],

    pub static_secret: tropic_rs::external::x25519_dalek::StaticSecret,
}

impl
    From<(
        tropic_rs::l2::handshake::HandshakeResp,
        tropic_rs::external::x25519_dalek::StaticSecret,
    )> for Handshake
{
    fn from(
        (handshake_resp, secret): (
            tropic_rs::l2::handshake::HandshakeResp,
            tropic_rs::external::x25519_dalek::StaticSecret,
        ),
    ) -> Self {
        Self {
            et_pubkey: handshake_resp.et_pubkey,
            auth_tag: handshake_resp.auth_tag,
            static_secret: secret,
        }
    }
}

pub fn sample_pairing_key_from_u8(slot: u8) -> anyhow::Result<SamplePairingKey> {
    match slot {
        0 => Ok(SamplePairingKey::Sample0),
        1 => Ok(SamplePairingKey::AttestSlot),
        2 => Ok(SamplePairingKey::ReadSerial),
        3 => Ok(SamplePairingKey::App),
        _ => Err(anyhow::anyhow!("wrong key_slot")),
    }
}

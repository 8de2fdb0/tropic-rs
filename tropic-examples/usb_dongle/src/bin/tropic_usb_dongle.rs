extern crate usb_dongle;

use std::{
    fs::{self, create_dir_all},
    io,
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;

use tropic_cert_decoder::nom_decoder::{NomCertificate, NomDecoder};
use tropic_rs::{cert_store::CertStore, external::x25519_dalek::PublicKey};

use usb_dongle::{serial_transport, type_wrapper, utils};

const BAUD_RATE: u32 = 115200;

const DEFAULT_HANDSHAKE_OUTFILE: &str = "handshake.json";
const DEFAULT_CERTSTORE_OUTFILE: &str = "cert_store.json";
const DEFAULT_SESSION_OUTFILE: &str = "session.json";
const DEFAULT_RCONFIG_OUTFILE: &str = "r_config.json";

const CFG_PATH_QLF: &str = "com";
const CFG_PATH_ORG: &str = "tropic-rs";
const CFG_PATH_APP: &str = "tropic-usb-dongle";

fn get_project_config_dir(file: &str) -> io::Result<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from(CFG_PATH_QLF, CFG_PATH_ORG, CFG_PATH_APP) {
        let config_dir = proj_dirs.config_dir();
        if !config_dir.exists() {
            create_dir_all(config_dir)?
        }
        return Ok(config_dir.join(file).to_path_buf());
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "config directory not found",
    ))
}

fn get_project_config<T: serde::de::DeserializeOwned>(file: &str) -> Result<T> {
    let content = std::fs::read(get_project_config_dir(file)?)?;
    Ok(serde_json::from_slice(&content)?)
}

fn set_project_config<T: serde::ser::Serialize>(file: &str, value: &T) -> Result<()> {
    let path = get_project_config_dir(file)?;
    std::fs::write(&path, serde_json::to_string(&value)? + "\n")?;
    println!("wrote: {path:?}");
    Ok(())
}

#[derive(Subcommand)]
enum SessionCmd {
    Handshake {
        #[arg(short, long, value_name = "KEY_SLOT", default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
        slot: u8,
    },
    Create {
        #[arg(short, long, value_name = "KEY_SLOT", default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
        slot: u8,
    },
    Abort,
    Ping {
        #[arg(short, long, value_name = "MESSAGE", default_value = "pong")]
        msg: String,
    },
}

#[derive(Subcommand)]
#[command(about = "Manage pairing keys: 
create priv key using: openssl genpkey -algorithm X25519 -out sh1_priv.pem
")]
enum PairingKeyCmd {
    Read {
        #[arg(short, long, value_name = "KEY_SLOT", default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
        slot: u8,
    },
    Write {
        #[arg(short, long, value_name = "KEY_SLOT", default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
        slot: u8,

        private_key_pem: String,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    Read,
    Write,
}

#[derive(Subcommand)]
enum SubCmd {
    Status,
    Info,
    FwBootHeader {
        bank_id: type_wrapper::BankId,
    },
    Log,
    Cert,
    Sleep {
        sleep_kind: Option<type_wrapper::SleepKind>,
    },
    Restart {
        restart_mode: Option<type_wrapper::RestartMode>,
    },
    Session {
        #[clap(subcommand)]
        cmd: SessionCmd,
    },
    PairingKey {
        #[clap(subcommand)]
        cmd: PairingKeyCmd,
    },
    Config {
        #[arg(short, long, help = "use irreversibale config")]
        irreversible: bool,

        #[clap(subcommand)]
        cmd: ConfigCmd,
    },
}

#[derive(clap::Parser)]
#[command(arg_required_else_help = true)]
struct Cli {
    #[arg(
        short,
        long,
        value_name = "DEVICE_FILE",
        default_value = "/dev/ttyACM0"
    )]
    dev: String,

    #[clap(subcommand)]
    cmd: SubCmd,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let transport = serial_transport::UsbDongleTransport::new(&cli.dev, BAUD_RATE)?;
    let mut tropic01 = tropic_rs::Tropic01::<_, NomDecoder>::new(transport);

    match cli.cmd {
        SubCmd::Status => {
            let cis = tropic01.get_chip_status().map_err(|e| anyhow!("{:?}", e))?;

            println!("chip_status: {:?}", cis);
        }
        SubCmd::Info => {
            let cid = tropic01.get_chip_id().map_err(|e| anyhow!("{:?}", e))?;

            let cid_json = serde_json::to_string_pretty(&cid)?;

            println!("chip_id:\n {}", cid_json);
        }
        SubCmd::FwBootHeader { bank_id } => {
            let boot_header = tropic01
                .get_firmware_boot_header(bank_id.into())
                .map_err(|e| anyhow!(e))?;
            println!(
                "firmware_boot_header:\n{}",
                serde_json::to_string_pretty(&boot_header)?
            );
        }
        SubCmd::Log => {
            let log_resp = tropic01.get_riscv_firmware_log().map_err(|e| anyhow!(e))?;
            println!("log:\n{}", log_resp);
        }
        SubCmd::Cert => {
            let mut cert_buf = [0u8; tropic_rs::cert_store::CERT_BUFFER_LEN];
            let cert_store = tropic01
                .get_cert_store(&mut cert_buf)
                .map_err(|e| anyhow!(e))?;

            set_project_config(DEFAULT_CERTSTORE_OUTFILE, &cert_store)?;
        }
        SubCmd::Sleep { sleep_kind } => {
            tropic01
                .sleep(sleep_kind.unwrap_or_default().into())
                .map_err(|e| anyhow!("{:?}", e))?;
            println!("Device put to sleep.");
        }
        SubCmd::Restart { restart_mode } => {
            tropic01
                .restart(restart_mode.unwrap_or_default().into())
                .map_err(|e| anyhow!("{:?}", e))?;
            println!("Device restarted.");
        }
        SubCmd::Session { cmd } => match cmd {
            SessionCmd::Handshake { slot } => {
                let handshake: type_wrapper::Handshake = tropic01
                    .get_handshake(rand::rng(), slot.try_into().unwrap())
                    .map_err(|e| anyhow!("{:?}", e))?
                    .into();

                set_project_config(DEFAULT_HANDSHAKE_OUTFILE, &handshake)?;
            }
            SessionCmd::Create { slot } => {
                let key = type_wrapper::sample_pairing_key_from_u8(slot)?;

                let cert_store_content =
                    std::fs::read(get_project_config_dir(DEFAULT_CERTSTORE_OUTFILE)?)?;
                let cert_store: CertStore<NomCertificate<'_>> =
                    serde_json::from_slice(&cert_store_content)?;

                let st_pubkey = cert_store
                    .get_pubkey(tropic_rs::cert_store::CertKind::Device)
                    .map_err(|e| anyhow!(e))?;

                let pairing_key_slot = slot
                    .try_into()
                    .map_err(|e: tropic_rs::common::Error| anyhow!(e))?;

                let session = tropic01
                    .create_session(
                        rand::rng(),
                        &key.to_x25519_secret(),
                        pairing_key_slot,
                        &st_pubkey,
                    )
                    .map_err(|e| anyhow!("error while creating session: {e}"))?;

                set_project_config(DEFAULT_SESSION_OUTFILE, &session)?;
            }
            SessionCmd::Abort => {
                tropic01
                    .abort_session()
                    .map_err(|e| anyhow!("error while aborting session: {e}"))?;
            }
            SessionCmd::Ping { msg } => {
                let mut session = get_project_config(DEFAULT_SESSION_OUTFILE)?;
                let ping_resp = tropic01
                    .ping(&mut session, msg.as_bytes())
                    .map_err(|e| anyhow!("error while pinging tropic01: {e}"))?;

                set_project_config(DEFAULT_SESSION_OUTFILE, &session)?;

                println!(
                    "received ping resp: {}",
                    std::str::from_utf8(ping_resp.msg())?
                );
            }
        },
        SubCmd::PairingKey { cmd } => match cmd {
            PairingKeyCmd::Read { slot } => {
                let pairing_key_slot = slot
                    .try_into()
                    .map_err(|e: tropic_rs::common::Error| anyhow!(e))?;

                let mut session = get_project_config(DEFAULT_SESSION_OUTFILE)?;

                let pairing_key = tropic01
                    .pairing_key_read(&mut session, pairing_key_slot)
                    .map_err(|e| anyhow!(e))?;

                set_project_config(DEFAULT_SESSION_OUTFILE, &session)?;
                println!(
                    "read pairingkey for slot: {slot}, {:x?}",
                    pairing_key.s_hipub
                )
            }
            PairingKeyCmd::Write {
                slot,
                private_key_pem,
            } => {
                let pairing_key_slot = slot
                    .try_into()
                    .map_err(|e: tropic_rs::common::Error| anyhow!(e))?;

                println!("reading: {}", &private_key_pem);
                let pem_file_content = fs::read(&private_key_pem)?;
                let secret = utils::parse_x25519_private_key(&pem_file_content)?;
                let pubkey = PublicKey::from(&secret);
                println!("writing pubkey: {:x?} to slot {}", &pubkey, slot);

                let mut session = get_project_config(DEFAULT_SESSION_OUTFILE)?;
                tropic01
                    .pairing_key_write(&mut session, pairing_key_slot, &pubkey)
                    .map_err(|e| anyhow!(e))?;

                set_project_config(DEFAULT_SESSION_OUTFILE, &session)?;
            }
        },
        SubCmd::Config {
            cmd,
            irreversible: _,
        } => match cmd {
            ConfigCmd::Read => {
                let mut session = get_project_config(DEFAULT_SESSION_OUTFILE)?;
                let r_config = tropic01
                    .r_config_read(&mut session)
                    .map_err(|e| anyhow!(e))?;

                set_project_config(DEFAULT_RCONFIG_OUTFILE, &r_config)?;
                set_project_config(DEFAULT_SESSION_OUTFILE, &session)?;
            }
            ConfigCmd::Write => {
                let mut session = get_project_config(DEFAULT_SESSION_OUTFILE)?;
                let r_config = get_project_config(DEFAULT_RCONFIG_OUTFILE)?;

                let status_resp = tropic01
                    .r_config_write(&mut session, &r_config)
                    .map_err(|e| anyhow!(e))?;

                set_project_config(DEFAULT_SESSION_OUTFILE, &session)?;

                println!("wrote config, status: {:?}", status_resp.status)
            }
        },
    }
    Ok(())
}

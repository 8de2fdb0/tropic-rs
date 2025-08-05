use std::convert::Infallible;

use clap::Parser;
use postcard_rpc::{
    header::VarSeqKind,
    host_client::{HostClient, HostErr},
    standard_icd::{WireError, ERROR_PATH},
};

use common::{ChipInfo, Commands, CommandsResp};

use host::RawUsbDevice;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("comm error")]
    Comms(HostErr<WireError>),

    #[error("usb comminication error")]
    UsbCommunicationError(#[from] host::UsbCommunicationError),

    #[error("postcard encoding")]
    Postcard(#[from] postcard::Error),

    #[error("invalid response")]
    InvalidResp(CommandsResp),
}

impl From<HostErr<WireError>> for Error {
    fn from(value: HostErr<WireError>) -> Self {
        Self::Comms(value)
    }
}

#[derive(Debug)]
pub struct Client {
    pub client: RawUsbDevice,
}

impl Client {
    pub async fn new() -> Self {
        // let client = HostClient::new_raw_nusb(
        //     |d| {
        //         println!("{:?}", d.product_string());
        //         d.product_string() == Some("USB-serial example")
        //     },
        //     ERROR_PATH,
        //     8,
        //     VarSeqKind::Seq2,
        // );

        let client = RawUsbDevice::connect().await.unwrap();

        Self { client }
    }

    pub async fn wait_closed(&self) {
        // self.client.wait_closed().await;
    }

    async fn send_request(&mut self, req: &Commands) -> Result<CommandsResp, Error> {
        let msg = postcard::to_stdvec(req).expect("Allocations should not ever fail");
        self.client.write_bytes(&msg).await?;
        let msg = self.client.read_bytes(64).await?;
        let resp = postcard::from_bytes::<CommandsResp>(&msg)?;
        Ok(resp)
    }

    pub async fn ping(&mut self, id: u32) -> Result<u32, Error> {
        let req = Commands::Ping(id);
        let val = self.send_request(&req).await?;
        match val {
            CommandsResp::Ping(val) => Ok(val),
            _ => Err(Error::InvalidResp(val)),
        }
    }

    pub async fn chip_info(&mut self, chip: Chip) -> Result<ChipInfo, Error> {
        let req = Commands::ChipInfo(chip.into());
        let val = self.send_request(&req).await?;
        match val {
            CommandsResp::ChipInfo(val) => Ok(val),
            _ => Err(Error::InvalidResp(val)),
        }
    }
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Chip {
    #[clap(alias = "rp235x")]
    Rp235X,
    #[clap(alias = "tropic01")]
    Tropic01,
}

impl From<Chip> for common::Chip {
    fn from(chip: Chip) -> Self {
        match chip {
            Chip::Rp235X => common::Chip::Rp235X,
            Chip::Tropic01 => common::Chip::Tropic01,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
enum Subcommand {
    Ping {
        #[clap(short, long)]
        id: u32,
    },
    ChipInfo {
        #[clap(long)]
        chip: Chip,
    },
}

#[derive(Debug, clap::Parser)]
struct Cli {
    #[clap(short, long)]
    verbose: bool,

    #[clap(subcommand)]
    cmd: Subcommand,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    let mut client = Client::new().await;

    match cli.cmd {
        Subcommand::Ping { id } => {
            let pong = client.ping(id).await?;
            println!("pong: {pong}");
        }
        Subcommand::ChipInfo { chip } => {
            let chip_info = client.chip_info(chip.into()).await?;
            println!("chip info: {chip_info:?}");
        }
    }

    Ok(())
}

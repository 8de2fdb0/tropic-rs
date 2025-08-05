#![cfg_attr(not(feature = "use-std"), no_std)]

pub mod usb {
    pub mod consts;

    #[cfg(feature = "rp235x")]
    pub mod rp235x;
}

// use postcard_rpc::{endpoints, topics, TopicDirection};

/// ascii encoding for serial usb inteface
use embedded_cli::{arguments::FromArgument, Command, CommandGroup};

// binary encoding for raw usb inteface
use postcard_schema::Schema;
use serde::{Deserialize, Serialize};

// endpoints! {
//     list = ENDPOINT_LIST;
//     omit_std = true;
//     | EndpointTy                | RequestTy     | ResponseTy            | Path              |
//     | ----------                | ---------     | ----------            | ----              |
//     | PingEndpoint              | u32           | u32                   | "ping"            |
//     | ChipInfoEndpoint          | ChipInfoReq  | ChipInfoResp          | "chipinfo"        |

// }

// topics! {
//     list = TOPICS_IN_LIST;
//     direction = TopicDirection::ToServer;
//     | TopicTy                   | MessageTy     | Path              |
//     | -------                   | ---------     | ----              |
// }

// topics! {
//     list = TOPICS_OUT_LIST;
//     direction = TopicDirection::ToClient;
//     | TopicTy                   | MessageTy     | Path              | Cfg                           |
//     | -------                   | ---------     | ----              | ---                           |
//     | AccelTopic                | Acceleration  | "accel/data"      |                               |
// }

#[derive(Serialize, Deserialize, Schema, Command, Debug, PartialEq)]
#[command(help_title = "Manage Device")]
pub enum SysCmd {
    Ping,
}

#[derive(Serialize, Deserialize, Schema, Debug, PartialEq)]
pub enum Chip {
    Rp235X,
    Tropic01,
}

impl<'de> FromArgument<'de> for Chip {
    fn from_arg(arg: &'de str) -> Result<Self, embedded_cli::arguments::FromArgumentError<'_>>
    where
        Self: Sized,
    {
        match arg {
            "rp235x" => Ok(Chip::Rp235X),
            "tropic01" => Ok(Chip::Tropic01),
            _ => Err(embedded_cli::arguments::FromArgumentError {
                value: arg,
                expected: "rp235x or tropic01",
            }),
        }
    }
}

#[derive(Serialize, Deserialize, Schema, Command, Debug, PartialEq)]
#[command(help_title = "Manage Indidual Chips")]
pub enum ChipCmd {
    GetChipInfo { chip: Chip },
}

#[derive(Serialize, Deserialize, Schema, Debug, PartialEq)]
pub struct Rp235XChipInfo {
    /// The device's id
    pub device_id: u32,
    /// The wafer's id
    pub wafer_id: u32,
}

#[derive(Serialize, Deserialize, Schema, Debug, PartialEq)]
pub enum ChipInfo {
    Rp235X {
        chip_id: u32,
        waver_id: u32,
        unique_id: u64,
    },
    Tropic,
}

#[derive(Serialize, Deserialize, Schema, CommandGroup, Debug, PartialEq)]
pub enum Commands {
    System(SysCmd),
    Chip(ChipCmd),
}

#[derive(Serialize, Deserialize, Schema, Debug, PartialEq)]
pub enum CommandsResp {
    Ping(u32),
    ChipInfo(ChipInfo),
}

use std::{collections::BTreeMap, io::Write};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_yaml;
use tempfile::{Builder, NamedTempFile};

use tropic_rs::common::config::{Config as TropciConfig, application, application_uap, bootloader};

const CHIP_ID: &str = "AQAAAAAAAAAAAAAAQUNBQoCq//8B8AIAAAAAAAAAAAAAAP//AfACAAAAAAAAAAAAAAAAAALwAgAA
ABkGGwkzAAAAAAANVFIwMS1DMlMtVDIwMP//AQTYlmEoAAx97ahwGQYbCTP///8=";

const I_PAIRING_KEYS_0: &str = "+XXrPC/XkMlvKU8VV6UDF4DJqvoUDaKPVedRVzeyUCw=";

const S_T_PRIV: &str = "+LljVM+0MRmbQNTaRB7YPl23s9k+uLs8pY4MSgRpK0w=";
const S_T_PUB: &str = "lQjwMhyx0uXR8aRgnAVBt4Dm3VDWSCtrCLLCfnt2Jkc=";

const X509_CERTIFICATE: &str =
    "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
DBRUcm9waWMgU3F1YXJlIHMuci5vLjEmMCQGA1UEAwwdVHJvcGljIFNxdWFyZSBURVNUIFJvb3Qg
Q0EgdjEwIBcNMjUwMzI0MTMxNDM4WhgPMjA3NTAzMjQxMzE0MzhaMFQxCzAJBgNVBAYTAkNaMR0w
GwYDVQQKDBRUcm9waWMgU3F1YXJlIHMuci5vLjEmMCQGA1UEAwwdVHJvcGljIFNxdWFyZSBURVNU
IFJvb3QgQ0EgdjEwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAE1x6JNFrN0sget6P5Q9QOtNODl
lsg/yYrbTEOIygrZsk536YS4l4JTqODW/WjqqNnJqabIg1oTjMz/URMNoQmGgADN9/rVoCu9hEU8
VjbyXxw5W9wi7ntEGoG1nyBAU4n0fWXwdKYC+TMt8TN58n1lT04bD9RWwamfVDZkD37gThtIgaNC
MEAwHQYDVR0OBBYEFC6bpUA0OSU0isYBa+UNcC14aLaIMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgEGMAoGCCqGSM49BAMEA4GKADCBhgJBai2dcrQ1MDVyXp1gf2L5J+iHtgfJ/n/Xvd8A
pNlLXVfzyTdwor4lwT9Z7p9BlxeflAbsKozqsdUZBUfsJEhvi5UCQTwKdKFhO9XbKfWOpMeSz/4B
4L5cKCIk5/+T9RJYpfIuO6Shg+iCpcVPXDnOFALRsmdMw0pBgurwYcT2bjDpaDIS";

const BINARY_DATA_START_2: &str = "%BINARY_DATA_START_2%";
const BINARY_DATA_START_8: &str = "%BINARY_DATA_START_8%";
const BINARY_DATA_END: &str = "%BINARY_DATA_END%";

#[derive(Debug, Clone, PartialEq)]
pub struct BinaryDataBase64(u8, String);

impl Serialize for BinaryDataBase64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let start_marker = match self.0 {
            2 => BINARY_DATA_START_2,
            8 => BINARY_DATA_START_8,
            _ => "UNSUPPORTED_INDENT_VALUE",
        };
        serializer.serialize_str(&format!("{}{}{}", start_marker, self.1, BINARY_DATA_END))
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Builder)]
#[builder(setter(strip_option), default)]
pub struct RIConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_sleep_mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_ecc_key_erase: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_ecc_key_generate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_ecc_key_read: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_ecc_key_store: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_ecdsa_sign: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_eddsa_sign: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_i_config_read: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_i_config_write: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_mac_and_destroy: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_mcounter_get: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_mcounter_init: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_mcounter_update: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_pairing_key_invalidate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_pairing_key_read: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_pairing_key_write: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_ping: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_r_config_read: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_r_config_write_erase: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_r_mem_data_erase: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_r_mem_data_read: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_r_mem_data_write: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_uap_random_value_get: Option<u32>,
}

impl From<RIConfig> for TropciConfig {
    fn from(cfg: RIConfig) -> Self {
        Self {
            bootloader: bootloader::Bootloader {
                start_up: bootloader::StartUp::all_bits(),
                sensor: bootloader::Sensor::all_bits(),
                debug: bootloader::Debug::all_bits(),
            },
            application: application::Application {
                gpo: application::Gpo::new(),
                sleep_mode: application::SleepMode::from_bits_retain(
                    cfg.cfg_sleep_mode.unwrap_or_default(),
                ),
            },
            application_uap: application_uap::ApplicationUap {
                pairing_key_write: application_uap::PairingKeyWrite::from_bits(
                    cfg.cfg_uap_pairing_key_write.unwrap_or_default(),
                ),
                pairing_key_read: application_uap::PairingKeyRead::from_bits(
                    cfg.cfg_uap_pairing_key_read.unwrap_or_default(),
                ),
                pairing_key_invalidate: application_uap::PairingKeyInvalidate::from_bits(
                    cfg.cfg_uap_pairing_key_invalidate.unwrap_or_default(),
                ),
                r_config_write_erase: application_uap::RConfigWriteErase::from_bits(
                    cfg.cfg_uap_r_config_write_erase.unwrap_or_default(),
                ),
                r_config_read: application_uap::RConfigRead::from_bits(
                    cfg.cfg_uap_r_config_read.unwrap_or_default(),
                ),
                i_config_write: application_uap::IConfigWrite::from_bits(
                    cfg.cfg_uap_i_config_write.unwrap_or_default(),
                ),
                i_config_read: application_uap::IConfigRead::from_bits(
                    cfg.cfg_uap_i_config_read.unwrap_or_default(),
                ),
                ping: application_uap::Ping::from_bits(cfg.cfg_uap_ping.unwrap_or_default()),
                r_mem_data_write: application_uap::RMemDataWrite::from_bits(
                    cfg.cfg_uap_r_mem_data_write.unwrap_or_default(),
                ),
                r_mem_data_read: application_uap::RMemDataRead::from_bits(
                    cfg.cfg_uap_r_mem_data_read.unwrap_or_default(),
                ),
                r_mem_data_erase: application_uap::RMemDataErase::from_bits(
                    cfg.cfg_uap_r_mem_data_erase.unwrap_or_default(),
                ),
                random_value_get: application_uap::RandomValueGet::from_bits(
                    cfg.cfg_uap_random_value_get.unwrap_or_default(),
                ),
                ecc_key_generate: application_uap::EccKeyGenerate::from_bits(
                    cfg.cfg_uap_ecc_key_generate.unwrap_or_default(),
                ),
                ecc_key_store: application_uap::EccKeyStore::from_bits(
                    cfg.cfg_uap_ecc_key_store.unwrap_or_default(),
                ),
                ecc_key_read: application_uap::EccKeyRead::from_bits(
                    cfg.cfg_uap_ecc_key_read.unwrap_or_default(),
                ),
                ecc_key_erase: application_uap::EccKeyErase::from_bits(
                    cfg.cfg_uap_ecc_key_erase.unwrap_or_default(),
                ),
                ecdsa_sign: application_uap::EcdsaSign::from_bits(
                    cfg.cfg_uap_ecdsa_sign.unwrap_or_default(),
                ),
                eddsa_sifn: application_uap::EddsaSign::from_bits(
                    cfg.cfg_uap_eddsa_sign.unwrap_or_default(),
                ),
                mcounter_init: application_uap::McounterInit::from_bits(
                    cfg.cfg_uap_mcounter_init.unwrap_or_default(),
                ),
                mcounter_get: application_uap::McounterGet::from_bits(
                    cfg.cfg_uap_mcounter_get.unwrap_or_default(),
                ),
                mcounter_update: application_uap::McounterUpdate::from_bits(
                    cfg.cfg_uap_mcounter_update.unwrap_or_default(),
                ),
                mac_and_destroy: application_uap::MacAndDestroy::from_bits(
                    cfg.cfg_uap_mac_and_destroy.unwrap_or_default(),
                ),
            },
        }
    }
}

const UAP_RESERVERD_BITMASK: u32 = 0b11110000111100001111000011110000;

pub fn cfg_uap_random() -> u32 {
    rand::random::<u32>() & UAP_RESERVERD_BITMASK
}

impl RIConfigBuilder {
    pub fn random() -> Self {
        Self {
            // sleep mode is allways enabled in the model
            cfg_sleep_mode: Some(Some(0b11111111111111111111111111111111)),
            cfg_uap_ecc_key_erase: Some(Some(cfg_uap_random())),
            cfg_uap_ecc_key_generate: Some(Some(cfg_uap_random())),
            cfg_uap_ecc_key_read: Some(Some(cfg_uap_random())),
            cfg_uap_ecc_key_store: Some(Some(cfg_uap_random())),
            cfg_uap_ecdsa_sign: Some(Some(cfg_uap_random())),
            cfg_uap_eddsa_sign: Some(Some(cfg_uap_random())),
            cfg_uap_i_config_read: Some(Some(cfg_uap_random())),
            cfg_uap_i_config_write: Some(Some(cfg_uap_random())),
            cfg_uap_mac_and_destroy: Some(Some(cfg_uap_random())),
            cfg_uap_mcounter_get: Some(Some(cfg_uap_random())),
            cfg_uap_mcounter_init: Some(Some(cfg_uap_random())),
            cfg_uap_mcounter_update: Some(Some(cfg_uap_random())),
            cfg_uap_pairing_key_invalidate: Some(Some(cfg_uap_random())),
            cfg_uap_pairing_key_read: Some(Some(cfg_uap_random())),
            cfg_uap_pairing_key_write: Some(Some(cfg_uap_random())),
            cfg_uap_ping: Some(Some(cfg_uap_random())),
            cfg_uap_r_config_read: Some(Some(cfg_uap_random())),
            cfg_uap_r_config_write_erase: Some(Some(cfg_uap_random())),
            cfg_uap_r_mem_data_erase: Some(Some(cfg_uap_random())),
            cfg_uap_r_mem_data_read: Some(Some(cfg_uap_random())),
            cfg_uap_r_mem_data_write: Some(Some(cfg_uap_random())),
            cfg_uap_random_value_get: Some(Some(cfg_uap_random())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PairingKey {
    pub state: String,
    pub value: BinaryDataBase64,
}

impl PairingKey {
    pub fn new(value: String) -> Self {
        Self {
            state: "written".into(),
            value: BinaryDataBase64(8, value),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EccKeys {}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mcounters {}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserData {}

#[derive(Debug, Clone, PartialEq, Serialize, Builder)]
pub struct ModelCfg {
    #[builder(setter(strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activate_encryption: Option<bool>,
    #[builder(setter(strip_option), default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub busy_iter: Vec<bool>,
    #[builder(setter(strip_option), default = Some(BinaryDataBase64(2, CHIP_ID.into())))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chip_id: Option<BinaryDataBase64>,
    #[builder(setter(into, strip_option), default)]
    #[serde(rename = "debug_random_value", skip_serializing_if = "Option::is_none")]
    pub debug_random_value: Option<String>,
    #[builder(setter(strip_option), default)]
    #[serde(rename = "i_config", skip_serializing_if = "Option::is_none")]
    pub i_config: Option<RIConfig>,
    #[builder(setter(into, strip_option), default = Some(default_i_pairing_keys()))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i_pairing_keys: Option<BTreeMap<u8, PairingKey>>,
    #[builder(setter(strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_byte: Option<BinaryDataBase64>,
    #[builder(setter(strip_option), default)]
    #[serde(rename = "r_config", skip_serializing_if = "Option::is_none")]
    pub r_config: Option<RIConfig>,
    #[builder(setter(strip_option), default)]
    #[serde(rename = "r_ecc_keys", skip_serializing_if = "Option::is_none")]
    pub r_ecc_keys: Option<EccKeys>,
    #[builder(setter(strip_option), default)]
    #[serde(rename = "r_mcounters", skip_serializing_if = "Option::is_none")]
    pub r_mcounters: Option<Mcounters>,
    #[builder(setter(strip_option), default)]
    #[serde(rename = "r_user_data", skip_serializing_if = "Option::is_none")]
    pub r_user_data: Option<UserData>,
    #[builder(setter(strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub riscv_fw_version: Option<BinaryDataBase64>,
    #[builder(setter( strip_option), default = Some(BinaryDataBase64(2, S_T_PRIV.into())))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_t_priv: Option<BinaryDataBase64>,
    #[builder(setter( strip_option), default = Some(BinaryDataBase64(2, S_T_PUB.into())))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_t_pub: Option<BinaryDataBase64>,
    #[builder(setter(strip_option), default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spect_fw_version: Option<BinaryDataBase64>,
    #[builder(setter(strip_option), default = Some(BinaryDataBase64(2, X509_CERTIFICATE.into())))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate: Option<BinaryDataBase64>,
}

impl ModelCfg {
    pub fn generate_yaml(&self) -> String {
        serde_yaml::to_string(self)
            .unwrap()
            .replace(
                &format!("'{start}", start = BINARY_DATA_START_8),
                "!!binary |\n        ",
            )
            .replace(
                &format!("'{start}", start = BINARY_DATA_START_2),
                "!!binary |\n  ",
            )
            .replace(
                &format!("|-\n  {start}", start = BINARY_DATA_START_2),
                "!!binary |\n  ",
            )
            .replace(&format!("{end}'", end = BINARY_DATA_END), "")
            .replace(BINARY_DATA_END, "")
    }

    pub fn write_to_tempfile(&self) -> NamedTempFile {
        let yaml = self.generate_yaml();

        let mut model_cfg_tempfile = Builder::new()
            .prefix("test_model_config_")
            .suffix(".yml")
            .tempfile()
            .expect("failed to create tempfile");

        write!(model_cfg_tempfile, "{yaml}").expect("failed to write to tempfile");
        model_cfg_tempfile
            .flush()
            .expect("failed to flush tempfile");
        model_cfg_tempfile
    }

    // pub fn with_random_r_config(mut self) -> Self {
    //     let config = RIConfig::random();
    //     self.r_config = Some(config.clone());
    //     self.clone()
    // }

    // pub fn with_random_i_config(mut self) -> Self {
    //     let config = RIConfig::random();
    //     self.i_config = Some(config.clone());
    //     self
    // }

    pub fn with_r_config(mut self, value: RIConfig) -> Self {
        self.r_config = Some(value);
        self
    }
}

fn default_i_pairing_keys() -> BTreeMap<u8, PairingKey> {
    let mut i_pairing_keys = BTreeMap::new();
    i_pairing_keys.insert(0, PairingKey::new(I_PAIRING_KEYS_0.into()));
    i_pairing_keys
}

// impl Default for ModelCfg {
//     fn default() -> Self {
//         let mut i_pairing_keys = BTreeMap::new();
//         i_pairing_keys.insert(0, PairingKey::new(I_PAIRING_KEYS_0.into()));

//         Self {
//             activate_encryption: None,
//             busy_iter: vec![],
//             chip_id: Some(BinaryDataBase64(2, CHIP_ID.into())),
//             debug_random_value: None,
//             i_config: None,
//             i_pairing_keys: Some(i_pairing_keys),
//             init_byte: None,
//             r_config: Some(
//                 RIConfigBuilder::default()
//                     .build()
//                     .expect("failed to build default RIConfig"),
//             ),
//             r_ecc_keys: None,
//             r_mcounters: None,
//             r_user_data: None,
//             riscv_fw_version: None,
//             s_t_priv: Some(BinaryDataBase64(2, S_T_PRIV.into())),
//             s_t_pub: Some(BinaryDataBase64(2, S_T_PUB.into())),
//             spect_fw_version: None,
//             x509_certificate: Some(BinaryDataBase64(2, X509_CERTIFICATE.into())),
//         }
//     }
// }

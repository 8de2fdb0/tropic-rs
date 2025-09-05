mod common;

use log::info;
use tropic_rs::{cert_store, l2::info::FirmwareType};

use crate::common::*;

const DEVICE_PUBKEY: [u8; 32] = [
    0x95, 0x08, 0xf0, 0x32, 0x1c, 0xb1, 0xd2, 0xe5, 0xd1, 0xf1, 0xa4, 0x60, 0x9c, 0x05, 0x41, 0xb7,
    0x80, 0xe6, 0xdd, 0x50, 0xd6, 0x48, 0x2b, 0x6b, 0x08, 0xb2, 0xc2, 0x7e, 0x7b, 0x76, 0x26, 0x47,
];

const XXXX_PUBKEY: [u8; 97] = [
    0x04, 0xb5, 0xb7, 0x29, 0xf4, 0x82, 0x5b, 0xca, 0x3a, 0xda, 0x2d, 0xee, 0xae, 0xca, 0xca, 0xb5,
    0xc4, 0x77, 0x96, 0xe4, 0x7f, 0x72, 0x27, 0x89, 0x88, 0xa0, 0xe6, 0xbd, 0xf2, 0xa8, 0x3c, 0x02,
    0xca, 0xe2, 0x2d, 0xca, 0xa6, 0x43, 0xbc, 0x7c, 0xac, 0xd4, 0x5d, 0xe5, 0x15, 0x35, 0x45, 0x97,
    0xde, 0x07, 0x72, 0x33, 0x88, 0xff, 0x79, 0x86, 0x42, 0x3f, 0x83, 0x8f, 0x25, 0x3f, 0x30, 0x4c,
    0xe0, 0xad, 0x0a, 0xf0, 0x21, 0x53, 0x05, 0xa7, 0x80, 0x50, 0x7a, 0x57, 0x94, 0x41, 0xaa, 0xc2,
    0x56, 0x3b, 0xcd, 0x8f, 0xcf, 0x10, 0x61, 0x2d, 0x3c, 0xb7, 0x88, 0x2b, 0xfa, 0x6c, 0xe4, 0xcd,
    0xd3,
];

const TROPIC_01_PUBKEY: [u8; 97] = [
    0x04, 0x76, 0x7a, 0x06, 0xca, 0x5c, 0xda, 0xa1, 0xda, 0x5b, 0x81, 0x77, 0xdc, 0x4f, 0x92, 0xd9,
    0x6b, 0xdc, 0x6d, 0x34, 0xc8, 0x33, 0xfb, 0xcb, 0x67, 0x43, 0x6f, 0xbc, 0x5d, 0xf8, 0x0d, 0xe0,
    0x61, 0xb2, 0x91, 0x82, 0x2b, 0x32, 0x82, 0xd9, 0xd1, 0x0a, 0x63, 0x3d, 0x6d, 0x5c, 0x39, 0x15,
    0xcc, 0xc4, 0x61, 0x8b, 0x01, 0x5d, 0x23, 0x87, 0x89, 0x13, 0xd9, 0xd1, 0x2d, 0x50, 0x6d, 0x1d,
    0x12, 0xdb, 0x0c, 0x5d, 0xc2, 0x79, 0x66, 0x78, 0x74, 0x5f, 0xc6, 0x44, 0xe9, 0x3b, 0x17, 0x41,
    0x70, 0x45, 0x16, 0x46, 0x67, 0x70, 0x3f, 0xeb, 0xcb, 0x42, 0xb8, 0x6a, 0xb8, 0x8d, 0x81, 0xd8,
    0xc4,
];

const ROOT_PUBKEY: [u8; 133] = [
    0x04, 0x01, 0x35, 0xc7, 0xa2, 0x4d, 0x16, 0xb3, 0x74, 0xb2, 0x07, 0xad, 0xe8, 0xfe, 0x50, 0xf5,
    0x03, 0xad, 0x34, 0xe0, 0xe5, 0x96, 0xc8, 0x3f, 0xc9, 0x8a, 0xdb, 0x4c, 0x43, 0x88, 0xca, 0x0a,
    0xd9, 0xb2, 0x4e, 0x77, 0xe9, 0x84, 0xb8, 0x97, 0x82, 0x53, 0xa8, 0xe0, 0xd6, 0xfd, 0x68, 0xea,
    0xa8, 0xd9, 0xc9, 0xa9, 0xa6, 0xc8, 0x83, 0x5a, 0x13, 0x8c, 0xcc, 0xff, 0x51, 0x13, 0x0d, 0xa1,
    0x09, 0x86, 0x80, 0x00, 0xcd, 0xf7, 0xfa, 0xd5, 0xa0, 0x2b, 0xbd, 0x84, 0x45, 0x3c, 0x56, 0x36,
    0xf2, 0x5f, 0x1c, 0x39, 0x5b, 0xdc, 0x22, 0xee, 0x7b, 0x44, 0x1a, 0x81, 0xb5, 0x9f, 0x20, 0x40,
    0x53, 0x89, 0xf4, 0x7d, 0x65, 0xf0, 0x74, 0xa6, 0x02, 0xf9, 0x33, 0x2d, 0xf1, 0x33, 0x79, 0xf2,
    0x7d, 0x65, 0x4f, 0x4e, 0x1b, 0x0f, 0xd4, 0x56, 0xc1, 0xa9, 0x9f, 0x54, 0x36, 0x64, 0x0f, 0x7e,
    0xe0, 0x4e, 0x1b, 0x48, 0x81,
];

#[test]
fn test_get_cert_store() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_get_cert_store")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let mut tropic_01 = get_tropic_test_instance(model_server.port().expect("failed to get port"));

    let mut cert_buffer = [0u8; cert_store::CERT_BUFFER_LEN];

    info!("Reading X509 Certificate Store...");
    let cert_store = tropic_01
        .get_cert_store(&mut cert_buffer)
        .expect("failed to get cert store");

    for cert in &cert_store.certificates {
        assert!(cert.is_some(), "certificate is none");
        // TODO: add more logging once nom_decoder can parse more fields
        // if let Some(cert) = cert {
        //     info!("Certificate: {:?}", cert.)
        // }
    }

    let cert_device_pubkey = cert_store
        .get_pubkey_as_bytes(cert_store::CertKind::Device)
        .expect("failed to get device key");
    assert_eq!(cert_device_pubkey, DEVICE_PUBKEY);

    let cert_xxxx_pubkey = cert_store
        .get_pubkey_as_bytes(cert_store::CertKind::Xxxxx)
        .expect("failed to get device key");
    assert_eq!(cert_xxxx_pubkey, XXXX_PUBKEY);

    let cert_tropic_01_pubkey = cert_store
        .get_pubkey_as_bytes(cert_store::CertKind::Tropic01)
        .expect("failed to get device key");
    assert_eq!(cert_tropic_01_pubkey, TROPIC_01_PUBKEY);

    let cert_root_pubkey = cert_store
        .get_pubkey_as_bytes(cert_store::CertKind::TropicRoot)
        .expect("failed to get device key");
    assert_eq!(cert_root_pubkey, ROOT_PUBKEY);

    model_server.cleanup();
}

// values from 2025-06-27T07-51-29Z__prod_C2S_T200__provisioning__lab_batch_package/tropic01_lab_batch_package.yml
const CHIP_ID_VERSION: [u8; 4] = *b"\x01\x00\x00\x00";
const MANUFACTURING_TEST: [u8; 16] = *b"\x00\x00\x00\x00\x00\x00\x00\x00ACAB\x80\xaa\xff\xff";
const PROVISIONING_INFO: [u8; 16] =
    *b"\x01\xf0\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";
const SERIAL_NUMBER_V1: [u8; 16] =
    *b"\x01\xf0\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const SERIAL_NUMBER_V2: [u8; 16] = *b"\x02\xf0\x02\x00\x00\x00\x19\x06\x1b\t3\x00\x00\x00\x00\x00";
const PART_NUMBER: [u8; 16] = *b"\rTR01-C2S-T200\xff\xff";
const PROVISIONING_DATA: [u8; 20] =
    *b"\x01\x04\xd8\x96a(\x00\x0c}\xed\xa8p\x19\x06\x1b\t3\xff\xff\xff";

const MODEL_BINATY_DATA: [u8; 128] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 67, 65, 66, 128, 170, 255, 255, 1, 240, 2, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 240, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 240, 2, 0,
    0, 0, 25, 6, 27, 9, 51, 0, 0, 0, 0, 0, 13, 84, 82, 48, 49, 45, 67, 50, 83, 45, 84, 50, 48, 48,
    255, 255, 1, 4, 216, 150, 97, 40, 0, 12, 125, 237, 168, 112, 25, 6, 27, 9, 51, 255, 255, 255,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub fn find_pattern(haystack: &[u8; 128], needle: &[u8]) -> Option<(usize, usize)> {
    if needle.len() > haystack.len() {
        return None;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        let window = &haystack[i..(i + needle.len())];
        if window == needle {
            let start = i;
            let end = i + needle.len();
            return Some((start, end));
        }
    }
    None
}

#[test]
fn test_get_chip_id() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_get_chip_id")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let mut tropic_01 = get_tropic_test_instance(model_server.port().expect("failed to get port"));

    info!("Reading Chip ID...");
    let chip_id = tropic_01.get_chip_id().expect("failed to get chip_id");

    assert_eq!(
        find_pattern(&MODEL_BINATY_DATA, &CHIP_ID_VERSION),
        Some((0, 4))
    );
    assert_eq!(chip_id.chip_id_ver, CHIP_ID_VERSION);

    assert_eq!(
        find_pattern(&MODEL_BINATY_DATA, &MANUFACTURING_TEST),
        Some((4, 20))
    );
    assert_eq!(chip_id.fl_chip_info, MANUFACTURING_TEST);

    assert_eq!(
        find_pattern(&MODEL_BINATY_DATA, &PROVISIONING_INFO),
        Some((20, 36))
    );
    assert_eq!(
        chip_id.manu_info,
        tropic_rs::l2::info::ManufacturingInfo::from(PROVISIONING_INFO)
    );

    assert_eq!(
        find_pattern(&MODEL_BINATY_DATA, &SERIAL_NUMBER_V1),
        Some((36, 52))
    );
    assert_eq!(
        chip_id.prov_info,
        tropic_rs::l2::info::SerialNumberV1::from(SERIAL_NUMBER_V1)
    );

    assert_eq!(
        find_pattern(&MODEL_BINATY_DATA, &SERIAL_NUMBER_V2),
        Some((52, 68))
    );
    assert_eq!(
        chip_id.prov_info_v2,
        tropic_rs::l2::info::SerialNumberV2::from(SERIAL_NUMBER_V2)
    );

    assert_eq!(
        find_pattern(&MODEL_BINATY_DATA, &PART_NUMBER),
        Some((68, 84))
    );
    assert_eq!(chip_id.part_number, PART_NUMBER);

    assert_eq!(
        find_pattern(&MODEL_BINATY_DATA, &PROVISIONING_DATA),
        Some((84, 104))
    );
    assert_eq!(
        chip_id.prov_data,
        tropic_rs::l2::info::ProvisioningData::from(PROVISIONING_DATA)
    );

    assert_eq!(chip_id.rfu_4, [0u8; 24]);

    model_server.cleanup();
}

const RISCV_FW_VERSION: [u8; 4] = *b"risc";
const SPECT_FW_VERSION: [u8; 4] = *b"spec";

#[test]
fn test_firmware_versions() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_firmware_versions")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let mut tropic_01 = get_tropic_test_instance(model_server.port().expect("failed to get port"));

    info!("Reading RISC-V FW version...");
    let risc_firmware_versions = tropic_01
        .get_firmware_version(FirmwareType::Riscv)
        .expect("failed to get risc firmware versions");
    assert_eq!(risc_firmware_versions.version, RISCV_FW_VERSION);

    info!("Reading SPECT FW version...");
    let spect_firmware_versions = tropic_01
        .get_firmware_version(FirmwareType::Spect)
        .expect("failed to get spect firmware versions");
    assert_eq!(spect_firmware_versions.version, SPECT_FW_VERSION);

    model_server.cleanup();
}

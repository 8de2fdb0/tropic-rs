mod testing_common;

use log::info;
use rand::Rng;

use tropic_rs::{
    common::{MAC_AND_DESTROY_SLOT_MAX, MacAndDestroySlot, PairingKeySlot, hmac_sha256},
    l3::EncSession,
};

use crate::testing_common::*;

const PIN_LEN_MAX: usize = 2048;

const KDF_KEY_ZEROS: [u8; 256] = [0u8; 256];

fn xor_cyphertext(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut ciphertext = [0u8; 32];
    for (c, (x, y)) in ciphertext.iter_mut().zip(a.iter().zip(b.iter())) {
        *c = x ^ y;
    }
    ciphertext
}

#[test]
fn test_xor_cyphertext() {
    const S: [u8; 32] = [
        0x5a, 0x5e, 0x4e, 0x1c, 0x03, 0x5c, 0x36, 0x31, 0x7c, 0x28, 0x12, 0x09, 0x48, 0x13, 0x88,
        0x5b, 0xac, 0x6a, 0x7c, 0xaf, 0x10, 0x95, 0x13, 0xe8, 0xf9, 0xce, 0x24, 0x6b, 0xb6, 0x9c,
        0x3c, 0x10,
    ];
    const K_I: [u8; 32] = [
        0x7c, 0xf5, 0xdb, 0x12, 0xe4, 0xc2, 0x14, 0x4b, 0x36, 0xaf, 0xa4, 0xcb, 0xb4, 0x13, 0x72,
        0x11, 0xe4, 0x7d, 0xdb, 0x8a, 0x48, 0x51, 0x8c, 0x6a, 0x7e, 0xcc, 0xbe, 0xda, 0xca, 0x1a,
        0x18, 0xa6,
    ];
    const CIPHERTEXT: [u8; 32] = [
        0x26, 0xab, 0x95, 0x0e, 0xe7, 0x9e, 0x22, 0x7a, 0x4a, 0x87, 0xb6, 0xc2, 0xfc, 0x00, 0xfa,
        0x4a, 0x48, 0x17, 0xa7, 0x25, 0x58, 0xc4, 0x9f, 0x82, 0x87, 0x02, 0x9a, 0xb1, 0x7c, 0x86,
        0x24, 0xb6,
    ];

    let ciphertext = xor_cyphertext(&S, &K_I);
    assert_eq!(ciphertext, CIPHERTEXT);
}

#[derive(Debug, PartialEq)]
enum Error {
    Tropic(tropic_rs::Error),
    InvalidPin,
}

impl From<tropic_rs::Error> for Error {
    fn from(e: tropic_rs::Error) -> Self {
        Error::Tropic(e)
    }
}

fn check_pin(
    tropic_rs: &mut Tropic01TestInstance,
    session: &mut EncSession,
    pin: &[u8],
    slot: MacAndDestroySlot,
    ciphertext: &[u8; 32],
    t: &[u8; 32],
) -> Result<[u8; 32], Error> {
    info!("Computing v = KDF(0, PIN_DATA)...");
    let v = hmac_sha256(&KDF_KEY_ZEROS, pin);

    info!("Executing MAC_And_Destroy with v and slot #{}...", slot);
    let mac_and_destroy_resp = tropic_rs.mac_and_destroy(session, &slot, &v)?;

    info!("Computing k_i = KDF(w, PIN_DATA)...");
    let k_i = hmac_sha256(&mac_and_destroy_resp.data_out, pin);

    info!("Decrypting (XOR) c_i using k_i...");
    let pin_decrypted = xor_cyphertext(ciphertext, &k_i);

    info!("Computing t' = KDF(s, \"0\")...");
    let t_prime = hmac_sha256(&pin_decrypted, &[b'0']);
    info!("Checking t == t'...");
    if t != &t_prime {
        return Err(Error::InvalidPin);
    }
    // assert_eq!(t, &t_prime);
    Ok(pin_decrypted)
}

#[test]
fn test_l3_mac_and_destroy() {
    setup_logging();

    info!("Starting model server");
    let mut model_server = ModelServerBuilder::default()
        .test_name("test_l3_mac_and_destroy")
        .build()
        .expect("failed to build model server");
    model_server.start_tcp();

    let (mut tropic_01, mut session) = get_tropic_test_instance_with_session(
        SamplePairingKey::TvlModelSlot0.to_x25519_secret(),
        PairingKeySlot::Index0,
        model_server.port().expect("failed to get port"),
    );

    info!("Setup PIN");
    info!(
        "Generating random number of max attempts n from {{1...{}}}...",
        MAC_AND_DESTROY_SLOT_MAX
    );
    let n = rand::rng().random_range(1..=MAC_AND_DESTROY_SLOT_MAX);

    info!("Generating random 32B secret s...");
    let s = rand::rng().random::<[u8; 32]>();

    info!(
        "Generating random length from {{1...{}}} for the PIN...",
        PIN_LEN_MAX
    );
    let pin_len = rand::rng().random_range(1..=PIN_LEN_MAX);
    info!("Generating random PIN of length {}...", pin_len);
    let pin = rand_bytes(pin_len);

    info!("Computing t = KDF(s, \"0\")...");
    let t = hmac_sha256(&s, &[b'0']);

    info!("Computing u = KDF(s, \"1\")...");
    let u = hmac_sha256(&s, &[b'1']);

    info!("Computing v = KDF(0, PIN_DATA)...");
    let v = hmac_sha256(&KDF_KEY_ZEROS, &pin);

    let mut ciphertexts = [[0_u8; 32]; 128];

    info!("Starting {} blocks of MAC_And_Destroy sequences", n);
    for i in 0..n {
        info!("Executing MAC_And_Destroy with u and slot #{}...", i);
        let _ = tropic_01
            .mac_and_destroy(&mut session, &i.try_into().expect("invalid slot"), &u)
            .expect("failed to execute MAC_And_Destroy");

        info!("Executing MAC_And_Destroy with v and slot #{}...", i);
        let mac_and_destroy_resp = tropic_01
            .mac_and_destroy(&mut session, &i.try_into().expect("invalid slot"), &v)
            .expect("failed to execute MAC_And_Destroy");

        info!("Executing MAC_And_Destroy with u and slot #{}...", i);
        let _ = tropic_01
            .mac_and_destroy(&mut session, &i.try_into().expect("invalid slot"), &u)
            .expect("failed to execute MAC_And_Destroy");

        info!("Computing k_i = KDF(w, PIN_DATA)...");
        let k_i = hmac_sha256(&mac_and_destroy_resp.data_out, &pin);

        info!("Encrypting (XOR) s using k_i...");
        ciphertexts[i as usize] = xor_cyphertext(&s, &k_i);
    }

    let k_from_setup = hmac_sha256(&s, &[b'2']);

    info!(
        "Generating a random number of wrong attempts from {{0...{}}}...",
        n - 1,
    );
    let wrong_attempts = rand::rng().random_range(0..n - 1);

    let mut pin_wrong = pin.clone();
    pin_wrong[0] ^= 0xFF; // Corrupt the PIN to make it wrong
    info!("Starting {} wrong attempts", wrong_attempts);
    for i in 0..wrong_attempts {
        info!("Doing wrong attempt #{} to check PIN", i);
        let result = check_pin(
            &mut tropic_01,
            &mut session,
            &pin_wrong,
            i.try_into().expect("invalid slot"),
            &ciphertexts[i as usize],
            &t,
        );
        assert!(result.is_err());
        assert_eq!(result.err(), Some(Error::InvalidPin));
    }

    info!(
        "Checking PIN with the first undestroyed slot #{}...",
        wrong_attempts
    );
    let s = check_pin(
        &mut tropic_01,
        &mut session,
        &pin,
        wrong_attempts.try_into().expect("invalid slot"),
        &ciphertexts[wrong_attempts as usize],
        &t,
    )
    .expect("failed to check PIN");

    info!("Comparing cryptographic key k to the one from the setup phase...");
    let k_from_check = hmac_sha256(&s, &[b'2']);
    assert_eq!(k_from_setup, k_from_check);

    info!("Starting a restoration of destroyed slots");
    info!("Computing u = KDF(s, \"1\")...");
    let u = hmac_sha256(&s, &[b'1']);

    for i in 0..=wrong_attempts {
        info!("Restoring slot #{}...", i);
        let _ = tropic_01
            .mac_and_destroy(&mut session, &i.try_into().expect("invalid slot"), &u)
            .expect("failed to execute MAC_And_Destroy");
    }

    info!("Checking PIN with all used slots...");
    for i in 0..n {
        info!("Doing an attempt with the correct PIN with slot #{}...", i);
        let s_check = check_pin(
            &mut tropic_01,
            &mut session,
            &pin,
            i.try_into().expect("invalid slot"),
            &ciphertexts[i as usize],
            &t,
        )
        .expect("failed to check PIN");

        info!("Comparing cryptographic key k to the one from the setup phase...");
        let k_from_check = hmac_sha256(&s_check, &[b'2']);
        assert_eq!(k_from_setup, k_from_check);
    }

    model_server.cleanup();
}

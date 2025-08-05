use rand_core::{CryptoRng, RngCore};
use rand_core_compat::Rng09;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn generate_key_pair<R>(mut rng: R) -> (EphemeralSecret, PublicKey)
where
    R: RngCore + CryptoRng,
{
    // Generate a 32-byte secret key using the provided RNG
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    let compat_rng = Rng09(rng);
    let secret = EphemeralSecret::random_from_rng(compat_rng);
    let public = PublicKey::from(&secret);

    (secret, public)
}

pub fn get_shared_secret(host_privkey: EphemeralSecret, tropic_pubbkey: &PublicKey) -> [u8; 32] {
    let shared_secret = host_privkey.diffie_hellman(tropic_pubbkey);
    shared_secret.to_bytes()
}

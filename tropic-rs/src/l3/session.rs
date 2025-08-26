use aes_gcm::{
    Aes256Gcm, Key,
    aead::{AeadMutInPlace, KeyInit},
};
use hmac::Mac;
use rand_core::{CryptoRng, RngCore};
use rand_core_compat::Rng09;
use sha2::Digest;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{common::PairingKeySlot, l3::TAG_LEN};

/// Noise_KK1_25519_AESGCM_SHA256\x00\x00\x00
const PROTOCOL_NAME: [u8; 32] = [
    b'N', b'o', b'i', b's', b'e', b'_', b'K', b'K', b'1', b'_', b'2', b'5', b'5', b'1', b'9', b'_',
    b'A', b'E', b'S', b'G', b'C', b'M', b'_', b'S', b'H', b'A', b'2', b'5', b'6', 0x00, 0x00, 0x00,
];

#[derive(Debug)]
pub enum Error {
    HkdfInvalidLength(hkdf::InvalidLength),
    AesAead(aes_gcm::aead::Error),
    NonceOverflow,
    #[cfg(test)]
    BadDecTag,
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HkdfInvalidLength(err) => write!(f, "hkdf invalid length: {}", err),
            Self::AesAead(err) => write!(f, "aes aead error: {}", err),
            Self::NonceOverflow => write!(f, "nonce overflow"),
            #[cfg(test)]
            Self::BadDecTag => write!(f, "bad decryption tag"),
        }
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(err: hkdf::InvalidLength) -> Self {
        Self::HkdfInvalidLength(err)
    }
}

impl From<aes_gcm::aead::Error> for Error {
    fn from(err: aes_gcm::aead::Error) -> Self {
        Self::AesAead(err)
    }
}

pub trait Session {
    fn encrypt_request(&mut self, data: &mut [u8]) -> Result<[u8; 16], Error>;

    fn decrypt_response(&mut self, data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error>;
}

pub fn generate_key_pair<R>(mut rng: R) -> (StaticSecret, PublicKey)
where
    R: RngCore + CryptoRng,
{
    // Generate a 32-byte secret key using the provided RNG
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    let compat_rng = Rng09(rng);
    let secret = StaticSecret::random_from_rng(compat_rng);
    let public = PublicKey::from(&secret);

    (secret, public)
}

fn cumulative_sha256(input: &[u8], cumulative: Option<&[u8]>) -> [u8; 32] {
    let mut hasher = sha2::Sha256::default();
    if let Some(cumulative) = cumulative {
        hasher.update(cumulative);
    }
    hasher.update(&input);
    let hash = hasher.finalize();
    hash.into()
}

fn generate_hash(
    // static host pairing pubkey
    sh_pubkey: &PublicKey,
    // static host pairing key index
    pairing_key_slot: PairingKeySlot,
    // static tropic public key from certstore
    st_pubkey: &PublicKey,
    // ephemeral host pubkey
    eh_pubkey: &PublicKey,
    // ephemeral Tropic public key
    et_pubkey: &PublicKey,
) -> [u8; 32] {
    let h = cumulative_sha256(&PROTOCOL_NAME, None);
    let h = cumulative_sha256(&sh_pubkey.to_bytes(), Some(&h));
    let h = cumulative_sha256(&st_pubkey.to_bytes(), Some(&h));
    let h = cumulative_sha256(&eh_pubkey.to_bytes(), Some(&h));
    let h = cumulative_sha256(&[pairing_key_slot as u8], Some(&h));
    cumulative_sha256(&et_pubkey.to_bytes(), Some(&h))
}

fn tropic_hkdf(
    init_key: &[u8],
    info_context: &[u8],
) -> Result<([u8; 32], [u8; 32]), hkdf::InvalidLength> {
    let mut output_1 = [0_u8; 32];
    let mut output_2 = [0_u8; 32];

    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(init_key).unwrap();
    mac.update(info_context);
    let tmp = mac.finalize().into_bytes();

    // output_1 = HMAC(tmp, 0x01)
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&tmp).unwrap();
    mac.update(&[0x01]);
    output_1.copy_from_slice(&mac.finalize().into_bytes());

    // output_2 = HMAC(tmp, output_1 || 0x02)
    let mut helper = [0u8; 33];
    helper[..32].copy_from_slice(&mut output_1);
    helper[32] = 0x02;
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&tmp).unwrap();
    mac.update(&helper);
    output_2.copy_from_slice(&mac.finalize().into_bytes());
    Ok((output_1, output_2))
}

#[derive(Default)]
struct TropicNonce {
    value: [u8; 12],
}

impl TropicNonce {
    fn increase(&mut self) -> Result<(), Error> {
        let mut nonce_int = u32::from_le_bytes(self.value[..4].try_into().unwrap());
        if nonce_int == u32::MAX {
            return Err(Error::NonceOverflow);
        }
        nonce_int += 1;
        self.value[..4].copy_from_slice(&nonce_int.to_le_bytes());
        Ok(())
    }
}

pub struct EncSession {
    nonce_cmd: TropicNonce,
    nonce_res: TropicNonce,
    k_auth: [u8; 32],
    k_cmd: [u8; 32],
    k_res: [u8; 32],
    handshake_hash: [u8; 32],
}

impl EncSession {
    pub fn create_session(
        // static host pairing key
        sh_secret: &StaticSecret,
        // static host pairing key index
        pairing_key_slot: PairingKeySlot,
        // static tropic public key from certstore
        st_pubkey: &PublicKey,
        // ephemeral host key
        eh_secret: &StaticSecret,
        // ephemeral Tropic public key
        et_pubkey: &PublicKey,
        // l2 handshake auth Utag
        auth_tag: &[u8; TAG_LEN],
    ) -> Result<Self, Error> {
        let sh_pubkey: x25519_dalek::PublicKey = sh_secret.into();
        let eh_pubkey: x25519_dalek::PublicKey = eh_secret.into();

        let h = generate_hash(
            &sh_pubkey,
            pairing_key_slot,
            &st_pubkey,
            &eh_pubkey,
            &et_pubkey,
        );

        // ck = HKDF (ck, X25519(EHPRIV, ETPUB), 1)
        let shared_secret = eh_secret.diffie_hellman(et_pubkey);
        let (output_1, _output_2) = tropic_hkdf(&PROTOCOL_NAME, shared_secret.as_bytes())?;

        // ck = HKDF (ck, X25519(SHiPRIV, ETPUB), 1)
        let shared_secret = sh_secret.diffie_hellman(et_pubkey);
        let (output_1, _output_2) = tropic_hkdf(&output_1, shared_secret.as_bytes())?;

        // ck, kAUTH = HKDF (ck, X25519(EHPRIV, STPUB), 2)
        let shared_secret = eh_secret.diffie_hellman(st_pubkey);
        let (output_1, kauth) = tropic_hkdf(&output_1, shared_secret.as_bytes())?;
        let (kcmd, kres) = tropic_hkdf(&output_1, &[])?;

        // aes-gcm
        let key: &Key<Aes256Gcm> = &kauth.into();
        let nonce = [0_u8; 12];

        let mut buf = [0_u8; 0];
        let mut cipher = Aes256Gcm::new(&key);
        cipher.decrypt_in_place_detached(&nonce.into(), &h, &mut buf, auth_tag.into())?;

        Ok(Self {
            nonce_cmd: TropicNonce::default(),
            nonce_res: TropicNonce::default(),
            k_auth: kauth,
            k_cmd: kcmd,
            k_res: kres,
            handshake_hash: h,
        })
    }

    pub fn encrypt_request(&mut self, data: &mut [u8]) -> Result<[u8; 16], Error> {
        let mut cipher = Aes256Gcm::new(&self.k_cmd.into());
        let tag = cipher.encrypt_in_place_detached(&self.nonce_cmd.value.into(), &[], data)?;
        self.nonce_cmd.increase()?;
        Ok(tag.into())
    }

    pub fn decrypt_response(&mut self, data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
        let mut cipher = Aes256Gcm::new(&self.k_res.into());
        cipher.decrypt_in_place_detached(&self.nonce_res.value.into(), &[], data, tag.into())?;
        self.nonce_res.increase()?;
        Ok(())
    }
}

impl Session for EncSession {
    fn decrypt_response(&mut self, data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
        self.decrypt_response(data, tag)
    }
    fn encrypt_request(&mut self, data: &mut [u8]) -> Result<[u8; 16], Error> {
        self.encrypt_request(data)
    }
}

#[cfg(test)]
pub(crate) mod mock {
    use super::*;

    pub struct MockSession {
        pub enc_tag: [u8; 16],
        pub dec_tag: [u8; 16],
    }

    impl Session for MockSession {
        fn decrypt_response(&mut self, _data: &mut [u8], tag: &[u8; 16]) -> Result<(), Error> {
            for i in 0..tag.len() {
                if tag[i] != self.dec_tag[i] {
                    return Err(Error::BadDecTag);
                }
            }
            Ok(())
        }

        fn encrypt_request(&mut self, _data: &mut [u8]) -> Result<[u8; 16], Error> {
            Ok(self.enc_tag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // const PKEY_INDEX: u8 = 0x0;

    const HASH: [u8; 32] = [
        0xbf, 0x1d, 0x41, 0x2d, 0xf3, 0xc8, 0xe2, 0xcb, 0xf9, 0xeb, 0xc1, 0xb1, 0xa7, 0x8a, 0x48,
        0xc3, 0x89, 0xca, 0xbe, 0x83, 0x22, 0x1c, 0x72, 0x4a, 0x49, 0x13, 0xe3, 0x9b, 0xef, 0x77,
        0x41, 0x45,
    ];
    // const SHARED_SECRET_1: [u8; 32] = [
    //     0x89, 0xf3, 0xe2, 0xc0, 0xab, 0x82, 0x24, 0xe2, 0xbb, 0x97, 0x3d, 0xc6, 0x45, 0x2a, 0xcc,
    //     0xd3, 0xe8, 0x13, 0x22, 0x18, 0x8e, 0x06, 0x1e, 0xf0, 0x46, 0xb4, 0x7c, 0xb2, 0xf4, 0x78,
    //     0x61, 0x0c,
    // ];
    // const SHARED_SECRET_2: [u8; 32] = [
    //     0xb7, 0x86, 0x36, 0x96, 0xec, 0xd2, 0x30, 0x94, 0x03, 0x65, 0x42, 0xe4, 0x78, 0xf3, 0xec,
    //     0x9a, 0x20, 0x63, 0xdf, 0x00, 0xed, 0xef, 0xe3, 0x88, 0xff, 0x7a, 0x5a, 0x92, 0xed, 0xb2,
    //     0x22, 0x18,
    // ];
    // const SHARED_SECRET_3: [u8; 32] = [
    //     0xbb, 0x1c, 0x19, 0xd3, 0x42, 0x16, 0x0a, 0x3d, 0xe3, 0x41, 0x25, 0x0a, 0xc5, 0x9c, 0x2f,
    //     0x86, 0xb1, 0x8f, 0x1b, 0x0e, 0x76, 0xf0, 0x60, 0x37, 0x60, 0x2b, 0xf1, 0x7a, 0x2f, 0x4e,
    //     0x87, 0x12,
    // ];
    const AUTH_TAG: [u8; 16] = [
        0xdf, 0xb2, 0xe2, 0xb4, 0xd5, 0x03, 0x13, 0x5b, 0x1b, 0xab, 0x3a, 0x65, 0x45, 0x28, 0xf1,
        0x6f,
    ];
    const SHI_PRIV: [u8; 32] = [
        0x28, 0x3f, 0x5a, 0x0f, 0xfc, 0x41, 0xcf, 0x50, 0x98, 0xa8, 0xe1, 0x7d, 0xb6, 0x37, 0x2c,
        0x3c, 0xaa, 0xd1, 0xee, 0xee, 0xdf, 0x0f, 0x75, 0xbc, 0x3f, 0xbf, 0xcd, 0x9c, 0xab, 0x3d,
        0xe9, 0x72,
    ];
    // const SHI_PUB: [u8; 32] = [
    //     0xf9, 0x75, 0xeb, 0x3c, 0x2f, 0xd7, 0x90, 0xc9, 0x6f, 0x29, 0x4f, 0x15, 0x57, 0xa5, 0x03,
    //     0x17, 0x80, 0xc9, 0xaa, 0xfa, 0x14, 0x0d, 0xa2, 0x8f, 0x55, 0xe7, 0x51, 0x57, 0x37, 0xb2,
    //     0x50, 0x2c,
    // ];
    const ST_PUB: [u8; 32] = [
        0x95, 0x08, 0xf0, 0x32, 0x1c, 0xb1, 0xd2, 0xe5, 0xd1, 0xf1, 0xa4, 0x60, 0x9c, 0x05, 0x41,
        0xb7, 0x80, 0xe6, 0xdd, 0x50, 0xd6, 0x48, 0x2b, 0x6b, 0x08, 0xb2, 0xc2, 0x7e, 0x7b, 0x76,
        0x26, 0x47,
    ];
    const EH_PRIV: [u8; 32] = [
        0x5a, 0x6e, 0x75, 0x72, 0xb0, 0xf9, 0xb2, 0x47, 0x05, 0x01, 0x85, 0x03, 0x4f, 0x5c, 0x69,
        0x0a, 0xbc, 0x1a, 0xb3, 0x30, 0xfa, 0xcc, 0x08, 0x2c, 0x16, 0xbb, 0x00, 0x73, 0x35, 0x9a,
        0x11, 0x0d,
    ];
    // const EH_PUB: [u8; 32] = [
    //     0x94, 0x71, 0xea, 0xcd, 0xcc, 0xb7, 0x20, 0xfb, 0x15, 0x4f, 0x9d, 0xbb, 0x54, 0x64, 0x94,
    //     0x6b, 0xa7, 0xf3, 0xf7, 0x40, 0x4e, 0x11, 0x72, 0x15, 0xe7, 0xb5, 0x51, 0x38, 0x26, 0x0f,
    //     0xe4, 0x48,
    // ];
    const ET_PUB: [u8; 32] = [
        0x7f, 0x85, 0xf3, 0x71, 0xee, 0x96, 0x0b, 0x49, 0x39, 0xcd, 0x96, 0x71, 0xf0, 0x33, 0x32,
        0x22, 0xd6, 0x0c, 0xb6, 0x5c, 0x42, 0x32, 0xdb, 0x96, 0xa3, 0xbd, 0x3f, 0x88, 0xa9, 0x68,
        0x07, 0x4b,
    ];
    const KAUTH: [u8; 32] = [
        0x2e, 0x27, 0x4f, 0xdc, 0x52, 0x88, 0x8a, 0xe3, 0x86, 0xed, 0xc3, 0x43, 0x49, 0x7e, 0x8e,
        0x2d, 0x6d, 0x34, 0x56, 0x72, 0x5a, 0x66, 0x55, 0xb6, 0x90, 0x82, 0x1b, 0x05, 0xc6, 0x74,
        0x1d, 0x48,
    ];
    const KCMD: [u8; 32] = [
        0x5c, 0x53, 0xab, 0x75, 0xc3, 0xfb, 0xe9, 0x39, 0x2b, 0xff, 0x32, 0xe1, 0xad, 0x42, 0x84,
        0x3e, 0x0d, 0x3c, 0xd3, 0x65, 0x73, 0x13, 0x36, 0x1b, 0xfe, 0xbe, 0xbb, 0xa8, 0xf6, 0x86,
        0xcd, 0x5f,
    ];
    const KRES: [u8; 32] = [
        0x0e, 0x58, 0xf6, 0x92, 0x51, 0xb0, 0xfd, 0xfb, 0x07, 0x49, 0xb6, 0xd8, 0x3e, 0xf8, 0xf0,
        0xb5, 0xbf, 0x33, 0xe6, 0x89, 0x6b, 0xb3, 0xbf, 0x74, 0x83, 0xe7, 0xbd, 0x4e, 0x1a, 0xf8,
        0x26, 0x7f,
    ];

    #[test]
    fn test_generat_hash() {
        let sh_pubkey = PublicKey::from(&StaticSecret::from(SHI_PRIV));
        let eh_pubkey = PublicKey::from(&StaticSecret::from(EH_PRIV));

        let hash = generate_hash(
            &sh_pubkey,
            PairingKeySlot::Index0,
            &ST_PUB.into(),
            &eh_pubkey,
            &ET_PUB.into(),
        );

        assert_eq!(hash, HASH);
    }

    #[test]
    fn test_hkdf() {
        let eh_secret = StaticSecret::from(EH_PRIV);
        let sh_secret = StaticSecret::from(SHI_PRIV);
        let et_pubkey = PublicKey::from(ET_PUB);
        let st_pubkey = PublicKey::from(ST_PUB);

        // ck = HKDF (ck, X25519(EHPRIV, ETPUB), 1)
        let shared_secret = eh_secret.diffie_hellman(&et_pubkey);
        let (output_1, _output_2) = tropic_hkdf(&PROTOCOL_NAME, shared_secret.as_bytes())
            .expect("unable to create tropic hkdf");

        // ck = HKDF (ck, X25519(SHiPRIV, ETPUB), 1)
        let shared_secret = sh_secret.diffie_hellman(&et_pubkey);
        let (output_1, _output_2) =
            tropic_hkdf(&output_1, shared_secret.as_bytes()).expect("unable to create tropic hkdf");

        // ck, kAUTH = HKDF (ck, X25519(EHPRIV, STPUB), 2)
        let shared_secret = eh_secret.diffie_hellman(&st_pubkey);
        let (output_1, kauth) =
            tropic_hkdf(&output_1, shared_secret.as_bytes()).expect("unable to create tropic hkdf");
        let (kcmd, kres) = tropic_hkdf(&output_1, &[]).expect("unable to create tropic hkdf");

        assert_eq!(kauth, KAUTH);
        assert_eq!(kcmd, KCMD);
        assert_eq!(kres, KRES);
    }

    #[test]
    fn test_create_session() {
        let enc_session = EncSession::create_session(
            &SHI_PRIV.into(),
            PairingKeySlot::Index0,
            &ST_PUB.into(),
            &EH_PRIV.into(),
            &ET_PUB.into(),
            &AUTH_TAG,
        )
        .expect("unable to create session");

        assert_eq!(enc_session.k_auth, KAUTH);
        assert_eq!(enc_session.k_cmd, KCMD);
        assert_eq!(enc_session.k_res, KRES);
    }

    #[test]
    fn test_k_auth_fail() {
        let key: [u8; 32] = [
            178, 95, 193, 61, 142, 18, 4, 163, 190, 211, 23, 249, 179, 92, 5, 77, 238, 165, 246,
            143, 90, 88, 145, 116, 0, 235, 212, 139, 157, 247, 235, 124,
        ];

        let nonce = [0_u8; 12];

        let associated_data: [u8; 32] = [
            137, 23, 29, 167, 14, 120, 140, 26, 39, 206, 107, 166, 63, 80, 116, 153, 170, 22, 56,
            241, 181, 252, 205, 212, 149, 84, 166, 61, 196, 180, 118, 64,
        ];

        let mut buffer = [0u8; 0];
        let tag: [u8; 16] = [
            6, 231, 210, 98, 87, 116, 91, 243, 112, 106, 197, 154, 252, 76, 213, 99,
        ];

        let mut cipher = Aes256Gcm::new(&key.into());

        let result = cipher.decrypt_in_place_detached(
            &nonce.into(),
            &associated_data,
            &mut buffer,
            &tag.into(),
        );

        assert_eq!(result.unwrap_err(), aes_gcm::Error)
    }

    #[test]
    fn test_k_auth_working() {
        let key: [u8; 32] = [
            46, 39, 79, 220, 82, 136, 138, 227, 134, 237, 195, 67, 73, 126, 142, 45, 109, 52, 86,
            114, 90, 102, 85, 182, 144, 130, 27, 5, 198, 116, 29, 72,
        ];

        let nonce = [0_u8; 12];

        let associated_data: [u8; 32] = [
            191, 29, 65, 45, 243, 200, 226, 203, 249, 235, 193, 177, 167, 138, 72, 195, 137, 202,
            190, 131, 34, 28, 114, 74, 73, 19, 227, 155, 239, 119, 65, 69,
        ];

        let mut buffer = [0u8; 0];
        let tag: [u8; 16] = [
            223, 178, 226, 180, 213, 3, 19, 91, 27, 171, 58, 101, 69, 40, 241, 111,
        ];

        let mut cipher = Aes256Gcm::new(&key.into());

        cipher
            .decrypt_in_place_detached(&nonce.into(), &associated_data, &mut buffer, &tag.into())
            .expect("unable to decrypt k_auth");
    }

    #[test]
    fn test_nonce_increase() {
        let mut nonce = TropicNonce {
            value: [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        assert!(nonce.increase().is_ok());
        assert_eq!(
            nonce.value,
            [
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn test_nonce_overflow() {
        let mut nonce = TropicNonce {
            value: [
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        assert!(nonce.increase().is_err());
        assert_eq!(
            nonce.value,
            [
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }
}

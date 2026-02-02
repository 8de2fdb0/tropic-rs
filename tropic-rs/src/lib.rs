#![no_std]

mod crc16;
mod error;

pub mod common;
pub mod l1;
pub mod l2;
pub mod l3;
pub mod transport;
pub mod tropic;

pub mod cert_store {
    #[cfg(test)]
    pub use crate::l2::cert::tests::{MockCertificate, MockDecoder};

    pub use crate::l2::cert_store::{
        CERT_BUFFER_LEN, CERT_SIZE_SINGLE, CertStore, Error as CertStoreError,
    };

    pub use crate::l2::cert::{
        CertDecoder, CertKind, Certificate, Error, ErrorKind, ErrorType, PubKeyAlgorithm,
        SubjectPubkey,
    };
}

pub use tropic::{Error, Tropic01};

pub mod external {
    pub mod x25519_dalek {
        pub use x25519_dalek::{PublicKey, StaticSecret};
    }
}

#[cfg(test)]
pub mod mocks {
    pub use crate::l2::cert::tests::{MockCertificate, MockDecoder};
}

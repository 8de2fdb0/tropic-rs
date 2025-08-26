#![no_std]

mod crc16;
mod error;

pub mod common;
pub mod l1;
pub mod l2;
pub mod l3;
pub mod tropic;

pub mod cert_store {
    #[cfg(test)]
    pub(crate) use crate::l2::cert::tests::{MockCertificate, MockDecoder};

    pub use crate::l2::cert_store::{CertStore, Error as CertStoreError};

    pub use crate::l2::cert::{
        CertDecoder, CertKind, Certificate, Error, ErrorKind, ErrorType, PubKeyAlgorithm,
        SubjectPubkey,
    };
}

pub use tropic::{Error, Tropic01};

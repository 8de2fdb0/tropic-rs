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

    pub use tropic_cert_decoder::{
        CERT_SIZE_SINGLE, CertDecoder, CertKind, Certificate, Error, ErrorKind, ErrorType,
        PubKeyAlgorithm, SubjectPubkey,
    };

    pub use crate::l2::cert_store::{CERT_BUFFER_LEN, CertStore, Error as CertStoreError};
}

pub use tropic::{Error, Tropic01};

pub mod external {
    pub mod x25519_dalek {
        pub use x25519_dalek::{PublicKey, StaticSecret};
    }
}

#[cfg(test)]
pub mod mocks {
    pub use crate::l2::cert_store::tests::{MockCertificate, MockDecoder};
}

pub mod version {
    //! Version information about the tropic-rs library.

    #[derive(Debug)]
    pub struct VersionInfo {
        pub carggo_debug: &'static str,
        pub cargo_feature: &'static str,
        pub cargo_target: &'static str,
        pub git_branch: &'static str,
        pub git_commit: &'static str,
        pub git_describe: &'static str,
    }

    #[cfg(feature = "display")]
    impl core::fmt::Display for VersionInfo {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "cargo: [debug: {}, features: {}, target: {}] git:[branch: {}, commit: {}, describe: {}]",
                self.carggo_debug,
                self.cargo_feature,
                self.cargo_target,
                self.git_branch,
                self.git_commit,
                self.git_describe
            )
        }
    }

    /// Returns the version information of the tropic-rs library.
    pub fn info() -> &'static VersionInfo {
        &VersionInfo {
            carggo_debug: env!("VERGEN_CARGO_DEBUG"),
            cargo_feature: env!("VERGEN_CARGO_FEATURES"),
            cargo_target: env!("VERGEN_CARGO_TARGET_TRIPLE"),
            git_branch: env!("VERGEN_GIT_BRANCH"),
            git_commit: env!("VERGEN_GIT_SHA"),
            git_describe: env!("VERGEN_GIT_DESCRIBE"),
        }
    }
}

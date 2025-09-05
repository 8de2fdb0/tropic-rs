pub mod delay {
    use embedded_hal::delay::DelayNs;
    pub struct MockDelay;

    impl DelayNs for MockDelay {
        fn delay_ns(&mut self, _ns: u32) {
            // we don't need a real delay here
            // if ns > 0 {
            //     let quick_ns = ns.div_ceil(10000);
            //     std::thread::sleep(Duration::from_nanos(quick_ns as u64));
            // }
        }
    }
}

pub mod certificat {
    use tropic_rs::cert_store::{
        CertDecoder, CertKind, Certificate, ErrorType, PubKeyAlgorithm, SubjectPubkey,
    };

    pub struct MockCertificate<'a> {
        kind: CertKind,
        pubkey: &'a [u8],
    }

    impl<'a> ErrorType for MockCertificate<'a> {
        type Error<'b> = core::convert::Infallible;
    }

    impl<'a> Certificate<'a> for MockCertificate<'a> {
        fn kind(&self) -> &CertKind {
            &self.kind
        }
        fn pubkey(&self) -> Result<SubjectPubkey<'a>, Self::Error<'_>> {
            Ok(SubjectPubkey {
                algorithm: PubKeyAlgorithm::X25519Pubkey,
                public_key: self.pubkey,
            })
        }
    }

    pub struct MockDecoder {
        #[allow(unused)]
        kind: CertKind,
        #[allow(unused)]
        pubkey: [u8; 32],
    }

    impl ErrorType for MockDecoder {
        type Error<'a> = core::convert::Infallible;
    }

    impl CertDecoder for MockDecoder {
        type Cert<'a> = MockCertificate<'a>;

        fn from_der_and_kind<'a>(
            der_buf: &'a [u8],
            kind: CertKind,
        ) -> Result<Self::Cert<'a>, Self::Error<'a>> {
            Ok(MockCertificate {
                pubkey: der_buf,
                kind,
            })
        }
    }
}

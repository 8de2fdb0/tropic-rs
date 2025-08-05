pub mod nom_parser;

use tropic_rs::cert_store::{CertDecoder, CertKind, Certificate, ErrorType};

#[non_exhaustive]
#[derive(Debug)]
pub enum Error<'a> {
    NomParser(nom_parser::Error<'a>),
    ExtractPubKey,
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Error<'a> {
    fn format(&self, f: defmt::Formatter) {
        match self {
            // Format the error using Debug so it prints as a string
            Self::NomParser(e) => defmt::write!(f, "nom paerser errro: {:?}", e),
            Self::ExtractPubKey => defmt::write!(f, "unable to extract pubkey"),
        }
    }
}

#[cfg(feature = "display")]
impl<'a> core::fmt::Display for Error<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NomParser(e) => f.write_fmt(format_args!("nom paerser errro: {}", e)),
            Self::ExtractPubKey => f.write_str("unable to extract pubkey"),
        }
    }
}

impl<'a> tropic_rs::cert_store::Error for Error<'a> {
    fn kind(&self) -> tropic_rs::cert_store::ErrorKind {
        match self {
            Self::NomParser(_) => tropic_rs::cert_store::ErrorKind::Decoding,
            Self::ExtractPubKey => tropic_rs::cert_store::ErrorKind::ExtractPubKey,
        }
    }
}

impl<'a> From<nom_parser::Error<'a>> for Error<'a> {
    fn from(err: nom_parser::Error<'a>) -> Self {
        Self::NomParser(err)
    }
}

#[derive(Debug)]
pub struct NomCertificate<'a> {
    kind: CertKind,
    cert: nom_parser::Certificate<'a>,
}

impl<'a> ErrorType for NomCertificate<'a> {
    type Error<'b> = Error<'a>;
}

impl<'a> Certificate<'a> for NomCertificate<'a> {
    fn kind(&self) -> &CertKind {
        &self.kind
    }
    fn pubkey(&self) -> Result<&[u8], Self::Error<'a>> {
        match nom_parser::find_subject_public_key_info(
            self.cert.tbs_certificate,
            &nom_parser::OBJ_ID_CURVEX25519,
            &nom_parser::OID_ECDSA_WITH_SHA512,
        ) {
            Some(bytes) => Ok(bytes),
            None => Err(Error::ExtractPubKey),
        }
    }
}

pub struct NomDecoder;

impl ErrorType for NomDecoder {
    type Error<'a> = Error<'a>;
}

impl CertDecoder for NomDecoder {
    type Cert<'a> = NomCertificate<'a>;

    fn from_der_and_kind<'a>(
        der_buf: &'a [u8],
        kind: CertKind,
    ) -> Result<Self::Cert<'a>, Self::Error<'a>> {
        let cert = nom_parser::extract_x509_certificate_parts(&der_buf)?;
        Ok(NomCertificate { kind, cert })
    }
}

pub mod x509_parser;

use der::Decode;
use tropic_rs::cert_store::{CertDecoder, CertKind, Certificate, ErrorType};

#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    Spki(spki::Error),
    Der(der::Error),
    ExtractPubKey,
}

#[cfg(feature = "defmt")]
fn defmt_der(f: defmt::Formatter, err: &der::Error) {
    match err.kind() {
        der::ErrorKind::Incomplete {
            expected_len,
            actual_len,
        } => defmt::write!(
            f,
            "ASN.1 DER message is incomplete: expected {}, actual {}",
            u32::from(expected_len),
            u32::from(actual_len)
        ),
        der::ErrorKind::TrailingData { decoded, remaining } => defmt::write!(
            f,
            "trailing data at end of DER message: decoded {} bytes, {} bytes remaining",
            u32::from(decoded),
            u32::from(remaining)
        ),
        _ => defmt::write!(f, "Failed"),
    }
}

#[cfg(feature = "defmt")]
fn defmt_spki(f: defmt::Formatter, err: &spki::Error) {
    match err {
        spki::Error::AlgorithmParametersMissing => {
            defmt::write!(f, "AlgorithmIdentifier parameters missing")
        }
        spki::Error::Asn1(e) => defmt_der(f, e),
        spki::Error::KeyMalformed => defmt::write!(f, "SPKI cryptographic key data malformed"),
        spki::Error::OidUnknown { oid } => {
            defmt::write!(f, "unknown/unsupported algorithm OID: {}", oid.as_bytes())
        }
        _ => defmt::write!(f, "Failed"),
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Error {
    fn format(&self, f: defmt::Formatter) {
        match self {
            Self::Spki(e) => defmt_spki(f, e),
            Self::Der(e) => defmt_der(f, e),
            Self::ExtractPubKey => defmt::write!(f, "unable to extract pubkey"),
        }
    }
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Spki(err) => f.write_fmt(format_args!("asn1 parsing error: {}", err)),
            Self::Der(err) => f.write_fmt(format_args!("der parsing error: {}", err)),
            Self::ExtractPubKey => f.write_str("unable to extract pubkey"),
        }
    }
}

impl tropic_rs::cert_store::Error for Error {
    fn kind(&self) -> tropic_rs::cert_store::ErrorKind {
        match self {
            Self::Spki(_) => tropic_rs::cert_store::ErrorKind::Decoding,
            Self::Der(_) => tropic_rs::cert_store::ErrorKind::Decoding,
            Self::ExtractPubKey => tropic_rs::cert_store::ErrorKind::ExtractPubKey,
        }
    }
}
impl From<der::Error> for Error {
    fn from(err: der::Error) -> Self {
        Self::Der(err)
    }
}

#[derive(Debug)]
pub struct DerCertificate<'a> {
    kind: CertKind,
    cert: x509_parser::Certificate<'a>,
}

impl<'a> ErrorType for DerCertificate<'a> {
    type Error<'b> = Error;
}

impl<'a> Certificate<'a> for DerCertificate<'a> {
    fn kind(&self) -> &CertKind {
        &self.kind
    }
    fn pubkey(&self) -> Result<&[u8], Self::Error<'_>> {
        match self
            .cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
        {
            Some(bytes) => Ok(bytes),
            None => Err(Error::ExtractPubKey),
        }
    }
}

pub struct DerDecoder;

impl ErrorType for DerDecoder {
    type Error<'a> = Error;
}

impl CertDecoder for DerDecoder {
    type Cert<'a> = DerCertificate<'a>;

    fn from_der_and_kind<'a>(
        der_buf: &'a [u8],
        kind: CertKind,
    ) -> Result<Self::Cert<'a>, Self::Error<'a>> {
        let cert = x509_parser::Certificate::from_der(&der_buf)?;
        Ok(DerCertificate { kind, cert })
    }
}

pub mod nom_parser;

use tropic_rs::cert_store::{CertDecoder, CertKind, Certificate, ErrorType, SubjectPubkey};

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

impl tropic_rs::cert_store::Error for Error<'_> {
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
    fn pubkey(&self) -> Result<SubjectPubkey<'a>, Self::Error<'a>> {
        Ok(SubjectPubkey {
            algorithm: self.cert.spki.algorithm.clone(),
            public_key: self.cert.spki.public_key.data,
        })
    }
}

pub struct NomDecoder;

impl ErrorType for NomDecoder {
    type Error<'a> = Error<'a>;
}

impl CertDecoder for NomDecoder {
    type Cert<'a> = NomCertificate<'a>;

    fn from_der_and_kind(
        der_buf: &[u8],
        kind: CertKind,
    ) -> Result<Self::Cert<'_>, Self::Error<'_>> {
        let cert = nom_parser::extract_x509_certificate_parts(der_buf)?;
        Ok(NomCertificate { kind, cert })
    }
}

#[cfg(test)]
mod tests {
    use tropic_rs::cert_store::{self, PubKeyAlgorithm};

    use super::*;

    const DER_1: [u8; 424] = [
        48, 130, 1, 164, 48, 130, 1, 42, 160, 3, 2, 1, 2, 2, 16, 1, 240, 15, 0, 5, 68, 84, 83, 84,
        48, 49, 3, 0, 7, 0, 22, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 48, 82, 49, 11, 48, 9,
        6, 3, 85, 4, 6, 19, 2, 67, 90, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 84, 114, 111, 112,
        105, 99, 32, 83, 113, 117, 97, 114, 101, 32, 115, 46, 114, 46, 111, 46, 49, 36, 48, 34, 6,
        3, 85, 4, 3, 12, 27, 84, 82, 79, 80, 73, 67, 48, 49, 45, 88, 32, 67, 65, 32, 118, 49, 45,
        86, 65, 76, 73, 68, 65, 84, 73, 79, 78, 48, 30, 23, 13, 50, 53, 48, 50, 50, 49, 48, 56, 49,
        48, 53, 51, 90, 23, 13, 52, 53, 48, 50, 50, 49, 48, 56, 49, 48, 53, 51, 90, 48, 34, 49, 32,
        48, 30, 6, 3, 85, 4, 3, 12, 23, 84, 82, 79, 80, 73, 67, 48, 49, 32, 101, 83, 69, 45, 86,
        65, 76, 73, 68, 65, 84, 73, 79, 78, 48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0, 242, 65,
        182, 143, 78, 1, 255, 248, 105, 41, 10, 10, 140, 192, 157, 121, 121, 150, 33, 98, 12, 76,
        74, 108, 42, 181, 21, 46, 189, 162, 100, 105, 163, 65, 48, 63, 48, 12, 6, 3, 85, 29, 19, 1,
        1, 255, 4, 2, 48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 3, 8, 48, 31, 6, 3,
        85, 29, 35, 4, 24, 48, 22, 128, 20, 160, 126, 23, 201, 129, 74, 37, 161, 46, 118, 8, 236,
        34, 70, 178, 168, 246, 27, 190, 62, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 3, 104, 0,
        48, 101, 2, 48, 26, 112, 109, 155, 151, 152, 49, 53, 130, 76, 122, 136, 165, 124, 167, 109,
        67, 43, 55, 105, 78, 175, 134, 55, 250, 236, 245, 105, 228, 40, 88, 211, 151, 237, 245, 73,
        29, 204, 163, 15, 12, 105, 4, 186, 172, 252, 36, 216, 2, 49, 0, 147, 198, 165, 192, 156,
        165, 229, 75, 26, 24, 65, 14, 235, 184, 141, 214, 101, 42, 48, 76, 115, 0, 125, 32, 181,
        223, 164, 218, 145, 13, 237, 162, 104, 192, 32, 13, 74, 226, 187, 26, 31, 61, 235, 8, 13,
        189, 236, 125,
    ];

    const DER_1_PUBKEY: [u8; 32] = [
        0xf2, 0x41, 0xb6, 0x8f, 0x4e, 0x01, 0xff, 0xf8, 0x69, 0x29, 0x0a, 0x0a, 0x8c, 0xc0, 0x9d,
        0x79, 0x79, 0x96, 0x21, 0x62, 0x0c, 0x4c, 0x4a, 0x6c, 0x2a, 0xb5, 0x15, 0x2e, 0xbd, 0xa2,
        0x64, 0x69,
    ];

    const DER_1_SIGNATURE: [u8; 103] = [
        0x30, 0x65, 0x02, 0x30, 0x1a, 0x70, 0x6d, 0x9b, 0x97, 0x98, 0x31, 0x35, 0x82, 0x4c, 0x7a,
        0x88, 0xa5, 0x7c, 0xa7, 0x6d, 0x43, 0x2b, 0x37, 0x69, 0x4e, 0xaf, 0x86, 0x37, 0xfa, 0xec,
        0xf5, 0x69, 0xe4, 0x28, 0x58, 0xd3, 0x97, 0xed, 0xf5, 0x49, 0x1d, 0xcc, 0xa3, 0x0f, 0x0c,
        0x69, 0x04, 0xba, 0xac, 0xfc, 0x24, 0xd8, 0x02, 0x31, 0x00, 0x93, 0xc6, 0xa5, 0xc0, 0x9c,
        0xa5, 0xe5, 0x4b, 0x1a, 0x18, 0x41, 0x0e, 0xeb, 0xb8, 0x8d, 0xd6, 0x65, 0x2a, 0x30, 0x4c,
        0x73, 0x00, 0x7d, 0x20, 0xb5, 0xdf, 0xa4, 0xda, 0x91, 0x0d, 0xed, 0xa2, 0x68, 0xc0, 0x20,
        0x0d, 0x4a, 0xe2, 0xbb, 0x1a, 0x1f, 0x3d, 0xeb, 0x08, 0x0d, 0xbd, 0xec, 0x7d,
    ];

    const DER_2: [u8; 581] = [
        48, 130, 2, 65, 48, 130, 1, 199, 160, 3, 2, 1, 2, 2, 2, 39, 17, 48, 10, 6, 8, 42, 134, 72,
        206, 61, 4, 3, 3, 48, 90, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 67, 90, 49, 29, 48, 27, 6,
        3, 85, 4, 10, 12, 20, 84, 114, 111, 112, 105, 99, 32, 83, 113, 117, 97, 114, 101, 32, 115,
        46, 114, 46, 111, 46, 49, 44, 48, 42, 6, 3, 85, 4, 3, 12, 35, 84, 114, 111, 112, 105, 99,
        32, 83, 113, 117, 97, 114, 101, 32, 82, 111, 111, 116, 32, 67, 65, 32, 118, 49, 45, 86, 65,
        76, 73, 68, 65, 84, 73, 79, 78, 48, 32, 23, 13, 50, 52, 49, 50, 50, 56, 49, 56, 48, 57, 50,
        56, 90, 24, 15, 50, 48, 53, 57, 49, 50, 50, 56, 49, 56, 48, 57, 50, 56, 90, 48, 82, 49, 11,
        48, 9, 6, 3, 85, 4, 6, 19, 2, 67, 90, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 84, 114,
        111, 112, 105, 99, 32, 83, 113, 117, 97, 114, 101, 32, 115, 46, 114, 46, 111, 46, 49, 36,
        48, 34, 6, 3, 85, 4, 3, 12, 27, 84, 82, 79, 80, 73, 67, 48, 49, 45, 88, 32, 67, 65, 32,
        118, 49, 45, 86, 65, 76, 73, 68, 65, 84, 73, 79, 78, 48, 118, 48, 16, 6, 7, 42, 134, 72,
        206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0, 4, 180, 28, 57, 113, 37, 108, 15, 100,
        182, 183, 118, 209, 199, 86, 67, 181, 200, 151, 229, 19, 60, 194, 148, 240, 127, 28, 78,
        62, 40, 186, 98, 226, 162, 207, 224, 206, 60, 214, 95, 17, 248, 51, 22, 163, 38, 97, 115,
        104, 6, 55, 116, 193, 96, 226, 75, 135, 120, 61, 223, 31, 48, 119, 64, 45, 36, 74, 63, 144,
        35, 124, 190, 69, 184, 76, 2, 34, 8, 141, 65, 214, 59, 149, 140, 214, 65, 93, 193, 200,
        153, 15, 212, 51, 243, 39, 208, 10, 163, 102, 48, 100, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4,
        20, 160, 126, 23, 201, 129, 74, 37, 161, 46, 118, 8, 236, 34, 70, 178, 168, 246, 27, 190,
        62, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 0, 48, 14, 6, 3, 85,
        29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 215,
        240, 84, 17, 16, 136, 120, 24, 3, 12, 140, 149, 6, 87, 94, 187, 96, 157, 41, 240, 48, 10,
        6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 3, 104, 0, 48, 101, 2, 48, 34, 105, 234, 244, 116, 69,
        115, 42, 177, 16, 54, 210, 170, 4, 24, 19, 179, 243, 18, 245, 37, 142, 156, 173, 148, 207,
        201, 239, 80, 232, 94, 93, 166, 202, 170, 44, 152, 71, 192, 126, 165, 135, 3, 174, 244,
        131, 191, 57, 2, 49, 0, 238, 90, 35, 200, 234, 93, 172, 124, 75, 199, 223, 31, 192, 176,
        165, 129, 209, 126, 93, 179, 247, 64, 185, 119, 185, 70, 231, 59, 24, 232, 148, 216, 241,
        41, 89, 74, 243, 61, 181, 105, 253, 62, 134, 94, 18, 181, 174, 61,
    ];

    const DER_2_PUBKEY: [u8; 97] = [
        0x04, 0xb4, 0x1c, 0x39, 0x71, 0x25, 0x6c, 0x0f, 0x64, 0xb6, 0xb7, 0x76, 0xd1, 0xc7, 0x56,
        0x43, 0xb5, 0xc8, 0x97, 0xe5, 0x13, 0x3c, 0xc2, 0x94, 0xf0, 0x7f, 0x1c, 0x4e, 0x3e, 0x28,
        0xba, 0x62, 0xe2, 0xa2, 0xcf, 0xe0, 0xce, 0x3c, 0xd6, 0x5f, 0x11, 0xf8, 0x33, 0x16, 0xa3,
        0x26, 0x61, 0x73, 0x68, 0x06, 0x37, 0x74, 0xc1, 0x60, 0xe2, 0x4b, 0x87, 0x78, 0x3d, 0xdf,
        0x1f, 0x30, 0x77, 0x40, 0x2d, 0x24, 0x4a, 0x3f, 0x90, 0x23, 0x7c, 0xbe, 0x45, 0xb8, 0x4c,
        0x02, 0x22, 0x08, 0x8d, 0x41, 0xd6, 0x3b, 0x95, 0x8c, 0xd6, 0x41, 0x5d, 0xc1, 0xc8, 0x99,
        0x0f, 0xd4, 0x33, 0xf3, 0x27, 0xd0, 0x0a,
    ];

    const DER_2_SIGNATURE: [u8; 103] = [
        0x30, 0x65, 0x02, 0x30, 0x22, 0x69, 0xea, 0xf4, 0x74, 0x45, 0x73, 0x2a, 0xb1, 0x10, 0x36,
        0xd2, 0xaa, 0x04, 0x18, 0x13, 0xb3, 0xf3, 0x12, 0xf5, 0x25, 0x8e, 0x9c, 0xad, 0x94, 0xcf,
        0xc9, 0xef, 0x50, 0xe8, 0x5e, 0x5d, 0xa6, 0xca, 0xaa, 0x2c, 0x98, 0x47, 0xc0, 0x7e, 0xa5,
        0x87, 0x03, 0xae, 0xf4, 0x83, 0xbf, 0x39, 0x02, 0x31, 0x00, 0xee, 0x5a, 0x23, 0xc8, 0xea,
        0x5d, 0xac, 0x7c, 0x4b, 0xc7, 0xdf, 0x1f, 0xc0, 0xb0, 0xa5, 0x81, 0xd1, 0x7e, 0x5d, 0xb3,
        0xf7, 0x40, 0xb9, 0x77, 0xb9, 0x46, 0xe7, 0x3b, 0x18, 0xe8, 0x94, 0xd8, 0xf1, 0x29, 0x59,
        0x4a, 0xf3, 0x3d, 0xb5, 0x69, 0xfd, 0x3e, 0x86, 0x5e, 0x12, 0xb5, 0xae, 0x3d,
    ];

    const DER_3: [u8; 626] = [
        48, 130, 2, 110, 48, 130, 1, 207, 160, 3, 2, 1, 2, 2, 2, 3, 233, 48, 10, 6, 8, 42, 134, 72,
        206, 61, 4, 3, 4, 48, 90, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 67, 90, 49, 29, 48, 27, 6,
        3, 85, 4, 10, 12, 20, 84, 114, 111, 112, 105, 99, 32, 83, 113, 117, 97, 114, 101, 32, 115,
        46, 114, 46, 111, 46, 49, 44, 48, 42, 6, 3, 85, 4, 3, 12, 35, 84, 114, 111, 112, 105, 99,
        32, 83, 113, 117, 97, 114, 101, 32, 82, 111, 111, 116, 32, 67, 65, 32, 118, 49, 45, 86, 65,
        76, 73, 68, 65, 84, 73, 79, 78, 48, 32, 23, 13, 50, 52, 49, 50, 50, 56, 49, 56, 48, 57, 50,
        56, 90, 24, 15, 50, 48, 54, 52, 49, 50, 50, 56, 49, 56, 48, 57, 50, 56, 90, 48, 90, 49, 11,
        48, 9, 6, 3, 85, 4, 6, 19, 2, 67, 90, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 84, 114,
        111, 112, 105, 99, 32, 83, 113, 117, 97, 114, 101, 32, 115, 46, 114, 46, 111, 46, 49, 44,
        48, 42, 6, 3, 85, 4, 3, 12, 35, 84, 114, 111, 112, 105, 99, 32, 83, 113, 117, 97, 114, 101,
        32, 82, 111, 111, 116, 32, 67, 65, 32, 118, 49, 45, 86, 65, 76, 73, 68, 65, 84, 73, 79, 78,
        48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0, 4,
        201, 106, 94, 208, 78, 129, 191, 222, 91, 3, 21, 60, 181, 12, 25, 60, 36, 240, 15, 121, 9,
        174, 228, 148, 16, 27, 175, 51, 143, 128, 248, 131, 113, 4, 42, 68, 209, 237, 207, 60, 7,
        235, 182, 73, 102, 125, 252, 244, 176, 223, 206, 244, 223, 109, 108, 237, 23, 247, 231, 58,
        81, 232, 190, 188, 82, 159, 71, 185, 64, 143, 206, 108, 118, 79, 76, 182, 115, 213, 255,
        119, 229, 18, 108, 5, 192, 224, 124, 45, 204, 103, 62, 249, 129, 20, 189, 253, 163, 102,
        48, 100, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 215, 240, 84, 17, 16, 136, 120, 24, 3, 12,
        140, 149, 6, 87, 94, 187, 96, 157, 41, 240, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48,
        6, 1, 1, 255, 2, 1, 1, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 6, 48, 31, 6, 3,
        85, 29, 35, 4, 24, 48, 22, 128, 20, 10, 231, 166, 114, 61, 216, 62, 51, 78, 115, 8, 145,
        100, 30, 129, 60, 89, 254, 16, 83, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 4, 3, 129,
        140, 0, 48, 129, 136, 2, 66, 0, 158, 147, 5, 57, 141, 176, 77, 213, 131, 193, 144, 184,
        224, 29, 210, 34, 45, 73, 184, 122, 155, 176, 164, 135, 127, 14, 4, 162, 197, 217, 41, 132,
        180, 28, 189, 67, 68, 129, 29, 115, 252, 191, 204, 120, 182, 61, 13, 122, 110, 219, 80,
        115, 95, 128, 11, 134, 102, 152, 150, 13, 171, 178, 45, 21, 136, 2, 66, 1, 194, 96, 16, 54,
        41, 148, 120, 149, 211, 116, 228, 195, 147, 231, 231, 33, 184, 194, 223, 107, 222, 153,
        157, 179, 35, 229, 100, 80, 210, 15, 191, 192, 171, 110, 96, 190, 87, 131, 111, 86, 37,
        132, 240, 197, 165, 156, 24, 188, 82, 201, 88, 48, 51, 75, 123, 117, 231, 183, 243, 82,
        115, 182, 204, 122, 19,
    ];

    const DER_3_PUBKEY: [u8; 97] = [
        0x04, 0xc9, 0x6a, 0x5e, 0xd0, 0x4e, 0x81, 0xbf, 0xde, 0x5b, 0x03, 0x15, 0x3c, 0xb5, 0x0c,
        0x19, 0x3c, 0x24, 0xf0, 0x0f, 0x79, 0x09, 0xae, 0xe4, 0x94, 0x10, 0x1b, 0xaf, 0x33, 0x8f,
        0x80, 0xf8, 0x83, 0x71, 0x04, 0x2a, 0x44, 0xd1, 0xed, 0xcf, 0x3c, 0x07, 0xeb, 0xb6, 0x49,
        0x66, 0x7d, 0xfc, 0xf4, 0xb0, 0xdf, 0xce, 0xf4, 0xdf, 0x6d, 0x6c, 0xed, 0x17, 0xf7, 0xe7,
        0x3a, 0x51, 0xe8, 0xbe, 0xbc, 0x52, 0x9f, 0x47, 0xb9, 0x40, 0x8f, 0xce, 0x6c, 0x76, 0x4f,
        0x4c, 0xb6, 0x73, 0xd5, 0xff, 0x77, 0xe5, 0x12, 0x6c, 0x05, 0xc0, 0xe0, 0x7c, 0x2d, 0xcc,
        0x67, 0x3e, 0xf9, 0x81, 0x14, 0xbd, 0xfd,
    ];

    const DER_3_SIGNATURE: [u8; 139] = [
        0x30, 0x81, 0x88, 0x02, 0x42, 0x00, 0x9e, 0x93, 0x05, 0x39, 0x8d, 0xb0, 0x4d, 0xd5, 0x83,
        0xc1, 0x90, 0xb8, 0xe0, 0x1d, 0xd2, 0x22, 0x2d, 0x49, 0xb8, 0x7a, 0x9b, 0xb0, 0xa4, 0x87,
        0x7f, 0x0e, 0x04, 0xa2, 0xc5, 0xd9, 0x29, 0x84, 0xb4, 0x1c, 0xbd, 0x43, 0x44, 0x81, 0x1d,
        0x73, 0xfc, 0xbf, 0xcc, 0x78, 0xb6, 0x3d, 0x0d, 0x7a, 0x6e, 0xdb, 0x50, 0x73, 0x5f, 0x80,
        0x0b, 0x86, 0x66, 0x98, 0x96, 0x0d, 0xab, 0xb2, 0x2d, 0x15, 0x88, 0x02, 0x42, 0x01, 0xc2,
        0x60, 0x10, 0x36, 0x29, 0x94, 0x78, 0x95, 0xd3, 0x74, 0xe4, 0xc3, 0x93, 0xe7, 0xe7, 0x21,
        0xb8, 0xc2, 0xdf, 0x6b, 0xde, 0x99, 0x9d, 0xb3, 0x23, 0xe5, 0x64, 0x50, 0xd2, 0x0f, 0xbf,
        0xc0, 0xab, 0x6e, 0x60, 0xbe, 0x57, 0x83, 0x6f, 0x56, 0x25, 0x84, 0xf0, 0xc5, 0xa5, 0x9c,
        0x18, 0xbc, 0x52, 0xc9, 0x58, 0x30, 0x33, 0x4b, 0x7b, 0x75, 0xe7, 0xb7, 0xf3, 0x52, 0x73,
        0xb6, 0xcc, 0x7a, 0x13,
    ];

    const DER_4: [u8; 626] = [
        48, 130, 2, 110, 48, 130, 1, 208, 160, 3, 2, 1, 2, 2, 1, 101, 48, 10, 6, 8, 42, 134, 72,
        206, 61, 4, 3, 4, 48, 90, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 67, 90, 49, 29, 48, 27, 6,
        3, 85, 4, 10, 12, 20, 84, 114, 111, 112, 105, 99, 32, 83, 113, 117, 97, 114, 101, 32, 115,
        46, 114, 46, 111, 46, 49, 44, 48, 42, 6, 3, 85, 4, 3, 12, 35, 84, 114, 111, 112, 105, 99,
        32, 83, 113, 117, 97, 114, 101, 32, 82, 111, 111, 116, 32, 67, 65, 32, 118, 49, 45, 86, 65,
        76, 73, 68, 65, 84, 73, 79, 78, 48, 32, 23, 13, 50, 52, 49, 50, 50, 56, 49, 56, 48, 57, 50,
        55, 90, 24, 15, 50, 48, 55, 52, 49, 50, 50, 56, 49, 56, 48, 57, 50, 55, 90, 48, 90, 49, 11,
        48, 9, 6, 3, 85, 4, 6, 19, 2, 67, 90, 49, 29, 48, 27, 6, 3, 85, 4, 10, 12, 20, 84, 114,
        111, 112, 105, 99, 32, 83, 113, 117, 97, 114, 101, 32, 115, 46, 114, 46, 111, 46, 49, 44,
        48, 42, 6, 3, 85, 4, 3, 12, 35, 84, 114, 111, 112, 105, 99, 32, 83, 113, 117, 97, 114, 101,
        32, 82, 111, 111, 116, 32, 67, 65, 32, 118, 49, 45, 86, 65, 76, 73, 68, 65, 84, 73, 79, 78,
        48, 129, 155, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 35, 3, 129,
        134, 0, 4, 0, 186, 243, 115, 237, 14, 72, 161, 208, 51, 120, 87, 184, 215, 10, 242, 59, 76,
        216, 14, 28, 201, 129, 96, 207, 119, 4, 2, 250, 107, 69, 140, 168, 58, 108, 8, 91, 90, 139,
        87, 133, 197, 148, 207, 173, 3, 87, 184, 202, 232, 116, 95, 236, 137, 170, 148, 46, 155,
        190, 199, 171, 114, 10, 130, 77, 120, 1, 171, 199, 48, 47, 246, 84, 164, 92, 227, 74, 155,
        110, 217, 88, 111, 248, 120, 140, 229, 196, 117, 9, 155, 255, 192, 154, 46, 151, 213, 45,
        31, 138, 69, 201, 25, 97, 89, 149, 185, 134, 164, 183, 248, 41, 227, 212, 141, 225, 98,
        137, 172, 220, 143, 27, 251, 205, 27, 137, 92, 239, 152, 242, 31, 40, 108, 163, 66, 48, 64,
        48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 10, 231, 166, 114, 61, 216, 62, 51, 78, 115, 8,
        145, 100, 30, 129, 60, 89, 254, 16, 83, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3,
        1, 1, 255, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 6, 48, 10, 6, 8, 42, 134,
        72, 206, 61, 4, 3, 4, 3, 129, 139, 0, 48, 129, 135, 2, 65, 18, 146, 92, 162, 52, 54, 202,
        49, 13, 207, 206, 214, 150, 254, 11, 86, 131, 225, 148, 70, 221, 34, 231, 238, 85, 207,
        205, 181, 147, 66, 11, 171, 7, 64, 233, 125, 214, 108, 9, 55, 139, 241, 44, 143, 238, 241,
        252, 141, 234, 36, 76, 48, 127, 59, 133, 92, 126, 244, 3, 31, 74, 223, 64, 224, 109, 2, 66,
        1, 207, 183, 177, 59, 196, 106, 196, 83, 119, 50, 194, 26, 199, 202, 6, 24, 193, 157, 217,
        9, 176, 229, 90, 204, 13, 36, 93, 30, 176, 228, 44, 64, 155, 231, 250, 144, 172, 160, 232,
        90, 244, 252, 206, 67, 74, 35, 123, 4, 167, 249, 220, 162, 188, 100, 62, 164, 69, 169, 164,
        8, 250, 26, 95, 199, 100,
    ];

    const DER_4_PUBKEY: [u8; 133] = [
        0x04, 0x00, 0xba, 0xf3, 0x73, 0xed, 0x0e, 0x48, 0xa1, 0xd0, 0x33, 0x78, 0x57, 0xb8, 0xd7,
        0x0a, 0xf2, 0x3b, 0x4c, 0xd8, 0x0e, 0x1c, 0xc9, 0x81, 0x60, 0xcf, 0x77, 0x04, 0x02, 0xfa,
        0x6b, 0x45, 0x8c, 0xa8, 0x3a, 0x6c, 0x08, 0x5b, 0x5a, 0x8b, 0x57, 0x85, 0xc5, 0x94, 0xcf,
        0xad, 0x03, 0x57, 0xb8, 0xca, 0xe8, 0x74, 0x5f, 0xec, 0x89, 0xaa, 0x94, 0x2e, 0x9b, 0xbe,
        0xc7, 0xab, 0x72, 0x0a, 0x82, 0x4d, 0x78, 0x01, 0xab, 0xc7, 0x30, 0x2f, 0xf6, 0x54, 0xa4,
        0x5c, 0xe3, 0x4a, 0x9b, 0x6e, 0xd9, 0x58, 0x6f, 0xf8, 0x78, 0x8c, 0xe5, 0xc4, 0x75, 0x09,
        0x9b, 0xff, 0xc0, 0x9a, 0x2e, 0x97, 0xd5, 0x2d, 0x1f, 0x8a, 0x45, 0xc9, 0x19, 0x61, 0x59,
        0x95, 0xb9, 0x86, 0xa4, 0xb7, 0xf8, 0x29, 0xe3, 0xd4, 0x8d, 0xe1, 0x62, 0x89, 0xac, 0xdc,
        0x8f, 0x1b, 0xfb, 0xcd, 0x1b, 0x89, 0x5c, 0xef, 0x98, 0xf2, 0x1f, 0x28, 0x6c,
    ];

    const DER_4_SIGNATURE: [u8; 138] = [
        0x30, 0x81, 0x87, 0x02, 0x41, 0x12, 0x92, 0x5c, 0xa2, 0x34, 0x36, 0xca, 0x31, 0x0d, 0xcf,
        0xce, 0xd6, 0x96, 0xfe, 0x0b, 0x56, 0x83, 0xe1, 0x94, 0x46, 0xdd, 0x22, 0xe7, 0xee, 0x55,
        0xcf, 0xcd, 0xb5, 0x93, 0x42, 0x0b, 0xab, 0x07, 0x40, 0xe9, 0x7d, 0xd6, 0x6c, 0x09, 0x37,
        0x8b, 0xf1, 0x2c, 0x8f, 0xee, 0xf1, 0xfc, 0x8d, 0xea, 0x24, 0x4c, 0x30, 0x7f, 0x3b, 0x85,
        0x5c, 0x7e, 0xf4, 0x03, 0x1f, 0x4a, 0xdf, 0x40, 0xe0, 0x6d, 0x02, 0x42, 0x01, 0xcf, 0xb7,
        0xb1, 0x3b, 0xc4, 0x6a, 0xc4, 0x53, 0x77, 0x32, 0xc2, 0x1a, 0xc7, 0xca, 0x06, 0x18, 0xc1,
        0x9d, 0xd9, 0x09, 0xb0, 0xe5, 0x5a, 0xcc, 0x0d, 0x24, 0x5d, 0x1e, 0xb0, 0xe4, 0x2c, 0x40,
        0x9b, 0xe7, 0xfa, 0x90, 0xac, 0xa0, 0xe8, 0x5a, 0xf4, 0xfc, 0xce, 0x43, 0x4a, 0x23, 0x7b,
        0x04, 0xa7, 0xf9, 0xdc, 0xa2, 0xbc, 0x64, 0x3e, 0xa4, 0x45, 0xa9, 0xa4, 0x08, 0xfa, 0x1a,
        0x5f, 0xc7, 0x64,
    ];

    #[test]
    fn test_parse_der_1() {
        let cert_store = NomDecoder::from_der_and_kind(&DER_1, cert_store::CertKind::Device)
            .expect("unable to parse der_1");

        assert_eq!(
            cert_store.cert.spki.algorithm,
            PubKeyAlgorithm::X25519Pubkey
        );
        assert_eq!(cert_store.cert.spki.public_key.data, DER_1_PUBKEY);

        assert_eq!(
            cert_store.cert.signature.alg,
            nom_parser::SignatureAlgorithm::EcdsaWithSha384
        );
        assert_eq!(cert_store.cert.signature.sig.data, DER_1_SIGNATURE);

        let subjetc_pubkey = cert_store.pubkey().expect("unable to parse pubkey");
        assert_eq!(subjetc_pubkey.public_key, &DER_1_PUBKEY);
    }

    #[test]
    fn test_parse_der_2() {
        let cert_store = NomDecoder::from_der_and_kind(&DER_2, cert_store::CertKind::Device)
            .expect("unable to parse der_1");

        assert_eq!(
            cert_store.cert.spki.algorithm,
            PubKeyAlgorithm::EcPubkeyP384
        );
        assert_eq!(cert_store.cert.spki.public_key.data, DER_2_PUBKEY);

        assert_eq!(
            cert_store.cert.signature.alg,
            nom_parser::SignatureAlgorithm::EcdsaWithSha384
        );
        assert_eq!(cert_store.cert.signature.sig.data, DER_2_SIGNATURE);

        let subjetc_pubkey = cert_store.pubkey().expect("unable to parse pubkey");
        assert_eq!(subjetc_pubkey.public_key, &DER_2_PUBKEY);
    }

    #[test]
    fn test_parse_der_3() {
        let cert_store = NomDecoder::from_der_and_kind(&DER_3, cert_store::CertKind::Device)
            .expect("unable to parse der_1");

        assert_eq!(
            cert_store.cert.spki.algorithm,
            PubKeyAlgorithm::EcPubkeyP384
        );
        assert_eq!(cert_store.cert.spki.public_key.data, DER_3_PUBKEY);

        assert_eq!(
            cert_store.cert.signature.alg,
            nom_parser::SignatureAlgorithm::EcdsaWithSha512
        );
        assert_eq!(cert_store.cert.signature.sig.data, DER_3_SIGNATURE);
        let subjetc_pubkey = cert_store.pubkey().expect("unable to parse pubkey");
        assert_eq!(subjetc_pubkey.public_key, &DER_3_PUBKEY);
    }

    #[test]
    fn test_parse_der_4() {
        let cert_store = NomDecoder::from_der_and_kind(&DER_4, cert_store::CertKind::Device)
            .expect("unable to parse der_1");

        assert_eq!(
            cert_store.cert.spki.algorithm,
            PubKeyAlgorithm::EcPubkeyP521
        );
        assert_eq!(cert_store.cert.spki.public_key.data, DER_4_PUBKEY);

        assert_eq!(
            cert_store.cert.signature.alg,
            nom_parser::SignatureAlgorithm::EcdsaWithSha512
        );
        assert_eq!(cert_store.cert.signature.sig.data, DER_4_SIGNATURE);

        let subjetc_pubkey = cert_store.pubkey().expect("unable to parse pubkey");
        assert_eq!(subjetc_pubkey.public_key, &DER_4_PUBKEY);
    }
}

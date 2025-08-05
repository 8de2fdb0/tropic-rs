use nom::{IResult, bytes::complete::take, number::complete::be_u8};

#[derive(Debug)]
pub enum Error<'a> {
    InvalidTopLevelSequence,
    MissingTbsCertificate,
    InvalidTbsCertificate,
    MissingSerialNumber,
    MissingSignatureAlgorithm,
    MissingIssuer,
    MissingValidity,
    MissingSubject,
    MissingSPKI,
    MissingSignatureAlgorithmTop,
    MissingSignatureValue,
    Nom(nom::Err<nom::error::Error<&'a [u8]>>),
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Error<'a> {
    fn format(&self, f: defmt::Formatter) {
        match self {
            Self::InvalidTopLevelSequence => {
                defmt::write!(f, "Invalid top-level SEQUENCE")
            }
            Self::MissingTbsCertificate => defmt::write!(f, "Missing tbsCertificate"),
            Self::InvalidTbsCertificate => defmt::write!(f, "Invalid tbsCertificate"),
            Self::MissingSerialNumber => defmt::write!(f, "Missing serialNumber"),
            Self::MissingSignatureAlgorithm => {
                defmt::write!(f, "Missing signatureAlgorithm")
            }
            Self::MissingIssuer => defmt::write!(f, "Missing issuer"),
            Self::MissingValidity => defmt::write!(f, "Missing validity"),
            Self::MissingSubject => defmt::write!(f, "Missing subject"),
            Self::MissingSPKI => defmt::write!(f, "Missing SubjectPublicKeyInfo"),
            Self::MissingSignatureAlgorithmTop => {
                defmt::write!(f, "Missing top-level signatureAlgorithm")
            }
            Self::MissingSignatureValue => defmt::write!(f, "Missing signatureValue"),
            Self::Nom(err) => match err {
                nom::Err::Incomplete(_) => defmt::write!(f, "incomplete input"),
                nom::Err::Failure(_) => defmt::write!(f, "parsing failure"),
                nom::Err::Error(_) => defmt::write!(f, "parsing error"),
            },
        }
    }
}

#[cfg(feature = "display")]
impl<'a> core::fmt::Display for Error<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTopLevelSequence => {
                write!(f, "Invalid top-level SEQUENCE")
            }
            Self::MissingTbsCertificate => write!(f, "Missing tbsCertificate"),
            Self::InvalidTbsCertificate => write!(f, "Invalid tbsCertificate"),
            Self::MissingSerialNumber => write!(f, "Missing serialNumber"),
            Self::MissingSignatureAlgorithm => {
                write!(f, "Missing signatureAlgorithm")
            }
            Self::MissingIssuer => write!(f, "Missing issuer"),
            Self::MissingValidity => write!(f, "Missing validity"),
            Self::MissingSubject => write!(f, "Missing subject"),
            Self::MissingSPKI => write!(f, "Missing SubjectPublicKeyInfo"),
            Self::MissingSignatureAlgorithmTop => {
                write!(f, "Missing top-level signatureAlgorithm")
            }
            Self::MissingSignatureValue => write!(f, "Missing signatureValue"),
            Self::Nom(err) => match err {
                nom::Err::Incomplete(_) => write!(f, "incomplete input"),
                nom::Err::Failure(_) => write!(f, "parsing failure"),
                nom::Err::Error(_) => write!(f, "parsing error"),
            },
        }
    }
}

impl<'a> From<nom::Err<nom::error::Error<&'a [u8]>>> for Error<'a> {
    fn from(err: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        Error::Nom(err)
    }
}

/// ASN.1 tags
const ASN1DER_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_STRING_OCTET: u8 = 0x04;
const TAG_STRING_NULL: u8 = 0x05;
const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const TAG_STRING_UTF8: u8 = 0x0C;
const TAG_STRING_PRINTABLE: u8 = 0x13;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_SEQUENCE: u8 = 0x30;

/// OBJ_ID_CURVEX25519 in DER: 2B 65 6E
pub(crate) const OBJ_ID_CURVEX25519: [u8; 3] = [0x2B, 0x65, 0x6E];
/// ecdsa-with-SHA512 OID: 1.2.840.10045.4.3.4 in DER: 06 08 2A 86 48 CE 3D 04 03 04
pub(crate) const OID_ECDSA_WITH_SHA512: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];

/// Parses ASN.1 DER length (definite form only)
fn parse_length(input: &[u8]) -> IResult<&[u8], usize> {
    let (input, first) = be_u8(input)?;
    if first < 0x80 {
        Ok((input, first as usize))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        let (input, bytes) = take(num_bytes)(input)?;
        let mut len = 0usize;
        for b in bytes {
            len = (len << 8) | (*b as usize);
        }
        Ok((input, len))
    }
}

/// Parses an ASN.1 OBJECT IDENTIFIER
fn parse_oid(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, tag) = be_u8(input)?;
    if tag != TAG_OBJECT_IDENTIFIER {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    let (input, len) = parse_length(input)?;
    let (input, oid_bytes) = take(len)(input)?;
    Ok((input, oid_bytes))
}

/// Parse a SEQUENCE and return the full slice (tag + length + content)
fn parse_sequence_full(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let start = input;
    let (input, tag) = be_u8(input)?;
    if tag != TAG_SEQUENCE {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    let (input, len) = parse_length(input)?;
    let header_len = start.len() - input.len();
    let (input, _) = take(len)(input)?;
    let total_len = header_len + len;
    let sequence = &start[..total_len];
    Ok((input, sequence))
}

/// Parse a SEQUENCE and return only its contents
fn parse_sequence_contents(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, tag) = be_u8(input)?;
    if tag != TAG_SEQUENCE {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    let (input, len) = parse_length(input)?;
    let (input, seq_bytes) = take(len)(input)?;
    Ok((input, seq_bytes))
}

/// Parse a BIT STRING and return its contents (excluding tag/length)
fn parse_bit_string_contents(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, tag) = be_u8(input)?;
    if tag != TAG_BIT_STRING {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    let (input, len) = parse_length(input)?;
    let (input, bit_str) = take(len)(input)?;
    Ok((input, bit_str))
}

#[derive(Debug)]
pub struct Certificate<'a> {
    pub tbs_certificate: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub validity: &'a [u8],
    pub signature: &'a [u8],
    pub raw_der: &'a [u8],
}

/// Top-level extractor
pub fn extract_x509_certificate_parts<'a>(der: &'a [u8]) -> Result<Certificate<'a>, Error<'a>> {
    // Certificate ::= SEQUENCE {
    //      tbsCertificate          SEQUENCE,
    //      signatureAlgorithm      AlgorithmIdentifier,
    //      signatureValue          BIT STRING
    // }
    let (_, cert_seq_contents) =
        parse_sequence_contents(der).map_err(|_e| Error::InvalidTopLevelSequence)?;

    // tbsCertificate is the first SEQUENCE
    let (rest, tbs_full) =
        parse_sequence_full(cert_seq_contents).map_err(|_e| Error::MissingTbsCertificate)?;

    // Parse tbsCertificate SEQUENCE contents
    let (_, tbs_contents) =
        parse_sequence_contents(tbs_full).map_err(|_e| Error::InvalidTbsCertificate)?;

    // Now parse issuer, validity, subject from tbsCertificate contents.
    // tbsCertificate structure:
    // [version?] [serialNumber] [signature] [issuer] [validity] [subject] ...
    // We need to skip optional version (context-specific tag [0]) and serialNumber, signature

    let mut offset = 0;

    // Check if version is present (context-specific tag [0] = 0xA0)
    if tbs_contents[offset] == 0xA0 {
        let (_, ctx0_len) = parse_length(&tbs_contents[offset + 1..]).map_err(|e| Error::Nom(e))?;
        // move offset past [0] version
        offset += 2 + ctx0_len;
    }

    // serialNumber (INTEGER)
    let (_, sn_len) =
        parse_length(&tbs_contents[offset + 1..]).map_err(|_e| Error::MissingSerialNumber)?;
    offset += 2 + sn_len;

    // signature (AlgorithmIdentifier SEQUENCE)
    let (_, sigalg_full) = parse_sequence_full(&tbs_contents[offset..])
        .map_err(|_e| Error::MissingSignatureAlgorithm)?;
    offset += sigalg_full.len();

    // issuer (SEQUENCE)
    let (_, issuer_full) =
        parse_sequence_full(&tbs_contents[offset..]).map_err(|_e| Error::MissingIssuer)?;
    offset += issuer_full.len();

    // validity (SEQUENCE)
    let (_, validity_full) =
        parse_sequence_full(&tbs_contents[offset..]).map_err(|_e| Error::MissingValidity)?;
    offset += validity_full.len();

    // subject (SEQUENCE)
    let (_, subject_full) =
        parse_sequence_full(&tbs_contents[offset..]).map_err(|_e| Error::MissingSubject)?;
    // offset += subject_full.len();

    // Now, signatureValue is after signatureAlgorithm in cert_seq_contents
    // signatureAlgorithm is next after tbsCertificate
    let (sig_rest, _sigalg2_full) =
        parse_sequence_full(rest).map_err(|_e| Error::MissingSignatureAlgorithmTop)?;

    // signatureValue (BIT STRING)
    let (_, sig_value) =
        parse_bit_string_contents(sig_rest).map_err(|_e| Error::MissingSignatureValue)?;

    Ok(Certificate {
        tbs_certificate: tbs_full,
        issuer: issuer_full,
        subject: subject_full,
        validity: validity_full,
        signature: sig_value,
        raw_der: der,
    })
}

/// Find the SubjectPublicKeyInfo SEQUENCE by key_oid or sig_oid in tbsCertificate
pub fn find_subject_public_key_info<'a>(
    tbs: &'a [u8],
    key_oid: &[u8],
    sig_oid: &[u8],
) -> Option<&'a [u8]> {
    // tbsCertificate: parse fields and find SubjectPublicKeyInfo (after subject)
    let mut offset = 0;
    if tbs[offset] == 0xA0 {
        if let Ok((_, ctx0_len)) = parse_length(&tbs[offset + 1..]) {
            offset += 2 + ctx0_len;
        }
    }
    // serialNumber
    if let Ok((_, sn_len)) = parse_length(&tbs[offset + 1..]) {
        offset += 2 + sn_len;
    }
    // signature AlgorithmIdentifier
    if let Ok((_, sigalg_full)) = parse_sequence_full(&tbs[offset..]) {
        offset += sigalg_full.len();
    }
    // issuer
    if let Ok((_, issuer_full)) = parse_sequence_full(&tbs[offset..]) {
        offset += issuer_full.len();
    }
    // validity
    if let Ok((_, validity_full)) = parse_sequence_full(&tbs[offset..]) {
        offset += validity_full.len();
    }
    // subject
    if let Ok((_, subject_full)) = parse_sequence_full(&tbs[offset..]) {
        offset += subject_full.len();
    }
    // SubjectPublicKeyInfo SEQUENCE is next
    if let Ok((_, spki_full)) = parse_sequence_full(&tbs[offset..]) {
        // Check AlgorithmIdentifier OID inside SPKI
        if let Ok((_, alg_id_bytes)) = parse_sequence_contents(&spki_full[2..]) {
            if let Ok((_, oid_bytes)) = parse_oid(alg_id_bytes) {
                if oid_bytes == key_oid || oid_bytes == sig_oid {
                    return Some(spki_full);
                }
            }
        }
    }
    None
}

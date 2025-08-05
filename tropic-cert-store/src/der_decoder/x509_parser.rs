use der::{
    Sequence, ValueOrd,
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, UintRef},
};
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

const MAX_RDN_ATTRIBUTES: usize = 5;
const MAX_RDNS: usize = 10;
const MAX_EXTENSIONS: usize = 10;

/// An AttributeTypeAndValue structure (e.g., C=US, O=Example Inc.).
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct AttributeTypeAndValue<'a> {
    pub oid: ObjectIdentifier,
    pub value: AnyRef<'a>,
}

pub type RelativeDistinguishedName<'a, const N: usize> =
    der::asn1::SetOf<AttributeTypeAndValue<'a>, N>;

pub type Name<'a, const N: usize, const M: usize> =
    der::asn1::SequenceOf<RelativeDistinguishedName<'a, N>, M>;

/// The Validity structure from RFC 5280.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Validity<'a> {
    pub not_before: AnyRef<'a>,
    pub not_after: AnyRef<'a>,
}

/// The Extension structure from RFC 5280.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Extension<'a> {
    pub extn_id: ObjectIdentifier,
    #[asn1(default = "bool::default")]
    pub critical: bool,
    pub extn_value: der::asn1::OctetStringRef<'a>,
}

/// The to be signed (TBS) Certificate structure from RFC 5280.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsCertificate<'a> {
    #[asn1(context_specific = "0")]
    pub version: u8,
    pub serial_number: UintRef<'a>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub issuer: Name<'a, MAX_RDN_ATTRIBUTES, MAX_RDNS>,
    pub validity: Validity<'a>,
    pub subject: Name<'a, MAX_RDN_ATTRIBUTES, MAX_RDNS>,
    pub subject_public_key_info: SubjectPublicKeyInfoRef<'a>,
    #[asn1(context_specific = "3", optional = "true")]
    pub extensions: Option<der::asn1::SequenceOf<Extension<'a>, MAX_EXTENSIONS>>, // Use AnyRef to capture the whole sequence
}

/// The top-level Certificate structure from RFC 5280.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature_value: BitStringRef<'a>,
}

#[cfg(feature = "defmt")]
mod core_fmt {

    use core::fmt;

    use der::asn1::ObjectIdentifier;

    const VALUE_UNKNOWN: &str = "VALUE_UNKNOWN";

    #[macro_export]
    macro_rules! writeln_lf {
    ($dst:expr $(,)?) => {
        $crate::write!($dst, "\r\n")
    };
    ($dst:expr, $($arg:tt)*) => {
        $dst.write_fmt(format_args!($($arg)*))
    };
    }

    // OID constants for common name attributes
    const OID_COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
    const OID_ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
    const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

    const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
    const OID_EXT_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

    fn get_der_oid(oid: ObjectIdentifier) -> Option<&'static str> {
        match oid {
            OID_COUNTRY_NAME => Some("C"),
            OID_ORGANIZATION_NAME => Some("O"),
            OID_COMMON_NAME => Some("CN"),
            OID_EXT_BASIC_CONSTRAINTS => Some("X509v3 Basic Constraints"),
            OID_EXT_KEY_USAGE => Some("X509v3 Key Usage"),
            OID_EXT_SUBJECT_KEY_ID => Some("X509v3 Subject Key Identifier"),
            _ => None,
        }
    }

    const OID_X25519: ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.101.110");
    const OID_ECDSA_SHA384: ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

    fn get_spki_oid(oid: spki::ObjectIdentifier) -> Option<&'static str> {
        match oid {
            OID_X25519 => Some("X25519"),
            OID_ECDSA_SHA384 => Some("ecdsa-with-SHA384"),
            _ => None,
        }
    }

    struct HexSlice<'a> {
        value: &'a [u8],
        block: usize,
        ident: usize,
    }

    impl<'a> HexSlice<'a> {
        fn new(value: &'a [u8]) -> Self {
            Self {
                value,
                block: 0,
                ident: 0,
            }
        }
        fn block_size(mut self, block: usize) -> Self {
            self.block = block;
            self
        }
        fn with_ident(mut self, ident: usize) -> Self {
            self.ident = ident;
            self
        }
    }

    impl<'a> fmt::Display for HexSlice<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if self.block > 0 {
                for (i, chunk) in self.value.chunks(self.block).enumerate() {
                    write!(f, "{:ident$}", "", ident = self.ident)?;
                    for (j, &byte) in chunk.iter().enumerate() {
                        if j > 0 {
                            write!(f, ":")?;
                        }
                        write!(f, "{:02x}", byte)?;
                    }
                    if i < self.value.len() / self.block {
                        write!(f, ":\n")?;
                    }
                }
            } else {
                // write one line
                for (i, &byte) in self.value.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{:02X}", byte)?;
                }
            }
            Ok(())
        }
    }

    struct OctedStringValuer<'a>(der::asn1::OctetStringRef<'a>);
    impl<'a> fmt::Display for OctedStringValuer<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0.as_bytes() {
                [48, 0] => write!(f, "CA:FALSE")?,
                [3, 2, 3, 8] => write!(f, "Key Agreement")?,
                [
                    48,
                    22,
                    128,
                    20,
                    160,
                    126,
                    23,
                    201,
                    129,
                    74,
                    37,
                    161,
                    46,
                    118,
                    8,
                    236,
                    34,
                    70,
                    178,
                    168,
                    246,
                    27,
                    190,
                    62,
                ] => write!(f, "{}", HexSlice::new(self.0.as_bytes()))?,
                _ => write!(f, "{:?}", self.0.as_bytes())?,
            };
            Ok(())
        }
    }

    #[cfg(feature = "defmt")]
    impl<'a> fmt::Display for super::AttributeTypeAndValue<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let name_str = get_der_oid(self.oid);

            let value = match name_str {
                Some("C") => {
                    let printable_string =
                        der::asn1::PrintableStringRef::try_from(self.value).unwrap();
                    printable_string.as_str()
                }
                Some("O") | Some("CN") => {
                    let utf8_string = der::asn1::Utf8StringRef::try_from(self.value).unwrap();
                    utf8_string.as_str()
                }
                _ => VALUE_UNKNOWN,
            };

            if value != VALUE_UNKNOWN {
                write!(f, " {} = {}", name_str.unwrap(), value)
            } else {
                write!(
                    f,
                    " {} = {:?}",
                    HexSlice::new(self.oid.as_bytes()),
                    self.value
                )
            }
        }
    }

    impl<'a> fmt::Display for super::Validity<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let not_before = der::asn1::UtcTime::try_from(self.not_before).unwrap();
            let not_after = der::asn1::UtcTime::try_from(self.not_after).unwrap();

            writeln_lf!(f, "            Not Before: {}", not_before.to_date_time())?;
            write!(f, "            Not After: {}", not_after.to_date_time())
        }
    }

    impl<'a> fmt::Display for super::Extension<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let criticat = if self.critical { "critical" } else { "" };

            if let Some(extn_id) = get_der_oid(self.extn_id) {
                writeln_lf!(f, "            {}: {}", extn_id, criticat)?;
            } else {
                writeln_lf!(
                    f,
                    "            {}: {}",
                    HexSlice::new(self.extn_id.as_bytes()),
                    criticat
                )?;
            }
            write!(f, "                {}", OctedStringValuer(self.extn_value))?;
            Ok(())
        }
    }

    impl<'a> fmt::Display for super::TbsCertificate<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln_lf!(
                f,
                "        Version: {} ({:x})",
                self.version + 1,
                self.version
            )?;
            writeln_lf!(
                f,
                "        Serial Number: {}",
                HexSlice::new(self.serial_number.as_bytes())
            )?;

            if let Some(signature_algorithm) = get_spki_oid(self.signature_algorithm.oid) {
                writeln_lf!(f, "        Signature Algorithm: {}", signature_algorithm)?;
            } else {
                writeln_lf!(
                    f,
                    "        Signature Algorithm: {}",
                    HexSlice::new(self.signature_algorithm.oid.as_bytes())
                )?;
            }
            write!(f, "        Issuer:")?;
            for (i, name) in self.issuer.iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                for rdn in name.iter() {
                    write!(f, "{}", rdn)?;
                }
            }
            writeln_lf!(f, "")?;
            writeln_lf!(f, "        Validity:\n{}", self.validity)?;
            write!(f, "        Subject:")?;
            for (i, name) in self.subject.iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                for rdn in name.iter() {
                    write!(f, "{}", rdn)?;
                }
            }
            writeln_lf!(f, "")?;
            if let Some(bytes) = self.subject_public_key_info.subject_public_key.as_bytes() {
                let (algoritm, algorythm_pubkey) = match self.subject_public_key_info.algorithm.oid
                {
                    OID_X25519 => ("X25519", "X25519 Public-Key"),
                    _ => ("Unknown", "Unknown"),
                };
                writeln_lf!(
                    f,
                    "        Subject Public Key Info:
            Public Key Algorithm: {}
                {}:
{}",
                    algoritm,
                    algorythm_pubkey,
                    HexSlice::new(bytes).block_size(15).with_ident(20)
                )?;
            }
            if let Some(extensions) = &self.extensions {
                writeln_lf!(f, "        X509v3 extensions:")?;
                for extension in extensions.iter() {
                    writeln_lf!(f, "{}", extension)?;
                }
            }
            Ok(())
        }
    }

    impl<'a> fmt::Display for super::Certificate<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln_lf!(f, "Certificate:")?;
            write!(f, "    Data:\n{}", self.tbs_certificate)?;
            if let Some(signature_algorithm) = get_spki_oid(self.signature_algorithm.oid) {
                writeln_lf!(f, "    Signature Algorithm: {}", signature_algorithm)?;
            } else {
                writeln_lf!(
                    f,
                    "    Signature Algorithm: {}",
                    HexSlice::new(self.signature_algorithm.oid.as_bytes())
                )?;
            }
            if let Some(signature_value) = self.signature_value.as_bytes() {
                writeln_lf!(
                    f,
                    "    Signature Value:\n{}",
                    HexSlice::new(signature_value).block_size(18).with_ident(8)
                )?;
            }
            write!(f, "")
        }
    }
}

use core::fmt::Debug;

/// Cert error.
pub trait Error: Debug {
    /// Convert error to a generic Certificate error kind.
    ///
    /// By using this method, Certificate errors freely defined by implementations
    /// can be converted to a set of generic  errors upon which generic
    /// code can act.
    fn kind(&self) -> ErrorKind;
}

/// Certificate error kind.
///
/// This represents a common set of Certificate operation errors. Implementations are
/// free to define more specific or additional error types. However, by providing
/// a mapping to these common errors, generic code can still react to them.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
// #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
#[non_exhaustive]
pub enum ErrorKind {
    /// Certidficate couyld not be decoded.
    Decoding,
    /// Certificate could not be found.
    CertNotFound,
    /// Unable to extract the certificates.
    ExtractPubKey,
    /// A different error occurred. The original error may contain more information.
    Other,
}

impl Error for ErrorKind {
    #[inline]
    fn kind(&self) -> ErrorKind {
        *self
    }
}

impl core::fmt::Display for ErrorKind {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decoding => f.write_str("certificate could not be decoded"),
            Self::CertNotFound => f.write_str("certificate not found"),
            Self::ExtractPubKey => f.write_str("unable to extract pubkey"),
            Self::Other => write!(
                f,
                "A different error occurred. The original error may contain more information"
            ),
        }
    }
}

/// Certificate error type trait.
///
/// This just defines the error type, to be used by the other Certificate traits.
pub trait ErrorType {
    /// Error type.
    type Error<'a>: Error;
}

impl<T: ErrorType + ?Sized> ErrorType for &mut T {
    type Error<'a> = T::Error<'a>;
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum CertKind {
    Device = 0,
    Xxxxx = 1,
    Tropic01 = 2,
    TropicRoot = 3,
}

impl From<usize> for CertKind {
    fn from(kind: usize) -> Self {
        match kind {
            0 => Self::Device,
            1 => Self::Xxxxx,
            2 => Self::Tropic01,
            3 => Self::TropicRoot,
            _ => panic!("invalid certificate kind"),
        }
    }
}

pub trait Certificate<'a>: ErrorType + Sized {
    fn kind(&self) -> &CertKind;
    fn pubkey(&self) -> Result<&[u8], Self::Error<'a>>;
}

pub trait CertDecoder: ErrorType + Sized {
    type Cert<'a>: Certificate<'a>;

    fn from_der_and_kind<'a>(
        der_buf: &'a [u8],
        kind: CertKind,
    ) -> Result<Self::Cert<'a>, Self::Error<'a>>;
}

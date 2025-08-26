// use der::Decode;

// use super::x509_parser;

use crate::{
    cert_store::{Certificate, Error as _},
    l1,
    l2::{self, info},
};

/// Maximal size of TROPIC01's certificate
pub(crate) const _CERT_SIZE_TOTAL: usize = 3840;
pub(crate) const CERT_SIZE_SINGLE: usize = 700;

pub(crate) const CERT_STORE_VERSION: u8 = 1;
pub(crate) const NUM_CERTIFICATES: usize = 4;

#[derive(Debug)]
pub enum Error {
    StoreVersion,
    NumCerts,
    CertSize,
    L1(l1::Error),
    NotEnoughData,
    BufferTooSmall,
    CertNotFound,
    ExtractPubKey,
    PubKeyWrongSize(usize),
    Certificate(crate::cert_store::ErrorKind),
}

#[cfg(feature = "display")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreVersion => f.write_str("invalid cert store version"),
            Self::NumCerts => f.write_str("invalid number of certificates"),
            Self::CertSize => f.write_str("invalid certificate size"),
            Self::L1(err) => f.write_fmt(format_args!("l1 error: {}", err)),
            Self::NotEnoughData => f.write_str("not enough data"),
            Self::BufferTooSmall => f.write_str("provided certificate buffer is too small"),
            Self::CertNotFound => f.write_str("certificate not found"),
            Self::ExtractPubKey => f.write_str("unable to extract pubkey"),
            Self::PubKeyWrongSize(size) => f.write_fmt(format_args!("pubkey wrong size: {}", size)),
            Self::Certificate(e) => f.write_fmt(format_args!("certificate error: {}", e)),
        }
    }
}

impl<E: crate::cert_store::Error> From<E> for Error {
    fn from(err: E) -> Self {
        Self::Certificate(err.kind())
    }
}

const HEADER_OFFSET: usize = 2; // Version (1) + Num_Certs (1)
const CERT_STORE_RSP_LEN: usize = 128; // same as GET_INFO_BLOCK_LEN

/// Recommended size of certificate buffer.
pub const CERT_BUFFER_LEN: usize = 10 * CERT_SIZE_SINGLE;

// #[derive(Debug)]
// pub struct Certificate<'a> {
//     pub kind: CertKind,
//     pub cert: x509_parser::Certificate<'a>,
// }

// The struct to hold the parsed certificates in a no_std friendly way.
// This assumes a maximum of 10 certificates.
#[derive(Debug)]
pub struct CertStore<C> {
    pub version: u8,
    pub num_certs: u8,
    pub cert_lengths: [u16; NUM_CERTIFICATES],
    pub total_packets_needed: usize,
    pub certificates: [Option<C>; NUM_CERTIFICATES],
}

impl<'a, C> CertStore<C>
where
    C: Certificate<'a>,
{
    pub fn get_pubkey(
        &self,
        kind: crate::cert_store::CertKind,
    ) -> Result<x25519_dalek::PublicKey, Error> {
        let key = self.get_pubke_as_bytes(kind)?;
        if key.len() != 32 {
            return Err(Error::PubKeyWrongSize(key.len()));
        }
        let key: [u8; 32] = key.try_into().unwrap();
        Ok(key.into())
    }

    pub fn get_pubke_as_bytes(&self, kind: crate::cert_store::CertKind) -> Result<&'a [u8], Error> {
        if let Some(cert) = self
            .certificates
            .iter()
            .find(|&c| {
                if let Some(c) = c {
                    if *c.kind() == kind {
                        return true;
                    }
                }
                return false;
            })
            .ok_or(Error::CertNotFound)?
        {
            return Ok(cert.pubkey()?.public_key);
        }
        Err(Error::CertNotFound)
    }
}

// impl<'a> core::fmt::Display for CertificateChain<'a> {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         write!(f, "Version: {}\n", self.version)?;
//         write!(f, "Number of Certificates: {}\n", self.num_certs)?;
//         write!(f, "Certificate Lengths:\n")?;

//         for cert in &self.certificates {
//             if let Some(cert) = cert {
//                 write!(f, "Certificate Kind: {:?}", cert.kind)?;
//                 write!(f, "\n{}", cert.cert)?;
//             }
//         }
//         Ok(())
//     }
// }

pub(crate) fn request_cert_store<
    'a,
    SPI: embedded_hal::spi::SpiDevice,
    D: embedded_hal::delay::DelayNs,
    C: crate::cert_store::CertDecoder,
>(
    spi_device: &mut SPI,
    delay: &mut D,
    certificate_buffer: &'a mut [u8],
) -> Result<CertStore<C::Cert<'a>>, l2::Error> {
    // 1. Parse the header from the first packet (p0).
    let req = info::GetInfoReq::create(
        info::GetInfoObjectId::X509Certificate,
        info::BlocIndex::CeryStore(0),
    )?;

    spi_device.write(&req)?;
    let l2_resp: l2::Response<{ CERT_STORE_RSP_LEN }> =
        l1::receive(spi_device, delay)?.try_into()?;

    let l2_get_info_resp: l2::info::GetInfoResp<{ CERT_STORE_RSP_LEN }> = l2_resp.into();
    let p0 = l2_get_info_resp.object;

    let version = p0[0];
    let num_certs = p0[1] as usize;

    if version != CERT_STORE_VERSION {
        return Err(l2::Error::CertStore(Error::StoreVersion));
    }

    if num_certs != NUM_CERTIFICATES {
        return Err(l2::Error::CertStore(Error::NumCerts));
    }

    // Read the lengths of the certificates from p0.
    let mut cert_lengths = [0_u16; NUM_CERTIFICATES];
    for i in 0..NUM_CERTIFICATES {
        let len_bytes = &p0[HEADER_OFFSET + i * 2..HEADER_OFFSET + i * 2 + 2];
        cert_lengths[i] = u16::from_be_bytes([len_bytes[0], len_bytes[1]]);
    }

    // Version (1) + Num_Certs (1) + ( Num_Certs * Cert_Size(2))
    let header_end_offset = HEADER_OFFSET + num_certs * 2;

    // 2. Collect all packets into a fixed-size array on the stack.
    let total_data_size =
        cert_lengths.iter().take(num_certs).sum::<u16>() as usize + header_end_offset;
    let total_packets_needed = (total_data_size + CERT_STORE_RSP_LEN - 1) / CERT_STORE_RSP_LEN;

    if certificate_buffer.len() < total_data_size {
        return Err(l2::Error::CertStore(Error::BufferTooSmall));
    }
    certificate_buffer[..CERT_STORE_RSP_LEN].copy_from_slice(&p0);

    // Request and copy remaining packets.
    for i in 1..total_packets_needed {
        let req = info::GetInfoReq::create(
            info::GetInfoObjectId::X509Certificate,
            info::BlocIndex::CeryStore(i as u8),
        )?;

        spi_device.write(&req)?;
        let l2_resp: l2::Response<{ CERT_STORE_RSP_LEN }> = l1::receive(spi_device, delay)
            .map_err(|e| l2::Error::CertStore(Error::L1(e)))?
            .try_into()?;

        let l2_get_info_resp: l2::info::GetInfoResp<{ CERT_STORE_RSP_LEN }> = l2_resp.into();

        let offset = i * CERT_STORE_RSP_LEN;
        certificate_buffer[offset..offset + CERT_STORE_RSP_LEN]
            .clone_from_slice(&l2_get_info_resp.object);
    }

    // Create a single, contiguous slice from the buffer.
    let full_data_slice = &certificate_buffer[..total_data_size];

    // Move a cursor over the slice.
    let mut current_offset = header_end_offset;

    // 3. Loop through and parse each certificate.
    let mut certificates: [Option<C::Cert<'a>>; NUM_CERTIFICATES] =
        [const { None }; NUM_CERTIFICATES];

    for i in 0..NUM_CERTIFICATES {
        let cert_len = cert_lengths[i] as usize;
        let end_offset = current_offset + cert_len;

        // Check bounds.
        if end_offset > full_data_slice.len() {
            return Err(l2::Error::CertStore(Error::NotEnoughData));
        }

        // Get the slice for the current certificate.
        let cert_data = &full_data_slice[current_offset..end_offset];

        // let cert = x509_parser::Certificate::from_der(&cert_data)
        //     .map_err(|e| l2::Error::CertStore(Error::Der(e)))?;

        let cert = C::from_der_and_kind(cert_data, i.into())
            .map_err(|e| l2::Error::CertStore(Error::Certificate(e.kind())))?;

        certificates[i] = Some(
            C::from_der_and_kind(cert_data, i.into())
                .map_err(|e| l2::Error::CertStore(Error::Certificate(e.kind())))?,
        );

        // certificates[i] = Some(Certificate {
        //     kind: i.into(),
        //     cert,
        // });

        current_offset = end_offset;
    }

    Ok(CertStore {
        version,
        num_certs: num_certs as u8,
        cert_lengths,
        total_packets_needed,
        certificates,
    })
}

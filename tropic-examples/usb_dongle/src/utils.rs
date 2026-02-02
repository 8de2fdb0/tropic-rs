use pkcs8::{der::Decode, PrivateKeyInfo};
use tropic_rs::external::x25519_dalek::StaticSecret;

const OBJ_ID_X25519: [u8; 3] = [43, 101, 110];

pub fn parse_x25519_private_key(input: &[u8]) -> anyhow::Result<StaticSecret> {
    let pem_content =
        pem::parse(input).map_err(|e| anyhow::anyhow!("error while decoding pem: {e}"))?;

    let info = PrivateKeyInfo::from_der(pem_content.contents())
        .map_err(|e| anyhow::anyhow!("error while decoding der: {e}"))?;

    if info.algorithm.oid.as_bytes() != OBJ_ID_X25519 {
        return Err(anyhow::anyhow!("not an X25519 private key"));
    }

    let mut raw_key = info.private_key;

    if raw_key.len() == 34 && raw_key[0] == 0x04 && raw_key[1] == 0x20 {
        // strip asn1 octet string header
        raw_key = &raw_key[2..];
    }
    let raw_key: [u8; 32] = raw_key.try_into()?;
    Ok(StaticSecret::from(raw_key))
}

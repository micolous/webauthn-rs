//! Common cryptographic routines for FIDO2.

use openssl::{
    ec::{EcGroup, EcKey},
    md::Md,
    nid::Nid,
    pkey::{Id, Private, Public, PKey},
    pkey_ctx::PkeyCtx,
    symm::{Cipher, Crypter, Mode},
};

use crate::error::WebauthnCError;

/// Gets an [EcGroup] for P-256
pub fn get_group() -> Result<EcGroup, WebauthnCError> {
    Ok(EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?)
}

/// Encrypts some data using AES-256-CBC, with no padding.
///
/// `plaintext.len()` must be a multiple of the cipher's blocksize.
pub fn encrypt(key: &[u8], iv: Option<&[u8]>, plaintext: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
    let cipher = Cipher::aes_256_cbc();
    let mut ct = vec![0; plaintext.len() + cipher.block_size()];
    let mut c = Crypter::new(cipher, Mode::Encrypt, key, iv)?;
    c.pad(false);
    let l = c.update(plaintext, &mut ct)?;
    let l = l + c.finalize(&mut ct[l..])?;
    ct.truncate(l);
    Ok(ct)
}

/// Decrypts some data using AES-256-CBC, with no padding.
pub fn decrypt(
    key: &[u8],
    iv: Option<&[u8]>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WebauthnCError> {
    let cipher = Cipher::aes_256_cbc();
    if ciphertext.len() % cipher.block_size() != 0 {
        error!(
            "ciphertext length {} is not a multiple of {} bytes",
            ciphertext.len(),
            cipher.block_size()
        );
        return Err(WebauthnCError::Internal);
    }

    let mut pt = vec![0; ciphertext.len() + cipher.block_size()];
    let mut c = Crypter::new(cipher, Mode::Decrypt, key, iv)?;
    c.pad(false);
    let l = c.update(ciphertext, &mut pt)?;
    let l = l + c.finalize(&mut pt[l..])?;
    pt.truncate(l);
    Ok(pt)
}

pub fn hkdf_sha_256(
    salt: &[u8],
    ikm: &[u8],
    info: Option<&[u8]>,
    output: &mut [u8],
) -> Result<(), WebauthnCError> {
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_salt(salt)?;
    ctx.set_hkdf_key(ikm)?;
    if let Some(info) = info {
        ctx.add_hkdf_info(info)?;
    }
    ctx.derive(Some(output))?;
    Ok(())
}

/// Generate a fresh, random P-256 private key
pub fn regenerate() -> Result<EcKey<Private>, WebauthnCError> {
    let ecgroup = get_group()?;
    let eckey = EcKey::generate(&ecgroup)?;
    Ok(eckey)
}

pub fn ecdh(
    private_key: EcKey<Private>,
    peer_key: EcKey<Public>,
    output: &mut [u8],
) -> Result<(), WebauthnCError> {
    let peer_key = PKey::from_ec_key(peer_key)?;
    let pkey = PKey::from_ec_key(private_key)?;
    let mut ctx = PkeyCtx::new(&pkey)?;
    ctx.derive_init()?;
    ctx.derive_set_peer(&peer_key)?;
    ctx.derive(Some(output))?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hkdf() {
        let salt: Vec<u8> = (0..0x0d).collect();
        let ikm: [u8; 22] = [0x0b; 22];
        let info: Vec<u8> = (0xf0..0xfa).collect();
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0xa, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x0, 0x72, 0x8, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut output: [u8; 42] = [0; 42];

        hkdf_sha_256(salt.as_slice(), &ikm, Some(info.as_slice()), &mut output)
            .expect("hkdf_sha_256 fail");
        assert_eq!(expected, output);
    }
}

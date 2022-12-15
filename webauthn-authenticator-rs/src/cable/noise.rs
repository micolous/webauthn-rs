use std::mem::size_of;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcKeyRef, EcPoint, EcPointRef, PointConversionForm},
    envelope::Seal,
    nid::Nid,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};

use crate::{ctap2::hkdf_sha_256, prelude::WebauthnCError, util::compute_sha256_2};

pub fn get_public_key_bytes(private_key: &EcKeyRef<Private>) -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    private_key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap()
}

// implementing Cable's version of noise from scratch
const NOISE_KN_PROTOCOL: &[u8; 32] = b"Noise_KNpsk0_P256_AESGCM_SHA256\0";
const NOISE_NK_PROTOCOL: &[u8; 32] = b"Noise_NKpsk0_P256_AESGCM_SHA256\0";

pub enum HandshakeType {
    KNpsk0,
    NKpsk0,
}

#[derive(Default)]
pub struct CableNoise {
    chaining_key: [u8; 32],
    h: [u8; 32],
    symmetric_key: [u8; 32],
    symmetric_nonce: u32,
}

impl CableNoise {
    pub fn new(handshake_type: HandshakeType) -> Self {
        let chaining_key = match handshake_type {
            HandshakeType::KNpsk0 => *NOISE_KN_PROTOCOL,
            HandshakeType::NKpsk0 => *NOISE_NK_PROTOCOL,
        };

        Self {
            chaining_key,
            h: chaining_key,
            ..Default::default()
        }
    }

    pub fn mix_hash(&mut self, i: &[u8]) {
        self.h = compute_sha256_2(&self.h, i);
    }

    pub fn mix_hash_point(&mut self, point: &EcPointRef) -> Result<(), WebauthnCError> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let point = point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        self.mix_hash(&point);
        Ok(())
    }

    pub fn mix_key(&mut self, ikm: &[u8]) -> Result<(), WebauthnCError> {
        let mut o = [0; 64];
        hkdf_sha_256(&self.chaining_key, ikm, None, &mut o)?;
        self.chaining_key.copy_from_slice(&o[..32]);
        self.init_key(&o[32..]);
        Ok(())
    }

    pub fn mix_key_and_hash(&mut self, ikm: &[u8]) -> Result<(), WebauthnCError> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/noise.cc;l=90;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        let mut o = [0; 32 * 3];
        hkdf_sha_256(&self.chaining_key, ikm, None, &mut o)?;
        self.chaining_key.copy_from_slice(&o[..32]);
        self.mix_hash(&o[32..64]);
        self.init_key(&o[64..]);
        Ok(())
    }

    pub fn encrypt_and_hash(&mut self, pt: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        let mut nonce = [0; 12];
        nonce[..size_of::<u32>()].copy_from_slice(&self.symmetric_nonce.to_be_bytes());
        self.symmetric_nonce += 1;

        let cipher = Cipher::aes_256_gcm();
        let mut tag = [0; 16];
        let mut encrypted = encrypt_aead(
            cipher,
            &self.symmetric_key,
            Some(&nonce),
            &self.h[..],
            pt,
            &mut tag,
        )?;
        encrypted.extend_from_slice(&tag);
        self.mix_hash(&encrypted);
        Ok(encrypted)
    }

    pub fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        let mut nonce = [0; 12];
        nonce[..size_of::<u32>()].copy_from_slice(&self.symmetric_nonce.to_be_bytes());
        self.symmetric_nonce += 1;
        let msg_len = ct.len() - 16;
        trace!(
            "decrypt_and_hash(ct={:?}, tag={:?}, nonce={:?})",
            &ct[..msg_len],
            &ct[msg_len..],
            &nonce
        );
        let cipher = Cipher::aes_256_gcm();
        let decrypted = decrypt_aead(
            cipher,
            &self.symmetric_key,
            Some(&nonce),
            &self.h[..],
            &ct[..msg_len],
            &ct[msg_len..],
        )
        .unwrap();
        trace!("decrypted: {:?}", decrypted);
        self.mix_hash(ct);
        Ok(decrypted)
    }

    /// `write_key, read_key`
    pub fn traffic_keys(&self) -> Result<([u8; 32], [u8; 32]), WebauthnCError> {
        let mut o = [0; 64];
        hkdf_sha_256(&self.chaining_key, &[], None, &mut o)?;

        let mut a = [0; 32];
        let mut b = [0; 32];
        a.copy_from_slice(&o[..32]);
        b.copy_from_slice(&o[32..]);
        Ok((a, b))
    }

    fn init_key(&mut self, key: &[u8]) {
        assert_eq!(key.len(), 32);
        self.symmetric_key.copy_from_slice(key);
        self.symmetric_nonce = 0;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn a() {
        let _ = tracing_subscriber::fmt::try_init();
        let ck = [
            0x30, 0x7a, 0x70, 0x6e, 0x63, 0x38, 0x2e, 0x8e, 0x9d, 0x46, 0xcc, 0xdb, 0xc, 0xeb,
            0xed, 0x5c, 0x2b, 0x19, 0x28, 0xc5, 0xae, 0x2d, 0xee, 0x63, 0x52, 0xe1, 0x30, 0xac,
            0xe1, 0xf7, 0x4f, 0x44,
        ];
        let expected = [
            0x1f, 0xba, 0x3c, 0xce, 0x17, 0x62, 0x2c, 0x68, 0x26, 0x8d, 0x9f, 0x75, 0xb5, 0xa8,
            0xa3, 0x35, 0x1b, 0x51, 0x7f, 0x9, 0x6f, 0xb5, 0xe2, 0x94, 0x94, 0x1a, 0xf7, 0xe3,
            0xa6, 0xa8, 0xd6, 0xe1, 0xe3, 0x4f, 0x1a, 0xa3, 0x74, 0x72, 0x38, 0xc0, 0x4d, 0x3b,
            0xd2, 0x5e, 0x7, 0xef, 0x1b, 0x35, 0xfe, 0xf3, 0x59, 0x0, 0xd, 0x75, 0x56, 0x15, 0xcd,
            0x85, 0xbe, 0x27, 0xcf, 0xc8, 0x7, 0xd1,
        ];
        let mut actual = [0; 64];

        hkdf_sha_256(&ck, &[], None, &mut actual).unwrap();
        assert_eq!(expected, actual);
    }
}

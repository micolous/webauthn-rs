use std::mem::size_of;

use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};

use crate::error::WebauthnCError;

pub type EncryptionKey = [u8; 32];
pub const OLD_ADDITIONAL_BYTES: [u8; 1] = [/* version */ 2];
pub const NEW_ADDITIONAL_BYTES: [u8; 0] = [];
const PADDING_MUL: usize = 32;

#[derive(Default)]
pub struct Crypter {
    read_key: EncryptionKey,
    write_key: EncryptionKey,
    read_seq: u32,
    write_seq: u32,
    new_construction: bool,
}

impl Crypter {
    pub fn new(read_key: EncryptionKey, write_key: EncryptionKey) -> Self {
        Self {
            read_key,
            write_key,
            ..Default::default()
        }
    }

    pub fn encrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        let padded_len = (msg.len() + PADDING_MUL) & !(PADDING_MUL - 1);
        assert!(padded_len > msg.len());
        let zeros = padded_len - msg.len() - 1;
        assert!(zeros < 256);

        let mut padded = vec![0; padded_len];
        padded[..msg.len()].copy_from_slice(&msg);
        padded[padded_len - 1] = zeros as u8;
        trace!("padded: {:02x?}", padded);
        assert_eq!(padded.len() % PADDING_MUL, 0);

        let nonce = self.construct_nonce(self.write_seq);
        self.write_seq += 1;
        let cipher = Cipher::aes_256_gcm();
        let aad = if self.new_construction {
            &NEW_ADDITIONAL_BYTES[..]
        } else {
            &OLD_ADDITIONAL_BYTES[..]
        };
        let mut tag = [0; 16];

        let mut encrypted = encrypt_aead(cipher, &self.write_key, Some(&nonce), aad, &padded, &mut tag)?;
        encrypted.reserve(16);
        encrypted.extend_from_slice(&tag);
        
        Ok(encrypted)
    }

    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
        let nonce = self.construct_nonce(self.read_seq);
        let cipher = Cipher::aes_256_gcm();
        let aad = if self.new_construction {
            &NEW_ADDITIONAL_BYTES[..]
        } else {
            &OLD_ADDITIONAL_BYTES[..]
        };

        let msg_len = ct.len() - 16;
        trace!("decrypt(ct={:?}, tag={:?}, nonce={:?})", &ct[..msg_len], &ct[msg_len..], &nonce);

        let decrypted = decrypt_aead(cipher, &self.read_key, Some(&nonce), aad, &ct[..msg_len], &ct[msg_len..]);
        trace!("decrypted: {:?}", decrypted);

        let mut decrypted = match decrypted {
            Err(e) => {
                if !self.new_construction && self.read_seq == 0 {
                    // Switch to new construction mode
                    trace!("trying new construction");
                    self.new_construction = true;
                    return self.decrypt(ct);
                } else {
                    // throw original error
                    return Err(e.into());
                }
            },

            Ok(decrypted) => decrypted,
        };
        
        self.read_seq += 1;

        if decrypted.is_empty() {
            error!("Invalid caBLE message (empty)");
            return Err(WebauthnCError::Internal);
        }

        // Handle padding
        let padding_len = (decrypted.last().map(|l| *l).unwrap_or_default() as usize) + 1;
        if padding_len > decrypted.len() {
            error!("Invalid caBLE message (padding length {} > message length {})", padding_len, decrypted.len());
            return Err(WebauthnCError::Internal);
        }

        decrypted.truncate(decrypted.len() - padding_len);
        Ok(decrypted)
    }

    fn construct_nonce(&self, counter: u32) -> [u8; 12] {
        let mut nonce = [0; 12];
        if self.new_construction {
            nonce[12 - size_of::<u32>()..].copy_from_slice(&counter.to_be_bytes());
        } else {
            nonce[..size_of::<u32>()].copy_from_slice(&counter.to_le_bytes());
        }
        trace!("new_constuction: {:?}, nonce: {:?}", self.new_construction, nonce);
        nonce
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let _ = tracing_subscriber::fmt::try_init();

        let key0 = [123; 32];
        let key1 = [231; 32];

        let mut alice = Crypter::new(key0, key1);
        let mut bob = Crypter::new(key1, key0);
        let mut corrupted = Crypter::new(key1, key0);

        for l in 0..530 {
            let msg = vec![0xff; l];
            let mut crypted = alice.encrypt(&msg).unwrap();
            let decrypted = bob.decrypt(&crypted).unwrap();

            assert_eq!(msg, decrypted);
            assert!(!bob.new_construction);
            if l > 0 {
                crypted[(l * 3) % l] ^= 0x01;
            }
            corrupted.read_seq = bob.read_seq;
            assert!(corrupted.decrypt(&crypted).is_err());
        }
    }

    #[test]
    fn encrypt_decrypt_new() {
        let _ = tracing_subscriber::fmt::try_init();

        let key0 = [123; 32];
        let key1 = [231; 32];

        let mut alice = Crypter::new(key0, key1);
        alice.new_construction = true;
        let mut bob = Crypter::new(key1, key0);
        let mut corrupted = Crypter::new(key1, key0);

        for l in 1..5 {
            let msg = vec![0xff; l];
            let mut crypted = alice.encrypt(&msg).unwrap();
            let decrypted = bob.decrypt(&crypted).unwrap();

            assert!(bob.new_construction);
            assert_eq!(msg, decrypted);
            if l > 0 {
                crypted[(l * 3) % l] ^= 0x01;
            }
            corrupted.new_construction = bob.new_construction;
            corrupted.read_seq = bob.read_seq;
            assert!(corrupted.decrypt(&crypted).is_err());
        }
    }
}
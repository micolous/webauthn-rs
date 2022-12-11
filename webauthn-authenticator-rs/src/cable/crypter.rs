use std::mem::size_of;

use openssl::symm::{Cipher, decrypt_aead};

use crate::{error::WebauthnCError, ctap2::decrypt};

pub type EncryptionKey = [u8; 32];
pub const OLD_ADDITIONAL_BYTES: [u8; 1] = [/* version */ 2];
pub const NEW_ADDITIONAL_BYTES: [u8; 0] = [];


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

        todo!()
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
        // TODO: remove this hack
        if msg_len == 0 {
            warn!("TODO: no message payload, skipping decryption, this implementation is probably wrong");
            return Ok(vec![]);
        }


        let decrypted = decrypt_aead(cipher, &self.read_key, Some(&nonce), aad, &ct[..msg_len], &ct[msg_len..]);
        trace!("decrypted: {:?}", decrypted);

        let decrypted = match decrypted {
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
        trace!("decrypted value: {:?}", decrypted);
        // TODO: handle padding

        todo!()
    }

    fn construct_nonce(&self, counter: u32) -> [u8; 12] {
        let mut nonce = [0; 12];
        if self.new_construction {
            nonce[12 - size_of::<u32>()..].copy_from_slice(&counter.to_be_bytes());
        } else {
            nonce[..size_of::<u32>()].copy_from_slice(&counter.to_le_bytes());
        }

        nonce
    }
}
use std::mem::size_of;

use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcKeyRef, EcPointRef, PointConversionForm},
    nid::Nid,
    pkey::Private,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};

use crate::{ctap2::hkdf_sha_256, prelude::WebauthnCError, util::compute_sha256_2};

use super::{
    crypter::Crypter,
    tunnel::{bytes_to_public_key, ecdh},
    Psk,
};

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

pub struct CableNoise {
    chaining_key: [u8; 32],
    h: [u8; 32],
    symmetric_key: [u8; 32],
    symmetric_nonce: u32,
    ephemeral_key: EcKey<Private>,
    local_identity: Option<EcKey<Private>>,
}

impl CableNoise {
    fn new(handshake_type: HandshakeType) -> Result<Self, WebauthnCError> {
        let chaining_key = match handshake_type {
            HandshakeType::KNpsk0 => *NOISE_KN_PROTOCOL,
            HandshakeType::NKpsk0 => *NOISE_NK_PROTOCOL,
        };

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ephemeral_key = EcKey::generate(&group)?;

        Ok(Self {
            chaining_key,
            h: chaining_key,
            symmetric_key: [0; 32],
            symmetric_nonce: 0,
            ephemeral_key,
            local_identity: None,
        })
    }

    fn mix_hash(&mut self, i: &[u8]) {
        self.h = compute_sha256_2(&self.h, i);
    }

    fn mix_hash_point(&mut self, point: &EcPointRef) -> Result<(), WebauthnCError> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let point = point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        self.mix_hash(&point);
        Ok(())
    }

    fn mix_key(&mut self, ikm: &[u8]) -> Result<(), WebauthnCError> {
        let mut o = [0; 64];
        hkdf_sha_256(&self.chaining_key, ikm, None, &mut o)?;
        self.chaining_key.copy_from_slice(&o[..32]);
        self.init_key(&o[32..]);
        Ok(())
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) -> Result<(), WebauthnCError> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/noise.cc;l=90;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        let mut o = [0; 32 * 3];
        hkdf_sha_256(&self.chaining_key, ikm, None, &mut o)?;
        self.chaining_key.copy_from_slice(&o[..32]);
        self.mix_hash(&o[32..64]);
        self.init_key(&o[64..]);
        Ok(())
    }

    fn encrypt_and_hash(&mut self, pt: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
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

    fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, WebauthnCError> {
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
    fn traffic_keys(&self) -> Result<([u8; 32], [u8; 32]), WebauthnCError> {
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

    fn get_ephemeral_key_public_bytes(&self) -> Result<[u8; 65], WebauthnCError> {
        let mut o = [0; 65];
        let v = get_public_key_bytes(self.ephemeral_key.as_ref());
        if v.len() != o.len() {
            error!("unexpected public key length {} != {}", v.len(), o.len());
            return Err(WebauthnCError::Internal);
        }
        o.copy_from_slice(&v);
        Ok(o)
    }

    /// Starts a Noise handshake with a peer as the initiating party (platform).
    ///
    /// Returns `(CableNoise, initial_message)`. `initial_message` is sent to
    /// the responding party ([CableNoise::build_responder]).
    pub fn build_initiator(
        local_identity: Option<&EcKeyRef<Private>>,
        psk: Psk,
        peer_identity: Option<[u8; 65]>,
    ) -> Result<(Self, Vec<u8>), WebauthnCError> {
        // BuildInitialMessage
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=880;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29

        let mut noise = if let Some(peer_identity) = peer_identity {
            // TODO: test
            let mut noise = Self::new(HandshakeType::NKpsk0)?;
            let prologue = [0];
            noise.mix_hash(&prologue);
            noise.mix_hash(&peer_identity);
            noise
        } else if let Some(local_identity) = local_identity {
            let mut noise = Self::new(HandshakeType::KNpsk0)?;
            let prologue = [1];
            noise.mix_hash(&prologue);
            noise.mix_hash_point(&local_identity.public_key())?;
            noise.local_identity = Some(local_identity.to_owned());
            noise
        } else {
            error!("build_initiator requires local_identity or peer_identity");
            return Err(WebauthnCError::Internal);
        };

        noise.mix_key_and_hash(&psk)?;

        let ephemeral_key_public_bytes = noise.get_ephemeral_key_public_bytes()?;

        noise.mix_hash(&ephemeral_key_public_bytes);
        noise.mix_key(&ephemeral_key_public_bytes)?;

        if let Some(peer_identity) = peer_identity {
            // TODO: test
            let peer_identity_point = bytes_to_public_key(&peer_identity)?;
            let mut es_key = [0; 32];
            ecdh(&noise.ephemeral_key, &peer_identity_point, &mut es_key)?;
            noise.mix_key(&es_key)?;
        }

        let ct = noise.encrypt_and_hash(&[])?;

        let mut handshake_message = Vec::with_capacity(ephemeral_key_public_bytes.len() + ct.len());
        handshake_message.extend_from_slice(&ephemeral_key_public_bytes);
        handshake_message.extend_from_slice(&ct);

        Ok((noise, handshake_message))
    }

    /// Processes the response from the responding party (authenticator) and
    /// creates a [Crypter] for further message passing.
    ///
    /// * `response` is the message from the responding party ([CableNoise::build_responder])
    ///
    /// ## Warning
    ///
    /// This function mutates the state of `self`, *even on errors*. This
    /// renders the internal state invalid for "retrying" or future
    /// transactions.
    pub fn process_response(mut self, response: &[u8]) -> Result<Crypter, WebauthnCError> {
        if response.len() < 65 {
            error!("Handshake response too short ({} bytes)", response.len());
            return Err(WebauthnCError::MessageTooShort);
        }

        // ProcessResponse
        let (peer_point_bytes, ct) = response.split_at(65);

        let peer_key = bytes_to_public_key(peer_point_bytes)?;
        let mut shared_key_ee = [0; 32];
        ecdh(&self.ephemeral_key, &peer_key, &mut shared_key_ee)?;
        self.mix_hash(peer_point_bytes);
        self.mix_key(peer_point_bytes)?;
        self.mix_key(&shared_key_ee)?;

        if let Some(local_identity) = &self.local_identity {
            let mut shared_key_se = [0; 32];
            ecdh(&local_identity, &peer_key, &mut shared_key_se)?;
            self.mix_key(&shared_key_se)?;
        }

        let pt = self.decrypt_and_hash(ct)?;
        if pt.len() != 0 {
            error!(
                "expected handshake to be empty, got {} bytes: {:02x?}",
                pt.len(),
                &pt
            );
            return Err(WebauthnCError::MessageTooLarge);
        }

        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=982;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        let (write_key, read_key) = self.traffic_keys()?;

        trace!(?write_key);
        trace!(?read_key);
        Ok(Crypter::new(read_key, write_key))
    }

    /// Starts a Noise handshake with a peer as the responding party (authenticator):
    ///
    /// * `message` is the value from the initiating party ([CableNoise::build_initiator])
    ///
    /// Returns `(crypter, response)`. `response` is sent to the initiating party ([CableNoise::process_response]).
    pub fn build_responder(
        local_identity: Option<&EcKeyRef<Private>>,
        psk: Psk,
        peer_identity: Option<[u8; 65]>,
        message: &[u8],
    ) -> Result<(Crypter, Vec<u8>), WebauthnCError> {
        if message.len() < 65 {
            error!("Initiator message too short ({} bytes)", message.len());
            return Err(WebauthnCError::MessageTooShort);
        }

        // RespondToHandshake
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=987;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        let (peer_point_bytes, ct) = message.split_at(65);

        let mut noise = if let Some(local_identity) = local_identity {
            let mut noise = Self::new(HandshakeType::NKpsk0)?;
            let prologue = [0];
            noise.mix_hash(&prologue);
            noise.mix_hash_point(&local_identity.public_key())?;
            noise.local_identity = Some(local_identity.to_owned());

            noise
        } else if let Some(peer_identity) = peer_identity {
            let mut noise = Self::new(HandshakeType::KNpsk0)?;
            let prologue = [1];
            noise.mix_hash(&prologue);
            noise.mix_hash(&peer_identity);
            noise
        } else {
            error!("build_initiator requires local_identity or peer_identity");
            return Err(WebauthnCError::Internal);
        };

        noise.mix_key_and_hash(&psk)?;
        noise.mix_hash(peer_point_bytes);
        noise.mix_key(peer_point_bytes)?;

        let peer_point = bytes_to_public_key(&peer_point_bytes)?;

        if let Some(local_identity) = local_identity {
            let mut es_key = [0; 32];
            ecdh(&local_identity, &peer_point, &mut es_key)?;
            noise.mix_key(&es_key)?;
        }

        let pt = noise.decrypt_and_hash(ct)?;
        if pt.len() != 0 {
            error!(
                "expected handshake to be empty, got {} bytes: {:02x?}",
                pt.len(),
                &pt
            );
            return Err(WebauthnCError::MessageTooLarge);
        }

        let ephemeral_key_public_bytes = noise.get_ephemeral_key_public_bytes()?;
        noise.mix_hash(&ephemeral_key_public_bytes);
        noise.mix_key(&ephemeral_key_public_bytes)?;

        let mut shared_key_ee = [0; 32];
        ecdh(&noise.ephemeral_key, &peer_point, &mut shared_key_ee)?;
        noise.mix_key(&shared_key_ee)?;

        if let Some(peer_identity) = peer_identity {
            let peer_identity_point = bytes_to_public_key(&peer_identity)?;
            let mut shared_key_se = [0; 32];
            ecdh(
                &noise.ephemeral_key,
                &peer_identity_point,
                &mut shared_key_se,
            )?;
            noise.mix_key(&shared_key_se)?;
        }

        let ct = noise.encrypt_and_hash(&[])?;
        let mut response_message = Vec::with_capacity(ephemeral_key_public_bytes.len() + ct.len());
        response_message.extend_from_slice(&ephemeral_key_public_bytes);
        response_message.extend_from_slice(&ct);

        let (read_key, write_key) = noise.traffic_keys()?;
        trace!(?read_key);
        trace!(?write_key);
        Ok((Crypter::new(read_key, write_key), response_message))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn hkdf_chromium() {
        // Compare hkdf using values debug-logged from Chormium
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

    #[test]
    fn noise() {
        let _ = tracing_subscriber::fmt::try_init();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let identity_key = EcKey::generate(&group).unwrap();
        let identity_pub = get_public_key_bytes(&identity_key).try_into().unwrap();
        let psk = [0; size_of::<Psk>()];

        let (initiator_noise, initiator_msg) =
            CableNoise::build_initiator(Some(&identity_key), psk.to_owned(), None).unwrap();

        let (mut responder_crypt, responder_msg) =
            CableNoise::build_responder(None, psk, Some(identity_pub), &initiator_msg).unwrap();

        let mut initiator_crypt = initiator_noise.process_response(&responder_msg).unwrap();

        assert!(initiator_crypt.is_counterparty(&responder_crypt));
        responder_crypt.use_new_construction();

        let ct = responder_crypt.encrypt(b"Hello, world!").unwrap();
        let pt = initiator_crypt.decrypt(&ct).unwrap();
        assert_eq!(b"Hello, world!", pt.as_slice());
        // Decrypting the same ciphertext twice should fail, because of the nonce change
        assert!(initiator_crypt.decrypt(&ct).is_err());

        let ct2 = initiator_crypt
            .encrypt(b"The quick brown fox jumps over the lazy dog")
            .unwrap();

        // Decrypting responder's initial ciphertext should fail because of different keys from Noise
        assert!(responder_crypt.decrypt(&ct).is_err());

        // A failure in Crypter shouldn't impact our ability to receive correct ciphertexts, if they're in order
        let pt2 = responder_crypt.decrypt(&ct2).unwrap();
        assert_eq!(
            b"The quick brown fox jumps over the lazy dog",
            pt2.as_slice()
        );
        assert!(responder_crypt.decrypt(&ct).is_err());
    }
}

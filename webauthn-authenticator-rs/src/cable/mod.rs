//! caBLE / Hybrid Authenticator
//!
//! In absence of a publicly-published spec, this is based on [Chromium's implementation][crcable].
//!
//! [crcable]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/

mod base10;
mod handshake;
mod tunnel;

use std::mem::size_of;

pub use base10::DecodeError;
use num_traits::ToPrimitive;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
    sign::Signer,
};

use self::handshake::*;
use crate::{
    ctap2::{decrypt, encrypt, hkdf_sha_256, regenerate},
    error::WebauthnCError,
};

type BleAdvert = [u8; 16 + 4];
type RoutingId = [u8; 3];
type BleNonce = [u8; 10];
type QrSecret = [u8; 16];
// type QrSeed = [u8; 32];
// type QrKey = [u8; size_of::<QrSecret>() + size_of::<QrSeed>()];
type EidKey = [u8; 32 + 32];
type CableEid = [u8; 16];

pub struct Discovery {
    request_type: CableRequestType,
    local_identity: EcKey<Private>,
    qr_secret: QrSecret,
    eid_key: EidKey,
}

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u32)]
enum DerivedValueType {
    EIDKey = 1,
    TunnelID = 2,
    PSK = 3,
    PairedSecret = 4,
    IdentityKeySeed = 5,
    PerContactIDSecret = 6,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Eid {
    pub tunnel_server_id: u16,
    pub routing_id: RoutingId,
    pub nonce: BleNonce,
}

impl Eid {
    pub fn to_bytes(&self) -> CableEid {
        let mut o: CableEid = [0; size_of::<CableEid>()];
        let mut p = 1;
        let mut q = p + size_of::<BleNonce>();
        o[p..q].copy_from_slice(&self.nonce);

        p = q;
        q += size_of::<RoutingId>();
        o[p..q].copy_from_slice(&self.routing_id);

        p = q;
        q += size_of::<u16>();
        o[p..q].copy_from_slice(&self.tunnel_server_id.to_le_bytes());

        o
    }

    pub fn from_bytes(eid: CableEid) -> Self {
        let mut p = 1;
        let mut nonce: BleNonce = [0; size_of::<BleNonce>()];
        let mut q = p + size_of::<BleNonce>();
        nonce.copy_from_slice(&eid[p..q]);

        p = q;
        q += size_of::<RoutingId>();
        let mut routing_id: RoutingId = [0; size_of::<RoutingId>()];
        routing_id.copy_from_slice(&eid[p..q]);

        p = q;
        q += size_of::<u16>();
        let tunnel_server_id = u16::from_le_bytes(eid[p..q].try_into().unwrap());

        Self {
            nonce,
            routing_id,
            tunnel_server_id,
        }
    }
}

fn derive(
    salt: &[u8],
    ikm: &[u8],
    typ: DerivedValueType,
    output: &mut [u8],
) -> Result<(), WebauthnCError> {
    let typ = typ.to_u32().ok_or(WebauthnCError::Internal)?.to_le_bytes();
    Ok(hkdf_sha_256(salt, ikm, &typ, output)?)
}

fn decrypt_advert(advert: BleAdvert, key: &EidKey) -> Result<Option<CableEid>, WebauthnCError> {
    let signing_key = PKey::hmac(&key[32..64])?;
    let mut signer = Signer::new(MessageDigest::sha256(), &signing_key)?;

    let mut calculated_hmac: [u8; 32] = [0; 32];
    signer.update(&advert[..16])?;
    signer.sign(&mut calculated_hmac)?;
    if &calculated_hmac[..4] != &advert[16..20] {
        warn!("incorrect HMAC when decrypting caBLE advertisement");
        return Ok(None);
    }

    // HMAC checks out, try to decrypt
    let plaintext = decrypt(&key[..32], None, &advert[..16])?;
    let plaintext: Option<CableEid> = plaintext.try_into().ok();

    Ok(match plaintext {
        Some(plaintext) => {
            if plaintext[0] != 0 {
                warn!("reserved bits not 0 in decrypted caBLE advertisement");
                return Ok(None);
            }

            let tunnel_server_id = u16::from_le_bytes(
                plaintext[14..16]
                    .try_into()
                    .map_err(|_| WebauthnCError::Internal)?,
            );
            if tunnel::get_domain(tunnel_server_id).is_none() {
                warn!(
                    "invalid tunnel server 0x{:04x} in caBLE advertisement",
                    tunnel_server_id
                );
                return Ok(None);
            }

            Some(plaintext)
        }
        None => None,
    })
}

fn encrypt_advert(eid: CableEid, key: &EidKey) -> Result<BleAdvert, WebauthnCError> {
    let c = encrypt(&key[..32], None, &eid)?;

    let mut crypted: BleAdvert = [0; size_of::<BleAdvert>()];
    crypted[..size_of::<CableEid>()].copy_from_slice(&c);

    let signing_key = PKey::hmac(&key[32..64])?;
    let mut signer = Signer::new(MessageDigest::sha256(), &signing_key)?;

    let mut calculated_hmac: [u8; 32] = [0; 32];
    signer.update(&crypted[..16])?;
    signer.sign(&mut calculated_hmac)?;
    crypted[size_of::<CableEid>()..].copy_from_slice(&calculated_hmac[..4]);

    Ok(crypted)
}

impl Discovery {
    pub fn new(request_type: CableRequestType) -> Result<Self, WebauthnCError> {
        // chrome_authenticator_request_delegate.cc  ChromeAuthenticatorRequestDelegate::ConfigureCable
        // generates a random value
        let mut qr_secret: QrSecret = [0; size_of::<QrSecret>()];
        rand_bytes(&mut qr_secret)?;
        let local_identity = regenerate()?;

        Self::new_with_qr_generator_key(request_type, local_identity, qr_secret)
    }

    pub fn new_with_qr_generator_key(
        request_type: CableRequestType,
        local_identity: EcKey<Private>,
        qr_secret: QrSecret,
    ) -> Result<Self, WebauthnCError> {
        // Trying to EC_KEY_derive_from_secret is only in BoringSSL, and doesn't have openssl-rs bindings
        // Opted to just take in an EcKey here.

        let mut eid_key: EidKey = [0; size_of::<EidKey>()];
        derive(&qr_secret, &[], DerivedValueType::EIDKey, &mut eid_key)?;

        Ok(Self {
            request_type,
            local_identity,
            qr_secret,
            eid_key,
        })
    }

    fn seed_to_public_key(&self) -> Result<EcKey<Public>, WebauthnCError> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        Ok(EcKey::from_public_key(
            &group,
            self.local_identity.public_key(),
        )?)
    }

    pub fn decrypt_advert(&self, advert: BleAdvert) -> Result<Option<CableEid>, WebauthnCError> {
        decrypt_advert(advert, &self.eid_key)
    }

    pub fn encrypt_advert(&self, eid: CableEid) -> Result<BleAdvert, WebauthnCError> {
        encrypt_advert(eid, &self.eid_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        tracing_subscriber::fmt::init();

        let d = Discovery::new(CableRequestType::MakeCredential).unwrap();
        let c = Eid {
            tunnel_server_id: 0x0102,
            routing_id: [9, 10, 11],
            nonce: [9, 139, 115, 107, 54, 169, 140, 185, 164, 47],
        };

        let eid = c.to_bytes();
        let mut advert = d.encrypt_advert(eid).unwrap();
        // advert != eid
        assert_ne!(&eid, &advert[..eid.len()]);

        let decrypted = d.decrypt_advert(advert.clone()).unwrap().unwrap();
        // decrypting gets back the original value
        assert_eq!(&eid, &decrypted);

        let c2 = Eid::from_bytes(eid);
        assert_eq!(c, c2);

        // Changing bits fails
        advert[0] ^= 1;
        let decrypted = d.decrypt_advert(advert).unwrap();
        assert!(decrypted.is_none());
    }
}

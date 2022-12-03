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

#[derive(Debug)]
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
    ikm: &[u8],
    salt: &[u8],
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
        None => {
            warn!("decrypt fail");
            None
        }
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

    pub fn make_handshake(&self) -> Result<HandshakeV2, WebauthnCError> {
        let public_key = EcKey::from_public_key(
            self.local_identity.group(),
            self.local_identity.public_key(),
        )?;
        HandshakeV2::new(self.request_type, public_key, self.qr_secret)
    }

    pub(self) fn get_private_key_for_testing(&self) -> Result<Vec<u8>, WebauthnCError> {
        Ok(self.local_identity.private_key_to_pem()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let _ = tracing_subscriber::fmt::try_init();

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

    // #[test]
    // fn new() {
    //     let _ = tracing_subscriber::fmt::try_init();
    //     let disco = Discovery::new(CableRequestType::DiscoverableMakeCredential).unwrap();
    //     trace!(?disco);
    //     let private_key = String::from_utf8(disco.get_private_key_for_testing().unwrap()).unwrap();
    //     trace!("private key:\n{}", private_key);

    //     let handshake = disco.make_handshake().unwrap();
    //     trace!(?handshake);

    //     let url = handshake.to_qr_url().unwrap();
    //     trace!(?url);
    //     let qr = qrcode::QrCode::new(url).unwrap();

    //     let code = qr
    //         .render::<qrcode::render::unicode::Dense1x2>()
    //         .dark_color(qrcode::render::unicode::Dense1x2::Light)
    //         .light_color(qrcode::render::unicode::Dense1x2::Dark)
    //         .build();
    //     trace!("\n{}", code);
    // }

    #[test]
    fn decrypt_known() {
        let _ = tracing_subscriber::fmt::try_init();
        // let test_key = [
        //     45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 69, 67, 32, 80, 82, 73, 86, 65, 84, 69, 32,
        //     75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 72, 99, 67, 65, 81, 69, 69, 73, 80, 114, 54,
        //     76, 105, 83, 120, 81, 73, 82, 55, 69, 51, 72, 81, 90, 98, 78, 114, 57, 80, 78, 66, 114,
        //     105, 50, 110, 56, 83, 66, 99, 89, 67, 65, 73, 56, 89, 69, 89, 57, 85, 113, 68, 111, 65,
        //     111, 71, 67, 67, 113, 71, 83, 77, 52, 57, 10, 65, 119, 69, 72, 111, 85, 81, 68, 81,
        //     103, 65, 69, 90, 68, 103, 112, 55, 66, 76, 82, 82, 47, 79, 100, 116, 89, 104, 118, 83,
        //     43, 109, 88, 65, 51, 82, 87, 121, 51, 85, 65, 86, 112, 48, 49, 115, 52, 73, 111, 83,
        //     78, 56, 47, 65, 114, 68, 77, 57, 56, 73, 88, 57, 104, 88, 102, 10, 70, 116, 47, 119,
        //     65, 109, 68, 79, 119, 78, 78, 55, 66, 100, 84, 57, 84, 48, 86, 109, 110, 70, 73, 99,
        //     55, 84, 49, 116, 106, 97, 105, 84, 68, 103, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68,
        //     32, 69, 67, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10,
        // ];
        // Discovery { request_type: DiscoverableMakeCredential, local_identity: EcKey,
        //  qr_secret: [1, 254, 166, 247, 196, 128, 116, 147, 220, 37, 111, 158, 172, 247, 86, 201],
        //  eid_key: [71, 198, 63, 179, 47, 46, 248, 209, 45, 152, 14, 113, 249, 195, 83, 240, 190, 43, 150, 219, 184, 209, 141, 199, 120, 65, 118, 178, 1, 231, 76, 120, 59, 145, 227, 9, 254, 71, 60, 47, 0, 15, 75, 80, 23, 69, 155, 106, 127, 123, 2, 165, 97, 86, 51, 86, 70, 70, 198, 20, 167, 240, 247, 240]
        // }
        // Private key: [45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 69, 67, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 72, 99, 67, 65, 81, 69, 69, 73, 80, 114, 54, 76, 105, 83, 120, 81, 73, 82, 55, 69, 51, 72, 81, 90, 98, 78, 114, 57, 80, 78, 66, 114, 105, 50, 110, 56, 83, 66, 99, 89, 67, 65, 73, 56, 89, 69, 89, 57, 85, 113, 68, 111, 65, 111, 71, 67, 67, 113, 71, 83, 77, 52, 57, 10, 65, 119, 69, 72, 111, 85, 81, 68, 81, 103, 65, 69, 90, 68, 103, 112, 55, 66, 76, 82, 82, 47, 79, 100, 116, 89, 104, 118, 83, 43, 109, 88, 65, 51, 82, 87, 121, 51, 85, 65, 86, 112, 48, 49, 115, 52, 73, 111, 83, 78, 56, 47, 65, 114, 68, 77, 57, 56, 73, 88, 57, 104, 88, 102, 10, 70, 116, 47, 119, 65, 109, 68, 79, 119, 78, 78, 55, 66, 100, 84, 57, 84, 48, 86, 109, 110, 70, 73, 99, 55, 84, 49, 116, 106, 97, 105, 84, 68, 103, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 69, 67, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10]
        // Handshake: HandshakeV2 { peer_identity: EcKey, secret: [1, 254, 166, 247, 196, 128, 116, 147, 220, 37, 111, 158, 172, 247, 86, 201], known_domains_count: 2, timestamp: SystemTime { intervals: 133145064076516439 }, supports_linking_info: false, request_type: DiscoverableMakeCredential, supports_non_discoverable_make_credential: false }
        // URL: FIDO:/1587255900792438944459061119478825010114531789068054428613131982194017978424543064885470041277246791701065710001119359100784325313076847471971309904207381668112901
        // {0000fff9-0000-1000-8000-00805f9b34fb: [2, 125, 132, 237, 96, 118, 181, 94, 36, 124, 131, 15, 130, 149, 94, 77, 18, 110, 127, 67]}

        let advert = [
            2, 125, 132, 237, 96, 118, 181, 94, 36, 124, 131, 15, 130, 149, 94, 77, 18, 110, 127,
            67,
        ];
        let qr_secret = [
            1, 254, 166, 247, 196, 128, 116, 147, 220, 37, 111, 158, 172, 247, 86, 201,
        ];
        let mut eid_key: EidKey = [0; size_of::<EidKey>()];
        derive(&qr_secret, &[], DerivedValueType::EIDKey, &mut eid_key).unwrap();
        trace!("eid_key = {:?}", eid_key);

        // TODO: didn't doesn't decrypt; probably doing eid_key derivation wrong
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=242;drc=f7385067f48da7ba86322cbd4eea3631037222fc
        // states:
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/fido_tunnel_device.h;l=79;drc=f7385067f48da7ba86322cbd4eea3631037222fc
        // matching advert:
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/fido_tunnel_device.cc;l=200-223;drc=f7385067f48da7ba86322cbd4eea3631037222fc
        // eid key:
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/fido_tunnel_device.cc;l=162;drc=f7385067f48da7ba86322cbd4eea3631037222fc
        // ah, salt and key (ikm) were swapped!
        let r = decrypt_advert(advert, &eid_key).unwrap();
        trace!("decrypted: {:?}", r);
        let r = r.unwrap();
        let r = Eid::from_bytes(r);
        trace!("eid: {:?}", r);

        let expected = Eid {
            tunnel_server_id: 0,
            routing_id: [2, 101, 85],
            nonce: [139, 181, 197, 201, 164, 77, 145, 58, 94, 178],
        };
        assert_eq!(expected, r);
    }
}

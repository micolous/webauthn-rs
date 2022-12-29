use num_traits::ToPrimitive;
use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rand::rand_bytes,
    sign::Signer,
};
/// Structures for device discovery over BTLE.
use std::mem::size_of;
use tokio_tungstenite::tungstenite::http::Uri;

use super::{btle::*, handshake::*, tunnel::get_domain};
use crate::{
    cable::{CableRequestType, Psk},
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
type TunnelId = [u8; 16];

// const BASE64URL: base64::Config = base64::Config::new(base64::CharacterSet::UrlSafe, false);

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

impl DerivedValueType {
    pub fn derive(&self, ikm: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), WebauthnCError> {
        let typ = self.to_u32().ok_or(WebauthnCError::Internal)?.to_le_bytes();
        Ok(hkdf_sha_256(salt, ikm, Some(&typ), output)?)
    }
}

#[derive(Debug)]
pub struct Discovery {
    request_type: CableRequestType,
    pub(super) local_identity: EcKey<Private>,
    qr_secret: QrSecret,
    eid_key: EidKey,
}

impl Discovery {
    /// Creates a [Discovery] for a given `request_type`.
    ///
    /// This method generates a random `qr_secret` and `local_identity`, and is
    /// suitable for use by an initiator.
    pub fn new(request_type: CableRequestType) -> Result<Self, WebauthnCError> {
        // chrome_authenticator_request_delegate.cc  ChromeAuthenticatorRequestDelegate::ConfigureCable
        let mut qr_secret: QrSecret = [0; size_of::<QrSecret>()];
        rand_bytes(&mut qr_secret)?;
        Self::new_with_qr_secret(request_type, qr_secret)
    }

    /// Creates a [Discovery] for a given `request_type` and `qr_secret`.
    ///
    /// This method generates a random `local_identity`, and is suitable for use
    /// by an authenticator.  See [HandshakeV2.to_discovery] for a public API.
    pub(super) fn new_with_qr_secret(
        request_type: CableRequestType,
        qr_secret: QrSecret,
    ) -> Result<Self, WebauthnCError> {
        let local_identity = regenerate()?;
        Self::new_with_qr_secret_and_cert(request_type, qr_secret, local_identity)
    }

    fn new_with_qr_secret_and_cert(
        request_type: CableRequestType,
        qr_secret: QrSecret,
        local_identity: EcKey<Private>,
    ) -> Result<Self, WebauthnCError> {
        // Trying to EC_KEY_derive_from_secret is only in BoringSSL, and doesn't have openssl-rs bindings
        // Opted to just take in an EcKey here.

        let mut eid_key: EidKey = [0; size_of::<EidKey>()];
        DerivedValueType::EIDKey.derive(&qr_secret, &[], &mut eid_key)?;

        Ok(Self {
            request_type,
            local_identity,
            qr_secret,
            eid_key,
        })
    }

    /// Decrypts a Bluetooth service data advertisement with this [Discovery]'s
    /// `eid_key`.
    ///
    /// Returns `Ok(None)` when the advertisement was encrypted using a
    /// different key.
    pub fn decrypt_advert(&self, advert: BleAdvert) -> Result<Option<Eid>, WebauthnCError> {
        Eid::decrypt_advert(advert, &self.eid_key)
    }

    /// Encrypts an [Eid] with this [Discovery]'s `eid_key`.
    ///
    /// Returns a byte array to be transmitted in as the payload of a Bluetooth
    /// service data advertisement.
    pub fn encrypt_advert(&self, eid: &Eid) -> Result<BleAdvert, WebauthnCError> {
        eid.encrypt_advert(&self.eid_key)
    }

    /// Makes a [HandshakeV2] for this [Discovery].
    ///
    /// This payload includes the `request_type`, public key for the
    /// `local_identity`, and `qr_secret`.
    pub fn make_handshake(&self) -> Result<HandshakeV2, WebauthnCError> {
        let public_key = EcKey::from_public_key(
            self.local_identity.group(),
            self.local_identity.public_key(),
        )?;
        HandshakeV2::new(self.request_type, public_key, self.qr_secret)
    }

    pub async fn wait_for_matching_response(
        &self,
        scanner: &Scanner,
    ) -> Result<Option<Eid>, WebauthnCError> {
        let mut rx = scanner.scan().await?;
        while let Some(a) = rx.recv().await {
            trace!("advert: {:?}", a);
            if a.len() != size_of::<BleAdvert>() {
                continue;
            }
            let mut advert: BleAdvert = [0; size_of::<BleAdvert>()];
            advert.copy_from_slice(a.as_ref());
            if let Some(eid) = self.decrypt_advert(advert)? {
                return Ok(Some(eid));
            }
        }

        Ok(None)
    }

    /// Gets the tunnel ID associated with this [Discovery]
    pub fn get_tunnel_id(&self) -> Result<TunnelId, WebauthnCError> {
        let mut tunnel_id: TunnelId = [0; size_of::<TunnelId>()];
        DerivedValueType::TunnelID.derive(&self.qr_secret, &[], &mut tunnel_id)?;
        Ok(tunnel_id)
    }

    /// Gets the pre-shared key associated with this [Discovery]
    pub fn get_psk(&self, eid: &Eid) -> Result<Psk, WebauthnCError> {
        let mut psk: Psk = [0; size_of::<Psk>()];
        DerivedValueType::PSK.derive(&self.qr_secret, &eid.to_bytes(), &mut psk)?;
        Ok(psk)
    }

    /// Gets the Websocket connection URI which the platform will use to connect
    /// to the authenticator.
    pub fn get_connect_uri(&self, eid: &Eid) -> Result<Uri, WebauthnCError> {
        let tunnel_id = self.get_tunnel_id()?;
        eid.get_connect_uri(tunnel_id).ok_or_else(|| {
            error!("Unknown WebSocket tunnel URL for {:?}", eid);
            WebauthnCError::NotSupported
        })
    }

    /// Gets the Websocket connection URL which the authenticator will use to
    /// connect to the platform.
    pub fn get_new_tunnel_uri(&self, domain_id: u16) -> Result<Uri, WebauthnCError> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=170;drc=de9f16dcca1d5057ba55973fa85a5b27423d414f
        get_domain(domain_id)
            .and_then(|domain| {
                let tunnel_id = hex::encode_upper(&self.get_tunnel_id().ok()?);
                Uri::builder()
                    .scheme("wss")
                    .authority(domain)
                    .path_and_query(format!("/cable/new/{}", tunnel_id))
                    .build()
                    .ok()
            })
            .ok_or_else(|| {
                error!("Unknown WebSocket tunnel URL for {:?}", domain_id);
                WebauthnCError::NotSupported
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Eid {
    pub tunnel_server_id: u16,
    pub routing_id: RoutingId,
    pub nonce: BleNonce,
}

impl Eid {
    pub fn new(tunnel_server_id: u16, routing_id: RoutingId) -> Result<Self, WebauthnCError> {
        let mut nonce: BleNonce = [0; size_of::<BleNonce>()];
        rand_bytes(&mut nonce)?;

        Ok(Self {
            tunnel_server_id,
            routing_id,
            nonce,
        })
    }

    /// Converts this [Eid] into unencrypted bytes.
    fn to_bytes(&self) -> CableEid {
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

    /// Parses an [Eid] from unencrypted bytes.
    fn from_bytes(eid: CableEid) -> Self {
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

    /// Decrypts and parses a BLE advertisement with a given key.
    ///
    /// Returns `Ok(None)` if `advert` was not decryptable with `key`, or the
    /// resulting payload was invalid.
    fn decrypt_advert(advert: BleAdvert, key: &EidKey) -> Result<Option<Eid>, WebauthnCError> {
        trace!("Decrypting {:?} with key {:?}", advert, key);
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

                let eid = Eid::from_bytes(plaintext);
                if eid.get_domain().is_none() {
                    return Ok(None);
                }

                trace!(?eid);
                Some(eid)
            }
            None => {
                warn!("decrypt fail");
                None
            }
        })
    }

    /// Converts this [Eid] into an encrypted payload for BLE advertisements.
    fn encrypt_advert(&self, key: &EidKey) -> Result<BleAdvert, WebauthnCError> {
        let eid = self.to_bytes();
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

    /// Gets the tunnel server domain for this [Eid].
    fn get_domain(&self) -> Option<String> {
        get_domain(self.tunnel_server_id)
    }

    /// Gets the Websocket connection URI which the platform will use to connect
    /// to the authenticator.
    ///
    /// `tunnel_id` is provided from [Discovery::get_tunnel_id].
    fn get_connect_uri(&self, tunnel_id: TunnelId) -> Option<Uri> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=179;drc=de9f16dcca1d5057ba55973fa85a5b27423d414f
        self.get_domain().and_then(|domain| {
            let routing_id = hex::encode_upper(&self.routing_id);
            let tunnel_id = hex::encode_upper(tunnel_id);

            Uri::builder()
                .scheme("wss")
                .authority(domain)
                .path_and_query(format!("/cable/connect/{}/{}", routing_id, tunnel_id))
                .build()
                .ok()
        })
    }

    // TODO: needed for pairing
    // fn get_contact_uri(&self) -> Option<Uri> {
    //     self.get_domain().and_then(|domain| {
    //         let routing_id = base64::encode_config(&self.routing_id, BASE64URL);
    //         Uri::builder()
    //             .scheme("wss")
    //             .authority(domain)
    //             .path_and_query(format!("/cable/contact/{}", routing_id))
    //             .build()
    //             .ok()
    //     })
    // }
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

        let mut advert = d.encrypt_advert(&c).unwrap();

        let c2 = d.decrypt_advert(advert.clone()).unwrap().unwrap();
        // decrypting gets back the original value
        assert_eq!(c, c2);

        // Changing bits fails
        advert[0] ^= 1;
        let decrypted = d.decrypt_advert(advert).unwrap();
        assert!(decrypted.is_none());
    }

    #[test]
    fn decrypt_known() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_key = [
            45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 69, 67, 32, 80, 82, 73, 86, 65, 84, 69, 32,
            75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 72, 99, 67, 65, 81, 69, 69, 73, 80, 114, 54,
            76, 105, 83, 120, 81, 73, 82, 55, 69, 51, 72, 81, 90, 98, 78, 114, 57, 80, 78, 66, 114,
            105, 50, 110, 56, 83, 66, 99, 89, 67, 65, 73, 56, 89, 69, 89, 57, 85, 113, 68, 111, 65,
            111, 71, 67, 67, 113, 71, 83, 77, 52, 57, 10, 65, 119, 69, 72, 111, 85, 81, 68, 81,
            103, 65, 69, 90, 68, 103, 112, 55, 66, 76, 82, 82, 47, 79, 100, 116, 89, 104, 118, 83,
            43, 109, 88, 65, 51, 82, 87, 121, 51, 85, 65, 86, 112, 48, 49, 115, 52, 73, 111, 83,
            78, 56, 47, 65, 114, 68, 77, 57, 56, 73, 88, 57, 104, 88, 102, 10, 70, 116, 47, 119,
            65, 109, 68, 79, 119, 78, 78, 55, 66, 100, 84, 57, 84, 48, 86, 109, 110, 70, 73, 99,
            55, 84, 49, 116, 106, 97, 105, 84, 68, 103, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68,
            32, 69, 67, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10,
        ];
        let qr_secret = [
            1, 254, 166, 247, 196, 128, 116, 147, 220, 37, 111, 158, 172, 247, 86, 201,
        ];
        let local_identity = EcKey::private_key_from_pem(&test_key).unwrap();

        let discovery = Discovery::new_with_qr_secret_and_cert(
            CableRequestType::DiscoverableMakeCredential,
            qr_secret,
            local_identity,
        )
        .unwrap();
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
        let mut eid_key: EidKey = [0; size_of::<EidKey>()];
        DerivedValueType::EIDKey
            .derive(&qr_secret, &[], &mut eid_key)
            .unwrap();
        trace!("eid_key = {:?}", eid_key);

        let r = discovery.decrypt_advert(advert).unwrap().unwrap();
        trace!("eid: {:?}", r);

        let expected = Eid {
            tunnel_server_id: 0,
            routing_id: [2, 101, 85],
            nonce: [139, 181, 197, 201, 164, 77, 145, 58, 94, 178],
        };
        assert_eq!(expected, r);
        assert_eq!(
            "wss://cable.ua5v.com/cable/connect/026555/367CBBF5F5085DF4098476AFE4B9B1D2",
            discovery.get_connect_uri(&r).unwrap().to_string()
        );
    }
}

//! caBLE / Hybrid Authenticator
//!
//! **tl;dr:** scan a QR code with a `FIDO:/` URL, mobile device sends a BLE
//! advertisement, this is used to establish a doubly-encrypted (TLS and Noise)
//! Websocket tunnel over which the platform can send a single CTAP 2.x command
//! and get a response.
//!
//! ## Warning
//!
//! **There is no publicly-published spec from this protocol, aside from
//! [Chromium's C++ implementation][crcable]. There are probably errors in this
//! implementation and its documentation.**
//!
//! **This implementation is incomplete, and has not been reviewed from a
//! cryptography standpoint.**
//!
//! This implementation is a *very* rough port to "make things work" based on
//! what Chromium does -- there will probably be errors compared to whatever
//! the final spec is (FIDO v2.2?)
//!
//! There are two major versions of caBLE, and this only implements caBLE v2.
//! There are also several minor versions of caBLE v2, which aren't fully
//! explained (or implemented here).
//!
//! caBLE v1 is significantly different, and is not implemented here.
//!
//! This should work with Android devices with a current version of Google
//! Play Services, and with iOS devices on a current version of iOS. The
//! computer running this library will need a Bluetooth Low Energy adaptor.
//!
//! This does not implement the AOA (Android Open Accessory) Hybrid
//! authenticator protocol.
//!
//! This does not implement "contact lists" ("remember this computer").
//!
//! ## Requirements
//!
//! The platform (generating the request) requires:
//!
//! * a Bluetooth Low Energy (BLE) adaptor
//!
//! * an internet connection
//!
//! The authenticator (mobile device) requires:
//!
//! * a caBLE implementation, such as:
//!
//!   * [Android 7 or later][android-ver] with
//!     [a recent version of Chrome and Google Play Services (October 2022)][android-announce]
//!
//!   * [iOS 16 or later][ios]
//!
//! * a Bluetooth Low Energy (BLE) radio
//!
//! * a camera and QR code scanner[^qr]
//!
//! * an internet connection
//!
//! **On Android,** Chrome handles the `FIDO:/` URL and establishes the
//! Websocket tunnel, and proxies commands to
//! [Google Play's FIDO2 API][gpfido2]. The authenticator
//! [is stored in Google Password Manager][android-sec], and it also supports
//! [devicePubKey][] for an un-synchronised credential.
//!
//! **On iOS,** the authenticator is stored in the iCloud Keychain and shared
//! with all devices signed in to that iCloud account. There is no way to
//! identify which device was used.
//!
//! In both cases, the credential is cached in the device's secure element, and
//! requires user verification (lock screen pattern, PIN, password or biometric
//! authentication) to access.
//!
//! **Warning:** iOS 15 will recognise caBLE QR codes and attempt to offer to
//! authenticate, but this version of the protocol is not supported.
//!
//! ## Protocol overview
//!
//! The platform (or "browser") generates a CBOR message ([HandshakeV2])
//! containing the desired transaction type (`MakeCredential` or
//! `GetAssertion`), a shared secret and some protocol version information. This
//! gets encoded as [base10] and turned into a `FIDO:/` URL, and is displayed as
//! a QR code for the user to scan with their mobile device.
//!
//! The authenticator (mobile device) scans this QR code, and establishes a
//! tunnel to a well-known WebSocket tunnel server of *its* choosing
//! ([get_domain]). Once established, it then broadcasts an encrypted [Eid]
//! message over BLE service advertisements to be discovered by the platform.
//!
//! Meanwhile, the platform scans for caBLE BLE advertisements and tries to
//! decrypt and parse them ([decrypt_advert]). On success, it can then find
//! which tunnel server to connect to, the tunnel ID, and a nonce.
//!
//! The platform connects to the tunnel server, and starts a handshake with the
//! authenticator using a non-standard version of the [Noise protocol][]
//! ([noise::CableNoise]), using secrets exchanged in the QR code and BTLE
//! advertisement and a new ephemeral session key, allowing them to derive
//! traffic keys for [crypter::Crypter].
//!
//! The authenticator will then immediately send a [GetInfoResponse], and may
//! also send a pairing payload (presently Android only). Where supported, a
//! pairing payload is sent *regardless* of whether the user selects "remember
//! this computer" on the mobile device (the payload will just be null bytes).
//!
//! The platform can then send a *single* `MakeCredential` or `GetAssertion`
//! command to the authenticator in CTAP 2.x format.
//!
//! Once the command is sent, the authenticator will prompt the user to approve
//! the request in a user-verifying way (biometric or lock screen pattern,
//! password or PIN), showing the relying party information (website domain).
//!
//! The authenticator returns the response to the command, and then closes the
//! Websocket channel. A new handshake must be performed if the user wishes to
//! perform another transaction.
//!
//! [android]: https://developers.google.com/identity/passkeys/supported-environments
//! [android-sec]: https://security.googleblog.com/2022/10/SecurityofPasskeysintheGooglePasswordManager.html
//! [android-ver]: https://source.chromium.org/chromium/chromium/src/+/main:chrome/android/features/cablev2_authenticator/java/src/org/chromium/chrome/browser/webauth/authenticator/CableAuthenticatorUI.java;l=170-171;drc=4a8573cb240df29b0e4d9820303538fb28e31d84
//! [crcable]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/
//! [devicePubKey]: https://w3c.github.io/webauthn/#sctn-device-publickey-extension
//! [gpfido2]: https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/Fido2PrivilegedApiClient
//! [ios]: https://developer.apple.com/videos/play/wwdc2022/10092/
//! [Noise protocol]: http://noiseprotocol.org/noise.html
//! [^qr]: Most mobile device camera apps have an integrated QR code scanner.

mod base10;
mod btle;
mod crypter;
mod framing;
mod handshake;
mod noise;
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
use tokio_tungstenite::tungstenite::http::Uri;

pub use self::handshake::CableRequestType;
use self::{
    btle::*,
    handshake::*,
    tunnel::{get_domain, Tunnel},
};
use crate::{
    ctap2::{
        commands::GetInfoResponse, decrypt, encrypt, hkdf_sha_256, regenerate, CtapAuthenticator,
    },
    error::WebauthnCError,
    ui::UiCallback,
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
type Psk = [u8; 32];
const BASE64URL: base64::Config = base64::Config::new(base64::CharacterSet::UrlSafe, false);

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

impl DerivedValueType {
    pub fn derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        output: &mut [u8],
    ) -> Result<(), WebauthnCError> {
        let typ = self.to_u32().ok_or(WebauthnCError::Internal)?.to_le_bytes();
        Ok(hkdf_sha_256(salt, ikm, Some(&typ), output)?)
    }
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

    fn decrypt_advert(advert: BleAdvert, key: &EidKey) -> Result<Option<Eid>, WebauthnCError> {
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
    
                Some(eid)
            }
            None => {
                warn!("decrypt fail");
                None
            }
        })
    }

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

    fn get_domain(&self) -> Option<String> {
        get_domain(self.tunnel_server_id)
    }

    pub fn get_connect_url(&self, tunnel_id: TunnelId) -> Option<Uri> {
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

    pub fn get_contact_url(&self) -> Option<Uri> {
        self.get_domain().and_then(|domain| {
            let routing_id = base64::encode_config(&self.routing_id, BASE64URL);
            Uri::builder()
                .scheme("wss")
                .authority(domain)
                .path_and_query(format!("/cable/contact/{}", routing_id))
                .build()
                .ok()
        })
    }

    pub fn get_new_tunnel_url(&self, tunnel_id: TunnelId) -> Option<Uri> {
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=170;drc=de9f16dcca1d5057ba55973fa85a5b27423d414f
        self.get_domain().and_then(|domain| {
            let tunnel_id = hex::encode_upper(tunnel_id);
            Uri::builder()
                .scheme("wss")
                .authority(domain)
                .path_and_query(format!("/cable/new/{}", tunnel_id))
                .build()
                .ok()
        })
    }
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
        DerivedValueType::EIDKey.derive(&qr_secret, &[], &mut eid_key)?;

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

    pub fn decrypt_advert(&self, advert: BleAdvert) -> Result<Option<Eid>, WebauthnCError> {
        Eid::decrypt_advert(advert, &self.eid_key)
    }

    pub fn encrypt_advert(&self, eid: &Eid) -> Result<BleAdvert, WebauthnCError> {
        eid.encrypt_advert(&self.eid_key)
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
        DerivedValueType::TunnelID.derive(
            &self.qr_secret,
            &[],
            &mut tunnel_id,
        )?;
        Ok(tunnel_id)
    }

    /// Gets the pre-shared key associated with this [Discovery]
    pub fn get_psk(&self, eid: &Eid) -> Result<Psk, WebauthnCError> {
        let mut psk: Psk = [0; size_of::<Psk>()];
        DerivedValueType::PSK.derive(
            &self.qr_secret,
            &eid.to_bytes(),
            &mut psk,
        )?;
        Ok(psk)
    }
}

pub async fn connect_cable_authenticator<'a, U: UiCallback + 'a>(
    request_type: CableRequestType,
    ui_callback: &'a U,
) -> Result<CtapAuthenticator<'a, Tunnel, U>, WebauthnCError> {
    // TODO: it may be better to return a caBLE-specific authenticator object,
    // rather than CtapAuthenticator, because the device will close the
    // Websocket connection as soon as we've sent a single command.
    trace!("Creating discovery QR code...");
    let disco = Discovery::new(request_type)?;
    let handshake = disco.make_handshake()?;
    let url = handshake.to_qr_url()?;
    ui_callback.cable_qr_code(url);

    trace!("Opening BTLE...");
    let scanner = Scanner::new().await?;
    trace!("Waiting for beacon...");
    let eid = disco
        .wait_for_matching_response(&scanner)
        .await?
        .ok_or_else(|| {
            error!("No caBLE EID received!");
            WebauthnCError::NoSelectedToken
        })?;
    ui_callback.dismiss_qr_code();

    let tunnel_id: TunnelId = disco.get_tunnel_id()?;
    let psk: Psk = disco.get_psk(&eid)?;

    let connect_url = eid.get_connect_url(tunnel_id).ok_or_else(|| {
        error!("Unknown WebSocket tunnel URL for {:?}", eid);
        WebauthnCError::NotSupported
    })?;
    let tun = Tunnel::connect(&connect_url, psk, &disco.local_identity.as_ref()).await?;

    tun.get_authenticator(ui_callback).ok_or_else(|| {
        error!("no supported protocol versions!");
        WebauthnCError::NotSupported
    })
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
        DerivedValueType::EIDKey.derive(&qr_secret, &[], &mut eid_key).unwrap();
        trace!("eid_key = {:?}", eid_key);

        let r = Eid::decrypt_advert(advert, &eid_key).unwrap().unwrap();
        trace!("eid: {:?}", r);

        let expected = Eid {
            tunnel_server_id: 0,
            routing_id: [2, 101, 85],
            nonce: [139, 181, 197, 201, 164, 77, 145, 58, 94, 178],
        };
        assert_eq!(expected, r);
        trace!("url: {:?}", r.get_contact_url());
    }

    /*
    Apple:
    TRACE webauthn_authenticator_rs::cable::test: disco=Discovery { request_type: DiscoverableMakeCredential, local_identity: EcKey, qr_secret: [2, 164, 38, 70, 252, 116, 18, 55, 28, 11, 186, 14, 82, 68, 97, 181], eid_key: [48, 110, 164, 59, 84, 219, 104, 197, 65, 215, 206, 40, 249, 91, 45, 83, 58, 54, 61, 136, 206, 139, 231, 105, 189, 12, 211, 190, 63, 173, 17, 227, 144, 28, 61, 153, 255, 224, 214, 143, 233, 185, 225, 207, 140, 217, 239, 164, 53, 205, 254, 207, 114, 20, 130, 255, 78, 3, 69, 97, 82, 90, 94, 180] }
    TRACE webauthn_authenticator_rs::cable::test: private key:
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIGuC17W0YFDQsBzJEPJT6WAx9VUB4wofABtikTPbny3WoAoGCCqGSM49
    AwEHoUQDQgAEG/uQgbosFbITdGzc6hMI3XYa7p//a9lyucfAcIr4Vg8sZ9niz2Z2
    dviW2pxCfxI7M/CVPXQx23Y6zQVbisjBaQ==
    -----END EC PRIVATE KEY-----

    TRACE webauthn_authenticator_rs::cable::test: handshake=HandshakeV2 { peer_identity: EcKey, secret: [2, 164, 38, 70, 252, 116, 18, 55, 28, 11, 186, 14, 82, 68, 97, 181], known_domains_count: 2, timestamp: SystemTime { tv_sec: 1670053563, tv_nsec: 523972000 }, supports_linking_info: false, request_type: DiscoverableMakeCredential, supports_non_discoverable_make_credential: false }
    TRACE webauthn_authenticator_rs::cable::test: url="FIDO:/7067991941264195705543828571980176622148514907700366119881559022655069958011099527538108763789541415260312724760225287000762379316104890529156909664837141668112901"
    TRACE webauthn_authenticator_rs::cable::test:
    █████████████████████████████████████████████
    █████████████████████████████████████████████
    ████ ▄▄▄▄▄ █▄▄ ▄▄ ▄▀▄ ▀▄ ▀█  ▀▀ ██ ▄▄▄▄▄ ████
    ████ █   █ █▄█▄ ██▀▀▄▀▀▄ ▄█▄▄█ ▀▀█ █   █ ████
    ████ █▄▄▄█ █▀█  ▀▄▀▄▀▀  ▄▀ ▀ ▀▀█▀█ █▄▄▄█ ████
    ████▄▄▄▄▄▄▄█▄▀ ▀▄█ ▀ ▀▄█▄█▄▀ ▀▄█▄█▄▄▄▄▄▄▄████
    ████▄▀▄█▀▀▄ ▀ ▄▄█ ▀██ █▄ █  ▀▄▄█▄▀▀ ██ █▄████
    ████▄▄▀▀▀▀▄ ▄█   █▄▄█▀ ▀ █▄▀▄██ █  ▄▄█▀██████
    ████▄▀ ▄▄▄▄▄▀ █▀█▄ ▄ ████ ▄ █ █ ▄▄▄▀▀███ ████
    ████▀█▄█▀▀▄█▀ ▀ ▀▄███▄ ███ ▄▀███▄▀ █▄▀▀▀█████
    █████▀ ██▀▄▄███ █▄▀▄ ▄ ▄▄▀▄ █▀███▄▄█▄█▀▀▄████
    █████▄ ▀▄█▄▄█ ██▄█▄▀ ▀ ▄█▄ ▀ ▄█▄ ▄█▀ ▄█▀ ████
    ████ █▀▄ ▀▄▀ █▀▀▀▄▀▀▀ █  ▀▄▀███▀▄▀ █▀▄▀▄█████
    ████▀▀▄▀▄█▄▀█▄ ▄▀▄▄▀▄▀█▀█ ▄█▀█▄▀█ ▄▄▄▀ █▀████
    ████▄▄█▀██▄ █ ▀ ▄█▄▄█ █▀▄█▄▄ █▀ ██ ▀█▄▄█ ████
    ████▄▄▀ ▀▄▄▀▄██ ▀▄▄▄█▄▄ ▄██  ▄▄▀▄█▀▄▄▀█  ████
    ████▄▄█▄▄▄▄█ ▀█ █▀   ▄█▄██ ▀█ █▄ ▄▄▄  █  ████
    ████ ▄▄▄▄▄ █▄  █ ▄▀▀ ▄ █▄▀█  █▄▀ █▄█ ▄ ▄▀████
    ████ █   █ ██▀ ██▄██ ▄ ▄▀ █▄ ▄██▄ ▄  ▄█▄█████
    ████ █▄▄▄█ █▄ █▄▄ ▄▀ ▀█▀▄█▀ █▀█▄█▄▀ ▀  ▄ ████
    ████▄▄▄▄▄▄▄█▄███▄████▄█████▄█▄▄█▄▄▄▄▄▄█▄▄████
    █████████████████████████████████████████████
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
    TRACE webauthn_authenticator_rs::cable::test: Opening BTLE
    TRACE webauthn_authenticator_rs::cable::test: Waiting for beacon...
    TRACE btleplug::corebluetooth::internal: Authorization status AllowedAlways
    DEBUG btleplug::corebluetooth::adapter: Waiting on adapter connect
    TRACE btleplug::corebluetooth::central_delegate::CentralDelegate: delegate_class
    TRACE btleplug::corebluetooth::central_delegate::CentralDelegate: delegate_init
    TRACE btleplug::corebluetooth::central_delegate::CentralDelegate: Storing off ivars!
    TRACE btleplug::corebluetooth::central_delegate::CentralDelegate: delegate_centralmanagerdidupdatestate
    DEBUG btleplug::corebluetooth::adapter: Adapter connected
    TRACE btleplug::corebluetooth::internal: Adapter message!
    TRACE btleplug::corebluetooth::internal: BluetoothAdapter::start_discovery
    TRACE btleplug::corebluetooth::internal: Got service data advertisement! {0000fde2-0000-1000-8000-00805f9b34fb: [177, 140, 190, 144, 131, 154, 165, 118, 246, 215, 118, 5, 40, 147, 26, 30, 54, 95, 85, 34]}
    TRACE webauthn_authenticator_rs::cable: advert: [177, 140, 190, 144, 131, 154, 165, 118, 246, 215, 118, 5, 40, 147, 26, 30, 54, 95, 85, 34]
    TRACE webauthn_authenticator_rs::cable::test: r=Ok(Some(Eid { tunnel_server_id: 1, routing_id: [77, 228, 203], nonce: [120, 156, 18, 36, 92, 175, 175, 136, 191, 84] }))
         */
}

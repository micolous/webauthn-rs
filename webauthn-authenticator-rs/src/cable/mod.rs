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
mod discovery;
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
    discovery::{Eid, Discovery},
    tunnel::{get_domain, Tunnel},
};
use crate::{
    ctap2::{
        commands::GetInfoResponse, decrypt, encrypt, hkdf_sha_256, regenerate, CtapAuthenticator,
    },
    error::WebauthnCError,
    ui::UiCallback,
};

type Psk = [u8; 32];

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

    let tunnel_id = disco.get_tunnel_id()?;
    let psk = disco.get_psk(&eid)?;

    let connect_url = disco.get_connect_uri(&eid)?;
    let tun = Tunnel::connect(&connect_url, psk, &disco.local_identity.as_ref()).await?;

    tun.get_authenticator(ui_callback).ok_or_else(|| {
        error!("no supported protocol versions!");
        WebauthnCError::NotSupported
    })
}

#[cfg(test)]
mod test {
    // TODO
}

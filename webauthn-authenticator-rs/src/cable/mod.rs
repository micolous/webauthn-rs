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
//! [devicePubKey][] to attest a specific device's identity.
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
//! The platform (or "browser") generates a CBOR message
//! ([HandshakeV2][handshake::HandshakeV2]) containing the desired transaction
//! type (`MakeCredential` or `GetAssertion`), a shared secret and some protocol
//! version information. This gets encoded as [base10] and turned into a
//! `FIDO:/` URL, and is displayed as a QR code for the user to scan with their
//! mobile device.
//!
//! The authenticator (mobile device) scans this QR code, and establishes a
//! tunnel to a well-known WebSocket tunnel server of *its* choosing
//! ([get_domain][tunnel::get_domain]). Once established, it broadcasts an
//! encrypted [Eid][discovery::Eid] message over BLE service
//! advertisements to be discovered by the platform.
//!
//! Meanwhile, the platform scans for caBLE BLE advertisements and tries to
//! decrypt and parse them
//! ([decrypt_advert][discovery::Discovery::decrypt_advert]). On success,
//! it can then find which tunnel server to connect to, the tunnel ID, and a
//! nonce.
//!
//! The platform connects to the tunnel server, and starts a handshake with the
//! authenticator using a non-standard version of the [Noise protocol][]
//! ([CableNoise][noise::CableNoise]), using secrets exchanged in the QR code and BTLE
//! advertisement and a new ephemeral session key, allowing them to derive
//! traffic keys for [Crypter][crypter::Crypter].
//!
//! The authenticator will then immediately send a
//! [GetInfoResponse][crate::ctap2::GetInfoResponse], and may also send a
//! pairing payload (presently Android only). Where supported, a pairing payload
//! is sent *regardless* of whether the user selects "remember this computer" on
//! the mobile device (the payload will just be null bytes).
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
#[allow(rustdoc::private_intra_doc_links)]

mod base10;
mod btle;
mod crypter;
mod discovery;
mod framing;
mod handshake;
mod noise;
mod tunnel;

pub use base10::DecodeError;

use self::{
    btle::Scanner,
    discovery::Discovery,
    tunnel::Tunnel,
};
use crate::{
    ctap2::CtapAuthenticator,
    error::WebauthnCError,
    ui::UiCallback,
};

type Psk = [u8; 32];

#[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
pub enum CableRequestType {
    #[default]
    GetAssertion,
    MakeCredential,
    DiscoverableMakeCredential,
}

impl ToString for CableRequestType {
    fn to_string(&self) -> String {
        use CableRequestType::*;
        match self {
            GetAssertion => String::from("ga"),
            DiscoverableMakeCredential => String::from("mc"),
            MakeCredential => String::from("mc"),
        }
    }
}

impl CableRequestType {
    pub fn from_string(val: &str, supports_non_discoverable_make_credential: bool) -> Option<Self> {
        use CableRequestType::*;
        match val {
            "ga" => Some(GetAssertion),
            "mc" => Some(if supports_non_discoverable_make_credential {
                MakeCredential
            } else {
                DiscoverableMakeCredential
            }),
            _ => None,
        }
    }
}

/// Establishes a connection to a caBLE authenticator using QR codes, Bluetooth
/// Low Energy and a Websocket tunnel.
/// 
/// The QR code to be displayed will be passed via [UiCallback::cable_qr_code].
/// 
/// The resulting connection is passed as a [CtapAuthenticator], but the remote
/// device will only accept a single command (specified in the `request_type`
/// parameter) and then close the underlying Websocket.
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

    let psk = disco.get_psk(&eid)?;

    let connect_url = disco.get_connect_uri(&eid)?;
    let tun = Tunnel::connect(&connect_url, psk, disco.local_identity.as_ref()).await?;

    tun.get_authenticator(ui_callback).ok_or_else(|| {
        error!("no supported protocol versions!");
        WebauthnCError::NotSupported
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cable_request_type() {
        assert_eq!(Some(CableRequestType::DiscoverableMakeCredential), CableRequestType::from_string("mc", false));
        assert_eq!(Some(CableRequestType::MakeCredential), CableRequestType::from_string("mc", true));
        assert_eq!(Some(CableRequestType::GetAssertion), CableRequestType::from_string("ga", false));
        assert_eq!(Some(CableRequestType::GetAssertion), CableRequestType::from_string("ga", true));
        assert_eq!(None, CableRequestType::from_string("nonsense", false));

        assert_eq!("mc", CableRequestType::DiscoverableMakeCredential.to_string());
        assert_eq!("mc", CableRequestType::MakeCredential.to_string());
        assert_eq!("ga", CableRequestType::GetAssertion.to_string());
    }

}

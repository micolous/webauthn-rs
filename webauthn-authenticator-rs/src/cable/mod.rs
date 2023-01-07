//! caBLE / Hybrid Authenticator
//!
//! **tl;dr:** scan a QR code with a `FIDO:/` URL, mobile device sends a BTLE
//! advertisement, this is used to establish a doubly-encrypted (TLS and Noise)
//! Websocket tunnel over which the platform can send a single CTAP 2.x command
//! and get a response.
//!
//! This module implements both the [initator][connect_cable_authenticator] and
//! [authenticator][share_cable_authenticator] side of caBLE, provided
//! [you have appropriate hardware](#requirements).
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
//! This does not implement pairing (aka: "contact lists", "remember this
//! computer").
//!
//! ## Requirements
//!
//! The initator (or "browser") requires:
//!
//! * a Bluetooth Low Energy (BTLE) adaptor
//!
//! * an internet connection
//!
//! The authenticator (mobile device) requires:
//!
//! * a caBLE implementation, such as:
//!
//!   * [Android 7 or later][android-ver] with
//!     [a recent version of Chrome and Google Play Services (October 2022)][android]
//!
//!   * [iOS 16 or later][ios]
//!
//! * a Bluetooth Low Energy (BTLE) radio which can transmit service data
//!   advertisements
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
//! identify *which* device was used.
//!
//! In both cases, the credential is cached in the device's secure element, and
//! requires user verification (lock screen pattern, PIN, password or biometric
//! authentication) to access.
//!
//! **Warning:** iOS 15 will recognise caBLE QR codes and offer to authenticate,
//! but this version of the protocol is not supported.
//!
//! ## Protocol overview
//!
//! Entities in a caBLE transaction:
//!
//! * The _initator_ (typically a web browser) starts the caBLE session for a
//!   `MakeCredential` or `GetAssertion` request on behalf of a relying party.
//!
//! * The _authenticator_ (or mobile device) stores credential(s) for the user
//!   in a secure fashion, with some sort of local authentication.
//!
//! * The _tunnel server_ provides a two-way channel for the initator and
//!   authenticator to communicate over WebSockets. These are operated by
//!   organisations providing caBLE authenticators (eg: Apple, Google).
//!
//! The user attempts to register or sign in using WebAuthn, and chooses to use
//! caBLE ("create a passkey on another device", "save a passkey on a device
//! with a camera"). This application becomes the _initator_ of the caBLE
//! session.
//!
//! The initator generates a CBOR message ([HandshakeV2][]) containing the
//! desired transaction type (`MakeCredential` or `GetAssertion`),
//! [a shared secret][qr-secret] and some protocol version information. It
//! encodes the message as a `FIDO:/` URL by encoding the CBOR as [base10], and
//! then displays it as a QR code for the user to scan with their authenticator.
//!
//! The user scans this QR code using their authenticator (mobile device), which
//! deserialises the [HandshakeV2][] message.
//!
//! Both the initiator and authenticator
//! [derive the tunnel ID][discovery::Discovery::derive_tunnel_id] from the QR
//! code's [shared secret][qr-secret].
//!
//! The authenticator establishes a connection to
//! [a well-known WebSocket tunnel server][tunnel::get_domain] of *its*
//! choosing. Once established, the tunnel server provides a routing ID, which
//! allows the initiator to connect to this session.
//!
//! The authenticator takes [the routing ID][routing_id],
//! [tunnel server ID][tunnel_server_id], and
//! [a nonce of its choosing][nonce] (not shared with the tunnel server) into an
//! [Eid][], and then encrypts and signs it using a secret derived from the QR
//! code's [shared secret][qr-secret]. It then broadcasts this encrypted [Eid][]
//! as a BTLE service data advertisement.
//!
//! Meanwhile, the initiator scans for caBLE BTLE service data advertisements,
//! and [tries to decrypt and parse them][discovery::Discovery::decrypt_advert].
//! On success, it can then find which
//! [tunnel server to connect to][tunnel_server_id], the
//! [routing ID][routing_id], and [the nonce][nonce].
//!
//! Both the initator and the authenticator
//! [derive a pre-shared key][discovery::Discovery::derive_psk] from the
//! [shared secret][qr-secret] and [nonce][].
//!
//! The initator connects to the tunnel server, and starts a handshake with the
//! authenticator using a non-standard version of the [Noise protocol][]
//! ([CableNoise][]), using the pre-shared key and a new
//! ephemeral session key.
//!
//! They use the [CableNoise][] to derive traffic keys for [Crypter][]. All
//! further communications between the initiator and authenticator occur over
//! the [Crypter][] channel.
//!
//! The authenticator immediately sends a [GetInfoResponse][], and will also
//! send a pairing payload once the user has accepted or refused consent[^pair].
//!
//! The initiator can then send a *single* `MakeCredential` or `GetAssertion`
//! command to the authenticator in CTAP 2.0 format. This request *does not* use
//! PIN/UV auth – user verification is handled internally by the authenticator
//! *outside* the CTAP 2.0 protocol[^uv].
//!
//! Once the command is sent, the authenticator will prompt the user to approve
//! the request in a user-verifying way (biometric or lock screen pattern,
//! password or PIN), showing the user and relying party name.
//!
//! Once approved or rejected, the authenticator returns the response to the
//! command, and then close the Websocket channel. A new handshake must be
//! performed if the user wishes to perform another transaction.
//!
//! The initiator then sends the authenticator's response to the relying party
//! using the usual WebAuthn APIs.
//!
//! [android]: https://developers.google.com/identity/passkeys/supported-environments
//! [android-sec]: https://security.googleblog.com/2022/10/SecurityofPasskeysintheGooglePasswordManager.html
//! [android-ver]: https://source.chromium.org/chromium/chromium/src/+/main:chrome/android/features/cablev2_authenticator/java/src/org/chromium/chrome/browser/webauth/authenticator/CableAuthenticatorUI.java;l=170-171;drc=4a8573cb240df29b0e4d9820303538fb28e31d84
//! [CableNoise]: noise::CableNoise
//! [crcable]: https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/
//! [Crypter]: noise::Crypter
//! [devicePubKey]: https://w3c.github.io/webauthn/#sctn-device-publickey-extension
//! [Eid]: discovery::Eid
//! [GetInfoResponse]: crate::ctap2::GetInfoResponse
//! [gpfido2]: https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/Fido2PrivilegedApiClient
//! [HandshakeV2]: handshake::HandshakeV2
//! [ios]: https://developer.apple.com/videos/play/wwdc2022/10092/
//! [Noise protocol]: http://noiseprotocol.org/noise.html
//! [nonce]: discovery::Eid::nonce
//! [qr-secret]: handshake::HandshakeV2::secret
//! [routing_id]: discovery::Eid::routing_id
//! [tunnel_server_id]: discovery::Eid::tunnel_server_id
//!
//! [^pair]: Pairing payloads are only supported on Android. Where supported,
//! pairing payloads will always be sent, padded to a constant size,
//! *regardless* of whether the user consented to pairing. If the user did not
//! consent, the payload will just be null bytes.
//!
//! [^uv]: Chromium and Safari won't even attempt PIN/UV auth, even if the
//! [GetInfoResponse][] suggested it was required.
//!
//! [^qr]: Most mobile device camera apps have an integrated QR code scanner.
#[allow(rustdoc::private_intra_doc_links)]
mod base10;
mod btle;
mod discovery;
mod framing;
mod handshake;
mod noise;
mod tunnel;

use std::collections::BTreeMap;

pub use base10::DecodeError;
pub use btle::Advertiser;

use crate::{
    authenticator_hashed::{
        perform_auth_with_request, perform_register_with_request,
        AuthenticatorBackendHashedClientData,
    },
    cable::{
        btle::Scanner,
        discovery::Discovery,
        framing::{CableFrameType, RequestType, SHUTDOWN_COMMAND},
        handshake::HandshakeV2,
        tunnel::Tunnel,
    },
    ctap2::{CtapAuthenticator, GetInfoResponse},
    error::{CtapError, WebauthnCError},
    transport::Token,
    types::{CableRequestType, CableState},
    ui::UiCallback,
};

type Psk = [u8; 32];

impl CableRequestType {
    fn to_cable_string(self) -> String {
        use CableRequestType::*;
        match self {
            GetAssertion => String::from("ga"),
            DiscoverableMakeCredential => String::from("mc"),
            MakeCredential => String::from("mc"),
        }
    }

    fn from_cable_string(
        val: &str,
        supports_non_discoverable_make_credential: bool,
    ) -> Option<Self> {
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
    ui_callback.cable_qr_code(request_type, url);

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
    drop(scanner);

    let psk = disco.derive_psk(&eid)?;

    let connect_url = disco.get_connect_uri(&eid)?;
    let tun = Tunnel::connect_initiator(
        &connect_url,
        psk,
        disco.local_identity.as_ref(),
        ui_callback,
    )
    .await?;

    tun.get_authenticator(ui_callback).ok_or_else(|| {
        error!("no supported protocol versions!");
        WebauthnCError::NotSupported
    })
}

/// Share an authenicator using caBLE.
///
/// * `backend` is a [AuthenticatorBackendHashedClientData] implementation.
///
/// * `url` is a `FIDO:/` URL from the initator's QR code.
///
/// * `tunnel_server_id` is the well-known tunnel server to use. Set this to 0
///   to use Google's tunnel server.
///
/// * `advertiser` is reference to an [Advertiser] for starting and stopping
///   Bluetooth Low Energy advertisements.
///
/// * `ui_callback` trait for prompting for user interaction where needed.
pub async fn share_cable_authenticator<'a, U>(
    backend: &mut impl AuthenticatorBackendHashedClientData,
    mut info: GetInfoResponse,
    url: &str,
    tunnel_server_id: u16,
    advertiser: &mut impl Advertiser,
    ui_callback: &'a U,
    close_after_one_command: bool,
) -> Result<(), WebauthnCError>
where
    U: UiCallback + 'a,
{
    // Because AuthenticatorBackendWithRequests does PIN/UV auth for us, we need
    // to remove anything from GetInfoResponse that would suggest the remote
    // side should attempt PIN/UV auth.
    //
    // Chromium and Safari appear to ignore these options, but we actually do
    // this properly. For now, we're just going to set this to "known" values.
    info.options = Some(BTreeMap::from([
        // Possibly a lie.
        ("uv".to_string(), true),
    ]));
    info.pin_protocols = None;
    let transports = info.transports.get_or_insert(Default::default());
    transports.push("cable".to_string());
    transports.push("hybrid".to_string());

    let handshake = HandshakeV2::from_qr_url(url)?;
    let discovery = handshake.to_discovery()?;

    let mut tunnel = Tunnel::connect_authenticator(
        &discovery,
        tunnel_server_id,
        &handshake.peer_identity,
        info,
        advertiser,
        ui_callback,
    )
    .await?;

    trace!("tunnel established");
    let timeout_ms = 30000;

    loop {
        ui_callback.cable_status_update(CableState::WaitingForInitiatorCommand);
        let msg = tunnel.recv().await?.ok_or(WebauthnCError::Closed)?;

        ui_callback.cable_status_update(CableState::Processing);
        let resp = match msg.message_type {
            CableFrameType::Shutdown => {
                break;
            }
            CableFrameType::Ctap => match (handshake.request_type, msg.parse_request()?) {
                (CableRequestType::MakeCredential, RequestType::MakeCredential(mc))
                | (CableRequestType::DiscoverableMakeCredential, RequestType::MakeCredential(mc)) => {
                    perform_register_with_request(backend, mc, timeout_ms)
                }
                (CableRequestType::GetAssertion, RequestType::GetAssertion(ga)) => {
                    perform_auth_with_request(backend, ga, timeout_ms)
                }
                (c, v) => {
                    error!("Unhandled command {:02x?} for {:?}", v, c);
                    Err(WebauthnCError::NotSupported)
                }
            },
            CableFrameType::Update => {
                warn!("Linking information is not supported, ignoring update message");
                continue;
            }

            _ => {
                error!("unhandled command: {:?}", msg);
                Err(WebauthnCError::NotSupported)
            }
        };

        // Re-insert the error code as needed.
        let resp = match resp {
            Err(e) => match e {
                WebauthnCError::Ctap(c) => vec![c.into()],
                _ => vec![CtapError::Ctap1InvalidParameter.into()],
            },
            Ok(mut resp) => {
                resp.reserve(1);
                resp.insert(0, CtapError::Ok.into());
                resp
            }
        };

        // Send the response to the command
        tunnel
            .send(framing::CableFrame {
                protocol_version: 1,
                message_type: CableFrameType::Ctap,
                data: resp,
            })
            .await?;

        if close_after_one_command {
            tunnel.send(SHUTDOWN_COMMAND).await?;
            break;
        }
    }

    // Hang up
    tunnel.close().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cable_request_type() {
        assert_eq!(
            Some(CableRequestType::DiscoverableMakeCredential),
            CableRequestType::from_cable_string("mc", false)
        );
        assert_eq!(
            Some(CableRequestType::MakeCredential),
            CableRequestType::from_cable_string("mc", true)
        );
        assert_eq!(
            Some(CableRequestType::GetAssertion),
            CableRequestType::from_cable_string("ga", false)
        );
        assert_eq!(
            Some(CableRequestType::GetAssertion),
            CableRequestType::from_cable_string("ga", true)
        );
        assert_eq!(None, CableRequestType::from_cable_string("nonsense", false));

        assert_eq!(
            "mc",
            CableRequestType::DiscoverableMakeCredential.to_cable_string()
        );
        assert_eq!("mc", CableRequestType::MakeCredential.to_cable_string());
        assert_eq!("ga", CableRequestType::GetAssertion.to_cable_string());
    }
}

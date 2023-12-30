//! Bindings for Windows 10 WebAuthn API, routed over
//! [WebAuthn Terminal Services Virtual Channel Protocol][1].
//!
//! This module essentially pretends to be MSTSC (Terminal Services Client),
//! issuing the same RPCs that MSTSC would for an RDP connection, using a subset
//! of [the Virtual Channel COM interface][0].
//!
//! This module can be used for both local and remote (terminal server)
//! sessions.
//!
//! While this seems convoluted, this is actually siginificantly cleaner and
//! safer than the regular Windows WebAuthn (C) APIs, as the transport layer is
//! mostly working with CBOR rather than structs and fundamentally unsafe types
//! like `PCWSTR`.
//!
//! Unlike the regular Windows APIs, this also supports
//! [AuthenticatorBackendHashedClientData], so you can proxy requests, and
//! supports the undocumented "test" provider (`MicrosoftCtapTestProvider`).
//!
//! This API is available in Windows 10 bulid 1903 and later.
//!
//! ## API docs
//!
//! * [`MS-RDPEWA`: Remote Desktop Protocol: WebAuthn Virtual Channel Protocol][1]
//! * [MSDN: WebAuthn API](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/)
//! * [webauthn.h](github.com/microsoft/webauthn) (describes versions)
//!
//! [0]: https://learn.microsoft.com/en-us/windows/win32/api/tsvirtualchannels/
//! [1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/68f2df2e-7c40-4a93-9bb0-517e4283a991

mod channel;
mod message;
mod plugin;

use crate::{
    ctap2::commands::{GetAssertionRequest, MakeCredentialRequest},
    error::WebauthnCError,
    win10::{
        gui::Window,
        rdp::{
            channel::{Connection, VirtualChannelManager},
            message::{WebauthnPara, CMD_API_VERSION, CMD_IUVPA},
        },
    },
    AuthenticatorBackendHashedClientData,
};
use base64urlsafedata::Base64UrlSafeData;
use uuid::Uuid;
use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticationExtensionsClientOutputs,
    AuthenticatorAssertionResponseRaw, AuthenticatorAttachment,
    AuthenticatorAttestationResponseRaw, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs, ResidentKeyRequirement, UserVerificationPolicy,
};
use windows::{
    core::{AsImpl as _, Result as WinResult},
    Win32::{
        Foundation::{E_FAIL, NTE_BAD_LEN},
        Networking::WindowsWebServices::{
            WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY,
            WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
            WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        },
        System::RemoteDesktop::{IWTSPlugin, IWTSVirtualChannelManager},
    },
};

/// Interface selection options for [Win10Rdp].
///
/// Reference: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/3012640f-f57a-45a4-aa87-e2afbad42a68>
#[derive(Default, Debug, PartialEq, Eq)]
pub enum InterfaceSelection {
    /// Only use CTAP2 interfaces.
    ForceCtap,
    /// Indicate the request and response will use U2F. The provider should use
    /// the U2F device interface instead of the CTAP interface.
    PreferU2F,
    /// Indicate to first try CTAP messages and protocol. If CTAP fails, use U2F
    /// messages.
    #[default]
    PreferCtap,
    /// Only use U2F interfaces.
    ForceU2F,
}

impl InterfaceSelection {
    const fn as_flag(&self) -> u32 {
        match self {
            InterfaceSelection::ForceCtap => 0,
            InterfaceSelection::PreferU2F => 0x0002_0000,
            InterfaceSelection::PreferCtap => 0x0004_0000,
            InterfaceSelection::ForceU2F => 0x0800_0000,
        }
    }
}

pub struct Win10Rdp {
    plugin: IWTSPlugin,
    iface: IWTSVirtualChannelManager,
    test_mode: bool,
    interface: InterfaceSelection,
}

impl Win10Rdp {
    pub fn new() -> WinResult<Self> {
        let o = Self {
            plugin: plugin::get_webauthn_iwtsplugin()?,
            iface: VirtualChannelManager::new().into(),
            test_mode: false,
            interface: InterfaceSelection::default(),
        };

        unsafe {
            o.plugin.Initialize(&o.iface)?;
            o.plugin.Connected()?;
        }

        Ok(o)
    }

    /// Enables Windows WebAuthn test mode (`MicrosoftCtapTestProvider`).
    ///
    /// ## Warning
    ///
    /// This mode is undocumented, and has a number of limitations and broken
    /// things:
    ///
    /// * Windows will pop up a message with "this security key can't be used"
    ///   momentarily. That will disappear without further interaction.
    ///
    /// * Test mode only works with [`AuthenticatorAttachment::CrossPlatform`].
    ///
    /// * User verification will never be performed, even if `required`.
    ///
    /// * `packed` attestation is broken - Windows incorrectly encodes the
    ///   `id-fido-gen-ce-aaguid` extension as only *one* layer of octet string,
    ///   rather than [the two required by the spec][0].
    ///
    /// * Requests will still be routed through RDP sessions, just like ordinary
    ///   platform WebAuthn requests on Windows.
    ///
    /// [0]: https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements
    pub fn enable_test_mode(&mut self) {
        self.test_mode = true;
    }

    /// Sets the interface Windows
    pub fn set_interface(&mut self, interface: InterfaceSelection) {
        self.interface = interface;
    }

    fn connect(&self) -> WinResult<Connection> {
        // Get back the IWTSListenerCallback
        let Some(c) = unsafe { self.iface.as_impl() }.get_webauthn_callback() else {
            return Err(E_FAIL.into());
        };

        Connection::new(&c)
    }

    /// Gets the currently supported API version.
    pub fn get_api_version(&self) -> WinResult<u32> {
        let c = self.connect()?;
        let s = serde_cbor_2::to_vec(&CMD_API_VERSION).unwrap();
        let r = c.transceive_raw(&s)?;

        Ok(u32::from_le_bytes(r.try_into().map_err(|_| NTE_BAD_LEN)?))
    }

    /// Checks if a user-verifying platform authenticator is available.
    pub fn is_user_verifying_platform_authenticator_available(&self) -> WinResult<bool> {
        let c = self.connect()?;
        let s = serde_cbor_2::to_vec(&CMD_IUVPA).unwrap();
        let r = c.transceive_raw(&s)?;

        Ok(u32::from_le_bytes(r.try_into().map_err(|_| NTE_BAD_LEN)?) == 1)
    }
}

impl AuthenticatorBackendHashedClientData for Win10Rdp {
    fn perform_register(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let c = self.connect().map_err(|_| WebauthnCError::Internal)?;
        let authenticator_selection = options.authenticator_selection.unwrap_or_default();

        let mut flags = self.interface.as_flag()
            | match authenticator_selection.user_verification {
                UserVerificationPolicy::Discouraged_DO_NOT_USE => 0x0100_0000,
                UserVerificationPolicy::Preferred => 0x0080_0000,
                UserVerificationPolicy::Required => 0x0040_0000,
            };

        if self.test_mode {
            warn!("Using test mode!");
            flags |= 0x8000_0000;
            if matches!(
                authenticator_selection.user_verification,
                UserVerificationPolicy::Required
            ) {
                warn!("user verification is not supported in test mode");
            }

            if !matches!(
                authenticator_selection.authenticator_attachment,
                Some(AuthenticatorAttachment::CrossPlatform)
            ) {
                warn!("test mode only supports cross-platform attachment");
            }
        }

        let mc = MakeCredentialRequest {
            client_data_hash,
            rp: options.rp,
            user: options.user,
            pub_key_cred_params: options.pub_key_cred_params,
            exclude_list: options.exclude_credentials.unwrap_or_default(),

            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let window = Window::new()?;

        let webauthn_para = WebauthnPara {
            wnd: window.hwnd.0,
            attachment: match authenticator_selection.authenticator_attachment {
                None => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
                Some(AuthenticatorAttachment::CrossPlatform) => {
                    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
                }
                Some(AuthenticatorAttachment::Platform) => {
                    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM
                }
            },
            require_resident: authenticator_selection.require_resident_key
                || matches!(
                    authenticator_selection.resident_key,
                    Some(ResidentKeyRequirement::Required)
                ),
            prefer_resident: matches!(
                authenticator_selection.resident_key,
                Some(ResidentKeyRequirement::Preferred)
            ),
            user_verification: match authenticator_selection.user_verification {
                UserVerificationPolicy::Required => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                UserVerificationPolicy::Preferred => {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED
                }
                UserVerificationPolicy::Discouraged_DO_NOT_USE => {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
                }
            },
            attestation_preference: match options.attestation {
                None => WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY,
                Some(AttestationConveyancePreference::None) => {
                    WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE
                }
                Some(AttestationConveyancePreference::Indirect) => {
                    WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT
                }
                Some(AttestationConveyancePreference::Direct) => {
                    WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
                }
            },
            enterprise_attestation: 0,
            cancellation_id: Uuid::nil(),
        };

        let (channel_response, ret) = c
            .transcieve_cbor(mc, flags, timeout_ms, Uuid::nil(), webauthn_para)
            .map_err(|_| WebauthnCError::Internal)?;

        drop(window);
        trace!(?ret);
        let ret = ret.ok_or(WebauthnCError::Internal)?;

        // The obvious thing to do here would be to pass the raw authenticator
        // data back, but it seems like everything expects a Map<String, Value>
        // here, rather than a Map<u32, Value>... so we need to re-serialize
        // that data!
        //
        // Alternatively, it may be possible to do this "more cheaply" by
        // remapping the keys of the map.
        let raw = serde_cbor_2::to_vec(&ret).map_err(|e| {
            error!("MakeCredentialResponse re-serialization: {:?}", e);
            WebauthnCError::Cbor
        })?;

        // HACK: parsing out the real ID is complicated, and other parts of the
        // library will do it for us, so we'll put in empty data here.
        let cred_id = vec![];
        let id = String::new();

        let type_ = ret.fmt.ok_or(WebauthnCError::InvalidAlgorithm)?;

        Ok(RegisterPublicKeyCredential {
            id,
            raw_id: Base64UrlSafeData(cred_id),
            type_,
            extensions: RegistrationExtensionsClientOutputs::default(), // TODO
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(raw),
                client_data_json: Base64UrlSafeData(vec![]),
                // The transport actually used
                transports: channel_response
                    .device_info
                    .as_ref()
                    .and_then(|device_info| device_info.get_transport())
                    .map(|t| vec![t]),
            },
        })
    }

    fn perform_auth(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        let c = self.connect().map_err(|_| WebauthnCError::Internal)?;

        // todo!()
        // trace!("trying to authenticate...");
        // let auth_token = block_on(self.get_pin_uv_auth_token(
        //     client_data_hash.as_slice(),
        //     Permissions::GET_ASSERTION,
        //     Some(options.rp_id.clone()),
        //     options.user_verification,
        // ))?;

        // let req_options = if let AuthToken::UvTrue = auth_token {
        //     // No pin_uv_auth_param, but verification is configured, so use it
        //     Some(BTreeMap::from([("uv".to_owned(), true)]))
        // } else {
        //     None
        // };
        // let (pin_uv_auth_proto, pin_uv_auth_param) = auth_token.into_pin_uv_params();

        let mut flags = self.interface.as_flag()
            | match options.user_verification {
                UserVerificationPolicy::Discouraged_DO_NOT_USE => 0x0100_0000,
                UserVerificationPolicy::Preferred => 0x0080_0000,
                UserVerificationPolicy::Required => 0x0040_0000,
            };

        if self.test_mode {
            warn!("Using test mode!");
            flags |= 0x8000_0000;
            if matches!(options.user_verification, UserVerificationPolicy::Required) {
                warn!("user verification is not supported in test mode");
            }
        }

        let ga = GetAssertionRequest {
            rp_id: options.rp_id,
            client_data_hash,
            allow_list: options.allow_credentials,
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
        };

        let window = Window::new()?;

        let webauthn_para = WebauthnPara {
            wnd: window.hwnd.0,
            attachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
            require_resident: false,
            prefer_resident: false,
            user_verification: match options.user_verification {
                UserVerificationPolicy::Required => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                UserVerificationPolicy::Preferred => {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED
                }
                UserVerificationPolicy::Discouraged_DO_NOT_USE => {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
                }
            },
            attestation_preference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY,
            enterprise_attestation: 0,
            cancellation_id: Uuid::nil(),
        };

        let (channel_response, ret) = c
            .transcieve_cbor(ga, flags, timeout_ms, Uuid::nil(), webauthn_para)
            .map_err(|_| WebauthnCError::Internal)?;

        drop(window);
        trace!(?ret);
        let ret = ret.ok_or(WebauthnCError::Internal)?;

        let raw_id = ret
            .credential
            .as_ref()
            .map(|c| c.id.to_owned())
            .ok_or(WebauthnCError::Cbor)?;
        let id = raw_id.to_string();
        let type_ = ret
            .credential
            .map(|c| c.type_)
            .ok_or(WebauthnCError::Cbor)?;
        let signature = Base64UrlSafeData(ret.signature.ok_or(WebauthnCError::Cbor)?);
        let authenticator_data = Base64UrlSafeData(ret.auth_data.ok_or(WebauthnCError::Cbor)?);

        Ok(PublicKeyCredential {
            id,
            raw_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data,
                client_data_json: Base64UrlSafeData(vec![]),
                signature,
                // TODO
                user_handle: None,
            },
            // TODO
            extensions: AuthenticationExtensionsClientOutputs::default(),
            type_,
        })
    }
}

impl Drop for Win10Rdp {
    fn drop(&mut self) {
        unsafe {
            let _ = self.plugin.Terminated();
        }
    }
}

#[cfg(test)]
mod test {
    use windows::Win32::Networking::WindowsWebServices::{
        WebAuthNGetApiVersionNumber, WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
    };

    use super::*;

    #[test]
    fn get_api_version() -> Result<(), Box<dyn std::error::Error>> {
        let api_ver = unsafe { WebAuthNGetApiVersionNumber() };
        assert_ne!(0, api_ver);

        let rdp = Win10Rdp::new()?;
        assert_eq!(api_ver, rdp.get_api_version()?);

        Ok(())
    }

    #[test]
    fn is_user_verifying_platform_authenticator_available() -> Result<(), Box<dyn std::error::Error>>
    {
        let ivupa: bool =
            unsafe { WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() }?.into();

        let rdp = Win10Rdp::new()?;
        assert_eq!(
            ivupa,
            rdp.is_user_verifying_platform_authenticator_available()?
        );
        Ok(())
    }
}

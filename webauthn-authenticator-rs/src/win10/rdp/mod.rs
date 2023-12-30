mod channel;
mod message;
mod plugin;
// mod tunnel;

use crate::{
    ctap2::commands::MakeCredentialRequest,
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
    AuthenticatorAttestationResponseRaw, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs,
};
use windows::{
    core::{AsImpl as _, Result as WinResult},
    Win32::{
        Foundation::{E_FAIL, NTE_BAD_LEN},
        System::RemoteDesktop::{IWTSPlugin, IWTSVirtualChannelManager},
    },
};

pub struct Win10Rdp {
    plugin: IWTSPlugin,
    iface: IWTSVirtualChannelManager,
}

impl Win10Rdp {
    pub fn new() -> WinResult<Self> {
        let o = Self {
            plugin: plugin::get_webauthn_iwtsplugin()?,
            iface: VirtualChannelManager::new().into(),
        };

        unsafe {
            o.plugin.Initialize(&o.iface)?;
            o.plugin.Connected()?;
        }

        Ok(o)
    }

    fn connect(&self) -> WinResult<Connection> {
        // Get back the IWTSListenerCallback
        let Some(c) = unsafe { self.iface.as_impl() }.get_webauthn_callback() else {
            return Err(E_FAIL.into());
        };

        Connection::new(&c)
    }

    pub fn get_api_version(&self) -> WinResult<u32> {
        let c = self.connect()?;
        let s = serde_cbor_2::to_vec(&CMD_API_VERSION).unwrap();
        let r = c.transceive_raw(&s)?;

        Ok(u32::from_le_bytes(r.try_into().map_err(|_| NTE_BAD_LEN)?))
    }

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
        options: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
        _timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::RegisterPublicKeyCredential, WebauthnCError> {
        let c = self.connect().map_err(|_| WebauthnCError::Internal)?;

        let authenticator_selection = options.authenticator_selection.unwrap_or_default();
        // let auth_token = block_on(self.get_pin_uv_auth_token(
        //     client_data_hash.as_slice(),
        //     Permissions::MAKE_CREDENTIAL,
        //     Some(options.rp.id.clone()),
        //     authenticator_selection.user_verification,
        // ))?;

        // let req_options = if let AuthToken::UvTrue = auth_token {
        //     // No pin_uv_auth_param, but verification is configured, so use it
        //     Some(BTreeMap::from([("uv".to_owned(), true)]))
        // } else {
        //     None
        // };
        // let (pin_uv_auth_proto, pin_uv_auth_param) = auth_token.into_pin_uv_params();

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
            attachment: 0,
            require_resident: false,
            prefer_resident: false,
            user_verification: 0,
            attestation_preference: 0,
            enterprise_attestation: 0,
            cancellation_id: Uuid::nil(),
        };

        let (channel_response, ret) = c
            .transcieve_cbor(mc, 4194304, 60000, Uuid::nil(), webauthn_para)
            .map_err(|_| WebauthnCError::Internal)?;

        drop(window);
        trace!(?channel_response, ?ret);
        let ret = ret.unwrap();

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
                // All transports the token supports, as opposed to the
                // transport which was actually used.
                // TODO
                transports: None,
            },
        })
    }

    fn perform_auth(
        &mut self,
        client_data_hash: Vec<u8>,
        options: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
        _timeout_ms: u32,
    ) -> Result<webauthn_rs_proto::PublicKeyCredential, crate::prelude::WebauthnCError> {
        todo!()
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

        // let ga = GetAssertionRequest {
        //     rp_id: options.rp_id,
        //     client_data_hash,
        //     allow_list: options.allow_credentials,
        //     options: req_options,
        //     pin_uv_auth_param,
        //     pin_uv_auth_proto,
        // };

        // trace!(?ga);
        // let ret = block_on(self.token.transmit(ga, self.ui_callback))?;
        // trace!(?ret);

        // let raw_id = ret
        //     .credential
        //     .as_ref()
        //     .map(|c| c.id.to_owned())
        //     .ok_or(WebauthnCError::Cbor)?;
        // let id = raw_id.to_string();
        // let type_ = ret
        //     .credential
        //     .map(|c| c.type_)
        //     .ok_or(WebauthnCError::Cbor)?;
        // let signature = Base64UrlSafeData(ret.signature.ok_or(WebauthnCError::Cbor)?);
        // let authenticator_data = Base64UrlSafeData(ret.auth_data.ok_or(WebauthnCError::Cbor)?);

        // Ok(PublicKeyCredential {
        //     id,
        //     raw_id,
        //     response: AuthenticatorAssertionResponseRaw {
        //         authenticator_data,
        //         client_data_json: Base64UrlSafeData(vec![]),
        //         signature,
        //         // TODO
        //         user_handle: None,
        //     },
        //     // TODO
        //     extensions: AuthenticationExtensionsClientOutputs::default(),
        //     type_,
        // })
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

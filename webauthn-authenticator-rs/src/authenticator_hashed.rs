use base64urlsafedata::Base64UrlSafeData;
use serde_cbor::ser::to_vec_packed;
use url::Url;
use webauthn_rs_proto::{
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

use crate::{
    error::WebauthnCError,
    util::{compute_sha256, creation_to_clientdata, get_to_clientdata},
    AuthenticatorBackend, ctap2::{commands::{MakeCredentialRequest, MakeCredentialResponse}, CBORResponse},
};

/// This is a variant of [AuthenticatorBackend] which passes a
/// `client_data_hash` rather than doing the hashing itself.
///
/// This is needed to proxy authenticator requests, such as via caBLE. This
/// is similar to Android's [BrowserPublicKeyCredentialCreationOptions][] API.
///
/// [AuthenticatorBackendHashedClientData] provides a [AuthenticatorBackend]
/// implementation – so backends should only implement one of those APIs.
///
/// This API won't work on Windows.
///
/// ## Important
///
/// This API is significantly different from [AuthenticatorBackend] in three
/// ways:
///
/// * these APIs have no `origin` parameter
/// * these APIs ignore the `options.challenge` parameter
/// * these APIs return an empty `client_data_json` value
///
/// [BrowserPublicKeyCredentialCreationOptions]: https://developers.google.com/android/reference/com/google/android/gms/fido/fido2/api/common/BrowserPublicKeyCredentialCreationOptions.Builder
pub trait AuthenticatorBackendHashedClientData {
    fn perform_register(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError>;

    fn perform_auth(
        &mut self,
        client_data_hash: Vec<u8>,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError>;
}

impl<T: AuthenticatorBackendHashedClientData> AuthenticatorBackend for T {
    fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let client_data = creation_to_clientdata(origin, options.challenge.clone());
        let client_data: Vec<u8> = serde_json::to_string(&client_data)
            .map_err(|_| WebauthnCError::Json)?
            .into();
        let client_data_hash = compute_sha256(&client_data).to_vec();
        let mut cred = self.perform_register(client_data_hash, options, timeout_ms)?;
        cred.response.client_data_json = Base64UrlSafeData(client_data);

        Ok(cred)
    }
    fn perform_auth(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        let client_data = get_to_clientdata(origin, options.challenge.clone());
        let client_data: Vec<u8> = serde_json::to_string(&client_data)
            .map_err(|_| WebauthnCError::Json)?
            .into();
        let client_data_hash = compute_sha256(&client_data).to_vec();
        let mut cred = self.perform_auth(client_data_hash, options, timeout_ms)?;
        cred.response.client_data_json = Base64UrlSafeData(client_data);
        todo!()
    }
}

/// This is a [AuthenticatorBackend]-like API, but with CTAP 2.0 message types.
/// 
/// This should only be implemented by [AuthenticatorBackendHashedClientData]
pub trait AuthenticatorBackendWithRequests {
    fn perform_register(&mut self, request: MakeCredentialRequest, timeout_ms: u32) -> Result<Vec<u8>, WebauthnCError>;
}

impl <T: AuthenticatorBackendHashedClientData> AuthenticatorBackendWithRequests for T {
    fn perform_register(&mut self, request: MakeCredentialRequest, timeout_ms: u32) -> Result<Vec<u8>, WebauthnCError> {
        let options = PublicKeyCredentialCreationOptions {
            rp: request.rp,
            user: request.user,
            challenge: Base64UrlSafeData(vec![]),
            pub_key_cred_params: request.pub_key_cred_params,
            timeout: Some(timeout_ms),
            exclude_credentials: Some(request.exclude_list),
            // TODO
            attestation: None,
            authenticator_selection: None,
            extensions: None,
        };
        let client_data_hash = request.client_data_hash;

        let mut cred: RegisterPublicKeyCredential = self.perform_register(client_data_hash, options, timeout_ms)?;

        //<MakeCredentialResponse as CBORResponse>::try_from(cred.response.attestation_object.0.as_slice()).map_err(|_| WebauthnCError::Cbor)
        // TODO: attestation_object is a MakeCredResponse, with string keys rather than int
        // This needs to convert Map<Sring, Value> back into Map<u32, Value>
        // Alternatively there may be a way where this gets plumbed as data
        let resp = serde_cbor::de::from_slice::<MakeCredentialResponse>(cred.response.attestation_object.0.as_slice()).map_err(|_| WebauthnCError::Cbor)?;
        cred.response.attestation_object = Base64UrlSafeData(to_vec_packed(&resp).map_err(|_| WebauthnCError::Cbor)?);

        Ok(cred.response.attestation_object.0)
    }
}

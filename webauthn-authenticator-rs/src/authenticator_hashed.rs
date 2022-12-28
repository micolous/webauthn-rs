use std::collections::BTreeMap;

use base64urlsafedata::Base64UrlSafeData;
use serde_cbor::{ser::to_vec_packed, Value};
use url::Url;
use webauthn_rs_proto::{
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

use crate::{
    ctap2::commands::{MakeCredentialRequest, MakeCredentialResponse},
    error::WebauthnCError,
    util::{compute_sha256, creation_to_clientdata, get_to_clientdata},
    AuthenticatorBackend,
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
/// This API won't work on Windows -- it will always try to hash `client_data`.
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
        Ok(cred)
    }
}

/// This is a [AuthenticatorBackend]-like API, but with CTAP 2.0 message types.
///
/// This should only be implemented by [AuthenticatorBackendHashedClientData]
pub trait AuthenticatorBackendWithRequests {
    fn perform_register(
        &mut self,
        request: MakeCredentialRequest,
        timeout_ms: u32,
    ) -> Result<Vec<u8>, WebauthnCError>;
}

impl<T: AuthenticatorBackendHashedClientData> AuthenticatorBackendWithRequests for T {
    fn perform_register(
        &mut self,
        request: MakeCredentialRequest,
        timeout_ms: u32,
    ) -> Result<Vec<u8>, WebauthnCError> {
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

        let mut cred: RegisterPublicKeyCredential =
            self.perform_register(client_data_hash, options, timeout_ms)?;

        // attestation_object is a MakeCredentialResponse, with string keys
        // rather than u32, we need to convert it.
        let resp: MakeCredentialResponse =
            serde_cbor::de::from_slice(cred.response.attestation_object.0.as_slice())
                .map_err(|_| WebauthnCError::Cbor)?;

        // Write value with u32 keys
        let resp: BTreeMap<u32, Value> = resp.into();
        cred.response.attestation_object =
            Base64UrlSafeData(to_vec_packed(&resp).map_err(|_| WebauthnCError::Cbor)?);

        Ok(cred.response.attestation_object.0)
    }
}

#[cfg(test)]
mod test {
    use openssl::{hash::MessageDigest, rand::rand_bytes, sign::Verifier, x509::X509};
    use webauthn_rs_proto::{PubKeyCredParams, RelyingParty, User};

    use crate::{
        ctap2::{commands::value_to_vec_u8, CBORResponse},
        softtoken::SoftToken,
    };

    use super::*;

    #[test]
    fn perform_register_with_command() {
        let _ = tracing_subscriber::fmt::try_init();
        let (mut soft_token, _) = SoftToken::new().unwrap();
        let mut client_data_hash = vec![0; 32];
        let mut user_id = vec![0; 16];
        rand_bytes(&mut client_data_hash).unwrap();
        rand_bytes(&mut user_id).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: client_data_hash.clone(),
            rp: RelyingParty {
                name: "example.com".to_string(),
                id: "example.com".to_string(),
            },
            user: User {
                id: Base64UrlSafeData(user_id),
                name: "sampleuser".to_string(),
                display_name: "Sample User".to_string(),
            },
            pub_key_cred_params: vec![
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: -7,
                },
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: -257,
                },
            ],
            exclude_list: vec![],
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let response =
            AuthenticatorBackendWithRequests::perform_register(&mut soft_token, request, 10000)
                .unwrap();

        // All keys should be ints
        let m: Value = serde_cbor::from_slice(response.as_slice()).unwrap();
        let m = if let Value::Map(m) = m {
            m
        } else {
            panic!("unexpected type")
        };
        assert!(m.keys().all(|k| if let Value::Integer(_) = k {
            true
        } else {
            false
        }));

        // Try to deserialise the MakeCredentialResponse again
        let response =
            <MakeCredentialResponse as CBORResponse>::try_from(response.as_slice()).unwrap();
        // trace!(?response);

        // Run packed attestation verification
        // https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
        let mut att_stmt = if let Value::Map(m) = response.att_stmt.unwrap() {
            m
        } else {
            panic!("unexpected type");
        };
        let signature = value_to_vec_u8(
            att_stmt.remove(&Value::Text("sig".to_string())).unwrap(),
            "att_stmt.sig",
        )
        .unwrap();

        // Extract attestation certificate
        let x5c = if let Value::Array(v) = att_stmt.remove(&Value::Text("x5c".to_string())).unwrap()
        {
            v
        } else {
            panic!("Unexpected type");
        };
        let x5c = value_to_vec_u8(x5c[0].to_owned(), "x5c[0]").unwrap();
        let verification_cert = X509::from_der(&x5c).unwrap();
        let pubkey = verification_cert.public_key().unwrap();

        // Reconstruct verification data (auth_data + client_data_hash)
        let mut verification_data =
            value_to_vec_u8(response.auth_data.unwrap(), "verification_data").unwrap();
        verification_data.reserve(client_data_hash.len());
        verification_data.extend_from_slice(&client_data_hash);

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey).unwrap();
        assert!(verifier
            .verify_oneshot(&signature, &verification_data)
            .unwrap());
    }
}

use crate::error::WebauthnCError;
use crate::{AuthenticatorBackend, Url};

use base64urlsafedata::Base64UrlSafeData;
use std::collections::BTreeMap;
use std::time::Duration;
use webauthn_rs_proto::{
    PubKeyCredParams, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential, User, CollectedClientData,
};

use openssl::sha;
use windows::core::{GUID, HSTRING, PCWSTR};
use windows::Win32::Foundation::{HWND};
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::System::Console::{GetConsoleTitleW, SetConsoleTitleW};
use windows::Win32::UI::WindowsAndMessaging::FindWindowW;
use std::thread::sleep;

pub struct Win10 {
    rp: WEBAUTHN_RP_ENTITY_INFORMATION,
}

const ID: &'static str = "some-id";
const NAME: &'static str = "webauthn-authenticator-rs";

fn str_to_pcwstr(s: &str) -> PCWSTR {
    let h: HSTRING = s.into();
    (&h).into()
}

impl Default for Win10 {
    fn default() -> Self {
        unsafe {
            println!("WebAuthNGetApiVersionNumber(): {}", WebAuthNGetApiVersionNumber());
            match WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() {
                Ok(v) => println!("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() = {:?}", <_ as Into<bool>>::into(v)),
                Err(e) => println!("error requesting platform authenticator: {:?}", e),
            }
        }

        Self {
            rp: WEBAUTHN_RP_ENTITY_INFORMATION {
                dwVersion: WEBAUTHN_API_CURRENT_VERSION,
                pwszId: str_to_pcwstr(ID),
                pwszName: str_to_pcwstr(NAME),
                pwszIcon: PCWSTR::null(),
            },
        }
    }
}

impl AuthenticatorBackend for Win10 {
    fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let hwnd = get_hwnd();
        let userinfo = creation_to_userinformation(&options.user);
        let mut pubkeycredparams: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> = options
            .pub_key_cred_params
            .iter()
            .map(pubkeycredparams_to_credential_parameter)
            .collect();

        let pubkeycredparams_n = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: pubkeycredparams.len() as u32,
            pCredentialParameters: pubkeycredparams.as_mut_ptr(),
        };

        let clientdata = creation_to_clientdata(origin, options.challenge.clone());
        //  Let clientDataJSON be the JSON-serialized client data constructed from collectedClientData.
        let mut client_data_json =
            serde_json::to_string(&clientdata).map_err(|_| WebauthnCError::Json)?;

        // Let clientDataHash be the hash of the serialized client data represented by clientDataJSON.
        let client_data_json_hash = compute_sha256(client_data_json.as_bytes()).to_vec();

        let clientdata = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data_json.len() as u32,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: str_to_pcwstr(WEBAUTHN_HASH_ALGORITHM_SHA_256),
        };

        let makecredopts = creation_to_makecredopts(&options, timeout_ms);

        println!("WebAuthNAuthenticatorMakeCredential()");
        let result = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                hwnd,
                &self.rp,
                &userinfo,
                &pubkeycredparams_n,
                &clientdata,
                Some(&makecredopts),
            )
        };

        println!("got result from WebAuthNAuthenticatorMakeCredential");
        result.map_err(|e| {
            error!("Error: {:?}", e);
            WebauthnCError::Internal
        } ).map(|a| {
            todo!();
        })
    }

    fn perform_auth(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        todo!();
    }
}

fn get_hwnd() -> HWND {
    let mut old_title: [u16; 1024] = [0; 1024];
    let mut r: [u8; 8] = [0; 8];
    openssl::rand::rand_bytes(&mut r);
    let r = str_to_pcwstr(&format!("{:?}", r));
    
    unsafe {
        let len = GetConsoleTitleW(&mut old_title);
        // println!("Console title: ({}) = {:?}", len, old_title);

        let res = SetConsoleTitleW(r);

        sleep(Duration::from_millis(500));

        let hwnd = FindWindowW(PCWSTR::null(), r);

        SetConsoleTitleW(PCWSTR(old_title.as_ptr()));

        println!("HWND = {:?}", hwnd);
        hwnd
    }
}

fn creation_to_userinformation(user: &User) -> WEBAUTHN_USER_ENTITY_INFORMATION {
    let mut id = user.id.to_string();
    let id_len = id.len();
    let id_ptr = id.as_mut_ptr();
    let name = str_to_pcwstr(&user.name);
    let display_name = str_to_pcwstr(&user.display_name);

    WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: id_len as u32,
        pbId: id_ptr,
        pwszName: name,
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: display_name,
    }
}

fn creation_to_clientdata(origin: Url, challenge: Base64UrlSafeData) -> CollectedClientData {
    CollectedClientData {
        type_: "webauthn.create".to_string(),
        challenge: challenge.clone(),
        origin,
        token_binding: None,
        cross_origin: None,
        unknown_keys: BTreeMap::new(),
    }
}

fn creation_to_makecredopts(
    options: &PublicKeyCredentialCreationOptions, timeout_ms: u32
) -> WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
    // todo!();
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
        dwTimeoutMilliseconds: timeout_ms,
        // TODO
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: 0,
            pCredentials: [].as_mut_ptr(),
        },
        Extensions: WEBAUTHN_EXTENSIONS {
            cExtensions: 0,
            pExtensions: [].as_mut_ptr(),
        },
        dwAuthenticatorAttachment: 0,
        bRequireResidentKey: false.into(),
        dwUserVerificationRequirement: 0,
        dwAttestationConveyancePreference: 0,
        dwFlags: 0,
        pCancellationId: std::ptr::null_mut(),
        pExcludeCredentialList: std::ptr::null_mut(),
        dwEnterpriseAttestation: 0,
        dwLargeBlobSupport: 0,
        bPreferResidentKey: false.into(),

    }
}

fn pubkeycredparams_to_credential_parameter(
    p: &PubKeyCredParams,
) -> WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType: str_to_pcwstr(&p.type_),
        lAlg: p.alg as i32,
    }
}

fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(data);
    hasher.finish()
}

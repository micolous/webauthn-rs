use crate::error::WebauthnCError;
use crate::{AuthenticatorBackend, Url};

use base64urlsafedata::Base64UrlSafeData;
use std::collections::BTreeMap;
use std::time::Duration;
use webauthn_rs_proto::{
    AuthenticatorAttestationResponseRaw, CollectedClientData, PubKeyCredParams,
    PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs, User,
};

use std::thread::sleep;
use windows::core::{GUID, HSTRING, PCWSTR};
use windows::w;
use windows::Win32::Foundation::{GetLastError, HWND};
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::System::Console::{GetConsoleTitleW, GetConsoleWindow, SetConsoleTitleW};
use windows::Win32::UI::WindowsAndMessaging::FindWindowW;

pub struct Win10 {
    rp: WEBAUTHN_RP_ENTITY_INFORMATION,
}

const ID: &'static HSTRING = w!("Id:webauthn-authenticator-rs");
const NAME: &'static HSTRING = w!("Name:webauthn-authenticator-rs");
const SHA_256: &'static HSTRING = w!("SHA-256");

fn str_to_pcwstr(s: &str) -> PCWSTR {
    let h: HSTRING = s.into();
    (&h).into()
}

impl Default for Win10 {
    fn default() -> Self {
        unsafe {
            println!(
                "WebAuthNGetApiVersionNumber(): {}",
                WebAuthNGetApiVersionNumber()
            );
            match WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() {
                Ok(v) => println!(
                    "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable() = {:?}",
                    <_ as Into<bool>>::into(v)
                ),
                Err(e) => println!("error requesting platform authenticator: {:?}", e),
            }
        }

        Self {
            rp: WEBAUTHN_RP_ENTITY_INFORMATION {
                dwVersion: WEBAUTHN_API_CURRENT_VERSION,
                pwszId: ID.into(),
                pwszName: NAME.into(),
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
        let userinfo = WinUserEntityInformation::from(&options.user);
        let pubkeycredparams = WinCoseCredentialParameters::from(&options.pub_key_cred_params);
        let clientdata =
            WinClientData::try_from(&creation_to_clientdata(origin, options.challenge.clone()))?;
        let makecredopts = WinAuthenticatorMakeCredentialOptions::new(&options, timeout_ms);

        println!("WebAuthNAuthenticatorMakeCredential()");
        let result = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                hwnd,
                &self.rp,
                userinfo.as_ref(),
                pubkeycredparams.as_ref(),
                clientdata.as_ref(),
                Some(makecredopts.as_ref()),
            )
            .map(|r| r.as_ref().ok_or(WebauthnCError::Internal))
        };

        println!("got result from WebAuthNAuthenticatorMakeCredential");
        let result = result.map_err(|e| {
            println!("Error: {:?}", e);
            WebauthnCError::Internal
        })?;

        result.map(|a| {
            println!("response data:");
            println!("{:?}", a);

            let c = convert_attestation(a);
            println!("converted:");
            println!("{:?}", c);

            c
        })?
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
    unsafe { GetConsoleWindow() }
    /*
        let mut old_title: [u16; 65536] = [0; 65536];

        // Make a random title to find
        let mut r: [u8; 8] = [0; 8];
        openssl::rand::rand_bytes(&mut r).expect("openssl::rand_bytes");
        let r: HSTRING = (&format!("{:?}", r)).into();

        unsafe {
            let len = GetConsoleTitleW(&mut old_title);
            if len == 0 {
                panic!("GetConsoleTitleW => {:?}", GetLastError());
            }
            // println!("Console title: ({}) = {:?}", len, old_title);

            let res = SetConsoleTitleW(&r);
            if !res.as_bool() {
                panic!("SetConsoleTitleW => {:?}", GetLastError());
            }

            sleep(Duration::from_millis(500));

            let hwnd = FindWindowW(PCWSTR::null(), &r);

            let res = SetConsoleTitleW(PCWSTR(old_title.as_ptr()));
            if !res.as_bool() {
                panic!("SetConsoleTitleW => {:?}", GetLastError());
            }

            println!("HWND = {:?}", hwnd);
            hwnd
        }
    */
}

/// Wrapper for [WEBAUTHN_USER_ENTITY_INFORMATION] to ensure pointer lifetime.
struct WinUserEntityInformation {
    id: String,
    name: HSTRING,
    display_name: HSTRING,
    native: WEBAUTHN_USER_ENTITY_INFORMATION,
}

impl From<&User> for WinUserEntityInformation {
    fn from(u: &User) -> Self {
        let mut id = u.id.to_string();
        let cb_id = id.len() as u32;
        let pb_id = id.as_mut_ptr();
        let name: HSTRING = u.name.clone().into();
        let display_name: HSTRING = u.display_name.clone().into();

        let native = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: cb_id,
            pbId: pb_id,
            pwszName: (&name).into(),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: (&display_name).into(),
        };

        Self {
            id,
            name: name,
            display_name: display_name,
            native,
        }
    }
}

impl AsRef<WEBAUTHN_USER_ENTITY_INFORMATION> for WinUserEntityInformation {
    fn as_ref(&self) -> &WEBAUTHN_USER_ENTITY_INFORMATION {
        &self.native
    }
}

// Wrapper for [WEBAUTHN_CLIENT_DATA] to ensure pointer lifetime.
struct WinClientData {
    client_data_json: String,
    native: WEBAUTHN_CLIENT_DATA,
}

impl TryFrom<&CollectedClientData> for WinClientData {
    type Error = WebauthnCError;
    fn try_from(clientdata: &CollectedClientData) -> Result<Self, Self::Error> {
        //  Let clientDataJSON be the JSON-serialized client data constructed from collectedClientData.
        let mut client_data_json =
            serde_json::to_string(clientdata).map_err(|_| WebauthnCError::Json)?;

        let native = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data_json.len() as u32,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: SHA_256.into(),
        };

        Ok(Self {
            client_data_json,
            native,
        })
    }
}

impl AsRef<WEBAUTHN_CLIENT_DATA> for WinClientData {
    fn as_ref(&self) -> &WEBAUTHN_CLIENT_DATA {
        &self.native
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

struct WinAuthenticatorMakeCredentialOptions {
    native: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
}

impl WinAuthenticatorMakeCredentialOptions {
    fn new(options: &PublicKeyCredentialCreationOptions, timeout_ms: u32) -> Self {
        let native = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
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
        };
        Self { native }
    }
}

impl AsRef<WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS>
    for WinAuthenticatorMakeCredentialOptions
{
    fn as_ref(&self) -> &WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        &self.native
    }
}

/// Wrapper for [WEBAUTHN_COSE_CREDENTIAL_PARAMETER] to ensure pointer lifetime.
struct WinCoseCredentialParameter {
    typ: HSTRING,
    native: WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
}

impl From<&PubKeyCredParams> for WinCoseCredentialParameter {
    fn from(p: &PubKeyCredParams) -> Self {
        let typ: HSTRING = p.type_.clone().into();
        let native = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: (&typ).into(),
            lAlg: p.alg as i32,
        };
        Self { typ, native }
    }
}

struct WinCoseCredentialParameters {
    // params: Vec<WinCoseCredentialParameter>,
    l: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER>,
    native: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
}

impl From<Vec<WinCoseCredentialParameter>> for WinCoseCredentialParameters {
    fn from(params: Vec<WinCoseCredentialParameter>) -> Self {
        let mut l: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> =
            params.iter().map(|p| p.native).collect();

        let native = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: l.len() as u32,
            pCredentialParameters: l.as_mut_ptr() as *mut _,
        };
        Self { l, native }
    }
}

impl From<&Vec<PubKeyCredParams>> for WinCoseCredentialParameters {
    fn from(params: &Vec<PubKeyCredParams>) -> Self {
        let params: Vec<WinCoseCredentialParameter> = params
            .iter()
            .map(WinCoseCredentialParameter::from)
            .collect();
        WinCoseCredentialParameters::from(params)
    }
}

impl AsRef<WEBAUTHN_COSE_CREDENTIAL_PARAMETERS> for WinCoseCredentialParameters {
    fn as_ref(&self) -> &WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        &self.native
    }
}

fn convert_attestation(
    a: &WEBAUTHN_CREDENTIAL_ATTESTATION,
) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
    let cred_id_len = a.cbCredentialId as usize;
    let mut cred_id: Vec<u8> = Vec::with_capacity(cred_id_len);
    unsafe {
        std::ptr::copy(a.pbCredentialId, cred_id.as_mut_ptr(), cred_id_len);
        cred_id.set_len(cred_id_len);
    }

    let id: String = Base64UrlSafeData(cred_id.clone()).to_string();

    Ok(RegisterPublicKeyCredential {
        id: id,
        raw_id: Base64UrlSafeData(cred_id),
        type_: "TODO".into(),
        extensions: RegistrationExtensionsClientOutputs::default(),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData("TODO".into()),
            client_data_json: Base64UrlSafeData("TODO".into()),
            transports: None,
        },
    })
}

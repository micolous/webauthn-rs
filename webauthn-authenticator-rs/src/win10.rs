use crate::error::WebauthnCError;
use crate::{AuthenticatorBackend, Url};

use base64urlsafedata::Base64UrlSafeData;
use std::collections::BTreeMap;
use std::marker::{PhantomData, PhantomPinned};
use std::pin::Pin;
use std::ptr::NonNull;
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
                userinfo.native_ptr(),
                pubkeycredparams.native_ptr(),
                clientdata.native_ptr(),
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

            let c = convert_attestation(a, clientdata.client_data_json.clone());
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
    /* TODO: make this work properly for non-console apps.
     *
     * The Windows WebAuthn APIs expect a HWND to know where to put the FIDO
     * GUI (centred over the calling application window).
     * 
     * GetConsoleWindow() only works with the "native" console, and not virtual
     * terminals: Windows Terminal and VS Code give a valid HWND that has the
     * dialog at the top-left of the screen but *behind* the active window.
     * 
     * Windows' docs suggest an alternative: change the console title to
     * some random value (SetConsoleTitleW), wait a moment, then search for it
     * (FindWindowW):
     * https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/obtain-console-window-handle
     * 
     * This works reliably with Windows Terminal, but not with VS Code. :(
     * 
     * https://github.com/microsoft/terminal/issues/2988
     * https://github.com/microsoft/vscode/issues/42356
     */

    let hwnd = unsafe {
        GetConsoleWindow()
    };
    println!("HWND = {:?}", hwnd);
    if hwnd != HWND(0) {
        return hwnd;
    }

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
}

/// Wrapper for [WEBAUTHN_USER_ENTITY_INFORMATION] to ensure pointer lifetime.
struct WinUserEntityInformation {
    native: WEBAUTHN_USER_ENTITY_INFORMATION,
    _id: String,
    _name: HSTRING,
    _display_name: HSTRING,
    _pin: PhantomPinned,
}

impl WinUserEntityInformation {
    fn from(u: &User) -> Pin<Box<Self>> {
        // Construct an incomplete type first, so that all the pointers are fixed.
        let res = Self {
            native: WEBAUTHN_USER_ENTITY_INFORMATION::default(),
            _id: u.id.clone().to_string(),
            _name: u.name.clone().into(),
            _display_name: u.display_name.clone().into(),
            _pin: PhantomPinned,
        };

        let mut boxed = Box::pin(res);

        // Create the real native type, which contains bare pointers.
        let native = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: boxed._id.len() as u32,
            pbId: boxed._id.as_ptr() as *mut _,
            pwszName: (&boxed._name).into(),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: (&boxed._display_name).into(),
        };

        // Update the boxed type with the proper native object.
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }

    fn native_ptr<'a>(&'a self) -> &'a WEBAUTHN_USER_ENTITY_INFORMATION {
        &self.native
    }
}

// Wrapper for [WEBAUTHN_CLIENT_DATA] to ensure pointer lifetime.
struct WinClientData {
    native: WEBAUTHN_CLIENT_DATA,
    client_data_json: String,
}

impl WinClientData {
    fn try_from(clientdata: &CollectedClientData) -> Result<Pin<Box<Self>>, WebauthnCError> {
        // Construct an incomplete type first, so that all the pointers are fixed.
        let res = Self {
            native: WEBAUTHN_CLIENT_DATA::default(),
            client_data_json:
                serde_json::to_string(clientdata).map_err(|_| WebauthnCError::Json)?,
        };

        let mut boxed = Box::pin(res);

        // Create the real native type, which contains bare pointers.
        let native = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: boxed.client_data_json.len() as u32,
            pbClientDataJSON: boxed.client_data_json.as_ptr() as *mut _,
            pwszHashAlgId: SHA_256.into(),
        };

        // Update the boxed type with the proper native object.
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        Ok(boxed)
    }

    fn native_ptr<'a>(&'a self) -> &'a WEBAUTHN_CLIENT_DATA {
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
    native: WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
    _typ: HSTRING,
}

impl WinCoseCredentialParameter {
    fn from(p: &PubKeyCredParams) -> Pin<Box<Self>> {
        let res = Self {
            native: Default::default(),
            _typ: p.type_.clone().into(),
        };

        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: (&boxed._typ).into(),
            lAlg: p.alg as i32,
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }
}

struct WinCoseCredentialParameters {
    native: WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    _params: Vec<Pin<Box<WinCoseCredentialParameter>>>,
    _l: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER>,
}

impl WinCoseCredentialParameters {
    fn from(params: &Vec<PubKeyCredParams>) -> Pin<Box<Self>> {
        let params: Vec<Pin<Box<WinCoseCredentialParameter>>> = params
            .iter()
            .map(WinCoseCredentialParameter::from)
            .collect();
        WinCoseCredentialParameters::from_wrapped(params)
    }

    fn from_wrapped(params: Vec<Pin<Box<WinCoseCredentialParameter>>>) -> Pin<Box<Self>> {
        // Create the result struct first, so we get stable addresses for _params and _l.
        let len = params.len();
        let res = Self {
            native: Default::default(),
            _l: Vec::with_capacity(len),
            _params: params,
        };

        // Box the struct so it doesn't move.
        let mut boxed = Box::pin(res);

        // Put in all the "native" values
        let p_ptr = boxed._params.as_ptr();
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            let mut l = &mut Pin::get_unchecked_mut(mut_ref)._l;
            let l_ptr = l.as_mut_ptr();
            for i in 0..len {
                *l_ptr.add(i) = (*p_ptr.add(i)).native;
            }
            
            l.set_len(len);
        }

        // let mut l: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> =
        //     params.iter().map(|p| p.native).collect();

        let native = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {            
            cCredentialParameters: boxed._l.len() as u32,
            pCredentialParameters: boxed._l.as_mut_ptr() as *mut _,
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }

    fn native_ptr<'a>(&'a self) -> &'a WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        &self.native
    }

}

fn copy_ptr<T>(cb: u32, pb: *const T) -> Result<Vec<T>, WebauthnCError> where T: Clone {
    if pb.is_null() {
        return Err(WebauthnCError::Internal)
    }
    let mut dst: Vec<T> = Vec::with_capacity(cb as usize);
    unsafe {
        std::ptr::copy(pb, dst.as_mut_ptr(), cb as usize);
        dst.set_len(cb as usize)
    }
    Ok(dst)
}

fn convert_attestation(
    a: &WEBAUTHN_CREDENTIAL_ATTESTATION,
    client_data_json: String,
) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
    let cred_id = copy_ptr(a.cbCredentialId, a.pbCredentialId)?;
    let attesation = copy_ptr(a.cbAttestation, a.pbAttestation)?;
    let type_: String = unsafe { a.pwszFormatType.to_string().unwrap() };

    // let cred_id_len = a.cbCredentialId as usize;
    // let mut cred_id: Vec<u8> = Vec::with_capacity(cred_id_len);
    // unsafe {
    //     std::ptr::copy(a.pbCredentialId, cred_id.as_mut_ptr(), cred_id_len);
    //     cred_id.set_len(cred_id_len);
    // }

    // let attestation_len 

    let id: String = Base64UrlSafeData(cred_id.clone()).to_string();

    Ok(RegisterPublicKeyCredential {
        id,
        raw_id: Base64UrlSafeData(cred_id),
        type_,
        extensions: RegistrationExtensionsClientOutputs::default(),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData(attesation),
            client_data_json: Base64UrlSafeData(client_data_json.into_bytes()),
            transports: None,
        },
    })
}

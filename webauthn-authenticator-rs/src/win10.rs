use crate::error::WebauthnCError;
use crate::{AuthenticatorBackend, Url};

use base64urlsafedata::Base64UrlSafeData;
use std::collections::BTreeMap;
use std::marker::{PhantomData, PhantomPinned};
use std::pin::Pin;
use std::ptr::NonNull;
use std::time::Duration;
use webauthn_rs_proto::{
    AuthenticatorAttachment, AuthenticatorAttestationResponseRaw, AuthenticatorTransport,
    CollectedClientData, PubKeyCredParams, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs, User, UserVerificationPolicy, RelyingParty,
};

use std::thread::sleep;
use windows::core::{GUID, HSTRING, PCWSTR};
use windows::w;
use windows::Win32::Foundation::{GetLastError, HWND};
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::System::Console::{GetConsoleTitleW, GetConsoleWindow, SetConsoleTitleW};
use windows::Win32::UI::WindowsAndMessaging::FindWindowW;

pub struct Win10 {
//    rp: WEBAUTHN_RP_ENTITY_INFORMATION,
}

const ID: &'static HSTRING = w!("Id:webauthn-authenticator-rs");
const NAME: &'static HSTRING = w!("Name:webauthn-authenticator-rs");
const SHA_256: &'static HSTRING = w!("SHA-256");
const CREDENTIAL_TYPE_PUBLIC_KEY: &'static HSTRING = w!("public-key");

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
        let rp = WinRpEntityInformation::from(&options.rp);
        let userinfo = WinUserEntityInformation::from(&options.user);
        let pubkeycredparams = WinCoseCredentialParameters::from(&options.pub_key_cred_params);
        let clientdata =
            WinClientData::try_from(&creation_to_clientdata(origin, options.challenge.clone()))?;
        let makecredopts = WinAuthenticatorMakeCredentialOptions::new(&options, timeout_ms)?;

        println!("WebAuthNAuthenticatorMakeCredential()");
        let result = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                hwnd,
                rp.native_ptr(),
                userinfo.native_ptr(),
                pubkeycredparams.native_ptr(),
                clientdata.native_ptr(),
                Some(makecredopts.native_ptr()),
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

    let hwnd = unsafe { GetConsoleWindow() };
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

/// Wrapper for [WEBAUTHN_RP_ENTITY_INFORMATION] to ensure pointer lifetime.
struct WinRpEntityInformation {
    native: WEBAUTHN_RP_ENTITY_INFORMATION,
    _id: HSTRING,
    _name: HSTRING,
}

impl WinRpEntityInformation {
    fn from(rp: &RelyingParty) -> Pin<Box<Self>> {
        // Construct an incomplete type first, so that all the pointers are fixed.
        let res = Self {
            native: Default::default(),
            _id: rp.id.clone().into(),
            _name: rp.name.clone().into(),
        };

        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_API_CURRENT_VERSION,
            pwszId: (&boxed._id).into(),
            pwszName: (&boxed._name).into(),
            pwszIcon: PCWSTR::null(),
        };

        // Update the boxed type with the proper native object.
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }

    fn native_ptr<'a>(&'a self) -> &'a WEBAUTHN_RP_ENTITY_INFORMATION {
        &self.native
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
            client_data_json: serde_json::to_string(clientdata)
                .map_err(|_| WebauthnCError::Json)?,
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
        challenge,
        origin,
        token_binding: None,
        cross_origin: None,
        unknown_keys: BTreeMap::new(),
    }
}

/// Converts an [AuthenticatiorAttachment] into a value for
/// [WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::dwAuthenticatorAttachment]
fn attachment_to_native(attachment: &Option<AuthenticatorAttachment>) -> u32 {
    match attachment {
        None => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        Some(AuthenticatorAttachment::CrossPlatform) => {
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
        }
        Some(AuthenticatorAttachment::Platform) => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
    }
}

/// Converts a [UserVerificationPolicy] into a value for
/// [WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::dwUserVerificationRequirement]
fn user_verification_to_native(policy: Option<&UserVerificationPolicy>) -> u32 {
    match policy {
        None => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY,
        Some(p) => match p {
            UserVerificationPolicy::Required => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            UserVerificationPolicy::Preferred => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
            UserVerificationPolicy::Discouraged_DO_NOT_USE => {
                WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
            }
        },
    }
}

/// Converts an [AuthenticatorTransport] into a value for
/// [WEBAUTHN_CREDENTIAL_EX::dwTransports]
fn transport_to_native(transport: &AuthenticatorTransport) -> u32 {
    match transport {
        AuthenticatorTransport::Ble => WEBAUTHN_CTAP_TRANSPORT_BLE,
        AuthenticatorTransport::Internal => WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
        AuthenticatorTransport::Nfc => WEBAUTHN_CTAP_TRANSPORT_NFC,
        AuthenticatorTransport::Usb => WEBAUTHN_CTAP_TRANSPORT_USB,
    }
}

/// Converts a bitmask of native transports into [AuthenticatorTransport].
fn native_to_transports(t: &u32) -> Vec<AuthenticatorTransport> {
    let mut o: Vec<AuthenticatorTransport> = Vec::new();
    if t & WEBAUTHN_CTAP_TRANSPORT_BLE == WEBAUTHN_CTAP_TRANSPORT_BLE {
        o.push(AuthenticatorTransport::Ble);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_INTERNAL == WEBAUTHN_CTAP_TRANSPORT_INTERNAL {
        o.push(AuthenticatorTransport::Internal);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_NFC == WEBAUTHN_CTAP_TRANSPORT_NFC {
        o.push(AuthenticatorTransport::Nfc);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_USB == WEBAUTHN_CTAP_TRANSPORT_USB {
        o.push(AuthenticatorTransport::Usb);
    }
    o
}

/// Converts a [Vec<AuthenticatorTransport>] into a value for
/// [WEBAUTHN_CREDENTIAL_EX::dwTransports]
fn transports_to_bitmask(transports: &Option<Vec<AuthenticatorTransport>>) -> u32 {
    match transports {
        None => 0,
        Some(transports) => transports.into_iter().map(transport_to_native).sum(),
    }
}

struct WinCredentialList {
    /// Native structure, which points to everything else here.
    native: WEBAUTHN_CREDENTIAL_LIST,
    /// Pointer to _l, because [WEBAUTHN_CREDENTIAL_LIST::ppCredentials] is a double-pointer.
    _p: *const WEBAUTHN_CREDENTIAL_EX,
    /// List of credentials
    _l: Vec<WEBAUTHN_CREDENTIAL_EX>,
    /// List of credential IDs, referenced by [WEBAUTHN_CREDENTIAL_EX::pbId]
    _ids: Vec<String>,
}

impl WinCredentialList {
    fn try_from(
        credentials: &Option<Vec<PublicKeyCredentialDescriptor>>,
    ) -> Result<Option<Pin<Box<Self>>>, WebauthnCError> {
        let credentials = match credentials {
            None => return Ok(None),
            Some(c) => c,
        };
        if credentials.is_empty() {
            return Ok(None);
        }

        // Check that all the credential types are supported.
        for c in credentials.iter() {
            if c.type_ != "public-key".to_string() {
                println!("Unsupported credential type: {:?}", c);
                return Err(WebauthnCError::Internal);
            }
        }

        let len = credentials.len();
        let res = Self {
            native: Default::default(),
            _p: std::ptr::null(),
            _l: Vec::with_capacity(len),
            _ids: credentials
                .iter()
                .map(|c| c.id.clone().to_string())
                .collect(),
        };

        // Box the struct so it doesn't move.
        let mut boxed = Box::pin(res);
        let id_ptr = boxed._ids.as_ptr();

        // Put in all the "native" values
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            let l = &mut Pin::get_unchecked_mut(mut_ref)._l;
            let l_ptr = l.as_mut_ptr();
            for i in 0..len {
                let id = id_ptr.add(i);
                *l_ptr.add(i) = WEBAUTHN_CREDENTIAL_EX {
                    dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                    cbId: (*id).len() as u32,
                    pbId: id as *mut _,
                    // TODO: support more than public-key
                    pwszCredentialType: CREDENTIAL_TYPE_PUBLIC_KEY.into(),
                    dwTransports: transports_to_bitmask(&credentials[i].transports),
                };
            }

            l.set_len(len);
        }

        // Add a pointer to the pointer...
        let p = boxed._l.as_ptr();
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref)._p = p;
        }

        let native = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: len as u32,
            ppCredentials: std::ptr::addr_of!(boxed._p) as *mut *mut _,
        };

        // Drop in the native struct
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }
        trace!(?boxed.native);

        Ok(Some(boxed))
    }
}

struct WinAuthenticatorMakeCredentialOptions {
    native: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    _exclude_credentials: Option<Pin<Box<WinCredentialList>>>,
}

impl WinAuthenticatorMakeCredentialOptions {
    fn new(
        options: &PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let exclude_credentials = WinCredentialList::try_from(&options.exclude_credentials)?;

        let res = Self {
            native: Default::default(),
            _exclude_credentials: exclude_credentials,
        };

        // Box the struct so it doesn't move.
        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: timeout_ms,
            // Superceded by pExcludeCredentialList for v3
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: [].as_mut_ptr(),
            },
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: 0,
                pExtensions: [].as_mut_ptr(),
            },
            dwAuthenticatorAttachment: attachment_to_native(
                &options
                    .authenticator_selection
                    .as_ref()
                    .map(|s| &s.authenticator_attachment)
                    .unwrap_or(&None),
            ),
            bRequireResidentKey: options
                .authenticator_selection
                .as_ref()
                .map(|s| s.require_resident_key)
                .unwrap_or(false)
                .into(),
            dwUserVerificationRequirement: user_verification_to_native(
                options
                    .authenticator_selection
                    .as_ref()
                    .map(|s| &s.user_verification),
            ),
            dwAttestationConveyancePreference: 0,
            dwFlags: 0,
            pCancellationId: std::ptr::null_mut(),
            pExcludeCredentialList: match &boxed._exclude_credentials {
                None => std::ptr::null_mut(),
                Some(l) => std::ptr::addr_of!(l.native) as *mut _,
            },
            dwEnterpriseAttestation: 0,
            dwLargeBlobSupport: 0,
            bPreferResidentKey: false.into(),
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        trace!(?boxed.native);

        Ok(boxed)
    }

    fn native_ptr<'a>(&'a self) -> &'a WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
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
            let l = &mut Pin::get_unchecked_mut(mut_ref)._l;
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

fn copy_ptr<T>(cb: u32, pb: *const T) -> Result<Vec<T>, WebauthnCError>
where
    T: Clone,
{
    if pb.is_null() {
        return Err(WebauthnCError::Internal);
    }
    let mut dst: Vec<T> = Vec::with_capacity(cb as usize);
    unsafe {
        std::ptr::copy(pb, dst.as_mut_ptr(), cb as usize);
        dst.set_len(cb as usize)
    }
    Ok(dst)
}

/// Convert return from [WebAuthNAuthenticatorMakeCredential] into
/// [RegisterPublicKeyCredential]
fn convert_attestation(
    a: &WEBAUTHN_CREDENTIAL_ATTESTATION,
    client_data_json: String,
) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
    let cred_id = copy_ptr(a.cbCredentialId, a.pbCredentialId)?;
    let attesation_object = copy_ptr(a.cbAttestationObject, a.pbAttestationObject)?;
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
            attestation_object: Base64UrlSafeData(attesation_object),
            client_data_json: Base64UrlSafeData(client_data_json.into_bytes()),
            transports: Some(native_to_transports(&a.dwUsedTransport)),
        },
    })
}

//! Bindings for Windows 10 Webauthn API
//!
//! This API is available in Windows 10 bulid 1903 and later.
//!
//! API docs:
//!
//! * [MSDN: WebAuthn](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/)
//! * [webauthn.h](github.com/microsoft/webauthn) (describes versions)
use crate::error::WebauthnCError;
use crate::{AuthenticatorBackend, Url};

use base64urlsafedata::Base64UrlSafeData;
use std::collections::BTreeMap;
use std::marker::{PhantomData, PhantomPinned};
use std::ops::Deref;
use std::pin::Pin;
use std::thread::sleep;
use std::time::Duration;
use webauthn_rs_proto::{
    AllowCredentials, AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw,
    AuthenticatorAttachment, AuthenticatorAttestationResponseRaw, AuthenticatorTransport,
    CollectedClientData, PubKeyCredParams, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs, RelyingParty, User, UserVerificationPolicy,
};

use windows::{
    core::{HSTRING, PCWSTR},
    w,
    Win32::{
        Foundation::{BOOL, GetLastError, HWND},
        Networking::WindowsWebServices::*,
        System::Console::{GetConsoleTitleW, GetConsoleWindow, SetConsoleTitleW},
        UI::WindowsAndMessaging::FindWindowW,
    },
};

pub struct Win10 {}

// Most constants are `&str`, but APIs expect `HSTRING`... there's no good work-around.
// https://github.com/microsoft/windows-rs/issues/2049
/// [WEBAUTHN_HASH_ALGORITHM_SHA_256]
const SHA_256: &HSTRING = w!("SHA-256");
/// [WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY]
const CREDENTIAL_TYPE_PUBLIC_KEY: &HSTRING = w!("public-key");

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

        Self {}
    }
}

/// Smart pointer type to auto-[Drop] bare pointers we got from Windows' API,
/// establishing a strict lifetime for data that we need to tell Windows to
/// free.
///
/// All fields of this struct are considered private.
struct WinPtr<'a, T: 'a> {
    _free: unsafe fn(*const T) -> (),
    _ptr: *const T,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T> WinPtr<'a, T> {
    /// Creates a wrapper around a `*const T` Pointer to automatically call its
    /// `free` function when this struct is dropped.
    ///
    /// Returns `None` if `ptr` is null.
    unsafe fn new(ptr: *const T, free: unsafe fn(*const T) -> ()) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            // println!("new_ptr: r={:?}", ptr);
            Some(Self {
                _free: free,
                _ptr: ptr,
                _phantom: PhantomData,
            })
        }
    }
}

impl<'a, T> Deref for WinPtr<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // This is as safe as we can, because we null-checked in `new()` and
        // this type is immutable.
        unsafe { &(*self._ptr) }
    }
}

impl<'a, T> Drop for WinPtr<'a, T> {
    fn drop(&mut self) {
        // println!("free_ptr: r={:?}, {:?}", self._raw, std::ptr::addr_of!(self._ptr));
        unsafe { (self._free)(self._ptr) }
    }
}

impl AuthenticatorBackend for Win10 {
    /// Perform a registration action using Windows WebAuth API.
    ///
    /// This wraps [WebAuthNAuthenticatorMakeCredential].
    ///
    /// [WebAuthnAuthenticatorMakeCredential]: https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatormakecredential
    fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        let hwnd = get_hwnd().ok_or(WebauthnCError::CannotFindHWND)?;
        let rp = WinRpEntityInformation::from(&options.rp);
        let userinfo = WinUserEntityInformation::from(&options.user);
        let pubkeycredparams = WinCoseCredentialParameters::from(&options.pub_key_cred_params);
        let clientdata =
            WinClientData::try_from(&creation_to_clientdata(origin, options.challenge.clone()))?;
        let makecredopts = WinAuthenticatorMakeCredentialOptions::new(&options, timeout_ms)?;

        println!("WebAuthNAuthenticatorMakeCredential()");
        let native_result = unsafe {
            let r = WebAuthNAuthenticatorMakeCredential(
                hwnd,
                rp.native_ptr(),
                userinfo.native_ptr(),
                pubkeycredparams.native_ptr(),
                clientdata.native_ptr(),
                Some(makecredopts.native_ptr()),
            )
            .map_err(|e| {
                // TODO: map error codes, if we learn them...
                error!("Error: {:?}", e);
                WebauthnCError::Internal
            })?;

            WinPtr::new(r, |a| WebAuthNFreeCredentialAttestation(Some(a)))
                .ok_or(WebauthnCError::Internal)?
        };

        println!("got result from WebAuthNAuthenticatorMakeCredential");

        convert_attestation(&native_result, &clientdata.client_data_json)
        // println!("converted:");
        // println!("{:?}", c);
        // c
    }

    /// Perform an authentication action using Windows WebAuth API.
    ///
    /// This wraps [WebAuthNAuthenticatorGetAssertion].
    ///
    /// [WebAuthNAuthenticatorGetAssertion]: https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion
    fn perform_auth(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        trace!(?options);
        let hwnd = get_hwnd().ok_or(WebauthnCError::CannotFindHWND)?;
        let rp_id: HSTRING = options.rp_id.clone().into();
        let clientdata =
            WinClientData::try_from(&get_to_clientdata(origin, options.challenge.clone()))?;
        let getassertopts = WinAuthenticatorGetAssertionOptions::new(&options, timeout_ms)?;
        // WebAuthNAuthenticatorGetAssertion
        println!("WebAuthNAuthenticatorGetAssertion()");
        let native_result = unsafe {
            let r = WebAuthNAuthenticatorGetAssertion(
                hwnd,
                &rp_id,
                clientdata.native_ptr(),
                Some(getassertopts.native_ptr()),
            )
            .map_err(|e| {
                // TODO: map error codes, if we learn them...
                error!("Error: {:?}", e);
                WebauthnCError::Internal
            })?;

            WinPtr::new(r, WebAuthNFreeAssertion).ok_or(WebauthnCError::Internal)?
        };

        println!("got result from WebAuthNAuthenticatorGetAssertion");
        convert_assertion(
            &native_result,
            &clientdata.client_data_json,
            getassertopts.app_id_used.into(),
        )
        // println!("converted:");
        // println!("{:?}", c);

        // c
    }
}

/// Try to find the [HWND] for the current application.
///
/// Returns [None] if we couldn't find it.
///
/// **TODO:** make this work properly for non-console apps.
///
/// The Windows WebAuthn APIs expect a HWND to know where to put the FIDO
/// GUI (centred over the calling application window).
///
/// `GetConsoleWindow()` only works with the "native" console, and not virtual
/// terminals, which is a bug: [Windows Terminal][terminal] and [VS Code][vscode]
/// give a valid HWND that has the dialog at the top-left of the screen (probably
/// conhost?), rather rather than centred over the terminal, and don't change
/// focus properly. VS Code also [doesn't propagate z-order changes][vscode],
/// so the dialog appears behind. Windows Terminal [fixed that bug][terminal],
/// but it still does weird things to <kbd>Alt</kbd> + <kbd>Tab</kbd>.
///
/// [Windows' docs suggest an alternative][hack]: change the console title to
/// some random value (`SetConsoleTitleW`), wait a moment, then search for it
/// (`FindWindowW`). However, that only works with Windows Terminal, so
/// VS Code is still stuck with the dialog opening in the background.
///
/// [hack]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/obtain-console-window-handle
/// [terminal]: https://github.com/microsoft/terminal/issues/2988
/// [vscode]: https://github.com/microsoft/vscode/issues/42356
fn get_hwnd() -> Option<HWND> {
    let chwnd = unsafe { GetConsoleWindow() };
    trace!("GetConsoleWindow HWND = {:?}", chwnd);

    let chwnd = if chwnd == HWND(0) { None } else { Some(chwnd) };
    let mut old_title: [u16; 65536] = [0; 65536];

    // Make a random title to find
    let mut r: [u8; 8] = [0; 8];
    openssl::rand::rand_bytes(&mut r).expect("openssl::rand_bytes");
    let r: HSTRING = (&format!("{:?}", r)).into();

    unsafe {
        let len = GetConsoleTitleW(&mut old_title);
        if len == 0 {
            error!("GetConsoleTitleW => {:?}", GetLastError());
            return chwnd;
        }
        // println!("Console title: ({}) = {:?}", len, old_title);

        let res = SetConsoleTitleW(&r);
        if !res.as_bool() {
            error!("SetConsoleTitleW => {:?}", GetLastError());
            return chwnd;
        }

        sleep(Duration::from_millis(500));

        let hwnd = FindWindowW(PCWSTR::null(), &r);

        let res = SetConsoleTitleW(PCWSTR(old_title.as_ptr()));
        if !res.as_bool() {
            error!("SetConsoleTitleW => {:?}", GetLastError());
        }

        trace!("FindWindowW HWND = {:?}", hwnd);
        if hwnd != HWND(0) {
            Some(hwnd)
        } else {
            chwnd
        }
    }
}

/// Wrapper for [WEBAUTHN_RP_ENTITY_INFORMATION] to ensure pointer lifetime.
struct WinRpEntityInformation {
    native: WEBAUTHN_RP_ENTITY_INFORMATION,
    _id: HSTRING,
    _name: HSTRING,
    _icon: Option<HSTRING>,
}

impl WinRpEntityInformation {
    fn from(rp: &RelyingParty) -> Pin<Box<Self>> {
        // Construct an incomplete type first, so that all the pointers are fixed.
        let res = Self {
            native: Default::default(),
            _id: rp.id.clone().into(),
            _name: rp.name.clone().into(),
            _icon: rp.icon.as_ref().map(|i| i.clone().as_ref().into()),
        };

        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_API_CURRENT_VERSION,
            pwszId: (&boxed._id).into(),
            pwszName: (&boxed._name).into(),
            pwszIcon: boxed._icon.as_ref().map_or(PCWSTR::null(), |i| i.into()),
        };

        // Update the boxed type with the proper native object.
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }

    fn native_ptr(&self) -> &WEBAUTHN_RP_ENTITY_INFORMATION {
        &self.native
    }
}

/// Wrapper for [WEBAUTHN_USER_ENTITY_INFORMATION] to ensure pointer lifetime, analgous to [User].
struct WinUserEntityInformation {
    native: WEBAUTHN_USER_ENTITY_INFORMATION,
    _id: String,
    _name: HSTRING,
    _display_name: HSTRING,
    _icon: Option<HSTRING>,
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
            _icon: u.icon.as_ref().map(|i| i.clone().as_ref().into()),
            _pin: PhantomPinned,
        };

        let mut boxed = Box::pin(res);

        // Create the real native type, which contains bare pointers.
        let native = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: boxed._id.len() as u32,
            pbId: boxed._id.as_ptr() as *mut _,
            pwszName: (&boxed._name).into(),
            pwszIcon: boxed._icon.as_ref().map_or(PCWSTR::null(), |i| i.into()),
            pwszDisplayName: (&boxed._display_name).into(),
        };

        // Update the boxed type with the proper native object.
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }

    fn native_ptr(&self) -> &WEBAUTHN_USER_ENTITY_INFORMATION {
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

    fn native_ptr(&self) -> *const WEBAUTHN_CLIENT_DATA {
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

fn get_to_clientdata(origin: Url, challenge: Base64UrlSafeData) -> CollectedClientData {
    CollectedClientData {
        type_: "webauthn.get".to_string(),
        challenge,
        origin,
        token_binding: None,
        cross_origin: None,
        unknown_keys: BTreeMap::new(),
    }
}

/// Converts an [AuthenticatorAttachment] into a value for
/// [WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::dwAuthenticatorAttachment]
fn attachment_to_native(attachment: Option<AuthenticatorAttachment>) -> u32 {
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
        AuthenticatorTransport::Test => WEBAUTHN_CTAP_TRANSPORT_TEST,
        AuthenticatorTransport::Usb => WEBAUTHN_CTAP_TRANSPORT_USB,
    }
}

/// Converts a bitmask of native transports into [AuthenticatorTransport].
fn native_to_transports(t: u32) -> Vec<AuthenticatorTransport> {
    let mut o: Vec<AuthenticatorTransport> = Vec::new();
    if t & WEBAUTHN_CTAP_TRANSPORT_BLE != 0 {
        o.push(AuthenticatorTransport::Ble);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_INTERNAL != 0 {
        o.push(AuthenticatorTransport::Internal);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_NFC != 0 {
        o.push(AuthenticatorTransport::Nfc);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_TEST != 0 {
        o.push(AuthenticatorTransport::Test);
    }
    if t & WEBAUTHN_CTAP_TRANSPORT_USB != 0 {
        o.push(AuthenticatorTransport::Usb);
    }
    o
}

/// Converts a [Vec<AuthenticatorTransport>] into a value for
/// [WEBAUTHN_CREDENTIAL_EX::dwTransports]
fn transports_to_bitmask(transports: &Option<Vec<AuthenticatorTransport>>) -> u32 {
    match transports {
        None => 0,
        Some(transports) => transports.iter().map(transport_to_native).sum(),
    }
}

/// Wrapper for [WEBAUTHN_CREDENTIAL_LIST] to ensure pointer lifetime, analogous to
/// [PublicKeyCredentialDescriptor] and [AllowCredentials].
struct WinCredentialList {
    /// Native structure, which points to everything else here.
    native: WEBAUTHN_CREDENTIAL_LIST,
    /// Pointer to _l, because [WEBAUTHN_CREDENTIAL_LIST::ppCredentials] is a double-pointer.
    _p: *const WEBAUTHN_CREDENTIAL_EX,
    /// List of credentials
    _l: Vec<WEBAUTHN_CREDENTIAL_EX>,
    /// List of credential IDs, referenced by [WEBAUTHN_CREDENTIAL_EX::pbId]
    _ids: Vec<Base64UrlSafeData>,
}

/// Trait to make [PublicKeyCredentialDescriptor] and [AllowCredentials] look the same.
trait CredentialType {
    fn type_(&self) -> String;
    fn id(&self) -> Base64UrlSafeData;
    fn transports(&self) -> u32;
}

impl CredentialType for PublicKeyCredentialDescriptor {
    fn type_(&self) -> String {
        self.type_.clone()
    }
    fn id(&self) -> Base64UrlSafeData {
        self.id.clone()
    }
    fn transports(&self) -> u32 {
        transports_to_bitmask(&self.transports)
    }
}

impl CredentialType for AllowCredentials {
    fn type_(&self) -> String {
        self.type_.clone()
    }
    fn id(&self) -> Base64UrlSafeData {
        self.id.clone()
    }
    fn transports(&self) -> u32 {
        transports_to_bitmask(&self.transports)
    }
}

impl WinCredentialList {
    fn try_from<T: CredentialType + std::fmt::Debug>(
        credentials: Option<&Vec<T>>,
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
            let typ = c.type_();
            if typ != *"public-key" {
                println!("Unsupported credential type: {:?}", c);
                return Err(WebauthnCError::Internal);
            }
        }

        let len = credentials.len();
        let res = Self {
            native: Default::default(),
            _p: std::ptr::null(),
            _l: Vec::with_capacity(len),
            _ids: credentials.iter().map(|c| c.id()).collect(),
        };

        // Box the struct so it doesn't move.
        let mut boxed = Box::pin(res);

        // Put in all the "native" values
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            let mut_ptr = Pin::get_unchecked_mut(mut_ref);
            let l = &mut mut_ptr._l;
            let l_ptr = l.as_mut_ptr();
            for (i, credential) in credentials.iter().enumerate() {
                let id = &mut mut_ptr._ids[i];
                *l_ptr.add(i) = WEBAUTHN_CREDENTIAL_EX {
                    dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                    cbId: id.0.len() as u32,
                    pbId: id.0.as_mut_ptr() as *mut _,
                    // TODO: support more than public-key
                    pwszCredentialType: CREDENTIAL_TYPE_PUBLIC_KEY.into(),
                    dwTransports: credential.transports(),
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
            ppCredentials: std::ptr::addr_of_mut!(boxed._p) as *mut *mut _,
        };

        // Drop in the native struct
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }
        trace!(?boxed.native);
        // unsafe {
        //     let pp = (**boxed.native.ppCredentials) as WEBAUTHN_CREDENTIAL_EX;
        //     trace!("ppCred = {:?}", pp);
        //     trace!("ppCred.type = {:?}", pp.pwszCredentialType.to_string());
        //     let v = copy_ptr(pp.cbId, pp.pbId);
        //     trace!("ppCred.id = {:?}", v);
        // }

        Ok(Some(boxed))
    }
}

/// Wrapper for [WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS] to ensure
/// pointer lifetime, analogous to [PublicKeyCredentialCreationOptions].
struct WinAuthenticatorMakeCredentialOptions {
    native: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    _exclude_credentials: Option<Pin<Box<WinCredentialList>>>,
}

impl WinAuthenticatorMakeCredentialOptions {
    fn new(
        options: &PublicKeyCredentialCreationOptions,
        timeout_ms: u32,
    ) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let exclude_credentials =
            WinCredentialList::try_from(options.exclude_credentials.as_ref())?;

        let res = Self {
            native: Default::default(),
            _exclude_credentials: exclude_credentials,
        };

        // Box the struct so it doesn't move.
        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: timeout_ms,
            // Superceded by pExcludeCredentialList for v3 (API v1, baseline)
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: [].as_mut_ptr(),
            },
            // TODO
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: 0,
                pExtensions: [].as_mut_ptr(),
            },
            dwAuthenticatorAttachment: attachment_to_native(
                options
                    .authenticator_selection
                    .as_ref()
                    .map(|s| s.authenticator_attachment)
                    .unwrap_or(None),
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

    fn native_ptr(&self) -> &WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        &self.native
    }
}

/// Wrapper for [WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS] to ensure pointer lifetime.
///
/// <https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_authenticator_get_assertion_options>
struct WinAuthenticatorGetAssertionOptions {
    native: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    _allow_credentials: Option<Pin<Box<WinCredentialList>>>,
    _app_id: Option<HSTRING>,

    /// Used as a *return* value from GetAssertion as to whether the U2F AppId was used,
    /// equivalent to [AuthenticationExtensionsClientOutputs::appid].
    ///
    /// Why here? Because for some reason, Windows' API decides to put a pointer for
    /// mutable *return* value inside an `_In_opt_ *const ptr` *request* value
    /// ([WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS]): `pbU2fAppId`.
    ///
    /// The documentation was very opaque here, but [Firefox's implementation][ffx]
    /// appears to correctly deal with this nonsense.
    ///
    /// However, [Chromium's implementation][chr] appears to have misunderstood this field,
    /// and always passes in pointers to `static BOOL` values `kUseAppIdTrue` or
    /// `kUseAppIdFalse` (depending on whether the extension was present) and doesn't read
    /// the response.
    ///
    /// Unfortunately, it looks like the WebAuthn API has been frozen for Windows 10, and
    /// the new revisions are only on Windows 11. So it's unlikely this will ever be
    /// properly fixed. 🙃
    ///
    /// [chr]: https://chromium.googlesource.com/chromium/src/+/f62b8f341c14be84c6c995133f485d76a58de090/device/fido/win/webauthn_api.cc#520
    /// [ffx]: https://github.com/mozilla/gecko-dev/blob/620490a051a1fc72563e1c6bbecfe7346122a6bc/dom/webauthn/WinWebAuthnManager.cpp#L714-L716
    app_id_used: BOOL,
}

impl WinAuthenticatorGetAssertionOptions {
    fn new(
        options: &PublicKeyCredentialRequestOptions,
        timeout_ms: u32,
    ) -> Result<Pin<Box<Self>>, WebauthnCError> {
        let allow_credentials = WinCredentialList::try_from(Some(&options.allow_credentials))?;

        let res = Self {
            native: Default::default(),
            _allow_credentials: allow_credentials,
            _app_id: options
                .extensions
                .as_ref()
                .map(|e| e.appid.as_ref().map(|a| a.clone().into()))
                .flatten(),
            app_id_used: false.into(),
        };

        // Box the struct so it doesn't move.
        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: timeout_ms,
            // Supersceded by pAllowCredentialList in v4 (API v1, baseline)
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: [].as_mut_ptr(),
            },
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: 0,
                pExtensions: [].as_mut_ptr(),
            },
            dwAuthenticatorAttachment: 0, // Not supported?
            dwUserVerificationRequirement: user_verification_to_native(Some(
                &options.user_verification,
            )),
            dwFlags: 0,
            pwszU2fAppId: match &boxed._app_id {
                None => PCWSTR::null(),
                Some(l) => l.into(),
            },
            pbU2fAppId: std::ptr::addr_of_mut!(boxed.app_id_used),
            pCancellationId: std::ptr::null_mut(),
            pAllowCredentialList: match &boxed._allow_credentials {
                None => std::ptr::null_mut(),
                Some(l) => std::ptr::addr_of!(l.native) as *mut _,
            },
            dwCredLargeBlobOperation: 0,
            cbCredLargeBlob: 0,
            pbCredLargeBlob: std::ptr::null_mut(),
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        trace!(?boxed.native);

        Ok(boxed)
    }

    fn native_ptr(&self) -> &WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
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
    fn from(params: &[PubKeyCredParams]) -> Pin<Box<Self>> {
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

    fn native_ptr(&self) -> &WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        &self.native
    }
}

// const WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET: &HSTRING = w!("hmac-secret");
// const WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT: &HSTRING = w!("credProtect");

enum WinExtensionMakeCredentialRequest {
    HmacSecret(BOOL),
    CredProtect(WEBAUTHN_CRED_PROTECT_EXTENSION_IN),
    CredBlob(WEBAUTHN_CRED_BLOB_EXTENSION),
    MinPinLength(BOOL),
}

struct WinExtensionRequest {
    native: WEBAUTHN_EXTENSION,
    _id: HSTRING,
    _e: WinExtensionMakeCredentialRequest,
}

impl WinExtensionRequest {
    fn new(e: WinExtensionMakeCredentialRequest) -> Pin<Box<Self>> {
        let id = match e {
            WinExtensionMakeCredentialRequest::CredBlob(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB,
            _ => todo!(),
        };

        let res = WinExtensionRequest {
            native: Default::default(),
            _id: id.clone().into(),
            _e: e,
        };

        // Box the struct so it doesn't move.
        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: (&boxed._id).into(),
            cbExtension: std::mem::size_of_val(&boxed._e) as u32,
            pvExtension: std::ptr::addr_of!(boxed._e) as *mut _,
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        boxed
    }
}

enum WinExtensionMakeCredentialResponse {
    HmacSecret(bool),
    CredProtect(u32),
    CredBlob(bool),
    MinPinLength(u32),
}

fn read_extension<'a, T: 'a, U: From<&'a T>>(e: &'a WEBAUTHN_EXTENSION) -> Result<U, WebauthnCError> {
    if (e.cbExtension as usize) < std::mem::size_of::<T>() {
        return Err(WebauthnCError::Internal);
    }
    let v = unsafe { (e.pvExtension as *mut T).as_ref() }.ok_or(WebauthnCError::Internal)?;
    Ok(v.into())
}

fn read_extension2<'a, T: 'a + Clone>(e: &'a WEBAUTHN_EXTENSION) -> Result<T, WebauthnCError> {
    if (e.cbExtension as usize) < std::mem::size_of::<T>() {
        return Err(WebauthnCError::Internal);
    }
    let v = unsafe { (e.pvExtension as *mut T).as_ref() }.ok_or(WebauthnCError::Internal)?;
    Ok(v.clone())
}

impl TryFrom<WEBAUTHN_EXTENSION> for WinExtensionMakeCredentialResponse {
    type Error = WebauthnCError;
    fn try_from(e: WEBAUTHN_EXTENSION) -> Result<Self, WebauthnCError> {
        let id = unsafe { e.pwszExtensionIdentifier.to_string().map_err(|_| WebauthnCError::Internal)? };
        // let id = &HSTRING::from_wide(unsafe { e.pwszExtensionIdentifier.as_wide() });
        match id.as_str() {
            WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET => {
                return read_extension::<'_, BOOL, _>(&e).map(WinExtensionMakeCredentialResponse::HmacSecret);
            },
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT => {
                return read_extension2(&e).map(WinExtensionMakeCredentialResponse::CredProtect);
            }
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB=> {
                return read_extension::<'_, BOOL, _>(&e).map(WinExtensionMakeCredentialResponse::CredBlob);
            }
            WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH => {
                return read_extension2(&e).map(WinExtensionMakeCredentialResponse::MinPinLength);
            }
            _ => todo!(),
        }
    }
}

enum WinExtensionGetAssertionResponse {
    CredBlob(Vec<u8>),
}

fn copy_ptr<T>(cb: u32, pb: *const T) -> Option<Vec<T>>
where
    T: Clone,
{
    if pb.is_null() || cb == 0 {
        return None;
    }
    let mut dst: Vec<T> = Vec::with_capacity(cb as usize);
    unsafe {
        std::ptr::copy(pb, dst.as_mut_ptr(), cb as usize);
        dst.set_len(cb as usize)
    }
    Some(dst)
}

/// Convert return from [WebAuthNAuthenticatorMakeCredential] into
/// [RegisterPublicKeyCredential]
fn convert_attestation(
    a: &WEBAUTHN_CREDENTIAL_ATTESTATION,
    client_data_json: &String,
) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
    let cred_id = copy_ptr(a.cbCredentialId, a.pbCredentialId).ok_or(WebauthnCError::Internal)?;
    let attesation_object =
        copy_ptr(a.cbAttestationObject, a.pbAttestationObject).ok_or(WebauthnCError::Internal)?;
    let type_: String = unsafe {
        a.pwszFormatType
            .to_string()
            .map_err(|_| WebauthnCError::Internal)?
    };

    let id: String = Base64UrlSafeData(cred_id.clone()).to_string();

    Ok(RegisterPublicKeyCredential {
        id,
        raw_id: Base64UrlSafeData(cred_id),
        type_,
        extensions: RegistrationExtensionsClientOutputs::default(),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData(attesation_object),
            client_data_json: Base64UrlSafeData(client_data_json.as_bytes().to_vec()),
            transports: Some(native_to_transports(a.dwUsedTransport)),
        },
    })
}

fn convert_assertion(
    a: &WEBAUTHN_ASSERTION,
    client_data_json: &String,
    app_id_used: bool,
) -> Result<PublicKeyCredential, WebauthnCError> {
    let user_id = copy_ptr(a.cbUserId, a.pbUserId);
    let authenticator_data =
        copy_ptr(a.cbAuthenticatorData, a.pbAuthenticatorData).ok_or(WebauthnCError::Internal)?;
    let signature = copy_ptr(a.cbSignature, a.pbSignature).ok_or(WebauthnCError::Internal)?;

    let credential_id = Base64UrlSafeData(
        copy_ptr(a.Credential.cbId, a.Credential.pbId).ok_or(WebauthnCError::Internal)?,
    );
    let type_: String = unsafe {
        a.Credential
            .pwszCredentialType
            .to_string()
            .map_err(|_| WebauthnCError::Internal)?
    };

    Ok(PublicKeyCredential {
        id: credential_id.to_string(),
        raw_id: credential_id,
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: Base64UrlSafeData(authenticator_data),
            client_data_json: Base64UrlSafeData(client_data_json.as_bytes().to_vec()),
            signature: Base64UrlSafeData(signature),
            user_handle: user_id.map(Base64UrlSafeData),
        },
        type_,
        extensions: AuthenticationExtensionsClientOutputs {
            appid: Some(app_id_used),
            // TODO
            ..Default::default()
        },
    })
}

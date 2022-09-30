//! Bindings for Windows 10 Webauthn API.
//!
//! This API is available in Windows 10 bulid 1903 and later.
//!
//! ## API docs
//!
//! * [MSDN: WebAuthn](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/)
//! * [webauthn.h](github.com/microsoft/webauthn) (describes versions)
mod clientdata;
mod cose;
mod credential;
mod extensions;
mod native;
mod rp;
mod user;

use crate::error::WebauthnCError;
use crate::win10::extensions::native_to_assertion_extensions;
use crate::win10::{
    clientdata::{creation_to_clientdata, get_to_clientdata, WinClientData},
    cose::WinCoseCredentialParameters,
    credential::{native_to_transports, WinCredentialList},
    extensions::{
        native_to_registration_extensions, WinExtensionGetAssertionRequest,
        WinExtensionMakeCredentialRequest, WinExtensionsRequest,
    },
    native::{WinPtr, WinWrapper},
    rp::WinRpEntityInformation,
    user::WinUserEntityInformation,
};
use crate::{AuthenticatorBackend, Url};

use base64urlsafedata::Base64UrlSafeData;
use std::thread::sleep;
use std::time::Duration;
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttachment,
    AuthenticatorAttestationResponseRaw, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential, UserVerificationPolicy,
};

use windows::{
    core::{HSTRING, PCWSTR},
    Win32::{
        Foundation::{GetLastError, BOOL, HWND},
        Networking::WindowsWebServices::*,
        System::Console::{GetConsoleTitleW, GetConsoleWindow, SetConsoleTitleW},
        UI::WindowsAndMessaging::FindWindowW,
    },
};

pub struct Win10 {}

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
        let rp = WinRpEntityInformation::new(&options.rp)?;
        let userinfo = WinUserEntityInformation::new(&options.user)?;
        let pubkeycredparams = WinCoseCredentialParameters::new(&options.pub_key_cred_params)?;
        let clientdata =
            WinClientData::new(&creation_to_clientdata(origin, options.challenge.clone()))?;

        let mut exclude_credentials = if let Some(e) = options.exclude_credentials.as_ref() {
            Some(WinCredentialList::new(e)?)
        } else {
            None
        };
        let extensions = match &options.extensions {
            Some(e) => WinExtensionsRequest::new(e)?,
            None => Box::pin(WinExtensionsRequest::<WinExtensionMakeCredentialRequest>::default()),
        };

        let makecredopts = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: timeout_ms,
            // Superceded by pExcludeCredentialList for v3 (API v1, baseline)
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: [].as_mut_ptr(),
            },
            Extensions: *extensions.native_ptr(),
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
            pExcludeCredentialList: match &mut exclude_credentials {
                None => std::ptr::null(),
                Some(l) => &l.native,
            } as *mut _,
            dwEnterpriseAttestation: 0,
            dwLargeBlobSupport: 0,
            bPreferResidentKey: false.into(),
        };

        println!("WebAuthNAuthenticatorMakeCredential()");
        trace!(?makecredopts);
        let a = unsafe {
            let r = WebAuthNAuthenticatorMakeCredential(
                hwnd,
                rp.native_ptr(),
                userinfo.native_ptr(),
                pubkeycredparams.native_ptr(),
                clientdata.native_ptr(),
                Some(&makecredopts),
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
        trace!("{:?}", (*a));

        let cred_id =
            copy_ptr(a.cbCredentialId, a.pbCredentialId).ok_or(WebauthnCError::Internal)?;
        let attesation_object = copy_ptr(a.cbAttestationObject, a.pbAttestationObject)
            .ok_or(WebauthnCError::Internal)?;
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
            extensions: native_to_registration_extensions(&a.Extensions)?,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(attesation_object),
                client_data_json: Base64UrlSafeData(
                    clientdata.client_data_json().as_bytes().to_vec(),
                ),
                transports: Some(native_to_transports(a.dwUsedTransport)),
            },
        })
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
        let clientdata = WinClientData::new(&get_to_clientdata(origin, options.challenge.clone()))?;

        let mut allow_credentials = WinCredentialList::new(options.allow_credentials.as_ref())?;

        let app_id: Option<HSTRING> = options
            .extensions
            .as_ref()
            .map(|e| e.appid.as_ref().map(|a| a.clone().into()))
            .flatten();
        // Used as a *return* value from GetAssertion as to whether the U2F AppId was used,
        // equivalent to [AuthenticationExtensionsClientOutputs::appid].
        //
        // Why here? Because for some reason, Windows' API decides to put a pointer for
        // mutable *return* value inside an `_In_opt_ *const ptr` *request* value
        // ([WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS]): `pbU2fAppId`.
        //
        // The documentation was very opaque here, but [Firefox's implementation][ffx]
        // appears to correctly deal with this nonsense.
        //
        // However, [Chromium's implementation][chr] appears to have misunderstood this field,
        // and always passes in pointers to `static BOOL` values `kUseAppIdTrue` or
        // `kUseAppIdFalse` (depending on whether the extension was present) and doesn't read
        // the response.
        //
        // Unfortunately, it looks like the WebAuthn API has been frozen for Windows 10, and
        // the new revisions are only on Windows 11. So it's unlikely this will ever be
        // properly fixed. 🙃
        //
        // [chr]: https://chromium.googlesource.com/chromium/src/+/f62b8f341c14be84c6c995133f485d76a58de090/device/fido/win/webauthn_api.cc#520
        // [ffx]: https://github.com/mozilla/gecko-dev/blob/620490a051a1fc72563e1c6bbecfe7346122a6bc/dom/webauthn/WinWebAuthnManager.cpp#L714-L716
        let mut app_id_used: BOOL = false.into();
        let extensions = match &options.extensions {
            Some(e) => WinExtensionsRequest::new(e)?,
            None => Box::pin(WinExtensionsRequest::<WinExtensionGetAssertionRequest>::default()),
        };

        let getassertopts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: timeout_ms,
            // Supersceded by pAllowCredentialList in v4 (API v1, baseline)
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: 0,
                pCredentials: [].as_mut_ptr(),
            },
            Extensions: *extensions.native_ptr(),
            dwAuthenticatorAttachment: 0, // Not supported?
            dwUserVerificationRequirement: user_verification_to_native(Some(
                &options.user_verification,
            )),
            dwFlags: 0,
            pwszU2fAppId: match &app_id {
                None => PCWSTR::null(),
                Some(l) => l.into(),
            },
            pbU2fAppId: std::ptr::addr_of_mut!(app_id_used),
            pCancellationId: std::ptr::null_mut(),
            pAllowCredentialList: &mut allow_credentials.native,
            dwCredLargeBlobOperation: 0,
            cbCredLargeBlob: 0,
            pbCredLargeBlob: std::ptr::null_mut(),
        };

        // WebAuthNAuthenticatorGetAssertion
        println!("WebAuthNAuthenticatorGetAssertion()");
        let a = unsafe {
            let r = WebAuthNAuthenticatorGetAssertion(
                hwnd,
                &rp_id,
                clientdata.native_ptr(),
                Some(&getassertopts),
            )
            .map_err(|e| {
                // TODO: map error codes, if we learn them...
                error!("Error: {:?}", e);
                WebauthnCError::Internal
            })?;

            WinPtr::new(r, WebAuthNFreeAssertion).ok_or(WebauthnCError::Internal)?
        };

        println!("got result from WebAuthNAuthenticatorGetAssertion");

        let user_id = copy_ptr(a.cbUserId, a.pbUserId);
        let authenticator_data = copy_ptr(a.cbAuthenticatorData, a.pbAuthenticatorData)
            .ok_or(WebauthnCError::Internal)?;
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

        let mut extensions = native_to_assertion_extensions(&a.Extensions)?;
        extensions.appid = Some(app_id_used.into());

        Ok(PublicKeyCredential {
            id: credential_id.to_string(),
            raw_id: credential_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: Base64UrlSafeData(authenticator_data),
                client_data_json: Base64UrlSafeData(
                    clientdata.client_data_json().as_bytes().to_vec(),
                ),
                signature: Base64UrlSafeData(signature),
                user_handle: user_id.map(Base64UrlSafeData),
            },
            type_,
            extensions,
        })

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

        sleep(Duration::from_millis(50));

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

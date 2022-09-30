use crate::prelude::WebauthnCError;
use std::collections::BTreeMap;
use std::pin::Pin;
use webauthn_rs_proto::PubKeyCredParams;

use super::WinWrapper;

use windows::{
    core::{HSTRING, PCWSTR},
    w,
    Win32::{
        Foundation::{GetLastError, BOOL, HWND},
        Networking::WindowsWebServices::*,
    },
};

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
            WinExtensionMakeCredentialRequest::CredBlob(_) => {
                WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB
            }
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

fn read_extension<'a, T: 'a, U: From<&'a T>>(
    e: &'a WEBAUTHN_EXTENSION,
) -> Result<U, WebauthnCError> {
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
        let id = unsafe {
            e.pwszExtensionIdentifier
                .to_string()
                .map_err(|_| WebauthnCError::Internal)?
        };
        // let id = &HSTRING::from_wide(unsafe { e.pwszExtensionIdentifier.as_wide() });
        match id.as_str() {
            WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET => {
                return read_extension::<'_, BOOL, _>(&e)
                    .map(WinExtensionMakeCredentialResponse::HmacSecret);
            }
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT => {
                return read_extension2(&e).map(WinExtensionMakeCredentialResponse::CredProtect);
            }
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB => {
                return read_extension::<'_, BOOL, _>(&e)
                    .map(WinExtensionMakeCredentialResponse::CredBlob);
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

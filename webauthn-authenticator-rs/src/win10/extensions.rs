use crate::prelude::WebauthnCError;
use std::ffi::c_void;
use std::pin::Pin;
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, CredBlobSet, CredProtect, CredentialProtectionPolicy,
    RegistrationExtensionsClientOutputs, RequestAuthenticationExtensions,
    RequestRegistrationExtensions,
};

use super::WinWrapper;

use windows::{
    core::HSTRING,
    Win32::{Foundation::BOOL, Networking::WindowsWebServices::*},
};

// const WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET: &HSTRING = w!("hmac-secret");
// const WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT: &HSTRING = w!("credProtect");

pub struct WinCredBlobSet {
    native: WEBAUTHN_CRED_BLOB_EXTENSION,
    blob: CredBlobSet,
}

pub(crate) enum WinExtensionMakeCredentialRequest {
    HmacSecret(BOOL),
    CredProtect(WEBAUTHN_CRED_PROTECT_EXTENSION_IN),
    CredBlob(Pin<Box<WinCredBlobSet>>),
    MinPinLength(BOOL),
}

pub(crate) enum WinExtensionGetAssertionRequest {
    CredBlob(BOOL),
}

pub trait WinExtensionRequestType
where
    Self: Sized,
{
    fn identifier(&self) -> &str;
    fn len(&self) -> u32;
    fn ptr(&mut self) -> *mut c_void;
    type WrappedType;
    fn to_native(e: &Self::WrappedType) -> Vec<Self>;
}

impl WinExtensionRequestType for WinExtensionMakeCredentialRequest {
    fn identifier(&self) -> &str {
        match self {
            Self::HmacSecret(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            Self::CredBlob(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB,
            Self::CredProtect(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT,
            Self::MinPinLength(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH,
        }
    }

    fn len(&self) -> u32 {
        (match self {
            Self::HmacSecret(_) => std::mem::size_of::<BOOL>(),
            Self::CredProtect(_) => std::mem::size_of::<WEBAUTHN_CRED_PROTECT_EXTENSION_IN>(),
            Self::CredBlob(_) => std::mem::size_of::<WEBAUTHN_CRED_BLOB_EXTENSION>(),
            Self::MinPinLength(_) => std::mem::size_of::<BOOL>(),
        }) as u32
    }

    fn ptr(&mut self) -> *mut c_void {
        match self {
            Self::HmacSecret(v) => v as *mut _ as *mut c_void,
            Self::CredProtect(v) => v as *mut _ as *mut c_void,
            Self::CredBlob(v) => (&mut v.native) as *mut _ as *mut c_void,
            Self::MinPinLength(v) => v as *mut _ as *mut c_void,
        }
    }

    type WrappedType = RequestRegistrationExtensions;

    fn to_native(e: &Self::WrappedType) -> Vec<Self> {
        let mut o: Vec<Self> = Vec::new();
        if let Some(c) = &e.cred_protect {
            o.push(c.into());
        }
        if let Some(h) = &e.hmac_create_secret {
            o.push(Self::HmacSecret(h.into()))
        }
        if let Some(x) = &e.cred_blob {
            o.push(Self::CredBlob(WinCredBlobSet::new(x)));
        }
        if let Some(x) = &e.min_pin_length {
            o.push(Self::MinPinLength(x.into()));
        }

        o
    }
}

impl WinExtensionRequestType for WinExtensionGetAssertionRequest {
    fn identifier(&self) -> &str {
        match self {
            Self::CredBlob(_) => WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB,
        }
    }

    fn len(&self) -> u32 {
        (match self {
            Self::CredBlob(_) => std::mem::size_of::<BOOL>(),
        }) as u32
    }

    fn ptr(&mut self) -> *mut c_void {
        match self {
            Self::CredBlob(v) => v as *mut _ as *mut c_void,
        }
    }

    type WrappedType = RequestAuthenticationExtensions;

    fn to_native(e: &Self::WrappedType) -> Vec<Self> {
        let mut o: Vec<Self> = Vec::new();
        if let Some(c) = &e.get_cred_blob {
            o.push(Self::CredBlob(c.0.into()));
        }

        o
    }
}

fn credential_protection_policy_from_native(p: u32) -> Option<CredentialProtectionPolicy> {
    Some(match p {
        WEBAUTHN_USER_VERIFICATION_OPTIONAL => CredentialProtectionPolicy::UserVerificationOptional,
        WEBAUTHN_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST => {
            CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList
        }
        WEBAUTHN_USER_VERIFICATION_REQUIRED => CredentialProtectionPolicy::UserVerificationRequired,
        _ => return None,
    })
}

fn credential_protection_policy_to_native(p: CredentialProtectionPolicy) -> u32 {
    match p {
        CredentialProtectionPolicy::UserVerificationOptional => WEBAUTHN_USER_VERIFICATION_OPTIONAL,
        CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList => {
            WEBAUTHN_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST
        }
        CredentialProtectionPolicy::UserVerificationRequired => WEBAUTHN_USER_VERIFICATION_REQUIRED,
    }
}

impl From<&CredProtect> for WinExtensionMakeCredentialRequest {
    fn from(c: &CredProtect) -> Self {
        Self::CredProtect(WEBAUTHN_CRED_PROTECT_EXTENSION_IN {
            dwCredProtect: credential_protection_policy_to_native(c.credential_protection_policy),
            bRequireCredProtect: c
                .enforce_credential_protection_policy
                .unwrap_or(false)
                .into(),
        })
    }
}

impl WinCredBlobSet {
    fn new(b: &CredBlobSet) -> Pin<Box<Self>> {
        let res = Self {
            native: Default::default(),
            blob: b.clone(),
        };
        let mut boxed = Box::pin(res);

        let native = WEBAUTHN_CRED_BLOB_EXTENSION {
            cbCredBlob: boxed.blob.0 .0.len() as u32,
            pbCredBlob: boxed.blob.0 .0.as_mut_ptr() as *mut _,
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

// TODO
enum WinExtensionGetAssertionResponse {
    CredBlob(Vec<u8>),
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

impl TryFrom<&WEBAUTHN_EXTENSION> for WinExtensionMakeCredentialResponse {
    type Error = WebauthnCError;
    fn try_from(e: &WEBAUTHN_EXTENSION) -> Result<Self, WebauthnCError> {
        let id = unsafe {
            e.pwszExtensionIdentifier
                .to_string()
                .map_err(|_| WebauthnCError::Internal)?
        };
        // let id = &HSTRING::from_wide(unsafe { e.pwszExtensionIdentifier.as_wide() });
        match id.as_str() {
            WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET => read_extension::<'_, BOOL, _>(&e)
                .map(WinExtensionMakeCredentialResponse::HmacSecret),
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT => {
                read_extension2(&e).map(WinExtensionMakeCredentialResponse::CredProtect)
            }
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB => {
                read_extension::<'_, BOOL, _>(&e).map(WinExtensionMakeCredentialResponse::CredBlob)
            }
            WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH => {
                read_extension2(&e).map(WinExtensionMakeCredentialResponse::MinPinLength)
            }
            o => {
                error!("unknown extension: {:?}", o);
                Err(WebauthnCError::Internal)
            }
        }
    }
}

pub fn native_to_registration_extensions(
    native: &WEBAUTHN_EXTENSIONS,
) -> Result<RegistrationExtensionsClientOutputs, WebauthnCError> {
    let mut o = RegistrationExtensionsClientOutputs::default();

    for i in 0..(native.cExtensions as usize) {
        let extn = unsafe { &*native.pExtensions.add(i) };
        let win = WinExtensionMakeCredentialResponse::try_from(extn)?;
        match win {
            WinExtensionMakeCredentialResponse::HmacSecret(v) => o.hmac_secret = Some(v),
            WinExtensionMakeCredentialResponse::CredProtect(v) => {
                o.cred_protect = credential_protection_policy_from_native(v);
            }
            WinExtensionMakeCredentialResponse::CredBlob(v) => {
                o.cred_blob = Some(v);
            }
            WinExtensionMakeCredentialResponse::MinPinLength(v) => {
                o.min_pin_length = Some(v);
            }
        }
    }

    Ok(o)
}

impl TryFrom<&WEBAUTHN_EXTENSION> for WinExtensionGetAssertionResponse {
    type Error = WebauthnCError;

    fn try_from(e: &WEBAUTHN_EXTENSION) -> Result<Self, Self::Error> {
        let id = unsafe {
            e.pwszExtensionIdentifier
                .to_string()
                .map_err(|_| WebauthnCError::Internal)?
        };

        match id.as_str() {
            WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB => {
                read_extension2(&e).map(WinExtensionGetAssertionResponse::CredBlob)
            }
            o => {
                error!("unknown extension: {:?}", o);
                Err(WebauthnCError::Internal)
            }
        }
    }
}

pub fn native_to_assertion_extensions(
    native: &WEBAUTHN_EXTENSIONS,
) -> Result<AuthenticationExtensionsClientOutputs, WebauthnCError> {
    let mut o = AuthenticationExtensionsClientOutputs::default();

    for i in 0..(native.cExtensions as usize) {
        let extn = unsafe { &*native.pExtensions.add(i) };
        let win = WinExtensionGetAssertionResponse::try_from(extn)?;
        match win {
            WinExtensionGetAssertionResponse::CredBlob(b) => {
                o.cred_blob = Some(b.into());
            }
        }
    }

    Ok(o)
}

pub struct WinExtensionsRequest<T>
where
    T: WinExtensionRequestType,
{
    native: WEBAUTHN_EXTENSIONS,
    native_list: Vec<WEBAUTHN_EXTENSION>,
    ids: Vec<HSTRING>,
    extensions: Vec<T>,
}

impl<T> Default for WinExtensionsRequest<T>
where
    T: WinExtensionRequestType,
{
    fn default() -> Self {
        Self {
            native: Default::default(),
            native_list: vec![],
            ids: vec![],
            extensions: vec![],
        }
    }
}

impl<T> WinWrapper<T::WrappedType> for WinExtensionsRequest<T>
where
    T: WinExtensionRequestType,
{
    type NativeType = WEBAUTHN_EXTENSIONS;
    fn native_ptr(&self) -> &WEBAUTHN_EXTENSIONS {
        &self.native
    }

    fn new(e: &T::WrappedType) -> Result<Pin<Box<Self>>, WebauthnCError> {
        // Convert the extensions to a Windows-ish type
        let extensions = T::to_native(e);
        let len = extensions.len();

        let res = Self {
            native: Default::default(),
            native_list: Vec::with_capacity(len),
            ids: extensions.iter().map(|e| e.identifier().into()).collect(),
            extensions,
        };

        // Put our final struct on the heap
        let mut boxed = Box::pin(res);

        // Put in all the "native" values
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            let mut_ptr = Pin::get_unchecked_mut(mut_ref);

            let l = &mut mut_ptr.native_list;
            let l_ptr = l.as_mut_ptr();
            for (i, extension) in mut_ptr.extensions.iter_mut().enumerate() {
                let id = &mut_ptr.ids[i];
                *l_ptr.add(i) = WEBAUTHN_EXTENSION {
                    pwszExtensionIdentifier: id.into(),
                    cbExtension: extension.len(),
                    pvExtension: extension.ptr(),
                };
            }

            l.set_len(len);
        }

        // Create the native list element
        let native = WEBAUTHN_EXTENSIONS {
            cExtensions: len as u32,
            pExtensions: boxed.native_list.as_ptr() as *mut _,
        };

        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        Ok(boxed)
    }
}

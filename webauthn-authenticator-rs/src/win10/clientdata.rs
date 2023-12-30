//! Wrappers for [CollectedClientData].
use crate::{error::WebauthnCError, win10::native::WinWrapper};
use std::pin::Pin;
use webauthn_rs_proto::CollectedClientData;
use windows::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_CLIENT_DATA, WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_HASH_ALGORITHM_SHA_256,
};

/// Wrapper for [WEBAUTHN_CLIENT_DATA] to ensure pointer lifetime.
pub struct WinClientData {
    native: WEBAUTHN_CLIENT_DATA,
    client_data_json: String,
}

impl WinClientData {
    pub fn client_data_json(&self) -> &String {
        &self.client_data_json
    }
}

impl WinWrapper<CollectedClientData> for WinClientData {
    type NativeType = WEBAUTHN_CLIENT_DATA;
    fn new(clientdata: &CollectedClientData) -> Result<Pin<Box<Self>>, WebauthnCError> {
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
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        // Update the boxed type with the proper native object.
        unsafe {
            let mut_ref: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            Pin::get_unchecked_mut(mut_ref).native = native;
        }

        Ok(boxed)
    }

    fn native_ptr(&self) -> &WEBAUTHN_CLIENT_DATA {
        &self.native
    }
}

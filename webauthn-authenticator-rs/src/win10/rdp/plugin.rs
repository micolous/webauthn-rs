use std::{ffi::c_void, mem::transmute};
use windows::{
    core::{s, ComInterface, Error, IntoParam, Result, GUID, HRESULT, PCSTR},
    Win32::{
        Foundation::{FreeLibrary, NTE_BAD_LEN},
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            RemoteDesktop::IWTSPlugin,
        },
    },
};

/// <https://learn.microsoft.com/en-us/windows/win32/termserv/virtualchannelgetinstance>
type VirtualChannelGetInstance = unsafe fn(&GUID, &mut u32, *mut *mut c_void) -> HRESULT;

const WEBAUTHN_DLL: PCSTR = s!("webauthn.dll");
const VIRTUAL_CHANNEL_GET_INSTANCE: PCSTR = s!("VirtualChannelGetInstance");

/// Load a function from a given library.
///
/// This is a small wrapper around `LoadLibrary` and `GetProcAddress`.
///
/// # Safety
///
/// * Both the library and function names must be valid PCSTR representations
unsafe fn delay_load(
    library: impl IntoParam<PCSTR>,
    function: impl IntoParam<PCSTR>,
) -> Result<*const c_void> {
    let library = LoadLibraryA(library)?;

    if library.is_invalid() {
        // GetLastError
        return Err(Error::from_win32());
    }

    let Some(address) = GetProcAddress(library, function) else {
        // GetLastError
        let result = Err(Error::from_win32());
        let _ = FreeLibrary(library);
        return result;
    };

    Ok(address as *const c_void)
}

/// Gets an instance of the WebAuthn [IWTSPlugin].
pub fn get_webauthn_iwtsplugin() -> Result<IWTSPlugin> {
    let virtual_channel_get_instance: VirtualChannelGetInstance =
        unsafe { transmute(delay_load(WEBAUTHN_DLL, VIRTUAL_CHANNEL_GET_INSTANCE)?) };

    let mut instance = Option::None;
    let mut num_objs = 1;
    Ok(unsafe {
        let plugin = virtual_channel_get_instance(
            &IWTSPlugin::IID,
            &mut num_objs,
            &mut instance as *mut _ as *mut _,
        )
        .and_some(instance)?;

        if num_objs != 1 {
            return Err(NTE_BAD_LEN.into());
        }

        plugin
    })
}

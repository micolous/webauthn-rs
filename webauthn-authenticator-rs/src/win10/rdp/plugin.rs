use std::{
    ffi::c_void,
    mem::{forget, transmute},
    ops::{DerefMut, RangeInclusive},
    slice,
    sync::{Arc, Mutex, RwLock},
};
use windows::{
    core::{
        implement, s, w, AsImpl, ComInterface, Error, IntoParam, BSTR, GUID, HRESULT, HSTRING,
        PCSTR, PCWSTR, Result,
    },
    Win32::{
        Foundation::{
            FreeLibrary, BOOL, DBG_UNABLE_TO_PROVIDE_HANDLE, ERROR_CONNECTION_REFUSED, E_FAIL,
            MAX_PATH, NTE_BAD_LEN, NTE_INVALID_PARAMETER, S_OK,
        },
        System::{
            Com::{CoInitializeEx, COINIT_MULTITHREADED},
            LibraryLoader::{GetProcAddress, LoadLibraryW},
            Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ},
            RemoteDesktop::{
                IWTSListenerCallback, IWTSPlugin, IWTSVirtualChannel, IWTSVirtualChannelCallback,
                IWTSVirtualChannelManager, IWTSVirtualChannelManager_Impl, IWTSVirtualChannel_Impl,
            },
        },
    },
};

/// <https://learn.microsoft.com/en-us/windows/win32/termserv/virtualchannelgetinstance>
type VirtualChannelGetInstance = unsafe fn(&GUID, &mut u32, *mut *mut c_void) -> HRESULT;

/// Load a function from a given library.
///
/// This is a small wrapper around `LoadLibrary` and `GetProcAddress`.
///
/// # Safety
///
/// * Both the library and function names must be valid PCWSTR/PCSTR
///   representations
unsafe fn delay_load(
    library: impl IntoParam<PCWSTR>,
    function: impl IntoParam<PCSTR>,
) -> Result<*const c_void> {
    let library = LoadLibraryW(library)?;

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

/// Gets the path of the Webauthn Terminal Server Client plugin from the registry.
///
/// This will automatically append a `.` to the end of the file name to prevent
/// `LoadLibrary` adding `.DLL` to the library name if the filename doesn't
/// exist.
///
/// ## Note
///
/// This does not check that the returned path exists, nor that it is a valid
/// virtual channel provider DLL.
fn get_webauthn_rdp_plugin_path() -> Result<HSTRING> {
    const SUBKEY: PCWSTR =
        w!("SOFTWARE\\Microsoft\\Terminal Server Client\\Default\\AddIns\\webauthn");
    const VALUE: PCWSTR = w!("Name");

    // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
    // suggests maximum recommended size is 2048 bytes
    let mut buf: Vec<u16> = vec![0; 1024];
    // len is in bytes
    let mut len = (buf.len() * std::mem::size_of::<u16>()) as u32;

    unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            SUBKEY,
            VALUE,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut c_void),
            Some(&mut len),
        )?;
    }

    // bytes -> wchars
    if (len as usize) % std::mem::size_of::<u16>() != 0 {
        return Err(NTE_BAD_LEN.into());
    }
    let len = (len as usize) / std::mem::size_of::<u16>();
    if len > buf.len() {
        return Err(NTE_BAD_LEN.into());
    }
    buf.truncate(len);
    if let Some(&l) = buf.last() {
        // Remove null terminator, HSTRING will put one in for us
        if l == 0 {
            buf.pop();
        }
    }

    // Add a `.` to the end to prevent LoadLibrary loading `example.dll.DLL`
    buf.push(b'.'.into());

    HSTRING::from_wide(&buf)
}

/// Gets an instance of the WebAuthn [IWTSPlugin].
pub fn get_webauthn_iwtsplugin() -> Result<IWTSPlugin> {
    let path = get_webauthn_rdp_plugin_path()?;

    let virtual_channel_get_instance: VirtualChannelGetInstance =
        unsafe { transmute(delay_load(&path, s!("VirtualChannelGetInstance"))?) };

    let mut instance = Option::None;
    let mut num_objs = 1;
    let plugin: IWTSPlugin = unsafe {
        let ret = virtual_channel_get_instance(
            &IWTSPlugin::IID,
            &mut num_objs,
            &mut instance as *mut _ as *mut _,
        )
        .and_some(instance)?;
        assert_eq!(1, num_objs);
        ret
    };

    Ok(plugin)
}

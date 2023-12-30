mod channel;
mod plugin;

use crate::win10::rdp::channel::{Connection, VirtualChannelManager};
use windows::{
    core::{AsImpl as _, Result},
    Win32::{
        Foundation::{E_FAIL, NTE_BAD_LEN},
        System::RemoteDesktop::{IWTSPlugin, IWTSVirtualChannelManager},
    },
};

pub struct Win10Rdp {
    plugin: IWTSPlugin,
    iface: IWTSVirtualChannelManager,
}

impl Win10Rdp {
    pub fn new() -> Result<Self> {
        let o = Self {
            plugin: plugin::get_webauthn_iwtsplugin()?,
            iface: VirtualChannelManager::new().into(),
        };

        unsafe {
            o.plugin.Initialize(&o.iface)?;
            o.plugin.Connected()?;
        }

        Ok(o)
    }

    fn connect(&self) -> Result<Connection> {
        // Get back the IWTSListenerCallback
        let Some(c) = unsafe { self.iface.as_impl() }.get_webauthn_callback() else {
            return Err(E_FAIL.into());
        };

        Connection::new(&c)
    }

    pub fn get_api_version(&self) -> Result<u32> {
        let c = self.connect()?;
        let r = c.transceive(&COMMAND_API_VERSION)?;

        Ok(u32::from_le_bytes(r.try_into().map_err(|_| NTE_BAD_LEN)?))
    }
}

impl Drop for Win10Rdp {
    fn drop(&mut self) {
        unsafe {
            let _ = self.plugin.Terminated();
        }
    }
}

// The canonical example had the wrong command code. It lists 5, it's actually 8.
const COMMAND_API_VERSION: [u8; 57] = [
    0xa4, 0x67, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, /* 0x5 */ 0x8, 0x65, 0x66, 0x6c,
    0x61, 0x67, 0x73, 0x0, 0x67, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x0, 0x6d, 0x74, 0x72,
    0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x50, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];

#[cfg(test)]
mod test {
    use windows::Win32::Networking::WindowsWebServices::WebAuthNGetApiVersionNumber;

    use super::*;

    #[test]
    fn get_api_version() -> Result<()> {
        let api_ver = unsafe { WebAuthNGetApiVersionNumber() };
        assert_ne!(0, api_ver);

        let rdp = Win10Rdp::new()?;
        assert_eq!(api_ver, rdp.get_api_version()?);

        Ok(())
    }
}

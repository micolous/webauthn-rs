use std::{
    ops::{DerefMut, RangeInclusive},
    slice,
    sync::{Arc, Mutex, RwLock},
};
use windows::{
    core::{implement, IUnknown, Result, BSTR, HRESULT, PCSTR},
    Win32::{
        Foundation::{
            BOOL, DBG_UNABLE_TO_PROVIDE_HANDLE, ERROR_CONNECTION_REFUSED, E_FAIL, MAX_PATH,
            NTE_BAD_LEN, NTE_INVALID_PARAMETER, S_OK,
        },
        System::RemoteDesktop::{
            IWTSListener, IWTSListenerCallback, IWTSVirtualChannel, IWTSVirtualChannelCallback,
            IWTSVirtualChannelManager, IWTSVirtualChannelManager_Impl, IWTSVirtualChannel_Impl,
        },
    },
};

#[derive(Default)]
#[implement(IWTSVirtualChannelManager)]
pub struct VirtualChannelManager(RwLock<Option<IWTSListenerCallback>>);

impl VirtualChannelManager {
    pub fn new() -> Self {
        Self(RwLock::new(None))
    }
}

impl IWTSVirtualChannelManager_Impl for VirtualChannelManager {
    #[allow(non_snake_case)]
    fn CreateListener(
        &self,
        pszchannelname: &PCSTR,
        uflags: u32,
        plistenercallback: Option<&IWTSListenerCallback>,
    ) -> Result<IWTSListener> {
        // https://learn.microsoft.com/en-us/windows/win32/api/tsvirtualchannels/nf-tsvirtualchannels-iwtsvirtualchannelmanager-createlistener
        if pszchannelname.is_null() || uflags != 0 {
            return Err(NTE_INVALID_PARAMETER.into());
        }

        let chan = unsafe { pszchannelname.as_bytes() };
        if chan.is_empty() || chan.len() > (MAX_PATH as usize) {
            return Err(NTE_BAD_LEN.into());
        }

        let Ok(chan) = std::str::from_utf8(chan) else {
            return Err(NTE_INVALID_PARAMETER.into());
        };

        if chan != "WebAuthN_Channel" {
            error!("unknown VirtualChannel name: {chan:?}");
            return Err(NTE_INVALID_PARAMETER.into());
        }

        let Ok(mut inner) = self.0.try_write() else {
            error!("failed to lock inner data");
            return Err(DBG_UNABLE_TO_PROVIDE_HANDLE.into());
        };

        // refcount++
        *inner.deref_mut() = plistenercallback.cloned();

        // webauthn.dll doesn't actually use the IWTSListenerCallback, so return
        // "null" here
        Err(S_OK.into())
    }
}

impl VirtualChannelManager {
    pub fn get_webauthn_callback(&self) -> Option<IWTSListenerCallback> {
        let Ok(lock) = self.0.try_read() else {
            return None;
        };

        // refcount++
        lock.as_ref().cloned()
    }
}

/// Implements a basic [IWTSVirtualChannel] which can collect only one message.
///
/// This will only work for an [IWTSPlugin] implements a basic request-response
/// model.
#[implement(IWTSVirtualChannel)]
pub struct VirtualChannel {
    ret: Arc<Mutex<Option<Result<Vec<u8>>>>>,
}

/// The valid response lengths for messages sent to the [IWTSVirtualChannel]
const CHANNEL_RESPONSE_LENGTH_RANGE: RangeInclusive<u32> = 4..=65536;

impl IWTSVirtualChannel_Impl for VirtualChannel {
    #[allow(non_snake_case)]
    fn Write(&self, cbsize: u32, pbuffer: *const u8, _preserved: Option<&IUnknown>) -> Result<()> {
        // Expect to see a buffer with:
        //   hresult: i32,
        //   payload: [u8] (optional),
        if pbuffer.is_null() {
            return Err(NTE_INVALID_PARAMETER.into());
        }

        if !CHANNEL_RESPONSE_LENGTH_RANGE.contains(&cbsize) {
            return Err(NTE_BAD_LEN.into());
        }

        let buf = unsafe { slice::from_raw_parts(pbuffer, cbsize as usize) };

        let hresult = {
            let mut b: [u8; 4] = [0; 4];
            b.copy_from_slice(&buf[0..4]);
            HRESULT(i32::from_le_bytes(b))
        };

        let result = hresult.and_then(|| (&buf[4..]).to_vec());

        let Ok(mut lock) = self.ret.try_lock() else {
            // Cannot lock the buffer.
            return Err(E_FAIL.into());
        };

        if let Some(msg) = lock.replace(result) {
            // There is some uncollected message, probably because
            // we got an unsolicited message.
            warn!("uncollected message in buffer: {msg:?}");
        }

        Ok(())
    }

    #[allow(non_snake_case)]
    fn Close(&self) -> windows::core::Result<()> {
        Ok(())
    }
}

pub struct Connection {
    /// [IWTSPlugin]'s callback used to connect a [VirtualChannel].
    callback: Arc<IWTSVirtualChannelCallback>,
    /// Reference to a [VirtualChannel], which needs to live for as long as this
    /// connection.
    _vc: Arc<IWTSVirtualChannel>,
    /// Shared value for [VirtualChannel] return.
    ret: Arc<Mutex<Option<windows::core::Result<Vec<u8>>>>>,
}

impl Connection {
    /// Creates a channel connection to pass messages into the
    /// [IWTSListenerCallback] to process events.
    pub fn new(c: &IWTSListenerCallback) -> windows::core::Result<Self> {
        let mut pbaccept: BOOL = true.into();
        let mut ppcallback: Option<IWTSVirtualChannelCallback> = None;

        // webauthn.dll's OnDataRecieved normally blocks, so this way we avoid a
        // race
        let ret = Arc::new(Mutex::new(None));
        let vc = Arc::new(VirtualChannel { ret: ret.clone() }.into());

        unsafe {
            c.OnNewChannelConnection::<&IWTSVirtualChannel, &BSTR>(
                &vc,
                &BSTR::new(),
                &mut pbaccept,
                &mut ppcallback,
            )?;
        }

        if !pbaccept.as_bool() {
            error!("Channel connection not accepted!");
            return Err(ERROR_CONNECTION_REFUSED.into());
        }

        let Some(callback) = ppcallback.as_ref() else {
            error!("WebAuthN_Channel did not provide callback!");
            return Err(ERROR_CONNECTION_REFUSED.into());
        };

        Ok(Self {
            callback: Arc::new(callback.clone()),
            _vc: vc,
            ret,
        })
    }

    /// Sends a command to a [IWTSVirtualChannelCallback] and waits for a
    /// response.
    ///
    /// This will only work correctly when:
    ///
    /// * [IWTSVirtualChannelCallback::OnDataReceived] is blocking
    /// * the [IWTSPlugin] which always issues a
    ///   [IWTSVirtualChannel_Impl::Write] for each
    ///   [IWTSVirtualChannelCallback::OnDataReceived] call
    pub fn transceive(&self, buf: &[u8]) -> windows::core::Result<Vec<u8>> {
        trace!(">>> {}", hex::encode(&buf));
        unsafe {
            // webauthn.dll's OnDataRecieved will block until it has a result.
            self.callback.OnDataReceived(buf)?;
        }

        let Ok(mut lock) = self.ret.try_lock() else {
            error!("cannot acquire lock on VirtualChannel buffer, OnDataRecieved may be async?");
            return Err(E_FAIL.into());
        };

        let res = lock.take().unwrap_or_else(|| {
            error!("no message in VirtualChannel buffer");
            Err(E_FAIL.into())
        });

        match &res {
            Ok(buf) => trace!("<<< {}", hex::encode(buf)),
            Err(e) => error!("{:#02x}: {}", e.code().0, e.message()),
        }

        res
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            let _ = self.callback.OnClose();
        }
    }
}

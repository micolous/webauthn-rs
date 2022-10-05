use crate::error::WebauthnCError;
use std::{thread::{JoinHandle, self}, time::Duration};
use windows::{
    core::{HSTRING, PCWSTR},
    w,
    Win32::{
        Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM, HINSTANCE},
        Graphics::Gdi::{GetSysColorBrush, UpdateWindow, COLOR_WINDOW},
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
            LoadCursorW, LoadIconW, PostQuitMessage, RegisterClassExW, ShowWindow, CS_HREDRAW,
            CS_OWNDC, CS_VREDRAW, CW_USEDEFAULT, IDC_ARROW, IDI_APPLICATION, MSG, SW_SHOW,
            WM_DESTROY, WNDCLASSEXW, WS_EX_LEFT, WS_OVERLAPPEDWINDOW,
        },
    },
};

pub unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // TODO: bubble z-order properly
    // trace!(
    //     "window_proc: {:?}, {:?}, {:?}, {:?}",
    //     hwnd,
    //     msg,
    //     wparam,
    //     lparam
    // );
    match msg {
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub struct Window {
    hwnd: HWND,
    t: JoinHandle<()>,
}

const WINDOW_CLASS: &HSTRING = w!("webauthn-authenticator-rs");
unsafe fn init() -> Result<HINSTANCE, WebauthnCError> {
    // TODO: run this once
    let hinstance = GetModuleHandleW(PCWSTR::null()).map_err(|_| WebauthnCError::CannotFindHWND)?;
    let wnd_class = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: CS_OWNDC | CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(None, IDI_APPLICATION).map_err(|_| WebauthnCError::Internal)?,
        hCursor: LoadCursorW(None, IDC_ARROW).map_err(|_| WebauthnCError::Internal)?,
        hbrBackground: GetSysColorBrush(COLOR_WINDOW),
        lpszMenuName: PCWSTR::null(),
        lpszClassName: WINDOW_CLASS.into(),
        hIconSm: LoadIconW(None, IDI_APPLICATION).map_err(|_| WebauthnCError::Internal)?,
    };
    let c = RegisterClassExW(&wnd_class);
    Ok(hinstance)
}

impl Window {
    pub fn new() -> Result<Self, WebauthnCError> {
        let hwnd = unsafe {
            let hinstance = init()?;

            CreateWindowExW(
                WS_EX_LEFT, // | WS_EX_TOPMOST,
                WINDOW_CLASS,
                None,
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                1,
                1,
                None,
                None,
                hinstance,
                None,
            )
        };

        if hwnd == HWND(0) {
            let e = unsafe { GetLastError() };
            trace!("window not created, {:?}", e);
            return Err(WebauthnCError::CannotFindHWND);
        }

        unsafe {
            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd);
        }

        // let (sender, receiver) = sync_channel::<()>(0);

        let t = thread::spawn(move || {
            trace!("spawned background");
            let mut msg: MSG = Default::default();
            loop {
                let res: bool = unsafe { GetMessageW(&mut msg, None, 0, 0) }.as_bool();
                if !res {
                    break;
                }
                unsafe {
                    DispatchMessageW(&msg);
                }
            }
            trace!("background stopped");
        });

        thread::sleep(Duration::from_millis(50));
        Ok(Self { hwnd, t })
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        trace!("dropping window");
        unsafe {
            DestroyWindow(self.hwnd);
        }
    }
}

impl Into<HWND> for &Window {
    fn into(self) -> HWND {
        self.hwnd
    }
}

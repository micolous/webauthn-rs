use crate::error::WebauthnCError;
use std::{
    sync::{mpsc::sync_channel, Once},
    thread::{self, JoinHandle},
};
use windows::{
    core::{HSTRING, PCWSTR},
    w,
    Win32::{
        Foundation::{GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        Graphics::Gdi::{GetSysColorBrush, COLOR_WINDOW},
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
            IsGUIThread, LoadCursorW, LoadIconW, PostMessageW, PostQuitMessage, RegisterClassExW,
            SetWindowPos, CS_HREDRAW, CS_OWNDC, CS_VREDRAW, CW_USEDEFAULT, HWND_TOP, IDC_ARROW,
            IDI_APPLICATION, MSG, SWP_NOMOVE, SWP_NOSIZE, WM_CLOSE, WM_DESTROY, WNDCLASSEXW,
            WS_CAPTION, WS_EX_LEFT, WS_OVERLAPPED, WS_SYSMENU, WS_VISIBLE,
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
        WM_CLOSE => {
            DestroyWindow(hwnd);
            LRESULT(0)
        }
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

unsafe fn get_hinstance() -> HINSTANCE {
    static init: Once = Once::new();
    static mut hinstance: HINSTANCE = HINSTANCE(0);

    init.call_once(|| {
        hinstance = GetModuleHandleW(PCWSTR::null()).expect("GetModuleHandleW");

        let icon = LoadIconW(None, IDI_APPLICATION).expect("LoadIconW");
        let wnd_class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_OWNDC | CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: icon,
            hCursor: LoadCursorW(None, IDC_ARROW).expect("LoadCursorW"),
            hbrBackground: GetSysColorBrush(COLOR_WINDOW),
            lpszMenuName: PCWSTR::null(),
            lpszClassName: WINDOW_CLASS.into(),
            hIconSm: icon,
        };

        RegisterClassExW(&wnd_class);
    });

    hinstance
}

impl Window {
    pub fn new() -> Result<Self, WebauthnCError> {
        let (sender, receiver) = sync_channel::<HWND>(0);

        let t = thread::spawn(move || {
            trace!("spawned background");
            unsafe {
                assert!(IsGUIThread(true).as_bool());
            }

            let hwnd = unsafe {
                let hinstance = get_hinstance();

                CreateWindowExW(
                    WS_EX_LEFT,
                    WINDOW_CLASS,
                    WINDOW_CLASS,
                    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    10,
                    10,
                    None,
                    None,
                    hinstance,
                    None,
                )
            };

            sender.send(hwnd);
            if hwnd == HWND(0) {
                let e = unsafe { GetLastError() };
                trace!("window not created, {:?}", e);
                return;
            }

            unsafe {
                //ShowWindow(hwnd, SW_SHOWNORMAL);
                //UpdateWindow(hwnd);
                assert!(
                    SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE).as_bool()
                );
            }

            let mut msg: MSG = Default::default();
            loop {
                let res: bool = unsafe { GetMessageW(&mut msg, None, 0, 0) }.as_bool();
                if !res {
                    break;
                }
                trace!(?msg);
                unsafe {
                    DispatchMessageW(&msg);
                }
            }
            trace!("background stopped");
        });

        let hwnd = receiver.recv().expect("oops recv");
        if hwnd == HWND(0) {
            return Err(WebauthnCError::CannotFindHWND);
        }
        Ok(Self { hwnd, t })
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        trace!("dropping window");
        unsafe {
            PostMessageW(self.hwnd, WM_CLOSE, None, None);
        }
    }
}

impl Into<HWND> for &Window {
    fn into(self) -> HWND {
        self.hwnd
    }
}

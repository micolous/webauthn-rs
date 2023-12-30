//! Bindings for Windows 10 WebAuthn API.
//!
//! This API is available in Windows 10 bulid 1903 and later.
//!
//! ## API docs
//!
//! * [MSDN: WebAuthn API](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/)
//! * [webauthn.h](github.com/microsoft/webauthn) (describes versions)
//! * [windows-rs API](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WindowsWebServices/index.html)
#[cfg(feature = "win10")]
mod clientdata;
#[cfg(feature = "win10")]
mod cose;
#[cfg(feature = "win10")]
mod credential;
#[cfg(feature = "win10")]
mod extensions;
#[cfg(any(feature = "win10", feature = "win10-rdp"))]
mod gui;
#[cfg(feature = "win10")]
mod native;
#[cfg(feature = "win10")]
mod rp;
#[cfg(feature = "win10")]
mod user;
#[cfg(feature = "win10")]
mod win10;

#[cfg(feature = "win10-rdp")]
pub mod rdp;

#[cfg(feature = "win10")]
/// Authenticator backend for Windows 10 WebAuthn API.
pub struct Win10 {}

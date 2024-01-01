//! Bindings for Windows 10 WebAuthn API.
//!
//! The main interface is [`Win10`][], which implements the
//! [`AuthenticatorBackend`][] and [`Default`] traits.
//!
//! This API is available in Windows 10 bulid 1903 and later.
//!
//! ## API docs
//!
//! * [MSDN: WebAuthn API](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/)
//! * [webauthn.h](github.com/microsoft/webauthn) (describes versions)
//! * [windows-rs API](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WindowsWebServices/index.html)
//! 
//! ## See also
//! 
//! * [`Win10Rdp`][] (available with `--features win10-rdp`), which uses the
//!   [WebAuthn Terminal Services Virtual Channel Protocol][rdpewa].
//!
//! ## Useful registry keys:
//! 
//! * `HKCU\SOFTWARE\Microsoft\CtapTest`:
//!   * `ClientPin` (SZ)
//!   * `InvalidCount` (DWORD)
//!   * `SignCount` (DWORD)
//!   * `Credentials`:
//!     * (hex credential ID)
//!       * `containerName` (SZ)
//!       * `createTime` (BINARY)
//!       * `id` (SZ)
//!       * `name` (SZ)
//!       * `icon` (SZ)
//!       * `displayName` (SZ)
//! * `HKCU\SOFTWARE\Microsoft\Cryptograpdy\FIDO`:
//!   * (paired hybrid devices)
//!     * `Name`
//!     * `Data`
//! * `HKLM\SOFTWARE\Microsoft\Cryptography\FIDO`:
//!   * `DebugMode` (DWORD)
//!   * `WebAuthNTimeout` (DWORD)
//! * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{F8A1793B-7873-4046-B2A7-1F318747F427}\Test`:
//!   * `SuppressPasskeyCreatedDialog` (DWORD)
//! * `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`:
//!   * `fDisableWebAuthn` (DWORD): disable remote redirection
//! 
//! [`AuthenticatorBackend`]: crate::AuthenticatorBackend
//! [`Win10Rdp`]: rdp::Win10Rdp
//! [rdpewa]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpewa/68f2df2e-7c40-4a93-9bb0-517e4283a991
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

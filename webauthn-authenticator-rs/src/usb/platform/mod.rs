/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// #[macro_use]
// mod util;

pub mod traits;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
pub mod hidproto;

#[cfg(any(target_os = "linux"))]
extern crate libudev;

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
#[cfg_attr(not(any(target_os = "linux", target_os = "windows")), path = "stub/mod.rs")]
mod os;

#[doc(inline)]
pub use os::*;
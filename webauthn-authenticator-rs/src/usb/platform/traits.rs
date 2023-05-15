use async_trait::async_trait;
use futures::stream::BoxStream;
use std::fmt::Debug;

use crate::{
    error::WebauthnCError,
    usb::{HidReportBytes, HidSendReportBytes},
};

/// Platform-specific USB device manager.
#[async_trait]
pub trait USBDeviceManager: Sized {
    /// The type used for USB device connections on this platform.
    type Device: USBDevice;
    /// The type used for USB device information produced on this platform.
    type DeviceInfo: USBDeviceInfo<Device = Self::Device>;

    /// Instantiates a new [USBDeviceManager] for this platform.
    fn new() -> Result<Self, WebauthnCError>;

    /// Watches for USB authenticator device connection and disconnection events
    /// until the resulting stream is dropped.
    ///
    /// This method fires [`WatchEvent::Added`] events for any USB devices
    /// *already* connected, followed by [`WatchEvent::EnumerationComplete`].
    fn watch_devices(&self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>, WebauthnCError>;

    /// Gets a list of currently-connected USB authenticators.
    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>, WebauthnCError>;
}

#[derive(Debug)]
pub enum WatchEvent<T>
where
    T: USBDeviceInfo,
{
    /// A new device was connected.
    Added(T),
    /// An existing device was disconnected.
    Removed(T::Id),
    /// Initial enumeration of existing devices completed.
    EnumerationComplete,
}

/// Platform-specific USB device info structure.
#[async_trait]
pub trait USBDeviceInfo: Debug {
    /// The type used for USB device connections on this platform.
    type Device: USBDevice;

    /// The type used for USB device identifiers on this platform.
    type Id: Debug;

    /// Opens a connection to this USB device.
    async fn open(self) -> Result<Self::Device, WebauthnCError>;
}

/// Platform-specific USB device connection structure.
#[async_trait]
pub trait USBDevice: Send {
    /// The type used for USB device information on this platform.
    type Info: USBDeviceInfo<Device = Self>;

    /// Gets the device info used to create this connection.
    fn get_info(&self) -> &Self::Info;

    /// Read some bytes from the FIDO device's HID input report descriptor.
    async fn read(&mut self) -> Result<HidReportBytes, WebauthnCError>;

    /// Write some bytes to the FIDO device's HID output report descriptor.
    async fn write(&self, data: HidSendReportBytes) -> Result<(), WebauthnCError>;
}

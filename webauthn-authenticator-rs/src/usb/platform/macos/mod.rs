/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use async_trait::async_trait;
use core_foundation::{
    mach_port::CFIndex,
    runloop::{
        kCFRunLoopDefaultMode, CFRunLoopActivity, CFRunLoopGetCurrent, CFRunLoopObserverRef,
        CFRunLoopRun, CFRunLoopStop,
    },
};
use futures::{stream::BoxStream, Stream}; // channel::mpsc::{self, Receiver, Sender}};
use libc::c_void;
use std::{
    fmt,
    marker::PhantomPinned,
    mem::size_of,
    pin::Pin,
    slice::from_raw_parts,
    // sync::mpsc::{self as std_mpsc, Receiver as StdReceiver, Sender as StdSender, SyncSender},
    sync::Arc,
    thread,
};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;

// mod device;
// pub mod transaction;

mod iokit;
// mod monitor;

use crate::{
    error::WebauthnCError,
    usb::{
        platform::{
            os::iokit::{
                kIOHIDManagerOptionNone, kIOHIDReportTypeOutput, IOHIDDevice, IOHIDDeviceMatcher,
                IOHIDDeviceOpen, IOHIDDeviceRef, IOHIDDeviceRegisterInputReportCallback,
                IOHIDDeviceScheduleWithRunLoop, IOHIDDeviceSetReport, IOHIDManager,
                IOHIDManagerCreate, IOHIDManagerRegisterDeviceMatchingCallback,
                IOHIDManagerRegisterDeviceRemovalCallback, IOHIDManagerSetDeviceMatching,
                IOHIDReportType, IOReturn,
            },
            traits::*,
        },
        HidReportBytes, HidSendReportBytes,
    },
};

use self::iokit::{
    CFRunLoopEntryObserver, IOHIDManagerOpen, IOHIDManagerScheduleWithRunLoop, SendableRunLoop,
};

pub struct USBDeviceManagerImpl {
    // stream: ReceiverStream<WatchEvent<USBDeviceInfoImpl>>,
    // tx: Sender<WatchEvent<USBDeviceInfoImpl>>,
    // manager: IOHIDManager,
    // _matcher: IOHIDDeviceMatcher,
}

impl fmt::Debug for USBDeviceManagerImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("USBDeviceManagerImpl")
            // .field("manager", &self.manager)
            .finish()
    }
}

unsafe impl Send for USBDeviceManagerImpl {}
unsafe impl Sync for USBDeviceManagerImpl {}

#[async_trait]
impl USBDeviceManager for USBDeviceManagerImpl {
    type Device = USBDeviceImpl;
    type DeviceInfo = USBDeviceInfoImpl;
    type DeviceId = IOHIDDevice;

    fn new() -> Result<Self, WebauthnCError> {
        Ok(Self {}) // manager, _matcher })
    }

    async fn watch_devices(&mut self) -> Result<BoxStream<WatchEvent<Self::DeviceInfo>>, WebauthnCError> {
        let (mut matcher, rx) = MacDeviceMatcher::new()?;
        let (observer_tx, mut observer_rx) = mpsc::channel(1);
        let stream = ReceiverStream::from(rx);

        thread::spawn(move || {
            let context = &observer_tx as *const _ as *mut c_void;
            let obs = CFRunLoopEntryObserver::new(MacDeviceMatcher::observe, context);
            obs.add_to_current_runloop();
            matcher.as_mut().start()
        });

        trace!("Waiting for manager runloop");

        let runloop: SendableRunLoop = observer_rx.recv().await.expect("failed to receive runloop");
        trace!("Got a manager runloop");

        Ok(Box::pin(MacRunLoopStream { runloop, stream }))
    }

    async fn get_devices(&self) -> Result<Vec<Self::DeviceInfo>, WebauthnCError> {
        todo!()
    }
}

struct MacRunLoopStream<T> {
    runloop: SendableRunLoop,
    stream: ReceiverStream<T>,
}

impl<T> Stream for MacRunLoopStream<T> {
    type Item = T;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let stream = unsafe { self.map_unchecked_mut(|s| &mut s.stream) };
        ReceiverStream::poll_next(stream, cx)
    }
}

impl<T> Drop for MacRunLoopStream<T> {
    fn drop(&mut self) {
        unsafe { CFRunLoopStop(*self.runloop) }
    }
}

// impl Drop for USBDeviceManagerImpl {
//     fn drop(&mut self) {
//         unsafe { CFRelease(self.manager.0 as *mut c_void) };
//     }
// }

struct MacDeviceMatcher {
    manager: IOHIDManager,
    _matcher: IOHIDDeviceMatcher,
    tx: Sender<WatchEvent<USBDeviceInfoImpl>>,
    _pin: PhantomPinned,
}

unsafe impl Send for MacDeviceMatcher {}
unsafe impl Sync for MacDeviceMatcher {}

impl MacDeviceMatcher {
    fn new() -> Result<
        (
            Pin<Box<Self>>,
            ReceiverStream<WatchEvent<USBDeviceInfoImpl>>,
        ),
        WebauthnCError,
    > {
        let manager =
            IOHIDManagerCreate(kIOHIDManagerOptionNone).ok_or(WebauthnCError::Internal)?;
        // Match FIDO devices only.
        let _matcher = IOHIDDeviceMatcher::new();
        IOHIDManagerSetDeviceMatching(&manager, Some(&_matcher));
        let (tx, rx) = mpsc::channel(16);
        let stream = ReceiverStream::from(rx);
        let o = Self {
            manager,
            _matcher,
            tx,
            _pin: PhantomPinned,
        };

        Ok((Box::pin(o), stream))
    }

    fn start(&self) {
        let context = self as *const Self as *const c_void;

        IOHIDManagerRegisterDeviceMatchingCallback(
            &self.manager,
            MacDeviceMatcher::on_device_matching,
            context,
        );

        IOHIDManagerRegisterDeviceRemovalCallback(
            &self.manager,
            MacDeviceMatcher::on_device_removal,
            context,
        );

        IOHIDManagerScheduleWithRunLoop(&self.manager);
        IOHIDManagerOpen(&self.manager, kIOHIDManagerOptionNone).unwrap();

        trace!("Starting manager runloop");
        unsafe {
            CFRunLoopRun();
        }

        trace!("runloop done");
    }

    extern "C" fn on_device_matching(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        println!("on_device_matching");

        let this = unsafe { &mut *(context as *mut Self) };
        let device = device_ref.into();
        println!("device: {:?}", device);
        // tokio::spawn(async move {
        //     println!("matching thread ...");
        let _ = this
            .tx
            .blocking_send(WatchEvent::Added(USBDeviceInfoImpl { device }));
        // .await;
        // });

        // let _ = this
        //     .selector_sender
        //     .send(DeviceSelectorEvent::DevicesAdded(vec![device_ref]));
        // let selector_sender = this.selector_sender.clone();
        // let status_sender = this.status_sender.clone();
        // let (tx, rx) = channel();
        // let f = &this.new_device_cb;

        // // Create a new per-device runloop.
        // let runloop = RunLoop::new(move |alive| {
        //     // Ensure that the runloop is still alive.
        //     if alive() {
        //         f((device_ref, rx), selector_sender, status_sender, alive);
        //     }
        // });

        // if let Ok(runloop) = runloop {
        //     this.map.insert(device_ref, DeviceData { tx, runloop });
        // }
    }

    extern "C" fn on_device_removal(
        context: *mut c_void,
        _: IOReturn,
        _: *mut c_void,
        device_ref: IOHIDDeviceRef,
    ) {
        println!("on_device_removal");
        let this = unsafe { &mut *(context as *mut Self) };
        let device = device_ref.into();
        println!("device: {:?}", device);
        // tokio::spawn(async {
        let _ = this.tx.blocking_send(WatchEvent::Removed(device)); //.await;
                                                           // });

        // this.remove_device(device_ref);
    }

    extern "C" fn observe(_: CFRunLoopObserverRef, _: CFRunLoopActivity, context: *mut c_void) {
        println!("observe");
        let tx: &Sender<SendableRunLoop> = unsafe { &*(context as *mut _) };
        let runloop = SendableRunLoop::retain(unsafe { CFRunLoopGetCurrent() });
        println!("Got manager runloop, sending...");
        // Send the current runloop to the receiver to unblock it.
        // tokio::spawn(async {
        let _ = tx.blocking_send(runloop);
        // });
    }
}

// impl Stream for MacDeviceMatcher {
//     type Item = WatchEvent<USBDeviceInfoImpl>;

//     fn poll_next(
//         self: Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Option<Self::Item>> {
//         let stream = unsafe { self.map_unchecked_mut(|s| &mut s.stream) };
//         ReceiverStream::poll_next(stream, cx)
//     }
// }

#[derive(Debug)]
pub struct USBDeviceInfoImpl {
    device: IOHIDDevice,
}

#[async_trait]
impl USBDeviceInfo for USBDeviceInfoImpl {
    type Device = USBDeviceImpl;
    type Id = IOHIDDevice;

    async fn open(self) -> Result<Self::Device, WebauthnCError> {
        USBDeviceImpl::new(self).await
    }
}

pub struct USBDeviceImpl {
    info: USBDeviceInfoImpl,
    rx: mpsc::Receiver<HidReportBytes>,
    runloop: SendableRunLoop,
}

unsafe impl Send for USBDeviceImpl {}
unsafe impl Sync for USBDeviceImpl {}

impl fmt::Debug for USBDeviceImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("USBDeviceImpl")
            .field("info", &self.info)
            .finish()
    }
}

impl Drop for USBDeviceImpl {
    fn drop(&mut self) {
        unsafe { CFRunLoopStop(*self.runloop) }
    }
}

impl USBDeviceImpl {
    async fn new(info: USBDeviceInfoImpl) -> Result<Self, WebauthnCError> {
        trace!("Opening device: {info:?}");

        let device = info.device.clone();
        let (worker, rx) = MacUSBDeviceWorker::new(device);

        let (observer_tx, mut observer_rx) = mpsc::channel(1);

        thread::spawn(move || {
            trace!("started device thread");
            let context = &observer_tx as *const _ as *mut c_void;
            let obs = CFRunLoopEntryObserver::new(MacUSBDeviceWorker::observe, context);
            obs.add_to_current_runloop();
            worker.as_ref().start()
        });

        trace!("waiting for a runloop for device");
        let runloop: SendableRunLoop = observer_rx.recv().await.expect("failed to receive runloop");
        trace!("Got device runloop");

        let d = Self { info, rx, runloop };

        // let context = (&mut d) as *mut Self as *mut c_void;

        // unsafe {
        //     IOHIDDeviceRegisterInputReportCallback(
        //         &d.info.device,
        //         d.buf.as_mut_ptr(),
        //         d.buf.len().try_into().unwrap(),
        //         Self::on_input_report,
        //         context,
        //     );

        //     IOHIDDeviceScheduleWithRunLoop(
        //         &d.info.device,
        //     );

        //     IOHIDDeviceOpen(&d.info.device, 0).map_err(|e| {
        //         error!("IOHIDDeviceOpen return error: {e:?}");
        //         WebauthnCError::Internal
        //     })?;
        // }

        Ok(d)
    }

    // extern "C" fn on_input_report(
    //     context: *mut c_void,
    //     _: IOReturn,
    //     _: IOHIDDeviceRef,
    //     _: IOHIDReportType,
    //     _: u32,
    //     report: *mut u8,
    //     report_len: CFIndex,
    // ) {
    //     let this = unsafe { &mut *(context as *mut Self) };
    //     println!("on_input_report: len = {report_len}");
    //     let src_data = unsafe { from_raw_parts(report, report_len as usize) };
    //     let mut data: HidReportBytes = [0; size_of::<HidReportBytes>()];
    //     data.copy_from_slice(src_data);
    //     this.tx.blocking_send(data).unwrap();
    // }
}

struct MacUSBDeviceWorker {
    device: IOHIDDevice,
    // Receiver, from perspective of worker (authenticator -> initiator)
    rx: Sender<HidReportBytes>,
    _pin: PhantomPinned,
}

impl MacUSBDeviceWorker {
    fn new(device: IOHIDDevice) -> (Pin<Box<Self>>, Receiver<HidReportBytes>) {
        let (rx, tx) = mpsc::channel(16);
        // let (rx_a, rx_i) = mpsc::channel(16);

        (
            Box::pin(Self {
                device,
                rx,
                _pin: PhantomPinned,
            }),
            tx,
        )
    }

    fn start(&self) {
        let context = unsafe { self as *const Self as *const c_void };
        let mut buf = [0; size_of::<HidReportBytes>()];
        IOHIDDeviceRegisterInputReportCallback(
            &self.device,
            buf.as_mut_ptr(),
            buf.len().try_into().unwrap(),
            Self::on_input_report,
            context,
        );

        IOHIDDeviceScheduleWithRunLoop(&self.device);

        IOHIDDeviceOpen(&self.device, 0)
            .map_err(|e| {
                error!("IOHIDDeviceOpen return error: {e:?}");
                WebauthnCError::Internal
            })
            .unwrap();

        trace!("Starting device runloop");
        unsafe {
            CFRunLoopRun();
        }

        trace!("device runloop done");
        drop(buf);
    }

    extern "C" fn on_input_report(
        context: *mut c_void,
        _: IOReturn,
        _: IOHIDDeviceRef,
        _: IOHIDReportType,
        _: u32,
        report: *mut u8,
        report_len: CFIndex,
    ) {
        let this = unsafe { &mut *(context as *mut Self) };
        println!("on_input_report: len = {report_len}");
        let src_data = unsafe { from_raw_parts(report, report_len as usize) };
        let mut data: HidReportBytes = [0; size_of::<HidReportBytes>()];
        data.copy_from_slice(src_data);
        let _ = this.rx.blocking_send(data);
    }

    extern "C" fn observe(_: CFRunLoopObserverRef, _: CFRunLoopActivity, context: *mut c_void) {
        println!("observe usbdevice");
        let tx: &Sender<SendableRunLoop> = unsafe { &*(context as *mut _) };
        let runloop = SendableRunLoop::retain(unsafe { CFRunLoopGetCurrent() });
        println!("Got device runloop, sending...");

        // Send the current runloop to the receiver to unblock it.
        let _ = tx.blocking_send(runloop);
    }
}

#[async_trait]
impl USBDevice for USBDeviceImpl {
    type Info = USBDeviceInfoImpl;

    fn get_info(&self) -> &Self::Info {
        &self.info
    }

    async fn read(&mut self) -> Result<HidReportBytes, WebauthnCError> {
        let ret = self.rx.recv().await;
        ret.ok_or(WebauthnCError::Closed)
    }

    async fn write(&self, data: HidSendReportBytes) -> Result<(), WebauthnCError> {
        let report_id = data[0];
        let data = &data[if report_id == 0 { 1 } else { 0 }..];
        IOHIDDeviceSetReport(
            &self.info.device,
            kIOHIDReportTypeOutput,
            report_id.try_into().unwrap(),
            data,
        )
        .map_err(|e| {
            error!("IOHIDDeviceSetReport return error: {e}");
            WebauthnCError::ApduTransmission
        })
    }
}

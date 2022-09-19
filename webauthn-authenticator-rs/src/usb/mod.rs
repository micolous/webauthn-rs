mod framing;

use hidapi::{DeviceInfo, HidApi, HidDevice};
use crate::cbor::*;
use crate::transport::*;
use crate::error::WebauthnCError;
use crate::usb::framing::*;

// u2f_hid.h
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_U2FHID: u16 = 0x01;
const HID_RPT_SIZE: usize = 64;
const U2FHID_TRANS_TIMEOUT: i32 = 3000;

const TYPE_INIT: u8 = 0x80;
const U2FHID_MSG: u8 = TYPE_INIT | 0x03;
const U2FHID_INIT: u8 = TYPE_INIT | 0x06;
const U2FHID_ERROR: u8 = TYPE_INIT | 0x3f;
const CAPABILITY_NMSG: u8 = 0x08;

const CID_BROADCAST: u32 = 0xffffffff;

pub struct USBTransport {
    api: HidApi,
}

pub struct USBToken {
    device: HidDevice,
    cid: u32,
}

impl Default for USBTransport {
    fn default() -> Self {
        Self { api: HidApi::new().unwrap() }
    }
}

impl Transport for USBTransport {
    type Token = USBToken;

    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError> {
        Ok(self.api
            .device_list()
            .filter(|d| d.usage_page() == FIDO_USAGE_PAGE && d.usage() == FIDO_USAGE_U2FHID)
            .map(|d| d.open_device(&self.api).expect("Could not open device"))
            .map(|device| USBToken { device, cid: 0 })
            .collect())
    }
    
}

impl USBToken {
    fn send(&self, frame: &U2FHIDFrame) -> Result<(), WebauthnCError> {
        let d: Vec<u8> = frame.into();
        println!(">>> {:02x?}", d);
        self.device.write(&d).map_err(|e| WebauthnCError::Internal).map(|_| ())
    }

    fn recv(&self) -> Result<U2FHIDFrame, WebauthnCError> {
        let mut ret: Vec<u8> = vec![0; HID_RPT_SIZE];

        let len = self.device
            .read_timeout(&mut ret, U2FHID_TRANS_TIMEOUT)
            .map_err(|_| WebauthnCError::Internal)?;

        println!("<<< {:02x?}", &ret[..len]);

        U2FHIDFrame::try_from(&ret[..len])
    }
}

impl Token for USBToken {
    fn transmit<'a, C, R>(&self, cmd: C) -> Result<R, WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
    {
        todo!();
        // let apdus = cmd.to_short_apdus().unwrap();
        // let resp = self.transmit_chunks(&apdus)?;

        // // CTAP has its own extra status code over NFC in the first byte.
        // R::try_from(&resp.data[1..]).map_err(|e| {
        //     //error!("error: {:?}", e);
        //     WebauthnCError::Cbor
        // })
    }

    fn init(&mut self) -> Result<(), WebauthnCError> {
        let mut nonce: [u8; 8] = [0; 8];

        // TODO: rng.fill_bytes(&mut nonce);
        
        self.send(&U2FHIDFrame {
            cid: CID_BROADCAST,
            cmd: U2FHID_INIT,
            data: nonce.to_vec(),
        });

        todo!();
    }

    fn close(&self) -> Result<(), WebauthnCError> {
        todo!();
    }
}

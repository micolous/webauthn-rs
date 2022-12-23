//! ## Message framing
//!
//! ### Post-handshake message
//!
//! <https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/fido_tunnel_device.cc;l=368-395;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29>
//!
//! * Two protocol versions here, protocol 1 and protocol 0.
//! * Protocol 1 has a CBOR map:
//!   * 1: GetInfoResponse bytes
//!   * 2: linking info (optional)
//! * Protocol 0: Padded map (todo)

use crate::{
    ctap2::{commands::value_to_vec_u8, CBORResponse, GetInfoResponse},
    error::WebauthnCError,
};
use serde::Serialize;
use serde_cbor::{ser::to_vec_packed, Value};
use std::collections::BTreeMap;

/// Prefix byte for messages sent to the authenticator
///
/// Not used for protocol version 0
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageType {
    Shutdown = 0,
    Ctap = 1,
    Update = 2,
    Unknown,
}

impl From<u8> for MessageType {
    fn from(v: u8) -> Self {
        use MessageType::*;
        match v {
            0 => Shutdown,
            1 => Ctap,
            2 => Update,
            _ => Unknown,
        }
    }
}

pub const SHUTDOWN_COMMAND: CableCommand = CableCommand {
    protocol_version: 1,
    message_type: MessageType::Shutdown,
    data: vec![],
};

#[derive(Debug, PartialEq, Eq)]
pub struct CableCommand {
    pub protocol_version: u32,
    pub message_type: MessageType,
    pub data: Vec<u8>,
}

impl CableCommand {
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.protocol_version == 0 {
            return self.data.to_owned();
        }

        let mut o = self.data.to_owned();
        o.insert(0, self.message_type as u8);
        o
    }

    pub fn from_bytes(protocol_version: u32, i: &[u8]) -> Self {
        let message_type: MessageType = if protocol_version > 0 {
            i[0].into()
        } else {
            MessageType::Ctap
        };

        let data = if protocol_version == 0 { i } else { &i[1..] }.to_vec();

        Self {
            protocol_version,
            message_type,
            data,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(try_from = "BTreeMap<u32, Value>", into = "BTreeMap<u32, Value>")]
pub struct CablePostHandshake {
    pub info: GetInfoResponse,
    pub linking_info: Option<Vec<u8>>,
}

impl TryFrom<BTreeMap<u32, Value>> for CablePostHandshake {
    type Error = WebauthnCError;

    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        // trace!("raw = {:?}", raw);
        let info = raw
            .remove(&0x01)
            .and_then(|v| value_to_vec_u8(v, "0x01"))
            .ok_or(WebauthnCError::MissingRequiredField)?;
        let info = <GetInfoResponse as CBORResponse>::try_from(info.as_slice())?;

        let linking_info = raw.remove(&0x02).and_then(|v| value_to_vec_u8(v, "0x02"));

        Ok(Self { info, linking_info })
    }
}

impl From<CablePostHandshake> for BTreeMap<u32, Value> {
    fn from(h: CablePostHandshake) -> Self {
        let info = to_vec_packed(&h.info).unwrap();
        let mut o = BTreeMap::from([(0x01, Value::Bytes(info))]);

        if let Some(linking_info) = h.linking_info {
            o.insert(0x02, Value::Bytes(linking_info));
        }

        o
    }
}

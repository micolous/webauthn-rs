//! ## Message framing
//!
//! ### Post-handshake message
//!
//! https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/fido_tunnel_device.cc;l=368-395;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
//!
//! * Two protocol versions here, protocol 1 and protocol 0.
//! * Protocol 1 has a CBOR map:
//!   * 1: GetInfoResponse bytes
//!   * 2: linking info (optional)
//! * Protocol 0: Padded map (todo)

use crate::{ctap2::commands::value_to_vec_u8, error::WebauthnCError};
use serde::Serialize;
use serde_cbor::Value;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
#[serde(try_from = "BTreeMap<u32, Value>")]
pub struct CableFrame {
    pub payload: Vec<u8>,
    pub linking_info: Option<Vec<u8>>,
}

impl TryFrom<BTreeMap<u32, Value>> for CableFrame {
    type Error = WebauthnCError;

    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        // trace!("raw = {:?}", raw);
        let payload = raw
            .remove(&0x01)
            .and_then(|v| value_to_vec_u8(v, "0x01"))
            .ok_or(WebauthnCError::MissingRequiredField)?;

        let linking_info = raw.remove(&0x02).and_then(|v| value_to_vec_u8(v, "0x02"));

        Ok(Self {
            payload,
            linking_info,
        })
    }
}

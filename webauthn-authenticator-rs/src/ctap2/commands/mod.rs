//! CTAP 2 commands.
use serde::Serialize;
use serde_cbor::{ser::to_vec_packed, Value};
use std::collections::{BTreeMap, BTreeSet};

mod bio_enrollment;
mod client_pin;
mod config;
mod get_assertion;
mod get_info;
mod make_credential;
mod reset;
mod selection;

pub use self::bio_enrollment::*;
pub use self::client_pin::*;
pub use self::config::*;
pub use self::get_assertion::*;
pub use self::get_info::*;
pub use self::make_credential::*;
pub use self::reset::*;
pub use self::selection::*;
use crate::error::WebauthnCError;
use crate::transport::iso7816::ISO7816RequestAPDU;

const FRAG_MAX: usize = 0xF0;

/// Common trait for all CBOR responses.
///
/// Ths handles some of the response deserialization process.
pub trait CBORResponse: Sized + std::fmt::Debug + Send {
    fn try_from(i: &[u8]) -> Result<Self, WebauthnCError>;
}

/// Common trait for all CBOR commands.
///
/// This handles some of the command serialization process.
pub trait CBORCommand: Serialize + Sized + std::fmt::Debug + Send {
    /// CTAP comand byte
    const CMD: u8;

    /// If true (default), then the command has a payload, which will be
    /// serialized into CBOR format.
    ///
    /// If false, then the command has no payload.
    const HAS_PAYLOAD: bool = true;

    /// The response type associated with this command.
    type Response: CBORResponse;

    /// Converts a CTAP v2 command into a binary form.
    fn cbor(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        // CTAP v2.1, s8.2.9.1.2 (USB CTAPHID_CBOR), s8.3.5 (NFC framing).
        // Similar form used for caBLE.
        // TODO: BLE is different, it includes a u16 length after the command?
        if !Self::HAS_PAYLOAD {
            return Ok(vec![Self::CMD]);
        }

        trace!("Sending: {:?}", self);
        let mut b = to_vec_packed(self)?;
        trace!(
            "CBOR: cmd={}, cbor={:?}",
            Self::CMD,
            serde_cbor::from_slice::<'_, serde_cbor::Value>(&b[..])
        );

        b.reserve(1);
        b.insert(0, Self::CMD);
        Ok(b)
    }

    /// Converts a CTAP v2 command into a form suitable for transmission with
    /// short ISO/IEC 7816-4 APDUs (over NFC).
    #[deprecated]
    fn to_short_apdus(&self) -> Result<Vec<ISO7816RequestAPDU>, serde_cbor::Error> {
        let cbor = self.cbor()?;
       Ok(to_short_apdus(&cbor))
    }

    /// Converts a CTAP v2 command into a form suitable for transmission with
    /// extended ISO/IEC 7816-4 APDUs (over NFC).
    #[deprecated]
    fn to_extended_apdu(&self) -> Result<ISO7816RequestAPDU, serde_cbor::Error> {
        Ok(ISO7816RequestAPDU {
            cla: 0x80,
            ins: 0x10,
            p1: 0, // 0x80,  // client supports NFCCTAP_GETRESPONSE
            p2: 0x00,
            data: self.cbor()?,
            ne: 65536,
        })
    }
}

/// Converts a CTAP v2 command into a form suitable for transmission with
/// short ISO/IEC 7816-4 APDUs (over NFC).
pub fn to_short_apdus(cbor: &[u8]) -> Vec<ISO7816RequestAPDU> {
    let chunks = cbor.chunks(FRAG_MAX).rev();
    let mut o = Vec::with_capacity(chunks.len());
    let mut last = true;

    for chunk in chunks {
        o.insert(
            0,
            ISO7816RequestAPDU {
                cla: if last { 0x80 } else { 0x90 },
                ins: 0x10,
                p1: 0x00,
                p2: 0x00,
                data: chunk.to_vec(),
                ne: if last { 256 } else { 0 },
            },
        );
        last = false;
    }

    o
}

fn value_to_vec_string(v: Value, loc: &str) -> Option<Vec<String>> {
    if let Value::Array(v) = v {
        let mut x = Vec::with_capacity(v.len());
        for s in v.into_iter() {
            if let Value::Text(s) = s {
                x.push(s);
            } else {
                error!("Invalid value inside {}: {:?}", loc, s);
            }
        }
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_set_string(v: Value, loc: &str) -> Option<BTreeSet<String>> {
    if let Value::Array(v) = v {
        let mut x = BTreeSet::new();
        for s in v.into_iter() {
            if let Value::Text(s) = s {
                x.insert(s);
            } else {
                error!("Invalid value inside {}: {:?}", loc, s);
            }
        }
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

fn value_to_vec_u32(v: Value, loc: &str) -> Option<Vec<u32>> {
    if let Value::Array(v) = v {
        let x = v
            .into_iter()
            .filter_map(|i| {
                if let Value::Integer(i) = i {
                    u32::try_from(i)
                        .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
                        .ok()
                } else {
                    error!("Invalid type for {}: {:?}", loc, i);
                    None
                }
            })
            .collect();
        Some(x)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

pub(crate) fn value_to_u32(v: &Value, loc: &str) -> Option<u32> {
    if let Value::Integer(i) = v {
        u32::try_from(*i)
            .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
            .ok()
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

pub(crate) fn value_to_u64(v: &Value, loc: &str) -> Option<u64> {
    if let Value::Integer(i) = v {
        u64::try_from(*i)
            .map_err(|_| error!("Invalid value inside {}: {:?}", loc, i))
            .ok()
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

/// Converts a [Value::Bool] into [Option<bool>]. Returns `None` for other [Value] types.
pub(crate) fn value_to_bool(v: &Value, loc: &str) -> Option<bool> {
    if let Value::Bool(b) = v {
        Some(*b)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

/// Converts a [Value::Bytes] into [Option<Vec<u8>>]. Returns `None` for other [Value] types.
pub(crate) fn value_to_vec_u8(v: Value, loc: &str) -> Option<Vec<u8>> {
    if let Value::Bytes(b) = v {
        Some(b)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

pub(crate) fn value_to_string(v: Value, loc: &str) -> Option<String> {
    if let Value::Text(s) = v {
        Some(s)
    } else {
        error!("Invalid type for {}: {:?}", loc, v);
        None
    }
}

/// Type for commands which have no response data.
#[derive(Debug)]
pub struct NoResponse {}

impl CBORResponse for NoResponse {
    fn try_from(_raw: &[u8]) -> Result<Self, WebauthnCError> {
        Ok(Self {})
    }
}

// TODO: switch to #derive
#[macro_export]
macro_rules! deserialize_cbor {
    ($name:ident) => {
        impl $crate::ctap2::commands::CBORResponse for $name {
            fn try_from(i: &[u8]) -> Result<Self, $crate::error::WebauthnCError> {
                if i.is_empty() {
                    TryFrom::try_from(std::collections::BTreeMap::new()).map_err(|e| {
                        error!("Tried to deserialise empty input, got error: {:?}", e);
                        $crate::error::WebauthnCError::Cbor
                    })
                } else {
                    serde_cbor::from_slice(&i).map_err(|e| {
                        error!("deserialise: {:?}", e);
                        $crate::error::WebauthnCError::Cbor
                    })
                }
            }
        }
    };
}

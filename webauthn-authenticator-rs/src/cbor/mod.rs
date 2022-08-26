use serde::Serialize;
use serde_cbor::{from_slice, Value, value::to_value};
use std::collections::{BTreeMap, BTreeSet};
use webauthn_rs_proto::{PubKeyCredParams, RelyingParty, User};

#[cfg(feature = "nfc")]
use crate::nfc::{ISO7816RequestAPDU, FRAG_MAX};

mod get_info;
mod make_credential;

pub use self::get_info::*;
pub use self::make_credential::*;

pub trait CBORCommand: Serialize + Sized {
    /// CTAP comand byte
    const CMD: u8;

    /// If true (default), then the command has a payload, which will be
    /// serialized into CBOR format.
    ///
    /// If false, then the command has no payload.
    const HAS_PAYLOAD: bool = true;

    /// Converts a command into a binary form.
    fn cbor(self: &Self) -> Result<Vec<u8>, serde_cbor::Error> {
        // CTAP v2.1, s8.2.9.1.2 (USB CTAPHID_CBOR), s8.3.5 (NFC framing).
        // TODO: BLE is different, it includes a u16 length after the command?
        if !Self::HAS_PAYLOAD {
            return Ok(vec![Self::CMD]);
        }

        let b = serde_cbor::to_vec(self)?;
        let mut x = Vec::with_capacity(b.len() + 1);
        x.push(Self::CMD);
        x.extend_from_slice(&b);
        Ok(x)
    }

    /// Converts a command into a form suitable for transmission with short
    /// ISO/IEC 7816-4 APDUs.
    #[cfg(feature = "nfc")]
    fn to_short_apdus(&self) -> Result<Vec<ISO7816RequestAPDU>, serde_cbor::Error> {
        let cbor = self.cbor()?;
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

        Ok(o)
    }

    /// Converts a command into a form suitable for transmission with extended
    /// ISO/IEC 7816-4 APDUs.
    #[cfg(feature = "nfc")]
    fn to_extended_apdu(&self) -> Result<ISO7816RequestAPDU, serde_cbor::Error> {
        Ok(ISO7816RequestAPDU {
            cla: 0x80,
            ins: 0x10,
            p1: 0x00,
            p2: 0x00,
            data: self.cbor()?,
            ne: 0xFFFF,
        })
    }
}

trait ConversionFunc where Self: Sized {
    fn conv(v: Value, k: u32) -> Option<Self>;
    fn rev(v: Self) -> Value;
}

impl ConversionFunc for BTreeMap<String, bool> {
    fn conv(v: Value, k: u32) -> Option<BTreeMap<String, bool>> {
        if let Value::Map(v) = v {
            let mut x = BTreeMap::new();
            for (ka, va) in v.into_iter() {
                match (ka, va) {
                    (Value::Text(s), Value::Bool(b)) => {
                        x.insert(s, b);
                    }
                    _ => error!("Invalid value inside {}", k),
                }
            }
            Some(x)
        } else {
            error!("Invalid type for {}: {:?}", k, v);
            None
        }
    }
    fn rev(v: BTreeMap<String, bool>) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for BTreeSet<String> {
    fn conv(v: Value, k: u32) -> Option<BTreeSet<String>> {
        if let Value::Array(v) = v {
            let mut x = BTreeSet::new();
            for s in v.into_iter() {
                if let Value::Text(s) = s {
                    x.insert(s);
                } else {
                    error!("Invalid value inside {}: {:?}", k, s);
                }
            }
            Some(x)
        } else {
            error!("Invalid type for {}: {:?}", k, v);
            None
        }
    }
    fn rev(v: BTreeSet<String>) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for Vec<String> {
    fn conv(v: Value, k: u32) -> Option<Vec<String>> {
        if let Value::Array(v) = v {
            let mut x = Vec::with_capacity(v.len());
            for s in v.into_iter() {
                if let Value::Text(s) = s {
                    x.push(s);
                } else {
                    error!("Invalid value inside {}: {:?}", k, s);
                }
            }
            Some(x)
        } else {
            error!("Invalid type for {}: {:?}", k, v);
            None
        }
    }
    fn rev(v: Vec<String>) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for u32 {
    fn conv(v: Value, k: u32) -> Option<u32> {
        if let Value::Integer(i) = v {
            u32::try_from(i)
                .map_err(|_| error!("Invalid value inside {}: {:?}", k, i))
                .ok()
        } else {
            error!("Invalid type for {}: {:?}", k, v);
            None
        }
    }
    fn rev(v: u32) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for Vec<u32> {
    fn conv(v: Value, k: u32) -> Option<Vec<u32>> {
        if let Value::Array(v) = v {
            let x = v
                .into_iter()
                .filter_map(|i| {
                    if let Value::Integer(i) = i {
                        u32::try_from(i)
                            .map_err(|_| error!("Invalid value inside {}: {:?}", k, i))
                            .ok()
                    } else {
                        error!("Invalid type for {}: {:?}", k, i);
                        None
                    }
                })
                .collect();
            Some(x)
        } else {
            error!("Invalid type for {}: {:?}", k, v);
            None
        }
    }
    fn rev(v: Vec<u32>) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for Vec<u8> {
    fn conv(v: Value, k: u32) -> Option<Vec<u8>> {
        match v {
            Value::Bytes(x) => Some(x),
            _ => {
                error!("Invalid type for {}: {:?}", k, v);
                None
            }
        }
    }
    fn rev(v: Vec<u8>) -> Value {
        Value::Bytes(v)
    }
}

impl ConversionFunc for RelyingParty {
    fn conv(v: Value, k: u32) -> Option<RelyingParty> {
        unimplemented!();
    }
    fn rev(v: RelyingParty) -> Value {
        to_value(v).expect("oops RelyingParty")
    }
}

impl ConversionFunc for User {
    fn conv(v: Value, k: u32) -> Option<User> {
        unimplemented!();
    }
    fn rev(v: User) -> Value {
        let mut user_map = BTreeMap::new();
        info!("{:?}", v.id);
        user_map.insert(Value::Text("id".to_string()), Value::Bytes(v.id.0));
        user_map.insert(Value::Text("name".to_string()), Value::Text(v.name));
        user_map.insert(
            Value::Text("displayName".to_string()),
            Value::Text(v.display_name),
        );
        Value::Map(user_map)
    }
}
impl ConversionFunc for Vec<PubKeyCredParams> {
    fn conv(v: Value, k: u32) -> Option<Vec<PubKeyCredParams>> {
        unimplemented!();
    }
    fn rev(v: Vec<PubKeyCredParams>) -> Value {
        to_value(v).expect("oops PubKeyCredParams")
    }
}

impl ConversionFunc for Value {
    fn conv(v: Value, _k: u32) -> Option<Value> {
        Some(v)
    }
    fn rev(v: Value) -> Value {
        v
    }
}

/*
// TODO: switch to #derive
#[macro_export]
macro_rules! deserialize_cbor {
    ($name:ident) => {
        impl TryFrom<&[u8]> for $name {
            type Error = ();

            fn try_from(i: &[u8]) -> Result<Self, Self::Error> {
                from_slice(&i).map_err(|e| {
                    error!("deserialise: {:?}", e);
                    ()
                })
            }
        }
    };
}
*/

use serde::{Serialize, de::DeserializeOwned};
use serde_cbor::{from_slice, value::{from_value, to_value}, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use webauthn_rs_proto::{PubKeyCredParams, RelyingParty, User};

#[cfg(feature = "nfc")]
use crate::nfc::{ISO7816RequestAPDU, FRAG_MAX};

mod get_info;
mod make_credential;

pub use self::get_info::*;
pub use self::make_credential::*;

pub trait CBORCommand: Sized + Serialize {
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

trait ConversionFunc
where
    Self: Sized,
{
    type Error: Display;

    /// Deserializes a CBOR [Value] into a [Self].
    fn de(v: Value) -> Result<Self, Self::Error>;
    /// Serializes [Self] into a CBOR [Value].
    fn ser(v: Self) -> Value;
}

impl ConversionFunc for BTreeMap<String, bool> {
    type Error = &'static str;
    fn de(v: Value) -> Result<BTreeMap<String, bool>, Self::Error> {
        if let Value::Map(v) = v {
            let mut x = BTreeMap::new();
            for (ka, va) in v.into_iter() {
                match (ka, va) {
                    (Value::Text(s), Value::Bool(b)) => {
                        x.insert(s, b);
                    }
                    _ => return Err("Invalid value inside BTreeMap<String, bool>"),
                }
            }
            Ok(x)
        } else {
            Err("Invalid type for BTreeMap<String, bool>")
        }
    }
    fn ser(v: BTreeMap<String, bool>) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for BTreeSet<String> {
    type Error = &'static str;
    fn de(v: Value) -> Result<BTreeSet<String>, Self::Error> {
        if let Value::Array(v) = v {
            let mut x = BTreeSet::new();
            for s in v.into_iter() {
                if let Value::Text(s) = s {
                    x.insert(s);
                } else {
                    return Err("Invalid value inside");
                }
            }
            Ok(x)
        } else {
            Err("Invalid type for BTreeSet<String>")
        }
    }
    fn ser(v: BTreeSet<String>) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for Vec<String> {
    type Error = &'static str;
    fn de(v: Value) -> Result<Vec<String>, Self::Error> {
        if let Value::Array(v) = v {
            let mut x = Vec::with_capacity(v.len());
            for s in v.into_iter() {
                if let Value::Text(s) = s {
                    x.push(s);
                } else {
                    return Err("Invalid value in Vec<String>");
                }
            }
            Ok(x)
        } else {
            return Err("Invalid type for Vec<String>");
        }
    }
    fn ser(v: Vec<String>) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for u32 {
    type Error = &'static str;

    fn de(v: Value) -> Result<u32, Self::Error> {
        if let Value::Integer(i) = v {
            u32::try_from(i).map_err(|_| "Invalid value in u32")
        } else {
            Err("Invalid type for u32")
        }
    }
    fn ser(v: u32) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for Vec<u32> {
    type Error = &'static str;

    fn de(v: Value) -> Result<Vec<u32>, Self::Error> {
        if let Value::Array(v) = v {
            let x = v
                .into_iter()
                .filter_map(|i| {
                    if let Value::Integer(i) = i {
                        u32::try_from(i)
                            .map_err(|_| "Invalid value in Vec<u32>")
                            .ok()
                    } else {
                        error!("Invalid type: {:?}", i);
                        None
                    }
                })
                .collect();
            Ok(x)
        } else {
            Err("Invalid type for Vec<u32>")
        }
    }
    fn ser(v: Vec<u32>) -> Value {
        unimplemented!();
    }
}

impl ConversionFunc for Vec<u8> {
    type Error = &'static str;

    fn de(v: Value) -> Result<Vec<u8>, Self::Error> {
        match v {
            Value::Bytes(x) => Ok(x),
            _ => Err("Invalid type for Vec<u8>"),
        }
    }
    fn ser(v: Vec<u8>) -> Value {
        Value::Bytes(v)
    }
}

/*
impl<T> ConversionFunc for Vec<T>
where T: Serialize + DeserializeOwned
{
    type Error = &'static str;

    fn de(v: Value) -> Result<Vec<T>, Self::Error> {
        match v {
            Value::Array(a) => {
                let res: Result<Vec<T>, _> = a.into_iter().map(|i| from_value::<T>(i)).collect();
                res.map_err(|e| "Invalid type for element in Vec<T>")
            },
            _ => Err("Invalid type for Vec<T>")
        }        
        // if let Value::Array(v) = v {
        //     let x = v.into_iter()
        //             .map(|i| {
        //                 from_value::<T>(i)
        //             })
        //             .collect();
        //     Ok(x)
        // } else {
        //     Err("Invalid type for Vec<T>")
        // }

        // unimplemented!();
        // match v {
        //     Value::Bytes(x) => Ok(x),
        //     _ => Err("Invalid type for Vec<u8>"),
        // }
    }
    fn ser(v: Vec<T>) -> Value {
        Value::Array(
            v.into_iter().map(|i| to_value::<T>(i).unwrap()).collect()
        )
    }
}
*/

impl ConversionFunc for RelyingParty {
    type Error = &'static str;

    fn de(v: Value) -> Result<RelyingParty, Self::Error> {
        unimplemented!();
    }
    fn ser(v: RelyingParty) -> Value {
        to_value(v).expect("oops RelyingParty")
    }
}

impl ConversionFunc for User {
    type Error = &'static str;

    fn de(v: Value) -> Result<User, Self::Error> {
        unimplemented!();
    }
    fn ser(v: User) -> Value {
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
    type Error = &'static str;
    fn de(v: Value) -> Result<Vec<PubKeyCredParams>, Self::Error> {
        unimplemented!();
    }
    fn ser(v: Vec<PubKeyCredParams>) -> Value {
        to_value(v).expect("oops PubKeyCredParams")
    }
}

impl ConversionFunc for Value {
    type Error = &'static str;
    fn de(v: Value) -> Result<Value, Self::Error> {
        Ok(v)
    }
    fn ser(v: Value) -> Value {
        v
    }
}

use cbor_derive::CborMessage;
use serde::{Deserialize, Serialize};
use serde_cbor::Value;

use self::CBORCommand;
use super::*;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
#[derive(Serialize, Debug, Clone)]
pub struct GetInfoRequest {}

impl CBORCommand for GetInfoRequest {
    const CMD: u8 = 0x04;
    const HAS_PAYLOAD: bool = false;
}

#[derive(Deserialize, Debug, CborMessage)]
// #[derive(Deserialize, Debug)]
#[serde(try_from = "GetInfoResponseDict")]
pub struct GetInfoResponse {
    #[f(Value::Integer(0x1))]
    pub versions: Option<BTreeSet<String>>,
    #[f(Value::Integer(0x2))]
    pub extensions: Option<Vec<String>>,
    #[f(Value::Integer(0x3))]
    pub aaguid: Option<Vec<u8>>,
    #[f(Value::Integer(0x4))]
    pub options: Option<BTreeMap<String, bool>>,
    #[f(Value::Integer(0x5))]
    pub max_msg_size: Option<u32>,
    #[f(Value::Integer(0x6))]
    pub pin_protocols: Option<Vec<u32>>,
    #[f(Value::Integer(0x7))]
    pub max_cred_count_in_list: Option<u32>,
    #[f(Value::Integer(0x8))]
    pub max_cred_id_len: Option<u32>,
    #[f(Value::Integer(0x9))]
    pub transports: Option<Vec<String>>,
    #[f(Value::Integer(0xA))]
    pub algorithms: Option<Value>,
    /*
    let max_ser_large_blob = raw.keys.remove(&0x0B)
        .map(|v| );

    let force_pin_change = raw.keys.remove(&0x0C)
        .map(|v| );

    let min_pin_len = raw.keys.remove(&0x0D)
        .map(|v| );

    let firmware_version = raw.keys.remove(&0x0E)
        .map(|v| );

    let max_cred_blob_len = raw.keys.remove(&0x0F)
        .map(|v| );

    let max_rpid_for_set_min_pin_len = raw.keys.remove(&0x10)
        .map(|v| );

    let preferred_plat_uv_attempts = raw.keys.remove(&0x11)
        .map(|v| );

    let uv_modality = raw.keys.remove(&0x12)
        .map(|v| );

    let certifications = raw.keys.remove(&0x13)
        .map(|v| );

    let remaining_discoverable_credentials = raw.keys.remove(&0x14)
        .map(|v| );

    let vendor_prototype_config_cmds = raw.keys.remove(&0x15)
        .map(|v| );
    */
}

/*
#[derive(Serialize, Deserialize, Debug)]
struct GetInfoResponseDict {
    #[serde(flatten)]
    pub keys: BTreeMap<u32, serde_cbor::Value>,
}
impl TryFrom<GetInfoResponse> for GetInfoResponseDict {
    type Error = &'static str;

    fn try_from(value: GetInfoResponse) -> Result<Self, Self::Error> {
        let mut keys: BTreeMap<u32, serde_cbor::Value> = BTreeMap::new();
        value.versions.map(|v| {
            ConversionFunc::ser(v).map(|b| {
                keys.insert(0x01, b);
            })
        });
        value.extensions.map(|v| {
            ConversionFunc::ser(v).map(|b| {
                keys.insert(0x02, b);
            })
        });
        /*
        value.aaguid.map(|v| {
            keys.insert(0x03, ConversionFunc::ser(v)?);
        });
        value.options.map(|v| {
            keys.insert(0x04, ConversionFunc::ser(v)?);
        });
        value.max_msg_size.map(|v| {
            keys.insert(0x05, ConversionFunc::ser(v)?);
        });
        value.pin_protocols.map(|v| {
            keys.insert(0x06, ConversionFunc::ser(v)?);
        });
        value.max_cred_count_in_list.map(|v| {
            keys.insert(0x07, ConversionFunc::ser(v)?);
        });
        value.max_cred_id_len.map(|v| {
            keys.insert(0x08, ConversionFunc::ser(v)?);
        });
        value.transports.map(|v| {
            keys.insert(0x09, ConversionFunc::ser(v)?);
        });
        value.algorithms.map(|v| {
            keys.insert(0x0a, ConversionFunc::ser(v)?);
        });
        */
        Ok(GetInfoResponseDict { keys })
    }
}
impl TryFrom<GetInfoResponseDict> for GetInfoResponse {
    type Error = &'static str;
    fn try_from(mut raw: GetInfoResponseDict) -> Result<Self, Self::Error> {

        Ok(GetInfoResponse {
            versions: match raw.keys.remove(&0x01) {
                Some(v) => match ConversionFunc::de(v) {
                    Ok(d) => Some(d),
                    Err(e) => return Err(e),
                },
                None => None,
            },
            extensions: raw
                .keys
                .remove(&0x02)
                .and_then(|v| match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }),
            aaguid: raw
                .keys
                .remove(&0x03)
                .and_then(|v| match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }),
            options: raw
                .keys
                .remove(&0x04)
                .and_then(|v| match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }),
            max_msg_size: raw
                .keys
                .remove(&0x05)
                .and_then(|v| match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }),
            pin_protocols: raw
                .keys
                .remove(&0x06)
                .and_then(|v| match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }),
            max_cred_count_in_list: raw.keys.remove(&0x07).and_then(|v| {
                match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }
            }),
            max_cred_id_len: raw
                .keys
                .remove(&0x08)
                .and_then(|v| match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }),
            transports: raw
                .keys
                .remove(&0x09)
                .and_then(|v| match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }),
            algorithms: raw
                .keys
                .remove(&0x0a)
                .and_then(|v| match ConversionFunc::de(v) {
                    Ok(v) => v,
                    Err(e) => return e,
                }),
        })
    }
}
impl TryFrom<&[u8]> for GetInfoResponse {
    fn try_from(i: &[u8]) -> serde_cbor::error::Result<Self> {
        serde_cbor::from_slice(&i)
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_response_nfc_usb() {
        let _ = tracing_subscriber::fmt().try_init();

        let raw_apdu: Vec<u8> = vec![
            170, 1, 131, 102, 85, 50, 70, 95, 86, 50, 104, 70, 73, 68, 79, 95, 50, 95, 48, 108, 70,
            73, 68, 79, 95, 50, 95, 49, 95, 80, 82, 69, 2, 130, 107, 99, 114, 101, 100, 80, 114,
            111, 116, 101, 99, 116, 107, 104, 109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 3, 80,
            47, 192, 87, 159, 129, 19, 71, 234, 177, 22, 187, 90, 141, 185, 32, 42, 4, 165, 98,
            114, 107, 245, 98, 117, 112, 245, 100, 112, 108, 97, 116, 244, 105, 99, 108, 105, 101,
            110, 116, 80, 105, 110, 245, 117, 99, 114, 101, 100, 101, 110, 116, 105, 97, 108, 77,
            103, 109, 116, 80, 114, 101, 118, 105, 101, 119, 245, 5, 25, 4, 176, 6, 129, 1, 7, 8,
            8, 24, 128, 9, 130, 99, 110, 102, 99, 99, 117, 115, 98, 10, 130, 162, 99, 97, 108, 103,
            38, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162,
            99, 97, 108, 103, 39, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45,
            107, 101, 121,
        ];

        let a = GetInfoResponse::try_from(raw_apdu.as_slice()).expect("Falied to decode apdu");

        // Assert the content
        // info!(?a);

        let versions = a.versions.expect("versions missing");
        assert!(versions.len() == 3);
        assert!(versions.contains("U2F_V2"));
        assert!(versions.contains("FIDO_2_0"));
        assert!(versions.contains("FIDO_2_1_PRE"));

        assert!(a.extensions == Some(vec!["credProtect".to_string(), "hmac-secret".to_string()]));
        assert!(
            a.aaguid
                == Some(vec![47, 192, 87, 159, 129, 19, 71, 234, 177, 22, 187, 90, 141, 185, 32, 42])
        );

        let m = a.options.as_ref().unwrap();
        assert!(m.len() == 5);
        assert!(m.get("clientPin") == Some(&true));
        assert!(m.get("credentialMgmtPreview") == Some(&true));
        assert!(m.get("plat") == Some(&false));
        assert!(m.get("rk") == Some(&true));
        assert!(m.get("up") == Some(&true));

        assert!(a.max_msg_size == Some(1200));
        assert!(a.max_cred_count_in_list == Some(8));
        assert!(a.max_cred_id_len == Some(128));

        assert!(a.transports == Some(vec!["nfc".to_string(), "usb".to_string()]));
    }
}

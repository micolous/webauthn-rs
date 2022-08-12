use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, value::to_value, Value};

use self::CBORCommand;
use super::*;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
#[derive(Serialize, Debug, Clone)]
pub struct GetInfoRequest {}

impl CBORCommand for GetInfoRequest {
    const CMD: u8 = 0x04;
    const HAS_PAYLOAD: bool = false;
}

#[derive(Serialize, Deserialize, Debug)]
struct GetInfoResponseDict {
    #[serde(flatten)]
    pub keys: BTreeMap<u32, Value>,
}

#[derive(Deserialize, Debug)]
#[serde(try_from = "GetInfoResponseDict")]
pub struct GetInfoResponse {
    pub versions: BTreeSet<String>,
    pub extensions: Option<Vec<String>>,
    pub aaguid: Vec<u8>,
    pub options: Option<BTreeMap<String, bool>>,
    pub max_msg_size: Option<u32>,
    pub pin_protocols: Option<Vec<u32>>,
    pub max_cred_count_in_list: Option<u32>,
    pub max_cred_id_len: Option<u32>,
    pub transports: Option<Vec<String>>,
    pub algorithms: Option<Value>,
}

impl TryFrom<GetInfoResponseDict> for GetInfoResponse {
    type Error = &'static str;

    fn try_from(mut raw: GetInfoResponseDict) -> Result<Self, Self::Error> {
        let versions = raw
            .keys
            .remove(&0x01)
            .and_then(|v| value_to_set_string(v, "0x01"))
            .ok_or("0x01")?;

        let extensions = raw
            .keys
            .remove(&0x02)
            .and_then(|v| value_to_vec_string(v, "0x02"));

        let aaguid = raw
            .keys
            .remove(&0x03)
            .and_then(|v| match v {
                Value::Bytes(x) => Some(x),
                _ => {
                    error!("Invalid type for 0x03: {:?}", v);
                    None
                }
            })
            .ok_or("0x03")?;

        let options = raw.keys.remove(&0x04).and_then(|v| {
            if let Value::Map(v) = v {
                let mut x = BTreeMap::new();
                for (ka, va) in v.into_iter() {
                    match (ka, va) {
                        (Value::Text(s), Value::Bool(b)) => {
                            x.insert(s, b);
                        }
                        _ => error!("Invalid value inside 0x04"),
                    }
                }
                Some(x)
            } else {
                error!("Invalid type for 0x04: {:?}", v);
                None
            }
        });

        let max_msg_size = raw.keys.remove(&0x05).and_then(|v| value_to_u32(v, "0x05"));

        let pin_protocols = raw
            .keys
            .remove(&0x06)
            .and_then(|v| value_to_vec_u32(v, "0x06"));

        let max_cred_count_in_list = raw.keys.remove(&0x07).and_then(|v| value_to_u32(v, "0x07"));

        let max_cred_id_len = raw.keys.remove(&0x08).and_then(|v| value_to_u32(v, "0x08"));

        let transports = raw
            .keys
            .remove(&0x09)
            .and_then(|v| value_to_vec_string(v, "0x09"));

        let algorithms = raw.keys.remove(&0x0A);
        // .map(|v| );

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

        Ok(GetInfoResponse {
            versions,
            extensions,
            aaguid,
            options,
            max_msg_size,
            pin_protocols,
            max_cred_count_in_list,
            max_cred_id_len,
            transports,
            algorithms,
            /*
            max_ser_large_blob,
            force_pin_change,
            min_pin_len,
            firmware_version,
            max_cred_blob_len,
            max_rpid_for_set_min_pin_len,
            preferred_plat_uv_attempts,
            uv_modality,
            certifications,
            remaining_discoverable_credentials,
            vendor_prototype_config_cmds,
            */
        })
    }
}

impl TryFrom<&[u8]> for GetInfoResponse {
    type Error = ();

    fn try_from(rapdu: &[u8]) -> Result<Self, Self::Error> {
        if cfg!(debug) {
            let v: Result<Value, _> = from_slice(&rapdu);
            trace!("got APDU Value response: {:?}", v);
        }

        let agir = from_slice(&rapdu);
        trace!(?agir);
        agir.map_err(|e| ())
    }
}
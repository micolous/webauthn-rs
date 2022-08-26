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
#[serde(try_from = "GetInfoResponseDict")]
pub struct GetInfoResponse {
    #[cbor_field(0x01)]
    pub versions: Option<BTreeSet<String>>,
    #[cbor_field(0x02)]
    pub extensions: Option<Vec<String>>,
    #[cbor_field(0x03)]
    pub aaguid: Option<Vec<u8>>,
    #[cbor_field(0x04)]
    pub options: Option<BTreeMap<String, bool>>,
    #[cbor_field(0x05)]
    pub max_msg_size: Option<u32>,
    #[cbor_field(0x06)]
    pub pin_protocols: Option<Vec<u32>>,
    #[cbor_field(0x07)]
    pub max_cred_count_in_list: Option<u32>,
    #[cbor_field(0x08)]
    pub max_cred_id_len: Option<u32>,
    #[cbor_field(0x09)]
    pub transports: Option<Vec<String>>,
    #[cbor_field(0x0a)]
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

        assert!(a.versions.len() == 3);
        assert!(a.versions.contains("U2F_V2"));
        assert!(a.versions.contains("FIDO_2_0"));
        assert!(a.versions.contains("FIDO_2_1_PRE"));

        assert!(a.extensions == Some(vec!["credProtect".to_string(), "hmac-secret".to_string()]));
        assert!(
            a.aaguid
                == vec![47, 192, 87, 159, 129, 19, 71, 234, 177, 22, 187, 90, 141, 185, 32, 42]
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

use serde::{Deserialize, Serialize};


// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit

pub const ISO7816_STATUS_OK: [u8; 2] = [0x90, 0x00];

pub const APPLET_U2F_V2: [u8; 6] = [0x55, 0x32, 0x46, 0x5f, 0x56, 0x32];
pub const APPLET_FIDO_2_0: [u8; 8] = [0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30];
pub const APPLET_DF: [u8; 8] = [
    /* RID */ 0xA0, 0x00, 0x00, 0x06, 0x47, /* PIX */ 0x2F, 0x00, 0x01,
];

pub const FRAG_MAX: usize = 0xF0;
pub const MAX_SHORT_BUFFER_SIZE: usize = 256;
pub const MAX_EXT_BUFFER_SIZE: usize = 65536;


#[cfg(test)]
mod tests {
    //use super::*;
    use base64urlsafedata::Base64UrlSafeData;
    use serde_cbor::{from_slice, to_vec, Value};
    use webauthn_rs_proto::{RelyingParty, PubKeyCredParams, User};
    use crate::cbor::CBORCommand;
    use crate::cbor::get_info::*;
    use crate::cbor::make_credential::*;
    use crate::nfc::iso7816::*;

    #[test]
    fn nfc_apdu_authenticator_get_info() {
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

        let a = GetInfoResponse::try_from(raw_apdu.as_slice())
            .expect("Falied to decode apdu");

        // Assert the content
        info!(?a);

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

    #[test]
    fn nfc_apdu_authenticator_make_credential() {
        let _ = tracing_subscriber::fmt().try_init();

        // let map: BTreeMap<Value, Value> = BTreeMap::new();

        // clientDataHash 0x01
        // rp 0x02
        // user 0x03
        // pubKeyCredParams 0x04
        // excludeList 0x05
        // extensions 0x06
        // options 0x07
        // pinUvAuthParam 0x08
        // pinUvAuthProtocol 0x09
        // enterpriseAttestation 0x0A

        /*
        Dec 28 18:41:01.160  INFO webauthn_authenticator_rs::nfc::apdu::tests: got APDU Value response: Ok(Map(

        Integer(1): Bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Integer(1): Bytes([104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65]),
        Integer(2): Map({
            Text("id"): Text("test"),
            Text("name"): Text("test")
        }),
        Integer(2): Map({
            Text("id"): Text("test.ctap"),
            Text("name"): Text("test.ctap")
        }),
        Integer(3): Map({
            Text("id"): Bytes([116, 101, 115, 116]),
            Text("name"): Text("test"),
            Text("displayName"): Text("test")
        }),
        Integer(3): Map({
            Text("id"): Bytes([43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198, 10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140, 112]),
            Text("name"): Text("testctap@ctap.com"),
            Text("displayName"): Text("Test Ctap")
        }),
        Integer(4): Array([
            Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")})
        ])
        Integer(4): Array([
            Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-257), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-37), Text("type"): Text("public-key")})
        ]),
        // I think this is incorrect?
        Integer(6): Map({Text("hmac-secret"): Bool(true)}),
        // May need to set uv false?
        Integer(7): Map({Text("rk"): Bool(true)}),
        // Not needed
        Integer(8): Bytes([252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8]),
        // Not needed
        Integer(9): Integer(1)}))
        */

        // why is the a prepended 0x01?
        let bytes = vec![
            168, 1, 88, 32, 104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177,
            106, 226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65, 2, 162, 98, 105,
            100, 105, 116, 101, 115, 116, 46, 99, 116, 97, 112, 100, 110, 97, 109, 101, 105, 116,
            101, 115, 116, 46, 99, 116, 97, 112, 3, 163, 98, 105, 100, 88, 32, 43, 102, 137, 187,
            24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198, 10, 134, 27, 154, 123, 99,
            148, 105, 131, 224, 181, 119, 183, 140, 112, 100, 110, 97, 109, 101, 113, 116, 101,
            115, 116, 99, 116, 97, 112, 64, 99, 116, 97, 112, 46, 99, 111, 109, 107, 100, 105, 115,
            112, 108, 97, 121, 78, 97, 109, 101, 105, 84, 101, 115, 116, 32, 67, 116, 97, 112, 4,
            131, 162, 99, 97, 108, 103, 38, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105,
            99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 57, 1, 0, 100, 116, 121, 112, 101, 106,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 56, 36, 100, 116,
            121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 6, 161, 107, 104,
            109, 97, 99, 45, 115, 101, 99, 114, 101, 116, 245, 7, 161, 98, 114, 107, 245, 8, 80,
            252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8, 9, 1,
        ];

        let v: Result<Value, _> = from_slice(bytes.as_slice());
        info!("got APDU Value response: {:?}", v);

        let mc = MakeCredentialRequest {
            client_data_hash: vec![0; 32],
            rp: RelyingParty {
                name: "test".to_string(),
                id: "test".to_string(),
            },
            user: User {
                id: Base64UrlSafeData("test".as_bytes().into()),
                name: "test".to_string(),
                display_name: "test".to_string(),
            },
            pub_key_cred_params: vec![PubKeyCredParams {
                type_: "public-key".to_string(),
                alg: -7,
            }],
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let b = to_vec(&mc).unwrap();

        let v2: Result<Value, _> = from_slice(b.as_slice());
        info!("got APDU Value encoded: {:?}", v2);

        let pdu = mc.to_short_apdus();
        info!("got APDU: {:?}", pdu);
        info!("got inner APDU: {:?}", b);
    }
 
    #[test]
    fn get_authenticator_info() {
        let req = GetInfoRequest {};
        let ext = vec![0x80, 0x10, 0, 0, 0, 0, 1, 0x4, 0, 0xff, 0xff];

        assert_eq!(
            ext,
            req.to_extended_apdu().to_bytes(ISO7816LengthForm::Extended).unwrap()
        );

    }
}

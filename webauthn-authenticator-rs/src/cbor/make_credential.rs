use serde::{Deserialize, Serialize};
use serde_cbor::{value::to_value, Value};
use std::collections::BTreeMap;
use webauthn_rs_proto::{PubKeyCredParams, PublicKeyCredentialDescriptor, RelyingParty, User};
// use webauthn_rs_core::proto::{AttestationObject, Registration};

use crate::cbor::{value_to_bool, value_to_string, CBORCommand};

#[derive(Serialize, Debug, Clone)]
#[serde(into = "BTreeMap<u32, Value>")]
pub struct MakeCredentialRequest {
    pub client_data_hash: Vec<u8>,
    pub rp: RelyingParty,
    pub user: User,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub exclude_list: Vec<PublicKeyCredentialDescriptor>,
    // extensions:
    pub options: Option<BTreeMap<String, bool>>,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_proto: Option<u32>,
    pub enterprise_attest: Option<u32>,
}

impl CBORCommand for MakeCredentialRequest {
    const CMD: u8 = 0x01;
    // type Response = AttestationObject<Registration>;
    type Response = MakeCredentialResponse;
}

// Note: this needs to have the same names as AttestationObjectInner
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase", try_from = "BTreeMap<u32, Value>")]
pub struct MakeCredentialResponse {
    pub fmt: Option<String>,
    pub auth_data: Option<Value>,
    pub att_stmt: Option<Value>,
    pub epp_att: Option<bool>,
    pub large_blob_key: Option<Value>,
}

// impl CBORResponse for AttestationObject<Registration> {
//     fn try_from(i: &[u8]) -> Result<Self, WebauthnCError> {
//         TryFrom::<&[u8]>::try_from(i).map_err(|e| {
//             // TODO: propagate this properly
//             error!("WebauthnError: {:?}", e);
//             WebauthnCError::Internal
//         })
//     }
// }

impl From<MakeCredentialRequest> for BTreeMap<u32, Value> {
    fn from(value: MakeCredentialRequest) -> Self {
        let MakeCredentialRequest {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            options,
            pin_uv_auth_param,
            pin_uv_auth_proto,
            enterprise_attest: _,
        } = value;

        let mut keys = BTreeMap::new();

        keys.insert(0x01, Value::Bytes(client_data_hash));

        let rp_value = to_value(rp).expect("Unable to encode rp");
        keys.insert(0x2, rp_value);

        // Because of how webauthn-rs is made, we build this in a way that optimises for text, not
        // to ctap.
        let User {
            id,
            name,
            display_name,
        } = user;

        let mut user_map = BTreeMap::new();
        info!("{:?}", id);
        user_map.insert(Value::Text("id".to_string()), Value::Bytes(id.0));
        user_map.insert(Value::Text("name".to_string()), Value::Text(name));
        user_map.insert(
            Value::Text("displayName".to_string()),
            Value::Text(display_name),
        );

        let user_value = Value::Map(user_map);
        info!("{:?}", user_value);
        keys.insert(0x3, user_value);

        // let ps = Value::Array(pub_key_cred_params.iter().map(|p| {
        //     let mut m = BTreeMap::new();
        //     m.insert(Value::Text("type".to_string()), Value::Text(p.type_.clone()));
        //     m.insert(Value::Text("alg".to_string()), Value::Integer(p.alg as i128));
        //     Value::Map(m)
        // }).collect());

        let ps = to_value(pub_key_cred_params).expect("Unable to encode pub_key_cred_params");
        keys.insert(0x4, ps);

        if !exclude_list.is_empty() {
            keys.insert(
                0x05,
                Value::Array(
                    exclude_list
                        .iter()
                        .map(|a| {
                            let mut m = BTreeMap::from([
                                (
                                    Value::Text("type".to_string()),
                                    Value::Text(a.type_.to_owned()),
                                ),
                                (
                                    Value::Text("id".to_string()),
                                    Value::Bytes(a.id.0.to_owned()),
                                ),
                            ]);

                            if let Some(transports) = &a.transports {
                                let transports: Vec<Value> = transports
                                    .iter()
                                    .filter_map(|t| {
                                        None // TODO
                                    })
                                    .collect();

                                if !transports.is_empty() {
                                    m.insert(
                                        Value::Text("transports".to_string()),
                                        Value::Array(transports),
                                    );
                                }
                            }

                            Value::Map(m)
                        })
                        .collect(),
                ),
            );
        }

        if let Some(o) = options {
            let mut options_map = BTreeMap::new();
            for (option, value) in &o {
                options_map.insert(Value::Text(option.to_string()), Value::Bool(*value));
            }

            let options_value = Value::Map(options_map);
            keys.insert(0x7, options_value);
        }

        if let Some(p) = pin_uv_auth_param {
            keys.insert(0x08, Value::Bytes(p));
        }

        if let Some(p) = pin_uv_auth_proto {
            keys.insert(0x09, Value::Integer(p.into()));
        }

        keys
    }
}

impl TryFrom<BTreeMap<u32, Value>> for MakeCredentialResponse {
    type Error = &'static str;
    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        trace!(?raw);
        Ok(Self {
            fmt: raw.remove(&0x01).and_then(|v| value_to_string(v, "0x01")),
            auth_data: raw.remove(&0x02),
            att_stmt: raw.remove(&0x03),
            epp_att: raw.remove(&0x04).and_then(|v| value_to_bool(v, "0x04")),
            large_blob_key: raw.remove(&0x05),
        })
    }
}

crate::deserialize_cbor!(MakeCredentialResponse);

#[cfg(test)]
mod test {
    use std::num::ParseIntError;

    use crate::cbor::make_credential::*;
    use base64urlsafedata::Base64UrlSafeData;
    use serde_cbor::{from_slice, to_vec, Value};
    use webauthn_rs_proto::{PubKeyCredParams, RelyingParty, User};

    pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

    #[test]
    fn make_credential() {
        let _ = tracing_subscriber::fmt().try_init();

        // dropped 01 at start
        let b = "A8015820687134968222EC17202E42505F8ED2B16AE22F16BB05B88C25DB9E602645F14102A262696469746573742E63746170646E616D6569746573742E6374617003A362696458202B6689BB18F4169F069FBCDF50CB6EA3C60A861B9A7B63946983E0B577B78C70646E616D6571746573746374617040637461702E636F6D6B646973706C61794E616D65695465737420437461700483A263616C672664747970656A7075626C69632D6B6579A263616C6739010064747970656A7075626C69632D6B6579A263616C67382464747970656A7075626C69632D6B657906A16B686D61632D736563726574F507A162726BF50850FC43AAA411D948CC6C37068B8DA1D5080901";
        let b = decode_hex(b).expect("bad");
        info!("canonical thhing = {:?}", b);
        let _v: Value = from_slice(&b[..]).expect("also bad");
        /* Ok(Map({
        Integer(1): Bytes([104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66, 80, 95, 142, 210, 177, 106, 226, 47, 22, 187, 5, 184, 140, 37, 219, 158, 96, 38, 69, 241, 65]),
        Integer(2): Map({Text("id"): Text("test.ctap"), Text("name"): Text("test.ctap")}),
        Integer(3): Map({Text("id"): Bytes([43, 102, 137, 187, 24, 244, 22, 159, 6, 159, 188, 223, 80, 203, 110, 163, 198, 10, 134, 27, 154, 123, 99, 148, 105, 131, 224, 181, 119, 183, 140, 112]),
            Text("name"): Text("testctap@ctap.com"), Text("displayName"): Text("Test Ctap")}),
        Integer(4): Array([
            Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-257), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-37), Text("type"): Text("public-key")})]),
        Integer(6): Map({Text("hmac-secret"): Bool(true)}),
        Integer(7): Map({Text("rk"): Bool(true)}),
        Integer(8): Bytes([252, 67, 170, 164, 17, 217, 72, 204, 108, 55, 6, 139, 141, 161, 213, 8]),
        Integer(9): Integer(1)}))

        will send = Ok(Map({
        Integer(1): Bytes([148, 145, 139, 124, 8, 224, 156, 143, 91, 32, 250, 54, 89, 205, 14, 229, 185, 87, 249, 200, 63, 52, 60, 28, 179, 209, 104, 241, 133, 181, 28, 208]),
        Integer(2): Map({Text("id"): Text("localhost"), Text("name"): Text("https://localhost:8080/auth")}),
        Integer(3): Map({Text("id"): Bytes([158, 170, 228, 89, 68, 28, 73, 194, 134, 19, 227, 153, 107, 220, 150, 238]),
            Text("name"): Text("william"), Text("displayName"): Text("william")}),
        Integer(4): Array([
            Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")}),
            Map({Text("alg"): Integer(-257), Text("type"): Text("public-key")})])}))
        */
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

        // Response APDU has a prepended 0x01 (error code)
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
            exclude_list: vec![],
            pin_uv_auth_param: None,
            pin_uv_auth_proto: None,
            enterprise_attest: None,
        };

        let b = to_vec(&mc).unwrap();

        let v2: Result<Value, _> = from_slice(b.as_slice());
        info!("got APDU Value encoded: {:?}", v2);

        // let pdu = mc.to_short_apdus();
        // info!("got APDU: {:?}", pdu);
        info!("got inner APDU: {:?}", b);
    }
}

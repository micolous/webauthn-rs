
use serde::{Deserialize, Serialize};
use serde_cbor::{value::to_value, Value};
use std::collections::{BTreeMap};
use webauthn_rs_proto::{PubKeyCredParams, RelyingParty, User};

use super::CBORCommand;

#[derive(Serialize, Deserialize, Debug)]
struct MakeCredentialRequestRawDict {
        #[serde(flatten)]
        pub keys: BTreeMap<u32, Value>,
    }
    

#[derive(Serialize, Debug, Clone)]
#[serde(into = "MakeCredentialRequestRawDict")]
pub struct MakeCredentialRequest {
    pub(crate) client_data_hash: Vec<u8>,
    pub(crate) rp: RelyingParty,
    pub(crate) user: User,
    pub(crate) pub_key_cred_params: Vec<PubKeyCredParams>,
    // exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    // extensions:
    pub(crate) options: Option<BTreeMap<String, bool>>,
    pub(crate) pin_uv_auth_param: Option<Vec<u8>>,
    pub(crate) pin_uv_auth_proto: Option<u32>,
    pub(crate) enterprise_attest: Option<u32>,
}

impl CBORCommand for MakeCredentialRequest {
    const CMD: u8 = 0x01;
}

impl From<MakeCredentialRequest> for MakeCredentialRequestRawDict {
    fn from(value: MakeCredentialRequest) -> Self {
        let MakeCredentialRequest {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            options,
            pin_uv_auth_param,
            pin_uv_auth_proto,
            enterprise_attest,
        } = value;

        let mut keys = BTreeMap::new();

        keys.insert(0x1, Value::Bytes(client_data_hash));

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

        let pub_key_cred_params_value =
            to_value(pub_key_cred_params).expect("Unable to encode pub_key_cred_params");
        keys.insert(0x4, pub_key_cred_params_value);

        /*
        let mut options_map = BTreeMap::new();
        options_map.insert(Value::Text("rk".to_string()), Value::Bool(false));
        let options_value = Value::Map(options_map);
        keys.insert(0x7, options_value);
        */
        MakeCredentialRequestRawDict { keys }
    }
}

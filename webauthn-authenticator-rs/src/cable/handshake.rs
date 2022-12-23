use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcKeyRef, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::Public,
};
use serde::Serialize;
use serde_cbor::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    cable::{base10, CableRequestType},
    ctap2::commands::{
        value_to_bool, value_to_string, value_to_u32, value_to_u64, value_to_vec_u8,
    },
    error::WebauthnCError,
};

use super::discovery::Discovery;

#[derive(Serialize, Debug, Clone)]
#[serde(into = "BTreeMap<u32, Value>", try_from = "BTreeMap<u32, Value>")]
pub struct HandshakeV2 {
    pub(super) peer_identity: EcKey<Public>,
    secret: [u8; 16],
    known_domains_count: u32,
    timestamp: SystemTime,
    supports_linking_info: bool,
    request_type: CableRequestType,
    supports_non_discoverable_make_credential: bool,
}

impl From<HandshakeV2> for BTreeMap<u32, Value> {
    fn from(value: HandshakeV2) -> Self {
        let HandshakeV2 {
            peer_identity,
            secret,
            known_domains_count,
            timestamp,
            supports_linking_info,
            request_type,
            supports_non_discoverable_make_credential,
        } = value;

        let mut o = BTreeMap::from([
            (1, Value::Bytes(secret.to_vec())),
            (2, Value::Integer(known_domains_count.into())),
            (
                3,
                Value::Integer(
                    timestamp
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .into(),
                ),
            ),
            // Chrome omits this field when false, but Safari always includes it.
            // Presence of this field = v2.1, missing = v2.0
            (4, Value::Bool(supports_linking_info)),
            (5, Value::Text(request_type.to_string())),
        ]);

        if let Ok(v) = compress_public_key(peer_identity.as_ref()) {
            o.insert(0, Value::Bytes(v));
        }

        if supports_non_discoverable_make_credential
            && request_type == CableRequestType::MakeCredential
        {
            o.insert(6, Value::Bool(true));
        }

        o
    }
}

impl TryFrom<BTreeMap<u32, Value>> for HandshakeV2 {
    type Error = WebauthnCError;

    fn try_from(mut raw: BTreeMap<u32, Value>) -> Result<Self, Self::Error> {
        // trace!(?raw);
        let peer_identity = raw
            .remove(&0)
            .and_then(|v| value_to_vec_u8(v, "0x00"))
            .ok_or(WebauthnCError::MissingRequiredField)?;

        let peer_identity = decompress_public_key(
            peer_identity
                .try_into()
                // TODO: better error
                .map_err(|_| WebauthnCError::Internal)?,
        )?;

        let secret = raw
            .remove(&1)
            .and_then(|v| value_to_vec_u8(v, "0x01"))
            .ok_or(WebauthnCError::MissingRequiredField)?
            .try_into()
            // TODO: better error
            .map_err(|_| WebauthnCError::InvalidAlgorithm)?;

        let known_domains_count = raw
            .remove(&2)
            .and_then(|v| value_to_u32(&v, "0x02"))
            .unwrap_or_default();

        let timestamp = raw
            .remove(&3)
            .and_then(|v| value_to_u64(&v, "0x03"))
            .unwrap_or_default();
        let timestamp = UNIX_EPOCH + Duration::from_secs(timestamp);

        let supports_linking_info = raw
            .remove(&4)
            .and_then(|v| value_to_bool(&v, "0x04"))
            .unwrap_or_default();

        let supports_non_discoverable_make_credential = raw
            .remove(&6)
            .and_then(|v| value_to_bool(&v, "0x06"))
            .unwrap_or_default();

        let request_type = raw
            .remove(&5)
            .and_then(|v| value_to_string(v, "0x05"))
            .and_then(|v| {
                CableRequestType::from_string(v.as_str(), supports_non_discoverable_make_credential)
            })
            .unwrap_or_default();

        Ok(Self {
            peer_identity,
            secret,
            known_domains_count,
            timestamp,
            supports_linking_info,
            request_type,
            supports_non_discoverable_make_credential,
        })
    }
}

fn compress_public_key(key: &EcKeyRef<Public>) -> Result<Vec<u8>, WebauthnCError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    Ok(key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?)
}

fn decompress_public_key(bytes: [u8; 33]) -> Result<EcKey<Public>, WebauthnCError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, &bytes, &mut ctx)?;
    Ok(EcKey::from_public_key(&group, &point)?)
}

const URL_PREFIX: &str = "FIDO:/";

impl HandshakeV2 {
    pub fn new(
        request_type: CableRequestType,
        public_key: EcKey<Public>,
        qr_key: [u8; 16],
    ) -> Result<Self, WebauthnCError> {
        Ok(Self {
            peer_identity: public_key,
            secret: qr_key,
            // TODO: set to the real number
            known_domains_count: 2,
            timestamp: SystemTime::now(),
            supports_linking_info: false,
            request_type,
            supports_non_discoverable_make_credential: false,
        })
    }

    /// Encodes a [HandshakeV2] into a `FIDO:/` QR code.
    pub fn to_qr_url(&self) -> Result<String, WebauthnCError> {
        let payload: Vec<u8> =
            serde_cbor::ser::to_vec_packed(self).map_err(|_| WebauthnCError::Cbor)?;
        Ok(format!("{}{}", URL_PREFIX, base10::encode(&payload)))
    }

    /// Decodes a `FIDO:/` QR code into a [HandshakeV2].
    pub fn from_qr_url(url: &str) -> Result<Self, WebauthnCError> {
        let url = url.to_ascii_uppercase();
        if !url.starts_with(URL_PREFIX) || url.len() <= URL_PREFIX.len() {
            return Err(WebauthnCError::InvalidCableUrl);
        }

        let (_, payload) = url.split_at(URL_PREFIX.len());
        let payload = base10::decode(payload)?;
        let v: BTreeMap<u32, Value> =
            serde_cbor::from_slice(&payload).map_err(|_| WebauthnCError::Cbor)?;

        Ok(Self::try_from(v)?)
    }

    /// Converts a [HandshakeV2] payload (from a QR code) into a [Discovery]
    /// which can be used to respond to the request.
    pub fn to_discovery(&self) -> Result<Discovery, WebauthnCError> {
        Discovery::new_with_qr_secret(self.request_type, self.secret.to_owned())
    }
}

// https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/fido_tunnel_device.cc;l=152-159;drc=de9f16dcca1d5057ba55973fa85a5b27423d414f
// #[derive(Serialize, Debug, Clone)]
// #[serde(into = "BTreeMap<u32, Value>", try_from = "BTreeMap<u32, Value>")]
// pub struct ClientPayload {

// }

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn invalid_urls() {
        let _ = tracing_subscriber::fmt::try_init();

        use base10::DecodeError::*;
        use WebauthnCError::*;
        const URLS: [(&str, WebauthnCError); 7] = [
            ("http://example.com", InvalidCableUrl),
            ("fido:/", InvalidCableUrl),
            ("FIDO:/", InvalidCableUrl),
            ("FIDO://", Base10(ContainsNonDigitChars)),
            ("FIDO:/0", Base10(InvalidLength)),
            ("FIDO:/999", Base10(OutOfRange)),
            ("FIDO:/000", Cbor),
        ];

        for (u, e) in URLS {
            assert_eq!(Some(e), HandshakeV2::from_qr_url(u).err(), "url = {:?}", u);
        }
    }

    #[test]
    fn decode_chrome() {
        let _ = tracing_subscriber::fmt::try_init();

        // URL generated by Chrome
        let u = "FIDO:/162870791865632382552704231438327900152302540348097243854039966655366469794954476199158014113179232779520163209900691930075274801398564434658077048963842109321447142660";
        // let u = "FIDO:/4787604395760042106536043794938323598327797147779146960611161750662522396426829068078002995108866343660518517380208956200713956672233682060445840162168341668112901";

        let h = HandshakeV2::from_qr_url(u).unwrap();
        trace!(?h);

        // Can we round-trip the handshake?
        let e = h.to_qr_url().unwrap();
        assert_eq!(e.as_str(), u);
    }

    #[test]
    fn decode_safari_ios() {
        let _ = tracing_subscriber::fmt::try_init();

        let u = "FIDO:/089962132878132862898875319509818655951233947060166026934941652203853844930597225184066237811614893181300344014421205790072080843938838513707157859599106109321447142404";
        let h = HandshakeV2::from_qr_url(u).unwrap();
        trace!(?h);

        // Can we round-trip the handshake?
        let e = h.to_qr_url().unwrap();
        assert_eq!(e.as_str(), u);
    }

    // #[test]
    // fn new() {
    //     use qrcode::render::unicode;
    //     let k = HandshakeV2::new(CableRequestType::DiscoverableMakeCredential).unwrap();
    //     println!("handshake: {:?}", k);
    //     let url = k.to_qr_url().unwrap();
    //     println!("url: {}", url);
    //     let qr = qrcode::QrCode::new(url).unwrap();

    //     let code = qr
    //         .render::<unicode::Dense1x2>()
    //         .dark_color(unicode::Dense1x2::Light)
    //         .light_color(unicode::Dense1x2::Dark)
    //         .build();
    //     println!("{}", code);

    //     // HandshakeV2 {
    //     //  peer_identity: EcKey,
    //     //  secret: [103, 16, 1, 90, 124, 146, 90, 227, 107, 18, 210, 96, 213, 253, 86, 137],
    //     //  known_domains_count: 2,
    //     //  timestamp: SystemTime { intervals: 133140997330000000 },
    //     //  supports_linking_info: false,
    //     //  request_type: DiscoverableMakeCredential,
    //     //  supports_non_discoverable_make_credential: false
    //     // }
    //     // FIDO:/4787604395760042106536043794938323598327797147779146960611161750662522396426829068078002995108866343660518517380208956200713956672233682060445840162168341668112901
    //     // ServiceDataAdvertisement: PeripheralId(xxxx), {0000fff9-0000-1000-8000-00805f9b34fb: [30, 138, 234, 166, 182, 229, 66, 202, 62, 60, 202, 84, 115, 151, 207, 203, 17, 168, 61, 116]}
    // }
}

//! Tunnel functions

use futures::{SinkExt, StreamExt};
use openssl::ec::{EcKeyRef, EcPointRef, PointConversionForm};
use snow::{Builder, HandshakeState};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderValue, Request, Uri},
        Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use crate::{
    cable::noise::{get_params, get_resolver},
    prelude::WebauthnCError,
    util::compute_sha256,
};

use super::*;

/// Well-known domains.
///
/// Source: <https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=123-125;drc=6767131b3528fefd866f604b32ebbb278c35d395>
const ASSIGNED_DOMAINS: [&str; 2] = [
    // Google
    "cable.ua5v.com",
    // Apple
    "cable.auth.com",
];

const TUNNEL_SERVER_SALT: &[u8] = "caBLEv2 tunnel server domain\0\0\0".as_bytes();
const TUNNEL_SERVER_ID_OFFSET: usize = TUNNEL_SERVER_SALT.len() - 3;
const TUNNEL_SERVER_TLDS: [&str; 4] = [".com", ".org", ".net", ".info"];
const BASE32_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const NOISE_KN_PROTOCOL: &str = "Noise_KNpsk0_P256_AESGCM_SHA256";
const NOISE_NK_PROTOCOL: &str = "Noise_NKpsk0_P256_AESGCM_SHA256";

/// Decodes a `domain_id` into an actual domain name.
///
/// See Chromium's `tunnelserver::DecodeDomain`.
pub fn get_domain(domain_id: u16) -> Option<String> {
    if domain_id < 256 {
        return match ASSIGNED_DOMAINS.get(usize::from(domain_id)) {
            Some(d) => Some(d.to_string()),
            None => None,
        };
    }

    let mut buf = TUNNEL_SERVER_SALT.to_vec();
    buf[TUNNEL_SERVER_ID_OFFSET..TUNNEL_SERVER_ID_OFFSET + 2]
        .copy_from_slice(&domain_id.to_le_bytes());
    let digest = compute_sha256(&buf);
    let mut result = u64::from_le_bytes(digest[..8].try_into().ok()?);

    let tld = TUNNEL_SERVER_TLDS[(result & 3) as usize];

    let mut o = String::from("cable.");
    result = result >> 2;
    while result != 0 {
        o.push(char::from_u32(BASE32_CHARS[(result & 31) as usize].into())?);
        result = result >> 5;
    }
    o.push_str(tld);

    Some(o)
}

pub struct Tunnel<'a> {
    psk: Psk,
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    local_identity: &'a EcKeyRef<Private>,
    noise: HandshakeState,
}

impl<'a> Tunnel<'a> {
    pub async fn connect(
        uri: &Uri,
        psk: Psk,
        local_identity: &'a EcKeyRef<Private>,
    ) -> Result<Tunnel<'a>, WebauthnCError> {
        let mut request = IntoClientRequest::into_client_request(uri).unwrap();

        let headers = request.headers_mut();
        headers.insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("fido.cable"),
        );
        let origin = format!("wss://{}", uri.host().unwrap_or_default());
        headers.insert("Origin", HeaderValue::from_str(&origin).unwrap());

        trace!(?request);
        let (mut stream, response) = connect_async(request).await.map_err(|e| {
            error!("websocket error: {:?}", e);
            WebauthnCError::Internal
        })?;
        trace!(?response);

        let mut noise = Builder::with_resolver(get_params(), get_resolver())
            .prologue(&[1])
            .local_private_key(&local_identity.private_key_to_der()?)
            .psk(0, &psk)
            .build_initiator()
            .unwrap();

        let mut msg = [0; 65535];
        let len = noise.write_message(&[], &mut msg).unwrap();

        trace!(">>> {:02x?}", &msg[..len]);
        //let s = stream.get_mut();
        stream
            .send(Message::Binary((&msg[..len]).to_vec()))
            .await
            .unwrap();

        // Handshake sent, get response
        let resp = stream.next().await.unwrap().unwrap();
        //let len = s.read(&mut msg).await.unwrap();
        //trace!("<<< {:02x?}", &msg[..len]);
        trace!("<<< {:?}", resp);
        if let Message::Binary(v) = resp {
            if v.len() < 65 {
                warn!("too short response? got {} bytes", len);
            }
            // this is 81 bytes

            let mut payload = [0; 65535];
            let len = noise.read_message(&v, &mut payload).unwrap();
            if len != 0 {
                panic!(
                    "expected handshake to be empty, got {} bytes: {:02x?}",
                    len,
                    &payload[..len]
                );
            }
        }
        // Waiting for post-handshake message

        let t = Self {
            psk,
            stream,
            local_identity,
            noise,
        };

        Ok(t)
    }
}

fn point_to_bytes(point: &EcPointRef) -> Result<Vec<u8>, WebauthnCError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    Ok(point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_known_tunnel_server_domains() {
        assert_eq!(get_domain(0), Some(String::from("cable.ua5v.com")));
        assert_eq!(get_domain(1), Some(String::from("cable.auth.com")));
        assert_eq!(
            get_domain(266),
            Some(String::from("cable.wufkweyy3uaxb.com"))
        );

        assert_eq!(get_domain(255), None);

        // 🦀 = \u{1f980}
        assert_eq!(
            get_domain(0xf980),
            Some(String::from("cable.my4kstlhndi4c.net"))
        )
    }

    #[test]
    fn check_all_hashed_tunnel_servers() {
        for x in 256..u16::MAX {
            assert_ne!(get_domain(x), None);
        }
    }
}

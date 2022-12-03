//! Tunnel functions

use tokio_tungstenite::{connect_async, tungstenite::{http::{Request, Uri, HeaderValue}, client::IntoClientRequest}};

use crate::{util::compute_sha256, prelude::WebauthnCError};

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
const BASE32_CHARS: &[u8] = "abcdefghijklmnopqrstuvwxyz234567".as_bytes();

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

pub struct Tunnel {
}

impl Tunnel {
    pub async fn connect(uri: &Uri) -> Result<Self, WebauthnCError> {
        let mut request = IntoClientRequest::into_client_request(uri).unwrap();

        let headers = request.headers_mut();
        headers.insert("Sec-WebSocket-Protocol", HeaderValue::from_static("fido.cable"));
        let origin = format!("wss://{}", uri.host().unwrap_or_default());
        headers.insert("Origin", HeaderValue::from_str(&origin).unwrap());

        trace!(?request);
        let (stream, response) = connect_async(request).await.map_err(|e| {
            error!("websocket error: {:?}", e);
            WebauthnCError::Internal
        })?;
        trace!(?response);

        // TODO: build initial handshake message
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=880;drc=de9f16dcca1d5057ba55973fa85a5b27423d414f
        todo!()
    }
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
        assert_eq!(get_domain(0xf980), Some(String::from("cable.my4kstlhndi4c.net")))
    }

    #[test]
    fn check_all_hashed_tunnel_servers() {
        for x in 256..u16::MAX {
            assert_ne!(get_domain(x), None);
        }
    }
}

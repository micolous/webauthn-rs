//! Tunnel functions

use futures::{SinkExt, StreamExt};
use openssl::{ec::{EcKeyRef, EcPointRef, PointConversionForm, EcPoint}, pkey_ctx::PkeyCtx};
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
    cable::{noise::{CableNoise, HandshakeType, get_public_key_bytes}, crypter::Crypter},
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
    noise: CableNoise,
    ephemeral_key: EcKey<Private>,
    crypter: Crypter,
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

        // BuildInitialMessage
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=880;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        let mut noise = CableNoise::new(HandshakeType::KNpsk0);
        let prologue = [1];
        noise.mix_hash(&prologue);
        noise.mix_hash_point(&local_identity.public_key())?;

        noise.mix_key_and_hash(&psk)?;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ephemeral_key = EcKey::generate(&group)?;

        let ephemeral_key_public_bytes = get_public_key_bytes(&ephemeral_key.as_ref());
        assert_eq!(ephemeral_key_public_bytes.len(), 65);

        noise.mix_hash(&ephemeral_key_public_bytes);
        noise.mix_key(&ephemeral_key_public_bytes)?;

        let ct = noise.encrypt_and_hash(&[])?;

        let mut handshake_message = Vec::with_capacity(ephemeral_key_public_bytes.len() + ct.len());
        handshake_message.extend_from_slice(&ephemeral_key_public_bytes);
        handshake_message.extend_from_slice(&ct);

        // let mut noise = Builder::with_resolver(get_params(), get_resolver())
        //     .prologue(&[1])
        //     .local_private_key(&local_identity.private_key_to_der()?)
        //     .psk(0, &psk)
        //     .build_initiator()
        //     .unwrap();

        // let mut msg = [0; 65535];
        // let len = noise.write_message(&[], &mut msg).unwrap();

        trace!(">>> {:02x?}", &handshake_message);
        //let s = stream.get_mut();
        stream
            .send(Message::Binary(handshake_message))
            .await
            .unwrap();

        // Handshake sent, get response
        let resp = stream.next().await.unwrap().unwrap();
        //let len = s.read(&mut msg).await.unwrap();
        //trace!("<<< {:02x?}", &msg[..len]);
        trace!("<<< {:?}", resp);
        if let Message::Binary(v) = resp {
            if v.len() < 65 {
                warn!("too short response? got {} bytes", v.len());
            }
            // this is 81 bytes

            // ProcessResponse
            let peer_point_bytes = &v[..65];
            let ct = &v[65..];

            let peer_key = bytes_to_public_key(peer_point_bytes)?;
            let mut shared_key_ee = [0; 32];
            ecdh(&ephemeral_key, &peer_key, &mut shared_key_ee)?;
            noise.mix_hash(peer_point_bytes);
            noise.mix_key(peer_point_bytes)?;
            noise.mix_key(&shared_key_ee)?;

            // local identity
            let mut shared_key_se = [0; 32];
            ecdh(&local_identity, &peer_key, &mut shared_key_se)?;
            noise.mix_key(&shared_key_se)?;


            let pt = noise.decrypt_and_hash(ct)?;

            // let mut payload = [0; 65535];
            // let len = noise.read_message(&v, &mut payload).unwrap();
            if pt.len() != 0 {
                panic!(
                    "expected handshake to be empty, got {} bytes: {:02x?}",
                    pt.len(),
                    &pt
                );
            }
        } else {
            error!("Unexpected websocket response type");
            return Err(WebauthnCError::Unknown);
        }

        let (write_key, read_key) = noise.traffic_keys()?;

        trace!(?write_key);
        trace!(?read_key);
        let mut crypter = Crypter::new(read_key, write_key);

        // Waiting for post-handshake message
        trace!("Waiting for post-handshake message...");
        let resp = stream.next().await.unwrap().unwrap();
        trace!("Post-handshake message:");
        trace!("<<< {:?}", resp);
        let v = if let Message::Binary(v) = resp {
            v
        } else {
            error!("Unexpected websocket response type");
            return Err(WebauthnCError::Unknown);
        };
        
        trace!("decrypted:");
        let decrypted = crypter.decrypt(&v)?;
        trace!("<<< {:?}", decrypted);

        let t = Self {
            psk,
            stream,
            local_identity,
            noise,
            ephemeral_key,
            crypter,
        };

        Ok(t)
    }
}

fn point_to_bytes(point: &EcPointRef) -> Result<Vec<u8>, WebauthnCError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    Ok(point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?)
}

fn bytes_to_public_key(buf: &[u8]) -> Result<EcKey<Public>, WebauthnCError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, &buf, &mut ctx)?;
    Ok(EcKey::from_public_key(&group, &point)?)
}

fn ecdh(
    private_key: &EcKeyRef<Private>,
    peer_key: &EcKeyRef<Public>,
    output: &mut [u8],
) -> Result<(), WebauthnCError> {
    let peer_key = PKey::from_ec_key(peer_key.to_owned())?;
    let pkey = PKey::from_ec_key(private_key.to_owned())?;
    let mut ctx = PkeyCtx::new(&pkey)?;
    ctx.derive_init()?;
    ctx.derive_set_peer(&peer_key)?;
    ctx.derive(Some(output))?;
    Ok(())
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

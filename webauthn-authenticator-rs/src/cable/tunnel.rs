//! Tunnel functions

use std::fmt::Debug;
use std::collections::BTreeMap;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use openssl::{
    ec::{EcKeyRef, EcPoint, EcPointRef, PointConversionForm},
    pkey_ctx::PkeyCtx,
};
use serde_cbor::Value;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderValue, Uri},
        Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use webauthn_rs_proto::AuthenticatorTransport;

use crate::error::CtapError;
use crate::{
    cable::{
        crypter::Crypter,
        framing::{CableCommand, CablePostHandshake, MessageType},
        noise::{get_public_key_bytes, CableNoise, HandshakeType},
    },
    ctap2::{commands::GetInfoResponse, CBORCommand, CtapAuthenticator},
    prelude::WebauthnCError,
    transport::Token,
    ui::UiCallback,
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

pub struct Tunnel {
    psk: Psk,
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    noise: CableNoise,
    ephemeral_key: EcKey<Private>,
    crypter: Crypter,
    info: GetInfoResponse,
}

impl Tunnel {
    pub async fn connect(
        uri: &Uri,
        psk: Psk,
        local_identity: &EcKeyRef<Private>,
    ) -> Result<Tunnel, WebauthnCError> {
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

        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=982;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29
        // TODO: write_key here may be wrong
        // suspect the only way to debug this is to implement RespondToHandshake for a test
        // read_key is correct
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

        // TODO: android sends us a v0 handshake with extra padded CBOR and linking info
        // for some reason, serde_cbor is happy to decode this, so it doesn't error
        // Because supports_linking = false, then it is a v0 handshake
        let v: BTreeMap<u32, Value> =
            serde_cbor::from_slice(&decrypted).map_err(|_| WebauthnCError::Cbor)?;

        let frame = CablePostHandshake::try_from(v)?;
        trace!(?frame);

        let info = frame.info;

        let t = Self {
            psk,
            stream,
            noise,
            ephemeral_key,
            crypter,
            info,
        };

        Ok(t)
    }

    /// Establishes a [CtapAuthenticator] connection for communicating with a
    /// caBLE authenticator using CTAP 2.x.
    ///
    /// See [CtapAuthenticator::new] for further detail.
    pub fn get_authenticator<'a, U: UiCallback>(
        self,
        ui_callback: &'a U,
    ) -> Option<CtapAuthenticator<'a, Self, U>> {
        CtapAuthenticator::new_with_info(self.info.to_owned(), self, ui_callback)

        // Sending GetInfo here means we get an explicit close message
    }

    async fn send(&mut self, cmd: CableCommand) -> Result<(), WebauthnCError> {
        trace!("send: flushing before send");
        self.stream.flush().await.unwrap();
        let cmd = cmd.to_bytes();
        trace!(">>> {:02x?}", cmd);
        let encrypted = self.crypter.encrypt(&cmd)?;
        trace!("ENC {:02x?}", encrypted);
        self.stream.send(Message::Binary(encrypted)).await.unwrap();
        Ok(())
    }

    async fn recv(&mut self) -> Result<CableCommand, WebauthnCError> {
        let resp = self.stream.next().await.unwrap().unwrap();

        let resp = if let Message::Binary(v) = resp {
            v
        } else {
            error!("Incorrect message type");
            return Err(WebauthnCError::Unknown);
        };

        let decrypted = self.crypter.decrypt(&resp)?;
        // TODO: protocol version
        let frame = CableCommand::from_bytes(1, &decrypted);
        // TODO: shutdown, update events
        assert_eq!(frame.message_type, MessageType::Ctap);

        Ok(frame)
    }
}

impl Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("stream", &self.stream)
            .finish()
    }
}

#[async_trait]
impl Token for Tunnel {
    fn get_transport(&self) -> AuthenticatorTransport {
        AuthenticatorTransport::Hybrid
    }

    async fn transmit_raw<C, U>(&mut self, cmd: C, ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        C: CBORCommand,
        U: UiCallback,
    {
        let f = CableCommand {
            // TODO: handle protocol versions
            protocol_version: 1,
            message_type: MessageType::Ctap,
            data: cmd.cbor().map_err(|_| WebauthnCError::Cbor)?,
        };
        self.send(f).await?;
        let resp = self.recv().await?;
        let mut data = resp.data;

        let err = CtapError::from(data.remove(0));
        if !err.is_ok() {
            return Err(err.into());
        }
        Ok(data)
    }

    fn cancel(&self) -> Result<(), WebauthnCError> {
        todo!()
    }

    async fn init(&mut self) -> Result<(), WebauthnCError> {
        Ok(())
    }

    fn close(&self) -> Result<(), WebauthnCError> {
        todo!()
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

    /*
    Chrome

    FIDO: DEBUG: fido_tunnel_device.cc:429 Linking information was not received from caBLE device
    FIDO: DEBUG: fido_tunnel_device.cc:433 tunnel-7CE0C968AA83BB21: established v2.1
    FIDO: DEBUG: device_response_converter.cc:265 -> {1: ["FIDO_2_0"], 3: h'REDACTED', 4: {"rk": true, "uv": true}}
    FIDO: DEBUG: fido_device.cc:80 The device supports the CTAP2 protocol.


    FIDO: DEBUG: ctap2_device_operation.h:87 <- 1
    {1: h'66569EFC827249E894E662CA9C78401C128D9053685052E42395DC69B972611B',
     2: {"id": "webauthn.firstyear.id.au", "name": "webauthn.firstyear.id.au"},
     3: {"id": h'3BC33B00624F4D45912DC4E2EB75A289', "name": "a", "displayName": "a"},
     4: [{"alg": -7, "type": "public-key"}, {"alg": -257, "type": "public-key"}],
     5: [{"id": h'00010203', "type": "public-key"}],   // excludelist
     7: {"uv": true}}


    We send:

    CBOR: cmd=1, cbor=Ok(Map({
      Integer(1): Bytes( [246, 134, 212, 222, 63, 120, 188, 83, 162, 239, 197, 129, 146, 115, 255, 101, 140, 102, 137, 129, 161, 162, 25, 206, 163, 3, 22, 222, 112, 135, 101, 51]),
      Integer(2): Map({Text("id"): Text("webauthn.firstyear.id.au"), Text("name"): Text("webauthn.firstyear.id.au")}),
      Integer(3): Map({Text("id"): Bytes([158, 170, 228, 89, 68, 28, 73, 194, 134, 19, 227, 153, 107, 220, 150, 238]), Text("name"): Text("william"), Text("displayName"): Text("william")}),
      Integer(4): Array([Map({Text("alg"): Integer(-7), Text("type"): Text("public-key")}), Map({Text("alg"): Integer(-257), Text("type"): Text("public-key")})]),
      Integer(7): Map({Text("uv"): Bool(true)})}))
    */
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

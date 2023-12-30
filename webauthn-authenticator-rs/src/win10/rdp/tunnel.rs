use crate::{
    error::WebauthnCError, transport::Token, ui::UiCallback, win10::rdp::channel::Connection,
};
use async_trait::async_trait;
use webauthn_rs_proto::AuthenticatorTransport;

#[async_trait]
impl Token for Connection {
    type Id = ();

    fn get_transport(&self) -> AuthenticatorTransport {
        AuthenticatorTransport::Unknown
    }

    async fn transmit_raw<U>(&mut self, cbor: &[u8], ui: &U) -> Result<Vec<u8>, WebauthnCError>
    where
        U: UiCallback,
    {
        let f = CableFrame {
            // TODO: handle protocol versions
            protocol_version: 1,
            message_type: CableFrameType::Ctap,
            data: cbor.to_vec(),
        };
        self.send(f).await?;
        ui.cable_status_update(CableState::WaitingForAuthenticatorResponse);
        let mut data = loop {
            let resp = match self.recv().await? {
                Some(r) => r,
                None => {
                    // end of stream
                    self.close().await?;
                    return Err(WebauthnCError::Closed);
                }
            };

            if resp.message_type == CableFrameType::Ctap {
                break resp.data;
            } else {
                // TODO: handle these.
                warn!("unhandled message type: {:?}", resp);
            }
        };
        self.close().await?;
        ui.cable_status_update(CableState::Processing);

        let err = CtapError::from(data.remove(0));
        if !err.is_ok() {
            return Err(err.into());
        }
        Ok(data)
    }

    async fn cancel(&mut self) -> Result<(), WebauthnCError> {
        // There is no way to cancel transactions without closing in caBLE
        Ok(())
    }

    async fn init(&mut self) -> Result<(), WebauthnCError> {
        Ok(())
    }

    async fn close(&mut self) -> Result<(), WebauthnCError> {
        // // We don't care if this errors
        // self.send(SHUTDOWN_COMMAND).await.ok();
        // self.stream.close(None).await.ok();
        Ok(())
    }
}

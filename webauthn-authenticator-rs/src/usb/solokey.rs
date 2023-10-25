use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    prelude::WebauthnCError,
    transport::{
        solokey::{SoloKeyToken, CMD_UUID},
        types::{U2FError, U2FHID_ERROR},
    },
    usb::framing::U2FHIDFrame,
};

use super::{USBToken, USBTransport};

#[async_trait]
impl SoloKeyToken for USBToken {
    async fn get_solokey_uuid(&mut self) -> Result<Uuid, WebauthnCError> {
        let cmd = U2FHIDFrame {
            cid: self.cid,
            cmd: CMD_UUID,
            len: 0,
            data: vec![],
        };
        self.send_one(&cmd).await?;

        let r = self.recv_one().await?;
        match r.cmd {
            CMD_UUID => {
                if r.len != 16 || r.data.len() != 16 {
                    return Err(WebauthnCError::InvalidMessageLength);
                }

                let u = Uuid::from_bytes(
                    r.data
                        .try_into()
                        .map_err(|_| WebauthnCError::InvalidMessageLength)?,
                );

                Ok(u)
            }

            U2FHID_ERROR => Err(U2FError::from(r.data.as_slice()).into()),

            _ => Err(WebauthnCError::UnexpectedState),
        }
    }
}

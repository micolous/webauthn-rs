//! caBLE message framing types

use crate::{
    ctap2::{
        commands::{GetAssertionRequest, MakeCredentialRequest},
        CBORCommand, CBORResponse,
    },
    error::WebauthnCError,
};

/// Prefix byte for messages sent to the authenticator
///
/// Not used for protocol version 0
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CableFrameType {
    /// caBLE shutdown message
    Shutdown = 0,
    /// CTAP 2.x command
    Ctap = 1,
    /// Linking information
    Update = 2,
    Unknown,
}

impl From<u8> for CableFrameType {
    fn from(v: u8) -> Self {
        use CableFrameType::*;
        match v {
            0 => Shutdown,
            1 => Ctap,
            2 => Update,
            _ => Unknown,
        }
    }
}

pub const SHUTDOWN_COMMAND: CableFrame = CableFrame {
    protocol_version: 1,
    message_type: CableFrameType::Shutdown,
    data: vec![],
};

/// caBLE request and response framing.
///
/// These frames are encrypted ([Crypter][crate::cable::noise::Crypter])
/// and sent as binary Websocket messages.
///
/// ## Protocol description
///
/// ### Version 0
///
/// All frames are of the type [CableFrameType::Ctap], and the wire format is the
/// same as CTAP 2.0.
///
/// ### Version 1
///
/// Version 1 adds an initial [CableFrameType] byte before the payload (`data`):
///
/// * [CableFrameType::Shutdown]: no payload
/// * [CableFrameType::Ctap]: payload is CTAP 2.0 command / response
/// * [CableFrameType::Update]: payload is linking information (not implemented)
#[derive(Debug, PartialEq, Eq)]
pub struct CableFrame {
    pub protocol_version: u32,
    pub message_type: CableFrameType,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum RequestType {
    MakeCredential(MakeCredentialRequest),
    GetAssertion(GetAssertionRequest),
}

impl CableFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.protocol_version == 0 {
            return self.data.to_owned();
        }

        let mut o = self.data.to_owned();
        o.insert(0, self.message_type as u8);
        o
    }

    pub fn from_bytes(protocol_version: u32, i: &[u8]) -> Self {
        let message_type: CableFrameType = if protocol_version > 0 {
            i[0].into()
        } else {
            CableFrameType::Ctap
        };

        let data = if protocol_version == 0 { i } else { &i[1..] }.to_vec();

        Self {
            protocol_version,
            message_type,
            data,
        }
    }

    /// Parses a [CableFrame] (from an initiator) as a CBOR request type.
    ///
    /// Returns [WebauthnCError::NotSupported] on unknown command types, or if
    /// `message_type` is not [CableFrameType::Ctap].
    pub fn parse_request(&self) -> Result<RequestType, WebauthnCError> {
        if self.message_type != CableFrameType::Ctap {
            return Err(WebauthnCError::NotSupported);
        }
        match self.data[0] {
            MakeCredentialRequest::CMD => Ok(RequestType::MakeCredential(
                <MakeCredentialRequest as CBORResponse>::try_from(&self.data[1..])?,
            )),
            GetAssertionRequest::CMD => Ok(RequestType::GetAssertion(
                <GetAssertionRequest as CBORResponse>::try_from(&self.data[1..])?,
            )),
            _ => Err(WebauthnCError::NotSupported),
        }
    }
}


#[derive(Debug)]
struct InitResponse {
    nonce: Vec<u8>,
    /// Allocated channel identifier
    cid: u32,
    /// U2F protocol version (2)
    protocol_version: u8,
    device_version_major: u8,
    device_version_minor: u8,
    device_version_build: u8,
    capabilities: u8,
}

impl TryFrom<&[u8]> for InitResponse {
    type Error = ();
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.len() < 17 {
            return Err(());
        }

        let (nonce, d) = d.split_at(8);
        let nonce = nonce.to_vec();
        let (cid, d) = d.split_at(4);
        let cid = cid.try_into().map(u32::from_be_bytes).or(Err(()))?;

        Ok(InitResponse {
            nonce,
            cid,
            protocol_version: d[0],
            device_version_major: d[1],
            device_version_minor: d[2],
            device_version_build: d[3],
            capabilities: d[4],
        })
    }
}

/// CTAPv1 APDU (ISO 7816-like)
#[derive(Debug, PartialEq)]
struct MessageResponse {
    /// Data payload
    data: Vec<u8>,
    /// Status byte 1
    sw1: u8,
    /// Status byte 2
    sw2: u8,
}

impl MessageResponse {
    /// Did we get a simple "ok" response?
    fn is_ok(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0
    }
}

impl TryFrom<&[u8]> for MessageResponse {
    type Error = ();
    fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
        if d.len() < 2 {
            return Err(());
        }
        Ok(MessageResponse {
            data: d[..d.len() - 2].to_vec(),
            sw1: d[d.len() - 2],
            sw2: d[d.len() - 1],
        })
    }
}

#[derive(Debug)]
enum U2FError {
    None,
    InvalidCommand,
    InvalidParameter,
    InvalidMessageLength,
    InvalidMessageSequencing,
    MessageTimeout,
    ChannelBusy,
    ChannelRequiresLock,
    SyncCommandFailed,
    Unspecified,
    Unknown,
}

impl From<u8> for U2FError {
    fn from(v: u8) -> Self {
        match v {
            0x00 => U2FError::None,
            0x01 => U2FError::InvalidCommand,
            0x02 => U2FError::InvalidParameter,
            0x03 => U2FError::InvalidMessageLength,
            0x04 => U2FError::InvalidMessageSequencing,
            0x05 => U2FError::MessageTimeout,
            0x06 => U2FError::ChannelBusy,
            0x0a => U2FError::ChannelRequiresLock,
            0x0b => U2FError::SyncCommandFailed,
            0x7f => U2FError::Unspecified,
            _ => U2FError::Unknown,
        }
    }
}

impl From<&[u8]> for U2FError {
    fn from(d: &[u8]) -> Self {
        if d.len() >= 1 {
            U2FError::from(d[0])
        } else {
            U2FError::Unknown
        }
    }
}

#[derive(Debug)]
enum Response {
    Init(InitResponse),
    Msg(MessageResponse),
    Error(U2FError),
    Unknown,
}

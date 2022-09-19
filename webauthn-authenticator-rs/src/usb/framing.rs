use crate::error::WebauthnCError;
use crate::usb::HID_RPT_SIZE;

/// U2F HID request frame type
pub(crate) struct U2FHIDFrame {
    /// Channel identifier
    pub cid: u32,
    /// Command identifier
    pub cmd: u8,

    pub data: FrameType,
}

pub(crate) enum FrameType {
    Initial(u16, Vec<u8>),
    Continuation(Vec<u8>),
    Complete(Vec<u8>),
}

impl U2FHIDFrame {
    pub fn fragment(&self) -> Vec<Self> {
        let pl = match self.data {
            FrameType::Complete(pl) -> pl,
            _ -> panic!("already fragmented"),
        };

        if pl.len() < HID_RPT_SIZE - 7 {
            // Send as-is
            return 
        }
        todo!();
    }

    pub fn assemble(fragments: &[Self]) -> Self {
        todo!();
    }
}

impl Into<Vec<u8>> for &U2FHIDFrame {
    /// Serialises a U2FHIDFrame to bytes to be send via a USB HID report
    fn into(self) -> Vec<u8> {
        // This does not implement fragmentation / continuation packets!

        let mut o: Vec<u8> = vec![0; HID_RPT_SIZE + 1];
        // o[0] = 0; (Report ID)
        o[1..5].copy_from_slice(&self.cid.to_be_bytes());
        o[5] = self.cmd;

        if self.data.len() + 8 > o.len() {
            panic!("Data payload too long");
        }
        o[6..8].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        o[8..8 + self.data.len()].copy_from_slice(&self.data);

        o
    }
}

impl TryFrom<&[u8]> for U2FHIDFrame {
    type Error = WebauthnCError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        if b.len() < 7 {
            panic!("Response frame must be at least 7 bytes");
        }

        let (cid, b) = b.split_at(4);
        let cid = u32::from_be_bytes(cid.try_into().unwrap());
        let (cmd, b) = (b[0], &b[1..]);
        let (len, b) = b.split_at(2);
        let len = u16::from_be_bytes(len.try_into().unwrap()) as usize;
        if len == 0 || len > b.len() {
            Err(WebauthnCError::Cbor)
        } else {
            let data = (&b[..len]).to_vec();
            Ok(Self {
                cid, cmd, data
            })
        }
    }
}

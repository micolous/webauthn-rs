// use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)] // Serialize, ?
pub struct ISO7816RequestAPDU<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: &'a [u8],
    pub ne: u16,
}

fn push_length_value(buf: &mut Vec<u8>, value: u16, extended_form: bool) {
    if value == 0 {
        // do nothing
    } else if extended_form {
        // uint16be prefixed with 0
        buf.push(0);
        buf.push((value >> 8).try_into().unwrap());
        buf.push((value & 0xff).try_into().unwrap());
    } else if value > 256 {
        panic!("value {:?} not representable in short form", value);
    } else {
        // 256 = 0x00, 1 = 0x01, 255 = 0xFF
        buf.push((value & 0xff).try_into().unwrap());
    }
}

impl ISO7816RequestAPDU<'_> {
    pub fn to_bytes(&self) -> Vec<u8> {
        // s5.1: "short and extended length fields shall not be combined: either
        // both of them are short, or both of them are extended".
        let extended_form = self.ne > 256 || self.data.len() > 255;

        let lc_len = if self.data.len() == 0 {
            0
        } else if extended_form {
            3
        } else {
            1
        };

        let le_len = if self.ne == 0 {
            0
        } else if extended_form {
            3
        } else {
            1
        };

        let mut buf = Vec::with_capacity(4 + self.data.len() + lc_len + le_len);
        buf.push(self.cla);
        buf.push(self.ins);
        buf.push(self.p1);
        buf.push(self.p2);

        push_length_value(&mut buf, self.data.len().try_into().unwrap(), extended_form);
        if self.data.len() > 0 {
            buf.extend_from_slice(self.data);
        }
        push_length_value(&mut buf, self.ne, extended_form);

        buf
    }
}

#[derive(Debug, Clone)] // Serialize, ?
pub struct ISO7816ResponseAPDU {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl<'a> TryFrom<&[u8]> for ISO7816ResponseAPDU {
    type Error = &'static str;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < 2 {
            Err("response must be at least 2 bytes")
        } else {
            Ok(Self {
                data: (&raw[..raw.len() - 2]).to_vec(),
                sw1: raw[raw.len() - 2],
                sw2: raw[raw.len() - 1],
            })
        }
    }
}

impl ISO7816ResponseAPDU {
    pub fn is_ok(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    pub fn bytes_available(&self) -> u16 {
        if self.sw1 == 0x61 {
            if self.sw2 == 0x00 {
                256
            } else {
                self.sw2.into()
            }
        } else {
            0
        }
    }
}

pub fn select_by_df_name<'a>(df: &'a [u8]) -> ISO7816RequestAPDU<'a> {
    ISO7816RequestAPDU {
        cla: 0x00,
        ins: 0xA4, // SELECT
        p1: 0x04, // By DF name
        p2: 0x00, // First or only occurrence
        data: df,
        ne: 256,
    }
}

const EMPTY: [u8; 0] = [];

pub const GET_HISTORICAL_BYTES: ISO7816RequestAPDU<'static> = ISO7816RequestAPDU {
    cla: 0x00,
    ins: 0xCA,
    p1: 0x5F,
    p2: 0x51,
    data: &EMPTY,
    ne: 32
};

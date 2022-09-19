//! Helpers for framing U2FHID messages.
//! 
//! USB HID has a MTU (maximum transmission unit) of 64 bytes. U2FHID headers
//! are 7 bytes for the first frame of a message, and 5 bytes for every message
//! thereafter.
//! 
//! So, we need to be able to fragment our messages before sending them to a
//! token, and then defragment them on the other side.
use crate::error::WebauthnCError;
use crate::usb::{HID_RPT_SIZE, CAPABILITY_CBOR, CAPABILITY_NMSG};
use std::cmp::min;
use std::iter::Sum;
use std::ops::{Add, AddAssign};

/// The maximum data payload for the initial fragment of a message, in bytes.
const INITIAL_FRAGMENT_SIZE: usize = HID_RPT_SIZE - 7;
/// The maximum data payload for the second and subsequent fragments of a
/// message, in bytes.
const FRAGMENT_SIZE: usize = HID_RPT_SIZE - 5;

/// U2F HID request frame type.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct U2FHIDFrame {
    /// Channel identifier
    pub cid: u32,
    /// Command identifier or sequence number
    pub cmd: u8,
    /// Complete length, for fragmented packets
    pub len: u16,
    /// Data payload
    pub data: Vec<u8>,
}

impl U2FHIDFrame {
    pub fn complete(&self) -> bool {
        self.cmd & 0x80 > 0 && self.data.len() >= usize::from(self.len)
    }
}

const EMPTY_FRAME: U2FHIDFrame = U2FHIDFrame {
    cid: 0,
    cmd: 0,
    len: 0,
    data: vec![],
};

/// Iterator type for fragmenting a long [U2FHIDFrame] into smaller pieces that
/// fit within the USB HID MTU.
pub(crate) struct U2FHIDFrameIterator<'a> {
    /// The frame to fragment.
    f: &'a U2FHIDFrame,
    /// The current position within the frame we're up to.
    p: usize,
    /// The fragment number we're up to.
    i: u8,
}

impl<'a> U2FHIDFrameIterator<'a> {
    /// Creates a new iterator for fragmenting [U2FHIDFrame]
    pub fn new(f: &'a U2FHIDFrame) -> Self {
        U2FHIDFrameIterator { f: &f, p: 0, i: 0 }
    }
}

impl Iterator for U2FHIDFrameIterator<'_> {
    type Item = U2FHIDFrame;

    fn next(&mut self) -> Option<Self::Item> {
        let l = self.f.data.len();

        if self.p == 0 {
            // First round
            self.p = min(l, INITIAL_FRAGMENT_SIZE);
            Some(U2FHIDFrame {
                cid: self.f.cid,
                cmd: self.f.cmd,
                len: l as u16,
                data: self.f.data[..self.p].to_vec(),
            })
        } else if self.p >= l {
            // Already consumed iterator.
            None
        } else {
            // Fragment start position
            let p = self.p;
            // Fragment end position
            self.p = min(l, p + FRAGMENT_SIZE);
            let i = self.i & 0x7f;
            self.i = i + 1;
            Some(U2FHIDFrame {
                cid: self.f.cid,
                cmd: i,
                len: 0,
                data: self.f.data[p..self.p].to_vec(),
            })
        }
    }
}

/// Merges a fragmented [U2FHIDFrame]s back together. Assumes the LHS of the
/// operation is the initial fragment.
impl Add for U2FHIDFrame {
    type Output = Self;

    fn add(self, rhs: Self) -> Self
    {
        // Assume LHS is initial
        assert_eq!(self.cid, rhs.cid);
        let mut o: Vec<u8> = vec![0; usize::from(self.len)];
        o[..self.data.len()].copy_from_slice(&self.data);

        let p = INITIAL_FRAGMENT_SIZE + (usize::from(rhs.cmd) * FRAGMENT_SIZE);
        let q = min(p + rhs.data.len(), usize::from(self.len));
        o[p..q].copy_from_slice(&rhs.data[..q - p]);
        U2FHIDFrame {
            cid: self.cid,
            cmd: self.cmd,
            len: self.len,
            data: o,
        }
    }
}

/// Merges a fragmented [U2FHIDFrame]s back together. Assumes the LHS of the
/// operation is the initial fragment.
impl AddAssign for U2FHIDFrame {
    fn add_assign(&mut self, rhs: U2FHIDFrame) {
        // Assume LHS is initial
        assert_eq!(self.cid, rhs.cid);
        if self.data.len() != usize::from(self.len) {
            let mut o: Vec<u8> = vec![0; usize::from(self.len)];
            o[..self.data.len()].copy_from_slice(&self.data);
            self.data = o;
        }

        let p = INITIAL_FRAGMENT_SIZE + (usize::from(rhs.cmd) * FRAGMENT_SIZE);
        let q = min(p + rhs.data.len(), usize::from(self.len));
        self.data[p..q].copy_from_slice(&rhs.data[..q - p]);
    }
}

/// Merges a fragmented [U2FHIDFrame]s back together. Assumes the first element
/// is the initial fragment. Order of subsequent fragments doesn't matter.
impl<'a> Sum<&'a U2FHIDFrame> for U2FHIDFrame {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        // First frame
        let mut s: Option<&Self> = None;
        let mut o: Vec<u8> = Vec::with_capacity(0);

        for f in iter {
            match &s {
                None => {
                    o = vec![0; usize::from(f.len)];
                    let p = min(f.data.len(), usize::from(f.len));
                    o[..p].copy_from_slice(&f.data[..p]);
                    s = Some(&f);
                },

                Some(first) => {
                    assert_eq!(f.cid, first.cid);
                    let p = INITIAL_FRAGMENT_SIZE + (usize::from(f.cmd) * FRAGMENT_SIZE);
                    let q = min(p + f.data.len(), usize::from(first.len));
                    o[p..q].copy_from_slice(&f.data);
                }
            }
        }
        
        match s {
            Some(first) => {
                U2FHIDFrame {
                    cid: first.cid,
                    cmd: first.cmd,
                    len: first.len,
                    data: o,
                }
            },
            None => EMPTY_FRAME,
        }
    }
}

/// Serialises a [U2FHIDFrame] to bytes to be sent via a USB HID report.
/// 
/// This does not fragment packets: see [U2FHIDFrameIterator].
impl Into<Vec<u8>> for &U2FHIDFrame {
    fn into(self) -> Vec<u8> {
        let mut o: Vec<u8> = vec![0; HID_RPT_SIZE + 1];

        // o[0] = 0; (Report ID)
        o[1..5].copy_from_slice(&self.cid.to_be_bytes());
        o[5] = self.cmd;

        if self.cmd & 0x80 > 0 {
            // Initial
            o[6..8].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
            o[8..8 + self.data.len()].copy_from_slice(&self.data);
        } else {
            o[6..6 + self.data.len()].copy_from_slice(&self.data);
        }

        o
    }
}

/// Deserialises bytes from a USB HID report into a [U2FHIDFrame].
impl TryFrom<&[u8]> for U2FHIDFrame {
    type Error = WebauthnCError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        if b.len() < 7 {
            panic!("Response frame must be at least 7 bytes");
        }

        let (cid, b) = b.split_at(4);
        let cid = u32::from_be_bytes(cid.try_into().unwrap());
        let (cmd, b) = (b[0], &b[1..]);
        if cmd & 0x80 > 0 {
            // Initial
            let (len, b) = b.split_at(2);
            let len = u16::from_be_bytes(len.try_into().unwrap());
            if usize::from(len) < b.len() {
                let b = &b[..usize::from(len)];
            }

            Ok(Self {
                cid,
                cmd,
                len,
                data: b.to_vec(),
            })
        } else {
            // Continuation
            Ok(Self {
                cid,
                cmd,
                len: 0,
                data: b.to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_short() {
        let full = U2FHIDFrame {
            cid: 1,
            cmd: 0x90,
            len: 2,
            data: vec![1, 2],
        };

        let fragments: Vec<U2FHIDFrame> = U2FHIDFrameIterator::new(&full).collect();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], full);

        let assembled: U2FHIDFrame = fragments.iter().sum();
        assert_eq!(assembled, full);
    }

    #[test] 
    fn fragment_long() {
        let full = U2FHIDFrame {
            cid: 1,
            cmd: 0x90,
            len: 255,
            data: (0..255).collect(),
        };
        assert_eq!(full.complete(), true);

        let fragments: Vec<U2FHIDFrame> = U2FHIDFrameIterator::new(&full).collect();
        // 57, 59, 59, 59, 21
        assert_eq!(fragments.len(), 5);
        for f in &fragments {
            assert_eq!(f.cid, 1);
            assert_eq!(f.complete(), false);
        }

        assert_eq!(fragments[0].cmd, 0x90);
        assert_eq!(fragments[0].len, 255);
        assert_eq!(fragments[0].data, (0..57).collect::<Vec<u8>>());

        assert_eq!(fragments[1].cmd, 0);
        assert_eq!(fragments[1].data, (57..116).collect::<Vec<u8>>());

        assert_eq!(fragments[2].cmd, 1);
        assert_eq!(fragments[2].data, (116..175).collect::<Vec<u8>>());

        assert_eq!(fragments[3].cmd, 2);
        assert_eq!(fragments[3].data, (175..234).collect::<Vec<u8>>());

        assert_eq!(fragments[4].cmd, 3);
        assert_eq!(fragments[4].data, (234..255).collect::<Vec<u8>>());

        let assembled: U2FHIDFrame = fragments.iter().sum();
        assert_eq!(assembled, full);
        assert_eq!(assembled.complete(), true);

        let mut p: U2FHIDFrame = fragments[0].clone() + fragments[1].clone();
        p += fragments[2].clone();
        p += fragments[3].clone();
        p += fragments[4].clone();
        assert_eq!(p, full);
        assert_eq!(p.complete(), true);
    }
}

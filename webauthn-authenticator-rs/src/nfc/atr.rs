use pcsc::*;

use super::tlv::*;

#[derive(Debug, Clone)]
pub struct Atr {
    pub protocols: Vec<u8>,
    // Historical Bytes
    pub t1: Vec<u8>,

    pub command_chaining: bool,

    // Supports extended Lc and Le
    //
    // Yubikey says it supports extended Lc/Le in the ATR:
    // https://smartcard-atr.apdu.fr/parse?ATR=3b+8d+80+01+80+73+c0+21+c0+57+59+75+62+69+4b+65+79+f9
    // But it actually doesn't...
    pub extended_lc: bool,
}

const EMPTY: [u8; 0] = [];

impl<'a> TryFrom<&[u8]> for Atr {
    type Error = &'static str;

    fn try_from(atr: &[u8]) -> Result<Self, Self::Error> {
        let mut nibbles = Vec::with_capacity(MAX_ATR_SIZE);
        let mut i: usize = 1;
        loop {
            let y = atr[i] >> 4;
            nibbles.push(atr[i] & 0x0f);
            i += 1;
        
            // skip Ta, Tb, Tc fields
            i += ((y & 0x7) as usize);
            if y & 0x8 == 0 /* Td = 0 */ {
                break;
            }
        }
        
        let t1_len = nibbles[0] as usize;
        let protocols = if nibbles.len() > 1 {
            &nibbles[1..]
        } else {
            // no protocols
            &EMPTY
        };
        
        let mut command_chaining = false;
        let mut extended_lc = false;

        let t1 = &atr[i..i + t1_len];
        // TODO: handle PC/SC's brokenness (where they actually use Simple-TLV)
        // See PC/SC Spec Part 3, s3.1.3.2.3.2: Contactless Storage Cards
        // FIDO tokens won't be storage cards, but it means we don't barf if
        // someone tries to put their transit card in there.
        let tlv = CompactTlv::new(t1);
        for (t, v) in tlv {
            trace!("tlv: {:02x?} = {:02x?}", t, v);
            if t == 7 {
                // 8.1.1.2.7 Card capabilities
                if v.len() >= 3 {
                    command_chaining = (v[2] & 0x80) != 0;
                    extended_lc = (v[2] & 0x40) != 0;
                }
            }
        }
        
        Ok(Atr {
            protocols: protocols.to_vec(),
            t1: t1.to_vec(),
            command_chaining,
            extended_lc,
        })
    }
}

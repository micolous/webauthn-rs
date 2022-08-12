use pcsc::*;

use super::tlv::*;

/// ISO/IEC 7816-3 and -4 answer-to-reset structure for smart cards.
///
/// This supports a subset of the structure needed for working with FIDO tokens.
///
/// In addition to the standards,
/// * https://smartcard-atr.apdu.fr/:
#[derive(Debug, Clone, PartialEq)]
pub struct Atr {
    /// Supported protocols (T=), specified in ISO/IEC 7816-3:2006 §8.2.3.
    pub protocols: Vec<u8>,

    /// Historical Bytes, specified in ISO/IEC 7816-4:2005 §8.1.1.
    pub t1: Vec<u8>,

    /// If true, the device is a contactless storage card per PC/SC
    /// Specification Book 3, §3.1.3.2.3.2. Further clarification is available,
    /// but is beyond the scope of this module.
    pub storage_card: bool,

    /// Card issuer's data (ISO/IEC 7816-4:2005 §8.1.1.2.5). The structure of
    /// this value is defined by the card issuer. This sometimes contains a
    /// printable string identifying the card issuer.
    pub card_issuers_data: Option<Vec<u8>>,

    /// Whether the card supports command chaining (ISO/IEC 7816-4:2005
    /// §5.1.1.1). This allows the card to pass responses of
    ///
    /// If this value is set to None, the card did not provide a "card
    /// capabilities" value (ISO/IEC 7816-4:2005 §8.1.1.2.7).
    pub command_chaining: Option<bool>,

    /// Whether the card supports extended (3 byte) `Lc` and `Le` fields
    /// (ISO/IEC 7816-4:2005 §5.1) – which allows `Nc` (command data length) and
    /// `Ne` (maximum expected response length) values from 257 to 65536 bytes.
    ///
    /// If this value is set to None, the card did not provide a "card
    /// capabilities" value (§8.1.1.2.7), and therefore does not support
    /// extended fields (§5.1).
    ///
    /// **Note:** Some devices falsely report that they support extended
    /// `Lc`/`Le`, eg: [Yubikey](https://smartcard-atr.apdu.fr/parse?ATR=3b+8d+80+01+80+73+c0+21+c0+57+59+75+62+69+4b+65+79+f9)
    pub extended_lc: Option<bool>,
}

const PROTOCOL_T0: [u8; 1] = [0];
const PCSC_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x06];
const PCSC_RESPONSE_LEN: usize = 6 + PCSC_AID.len();

/// Validates check byte TCK according to ISO/IEC 7816-3:2006 §8.2.5: XOR'ing
/// all bytes from T0 to TCK inclusive should return zero.
fn checksum(i: &[u8]) -> bool {
    let o = i[1..].iter().fold(0, |a, i| a ^ i);

    #[cfg(test)]
    {
        let last = i.last().unwrap_or(&0);
        trace!("i.last == {:02x?}, expected {:02x?}", last, o ^ last);
    }
    return o == 0;
}

impl<'a> TryFrom<&[u8]> for Atr {
    type Error = &'static str;

    /// Attempts to parse an ATR from a `&[u8]`.
    fn try_from(atr: &[u8]) -> Result<Self, Self::Error> {
        if atr.len() < 2 {
            return Err("ATR must be at least 2 bytes");
        }

        let mut nibbles = Vec::with_capacity(MAX_ATR_SIZE);
        // Byte 0 intentionally skipped

        // Calculate checksum (TCK), present unless the only protocol is T=0:
        if atr.len() >= 3 // T != 0 protocols have at least 3 bytes ATR
        && atr[1] & 0x80 != 0x00 // TD0 present, no implicit T=0 only
        && (atr[2] & 0x0F != 0x00  // First protocol is not T=0, or
            || atr[2] & 0x80 != 0x00) // there is more than one protocol
        && !checksum(&atr)
        {
            return Err("ATR checksum incorrect");
        }

        let mut i: usize = 1;
        loop {
            let y = atr[i] >> 4;
            nibbles.push(atr[i] & 0x0f);
            i += 1;

            // skip Ta, Tb, Tc fields
            i += (y & 0x7) as usize;
            if y & 0x8 == 0 {
                /* Td = 0 */
                break;
            }
        }

        let t1_len = nibbles[0] as usize;
        let protocols = if nibbles.len() > 1 {
            &nibbles[1..]
        } else {
            // If TD1 is absent, the only offer is T=0.
            &PROTOCOL_T0
        };

        let mut storage_card = false;
        let mut command_chaining = None;
        let mut extended_lc = None;
        let mut card_issuers_data = None;
        if i + t1_len > atr.len() {
            return Err("T1 length > ATR length");
        }
        let t1 = &atr[i..i + t1_len];

        // First historical byte is the "category indicator byte".
        if t1_len == 0 {
            // No historical bytes
        } else if t1[0] == 0x00 || t1[0] == 0x80 {
            // 0x00, 0x80 = Compact-TLV payload
            let tlv_payload = if t1[0] == 0x00 {
                // 0x00: remaining historical bytes are followed by a mandatory
                // 3 byte status indicator (not in TLV)
                &t1[1..t1_len - 3]
            } else {
                // 0x80: remaining historical bytes are all TLV
                &t1[1..]
            };

            if tlv_payload.len() > PCSC_RESPONSE_LEN
                && tlv_payload[0] == 0x4f
                && &tlv_payload[2..7] == &PCSC_AID
            {
                // PC/SC Spec, Part 3, §3.1.3.2.3.2 (Contactless Storage Cards)
                // is incorrectly defined in Simple-TLV, not Compact-TLV. FIDO
                // tokens won't be storage cards, so we'll just ignore this.
                // This just means we don't barf on transit cards.
                storage_card = true;
            } else {
                let tlv = CompactTlv::new(&tlv_payload);
                for (t, v) in tlv {
                    // trace!("tlv: {:02x?} = {:02x?}", t, v);
                    if t == 7 {
                        // 7816-4 §8.1.1.2.7 Card capabilities
                        if v.len() >= 3 {
                            command_chaining = Some((v[2] & 0x80) != 0);
                            extended_lc = Some((v[2] & 0x40) != 0);
                        }
                    } else if t == 5 {
                        // 7816-4 §8.1.1.2.5 Card issuer's data
                        card_issuers_data = Some(v.to_vec());
                    }
                }
            }
        }

        Ok(Atr {
            protocols: protocols.to_vec(),
            t1: t1.to_vec(),
            storage_card,
            command_chaining,
            extended_lc,
            card_issuers_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yubikey_5_nfc() {
        let input = [
            0x3b, 0x8d, 0x80, 0x01, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69,
            0x4b, 0x65, 0xff, 0x7f,
        ];
        let expected = Atr {
            protocols: [0, 1].to_vec(),
            t1: [
                0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0xff,
            ]
            .to_vec(),
            storage_card: false,
            // "YubiKe\xFF"
            card_issuers_data: Some([0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0xff].to_vec()),
            command_chaining: Some(true),
            extended_lc: Some(true),
        };

        let actual = Atr::try_from(&input[..]).expect("yubikey_5_nfc ATR");
        assert_eq!(expected, actual);
    }

    #[test]
    fn yubico_security_key_c_nfc() {
        let input = [
            0x3b, 0x8d, 0x80, 0x01, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69,
            0x4b, 0x65, 0x79, 0xf9,
        ];
        let expected = Atr {
            protocols: [0, 1].to_vec(),
            t1: [
                0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79,
            ]
            .to_vec(),
            storage_card: false,
            // "YubiKey"
            card_issuers_data: Some([0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79].to_vec()),
            command_chaining: Some(true),
            extended_lc: Some(true),
        };

        let actual = Atr::try_from(&input[..]).expect("yubico_security_key_c_nfc ATR");
        assert_eq!(expected, actual);
    }

    #[test]
    fn desfire_storage_card() {
        let input = [0x3b, 0x81, 0x80, 0x01, 0x80, 0x80];
        let expected = Atr {
            protocols: [0, 1].to_vec(),
            t1: [0x80].to_vec(),
            storage_card: false,
            card_issuers_data: None,
            command_chaining: None,
            extended_lc: None,
        };

        let actual = Atr::try_from(&input[..]).expect("desfire_storage_card ATR");
        assert_eq!(expected, actual);
    }

    #[test]
    fn felica_storage_card() {
        let input = [
            0x3b, 0x8f, 0x80, 0x01, 0x80, 0x4f, 0x0c, 0xa0, 0x00, 0x00, 0x03, 0x06, 0x11, 0x00,
            0x3b, 0x00, 0x00, 0x00, 0x00, 0x42,
        ];
        let expected = Atr {
            protocols: [0, 1].to_vec(),
            t1: [
                0x80, 0x4f, 0x0c, 0xa0, 0x00, 0x00, 0x03, 0x06, 0x11, 0x00, 0x3b, 0x00, 0x00, 0x00,
                0x00,
            ]
            .to_vec(),
            storage_card: true,
            card_issuers_data: None,
            command_chaining: None,
            extended_lc: None,
        };

        let actual = Atr::try_from(&input[..]).expect("felica_storage_card ATR");
        assert_eq!(expected, actual);
    }

    #[test]
    fn short_capabilities() {
        // These have a 1 and 2 byte tag 0x7X, so command chaining and extended
        // lc support isn't available.
        let i1 = [0x3b, 0x83, 0x80, 0x01, 0x80, 0x71, 0xc0, 0x33];
        let expected_protocols = [0, 1].to_vec();
        let a1 = Atr::try_from(&i1[..]).expect("short caps atr1");

        assert_eq!(expected_protocols, a1.protocols);
        assert_eq!(None, a1.command_chaining);
        assert_eq!(None, a1.extended_lc);
        assert_eq!(false, a1.storage_card);

        let i2 = [0x3b, 0x84, 0x80, 0x01, 0x80, 0x71, 0xc0, 0x21, 0x15];
        let a2 = Atr::try_from(&i2[..]).expect("short caps atr2");

        assert_eq!(expected_protocols, a2.protocols);
        assert_eq!(None, a2.command_chaining);
        assert_eq!(None, a2.extended_lc);
        assert_eq!(false, a2.storage_card);
    }

    #[test]
    fn edge_cases() {
        let expected = Atr {
            protocols: [0].to_vec(),
            t1: [].to_vec(),
            storage_card: false,
            card_issuers_data: None,
            command_chaining: None,
            extended_lc: None,
        };

        let i1 = [0x3b, 0x80, 0x00];
        let a1 = Atr::try_from(&i1[..]).expect("edge_cases T=0");
        assert_eq!(expected, a1);

        let i2 = [0x3b, 0x00];
        let a2 = Atr::try_from(&i2[..]).expect("edge_cases T=(implicit)0");
        assert_eq!(expected, a2);
    }

    #[test]
    fn error_cases() {
        let i1 = [0x3b];
        let a1 = Atr::try_from(&i1[..]);
        assert!(a1.is_err());
    }
}
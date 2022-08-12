// use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// `ISO7816RequestAPDU.to_bytes()`: `data` was too long for the given
    /// length form.
    DataTooLong,
    /// `ISO7816RequestAPDU.to_bytes()`: `ne` was too long for the given length
    /// form.
    NeTooLong,
    IntegerOverflow,
    /// `ISO7816ResponseAPDU.from_bytes()`: response was less than 2 bytes.
    ResponseTooShort,
}

/// The form to use for `Lc` and `Le` in request APDUs, per ISO/IEC 7816-4:2005
/// §5.1.
pub enum ISO7816LengthForm {
    /// Only use short form (1 byte). This limits
    /// `ISO7816RequestAPDU.data.len()` to 255 bytes, and
    /// `ISO7816RequestAPDU.ne` to 256 bytes.
    ShortOnly,
    /// Automatically use extended form (3 bytes), if the request requires it.
    /// This may only be used if the card declares support for it in the ATR.
    Extended,
    /// Always use extended form, even if the request does not require it.
    /// This may only be used if the card declares support for it in the ATR.
    /// This is probably only useful for testing.
    ExtendedOnly,
}

#[derive(Debug, Clone)] // Serialize, ?
pub struct ISO7816RequestAPDU {
    /// Instruction class.
    pub cla: u8,
    /// Instruction code.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Optional command data.
    pub data: Vec<u8>,

    /// The maximum allowed response length from the card, in bytes.
    ///
    /// This library doesn't support responses of 65336 bytes, even though it
    /// would be allowed by ISO/IEC 7816-4.
    pub ne: u16,
}

/// Pushes a length value to a mutable buffer, optionally using ISO/IEC 7816-4
/// extended form.
fn push_length_value(buf: &mut Vec<u8>, value: u16, extended_form: bool) -> Result<(), Error> {
    if value == 0 {
        // do nothing
    } else if extended_form {
        // uint16be prefixed with 0
        buf.push(0);
        buf.push((value >> 8).try_into().unwrap());
        buf.push((value & 0xff).try_into().unwrap());
    } else if value > 256 {
        return Err(Error::IntegerOverflow);
    } else {
        // 256 = 0x00, 1 = 0x01, 255 = 0xFF
        buf.push((value & 0xff).try_into().unwrap());
    }
    Ok(())
}

impl ISO7816RequestAPDU {
    /// Serializes a request APDU into bytes to send to the card.
    pub fn to_bytes(&self, form: ISO7816LengthForm) -> Result<Vec<u8>, Error> {
        let extended_form = match form {
            ISO7816LengthForm::Extended => self.ne > 256 || self.data.len() > 255,
            ISO7816LengthForm::ShortOnly => false,
            ISO7816LengthForm::ExtendedOnly => true,
        };

        if extended_form && self.data.len() > 65535 {
            return Err(Error::DataTooLong);
        } else if !extended_form {
            if self.data.len() > 255 {
                return Err(Error::DataTooLong);
            }
            if self.ne > 256 {
                return Err(Error::NeTooLong);
            }
        }

        // §5.1: "short and extended length fields shall not be combined: either
        // both of them are short, or both of them are extended".
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

        push_length_value(
            &mut buf,
            self.data
                .len()
                .try_into()
                .map_err(|_| Error::IntegerOverflow)?,
            extended_form,
        )?;
        if self.data.len() > 0 {
            buf.extend_from_slice(&self.data);
        }
        push_length_value(&mut buf, self.ne, extended_form)?;

        Ok(buf)
    }
}

#[derive(Debug, Clone)] // Serialize, ?
pub struct ISO7816ResponseAPDU {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl<'a> TryFrom<&[u8]> for ISO7816ResponseAPDU {
    type Error = self::Error;

    /// Attempts to deserialize a ISO/IEC 7816-4 response APDU.
    fn try_from(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < 2 {
            Err(Error::ResponseTooShort)
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
    /// True if the response from the card was a simple "OK".
    pub fn is_ok(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    /// Non-zero if the card responded that further data bytes are available.
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

    /// **CTAP proprietary**: `true` if the card expects a `NFCCTAP_GETRESPONSE`
    /// command to get the actual response.
    pub fn ctap_needs_get_response(&self) -> bool {
        self.sw1 == 0x91 && self.sw2 == 0x00
    }

    pub fn is_success(&self) -> bool {
        self.is_ok() || self.bytes_available() > 0 || self.ctap_needs_get_response()
    }
}

pub fn select_by_df_name(df: &[u8]) -> ISO7816RequestAPDU {
    ISO7816RequestAPDU {
        cla: 0x00,
        ins: 0xA4, // SELECT
        p1: 0x04,  // By DF name
        p2: 0x00,  // First or only occurrence
        data: df.to_vec(),
        ne: 256,
    }
}

/// ISO/IEC 7816-4:2005 s7.6.1
pub fn get_response(cla: u8, ne: u16) -> ISO7816RequestAPDU {
    ISO7816RequestAPDU {
        cla: cla,
        ins: 0xC0, // GET RESPONSE
        p1: 0x00,
        p2: 0x00,
        data: vec![],
        ne: ne,
    }
}

pub const GET_HISTORICAL_BYTES: ISO7816RequestAPDU = ISO7816RequestAPDU {
    cla: 0x00,
    ins: 0xCA,
    p1: 0x5F,
    p2: 0x51,
    data: vec![],
    ne: 32,
};

pub const EMPTY_RESPONSE: ISO7816ResponseAPDU = ISO7816ResponseAPDU {
    data: vec![],
    sw1: 0,
    sw2: 0,
};

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! length_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, extended_form, expected): (u16, bool, Vec<u8>) = $value;
                let mut b = Vec::with_capacity(expected.len());
                assert!(push_length_value(&mut b, input, extended_form).is_ok());
                assert_eq!(expected, b);
            }
        )*
        }
    }

    macro_rules! length_errors {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, extended_form): (u16, bool) = $value;
                let mut b = Vec::with_capacity(0);
                let r = push_length_value(&mut b, input, extended_form);
                assert_eq!(Error::IntegerOverflow, r.unwrap_err());
                assert_eq!(0, b.len());
            }
        )*
        }
    }

    length_tests! {
        length_0_short: (0, false, vec![]),
        length_0_long: (0, false, vec![]),
        length_1_short: (1, false, vec![0x01]),
        length_1_long: (1, true, vec![0x00, 0x00, 0x01]),
        length_255_short: (255, false, vec![0xff]),
        length_255_long: (255, true, vec![0x00, 0x00, 0xff]),
        length_256_short: (256, false, vec![0x00]),
        length_256_long: (256, true, vec![0x00, 0x01, 0x00]),
        length_65535_long: (65535, true, vec![0x00, 0xff, 0xff]),
    }

    length_errors! {
        length_257_short: (257, false),
        length_65535_short: (65535, false),
    }
}

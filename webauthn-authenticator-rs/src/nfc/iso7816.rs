// use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// [`ISO7816RequestAPDU.to_bytes()`]: `data` was too long for the given
    /// length form.
    DataTooLong,
    /// [`ISO7816RequestAPDU.to_bytes()`]: `ne` was too long for the given length
    /// form.
    NeTooLong,
    /// [`push_length_value()`]: The given value cannot be represented in short
    /// form.
    IntegerOverflow,
    /// [`ISO7816ResponseAPDU.from_bytes()`]: response was less than 2 bytes.
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

/// ISO/IEC 7816-4 command APDU.
#[derive(Debug, Clone)]
pub struct ISO7816RequestAPDU {
    /// Class byte (`CLA`, ISO/IEC 7816-4:2005 §5.1.1).
    pub cla: u8,
    /// Instruction byte (`INS`, ISO/IEC 7816-4:2005 §5.1.2).
    pub ins: u8,
    /// Parameter byte 1 (`P1`).
    pub p1: u8,
    /// Parameter byte 2 (`P2`).
    pub p2: u8,
    /// Optional command data, up to 255 bytes in short form, or up to 65535
    /// bytes in extended form.
    pub data: Vec<u8>,

    /// The maximum expected response length from the card (`Ne`), in bytes, up
    /// to 256 bytes in short form, or 65535 bytes in extended form.
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

/// ISO/IEC 7816-4 response APDU.
#[derive(Debug, Clone, PartialEq)]
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

/// Selects an application by DF (directory file) name.
///
/// Reference: ISO/IEC 7816-4:2005 §7.1.1.
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

/// Requests a chunked response from the previous command that was too long for
/// the previous [`ISO7816RequestAPDU.ne`].
///
/// Reference: ISO/IEC 7816-4:2005 §7.6.1
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

pub const EMPTY_RESPONSE: ISO7816ResponseAPDU = ISO7816ResponseAPDU {
    data: vec![],
    sw1: 0,
    sw2: 0,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfc::APPLET_DF;

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

    macro_rules! command_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, form, expected): (ISO7816RequestAPDU, ISO7816LengthForm, Vec<u8>) = $value;
                let b = input.to_bytes(form).expect("serialisation error");
                assert_eq!(expected, b);
            }
        )*
        }
    }

    macro_rules! command_errors {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, form, expected): (ISO7816RequestAPDU, ISO7816LengthForm, Error) = $value;
                let err = input.to_bytes(form).expect_err("expected error");
                assert_eq!(expected, err);
            }
        )*
        }
    }

    macro_rules! response_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected): (Vec<u8>, ISO7816ResponseAPDU) = $value;
                let r = ISO7816ResponseAPDU::try_from(input.as_slice()).expect("deserialisation error");
                assert_eq!(expected, r);
            }
        )*
        }
    }

    macro_rules! response_errors {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let input: Vec<u8> = $value;
                let err = ISO7816ResponseAPDU::try_from(input.as_slice()).expect_err("expected error");
                assert_eq!(Error::ResponseTooShort, err);
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

    command_tests! {
        select_none_auto: (
            select_by_df_name(vec![].as_slice()),
            ISO7816LengthForm::Extended,
            vec![0x00, 0xa4, 0x04, 0x00, 0x00]),
        select_none_short: (
            select_by_df_name(vec![].as_slice()),
            ISO7816LengthForm::ShortOnly,
            vec![0x00, 0xa4, 0x04, 0x00, 0x00]),
        select_none_extended: (
            select_by_df_name(vec![].as_slice()),
            ISO7816LengthForm::ExtendedOnly,
            vec![0x00, 0xa4, 0x04, 0x00, 0x00, 0x01, 0x00]),

        select_u2f_applet_auto: (
            select_by_df_name(&APPLET_DF),
            ISO7816LengthForm::Extended,
            vec![0x00, 0xa4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00]),
        select_u2f_applet_short: (
            select_by_df_name(&APPLET_DF),
            ISO7816LengthForm::ShortOnly,
            vec![0x00, 0xa4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00]),
        select_u2f_applet_extended: (
            select_by_df_name(&APPLET_DF),
            ISO7816LengthForm::ExtendedOnly,
            vec![0x00, 0xa4, 0x04, 0x00, 0x00, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00, 0x01, 0x00]),
        
        get_response_auto: (
            get_response(0x80, 256),
            ISO7816LengthForm::Extended,
            vec![0x80, 0xc0, 0x00, 0x00, 0x00]),
        get_response_short: (
            get_response(0x80, 256),
            ISO7816LengthForm::ShortOnly,
            vec![0x80, 0xc0, 0x00, 0x00, 0x00]),
        get_response_extended: (
            get_response(0x80, 65535),
            ISO7816LengthForm::ExtendedOnly,
            vec![0x80, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xff]),
        get_response_extended_auto: (
            get_response(0x80, 65535),
            ISO7816LengthForm::Extended,
            vec![0x80, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xff]),
    }

    command_errors! {
        get_response_long_short: (
            get_response(0x80, 65535),
            ISO7816LengthForm::ShortOnly,
            Error::NeTooLong,
        ),
    }

    response_tests! {
        response_ok: (
            vec![0x90, 0x00],
            ISO7816ResponseAPDU { sw1: 0x90, sw2: 0x00, data: vec![] },
        ),
        response_data: (
            vec![0x01, 0x02, 0x03, 0x90, 0x00],
            ISO7816ResponseAPDU { sw1: 0x90, sw2: 0x00, data: vec![0x01, 0x02, 0x03] },
        ),
    }

    #[test]
    fn response_attrs() {
        // OK
        let mut r = ISO7816ResponseAPDU { sw1: 0x90, sw2: 0x00, data: vec![] };
        assert!(r.is_ok());
        assert!(r.is_success());
        assert!(!r.ctap_needs_get_response());
        assert_eq!(0, r.bytes_available());

        // More bytes available
        r = ISO7816ResponseAPDU { sw1: 0x61, sw2: 0x01, data: vec![] };
        assert!(!r.is_ok());
        assert!(r.is_success());
        assert!(!r.ctap_needs_get_response());
        assert_eq!(1, r.bytes_available());

        r = ISO7816ResponseAPDU { sw1: 0x61, sw2: 0x00, data: vec![] };
        assert!(!r.is_ok());
        assert!(r.is_success());
        assert!(!r.ctap_needs_get_response());
        assert_eq!(256, r.bytes_available());

        // Needs NFCCTAP_GETRESPONSE
        r = ISO7816ResponseAPDU { sw1: 0x91, sw2: 0x00, data: vec![] };
        assert!(!r.is_ok());
        assert!(r.is_success());
        assert!(r.ctap_needs_get_response());
        assert_eq!(0, r.bytes_available());

        // Error
        r = ISO7816ResponseAPDU { sw1: 0x6A, sw2: 0x82, data: vec![] };
        assert!(!r.is_ok());
        assert!(!r.is_success());
        assert!(!r.ctap_needs_get_response());
        assert_eq!(0, r.bytes_available());
    }

    response_errors! {
        response_empty: vec![],
        response_1_byte: vec![0x90],
    }
}

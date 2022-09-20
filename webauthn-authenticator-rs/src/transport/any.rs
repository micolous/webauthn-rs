use crate::transport::*;
#[cfg(feature = "nfc")]
use crate::nfc::*;
#[cfg(feature = "usb")]
use crate::usb::*;

/// [AnyTransport] merges all available transports for the platform.
/// 
/// If you don't care which transport is used for tokens, prefer to use
/// [AnyTransport] for the best experience.
#[derive(Debug)]
pub struct AnyTransport {
    #[cfg(feature = "nfc")]
    nfc: NFCReader,
    #[cfg(feature = "usb")]
    usb: USBTransport,
}

/// [AnyToken] abstracts calls to NFC and USB security tokens.
#[derive(Debug)]
pub enum AnyToken {
    #[cfg(feature = "nfc")]
    Nfc(NFCCard),
    #[cfg(feature = "usb")]
    Usb(USBToken),
}

impl Default for AnyTransport {
    fn default() -> Self {
        Self {
            #[cfg(feature = "nfc")]
            nfc: NFCReader::default(),
            #[cfg(feature = "usb")]
            usb: USBTransport::default(),
        }
    }
}

impl Transport for AnyTransport {
    type Token = AnyToken;

    fn tokens(&mut self) -> Result<Vec<Self::Token>, WebauthnCError> {
        let mut o: Vec<Self::Token> = Vec::new();
        #[cfg(feature = "nfc")]
        {
            let mut tokens = self.nfc.tokens()?;
            while let Some(t) = tokens.pop() {
                o.push(AnyToken::Nfc(t));
            }
        }

        #[cfg(feature = "usb")]
        {
            let mut tokens = self.usb.tokens()?;
            while let Some(t) = tokens.pop() {
                o.push(AnyToken::Usb(t));
            }
        }

        Ok(o)
    }
}

impl Token for AnyToken {
    fn transmit<C, R>(&self, cmd: C) -> Result<R, WebauthnCError>
    where
        C: CBORCommand<Response = R>,
        R: CBORResponse,
    {
        match self {
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => Token::transmit(n, cmd),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => Token::transmit(u, cmd),
        }
    }

    fn init(&mut self) -> Result<(), WebauthnCError> {
        match self {
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => n.init(),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.init(),
        }
    }

    fn close(&self) -> Result<(), WebauthnCError> {
        match self {
            #[cfg(feature = "nfc")]
            AnyToken::Nfc(n) => n.close(),
            #[cfg(feature = "usb")]
            AnyToken::Usb(u) => u.close(),
        }
    }
}

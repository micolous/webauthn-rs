use webauthn_authenticator_rs::nfc::*;
use webauthn_authenticator_rs::transport::*;
use webauthn_authenticator_rs::usb::*;

fn access_card<T: Token>(card: T) {
    info!("Card detected ...");

    match card.select_any() {
        Ok(Selected::FIDO_2_1_PRE(mut token)) => {
            info!("Using token {:?}", token);

            token.hack_make_cred();
            token.deselect_applet();
        }
        _ => {
            unimplemented!();
        }
    }
}

pub(crate) fn event_loop() {
    let mut reader = USBTransport::default();
    // let mut reader = NFCReader::default();
    info!("Using reader: {:?}", reader);

    while let Ok(mut tokens) = reader.tokens() {
        while let Some(mut card) = tokens.pop() {
            card.init();
            access_card(card);
        }

    }
}

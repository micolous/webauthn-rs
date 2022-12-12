use std::fmt::Debug;
use std::io::{stderr, Write};
use qrcode::{QrCode, render::unicode::Dense1x2};

use crate::ctap2::EnrollSampleStatus;

pub trait UiCallback: Sync + Send + Debug {
    /// Prompts the user to enter their PIN.
    fn request_pin(&self) -> Option<String>;

    /// Prompts the user to interact with their authenticator, normally by
    /// pressing or touching its button.
    ///
    /// This method will be called synchronously, and must not block.
    fn request_touch(&self);

    /// Provide the user feedback when they are enrolling fingerprints.
    ///
    /// This method will be called synchronously, and must not block.
    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    );

    /// Prompt the user to scan a QR code with their mobile device to start the
    /// caBLE linking process.
    /// 
    /// This method will be called synchronously, and must not block.
    fn cable_qr_code(
        &self,
        url: String,
    );

    /// Dismiss a displayed QR code from the screen.
    /// 
    /// This method will be called synchronously, and must not block.
    fn dismiss_qr_code(
        &self,
    );

}

/// Basic CLI [UiCallback] implementation.
///
/// This gets input from `stdin` and sends messages to `stderr`.
///
/// This is only intended for testing, and doesn't implement much functionality (like localization).
#[derive(Debug)]
pub struct Cli {}

impl UiCallback for Cli {
    fn request_pin(&self) -> Option<String> {
        rpassword::prompt_password_stderr("Enter PIN: ").ok()
    }

    fn request_touch(&self) {
        let mut stderr = stderr();
        writeln!(stderr, "Touch the authenticator").ok();
    }

    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    ) {
        let mut stderr = stderr();
        writeln!(stderr, "Need {} more sample(s)", remaining_samples).ok();
        if let Some(feedback) = feedback {
            writeln!(stderr, "Last impression was {:?}", feedback).ok();
        }
    }

    fn cable_qr_code(
        &self,
        url: String,
    ) {
        let qr = QrCode::new(url).unwrap();

        let code = qr
            .render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .build();
        println!("Scan the QR code with your mobile device to use caBLE:");
        println!("{}", code);
    }

    fn dismiss_qr_code(
        &self,
    ) {
        println!("caBLE authenticator detected, connecting...");
    }
}

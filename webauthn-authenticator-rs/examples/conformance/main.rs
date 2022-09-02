#[cfg(not(all(feature = "nfc", feature = "nfc_debug")))]
compile_error!("This example requires the feature \"nfc\" and \"nfc_debug\" features.");

#[cfg(all(feature = "nfc", feature = "nfc_debug"))]
#[macro_use]
extern crate tracing;

#[cfg(all(feature = "nfc", feature = "nfc_debug"))]
mod core;

fn main() {
    tracing_subscriber::fmt::init();
    #[cfg(all(feature = "nfc", feature = "nfc_debug"))]
    core::main();
}

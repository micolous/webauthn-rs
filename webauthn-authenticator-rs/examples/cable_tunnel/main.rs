//! `cable_tunnel` shares a [Token] over a caBLE connection.

#[macro_use]
extern crate tracing;

#[cfg(feature = "cable")]
mod core;

fn main() {
    #[cfg(feature = "cable")]
    core::main();

    #[cfg(not(feature = "cable"))]
    error!("This example requires the feature \"cable\" to be enabled.");
}

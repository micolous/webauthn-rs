#[macro_use]
extern crate tracing;

// mod core;
use webauthn_authenticator_rs::prelude::Url;
use webauthn_authenticator_rs::AuthenticatorBackend;
use webauthn_rs_core::WebauthnCore as Webauthn;

fn main() {
    let wan = Webauthn::new_unsafe_experts_only(
        "https://localhost:8080/auth",
        "localhost",
        vec![url::Url::parse("https://localhost:8080").unwrap()],
        None,
        None,
        None,
    );

    let unique_id = [
        158, 170, 228, 89, 68, 28, 73, 194, 134, 19, 227, 153, 107, 220, 150, 238,
    ];
    let name = "william";

    let (chal, reg_state) = wan
        .generate_challenge_register(&unique_id, name, name, false)
        .unwrap();

    info!("🍿 challenge -> {:x?}", chal);

    let mut u = webauthn_authenticator_rs::win10::Win10::default();

    let r = u
        .perform_register(
            Url::parse("https://localhost:8080").unwrap(),
            chal.public_key,
            60_000,
        )
        .unwrap();

    let cred = wan.register_credential(&r, &reg_state, None).unwrap();

    trace!(?cred);

    let (chal, auth_state) = wan
        .generate_challenge_authenticate(vec![cred], None)
        .unwrap();

    let r = u
        .perform_auth(
            Url::parse("https://localhost:8080").unwrap(),
            chal.public_key,
            60_000,
        )
        .map_err(|e| {
            error!("Error -> {:x?}", e);
            e
        })
        .expect("Failed to auth");

    let auth_res = wan
        .authenticate_credential(&r, &auth_state)
        .expect("webauth authentication denied");

    info!("auth_res -> {:x?}", auth_res);

    // tracing_subscriber::fmt::init();

    // core::event_loop();
}

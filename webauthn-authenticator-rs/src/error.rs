#[derive(Debug)]
pub enum WebauthnCError {
    Json,
    Cbor,
    Ctap,
    Unknown,
    Security,
    NotSupported,
    PlatformAuthenticator,
    Internal,
    ParseNOMFailure,
    OpenSSL,
    ApduConstruction,
    ApduTransmission,
    InvalidAlgorithm,
    InvalidAssertion,
}

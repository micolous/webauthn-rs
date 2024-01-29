#[cfg(any(all(doc, not(doctest)), feature = "vendor-yubikey"))]
pub mod ber;

#[cfg(any(all(doc, not(doctest)), feature = "nfc"))]
pub mod compact;

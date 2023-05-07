#[cfg(not(any(feature = "nfc", feature = "usb")))]
compile_error!(
    "you must build this tool with either the 'nfc' or 'usb' feature for it to do something useful"
);

extern crate tracing;

use hex::{FromHex, FromHexError};
use std::io::{stdin, stdout, Write};
use std::time::Duration;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand};
use openssl::sha::Sha256;

use webauthn_authenticator_rs::{
    ctap2::{select_one_token, CtapAuthenticator},
    transport::*,
    ui::Cli,
    SHA256Hash,
};
use webauthn_rs_core::interface::COSEKeyType;

/// Parses a Base-16 encoded string.
///
/// This function is intended for use as a `clap` `value_parser`.
pub fn parse_hex<T>(i: &str) -> Result<T, FromHexError>
where
    T: FromHex<Error = FromHexError>,
{
    FromHex::from_hex(i)
}

#[derive(Debug, Args)]
pub struct SetPinOpt {
    #[clap(short, long)]
    pub new_pin: String,
}

#[derive(Debug, Args)]
pub struct ChangePinOpt {
    #[clap(short, long)]
    pub old_pin: String,

    #[clap(short, long)]
    pub new_pin: String,
}

#[derive(Debug, Args)]
#[clap(group(
    ArgGroup::new("policy")
        .multiple(true)
        .required(true)
        .args(&["length", "rpids", "force-change"])))]
pub struct SetPinPolicyOpt {
    /// Sets the minimum PIN length, in Unicode codepoints.
    #[clap(short, long)]
    pub length: Option<u32>,

    /// Sets the RPIDs which are authorised to use the `minPinLength` extension. May be specified many times.
    #[clap(short, long)]
    pub rpids: Option<Vec<String>>,

    /// Invalidates the existing PIN, forcing it to be changed before the token can be used again.
    #[clap(long, action = ArgAction::SetTrue)]
    pub force_change: bool,
}

#[derive(Debug, Args)]
pub struct EnrollFingerprintOpt {
    /// A human-readable name for the finger (eg: 'left thumb')
    #[clap()]
    pub friendly_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct RenameFingerprintOpt {
    /// The template ID
    #[clap()]
    pub id: String,

    /// A human-readable name for the finger (eg: 'left thumb')
    #[clap()]
    pub friendly_name: String,
}

#[derive(Debug, Args)]
pub struct RemoveFingerprintOpt {
    /// The template ID(s) to remove
    #[clap(required = true)]
    pub id: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ListCredentialsOpt {
    /// List credentials for a relying party ID (eg: "example.com")
    #[clap(long, value_name = "RPID", conflicts_with = "hash")]
    pub rpid: Option<String>,

    /// List credentials for the SHA-256 hash of a relying party ID
    /// (eg: "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947")
    #[clap(long, value_parser = parse_hex::<SHA256Hash>, value_name = "HASH")]
    pub hash: Option<SHA256Hash>,
}

#[derive(Debug, Args)]
pub struct DeleteCredentialOpt {
    /// Credential ID to delete, encoded in base16
    /// (eg: "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947")
    #[clap(required = true, action = ArgAction::Set, value_parser = parse_hex::<Vec<u8>>, value_name = "HASH")]
    pub id: std::vec::Vec<u8>,
}

#[derive(Debug, Subcommand)]
#[clap(about = "authenticator key manager")]
pub enum Opt {
    /// Request user presence on a connected FIDO token.
    Selection,
    /// Show information about the connected FIDO token.
    Info,
    /// Resets the connected FIDO token to factory settings, deleting all keys.
    ///
    /// This command will only work for the first 10 seconds since the token was
    /// plugged in, _may_ only work on _one_ transport (for multi-interface
    /// tokens), and is only _guaranteed_ to work over USB HID.
    FactoryReset,
    /// Toggles the "Always Require User Verification" feature.
    ToggleAlwaysUv,
    /// Enables the "Enterprise Attestation" feature.
    EnableEnterpriseAttestation,
    /// Gets information about biometric authentication on the device.
    BioInfo,
    /// Enrolls a fingerprint on the device.
    ///
    /// Note: you must set a PIN on the device before you can enroll any
    /// fingerprints.
    EnrollFingerprint(EnrollFingerprintOpt),
    /// Lists all enrolled fingerprints on the device.
    ListFingerprints,
    /// Renames an enrolled fingerprint.
    RenameFingerprint(RenameFingerprintOpt),
    /// Removes an enrolled fingerprint.
    RemoveFingerprint(RemoveFingerprintOpt),
    /// Sets policies for PINs.
    SetPinPolicy(SetPinPolicyOpt),
    /// Sets a PIN on a FIDO token which does not already have one.
    SetPin(SetPinOpt),
    /// Changes a PIN on a FIDO token which already has a PIN set.
    ChangePin(ChangePinOpt),
    GetCredentialMetadata,
    /// List all discoverable credentials on this token. If neither filtering
    /// option is specified, shows a list of all RPs with discoverable
    /// credentials on this token.
    ListCredentials(ListCredentialsOpt),
    DeleteCredential(DeleteCredentialOpt),
}

#[derive(Debug, clap::Parser)]
#[clap(about = "FIDO key management tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

pub fn base16_encode<T: IntoIterator<Item = u8>>(i: T) -> String {
    i.into_iter().map(|c| format!("{c:02X}")).collect()
}

pub fn base16_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

#[tokio::main]
async fn main() {
    println!("DANGER: make sure you only have one key connected");
    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();

    let ui = Cli {};
    let mut transport = AnyTransport::new().await.unwrap();
    let mut tokens = transport.connect_all(&ui).expect("connect_all");

    if tokens.is_empty() {
        println!("No tokens available!");
        return;
    }

    let token_count = tokens.len();
    // let authenticator = select_transport(&ui);
    let authenticator = &mut tokens[0];

    match opt.commands {
        Opt::Selection => {
            let token = select_one_token(tokens.iter_mut()).await;
            println!("selected token: {token:?}");
        }

        Opt::Info => {
            for token in &tokens {
                println!("{}", token.get_info());
            }
        }

        Opt::FactoryReset => {
            assert_eq!(token_count, 1);
            println!("Resetting token to factory settings. Type 'yes' to continue.");
            let mut buf = String::new();
            stdout().flush().ok();
            stdin().read_line(&mut buf).expect("Cannot read stdin");
            buf = buf.trim_end().to_ascii_lowercase();

            if buf == "yes" {
                authenticator
                    .factory_reset()
                    .await
                    .expect("Error resetting token");
            } else {
                panic!("Unexpected response {buf:?}, exiting!");
            }
        }

        Opt::ToggleAlwaysUv => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter_map(|t| match t {
                    CtapAuthenticator::Fido21(a) => Some(a),
                    _ => None,
                })
                .filter(|t| t.supports_config())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting CTAP 2.1 authenticatorConfig"
            );
            tokens[0]
                .toggle_always_uv()
                .await
                .expect("Error toggling UV");
        }

        Opt::EnableEnterpriseAttestation => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter_map(|t| match t {
                    CtapAuthenticator::Fido21(a) => Some(a),
                    _ => None,
                })
                .filter(|t| t.supports_config() && t.supports_enterprise_attestation())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting CTAP 2.1 authenticatorConfig"
            );
            tokens[0]
                .enable_enterprise_attestation()
                .await
                .expect("Error enabling enterprise attestation");
        }

        Opt::BioInfo => {
            for token in &mut tokens {
                if let Some(b) = token.bio() {
                    let i = b.get_fingerprint_sensor_info().await;
                    println!("Fingerprint sensor info: {i:?}");
                } else {
                    println!("Authenticator does not support biometrics")
                }
            }
        }

        Opt::EnrollFingerprint(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_biometrics())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting biometrics"
            );
            let id = tokens[0]
                .bio()
                .unwrap()
                .enroll_fingerprint(Duration::from_secs(30), o.friendly_name)
                .await
                .expect("enrolling fingerprint");
            println!("Enrolled fingerpint {}", base16_encode(id));
        }

        Opt::ListFingerprints => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_biometrics())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting biometrics"
            );
            let fingerprints = tokens[0]
                .bio()
                .unwrap()
                .list_fingerprints()
                .await
                .expect("listing fingerprints");

            println!("{} enrolled fingerprint(s):", fingerprints.len());
            for t in fingerprints {
                println!(
                    "* ID: {}, Name: {:?}",
                    base16_encode(t.id),
                    t.friendly_name.unwrap_or_default()
                );
            }
        }

        Opt::RenameFingerprint(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_biometrics())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting biometrics"
            );

            tokens[0]
                .bio()
                .unwrap()
                .rename_fingerprint(base16_decode(&o.id).expect("decoding ID"), o.friendly_name)
                .await
                .expect("renaming fingerprint");
        }

        Opt::RemoveFingerprint(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_biometrics())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting biometrics"
            );

            let ids: Vec<Vec<u8>> =
                o.id.iter()
                    .map(|i| base16_decode(i).expect("decoding ID"))
                    .collect();
            tokens[0]
                .bio()
                .unwrap()
                .remove_fingerprints(ids)
                .await
                .expect("removing fingerprint");
        }

        Opt::SetPinPolicy(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter_map(|t| match t {
                    CtapAuthenticator::Fido21(a) => Some(a),
                    _ => None,
                })
                .filter(|t| t.supports_config())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting CTAP 2.1 authenticatorConfig"
            );
            tokens[0]
                .set_min_pin_length(
                    o.length,
                    o.rpids.unwrap_or_default(),
                    if o.force_change { Some(true) } else { None },
                )
                .await
                .expect("error setting policy");
        }

        Opt::SetPin(o) => {
            assert_eq!(token_count, 1);
            authenticator
                .set_new_pin(&o.new_pin)
                .await
                .expect("Error setting PIN");
        }

        Opt::ChangePin(o) => {
            assert_eq!(token_count, 1);
            authenticator
                .change_pin(&o.old_pin, &o.new_pin)
                .await
                .expect("Error changing PIN");
        }

        Opt::GetCredentialMetadata => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_credential_management())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting credential management"
            );

            let (creds, remain) = tokens[0]
                .credential_management()
                .unwrap()
                .get_credentials_metadata()
                .await
                .expect("Error getting credential metadata");
            println!("{creds} discoverable credential(s), {remain} maximum slot(s) free");
        }

        Opt::ListCredentials(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_credential_management())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting credential management"
            );

            let cm = tokens[0].credential_management().unwrap();

            let rp_id_hash = if let Some(rpid) = o.rpid {
                let mut h = Sha256::new();
                h.update(rpid.as_bytes());
                let h = h.finish();
                h
            } else if let Some(hash) = o.hash {
                hash
            } else {
                let rps = cm.enumerate_rps().await.expect("Error enumerating RPs");
                println!("{} RP(s):", rps.len());
                for (rp, hash) in rps {
                    print!("* {}: {}", hex::encode(hash), rp.id.unwrap_or_default());
                    if let Some(name) = &rp.name {
                        println!(" ({})", name);
                    } else {
                        println!();
                    }
                }
                return;
            };

            let creds = cm
                .enumerate_credentials_by_hash(rp_id_hash)
                .await
                .expect("Error listing credentials");

            println!(
                "{} credential(s) for {}:",
                creds.len(),
                hex::encode(rp_id_hash)
            );
            for (i, cred) in creds.iter().enumerate() {
                println!("Credential #{}:", i + 1);
                if let Some(cred_id) = &cred.credential_id {
                    println!("  ID: {}", hex::encode(&cred_id.id));
                    if !cred_id.transports.is_empty() {
                        println!("  Transports: {:?}", cred_id.transports);
                    }
                }
                if let Some(user) = &cred.user {
                    println!("  User info:");
                    println!("    User ID: {}", hex::encode(&user.id));
                    if let Some(name) = &user.name {
                        println!("    Name: {}", name);
                    }
                    if let Some(display_name) = &user.display_name {
                        println!("    Display name: {}", display_name);
                    }
                }

                if let Some(public_key) = &cred.public_key {
                    println!("  Public key algorithm: {:?}", public_key.type_);
                    match &public_key.key {
                        COSEKeyType::EC_OKP(okp) => {
                            println!("  Octet key pair, curve {:?}", okp.curve);
                            println!("    X-coordinate: {}", hex::encode(&okp.x));
                        }
                        COSEKeyType::EC_EC2(ec) => {
                            println!("  Elliptic curve key, curve {:?}", ec.curve);
                            println!("    X-coordinate: {}", hex::encode(&ec.x.0));
                            println!("    Y-coordinate: {}", hex::encode(&ec.y.0));
                        }
                        COSEKeyType::RSA(rsa) => {
                            println!("  RSA modulus: {}", hex::encode(&rsa.n.0));
                            println!("    Exponent: {}", hex::encode(&rsa.e));
                        }
                    }
                }
                if let Some(policy) = &cred.cred_protect {
                    println!("  Credential protection policy: {:?}", policy);
                }

                if let Some(key) = &cred.large_blob_key {
                    println!("  Large blob key: {}", hex::encode(key));
                }
            }
        }

        Opt::DeleteCredential(o) => {
            let mut tokens: Vec<_> = tokens
                .drain(..)
                .filter(|t| t.supports_credential_management())
                .collect();
            assert_eq!(
                tokens.len(),
                1,
                "Expected exactly one authenticator supporting credential management"
            );

            println!("Deleting credential {}...", hex::encode(&o.id));
            tokens[0]
                .credential_management()
                .unwrap()
                .delete_credential(o.id.into())
                .await
                .expect("Error deleting credential");
        }
    }
}

extern crate tracing;

use std::fs::OpenOptions;
use std::io::{stdin, stdout, Write};
use std::time::Duration;

use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand};
use webauthn_authenticator_rs::softtoken::SoftToken;

#[derive(Debug, clap::Parser)]
#[clap(about = "SoftToken management tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

#[derive(Debug, Subcommand)]
pub enum Opt {
    Create(CreateArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[clap()]
    pub filename: String,
}

fn main() {
    use Opt::*;

    let opt = CliParser::parse();
    tracing_subscriber::fmt::init();
    match opt.commands {
        Create(args) => {
            let (authenticator, _) = SoftToken::new().unwrap();
            let d = authenticator.to_cbor().unwrap();

            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(args.filename)
                .unwrap();
            f.write_all(&d).unwrap();
            f.flush().unwrap();
            drop(f);
        }
    }
}

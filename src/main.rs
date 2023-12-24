// Self-sovereign identity (SSID)
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2023-204 by
//     Cypher<cypher@cyphernet.io>
//
// Copyright 2023-2024 Cyphernet DAO, Switzerland
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate clap;

use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, io};

use bpstd::Address;
use clap::{Parser, ValueHint};
use ssid::{BindleContent, Fingerprint, RistrettoPk, Seal, Ssi};

pub const DATA_DIR_ENV: &str = "SSID_DATA_DIR";
#[cfg(any(target_os = "linux"))]
pub const DATA_DIR: &str = "~/.ssid";
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub const DATA_DIR: &str = "~/.ssid";
#[cfg(target_os = "macos")]
pub const DATA_DIR: &str = "~/Library/Application Support/SSID";
#[cfg(target_os = "windows")]
pub const DATA_DIR: &str = "~\\AppData\\Local\\SSID";
#[cfg(target_os = "ios")]
pub const DATA_DIR: &str = "~/Documents";
#[cfg(target_os = "android")]
pub const DATA_DIR: &str = ".";

pub const DEFAULT_ESPLORA: &str = "https://blockstream.info/testnet/api";

#[derive(Parser, Clone, Eq, PartialEq, Debug)]
#[command(author, version, about = "Self-sovereign identity command-line tool", long_about = Some("Suite for working with self-sovereign identity.

Self-sovereign identity is an identity format developed by Cyphernet 
Association, Switzerland. Being similar to OpenPGP, it operates without 
any key servers, using blockchain infrastructure. This allows provable and 
globally enforceable key revocation without dedicated revocation keys, 
global propagation of new keys information and provable or unique 
signatures which are timestamped or created using single-use-seal 
mechanism."))]
pub struct Cli {
    /// Produce verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Data directory path.
    ///
    /// Path to the directory that contains RGB stored data.
    #[arg(
        short,
        long,
        global = true,
        default_value = DATA_DIR,
        env = DATA_DIR_ENV,
        value_hint = ValueHint::DirPath
    )]
    pub data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn process(&mut self) -> Result<(), io::Error> {
        self.data_dir =
            PathBuf::from(shellexpand::tilde(&self.data_dir.display().to_string()).to_string());
        fs::create_dir_all(&self.data_dir)
    }
}

#[derive(Subcommand, Clone, Eq, PartialEq, Debug)]
pub enum Command {
    /// Generate new identity
    Generate {
        /// Single-use-seal definition which should be used for revocation
        seal: Seal,
    },

    /// Revoke existing key
    Revoke {
        /// Identity which key should be revoked
        identity: IdArg,

        // /// Output descriptor for the seal which is closed
        // descriptor: StdDescr,
        /// Address to pay the remaining funds
        address: Address,

        /// File to save generated PSBT used for the revocation
        #[clap(value_hint = ValueHint::DirPath)]
        psbt: Option<PathBuf>,
    },

    /// List known identities
    List {},

    /// Add an identity to an address book
    Add {},

    /// Export public information about identity
    Export {},

    /// Sign using identity
    Sign {},

    /// Verify signature
    Verify {},

    /// Encrypt for a given identities
    Encrypt {},

    /// Decrypt previously encrypted data
    Decrypt {},
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, From)]
#[display(inner)]
pub enum IdArg {
    #[from]
    Fingerprint(Fingerprint),
}

impl FromStr for IdArg {
    type Err = amplify::hex::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Fingerprint::from_str(s).map(Self::Fingerprint)
    }
}

fn main() -> Result<(), io::Error> {
    let mut cli = Cli::parse();
    cli.process()?;

    match cli.command {
        Command::Generate { seal } => {
            let ssi = Ssi::<RistrettoPk>::new(seal);
            let fp = ssi.fingerprint();
            let (mut sk_file, mut pk_file) = (cli.data_dir.clone(), cli.data_dir.clone());
            sk_file.push(format!("{fp}"));
            pk_file.push(format!("{fp}_pub"));
            fs::write(sk_file, &ssi.sk.bindle().to_string())?;
            fs::write(pk_file, &ssi.cert.bindle().to_string())?;
        }
        _ => todo!(),
    }

    Ok(())
}

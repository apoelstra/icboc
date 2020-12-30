// ICBOC 3D
// Written in 2020 by
//   Andrew Poelstra <icboc@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Argument Parsing
//!
//! Different subcommands supported by the command-line utility  
//!

use anyhow::{self, Context};
use icboc::Wallet;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
pub enum Command {
    /// Initialize a new wallet
    Init {
        /// Whether to initialize the wallet even if it already exists
        #[structopt(short, long)]
        force: bool,
    },
    Info {
        #[structopt(name="what")]
        what: Option<String>,
    },
}

#[derive(StructOpt)]
#[structopt(about = "a simple wallet software for the Ledger Nano S")]
pub struct Options {
    /// Wallet data file to operate on
    #[structopt(name="wallet_file", parse(from_os_str))]
    pub wallet_file: PathBuf,
    /// Action to take on the wallet
    #[structopt(subcommand)]
    pub command: Command,

    /// RPC hostname to connect to the bitcoind on
    #[structopt(short="h", long="rpchost", default_value="localhost")]
    pub rpchost: String,
    /// RPC port to connect to the bitcoind on
    #[structopt(short="p", long="rpcport", default_value="8332")]
    pub rpcport: u16,
    /// Cookie file from which to get a fixed user-pass pair. For normal authentication
    /// you can create such a file manually with the format username:password
    #[structopt(short="c", long="rpccookie", default_value="~/.bitcoin/.cookie")]
    pub rpccookie: String,
}

impl Command {
    /// Executes the command
    pub fn execute(&self, wallet_file: &PathBuf, wallet_key: [u8; 32]) -> anyhow::Result<()> {
        let wallet_name = wallet_file.to_string_lossy();

        match *self {
            Command::Init { force } => {
                if fs::metadata(wallet_file).is_ok() {
                    if force {
                        println!("WARNING: file {} already exists, overwriting.", wallet_name);
                    } else {
                        println!("File {} already exists, refusing to overwrite.", wallet_name);
                        return Err(anyhow::Error::msg("will not overwrite file with new wallet"));
                    }
                }

                let fh = fs::File::create(wallet_file)?;
                icboc::Wallet::new().write(fh, wallet_key)
                    .with_context(|| format!("writing to wallet {}", wallet_name))?;
                println!("Initialized wallet at {}.", wallet_name);
            },
            Command::Info { ref what } => {
                let fh = fs::File::open(wallet_file)
                    .with_context(|| format!("opening wallet {}", wallet_name))?;
                let wallet = icboc::Wallet::from_reader(fh, wallet_key)
                    .with_context(|| format!("reading wallet {}", wallet_name))?;
                if let Some(ref thing) = *what {
                } else {
                    println!("Opened wallet at {} with {} descriptors and {} txos.", wallet_name, wallet.descriptors.len(), wallet.txos.len());
                    println!("Assuming height {} is confirmed and will not rescan these blocks except when importing descriptors.", wallet.block_height);
                }
            },
        }
        Ok(())
    }
}


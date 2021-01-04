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
use icboc::{Dongle, Wallet};
use icboc::ledger::NanoS;
use miniscript::bitcoin;
use std::fs;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

use crate::rpc;

#[derive(StructOpt)]
pub enum Command {
    /// Initialize a new wallet
    Init {
        /// Whether to initialize the wallet even if it already exists
        #[structopt(short, long)]
        force: bool,
    },
    /// Gets information about the wallet or objects it contains
    Info {
        #[structopt(name="what")]
        what: Option<String>,
    },
    /// Imports a descriptor into the wallet
    ImportDescriptor {
        /// The descriptor to import
        #[structopt(name="descriptor")]
        desc: miniscript::Descriptor<miniscript::DescriptorPublicKey>,
        /// For ranged descriptors, first index to use. If a minimum is provided
        /// without a maximum, will instead use the range 0 through min.
        #[structopt(name="range_min")]
        lo: Option<u32>,
        /// For ranged descriptors, last index to use
        #[structopt(name="range_max")]
        hi: Option<u32>,
    },
    /// List every TXO known by the wallet
    ListAll,
    /// List every unsepent TXO known by the wallet
    ListUnspent,
    /// Scans the blockchain to learn about new coins
    Rescan {
        /// Height at which to scan from. Defaults to the height the
        /// wallet most recently scanned to, minus 100.
        from: Option<u64>,
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
    pub fn execute<P: AsRef<Path>>(
        self,
        wallet_file: P,
        wallet_key: [u8; 32],
        bitcoind: &rpc::Bitcoind,
        dongle: &mut NanoS,
    ) -> anyhow::Result<()> {
        fn save_out<P: AsRef<Path>>(
            wallet: &Wallet,
            wallet_file: P,
            wallet_key: [u8; 32],
            wallet_nonce: [u8; 12],
        ) -> anyhow::Result<()> {
            let wallet_name = wallet_file.as_ref().to_string_lossy().into_owned();
            // Write out wallet
            let tmp_name = wallet_name.clone() + ".tmp";
            let fh = fs::File::create(&tmp_name)?;
            wallet.write(fh, wallet_key, wallet_nonce)
                .with_context(|| format!("writing to wallet {}", wallet_name))?;
            // Above line took `fh` by value, dropping it, so we can safely rename here
            fs::rename(&tmp_name, &wallet_file)
                .with_context(|| format!("renaming {} to {}", tmp_name, wallet_name))?;
            Ok(())
        }

        let wallet_name = wallet_file.as_ref().to_string_lossy();
        let wallet_nonce = dongle.get_random_nonce()
            .context("getting random encryption IV from device")?;
println!("{:?}", wallet_nonce);

        let mut wallet;
        if let Command::Init { .. } = self {
            wallet = Wallet::new();
        } else {
            let fh = fs::File::open(&wallet_file)
                .with_context(|| format!("opening wallet {}", wallet_name))?;
            wallet = Wallet::from_reader(fh, wallet_key)
                .with_context(|| format!("reading wallet {}", wallet_name))?;
            println!(
                "Opened wallet at {} with {} descriptors and {} txos.",
                wallet_name,
                wallet.descriptors.len(),
                wallet.txos.len(),
            );
            let mut full_balance = 0;
            if !wallet.descriptors.is_empty() {
                println!("Descriptors:");
                for (n, desc) in wallet.descriptors() {
                    let txos = wallet.txos_for(n);
                    let mut n_spent = 0;
                    let mut balance = 0;
                    for txo in &txos {
                        if txo.spending_txid().is_some() {
                            n_spent += 1;
                        } else {
                            balance += txo.value();
                        }
                    }
                    println!("  {:4} {}", n, desc.desc);
                    println!("       Range: {}-{}", desc.low, desc.high - 1);
                    println!("       TXOs: {} total, {} spent", txos.len(), n_spent);
                    println!("       Balance: {}", bitcoin::Amount::from_sat(balance));
                    println!("");
                    full_balance += balance;
                }
            }
            println!("Wallet balance: {}", bitcoin::Amount::from_sat(full_balance));
            println!("");
        }

        match self {
            Command::Init { force } => {
                if fs::metadata(&wallet_file).is_ok() {
                    if force {
                        println!("WARNING: file {} already exists, overwriting.", wallet_name);
                    } else {
                        println!("File {} already exists, refusing to overwrite.", wallet_name);
                        return Err(anyhow::Error::msg("will not overwrite file with new wallet"));
                    }
                }

                let fh = fs::File::create(&wallet_file)?;
                wallet.write(fh, wallet_key, wallet_nonce)
                    .with_context(|| format!("writing to wallet {}", wallet_name))?;
                println!("Initialized wallet at {}.", wallet_name);
                return Ok(());
            },
            Command::Info { ref what } => {
                if let Some(ref thing) = *what {
                    // TODO
                } else {
                    println!("Last rescan was to height {}.", wallet.block_height);
                    let master_xpub = dongle.get_master_xpub()?;
                    println!("Dongle master xpub: {}", master_xpub);
                    println!("Dongle master fingerprint: {}", master_xpub.fingerprint());
                }
            },
            Command::ImportDescriptor { desc, lo, hi } => {
                let range = match (lo, hi) {
                    (None, None) => 0..101,
                    (Some(lo), None) => 0..lo + 1,
                    (Some(lo), Some(hi)) => lo..hi + 1,
                    (None, Some(_)) => unreachable!("structopt won't let this happen"),
                };
                if range.start >= range.end {
                    return Err(anyhow::Error::msg(format!("invalid range {:?}", range)));
                }

                println!("Asked to import descriptor {}. Generating addresses from {} through {}", desc, range.start, range.end - 1);
                let n_added = wallet.add_descriptor(desc, range.start, range.end, &mut *dongle)
                    .with_context(|| "importing descriptor")?;
                if n_added == 0 {
                    println!("Wallet already has all keys from {} through {}.", range.start, range.end - 1);
                    return Err(anyhow::Error::msg("nothing to do"));
                }
                println!("Imported {} new addresses. You should now call `rescan`.", n_added);
            },
            Command::ListAll => {
                for txo in wallet.txos.values() {
                    println!("{}", txo);
                }
            },
            Command::ListUnspent => {
                for txo in wallet.txos.values().filter(|txo| txo.spending_txid().is_none()) {
                    println!("{}", txo);
                }
            },
            Command::Rescan { from } => {
                let mut cache = wallet.script_pubkey_cache(&mut *dongle)
                    .context("getting scriptpubkeys from wallet")?;

                let mut height = from.unwrap_or(wallet.block_height.saturating_sub(100));
                let mut max_height = bitcoind.getblockcount()
                    .context("getting initial block count")?;

                println!("Scanning from block {}. Current height: {}", height, max_height);
                while height < max_height {
                    let block = bitcoind.getblock(height)
                        .with_context(|| format!("fetching block {}", height))?;

                    if height > 0 && height % 1000 == 0 {
                        wallet.block_height = height;
                        save_out(&wallet, &wallet_file, wallet_key, wallet_nonce)
                            .with_context(|| format!("saving wallet at height {}", height))?;
                        println!("Height {:7}: {} {:?}", height, block.block_hash(), std::time::Instant::now());
                    }

                    let (received, spent) = wallet.scan_block(&block, height, &mut cache)
                        .with_context(|| format!("updating wallet from block {}", height))?;
                    for txo in received {
                        println!("received {}", txo);
                    }
                    for txo in spent {
                        println!("spent {}", txo);
                    }

                    height += 1;
                    if height == max_height {
                        max_height = bitcoind.getblockcount().context("getting block count")?;
                    }
                }
                wallet.block_height = height;
            },
        }

        // Write out wallet
        save_out(&wallet, wallet_file, wallet_key, wallet_nonce)
    }
}


// ICBOC 3D
// Written in 2021 by
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

mod getnewaddress;
mod importdescriptor;
mod importicboc;
mod info;
mod init;
mod listunspent;
mod receive;
mod rescan;
mod signrawtransaction;

use anyhow::{self, Context};
use icboc::{Dongle, Wallet};
use miniscript::bitcoin::{
    bip32,
    hashes::{sha256, Hash},
};
use serde::de::DeserializeOwned;
use std::{borrow::Cow, env, fs, path::Path};

pub trait Command {
    type Options: DeserializeOwned;

    fn execute<D: Dongle, P: AsRef<Path>>(
        options: Self::Options,
        wallet_path: P,
        dongle: &mut D,
    ) -> anyhow::Result<()>;
}

macro_rules! register_commands {
    ($($cmd_name:ident, $type_name:ident, $help:expr;)*) => {
        $(use $cmd_name::$type_name;)*

        fn usage<T>(name: &str) -> anyhow::Result<T> {
            eprintln!("Usage: {} <wallet path> <command> [options]", name);
            eprintln!("");
            eprintln!("Commands:");
            $(eprintln!("    {:12} {}", stringify!($cmd_name), $help);)*
            Err(anyhow::Error::msg("bad invocation"))
        }

        /// Parse command-line arguments and execute them
        pub fn execute_from_args<D: Dongle>(
            dongle: &mut D,
        ) -> anyhow::Result<()> {
            let mut args = env::args_os();
            // Parse command-line parameters in a bizarrely verbose
            // way, so the borrowck doesn't complain about my pulling
            // things out of options and then letting them die
            let name = args.next();
            let name = match name.as_ref() {
                Some(name) => name.to_string_lossy(),
                None => usage("")?,
            };
            let path = match args.next() {
                Some(path) => path,
                None => usage("")?,
            };
            let cmd = args.next();
            let cmd = match cmd.as_ref() {
                Some(cmd) => cmd.to_string_lossy(),
                None => usage(&name)?,
            };
            let options = args.next();
            let options = options
                .as_ref()
                .map(|oss| oss.to_string_lossy())
                .unwrap_or(Cow::Borrowed("{}"));

            if args.next().is_some() {
                usage(&name)?
            }

            match cmd.as_ref() {
                $(stringify!($cmd_name) => {
                    let opts: <$type_name as Command>::Options = serde_json::from_str(&options)
                        .with_context(|| format!(
                            "deserializing options for {}",
                             stringify!($cmd_name),
                        ))?;
                    $type_name::execute(opts, path, dongle)?;
                }),*
                _ => usage(&name)?,
            }
            Ok(())
        }
    }
}

register_commands! {
    getnewaddress, GetNewAddress, "{ \"descriptor\": int, \"note\": string, \"index\": int (optional) }";
    init, Init, "{ \"force\": bool (optional) }";
    info, Info, "";
    listunspent, ListUnspent, "";
    importdescriptor, ImportDescriptor, "{ \"desc\": string, \"range_low\": int, \"range_high\": int }";
    importicboc, ImportIcboc, "{ \"file\": string }";
    receive, Receive, "{ \"tx\": hexstring }";
    rescan, Rescan, "{ \"start_from\": int, \"timeout_ms\": int }";
    signrawtransaction, SignRawTransaction, "{ \"tx\": hexstring, \"change_index\": int }";
}

/// Special message which has a very recognizeable pattern when
/// displayed on the Ledger "sign this message?" screen
pub const KEYSIG_MESSAGE: [u8; 32] = [
    0xb6, 0x02, 0xc8, 0x35, 0x8a, 0x73, 0xee, 0xb1, 0x3c, 0xfd, 0x3f, 0x3c, 0xfa, 0x16, 0xfe, 0x38,
    0xfa, 0x08, 0x37, 0x03, 0xa8, 0x87, 0x47, 0xaf, 0x7b, 0xd6, 0xe0, 0x4c, 0x54, 0x0e, 0xef, 0x1b,
];

/// Path on which to request the signature
///
/// For some reason the Ledger does not display to the user what this path is,
/// so it really doesn't matter, we just need to be consistent. But make half
/// an effort to not collide with paths other applications might use.
pub const KEYSIG_PATH: [bip32::ChildNumber; 2] = [
    bip32::ChildNumber::Hardened { index: 0xABCD },
    bip32::ChildNumber::Hardened { index: 0x1234 },
];

/// Utility function to query the dongle for its encryption key and a fresh uniformly random nonce
fn get_wallet_key_and_nonce<D: Dongle>(dongle: &mut D) -> anyhow::Result<([u8; 32], [u8; 12])> {
    println!("Unlock wallet by signing fixed message 0000990F48F5D865…0000000000000000 (Bitcoin block 332802).");
    let sig = dongle
        .sign_message(&KEYSIG_MESSAGE, &KEYSIG_PATH)
        .context("getting encryption key-signature from device")?;
    let wallet_key = sha256::Hash::hash(&sig.serialize_compact()).to_byte_array();
    let wallet_nonce = dongle
        .get_random_nonce()
        .context("getting random encryption IV from device")?;
    Ok((wallet_key, wallet_nonce))
}

/// Read a wallet from disk
fn open_wallet<D: Dongle, P: AsRef<Path>>(
    dongle: &mut D,
    wallet_path: P,
    wallet_key: [u8; 32],
) -> anyhow::Result<Wallet> {
    let wallet_name = wallet_path.as_ref().to_string_lossy().into_owned();
    let fh =
        fs::File::open(&wallet_path).with_context(|| format!("opening wallet {}", wallet_name))?;
    let wallet = Wallet::from_reader(dongle, fh, wallet_key)
        .with_context(|| format!("reading wallet {}", wallet_name))?;
    println!(
        "Opened wallet at {} with {} descriptors, {} txos, and {} generated addresses.",
        wallet_path.as_ref().to_string_lossy(),
        wallet.n_descriptors(),
        wallet.n_txos(),
        wallet.n_addresses(),
    );
    println!();
    Ok(wallet)
}

/// Save a wallet to dis
fn save_wallet<P: AsRef<Path>>(
    wallet: &Wallet,
    wallet_path: P,
    wallet_key: [u8; 32],
    wallet_nonce: [u8; 12],
) -> anyhow::Result<()> {
    let wallet_name = wallet_path.as_ref().to_string_lossy().into_owned();
    // Write out wallet
    let tmp_name = format!("{}.tmp", wallet_name);
    let fh = fs::File::create(&tmp_name)?;
    wallet
        .write(fh, wallet_key, wallet_nonce)
        .with_context(|| format!("writing to wallet {}", wallet_name))?;
    // Above line took `fh` by value, dropping it, so we can safely rename here
    fs::rename(&tmp_name, &wallet_path)
        .with_context(|| format!("renaming {} to {}", tmp_name, wallet_name))?;
    Ok(())
}

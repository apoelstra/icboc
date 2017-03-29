// IceBox
// Written in 2017 by
//   Andrew Poelstra <icebox@wpsoftware.net>
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

//! # Ice Box
//!
//! Ice Box is an application/library designed to use the Ledger Nano S
//! (and possibly other Ledger products) in a cold-wallet fashion. That
//! is, it does not interact with any other servers or networks, and is
//! meticulous about logging and timestamping all activity, warning about
//! unsafe usage (e.g. address reuse), and more TBD.
//!

extern crate bitcoin;
extern crate env_logger;
extern crate hex;
extern crate icebox;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::serialize::deserialize as bitcoin_deserialize;
use std::{env, io, fs, process};
use std::io::{Write, BufRead};
use std::str::FromStr;

use icebox::dongle::Dongle;
use icebox::error::Error;
use icebox::constants::apdu::ledger::sw;

/// Prompt the user for some string data
fn user_prompt(prompt: &str) -> String {
    print!("{}: ", prompt);
    io::stdout().flush().expect("flushing stdout");
    let stdin = io::stdin();
    let lock = stdin.lock();
    let line_res = lock.lines().next().expect("getting next line from stdin");
    line_res.expect("reading from stdin")
}

/// Prints the usage information and then halts the program
fn usage_and_die(name: &str) -> ! {
    println!("Usage: {} <wallet filename> <command>", name);
    println!("  {} <filename> init <account> <n_entries>", name);
    println!("  {} <filename> info [address index]", name);
    println!("  {} <filename> getaddress [address index]", name);
    println!("  {} <filename> receive <hex tx>", name);
    // TODO: extend wallet
    process::exit(1);
}

/// In case of error, prints a friendly version of an error message and then
/// halts. Like `expect` but does more work to unpack the error messages.
fn pretty_unwrap<T>(msg: &str, res: Result<T, Error>) -> T {
    match res {
        Ok(r) => r,
        Err(error) => {
            print!("{}: ", msg);
            match error {
                // Several APDU statuses can be fixed withuser intervention
                Error::ApduBadStatus(sw::BAD_LENGTH) => {
                    println!("We sent a bad length to the dongle. This is a bug.");
                }
                Error::ApduBadStatus(sw::BAD_DATA) => {
                    println!("We sent bad data to the dongle. This is a bug.");
                }
                Error::ApduBadStatus(sw::BAD_P1_OR_P2) => {
                    println!("We sent a bad P1 or P2 to the dongle. This is a bug.");
                }
                Error::ApduBadStatus(sw::INS_NOT_SUPPORTED) => {
                    println!("Device did not understand something. Are you running the BTC app?");
                }
                Error::ApduBadStatus(sw::exception::HALTED) => {
                    println!("The dongle app has halted and will refuse all further messages until it is restarted.");
                }
                Error::ApduBadStatus(sw::DONGLE_LOCKED) => {
                    println!("Please unlock the dongle.");
                }
                Error::ApduBadStatus(sw::SIGN_REFUSED) => {
                    println!("User refused the signature on the dongle.");
                }
                // Otherwise just print the error
                e => println!("{}", e)
            }
            process::exit(1);
        }
    }
}

fn main() {
    // Startup
    env_logger::init().unwrap();

    let args: Vec<String> = env::args().collect();
    match args.len() {
        0 => usage_and_die(""),
        1 | 2 => usage_and_die(&args[0]),
        _ => {}
    }

    // Contact device and run GET FIRMWARE to sanity check it
    let mut dongle = pretty_unwrap("Finding dongle", icebox::dongle::ledger::get_unique());
    println!("Successfully found dongle {:?}", dongle.product());
    let version = pretty_unwrap("Getting firmware version",
                                dongle.get_firmware_version());
    println!("Firmware version {}.{}.{}", version.major_version, version.minor_version, version.patch_version);

    // Decide what to do
    match &args[2][..] {
        // Create a new wallet
        "init" => {
            if args.len() < 5 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let account = u32::from_str(&args[3]).expect("Parsing account as number");
            let entries = usize::from_str(&args[4]).expect("Parsing n_entries as number");

            if fs::metadata(filename).is_ok() {
                println!("File {} already exists. Please move it out of the way to initialize a new wallet.", filename);
                process::exit(1);
            }

            let wallet = pretty_unwrap("Creating wallet",
                                       icebox::wallet::EncryptedWallet::new(&mut dongle, account, entries));
            pretty_unwrap("Saving wallet",
                          wallet.save(filename));
        }
        "info" => {
            if args.len() < 3 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let wallet = pretty_unwrap("Loading wallet",
                                       icebox::wallet::EncryptedWallet::load(filename));
            println!("Wallet: {} entries, account {}.", wallet.n_entries(), wallet.account());
            if args.len() > 3 {
                let index = usize::from_str(&args[3]).expect("Parsing index as number");
                let entry = pretty_unwrap("Decrypting entry",
                                          wallet.lookup(&mut dongle, index));
                println!("{}", entry);
            }
        }
        "getaddress" => {
            if args.len() < 3 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let mut wallet = pretty_unwrap("Loading wallet",
                                           icebox::wallet::EncryptedWallet::load(filename));
            let index;
            if args.len() > 3 {
                index = usize::from_str(&args[3]).expect("Parsing index as number");
            } else {
                println!("Scanning for next unused address. This may take a while.");
                index = pretty_unwrap("Finding next unused address",
                                      wallet.next_unused_index(&mut dongle));
            }

            let entry = pretty_unwrap("Decrypting entry",
                                      wallet.lookup(&mut dongle, index));
            if entry.state == icebox::wallet::EntryState::Unused {
                let name = user_prompt("Your name");
                let block_str = user_prompt("Recent blockhash (pick one say, 20 blocks ago, that is unlikely to be reorged out)");
                let block: Vec<u8> = hex::FromHex::from_hex(block_str.as_bytes()).expect("decoding blockhash hex");
                if block.len() != 32 {
                    println!("A blockhash must be 32 bytes (64 hex characters)");
                    process::exit(1);
                }
                let note = user_prompt("Note to tag address with");

                let entry = pretty_unwrap("Updating entry",
                                          wallet.update(&mut dongle, index, name, block, note));
                println!("{}", entry);
                pretty_unwrap("Saving wallet",
                              wallet.save(filename));
            } else {
                println!("This address has already been used.");
            }
        }
        "receive" => {
            if args.len() < 3 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let mut wallet = pretty_unwrap("Loading wallet",
                                           icebox::wallet::EncryptedWallet::load(filename));
            let tx_bytes: Vec<u8> = hex::FromHex::from_hex(args[3].as_bytes()).expect("decoding tx hex");
            let tx: Transaction = bitcoin_deserialize(&tx_bytes).expect("decoding transaction");

            pretty_unwrap("Processing transaction",
                          wallet.receive(&mut dongle, &tx));
            pretty_unwrap("Saving wallet",
                          wallet.save(filename));
        }
        _ => usage_and_die(&args[0])
    }
}


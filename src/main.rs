// ICBOC
// Written in 2017 by
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

//! # Ice Box
//!
//! Ice Box is an application/library designed to use the Ledger Nano S
//! (and possibly other Ledger products) in a cold-wallet fashion. That
//! is, it does not interact with any other servers or networks, and is
//! meticulous about logging and timestamping all activity, warning about
//! unsafe usage (e.g. address reuse), and more TBD.
//!

extern crate bitcoin;
extern crate hex;
extern crate icebox;
extern crate simplelog;

use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::network::constants::Network;
use bitcoin::network::serialize::serialize_hex as bitcoin_serialize_hex;
use bitcoin::network::serialize::deserialize as bitcoin_deserialize;
use bitcoin::util::address::Address;
use bitcoin::util::base58::FromBase58;
use std::{env, io, fs, process};
use std::io::{Write, BufRead};
use std::str::FromStr;

use icebox::dongle::Dongle;
use icebox::error::Error;
use icebox::constants::apdu::ledger::sw;
use icebox::spend::Spend;
use icebox::wallet::Update;

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
    println!("  {} <filename> init-testnet <account> <n_entries>", name);
    println!("  {} <filename> extend <new n_entries>", name);
    println!("  {} <filename> rerandomize", name);
    println!("");
    println!("  {} <filename> getaddress [address index]", name);
    println!("  {} <filename> getbalance", name);
    println!("  {} <filename> info [address|index]", name);
    println!("  {} <filename> receive <hex tx>", name);
    println!("");
    println!("  {} <filename> sendto <feerate> <destination> <amount> [<destination> <amount>...]", name);
    println!("");
    println!("All Bitcoin amounts should be specified in satoshi. No decimals.");
    println!("The feerate is given in satoshis per kilobyte.");
    println!("");
    println!("Note that several commands do a linear scan of the entire wallet,");
    println!("since dongle cooperation is required to decrypt each individual");
    println!("entry. These commands will be very slow.");
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
                Error::ApduBadStatus(sw::exception::EXCEPTION) => {
                    println!("The dongle app threw an exception.");
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
    simplelog::SimpleLogger::init(simplelog::LogLevelFilter::Info, simplelog::Config::default()).unwrap();

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
        "init" | "init-testnet" => {
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

            let network;
            if args[2] == "init-testnet" {
                network = Network::Testnet;
            } else {
                network = Network::Bitcoin;
            }

            let wallet = pretty_unwrap("Creating wallet",
                                       icebox::wallet::EncryptedWallet::new(&mut dongle, network, account, entries));
            pretty_unwrap("Saving wallet",
                          wallet.save(filename));
        }
        // Extend wallet capacity
        "extend" => {
            if args.len() < 4 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let n_entries = usize::from_str(&args[3]).expect("Parsing n_entries as number");

            let mut wallet = pretty_unwrap("Loading wallet",
                                           icebox::wallet::EncryptedWallet::load(&mut dongle, filename));
            if wallet.n_entries() >= n_entries {
                println!("Wallet already has {} entries, not decreasing.", wallet.n_entries());
            } else {
                pretty_unwrap("Extending wallet",
                              wallet.extend(&mut dongle, n_entries));
            }
            pretty_unwrap("Saving wallet",
                          wallet.save(filename));
        }
        // Get information about the wallet or a specific entry
        "info" => {
            if args.len() < 3 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let wallet = pretty_unwrap("Loading wallet",
                                       icebox::wallet::EncryptedWallet::load(&mut dongle, filename));
            println!("Wallet: {} entries, account {}.", wallet.n_entries(), wallet.account());
            if args.len() > 3 {
                // An index > length 10 is an address, we scan for it
                if args[3].len() > 10 {
                    let entry = pretty_unwrap("Searching for entry",
                                              wallet.search(&mut dongle, &args[3]));
                    println!("{}", entry);
                } else {
                // Otherwise take the index as an index
                    let index = usize::from_str(&args[3]).expect("Parsing index as number");
                    let entry = pretty_unwrap("Decrypting entry",
                                              wallet.lookup(&mut dongle, index));
                    println!("{}", entry);
                }
            }
        }
        // Update a new unused address slot
        "getaddress" => {
            if args.len() < 3 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let mut wallet = pretty_unwrap("Loading wallet",
                                           icebox::wallet::EncryptedWallet::load(&mut dongle, filename));
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
                                          wallet.update(&mut dongle, index, name, block, Update::Unused(note)));
                println!("{}", entry);
                println!("Rerandomizing wallet...");
                pretty_unwrap("Rerandomizing wallet",
                              wallet.rerandomize(&mut dongle));
                println!("Done. Saving.");
                pretty_unwrap("Saving wallet",
                              wallet.save(filename));
            } else {
                println!("This address has already been used.");
            }
        }
        // Sum all unspent entries to determine current wallet balance
        "getbalance" => {
            let filename = &args[1];
            let wallet = pretty_unwrap("Loading wallet",
                                       icebox::wallet::EncryptedWallet::load(&mut dongle, filename));
            let balance = pretty_unwrap("Checking balance",
                                        wallet.get_balance(&mut dongle));
            println!("Balance: {}", balance);
        }
        // Process a transaction that sends us coins
        "receive" => {
            if args.len() < 3 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let mut wallet = pretty_unwrap("Loading wallet",
                                           icebox::wallet::EncryptedWallet::load(&mut dongle, filename));
            let tx_bytes: Vec<u8> = hex::FromHex::from_hex(args[3].as_bytes()).expect("decoding tx hex");
            let tx: Transaction = bitcoin_deserialize(&tx_bytes).expect("decoding transaction");

            println!("Processing transaction...");
            pretty_unwrap("Processing transaction",
                          wallet.receive(&mut dongle, &tx));
            println!("Rerandomizing wallet...");
            pretty_unwrap("Rerandomizing wallet",
                          wallet.rerandomize(&mut dongle));
            println!("Done. Saving.");
            pretty_unwrap("Saving wallet",
                          wallet.save(filename));
        }
        // Re-encrypt the whole wallet to hide what has changed
        "rerandomize" => {
            let filename = &args[1];
            let mut wallet = pretty_unwrap("Loading wallet",
                                           icebox::wallet::EncryptedWallet::load(&mut dongle, filename));
            pretty_unwrap("Rerandomizing wallet",
                          wallet.rerandomize(&mut dongle));
            pretty_unwrap("Saving wallet",
                          wallet.save(filename));
        }
        // Spend money
        "sendto" =>{
            if args.len() < 6 || args.len() % 2 == 1 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let mut wallet = pretty_unwrap("Loading wallet",
                                           icebox::wallet::EncryptedWallet::load(&mut dongle, filename));

            // Assemble a "spend" object describing the transaction to be created
            let mut spend = Spend {
                input: vec![],
                change_path: [0; 5],
                change_amount: 0,
                change_vout: 0,
                output: vec![]
            };
            let fee_rate = u64::from_str(&args[3]).expect("Parsing fee rate as number");
            for i in 4..args.len() {
                if i % 2 == 1 {
                    continue;
                }
                let addr = Address::from_base58check(&args[i]).expect("Decoding address");
                let amount = u64::from_str(&args[i + 1]).expect("Parsing amount as number");
                spend.output.push(TxOut {
                    value: amount,
                    script_pubkey: addr.script_pubkey()
                });
            }
            println!("Scanning wallet to find funds and change...");
            pretty_unwrap("Finding funds and change",
                          wallet.get_inputs_and_change(&mut dongle, fee_rate, &mut spend));

            // Build transaction
            let mut tx = Transaction {
                version: 1,
                lock_time: 0,
                input: Vec::with_capacity(spend.input.len()),
                output: spend.output.clone(),
                witness: vec![]
            };

            // Obtain signatures for it
            for (n, input) in spend.input.iter().enumerate() {
                println!("Signing for input {} of {}...", n + 1, spend.input.len());
                let mut txin = input.txin.clone();
                txin.script_sig = pretty_unwrap("Signing for input",
                                                wallet.get_script_sig(&mut dongle, &spend, input.index, n > 0));
                tx.input.push(txin);
            }

            // Update all affected entries
            for input in &spend.input {
                println!("Marking entry {} as spent", input.index);
                pretty_unwrap("Marking spent",
                              wallet.mark_spent(&mut dongle, input.index));
            }
            // Update change
            if spend.change_amount > 0 {
                println!("Recording change output as used. We need a bit of information.");
                let name = user_prompt("Your name");
                let block_str = user_prompt("Recent blockhash (pick one say, 20 blocks ago, that is unlikely to be reorged out)");
                let block: Vec<u8> = hex::FromHex::from_hex(block_str.as_bytes()).expect("decoding blockhash hex");
                if block.len() != 32 {
                    println!("A blockhash must be 32 bytes (64 hex characters)");
                    process::exit(1);
                }
                let index = (spend.change_path[4] & 0x7fffffff) as usize;
                let entry = pretty_unwrap("Updating change entry",
                                          wallet.update(&mut dongle, index, name, block, Update::Change(&tx, spend.change_vout)));
                println!("{}", entry);
            }

            println!("Processing this as a receive to self-spends.");
            pretty_unwrap("Processing transaction",
                          wallet.receive(&mut dongle, &tx));

            println!("Please `sendrawtransaction` the following transaction {}", bitcoin_serialize_hex(&tx).unwrap());
            let yes = user_prompt("If this succeeded type YES to saveout the wallet.");
            if yes == "YES" {
                // Rerandomize
                pretty_unwrap("Rerandomizing wallet",
                              wallet.rerandomize(&mut dongle));

                pretty_unwrap("Saving wallet",
                              wallet.save(filename));
                println!("Done.");
            } else {
                println!("Cancelled.");
            }
        }
        // Don't recognize command
        _ => usage_and_die(&args[0])
    }
}


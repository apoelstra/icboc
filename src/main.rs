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

//! # Ice Box
//!
//! Ice Box is an application/library designed to use the Ledger Nano S
//! (and possibly other Ledger products) in a cold-wallet fashion. That
//! is, it does not interact with any other servers or networks, and is
//! meticulous about logging and timestamping all activity, warning about
//! unsafe usage (e.g. address reuse), and more TBD.
//!

use anyhow::Context;
use icboc::Dongle;
use miniscript::bitcoin::hashes::{Hash, sha256};
use miniscript::bitcoin::util::bip32;
use structopt::StructOpt;

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

mod commands;
mod rpc;

/// Entry point
fn main() -> anyhow::Result<()> {
    let opts = commands::Options::from_args();

    // Talk to the bitcoind
    let bitcoind = rpc::Bitcoind::connect(&opts)?;
    let n: usize = bitcoind.getblockcount()?;
    println!("{} blocks" , n);

    // Contact device and run GET FIRMWARE to sanity check it
    let hid_api = icboc::hid::Api::new()
        .context("getting HID API context")?;
    let mut dongle = icboc::ledger::NanoS::get(&hid_api)
        .context("finding dongle")?;
    let version = dongle.get_firmware_version()
        .context("getting firmware version")?;
    println!("Found dongle. Firmware version {}.{}.{}", version.major_version, version.minor_version, version.patch_version);

    // Get an encryption key for the wallet
    let sig = dongle.sign_message(&KEYSIG_MESSAGE, &KEYSIG_PATH)?;
    let wallet_key: [u8; 32] = sha256::Hash::hash(&sig.serialize_compact()).into_inner();

    // Do the user's bidding
    opts.command.execute(&opts.wallet_file, wallet_key, &mut dongle)?;

/*
    // Decide what to do
    match &args[2][..] {
        // Create a new wallet
        "init" => {
            if args.len() < 2 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];

            if fs::metadata(filename).is_ok() {
                println!("File {} already exists. Please move it out of the way to initialize a new wallet.", filename);
                return Err(anyhow::Error::msg("will not overwrite file with new wallet"));
            }

            let wallet = pretty_unwrap("Creating wallet",
                                       icboc::wallet::EncryptedWallet::new(&mut dongle, network, account, entries));
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
                                           icboc::wallet::EncryptedWallet::load(&mut dongle, filename));
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
                                       icboc::wallet::EncryptedWallet::load(&mut dongle, filename));
            println!("Wallet: {} entries, account {}.", wallet.n_entries(), wallet.account());
            if args.len() > 3 {
                // An index > length 10 is an address, we scan for it
                if args[3].len() > 10 {
                    let entry = pretty_unwrap("Searching for entry",
                                              wallet.search(&mut dongle, &args[3]));
                    println!("{}", entry);
                    if entry.state == EntryState::Valid {
                        pretty_unwrap("Confirming address",
                                      wallet.display(&mut dongle, entry.index));
                    }
                } else {
                // Otherwise take the index as an index
                    let index = usize::from_str(&args[3]).expect("Parsing index as number");
                    let entry = pretty_unwrap("Decrypting entry",
                                              wallet.lookup(&mut dongle, index));
                    println!("{}", entry);
                    if entry.state == EntryState::Valid {
                        pretty_unwrap("Confirming address",
                                      wallet.display(&mut dongle, entry.index));
                    }
                }
            }
        }
        // Sign a message with a specific entry
        "signmessage" => {
            if args.len() < 5 {
                usage_and_die(&args[0]);
            }

            let filename = &args[1];
            let wallet = pretty_unwrap("Loading wallet",
                                       icboc::wallet::EncryptedWallet::load(&mut dongle, filename));
            // An index > length 10 is an address, we scan for it
            let entry = if args[3].len() > 10 {
                pretty_unwrap("Searching for entry", wallet.search(&mut dongle, &args[3]))
            } else {
            // Otherwise take the index as an index
                let index = usize::from_str(&args[3]).expect("Parsing index as number");
                pretty_unwrap("Decrypting entry", wallet.lookup(&mut dongle, index))
            };
            let sig = pretty_unwrap("Getting signature", entry.sign_message(&mut dongle, &args[4]));
            let sig64 = pretty_unwrap("Encoding sig as base64", convert_compact_to_signmessage_rpc(&sig[..]));
            println!("{}", entry.address);
            println!("{}", sig64);
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
                let block = Sha256dHash::from_hex(&block_str).expect("decoding blockhash hex");
                let note = user_prompt("Note to tag address with");

                let entry = pretty_unwrap("Updating entry",
                                          wallet.update(&mut dongle, index, name, block, Update::Unused(note)));
                println!("{}", entry);
                pretty_unwrap("Confirming address",
                              wallet.display(&mut dongle, index));
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
                let addr = Address::from_str(&args[i]).expect("Decoding address");
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
                let block = Sha256dHash::from_hex(&block_str).expect("decoding blockhash hex");
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
        _ => usage_and_die(&args[0])?,
    }
    */
    Ok(())
}


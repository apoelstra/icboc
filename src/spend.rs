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

//! # Spending
//!
//! Utilities for creating spending transactions

use bitcoin::blockdata::transaction::{TxIn, TxOut};
use bitcoin::blockdata::script::Script;
use bitcoin::util::hash::Sha256dHash;

use wallet::Entry;

/// The data needed to convince the Ledger to sign an input
pub struct Input {
    /// The index of the corresponding entry in the wallet
    pub index: usize,
    /// The "trusted input" that encodes the transaction amount to the Ledger
    pub trusted_input: [u8; 56],
    /// The input amount
    pub amount: u64,
    /// The scriptpubkey of the txout this input spends
    pub script_pubkey: Script,
    /// The txin for this input, with blank script to be filled in
    pub txin: TxIn
}

impl Input {
    /// Extracts the relevant data from an Entry object
    pub fn from_entry(entry: &Entry) -> Input {
        let mut trusted_input = [0; 56];
        trusted_input.copy_from_slice(&entry.trusted_input[..]);

        Input {
            index: entry.index,
            trusted_input: trusted_input,
            amount: entry.amount,
            script_pubkey: entry.address.script_pubkey(),
            txin: TxIn {
                prev_hash: Sha256dHash::from(&entry.txid[..]),
                prev_index: entry.vout,
                script_sig: Script::new(),
                sequence: 0xfffffffe
            }
        }
    }
}

/// A structure holding all the data needed to build and sign a transaction
pub struct Spend {
    /// Array of transaction inputs; every one is owned by the wallet
    pub input: Vec<Input>,
    /// A BIP32 path to the address we plan to use for change
    pub change_path: [u32; 5],
    /// Which output has change in it
    pub change_vout: u32,
    /// The amount to allocate to change
    pub change_amount: u64,
    /// A list of outputs, including the change one
    pub output: Vec<TxOut>
}


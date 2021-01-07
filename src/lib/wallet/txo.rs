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

//! TXO
//!
//! Transaction outputs
//!

use miniscript::bitcoin;

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Txo {
    /// Index into the wallet-global descriptor array
    pub descriptor_idx: usize,
    /// If the descriptor has wildcards, index into it
    pub wildcard_idx: u32,
    /// Outpoint of the TXO
    pub outpoint: bitcoin::OutPoint,
    /// Value of the TXO, in satoshis
    pub value: u64,
    /// If the TXO is spent, the txid that spent it
    pub spent: Option<bitcoin::Txid>,
    /// Blockheight at which the UTXO was created
    pub height: u64,
    /// Blockheight at which the UTXO was spenta
    pub spent_height: Option<u64>,
}

impl Txo {
    /// Constructor
    pub fn new(
        descriptor_idx: usize,
        wildcard_idx: u32,
        outpoint: bitcoin::OutPoint,
        value: u64,
        height: u64,
    ) -> Txo {
        Txo {
            descriptor_idx: descriptor_idx,
            wildcard_idx: wildcard_idx,
            outpoint: outpoint,
            value: value,
            spent: None,
            height: height,
            spent_height: None,
        }
    }

    /// Accessor for the TXO's descriptor index
    pub fn descriptor_idx(&self) -> usize {
        self.descriptor_idx
    }

    /// Accessor for the TXO's index within a descriptor
    pub fn wildcard_idx(&self) -> u32 {
        self.wildcard_idx
    }

    /// Accessor for the outpoint of this TXO
    pub fn outpoint(&self) -> bitcoin::OutPoint {
        self.outpoint
    }

    /// Accessor for the height of this TXO
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Accessor for the value of this TXO
    pub fn value(&self) -> u64 {
        self.value
    }

    /// If this TXO has been spent, the txid that did it
    pub fn spending_txid(&self) -> Option<bitcoin::Txid> {
        self.spent
    }

    /// If this TXO has been spent, the height at which it happened
    pub fn spent_height(&self) -> Option<u64> {
        self.spent_height
    }

    /// Set the TXO as having been spent
    pub fn set_spent(&mut self, txid: bitcoin::Txid, height: u64) {
        self.spent = Some(txid);
        self.spent_height = Some(height);
    }
}

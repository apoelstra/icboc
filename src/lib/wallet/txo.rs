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

use std::io::{self, Read, Write};
use super::serialize::Serialize;

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Txo {
    /// Index into the wallet-global descriptor array
    descriptor_idx: u32,
    /// If the descriptor has wildcards, index into it
    wildcard_idx: u32,
    /// Outpoint of the TXO
    outpoint: bitcoin::OutPoint,
    /// Value of the TXO, in satoshis
    value: u64,
    /// If the TXO is spent, the txid that spent it
    spent: Option<bitcoin::Txid>,
    /// Blockheight at which the UTXO was created
    height: u64,
    /// Blockheight at which the UTXO was spenta
    spent_height: Option<u64>,
}

impl Txo {
    /// Constructor
    pub fn new(descriptor_idx: u32, wildcard_idx: u32, outpoint: bitcoin::OutPoint, value: u64, height: u64) -> Txo {
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
    pub fn descriptor_idx(&self) -> u32 {
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

impl Serialize for Txo {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.descriptor_idx.write_to(&mut w)?;
        self.wildcard_idx.write_to(&mut w)?;
        self.outpoint.write_to(&mut w)?;
        self.value.write_to(&mut w)?;
        self.spent.unwrap_or(Default::default()).write_to(&mut w)?;
        self.height.write_to(&mut w)?;
        self.spent_height.unwrap_or(Default::default()).write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(Txo {
            descriptor_idx: Serialize::read_from(&mut r)?,
            wildcard_idx: Serialize::read_from(&mut r)?,
            outpoint: Serialize::read_from(&mut r)?,
            value: Serialize::read_from(&mut r)?,
            spent: {
                let txid = Serialize::read_from(&mut r)?;
                if txid == bitcoin::Txid::default() {
                    None
                } else {
                    Some(txid)
                }
            },
            height: Serialize::read_from(&mut r)?,
            spent_height: {
                let height = Serialize::read_from(&mut r)?;
                if height == 0 {
                    None
                } else {
                    Some(height)
                }
            },
        })
    }
}


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
use std::{cmp, fmt, hash, sync::Arc};

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug)]
pub struct Txo {
    /// The address entry that this output was sent to
    pub address: Arc<super::Address>,
    /// Outpoint of the TXO
    pub outpoint: bitcoin::OutPoint,
    /// Value of the TXO, in satoshis
    pub value: bitcoin::Amount,
    /// Blockheight at which the UTXO was created. Can be changed
    /// when rescanning in case of reorg
    pub height: u64,
    /// Spending data
    pub spent_data: Option<SpentData>,
}

impl PartialEq for Txo {
    fn eq(&self, other: &Self) -> bool {
        self.outpoint == other.outpoint
    }
}
impl Eq for Txo {}

impl Ord for Txo {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Sort first by address since that's what the user cares about
        fn sort_key(obj: &Txo) -> impl Ord + '_ {
            (&obj.address, obj.outpoint)
        }
        sort_key(self).cmp(&sort_key(other))
    }
}

impl PartialOrd for Txo {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl hash::Hash for Txo {
    fn hash<H: hash::Hasher>(&self, h: &mut H) {
        self.outpoint.hash(h);
    }
}

impl fmt::Display for Txo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let address = self
            .address
            .instantiated_descriptor
            .address(bitcoin::Network::Bitcoin)
            .unwrap();
        write!(
            f,
            "{{ outpoint: \"{}\", value: \"{}\", height: {}, address: \"{}\", descriptor: \"{}\", index: {}",
            self.outpoint,
            self.value,
            self.height,
            address,
            self.address.descriptor.desc,
            self.address.index,
        )?;
        if let Some(ref data) = self.spent_data {
            write!(f, ", spent_by: \"{}\"", data.txid)?;
            write!(f, ", spent_height: {}", data.height)?;
        }
        if let Some(ref data) = *self.address.user_data.lock().unwrap() {
            write!(f, ", address_created_at: \"{}\"", data.time)?;
            write!(f, ", notes: \"{}\"", data.notes)?;
        }
        f.write_str("}")
    }
}

/// Data about where a TXO was spent
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentData {
    /// The txid that spent it
    pub txid: bitcoin::Txid,
    /// Blockheight at which that txid appeared
    pub height: u64,
}

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

//! Addresses
//!
//! Information associated to a wallet-generated address
//!

use miniscript::{self, bitcoin, DescriptorTrait};
use std::{
    cmp, fmt,
    sync::{Arc, Mutex},
};

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug)]
pub struct Address {
    /// Descriptor that generates this address
    pub descriptor: Arc<super::Descriptor>,
    /// If the descriptor has wildcards, index into it
    pub index: u32,
    /// The instantiated descriptor (with concrete public keys) corresponding
    /// to this address
    pub instantiated_descriptor: miniscript::Descriptor<bitcoin::PublicKey>,
    /// User data
    pub user_data: Mutex<Option<UserData>>,
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.descriptor == other.descriptor && self.index == other.index
    }
}
impl Eq for Address {}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        fn sort_key(obj: &Address) -> impl Ord {
            (obj.descriptor.wallet_idx, obj.index)
        }
        sort_key(self).cmp(&sort_key(other))
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let spk = self.instantiated_descriptor.script_pubkey();
        let address = bitcoin::Address::from_script(&spk, bitcoin::Network::Bitcoin).unwrap();
        write!(
            f,
            "{{ address: \"{}\", script_pubkey: \"{:x}\"",
            address, spk,
        )?;
        if let Some(ref data) = *self.user_data.lock().unwrap() {
            write!(
                f,
                " notes: \"{}\", address_created_at: \"{}\"",
                data.notes, data.time,
            )?;
        }
        f.write_str(" }")
    }
}

/// Data that a user has attached to an address upon "creating" it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserData {
    /// Time that the address was created, in format YYYY-MM-DD HH:MM:SS+ZZZZ
    pub time: String,
    /// User-provided notes about this address
    pub notes: String,
}

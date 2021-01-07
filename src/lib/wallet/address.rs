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

use crate::Error;
use miniscript::{bitcoin, DescriptorTrait};
use std::{cmp, fmt};

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// Index into the wallet-global descriptor array
    pub descriptor_idx: usize,
    /// If the descriptor has wildcards, index into it
    pub wildcard_idx: u32,
    /// Time that the address was created, in format YYYY-MM-DD HH:MM:SS+ZZZZ
    pub time: String,
    /// User-provided notes about this address
    pub notes: String,
}

impl Address {
    /// Constructor
    pub fn new(descriptor_idx: usize, wildcard_idx: u32, time: String, notes: String) -> Address {
        Address {
            descriptor_idx: descriptor_idx,
            wildcard_idx: wildcard_idx,
            time: time,
            notes: notes,
        }
    }

    /// Accessor for the time the address was created at
    pub fn create_time(&self) -> &str {
        &self.time
    }

    /// Accessor for the notes associated with the address
    pub fn notes(&self) -> &str {
        &self.notes
    }

    /// User-displayable information
    pub fn info<'w>(&self, wallet: &'w super::Wallet) -> Result<AddressInfo<'w>, Error> {
        let inst = wallet.instantiate_from_cache(self.descriptor_idx, self.wildcard_idx)?;

        Ok(AddressInfo {
            descriptor_idx: self.descriptor_idx,
            wildcard_idx: self.wildcard_idx,
            inst_descriptor: inst,
            wallet: wallet,
        })
    }
}

/// Address wrapper used for user display
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressInfo<'wallet> {
    /// Index into the wallet-global descriptor array
    descriptor_idx: usize,
    /// If the descriptor has wildcards, index into it
    wildcard_idx: u32,
    /// Instantiated descriptor with fixed public keys
    inst_descriptor: miniscript::Descriptor<bitcoin::PublicKey>,
    /// Pointer to the owning wallet
    wallet: &'wallet super::Wallet,
}

impl<'wallet> AddressInfo<'wallet> {
    /// Accessor for the creation time of the address, if known
    pub fn create_time(&self) -> Option<&str> {
       self.wallet
           .addresses
           .get(&self.inst_descriptor.script_pubkey())
           .map(|addr| &addr.time[..])
    }
}

impl<'wallet> fmt::Display for AddressInfo<'wallet> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let spk = self.inst_descriptor.script_pubkey();
        write!(
            f,
            "{{ address: \"{}\", script_pubkey: \"{:x}\"",
            self.inst_descriptor.address(bitcoin::Network::Bitcoin).unwrap(),
            spk,
        )?;
        if let Some(addr) = self.wallet.addresses.get(&spk) {
            write!(
                f,
                " notes: \"{}\", address_created_at: \"{}\"",
                addr.notes,
                addr.time,
            )?;
        }
        f.write_str(" }")
    }
}

impl<'wallet> Ord for AddressInfo<'wallet> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        fn sort_key<'a>(obj: &'a AddressInfo<'a>) -> impl Ord + 'a {
            (obj.create_time(), obj.descriptor_idx, obj.wildcard_idx, &obj.inst_descriptor)
        }
        sort_key(self).cmp(&sort_key(other))
    }
}

impl<'wallat> PartialOrd for AddressInfo<'wallat> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}


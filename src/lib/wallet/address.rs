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

use crate::{Dongle, Error};
use miniscript::{bitcoin, DescriptorTrait, TranslatePk2};
use std::{
    cell::RefCell,
    cmp, fmt,
    io::{self, Read, Write},
};
use super::serialize::Serialize;

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// Index into the wallet-global descriptor array
    descriptor_idx: u32,
    /// If the descriptor has wildcards, index into it
    wildcard_idx: u32,
    /// Time that the address was created, in format YYYY-MM-DD HH:MM:SS+ZZZZ
    time: String,
    /// User-provided notes about this address
    notes: String,
}

impl Address {
    /// Constructor
    pub fn new(descriptor_idx: u32, wildcard_idx: u32, time: String, notes: String) -> Address {
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
    pub fn info<'wallet, D: Dongle>(
        &self,
        wallet: &'wallet super::Wallet,
        dongle: &mut D,
    ) -> Result<AddressInfo<'wallet>, Error> {
        let inst = wallet
            .descriptors[self.descriptor_idx as usize]
            .desc
            .derive(self.wildcard_idx);
        let dongle = RefCell::new(&mut *dongle);
        let inst = inst.translate_pk2(
            |key| dongle.borrow_mut().get_wallet_public_key(key, &mut *wallet.key_cache.borrow_mut())
        )?;

        Ok(AddressInfo {
            descriptor_idx: self.descriptor_idx,
            wildcard_idx: self.wildcard_idx,
            inst_descriptor: inst,
            wallet: wallet,
        })
    }
}

impl Serialize for Address {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.descriptor_idx.write_to(&mut w)?;
        self.wildcard_idx.write_to(&mut w)?;
        self.time.write_to(&mut w)?;
        self.notes.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(Address {
            descriptor_idx: Serialize::read_from(&mut r)?,
            wildcard_idx: Serialize::read_from(&mut r)?,
            time: Serialize::read_from(&mut r)?,
            notes: Serialize::read_from(r)?,
        })
    }
}

/// Address wrapper used for user display
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressInfo<'wallet> {
    /// Index into the wallet-global descriptor array
    descriptor_idx: u32,
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
            "{{ address: \"{}\", script_pubkey: \"{}\"",
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


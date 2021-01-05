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

use std::io::{self, Read, Write};
use super::serialize::Serialize;

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// Index into the wallet-global descriptor array
    descriptor_idx: u32,
    /// If the descriptor has wildcards, index into it
    wildcard_idx: u32,
    /// User-provided notes about this address
    notes: String,
}

impl Address {
    /// Constructor
    pub fn new(descriptor_idx: u32, wildcard_idx: u32, notes: String) -> Address {
        Address {
            descriptor_idx: descriptor_idx,
            wildcard_idx: wildcard_idx,
            notes: notes,
        }
    }

    /// Accessor for the notes associated with the address
    pub fn notes(&self) -> &str {
        &self.notes
    }
}

impl Serialize for Address {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.descriptor_idx.write_to(&mut w)?;
        self.wildcard_idx.write_to(&mut w)?;
        self.notes.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(Address {
            descriptor_idx: Serialize::read_from(&mut r)?,
            wildcard_idx: Serialize::read_from(&mut r)?,
            notes: Serialize::read_from(r)?,
        })
    }
}


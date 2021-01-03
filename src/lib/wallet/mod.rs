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

//! Wallet
//!
//! Support for the on-disk wallet format
//!

mod chacha20;
mod crypt;
mod serialize;

use miniscript::{self, TranslatePk2};
use miniscript::bitcoin::{self, util::bip32};

use self::serialize::Serialize;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, Write};
use std::str::FromStr;

use crate::{Dongle, Error};

const MAX_DESCRIPTOR_LEN: u32 = 64 * 1024;

/// Wallet structure
#[derive(Default)]
pub struct Wallet {
    /// Last blockheight the wallet considers confirmed and will not rescan
    pub block_height: u64,
    /// List of descriptors tracked by the wallet
    pub descriptors: Vec<Descriptor>,
    /// Set of TXOs owned by the wallet
    pub txos: HashSet<Txo>,
    /// Cache of keys we've gotten from the dongel
    pub key_cache: HashMap<bip32::DerivationPath, bitcoin::PublicKey>,
}

impl Wallet {
    /// Construct a new empty wallet
    pub fn new() -> Self { Self::default() }

    /// Adds a new descriptor to the wallet. Returns the number of new keys
    /// (i.e. it not covered by descriptors already in wallet) added.
    pub fn add_descriptor<D: Dongle>(
        &mut self,
        desc: miniscript::Descriptor<miniscript::DescriptorPublicKey>,
        low: u32,
        high: u32,
        dongle: &mut D,
    ) -> Result<usize, Error> {
        let mut existing_indices = HashSet::new();
        for d in &self.descriptors {
            if d.desc == desc {
                for i in d.low..d.high {
                    existing_indices.insert(i);
                }
            }
        }

        let mut added_new = 0;
        for i in low..high {
            if !existing_indices.contains(&i) {
                added_new += 1;
                // Cache the new key
                let dongle = RefCell::new(&mut *dongle);
                let key_cache = RefCell::new(&mut self.key_cache);

                let copy = desc.derive(i);
                copy.translate_pk2(
                    |key| dongle.borrow_mut().get_wallet_public_key(key, Some(*key_cache.borrow_mut()))
                )?;
            }
        }

        if added_new > 0 {
            self.descriptors.push(Descriptor {
                desc: desc,
                low: low,
                high: high,
                next_idx: 0,
            });
        }

        Ok(added_new)
    }

    /// Read a wallet in encrypted form
    pub fn from_reader<R: Read + Seek>(r: R, key: [u8; 32]) -> io::Result<Self> {
        let reader = self::crypt::CryptReader::new(key, r)?;
        Self::read_from(reader)
    }

    /// Write out the wallet in encrypted form
    pub fn write<W: Write>(&self, w: W, key: [u8; 32]) -> io::Result<()> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)?;

        let mut writer = self::crypt::CryptWriter::new(key, nonce, w);
        writer.init()?;
        self.write_to(&mut writer)?;
        writer.finalize()?;
        Ok(())
    }
}

impl Serialize for Wallet {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.block_height.write_to(&mut w)?;
        self.descriptors.write_to(&mut w)?;
        self.txos.write_to(&mut w)?;
        self.key_cache.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(Wallet {
            block_height: Serialize::read_from(&mut r)?,
            descriptors: Serialize::read_from(&mut r)?,
            txos: Serialize::read_from(&mut r)?,
            key_cache: Serialize::read_from(r)?,
        })
    }
}

/// A descriptor held in the wallet
pub struct Descriptor {
    /// The underlying descriptor
    pub desc: miniscript::Descriptor<miniscript::DescriptorPublicKey>,
    /// The first (inclusive) index to instantiate
    pub low: u32,
    /// The last (exclusize) index to instantiate
    pub high: u32,
    /// The next unused index at which to instantiate this descriptor
    pub next_idx: u32,
}

impl Serialize for Descriptor {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.desc.write_to(&mut w)?;
        self.low.write_to(&mut w)?;
        self.high.write_to(&mut w)?;
        self.next_idx.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(Descriptor {
            desc: Serialize::read_from(&mut r)?,
            low: Serialize::read_from(&mut r)?,
            high: Serialize::read_from(&mut r)?,
            next_idx: Serialize::read_from(r)?,
        })
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Txo {
    /// Index into the wallet-global descriptor array
    descriptor_idx: u32,
    /// If the descriptor has wildcards, index into it
    wildcard_idx: u32,
    /// Outpoint of the TXO
    outpoint: miniscript::bitcoin::OutPoint,
    /// Value of the TXO, in satoshis
    value: u64,
    /// If the TXO is spent, the txid that spent it
    spent: Option<miniscript::bitcoin::Txid>,
}

impl Serialize for Txo {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.descriptor_idx.write_to(&mut w)?;
        self.wildcard_idx.write_to(&mut w)?;
        self.outpoint.write_to(&mut w)?;
        self.value.write_to(&mut w)?;
        self.spent.unwrap_or(Default::default()).write_to(&mut w)?;
        Ok(())
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(Txo {
            descriptor_idx: Serialize::read_from(&mut r)?,
            wildcard_idx: Serialize::read_from(&mut r)?,
            outpoint: Serialize::read_from(&mut r)?,
            value: Serialize::read_from(&mut r)?,
            spent: {
                let txid = Serialize::read_from(&mut r)?;
                if txid == miniscript::bitcoin::Txid::default() {
                    None
                } else {
                    Some(txid)
                }
            },
        })
    }
}

impl Serialize for bitcoin::PublicKey {
    fn write_to<W: Write>(&self, w: W) -> io::Result<()> {
        // FIXME this may panic, pending new rust-bitcoin release for fix..
        Ok(self.write_into(w))
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        // FIXME copied from https://github.com/rust-bitcoin/rust-bitcoin/pull/542 inline this when that is merged
        let mut bytes = [0; 65];
        let byte_sl;
        r.read_exact(&mut bytes[0..1])?;
        if bytes[0] < 4 {
            r.read_exact(&mut bytes[1..33])?;
            byte_sl = &bytes[0..33];
        } else {
            r.read_exact(&mut bytes[1..65])?;
            byte_sl = &bytes[0..65];
        }
        Self::from_slice(byte_sl).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl Serialize for bip32::DerivationPath {
    fn write_to<W: Write>(&self, w: W) -> io::Result<()> {
        // We could avoid this allocation if we were less lazy..
        let sl: &[bip32::ChildNumber] = &self.as_ref();
        let vec: Vec<u32> = sl.iter().cloned().map(From::from).collect();
        vec.write_to(w)
    }

    fn read_from<R: Read>(r: R) -> io::Result<Self> {
        let path: Vec<u32> = Serialize::read_from(r)?;
        let vec: Vec<bip32::ChildNumber> = path.into_iter().map(From::from).collect();
        Ok(bip32::DerivationPath::from(vec))
    }
}

impl Serialize for miniscript::Descriptor<miniscript::DescriptorPublicKey> {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        let string = self.to_string();
        (string.len() as u32).write_to(&mut w)?;
        w.write_all(string.as_bytes())
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let len: u32 = Serialize::read_from(&mut r)?;
        if len > MAX_DESCRIPTOR_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "reading descriptor of length {} exceeded max {}",
                    len,
                    MAX_DESCRIPTOR_LEN,
                ),
            ));
        }
        let mut data = vec![0; len as usize];
        r.read_exact(&mut data)?;
        let s = String::from_utf8(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        miniscript::Descriptor::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}


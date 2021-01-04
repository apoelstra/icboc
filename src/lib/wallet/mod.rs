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

//! Wallet
//!
//! Support for the on-disk wallet format
//!

mod chacha20;
mod crypt;
mod serialize;

use miniscript::{self, DescriptorTrait, TranslatePk2};
use miniscript::bitcoin::{self, util::bip32};

use self::serialize::Serialize;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::{
    cmp,
    fmt,
    io::{self, Read, Seek, Write},
    str::FromStr,
};

use crate::{Dongle, Error};

const MAX_DESCRIPTOR_LEN: u32 = 64 * 1024;

/// Opaque cache of all scriptpubkeys the wallet is tracking
pub struct ScriptPubkeyCache {
    /// Scriptpubkeys we control
    spks: HashMap<bitcoin::Script, (u32, u32)>,
}

/// Wallet structure
#[derive(Default)]
pub struct Wallet {
    /// Last blockheight the wallet considers confirmed and will not rescan
    pub block_height: u64,
    /// List of descriptors tracked by the wallet
    pub descriptors: Vec<Descriptor>,
    /// Set of TXOs owned by the wallet
    pub txos: HashMap<bitcoin::OutPoint, Txo>,
    /// Cache of keys we've gotten from the dongel
    pub key_cache: HashMap<bip32::DerivationPath, bitcoin::PublicKey>,
}

impl Wallet {
    /// Construct a new empty wallet
    pub fn new() -> Self { Self::default() }

    /// Helper fuction that caches keys from the Ledger and computes the
    /// scriptpubkey corresponding to an instantiated descriptor
    fn cache_key<D: Dongle>(
        key_cache: &mut HashMap<bip32::DerivationPath, bitcoin::PublicKey>,
        desc: &miniscript::Descriptor<miniscript::DescriptorPublicKey>,
        index: u32,
        dongle: &mut D,
    ) -> Result<bitcoin::Script, Error> {
        let dongle = RefCell::new(&mut *dongle);
        let key_cache = RefCell::new(key_cache);

        let copy = desc.derive(index);
        let inst = copy.translate_pk2(
            |key| dongle.borrow_mut().get_wallet_public_key(key, &mut *key_cache.borrow_mut())
        )?;
        Ok(inst.script_pubkey())
    }

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
                Wallet::cache_key(&mut self.key_cache, &desc, i, &mut *dongle)?;
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

    /// Iterator over all descriptors in the wallet, and their index
    pub fn descriptors<'a>(&'a self) -> impl Iterator<Item=(usize, &'a Descriptor)> {
        self.descriptors.iter().enumerate()
    }

    /// Gets the set of TXOs associated with a particular descriptor
    pub fn txos_for<'a>(&'a self, descriptor_idx: usize) -> HashSet<&'a Txo> {
        self.txos.values().filter(|txo| txo.descriptor_idx as usize == descriptor_idx).collect()
    }

    /// Returns an opaque object the wallet can use to recognize its own scriptpubkeys
    pub fn script_pubkey_cache<D: Dongle>(
        &mut self,
        dongle: &mut D,
    ) -> Result<ScriptPubkeyCache, Error> {
        let mut map = HashMap::new();
        for (didx, desc) in self.descriptors.iter().enumerate() {
            for widx in desc.low..desc.high {
                let spk = Wallet::cache_key(&mut self.key_cache, &desc.desc, widx, &mut *dongle)?;
                map.insert(spk, (didx as u32, widx as u32));
            }
        }

        Ok(ScriptPubkeyCache {
            spks: map,
        })
    }

    /// Scans a block for wallet-relevant information. Returns two sets, one of
    /// received coins and one of spent coins
    pub fn scan_block(
        &mut self,
        block: &bitcoin::Block,
        height: u64,
        cache: &mut ScriptPubkeyCache,
    ) -> Result<(HashSet<Txo>, HashSet<Txo>), Error> {
        let mut received = HashSet::new();
        let mut spent = HashSet::new();

        for tx in &block.txdata {
            for (vout, output) in tx.output.iter().enumerate() {
                if let Some((didx, widx)) = cache.spks.get(&output.script_pubkey) {
                    let outpoint = bitcoin::OutPoint::new(tx.txid(), vout as u32);
                    let new_txo = Txo {
                        descriptor_idx: *didx,
                        wildcard_idx: *widx,
                        outpoint: outpoint,
                        value: output.value,
                        spent: None,
                        height: height,
                        spent_height: None,
                    };
                    received.insert(new_txo);
                    self.txos.insert(outpoint, new_txo);
                }
            }

            for input in &tx.input {
                if let Some(txo) = self.txos.get_mut(&input.previous_output) {
                    txo.spent = Some(tx.txid());
                    txo.spent_height = Some(height);
                    spent.insert(*txo);
                }
            }
        }

        Ok((received, spent))
    }

    /// Read a wallet in encrypted form
    pub fn from_reader<R: Read + Seek>(r: R, key: [u8; 32]) -> io::Result<Self> {
        let reader = self::crypt::CryptReader::new(key, r)?;
        Self::read_from(reader)
    }

    /// Write out the wallet in encrypted form
    pub fn write<W: Write>(&self, w: W, key: [u8; 32], nonce: [u8; 12]) -> io::Result<()> {
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

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
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

impl Ord for Txo {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        fn sort_key(obj: &Txo) -> impl Ord {
            (obj.height, obj.descriptor_idx, obj.wildcard_idx, obj.outpoint)
        }
        sort_key(self).cmp(&sort_key(other))
    }
}

impl PartialOrd for Txo {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Txo {
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
}

impl fmt::Display for Txo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ outpoint: \"{}\", value: \"{}\", height: {}, descriptor: {}, index: {}",
            self.outpoint,
            bitcoin::Amount::from_sat(self.value),
            self.height,
            self.descriptor_idx,
            self.wildcard_idx,
        )?;
        if let Some(txid) = self.spent {
            write!(f, ", spent_by: \"{}\"", txid)?;
        }
        if let Some(height) = self.spent_height {
            write!(f, ", spent_height: {}", height)?;
        }
        f.write_str(" }")
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
        self.spent_height.unwrap_or(Default::default()).write_to(&mut w)?;
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


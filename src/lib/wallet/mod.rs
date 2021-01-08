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

mod address;
mod encode;
mod txo;

use miniscript::bitcoin;
use miniscript::{self, DescriptorTrait, ForEachKey, TranslatePk2};

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::{
    cmp,
    collections::hash_map::Entry,
    io::{Read, Seek, Write},
    sync::{Arc, Mutex},
};

pub use self::address::{Address, UserData};
use self::encode::{EncAddress, EncDescriptor, EncTxo, EncWallet};
pub use self::txo::{SpentData, Txo};
use crate::{Dongle, Error, KeyCache};

/// Wallet structure
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Wallet {
    /// Last blockheight the wallet considers confirmed and will not rescan
    block_height: u64,
    /// List of descriptors tracked by the wallet
    descriptors: Vec<Arc<Descriptor>>,
    /// Index from scriptpubkeys to addresses
    spk_address: HashMap<bitcoin::Script, Arc<Address>>,
    /// Index from descriptor/index pairs to addresses
    descriptor_address: HashMap<(usize, u32), Arc<Address>>,
    /// Set of TXOs owned by the wallet
    txos: HashMap<bitcoin::OutPoint, Txo>,
    /// Cache of keys we've gotten from the dongel
    key_cache: KeyCache,
}

impl Wallet {
    /// Construct a new empty wallet
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a wallet in encrypted form
    pub fn from_reader<D: Dongle, R: Read + Seek>(
        dongle: &mut D,
        r: R,
        key: [u8; 32],
    ) -> Result<Self, Error> {
        // Parse the wallet from disk
        let enc_wallet = EncWallet::from_reader(r, key)?;
        // Copy basic data into place
        let mut ret = Wallet {
            block_height: enc_wallet.block_height,
            descriptors: Vec::with_capacity(enc_wallet.descriptors.len()),
            spk_address: HashMap::with_capacity(enc_wallet.addresses.len()),
            descriptor_address: HashMap::with_capacity(enc_wallet.addresses.len()),
            txos: HashMap::with_capacity(enc_wallet.txos.len()),
            key_cache: enc_wallet.key_cache,
        };
        // Copy descriptors into arcs
        for enc_desc in enc_wallet.descriptors {
            let idx = ret.descriptors.len();
            // Determine the next unused index
            let mut next_idx = 0;
            for enc_addr in &enc_wallet.addresses {
                if enc_addr.descriptor_idx as usize == idx {
                    next_idx = cmp::max(next_idx, enc_addr.wildcard_idx + 1);
                }
            }
            // Create a new descriptor entry
            let desc_arc = Arc::new(Descriptor {
                desc: enc_desc.desc,
                wallet_idx: idx,
                low: enc_desc.low,
                high: enc_desc.high,
                next_idx: Mutex::new(next_idx),
            });
            // Generate address entries for every descriptor in the given range.
            for wildcard_idx in enc_desc.low..enc_desc.high {
                // Re-cache all keys, which should be a no-op, but may help to
                // recover in case the dongle was malfunctioning the last time the
                // cache was created).
                ret.cache_keys(&mut *dongle, &desc_arc.desc, wildcard_idx);
                // Create the address entry
                let inst = ret.instantiate_from_cache(&desc_arc.desc, wildcard_idx)?;
                let new_addr = Arc::new(Address {
                    descriptor: desc_arc.clone(),
                    index: wildcard_idx,
                    instantiated_descriptor: inst,
                    user_data: Mutex::new(None),
                });
                ret.descriptor_address
                    .insert((idx, wildcard_idx), new_addr.clone());
                ret.spk_address
                    .insert(new_addr.instantiated_descriptor.script_pubkey(), new_addr);
            }
            // Add the descriptor to the wallet
            ret.descriptors.push(desc_arc);
        }
        // Build address map
        for enc_addr in enc_wallet.addresses {
            let mut user_data = ret.descriptor_address
                [&(enc_addr.descriptor_idx as usize, enc_addr.wildcard_idx)]
                .user_data
                .lock()
                .unwrap();
            *user_data = Some(UserData {
                time: enc_addr.time,
                notes: enc_addr.notes,
            });
        }
        // Build txo map
        for enc_txo in enc_wallet.txos {
            ret.txos.insert(
                enc_txo.outpoint,
                Txo {
                    address: ret.descriptor_address
                        [&(enc_txo.descriptor_idx as usize, enc_txo.wildcard_idx)]
                        .clone(),
                    outpoint: enc_txo.outpoint,
                    value: enc_txo.value,
                    height: enc_txo.height,
                    spent_data: if let (Some(txid), Some(height)) =
                        (enc_txo.spent, enc_txo.spent_height)
                    {
                        Some(SpentData { txid, height })
                    } else {
                        None
                    },
                },
            );
        }
        Ok(ret)
    }

    /// Write out the wallet in encrypted form
    pub fn write<W: Write>(&self, w: W, key: [u8; 32], nonce: [u8; 12]) -> Result<(), Error> {
        EncWallet {
            block_height: self.block_height,
            descriptors: self
                .descriptors
                .iter()
                .map(|desc| EncDescriptor {
                    desc: desc.desc.clone(),
                    low: desc.low,
                    high: desc.high,
                })
                .collect(),
            addresses: self
                .spk_address
                .values()
                .filter_map(|addr| {
                    addr.user_data
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map(|user_data| EncAddress {
                            descriptor_idx: addr.descriptor.wallet_idx as u32,
                            wildcard_idx: addr.index,
                            time: user_data.time.clone(),
                            notes: user_data.notes.clone(),
                        })
                })
                .collect(),
            txos: self
                .txos
                .values()
                .map(|txo| EncTxo {
                    descriptor_idx: txo.address.descriptor.wallet_idx as u32,
                    wildcard_idx: txo.address.index,
                    outpoint: txo.outpoint,
                    value: txo.value,
                    height: txo.height,
                    spent: txo.spent_data.as_ref().map(|data| data.txid),
                    spent_height: txo.spent_data.as_ref().map(|data| data.height),
                })
                .collect(),
            key_cache: self.key_cache.clone(),
        }
        .write(w, key, nonce)
        .map_err(Error::from)
    }

    /// Accessor for the last block height that we synced this wallet to
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Setter for the last block height
    pub fn set_block_height(&mut self, new_height: u64) {
        self.block_height = new_height;
    }

    /// Accessor for the number of descriptors stored in the wallet
    pub fn n_descriptors(&self) -> usize {
        self.descriptors.len()
    }

    /// Accessor for the number of addresses stored by the wallet
    pub fn n_addresses(&self) -> usize {
        debug_assert_eq!(self.spk_address.len(), self.descriptor_address.len());
        self.spk_address.len()
    }

    /// Accessor for the number of txos tracked by the wallet
    pub fn n_txos(&self) -> usize {
        self.txos.len()
    }

    /// Iterator over all addresses generated in the wallet
    pub fn addresses<'a>(&'a self) -> impl Iterator<Item = Arc<Address>> + 'a {
        self.spk_address.values().cloned()
    }

    /// Iterator over all TXOs tracked by the wallet
    pub fn all_txos<'a>(&'a self) -> impl Iterator<Item = &'a Txo> {
        self.txos.values()
    }

    /// Look up an address by its scriptpubkey
    pub fn address_from_spk(&self, spk: &bitcoin::Script) -> Option<&Address> {
        self.spk_address.get(spk).map(|arc| &**arc)
    }

    /// Helper fuction that (tries to) cache a key from the Ledger
    fn cache_key<D: Dongle>(
        dongle: &mut D,
        key_cache: &mut KeyCache,
        key: &miniscript::DescriptorPublicKey,
    ) -> Result<bitcoin::PublicKey, Error> {
        dongle.get_wallet_public_key(key, key_cache)
    }

    /// Helper fuction that (tries to) cache all the keys in a descriptor from the Ledger
    fn cache_keys<D: Dongle>(
        &mut self,
        dongle: &mut D,
        desc: &miniscript::Descriptor<miniscript::DescriptorPublicKey>,
        index: u32,
    ) {
        let dongle = RefCell::new(dongle);
        let key_cache = RefCell::new(&mut self.key_cache);
        desc.for_each_key(|key| {
            Wallet::cache_key(
                *dongle.borrow_mut(),
                *key_cache.borrow_mut(),
                &key.as_key().clone().derive(index),
            )
            .is_ok()
        });
    }

    fn instantiate_from_cache(
        &self,
        descriptor: &miniscript::Descriptor<miniscript::DescriptorPublicKey>,
        index: u32,
    ) -> Result<miniscript::Descriptor<bitcoin::PublicKey>, Error> {
        let inst = descriptor.derive(index).translate_pk2(|key| {
            match self.key_cache.lookup_descriptor_pubkey(key) {
                Some(pk) => Ok(pk),
                None => Err(Error::KeyNotFound(key.clone())),
            }
        })?;
        Ok(inst)
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
                if d.low == low && d.high == high {
                    return Err(Error::DuplicateDescriptor);
                }
                for i in d.low..d.high {
                    existing_indices.insert(i);
                }
            }
        }

        let mut added_new = 0;
        for i in low..high {
            if !existing_indices.contains(&i) {
                added_new += 1;
                self.cache_keys(&mut *dongle, &desc, i);
            }
        }

        let idx = self.descriptors.len();
        self.descriptors.push(Arc::new(Descriptor {
            desc: desc,
            wallet_idx: idx,
            low: low,
            high: high,
            next_idx: Mutex::new(0),
        }));

        Ok(added_new)
    }

    /// Adds a new address to the wallet.
    pub fn add_address<'wallet>(
        &mut self,
        descriptor_idx: usize,
        wildcard_idx: Option<u32>,
        time: String,
        notes: String,
    ) -> Result<Arc<Address>, Error> {
        let mut next_idx = self.descriptors[descriptor_idx].next_idx.lock().unwrap();
        let wildcard_idx = wildcard_idx.unwrap_or(*next_idx);
        *next_idx = cmp::max(*next_idx, wildcard_idx) + 1;

        let desc_arc = self.descriptors[descriptor_idx].clone();
        let inst = self.instantiate_from_cache(&desc_arc.desc, wildcard_idx)?;
        let spk = inst.script_pubkey();

        let new_addr = Arc::new(Address {
            descriptor: desc_arc,
            index: wildcard_idx,
            instantiated_descriptor: inst,
            user_data: Mutex::new(Some(UserData {
                time: time,
                notes: notes,
            })),
        });
        self.spk_address.insert(spk, new_addr.clone());
        self.descriptor_address
            .insert((descriptor_idx, wildcard_idx), new_addr.clone());

        Ok(new_addr)
    }

    /// Iterator over all descriptors in the wallet, and their index
    pub fn descriptors<'a>(&'a self) -> impl Iterator<Item = &'a Descriptor> {
        self.descriptors.iter().map(|arc| &**arc)
    }

    /// Gets the set of TXOs associated with a particular descriptor
    pub fn txos_for<'a>(&'a self, descriptor_idx: usize) -> HashSet<&'a Txo> {
        self.txos
            .values()
            .filter(|txo| txo.address.descriptor.wallet_idx == descriptor_idx)
            .collect()
    }

    /// Looks up a specific TXO
    pub fn txo<'a>(&'a self, outpoint: bitcoin::OutPoint) -> Result<&'a Txo, Error> {
        match self.txos.get(&outpoint) {
            Some(txo) => Ok(txo),
            None => return Err(Error::TxoNotFound(outpoint)),
        }
    }

    /// Scans a block for wallet-relevant information. Returns two sets, one of
    /// received coins and one of spent coins
    pub fn scan_block(
        &mut self,
        block: &bitcoin::Block,
        height: u64,
    ) -> Result<(HashSet<bitcoin::OutPoint>, HashSet<bitcoin::OutPoint>), Error> {
        let mut received = HashSet::new();
        let mut spent = HashSet::new();

        for tx in &block.txdata {
            for (vout, output) in tx.output.iter().enumerate() {
                if let Some(addr) = self.spk_address.get(&output.script_pubkey) {
                    let outpoint = bitcoin::OutPoint::new(tx.txid(), vout as u32);
                    match self.txos.entry(outpoint) {
                        Entry::Vacant(v) => {
                            v.insert(Txo {
                                address: addr.clone(),
                                outpoint: outpoint,
                                value: output.value,
                                height: height,
                                spent_data: None,
                            });
                        }
                        Entry::Occupied(mut o) => o.get_mut().height = height,
                    }
                    received.insert(outpoint);
                }
            }

            for input in &tx.input {
                if let Some(txo) = self.txos.get_mut(&input.previous_output) {
                    txo.spent_data = Some(SpentData {
                        txid: tx.txid(),
                        height: height,
                    });
                    spent.insert(input.previous_output);
                }
            }
        }

        Ok((received, spent))
    }
}

/// A descriptor held in the wallet
#[derive(Debug)]
pub struct Descriptor {
    /// The underlying descriptor
    pub desc: miniscript::Descriptor<miniscript::DescriptorPublicKey>,
    /// Index of the descriptor in the wallet database
    pub wallet_idx: usize,
    /// The first (inclusive) index to instantiate
    pub low: u32,
    /// The last (exclusize) index to instantiate
    pub high: u32,
    /// The next unused index at which to instantiate this descriptor
    pub next_idx: Mutex<u32>,
}

impl PartialEq for Descriptor {
    fn eq(&self, other: &Descriptor) -> bool {
        self.wallet_idx == other.wallet_idx
    }
}
impl Eq for Descriptor {}

impl Ord for Descriptor {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.wallet_idx.cmp(&other.wallet_idx)
    }
}

impl PartialOrd for Descriptor {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

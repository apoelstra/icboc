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
    cmp, fmt,
    io::{Read, Seek, Write},
    sync::{Arc, Mutex},
};

pub use self::address::{Address, AddressInfo};
use self::encode::{EncAddress, EncDescriptor, EncTxo, EncWallet};
pub use self::txo::Txo;
use crate::{Dongle, Error, KeyCache};

/// Opaque cache of all scriptpubkeys the wallet is tracking
pub struct ScriptPubkeyCache {
    /// Scriptpubkeys we control
    spks: HashMap<bitcoin::Script, (usize, u32)>,
}

/// Wallet structure
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Wallet {
    /// Last blockheight the wallet considers confirmed and will not rescan
    pub block_height: u64,
    /// List of descriptors tracked by the wallet
    pub descriptors: Vec<Arc<Descriptor>>,
    /// Set of outstanding addresses that have notes attached to them
    pub addresses: HashMap<bitcoin::Script, Address>,
    /// Set of TXOs owned by the wallet
    pub txos: HashMap<bitcoin::OutPoint, Txo>,
    /// Cache of keys we've gotten from the dongel
    pub key_cache: KeyCache,
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
            addresses: HashMap::with_capacity(enc_wallet.addresses.len()),
            txos: HashMap::with_capacity(enc_wallet.txos.len()),
            key_cache: enc_wallet.key_cache,
        };
        // Copy descriptors into arcs
        for enc_desc in enc_wallet.descriptors {
            let idx = ret.descriptors.len();
            let mut next_idx = 0;
            // Re-cache keys (this should be basically a no-op, but allows the user
            // to recover in case the dongle was malfunctioning the last time the
            // cache was created).
            //
            // Also determine the next unused index
            for enc_addr in &enc_wallet.addresses {
                ret.cache_keys(&mut *dongle, &enc_desc.desc, enc_addr.wildcard_idx);
                if enc_addr.descriptor_idx as usize == idx {
                    next_idx = cmp::max(next_idx, enc_addr.wildcard_idx + 1);
                }
            }
            ret.descriptors.push(Arc::new(Descriptor {
                desc: enc_desc.desc,
                wallet_idx: idx,
                low: enc_desc.low,
                high: enc_desc.high,
                next_idx: Mutex::new(next_idx),
            }));
        }
        // Build address map
        for enc_addr in enc_wallet.addresses {
            // Load keys from cache
            let desc_arc = ret.descriptors[enc_addr.descriptor_idx as usize].clone();
            let inst = ret.instantiate_from_cache(&desc_arc.desc, enc_addr.wildcard_idx)?;
            ret.addresses.insert(
                inst.script_pubkey(),
                Address::new(
                    desc_arc,
                    enc_addr.wildcard_idx,
                    enc_addr.time,
                    enc_addr.notes,
                ),
            );
        }
        // Build txo map
        for enc_txo in enc_wallet.txos {
            ret.txos.insert(
                enc_txo.outpoint,
                Txo {
                    descriptor_idx: enc_txo.descriptor_idx as usize,
                    wildcard_idx: enc_txo.wildcard_idx,
                    outpoint: enc_txo.outpoint,
                    value: enc_txo.value,
                    spent: enc_txo.spent,
                    height: enc_txo.height,
                    spent_height: enc_txo.spent_height,
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
                .addresses
                .values()
                .map(|addr| EncAddress {
                    descriptor_idx: addr.descriptor.wallet_idx as u32,
                    wildcard_idx: addr.index,
                    time: addr.time.clone(),
                    notes: addr.time.clone(),
                })
                .collect(),
            txos: self
                .txos
                .values()
                .map(|txo| EncTxo {
                    descriptor_idx: txo.descriptor_idx as u32,
                    wildcard_idx: txo.wildcard_idx,
                    outpoint: txo.outpoint,
                    value: txo.value,
                    spent: txo.spent,
                    height: txo.height,
                    spent_height: txo.spent_height,
                })
                .collect(),
            key_cache: self.key_cache.clone(),
        }
        .write(w, key, nonce)
        .map_err(Error::from)
    }

    /// Iterator over all TXOs tracked by the wallet
    pub fn all_txos<'a>(&'a self) -> impl Iterator<Item = TxoInfo<'a>> {
        self.txos.keys().map(move |key| self.txo(*key).unwrap())
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
        &'wallet mut self,
        descriptor_idx: usize,
        wildcard_idx: Option<u32>,
        time: String,
        notes: String,
    ) -> Result<AddressInfo<'wallet>, Error> {
        let mut next_idx = self.descriptors[descriptor_idx].next_idx.lock().unwrap();
        let wildcard_idx = wildcard_idx.unwrap_or(*next_idx);
        *next_idx = cmp::max(*next_idx, wildcard_idx) + 1;

        let desc_arc = self.descriptors[descriptor_idx].clone();
        let spk = self
            .instantiate_from_cache(&desc_arc.desc, wildcard_idx)?
            .script_pubkey();
        let spk_clone = spk.clone(); // sigh rust
        self.addresses
            .insert(spk, Address::new(desc_arc, wildcard_idx, time, notes));
        self.addresses[&spk_clone].info(self)
    }

    /// Iterator over all descriptors in the wallet, and their index
    pub fn descriptors<'a>(&'a self) -> impl Iterator<Item = &'a Descriptor> {
        self.descriptors.iter().map(|arc| &**arc)
    }

    /// Gets the set of TXOs associated with a particular descriptor
    pub fn txos_for<'a>(&'a self, descriptor_idx: usize) -> HashSet<&'a Txo> {
        self.txos
            .values()
            .filter(|txo| txo.descriptor_idx() == descriptor_idx)
            .collect()
    }

    /// Looks up a specific TXO
    pub fn txo<'a>(&'a self, outpoint: bitcoin::OutPoint) -> Result<TxoInfo<'a>, Error> {
        let txo = match self.txos.get(&outpoint) {
            Some(txo) => txo,
            None => return Err(Error::TxoNotFound(outpoint)),
        };

        let desc_arc = self.descriptors[txo.descriptor_idx()].clone();
        let inst = self.instantiate_from_cache(&desc_arc.desc, txo.wildcard_idx())?;
        let spk = inst.script_pubkey();
        Ok(TxoInfo {
            txo: txo,
            address: inst
                .address(bitcoin::Network::Bitcoin)
                .expect("getting bitcoin address"),
            descriptor: &self.descriptors[txo.descriptor_idx()],
            address_info: self.addresses.get(&spk),
        })
    }

    /// Returns an opaque object the wallet can use to recognize its own scriptpubkeys
    pub fn script_pubkey_cache(&self) -> Result<ScriptPubkeyCache, Error> {
        let mut map = HashMap::new();
        for (didx, desc) in self.descriptors.iter().enumerate() {
            for widx in desc.low..desc.high {
                let spk = self
                    .instantiate_from_cache(&self.descriptors[didx].desc, widx as u32)?
                    .script_pubkey();
                map.insert(spk, (didx, widx as u32));
            }
        }

        Ok(ScriptPubkeyCache { spks: map })
    }

    /// Scans a block for wallet-relevant information. Returns two sets, one of
    /// received coins and one of spent coins
    pub fn scan_block(
        &mut self,
        block: &bitcoin::Block,
        height: u64,
        cache: &mut ScriptPubkeyCache,
    ) -> Result<(HashSet<bitcoin::OutPoint>, HashSet<bitcoin::OutPoint>), Error> {
        let mut received = HashSet::new();
        let mut spent = HashSet::new();

        for tx in &block.txdata {
            for (vout, output) in tx.output.iter().enumerate() {
                if let Some((didx, widx)) = cache.spks.get(&output.script_pubkey) {
                    let outpoint = bitcoin::OutPoint::new(tx.txid(), vout as u32);
                    let new_txo = Txo::new(*didx, *widx, outpoint, output.value, height);
                    self.txos.insert(outpoint, new_txo);
                    received.insert(outpoint);
                }
            }

            for input in &tx.input {
                if let Some(txo) = self.txos.get_mut(&input.previous_output) {
                    txo.set_spent(tx.txid(), height);
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
        self.wallet_idx == other.wallet_idx && self.low == other.low && self.high == other.high
    }
}
impl Eq for Descriptor {}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A structure containing information about a txo tracked by the wallet
pub struct TxoInfo<'wallet> {
    txo: &'wallet Txo,
    descriptor: &'wallet Descriptor,
    address: bitcoin::Address,
    address_info: Option<&'wallet Address>,
}

impl<'wallat> TxoInfo<'wallat> {
    /// Accessor for the value of this TXO
    pub fn value(&self) -> u64 {
        self.txo.value()
    }

    /// Whether the TXO has been spent or not
    pub fn is_unspent(&self) -> bool {
        self.txo.spent_height().is_none()
    }
}

impl<'wallat> Ord for TxoInfo<'wallat> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        fn sort_key<'a>(obj: &TxoInfo<'a>) -> impl Ord {
            (
                obj.txo.height(),
                obj.txo.descriptor_idx(),
                obj.txo.wildcard_idx(),
                obj.txo.outpoint(),
            )
        }
        sort_key(self).cmp(&sort_key(other))
    }
}

impl<'wallat> PartialOrd for TxoInfo<'wallat> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'wallat> fmt::Display for TxoInfo<'wallat> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ outpoint: \"{}\", value: \"{}\", height: {}, descriptor: \"{}\", index: {}",
            self.txo.outpoint(),
            bitcoin::Amount::from_sat(self.txo.value()),
            self.txo.height(),
            self.descriptor.desc,
            self.txo.wildcard_idx(),
        )?;
        if let Some(txid) = self.txo.spending_txid() {
            write!(f, ", spent_by: \"{}\"", txid)?;
        }
        if let Some(height) = self.txo.spent_height() {
            write!(f, ", spent_height: {}", height)?;
        }
        if let Some(addrinfo) = self.address_info {
            write!(f, ", address_created_at: \"{}\"", addrinfo.create_time())?;
            write!(f, ", notes: \"{}\"", addrinfo.notes())?;
        }
        f.write_str("}")
    }
}

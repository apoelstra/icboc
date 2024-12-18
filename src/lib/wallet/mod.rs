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

use miniscript::bitcoin::{
    self,
    hashes::{hash160, ripemd160, sha256},
    secp256k1,
};
use miniscript::{self, hash256, TranslatePk};

use std::collections::{HashMap, HashSet};
use std::{
    cmp,
    collections::hash_map::Entry,
    convert::Infallible,
    fmt,
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
    spk_address: HashMap<bitcoin::ScriptBuf, Arc<Address>>,
    /// Index from descriptor/index pairs to addresses
    descriptor_address: HashMap<(usize, u32), Arc<Address>>,
    /// Set of TXOs owned by the wallet
    txos: HashMap<bitcoin::OutPoint, Txo>,
    /// Cache of keys we've gotten from the dongle
    key_cache: KeyCache,
    /// Cache of transactions that are relevant to us
    tx_cache: HashMap<bitcoin::Txid, bitcoin::Transaction>,
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
            tx_cache: enc_wallet
                .tx_cache
                .into_iter()
                .map(|tx| (tx.txid(), tx))
                .collect(),
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
                let inst = ret.cache_keys(&mut *dongle, &desc_arc.desc, wildcard_idx)?;
                let new_addr = Arc::new(Address {
                    descriptor: Arc::clone(&desc_arc),
                    index: wildcard_idx,
                    instantiated_descriptor: inst,
                    user_data: Mutex::new(None),
                });
                ret.descriptor_address
                    .insert((idx, wildcard_idx), Arc::clone(&new_addr));
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
                    address: Arc::clone(
                        &ret.descriptor_address
                            [&(enc_txo.descriptor_idx as usize, enc_txo.wildcard_idx)],
                    ),
                    outpoint: enc_txo.outpoint,
                    value: enc_txo.value,
                    height: enc_txo.height,
                    spent_data: enc_txo.spent.map(|txid| SpentData {
                        txid,
                        height: enc_txo.spent_height,
                    }),
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
                    spent_height: txo.spent_data.as_ref().map_or(0, |data| data.height),
                })
                .collect(),
            key_cache: self.key_cache.clone(),
            tx_cache: self.tx_cache.values().cloned().collect(),
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
    pub fn addresses(&self) -> impl Iterator<Item = Arc<Address>> + '_ {
        self.spk_address
            .values()
            .filter(|addr| addr.user_data.lock().unwrap().is_some())
            .cloned()
    }

    /// Iterator over all TXOs tracked by the wallet
    pub fn all_txos(&self) -> impl Iterator<Item = &Txo> {
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
        key: &miniscript::DefiniteDescriptorKey,
    ) -> Result<secp256k1::PublicKey, Error> {
        dongle.get_wallet_public_key(key, key_cache)
    }

    /// Helper fuction that (tries to) cache all the keys in a descriptor from the Ledger
    fn cache_keys<D: Dongle>(
        &mut self,
        dongle: &mut D,
        desc: &miniscript::Descriptor<miniscript::DescriptorPublicKey>,
        index: u32,
    ) -> Result<miniscript::Descriptor<CachedKey>, Error> {
        let mut translator = KeyCachingTranslator {
            dongle,
            key_cache: &mut self.key_cache,
            index,
        };
        desc.translate_pk(&mut translator)
            .map_err(|e| e.expect_translator_err("caching won't cause duplicate keys"))
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

        let idx = self.descriptors.len();
        let desc_arc = Arc::new(Descriptor {
            desc,
            wallet_idx: idx,
            low,
            high,
            next_idx: Mutex::new(0),
        });

        let mut added_new = 0;
        for i in low..high {
            if !existing_indices.contains(&i) {
                added_new += 1;
                let inst = self.cache_keys(&mut *dongle, &desc_arc.desc, i)?;
                let new_addr = Arc::new(Address {
                    descriptor: Arc::clone(&desc_arc),
                    index: i,
                    instantiated_descriptor: inst,
                    user_data: Mutex::new(None),
                });
                self.descriptor_address
                    .insert((idx, i), Arc::clone(&new_addr));
                self.spk_address
                    .insert(new_addr.instantiated_descriptor.script_pubkey(), new_addr);
            }
        }

        self.descriptors.push(desc_arc);
        Ok(added_new)
    }

    /// Adds a new address to the wallet.
    pub fn add_address(
        &mut self,
        descriptor_idx: usize,
        wildcard_idx: Option<u32>,
        time: String,
        notes: String,
    ) -> Result<Arc<Address>, Error> {
        let wildcard_idx = {
            let mut next_idx = self.descriptors[descriptor_idx].next_idx.lock().unwrap();
            let wildcard_idx = wildcard_idx.unwrap_or(*next_idx);
            *next_idx = cmp::max(*next_idx, wildcard_idx) + 1;
            wildcard_idx
        };

        let mut translator = CachedKeyTranslator {
            key_cache: &self.key_cache,
            index: wildcard_idx,
        };
        // Unwrap safe since the error type here is `Infallible`
        let inst = self.descriptors[descriptor_idx]
            .desc
            .translate_pk(&mut translator)
            .unwrap();
        let spk = inst.script_pubkey();

        let new_addr = Arc::new(Address {
            descriptor: Arc::clone(&self.descriptors[descriptor_idx]),
            index: wildcard_idx,
            instantiated_descriptor: inst,
            user_data: Mutex::new(Some(UserData { time, notes })),
        });
        self.spk_address.insert(spk, Arc::clone(&new_addr));
        self.descriptor_address
            .insert((descriptor_idx, wildcard_idx), Arc::clone(&new_addr));

        Ok(new_addr)
    }

    /// Iterator over all descriptors in the wallet, and their index
    pub fn descriptors(&self) -> impl Iterator<Item = &Descriptor> {
        self.descriptors.iter().map(|arc| &**arc)
    }

    /// Gets the set of TXOs associated with a particular descriptor
    pub fn txos_for(&self, descriptor_idx: usize) -> HashSet<&Txo> {
        self.txos
            .values()
            .filter(|txo| txo.address.descriptor.wallet_idx == descriptor_idx)
            .collect()
    }

    /// Looks up a specific TXO
    pub fn txo(&self, outpoint: bitcoin::OutPoint) -> Result<&Txo, Error> {
        match self.txos.get(&outpoint) {
            Some(txo) => Ok(txo),
            None => Err(Error::TxoNotFound(outpoint)),
        }
    }

    /// Looks up a cached transaction
    pub fn tx(&self, txid: bitcoin::Txid) -> Result<&bitcoin::Transaction, Error> {
        match self.tx_cache.get(&txid) {
            Some(txo) => Ok(txo),
            None => Err(Error::TxNotFound(txid)),
        }
    }

    /// Scans a transaction for wallet-relevant information. Returns two sets, one of
    /// received coins and one of spent coins
    pub fn scan_tx(
        &mut self,
        tx: &bitcoin::Transaction,
        height: u64,
    ) -> (HashSet<bitcoin::OutPoint>, HashSet<bitcoin::OutPoint>) {
        let mut received = HashSet::new();
        let mut spent = HashSet::new();

        for (vout, output) in tx.output.iter().enumerate() {
            if let Some(addr) = self.spk_address.get(&output.script_pubkey) {
                let outpoint = bitcoin::OutPoint::new(tx.txid(), vout as u32);
                match self.txos.entry(outpoint) {
                    Entry::Vacant(v) => {
                        v.insert(Txo {
                            address: Arc::clone(addr),
                            outpoint,
                            value: output.value,
                            height,
                            spent_data: None,
                        });
                    }
                    Entry::Occupied(mut o) => o.get_mut().height = height,
                }
                self.tx_cache.insert(tx.txid(), tx.clone());
                received.insert(outpoint);
            }
        }

        for input in &tx.input {
            if let Some(txo) = self.txos.get_mut(&input.previous_output) {
                if let Some(data) = txo.spent_data.take() {
                    println!(
                        "Warning: {} is double-spent by {} (original transaction {})",
                        input.previous_output,
                        tx.txid(),
                        data.txid,
                    );
                }
                txo.spent_data = Some(SpentData {
                    txid: tx.txid(),
                    height,
                });
                spent.insert(input.previous_output);
            }
        }

        (received, spent)
    }

    /// Scans a block for wallet-relevant information. Returns two sets, one of
    /// received coins and one of spent coins
    pub fn scan_block(
        &mut self,
        block: &bitcoin::Block,
        height: u64,
    ) -> (HashSet<bitcoin::OutPoint>, HashSet<bitcoin::OutPoint>) {
        let mut received = HashSet::new();
        let mut spent = HashSet::new();

        for tx in &block.txdata {
            let (rec, spe) = self.scan_tx(tx, height);
            received.extend(rec);
            spent.extend(spe);
        }

        (received, spent)
    }
}

/// A public key known by the wallet
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CachedKey {
    /// Instantiated descriptor
    pub desc_key: miniscript::DefiniteDescriptorKey,
    /// Cached copy of the resulting [`secp256k1::PublicKey`]
    pub key: secp256k1::PublicKey,
}

impl fmt::Display for CachedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.desc_key.fmt(f)
    }
}

impl miniscript::MiniscriptKey for CachedKey {
    type Hash160 = hash160::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Sha256 = sha256::Hash;

    // FIXME in miniscript 11 we can drop this since the trait gains a default impl.
    // this function only returns a non-1 value if we were using BIP 389, which we do not.
    fn num_der_paths(&self) -> usize {
        1
    }
}

impl miniscript::ToPublicKey for CachedKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        bitcoin::PublicKey::new(self.key)
    }

    fn to_hash160(hash: &hash160::Hash) -> hash160::Hash {
        *hash
    }
    fn to_hash256(hash: &hash256::Hash) -> hash256::Hash {
        *hash
    }
    fn to_ripemd160(hash: &ripemd160::Hash) -> ripemd160::Hash {
        *hash
    }
    fn to_sha256(hash: &sha256::Hash) -> sha256::Hash {
        *hash
    }
}

/// A `Translator` for use with `miniscript::TranslatePk::translate_pk` which converts
/// a `DescriptorPublicKey` to a `CachedKey`, caching it along the way
pub struct KeyCachingTranslator<'dongle, 'keycache, D: Dongle> {
    pub dongle: &'dongle mut D,
    pub key_cache: &'keycache mut KeyCache,
    pub index: u32,
}

impl<D: Dongle> miniscript::Translator<miniscript::DescriptorPublicKey, CachedKey, Error>
    for KeyCachingTranslator<'_, '_, D>
{
    miniscript::translate_hash_clone!(miniscript::DescriptorPublicKey, CachedKey, Error);

    fn pk(&mut self, pk: &miniscript::DescriptorPublicKey) -> Result<CachedKey, Error> {
        let derived = pk.clone().at_derivation_index(self.index).unwrap();
        Ok(CachedKey {
            key: Wallet::cache_key(self.dongle, self.key_cache, &derived)?,
            desc_key: derived,
        })
    }
}

/// A `Translator` for use with `miniscript::TranslatePk::translate_pk` which converts
/// a `DescriptorPublicKey` to a `CachedKey` by looking it up in a given cache.
///
/// The translation will panic if the key is not actually in the cache. However,
/// this translation is only called when given an `Address`, which is impossible
/// to construct without first having cached the key.
pub struct CachedKeyTranslator<'keycache> {
    pub key_cache: &'keycache KeyCache,
    pub index: u32,
}

impl miniscript::Translator<miniscript::DescriptorPublicKey, CachedKey, Infallible>
    for CachedKeyTranslator<'_>
{
    miniscript::translate_hash_clone!(miniscript::DescriptorPublicKey, CachedKey, Infallible);

    fn pk(&mut self, pk: &miniscript::DescriptorPublicKey) -> Result<CachedKey, Infallible> {
        let derived = pk.clone().at_derivation_index(self.index).unwrap();
        Ok(CachedKey {
            key: self.key_cache.lookup_descriptor_pubkey(&derived).unwrap(),
            desc_key: derived,
        })
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

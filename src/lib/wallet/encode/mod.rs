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

//! Wallet Encoding
//!
//! Types used for de/serializing to disk
//!

mod chacha20;
mod crypt;
mod serialize;

use crate::KeyCache;
use miniscript::bitcoin;
use miniscript::bitcoin::hashes::Hash;
use std::collections::HashMap;
use std::io::{self, Read, Seek, Write};

use self::serialize::{Serialize, MAX_VEC_ELEMS};

/// The wallet structure as it is encoded on disk
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EncWallet {
    /// Last blockheight the wallet considers confirmed and will not rescan
    pub block_height: u64,
    /// List of descriptors tracked by the wallet
    pub descriptors: Vec<EncDescriptor>,
    /// Set of outstanding addresses that have notes attached to them
    pub addresses: Vec<EncAddress>,
    /// Set of TXOs owned by the wallet
    pub txos: Vec<EncTxo>,
    /// Cache of keys we've gotten from the dongle
    pub key_cache: KeyCache,
    /// Set of transactions that we care about
    pub tx_cache: Vec<bitcoin::Transaction>,
}

impl EncWallet {
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

impl Serialize for EncWallet {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.block_height.write_to(&mut w)?;
        self.descriptors.write_to(&mut w)?;
        self.addresses.write_to(&mut w)?;
        self.txos.write_to(&mut w)?;
        self.key_cache.write_to(&mut w)?;
        self.tx_cache.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(EncWallet {
            block_height: Serialize::read_from(&mut r)?,
            descriptors: Serialize::read_from(&mut r)?,
            addresses: Serialize::read_from(&mut r)?,
            txos: Serialize::read_from(&mut r)?,
            key_cache: Serialize::read_from(&mut r)?,
            tx_cache: Serialize::read_from(r)?,
        })
    }
}

/// A descriptor held in the wallet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncDescriptor {
    /// The underlying descriptor
    pub desc: miniscript::Descriptor<miniscript::DescriptorPublicKey>,
    /// The first (inclusive) index to instantiate
    pub low: u32,
    /// The last (exclusize) index to instantiate
    pub high: u32,
}

impl Serialize for EncDescriptor {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.desc.write_to(&mut w)?;
        self.low.write_to(&mut w)?;
        self.high.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(EncDescriptor {
            desc: Serialize::read_from(&mut r)?,
            low: Serialize::read_from(&mut r)?,
            high: Serialize::read_from(&mut r)?,
        })
    }
}

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncAddress {
    /// Index into the wallet-global descriptor array
    pub descriptor_idx: u32,
    /// If the descriptor has wildcards, index into it
    pub wildcard_idx: u32,
    /// Time that the address was created, in format YYYY-MM-DD HH:MM:SS+ZZZZ
    pub time: String,
    /// User-provided notes about this address
    pub notes: String,
}

impl Serialize for EncAddress {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.descriptor_idx.write_to(&mut w)?;
        self.wildcard_idx.write_to(&mut w)?;
        self.time.write_to(&mut w)?;
        self.notes.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(EncAddress {
            descriptor_idx: Serialize::read_from(&mut r)?,
            wildcard_idx: Serialize::read_from(&mut r)?,
            time: Serialize::read_from(&mut r)?,
            notes: Serialize::read_from(r)?,
        })
    }
}

/// A (potentially spent) transaction output tracked by the wallet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncTxo {
    /// Index into the wallet-global descriptor array
    pub descriptor_idx: u32,
    /// If the descriptor has wildcards, index into it
    pub wildcard_idx: u32,
    /// Outpoint of the TXO
    pub outpoint: bitcoin::OutPoint,
    /// Value of the TXO, in satoshis
    pub value: bitcoin::Amount,
    /// If the TXO is spent, the txid that spent it
    pub spent: Option<bitcoin::Txid>,
    /// Blockheight at which the UTXO was created
    pub height: u64,
    /// Blockheight at which the UTXO was spent (ignored
    /// if it is unspent)
    pub spent_height: u64,
}

impl Serialize for EncTxo {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.descriptor_idx.write_to(&mut w)?;
        self.wildcard_idx.write_to(&mut w)?;
        self.outpoint.write_to(&mut w)?;
        self.value.write_to(&mut w)?;
        self.spent
            .unwrap_or(bitcoin::Txid::all_zeros())
            .write_to(&mut w)?;
        self.height.write_to(&mut w)?;
        self.spent_height.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(EncTxo {
            descriptor_idx: Serialize::read_from(&mut r)?,
            wildcard_idx: Serialize::read_from(&mut r)?,
            outpoint: Serialize::read_from(&mut r)?,
            value: Serialize::read_from(&mut r)?,
            spent: {
                let txid = Serialize::read_from(&mut r)?;
                if txid == bitcoin::Txid::all_zeros() {
                    None
                } else {
                    Some(txid)
                }
            },
            height: Serialize::read_from(&mut r)?,
            spent_height: Serialize::read_from(&mut r)?,
        })
    }
}

impl Serialize for KeyCache {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        let len32 = self.map.values().map(HashMap::len).sum::<usize>() as u32;
        if len32 > MAX_VEC_ELEMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "writing key cache of length {} exceeded max {} (type {})",
                    len32,
                    MAX_VEC_ELEMS,
                    std::any::type_name::<Self>(),
                ),
            ));
        }

        len32.write_to(&mut w)?;
        for (xpub, map) in &self.map {
            for (path, key) in map {
                xpub.write_to(&mut w)?;
                path.write_to(&mut w)?;
                w.write_all(&key.serialize())?;
            }
        }
        Ok(())
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let len32: u32 = Serialize::read_from(&mut r)?;
        if len32 > MAX_VEC_ELEMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "reading key cache of length {} exceeded max {} (type {})",
                    len32,
                    MAX_VEC_ELEMS,
                    std::any::type_name::<Self>(),
                ),
            ));
        }

        let mut ret = KeyCache::new();
        for _ in 0..len32 {
            ret.insert(
                Serialize::read_from(&mut r)?,
                Serialize::read_from(&mut r)?,
                Serialize::read_from(&mut r)?,
            );
        }
        Ok(ret)
    }
}

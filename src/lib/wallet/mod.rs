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

use miniscript;

use crate::Error;
use self::serialize::Serialize;
use std::collections::HashSet;
use std::io::{self, Read, Seek, Write};
use std::str::FromStr;

const MAX_DESCRIPTOR_LEN: u32 = 64 * 1024;

/// Wallet structure
#[derive(Default)]
pub struct Wallet {
    /// Last blockheight the wallet considers confirmed and will not rescan
    pub block_height: u64,
    /// List of descriptors tracked by the wallet
    pub descriptors: Vec<miniscript::Descriptor<miniscript::DescriptorPublicKey>>,
    /// Set of TXOs owned by the wallet
    pub txos: HashSet<Txo>,
}

impl Wallet {
    /// Construct a new empty wallet
    pub fn new() -> Self { Self::default() }

    /// Read a wallet in encrypted form
    pub fn from_reader<R: Read + Seek>(r: R, key: [u8; 32]) -> io::Result<Self> {;
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
        self.txos.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(Wallet {
            block_height: Serialize::read_from(&mut r)?,
            descriptors: Serialize::read_from(&mut r)?,
            txos: Serialize::read_from(r)?,
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
println!("write desc");
        self.descriptor_idx.write_to(&mut w)?;
println!("write 1esc");
        self.wildcard_idx.write_to(&mut w)?;
println!("write 2esc");
        self.outpoint.write_to(&mut w)?;
println!("write 3esc");
        self.value.write_to(&mut w)?;
println!("write 4esc");
        self.spent.unwrap_or(Default::default()).write_to(&mut w)?;
println!("write 5esc");
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

impl Serialize for miniscript::Descriptor<miniscript::DescriptorPublicKey> {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        let string = self.to_string();
        (string.len() as u32).write_to(&mut w);
        w.write_all(string.as_bytes())
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let len: u32 = Serialize::read_from(&mut r)?;
        let mut data = vec![0; len as usize];
        r.read_exact(&mut data)?;
        let s = String::from_utf8(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        miniscript::Descriptor::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}


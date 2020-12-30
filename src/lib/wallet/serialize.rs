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

//! Wallet Serialization
//!
//! Data types which can be read and written to the wallet backing store
//!

use miniscript::bitcoin::hashes::Hash;
use std::collections::HashSet;
use std::io::{self, Read, Write};

// Largest item we serialize, a Utxo structure, is 84 bytes
const MAX_VEC_ELEMS: u32 = 100_000;

/// Trait describing an object which can be de/serialized to the wallet storage
pub trait Serialize: Sized {
    /// Write the data to a writer
    fn write_to<W: Write>(&self, w: W) -> io::Result<()>;

    /// Read the data from a reader
    fn read_from<R: Read>(r: R) -> io::Result<Self>;
}

impl Serialize for u8 {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        w.write_all(&[*self])
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let mut dat = [0; 1];
        r.read_exact(&mut dat)?;
        Ok(dat[0])
    }
}

impl Serialize for u32 {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        w.write_all(&[
            *self as u8,
            (*self >> 8) as u8,
            (*self >> 16) as u8,
            (*self >> 24) as u8,
        ])
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let mut dat = [0; 4];
        r.read_exact(&mut dat)?;
        Ok((dat[0] as u32) + ((dat[1] as u32) << 8) + ((dat[2] as u32) << 16) + ((dat[3] as u32) << 24))
    }
}

impl Serialize for u64 {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        (*self as u32).write_to(&mut w)?;
        ((*self >> 32) as u32).write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let lo: u32 = Serialize::read_from(&mut r)?;
        let hi: u32 = Serialize::read_from(&mut r)?;
        Ok((lo as u64) + (hi as u64) << 32)
    }
}

impl Serialize for miniscript::bitcoin::Txid {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        w.write_all(&self[..])
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let mut dat = [0; 32];
        r.read_exact(&mut dat)?;
        Ok(miniscript::bitcoin::Txid::from_inner(dat))
    }
}

impl Serialize for miniscript::bitcoin::OutPoint {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.txid.write_to(&mut w)?;
        self.vout.write_to(w)
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        Ok(miniscript::bitcoin::OutPoint {
            txid: Serialize::read_from(&mut r)?,
            vout: Serialize::read_from(r)?,
        })
    }
}

impl<T: Serialize> Serialize for Vec<T> {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        let len32: u32 = self.len() as u32;
        if self.len() > MAX_VEC_ELEMS as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "writing vector of length {} exceeded max {} (type {})",
                    len32,
                    MAX_VEC_ELEMS,
                    std::any::type_name::<Self>(),
                ),
            ));
        }
        len32.write_to(&mut w)?;
        for t in self {
            t.write_to(&mut w)?;
        }
        Ok(())
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let len32: u32 = Serialize::read_from(&mut r)?;
        let mut ret = Vec::with_capacity(len32 as usize);
        if len32 > MAX_VEC_ELEMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "reading vector of length {} exceeded max {} (type {})",
                    len32,
                    MAX_VEC_ELEMS,
                    std::any::type_name::<Self>(),
                ),
            ));
        }

        for _ in 0..len32 {
            ret.push(Serialize::read_from(&mut r)?);
        }
        Ok(ret)
    }
}

impl<T: Eq + std::hash::Hash + Serialize> Serialize for HashSet<T> {
    fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        let len32: u32 = self.len() as u32;
        if self.len() > MAX_VEC_ELEMS as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "writing vector of length {} exceeded max {} (type {})",
                    len32,
                    MAX_VEC_ELEMS,
                    std::any::type_name::<Self>(),
                ),
            ));
        }
        len32.write_to(&mut w)?;
        for t in self {
            t.write_to(&mut w)?;
        }
        Ok(())
    }

    fn read_from<R: Read>(mut r: R) -> io::Result<Self> {
        let len32: u32 = Serialize::read_from(&mut r)?;
        let mut ret = HashSet::with_capacity(len32 as usize);
        if len32 > MAX_VEC_ELEMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "reading vector of length {} exceeded max {} (type {})",
                    len32,
                    MAX_VEC_ELEMS,
                    std::any::type_name::<Self>(),
                ),
            ));
        }

        for _ in 0..len32 {
            ret.insert(Serialize::read_from(&mut r)?);
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use miniscript::bitcoin::OutPoint;

    use super::*;

    #[test]
    fn basic_rtt() {
        let data = vec![
            OutPoint::from_str("2222222222222222222222222222222222222222222222222222222222222222:0").unwrap(),
            OutPoint::from_str("3322222222222222222222222222222222222222222222222222222222222222:1").unwrap(),
            OutPoint::from_str("abcdabcda2923183201028930893081903819023810982301928301232222222:0").unwrap(),
            OutPoint::from_str("2222222220132823173987123973219789379379122222222222222222222222:9999").unwrap(),
        ];

        let mut ser = vec![];
        data.write_to(&mut ser);
        let read: Vec<OutPoint> = Serialize::read_from(&ser[..]).expect("read");
        assert_eq!(data, read);
    }
}


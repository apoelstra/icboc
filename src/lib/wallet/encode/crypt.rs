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

//! Wallet Cryter
//!
//! Defines a wrapper around [`io::Read`] and [`io::Write`] which does a simple
//! encrypt-then-MAC scheme using chacha20 and HMAC-SHA256. Does not
//! do any randomization; requires the user supply a uniformly random
//! 32-byte key and a unique (per message and key) 12-byte nonce.
//!

use miniscript::bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use std::io::{Read, Seek, Write};
use std::{cmp, io};

use super::chacha20;

/// Magic/version bytes which identify this as an ICBOC 3D wallet
const MAGIC_BYTES: [u8; 4] = *b"IX3D";

/// Wallet will be 0-padded to be a multiple of this value
const WALLET_ROUND_SIZE: usize = 0x8000;

/// Maximum size of a wallet we're willing to read. Set to we can comfortably
/// fit the whole wallet in RAM, and so that we can implement all of our
/// algorithms by linear searching. In a future version maybe we'll drop this
/// and relax these requirements.
const WALLET_MAX_SIZE: usize = WALLET_ROUND_SIZE * 1024;

/// Output size of chacha20
const CHACHA_SLICE_LEN: usize = 64;

/// Wrapper around a [`io::Read`] which reads encrypted and MAC'd data
pub struct CryptReader<R: Read + Seek> {
    key: [u8; 32],
    nonce: [u8; 12],
    read_len: usize,
    reader: R,
}

impl<R: Read + Seek> CryptReader<R> {
    /// Constructs a new encrypted reader, checking the MAC
    pub fn new(key: [u8; 32], mut r: R) -> io::Result<Self> {
        let tag = sha256::Hash::hash(b"icboc3d/wallet");
        let mut hmac_eng = HmacEngine::<sha256::Hash>::new(&key);

        hmac_eng.input(tag.as_byte_array());
        hmac_eng.input(tag.as_byte_array());

        let mut magic = [0; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("magic {:?} did not match expected {:?}", magic, MAGIC_BYTES),
            ));
        }
        hmac_eng.input(&magic[..]);

        let mut nonce = [0; 12];
        r.read_exact(&mut nonce)?;
        hmac_eng.input(&nonce[..]);

        // Read everything into hmac
        let wallet_len = r.seek(io::SeekFrom::End(0))?;
        r.seek(io::SeekFrom::Start(16))?;

        if wallet_len > WALLET_MAX_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("wallet size {} exceeds max {}", wallet_len, WALLET_MAX_SIZE),
            ));
        }

        let mut buf = [0; 64];
        let mut total_read: u64 = 16;
        while total_read < wallet_len - 32 {
            let to_read = cmp::min(wallet_len - 32 - total_read, 64);
            let n_read = r.read(&mut buf[..to_read as usize])?;
            if n_read == 0 {
                break;
            }
            hmac_eng.input(&buf[0..n_read]);
            total_read += n_read as u64;
        }
        assert_eq!(total_read, wallet_len - 32);

        let mut hmac_read = [0; 32];
        r.read_exact(&mut hmac_read)?;
        let hmac_read = Hmac::<sha256::Hash>::from_byte_array(hmac_read);
        let hmac_computed = Hmac::<sha256::Hash>::from_engine(hmac_eng);
        if hmac_read != hmac_computed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "hmac {} does not match computed {}",
                    hmac_read, hmac_computed
                ),
            ));
        }

        // Seek back to start to allow normal reading
        r.seek(io::SeekFrom::Start(16))?;
        Ok(CryptReader {
            key,
            nonce,
            read_len: 0,
            reader: r,
        })
    }
}

impl<R: Read + Seek> Read for CryptReader<R> {
    /// Read into a buffer
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let ret_n = self.reader.read(buf)?;
        buf = &mut buf[..ret_n];
        while !buf.is_empty() {
            let chacha_idx = (self.read_len / CHACHA_SLICE_LEN) as u32;
            let chacha_slice_idx = self.read_len % CHACHA_SLICE_LEN;
            let avail_len = CHACHA_SLICE_LEN - chacha_slice_idx;
            let read_len = cmp::min(buf.len(), avail_len);

            let chacha = chacha20::chacha20(self.key, chacha_idx, self.nonce);
            for i in 0..read_len {
                buf[i] ^= chacha[i + chacha_slice_idx];
            }

            buf = &mut buf[read_len..];
            self.read_len += read_len;
        }
        Ok(ret_n)
    }
}

/// Wrapper around a [`io::Write`] which encrypt-then-MACs data
pub struct CryptWriter<W: io::Write> {
    key: [u8; 32],
    nonce: [u8; 12],
    written_len: usize,
    writer: W,
    hmac_eng: HmacEngine<sha256::Hash>,
}

impl<W: io::Write> CryptWriter<W> {
    /// Constructs a new encrypted writer
    pub fn new(key: [u8; 32], nonce: [u8; 12], w: W) -> Self {
        CryptWriter {
            key,
            nonce,
            written_len: 0,
            writer: w,
            hmac_eng: HmacEngine::new(&key),
        }
    }

    /// Writes the initial magic bytes and nonce into the writer stream
    pub fn init(&mut self) -> io::Result<()> {
        let tag = sha256::Hash::hash(b"icboc3d/wallet");

        self.writer.write_all(&MAGIC_BYTES[..])?;
        self.writer.write_all(&self.nonce[..])?;

        self.hmac_eng.input(tag.as_byte_array());
        self.hmac_eng.input(tag.as_byte_array());
        self.hmac_eng.input(&MAGIC_BYTES[..]);
        self.hmac_eng.input(&self.nonce[..]);

        assert_eq!(self.written_len, 0);
        self.written_len = 16;
        Ok(())
    }

    /// Rounds the size up to the nearest 32k, writes out an hmac, and returns the underlying writer
    pub fn finalize(mut self) -> io::Result<W> {
        assert_eq!(WALLET_ROUND_SIZE % CHACHA_SLICE_LEN, 0);

        // First pad out til we can work with whole chacha blocks
        while self.written_len % CHACHA_SLICE_LEN != 0 {
            self.write_all(&[0])?;
        }

        // Pad out with chacha blocks of encrypted 0s
        let zeroes = [0; CHACHA_SLICE_LEN];
        while (self.written_len + CHACHA_SLICE_LEN) % WALLET_ROUND_SIZE != 0 {
            self.write_all(&zeroes[..])?;
        }
        self.write_all(&zeroes[..CHACHA_SLICE_LEN - 32])?;

        // Write out the hmac
        let hmac = Hmac::<sha256::Hash>::from_engine(self.hmac_eng);
        self.writer.write_all(&hmac[..])?;
        Ok(self.writer)
    }
}

impl<W: io::Write> io::Write for CryptWriter<W> {
    /// Puts some wallet data into the encrypted writer
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let enc_written = self.written_len - 16;
        let chacha_idx = (enc_written / CHACHA_SLICE_LEN) as u32;
        let chacha_slice_idx = enc_written % CHACHA_SLICE_LEN;

        let avail_len = CHACHA_SLICE_LEN - chacha_slice_idx;
        let write_len = cmp::min(data.len(), avail_len);

        let mut chacha = chacha20::chacha20(self.key, chacha_idx, self.nonce);
        for i in 0..write_len {
            chacha[i + chacha_slice_idx] ^= data[i];
        }
        let written_len = self
            .writer
            .write(&chacha[chacha_slice_idx..chacha_slice_idx + write_len])?;
        self.hmac_eng
            .input(&chacha[chacha_slice_idx..chacha_slice_idx + written_len]);

        self.written_len += written_len;
        Ok(written_len)
    }

    /// Flushes the underlying writer
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read, Write};

    // Joan Shelley "Teal" 2019
    const DATA: [u8; 1265] = *b"\
        Shock of teal blue beneath clouds gathering
        And the light of empty black on the waves at the horizon
        Like a glimpse into cold dark space where I go when I've been short with you
        and that with words
        and I have heard the tender things around me
        as to break your window
        for the immediate relief

        To tear apart summer stuffy and stale rooms
        To tear apart summer stuffy and stale rooms
        for fresh air and wind and waves
        for fresh air and wind and waves

        Looking further into the distance the bones in my neck lifted
        from their inward curving lines
        oh love escape this inward life
        when you have spoiled it
        at the table
        like a child in a fit of protest
        screaming out just to hear your name
        like a child who would break the window
        for fresh air and wind and waves
        for fresh air and wind and waves

        To tear apart summer stuffy and stale rooms
        To tear apart summer stuffy and stale rooms
        To tear apart summer stuffy and stale rooms
        for fresh air and wind and waves
        for fresh air and wind and waves
        for fresh air and wind and waves

        creating the work for winter\
    ";

    #[test]
    fn encrypt_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];

        let mut writer = CryptWriter::new(key, nonce, vec![]);
        writer.init().expect("init succeed");
        writer.write_all(&DATA[..]).expect("writing succeed");
        let mut vec = writer.finalize().expect("finalize succeed");

        assert_eq!(vec.len(), WALLET_ROUND_SIZE);

        let mut reader = CryptReader::new(key, io::Cursor::new(&*vec)).expect("check mac");
        let mut new_vec = vec![0; vec.len() - 32 - 16]; // MAC and header are skipped when reading
        reader
            .read_exact(&mut new_vec[..50])
            .expect("read first bytes");
        reader
            .read_exact(&mut new_vec[50..])
            .expect("read last bytes");

        assert_eq!(&new_vec[..DATA.len()], &DATA[..]);
        assert_eq!(
            &new_vec[DATA.len()..],
            &*vec![0; WALLET_ROUND_SIZE - 32 - 16 - DATA.len()],
        );

        // Spot check some random bytes to see if we break the MAC
        for i in 0..10 {
            vec[i * 771] ^= 55;
            CryptReader::new(key, io::Cursor::new(&*vec)).err().unwrap();
            vec[i * 771] ^= 55;
        }
    }
}

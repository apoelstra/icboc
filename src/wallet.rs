// IceBox
// Written in 2017 by
//   Andrew Poelstra <icebox@wpsoftware.net>
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

//! # Wallet
//!
//! Support for the "wallet" which is really more of an audit log
//!

use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt, BigEndian};
use crypto::aes;
use hex::ToHex;
use secp256k1::{self, Secp256k1, ContextFlag};
use std::{fmt, io, fs, str};
use std::io::{Read, Write};
use time;

use constants::wallet::{DECRYPTED_ENTRY_SIZE, ENCRYPTED_ENTRY_SIZE, MAGIC, MAX_USER_ID_BYTES, MAX_NOTE_BYTES};
use dongle::Dongle;
use error::Error;
use util::{hash_sha256, convert_compact_to_secp};

/// List of purposes that we use BIP32 keys
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum KeyPurpose {
    /// A Bitcoin address
    Address,
    /// The chaincode is an AES key
    AesKey,
    // TODO p2contract nonce (need Ledger support)
}

/// Obtain a BIP32 path corresponding to the appropriate key
pub fn bip32_path(account: u32, purpose: KeyPurpose, index: u32) -> [u32; 5] {
    let pp_index = match purpose {
        // 0 and 1 would correspond to "normal" or "change" in BIP44;
        // we deliberately avoid these indices to avoid standard BIP44
        // wallets overlapping with us, although we observe that using
        // hardened keys is already sufficient for this
        KeyPurpose::Address       => 2,
        KeyPurpose::AesKey        => 3,
    };
    [0x8000002c, 0x80000000, 0x80000000 | account, 0x80000000 | pp_index, 0x80000000 | index]
}

// This whole encryption business should be done on the dongle
/// Helper function to encrypt an entry
fn encrypt<D: Dongle>(dongle: &mut D, account: u32, index: usize, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let key = dongle.get_public_key(&bip32_path(account, KeyPurpose::AesKey, index as u32))?;
    let iv = dongle.get_random(32)?;
    let mut encryptor = aes::ctr(aes::KeySize::KeySize256, &key.chaincode[..], &iv);
    output[0..32].copy_from_slice(&iv);
    encryptor.process(input, &mut output[32..]);
    Ok(())
}

/// Helper function to decrypt an entry
fn decrypt<D: Dongle>(dongle: &mut D, account: u32, index: usize, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let key = dongle.get_public_key(&bip32_path(account, KeyPurpose::AesKey, index as u32))?;
    let iv = &input[0..32];
    let mut encryptor = aes::ctr(aes::KeySize::KeySize256, &key.chaincode[..], iv);
    encryptor.process(&input[32..], output);
    Ok(())
}

/// Structure representing an encrypted wallet
pub struct EncryptedWallet {
    account: u32,
    entries: Vec<[u8; ENCRYPTED_ENTRY_SIZE]>
}

impl EncryptedWallet {
    /// Construct a new empty wallet with the given account number
    pub fn new<D: Dongle>(dongle: &mut D, account: u32, n_entries: usize) -> Result<EncryptedWallet, Error> {
        let mut ret = EncryptedWallet {
            account: account,
            entries: Vec::with_capacity(n_entries)
        };


        for i in 0..n_entries {
            info!("Encrypting zeroes for key {}", i);
            let mut block = [0; ENCRYPTED_ENTRY_SIZE];
            let zeroes = [0; DECRYPTED_ENTRY_SIZE];
            encrypt(dongle, account, ret.entries.len(), &zeroes, &mut block)?;
            ret.entries.push(block);
        }

        Ok(ret)
    }

    /// Saves out the wallet to a file
    pub fn save(&self, filename: &str) -> Result<(), Error> {
        let mut temp_name = filename.to_owned();
        temp_name.push_str(".0");
        let fh = fs::File::create(&temp_name)?;
        let mut buf = io::BufWriter::new(fh);
        buf.write_u64::<BigEndian>(MAGIC)?;
        buf.write_u32::<BigEndian>(self.account)?;
        for data in &self.entries {
            buf.write(&data[..])?;
        }
        fs::rename(&temp_name, filename)?;
        info!("Saved wallet to {}", filename);
        Ok(())
    }

    /// Loads a wallet from a file
    pub fn load(filename: &str) -> Result<EncryptedWallet, Error> {
        let meta = fs::metadata(filename)?;
        let size = meta.len() as usize;

        if size % ENCRYPTED_ENTRY_SIZE != 12 {
            return Err(Error::WalletWrongSize(size));
        }

        let mut ret = EncryptedWallet {
            account: 0,
            entries: Vec::with_capacity(size / ENCRYPTED_ENTRY_SIZE)
        };

        let mut fh = fs::File::open(filename)?;
        let magic = fh.read_u64::<BigEndian>()?;
        if magic != MAGIC {
            return Err(Error::WalletWrongMagic(magic));
        }

        ret.account = fh.read_u32::<BigEndian>()?;
        for _ in 0..ret.entries.capacity() {
            let mut entry = [0; ENCRYPTED_ENTRY_SIZE];
            fh.read_exact(&mut entry)?;
            ret.entries.push(entry);
        }

        Ok(ret)
    }

    /// Scan the wallet for the first unused index
    pub fn next_unused_index<D: Dongle>(&self, dongle: &mut D) -> Result<usize, Error> {
        let mut output = [0u8; DECRYPTED_ENTRY_SIZE];
        for (index, entry) in self.entries.iter().enumerate() {
            decrypt(dongle, self.account, index, entry, &mut output)?;
            if output.iter().all(|x| *x == 0) {
                return Ok(index)
            }
        }
        Err(Error::WalletFull)
    }

    /// Accessor for the encrypted data in a wallet
    pub fn lookup<D: Dongle>(&self, dongle: &mut D, index: usize) -> Result<Entry, Error> {
        if index + 1 > self.entries.len() {
            return Err(Error::EntryOutOfRange(index));
        }

        Entry::decrypt_and_verify(dongle, self.account, index, &self.entries[index])
    }

    /// Update an address entry to indicate that it is in use
    pub fn update<D: Dongle>(&mut self, dongle: &mut D, index: usize, user: String, blockhash: Vec<u8>, note: String) -> Result<Entry, Error> {
        if user.as_bytes().len() > MAX_USER_ID_BYTES {
            return Err(Error::UserIdTooLong(user.as_bytes().len(), MAX_USER_ID_BYTES));
        }
        if note.as_bytes().len() > MAX_NOTE_BYTES {
            return Err(Error::UserIdTooLong(note.as_bytes().len(), MAX_NOTE_BYTES));
        }

        let timestr = time::strftime("%F %T%z", &time::now()).unwrap();
        assert_eq!(timestr.bytes().len(), 24);
        let mut timesl = [0; 24];
        timesl.clone_from_slice(timestr.as_bytes());
        let mut block = [0; 32];
        block.clone_from_slice(&blockhash);

        let key = dongle.get_public_key(&bip32_path(self.account, KeyPurpose::Address, index as u32))?;
        let entry = Entry {
            state: EntryState::Valid,
            address: key.b58_address,
            index: index,
            txid: [0; 32],
            vout: 0,
            amount: 0,
            date: timesl,
            user: user,
            blockhash: block,
            note: note
        };

        self.entries[index] = entry.sign_and_encrypt(dongle, self.account, index)?;

        Ok(entry)
    }

    /// Accessor for the account number
    pub fn account(&self) -> u32 { self.account }
    /// Accessor for the number of entries
    pub fn n_entries(&self) -> usize { self.entries.len() }
}

/// Whether an entry has been used
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EntryState {
    /// Entry is all zeroes
    Unused,
    /// Entry is nonzero and has a valid signature
    Valid,
    /// Entry is nonzero but has an invalid signature
    Invalid
}

/// Structure representing a decrypted entry
///
/// The full byte format is
/// +------------+-----------------------------------------+----------+--------+
/// | Field      | Description                             | Size     | Offset |
/// +------------+-----------------------------------------+----------+--------|
/// | Txid       | TXID of first output using this address | 32 bytes | 0      |
/// | vout       | vout of said output, big endian         |  4 bytes | 32     |
/// | Amount     | Amount of said output, big endian       |  8 bytes | 36     |
/// | Signature  | Sig w address of all fields from "Date" | 64 bytes | 44     |
/// | Date       | ASCII bytes YYYY-MM-DD HH:MM:SS+ZZZZ    | 24 bytes | 108    |
/// | Blockhash  | Recent blockhash, big endian            | 32 bytes | 132    |
/// | User ID    | Freeform, zero-padded, expected ASCII   | 32 bytes | 164    |
/// | Note       | Freeform, zero-padded, expected ASCII   | 60 bytes | 196    |
/// +------------+-----------------------------------------+----------+--------+
///
/// Total: 256 bytes
/// Total signed: 148 bytes
///
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    /// The overall state of this entry
    pub state: EntryState,
    /// The base58-encoded address of this entry
    pub address: String,
    /// The BIP32 index of this entry
    pub index: usize,
    /// The txid of the first receive to this address (or all zeros if it's yet unused)
    pub txid: [u8; 32],
    /// The vout of the first receive to this address (or zero if it's yet unused)
    pub vout: u32,
    /// The amount of the first receive to this address (or zero if it's yet unused)
    pub amount: u64,
    /// The date the entry was updated, in ASCII `YYYY-MM-DD HH:MM:SS+ZZZZ`
    pub date: [u8; 24],
    /// A recent bitcoin blockhash
    pub blockhash: [u8; 32],
    /// A freeform user ID, max 32 bytes
    pub user: String,
    /// A freeform note
    pub note: String
}

impl Entry {
    /// Encode an entry, sign the second half of it, and embed the signature in the entry
    fn sign_and_encrypt<D: Dongle>(&self, dongle: &mut D, account: u32, index: usize) -> Result<[u8; ENCRYPTED_ENTRY_SIZE], Error> {
        let mut input = [0; DECRYPTED_ENTRY_SIZE];
        // Copy out the unsigned data
        input[0..32].copy_from_slice(&self.txid);
        BigEndian::write_u32(&mut input[32..36], self.vout);
        BigEndian::write_u64(&mut input[36..44], self.amount);
        // Then the signed data
        input[108..132].copy_from_slice(&self.date);
        input[132..164].copy_from_slice(&self.blockhash);
        input[164..164 + self.user.as_bytes().len()].copy_from_slice(self.user.as_bytes());
        input[196..196 + self.note.as_bytes().len()].copy_from_slice(self.note.as_bytes());
        // Now sign it
        let sig = {
            let to_sign = &input[108..256];

            println!("The dongle will ask you to sign hash {}", hash_sha256(to_sign).to_hex());
            println!("This is the SHA256 of data {}", to_sign.to_hex());
            dongle.sign_message(to_sign, &bip32_path(account, KeyPurpose::Address, index as u32))?
        };
        input[44..108].copy_from_slice(&sig);

        // AES-encrypt the whole thing
        let mut ret = [0; ENCRYPTED_ENTRY_SIZE];
        encrypt(dongle, account, index, &input, &mut ret)?;
        Ok(ret)
    }

    /// Interpret a byte sequence as an entry; verify its signature if it's not blank
    fn decrypt_and_verify<D: Dongle>(dongle: &mut D, account: u32, index: usize, input: &[u8; ENCRYPTED_ENTRY_SIZE]) -> Result<Entry, Error> {
        let mut data = [0u8; DECRYPTED_ENTRY_SIZE];
        decrypt(dongle, account, index, &input[..], &mut data)?;

        if data.iter().all(|x| *x == 0) {
            Ok(Entry {
                state: EntryState::Unused,
                address: String::new(),
                index: 0,
                txid: [0; 32],
                vout: 0,
                amount: 0,
                date: [0; 24],
                user: String::new(),
                blockhash: [0; 32],
                note: String::new()
            })
        } else {
            let key = dongle.get_public_key(&bip32_path(account, KeyPurpose::Address, index as u32))?;

            let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);
            let sig = convert_compact_to_secp(&data[44..108])?;
            let mut msg_full = vec![0; 174];
            // nb the x18 here is the length of "Bitcoin Signed Message:\n", the x94 is the length of the rest
            msg_full[0..26].copy_from_slice(b"\x18Bitcoin Signed Message:\n\x94");
            msg_full[26..174].copy_from_slice(&data[108..256]);
            let msg_hash = hash_sha256(&hash_sha256(&msg_full));
            let msg = secp256k1::Message::from_slice(&msg_hash).unwrap();
            let verified = secp.verify(&msg, &sig, &key.public_key).is_ok();

            let mut txid = [0; 32]; txid.clone_from_slice(&data[0..32]);
            let mut date = [0; 24]; date.clone_from_slice(&data[108..132]);
            let mut hash = [0; 32]; hash.clone_from_slice(&data[132..164]);

            Ok(Entry {
                state: if verified { EntryState::Valid } else { EntryState::Invalid },
                address: key.b58_address,
                index: index,
                txid: txid,
                vout: BigEndian::read_u32(&data[32..36]),
                amount: BigEndian::read_u64(&data[36..44]),
                date: date,
                user: String::from_utf8(data[164..196].to_owned())?,
                blockhash: hash,
                note: String::from_utf8(data[196..256].to_owned())?
            })
        }
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Note that for an unused key we quit immediately. In particular it
        // is important that we not expose the address to the user until they
        // create a signed entry for it, otherwise it defeats the purpose of
        // the audit log
        match self.state {
            EntryState::Unused => return write!(f, "[unused]"),
            EntryState::Invalid => writeln!(f, "**** INVALID SIGNATURE **** :")?,
            EntryState::Valid => writeln!(f, "Signed Entry:")?
        }
        writeln!(f, "   index: {}", self.index)?;
        writeln!(f, " address: {}", self.address)?;
        if self.txid.iter().all(|x| *x == 0) {
            writeln!(f, "    txid: no associated output")?;
        } else {
            writeln!(f, "    txid: {}", self.txid.to_hex())?;
            writeln!(f, "    vout: {}", self.vout)?;
            writeln!(f, "  amount: {}", self.amount)?;
        }
        writeln!(f, " created: {}", str::from_utf8(&self.date[..]).unwrap())?;
        writeln!(f, " (after): {}", self.blockhash.to_hex())?;
        writeln!(f, "    user: {}", self.user)?;
        write!(f, "    note: {}", self.note)?;
        Ok(())
    }
}


// IceBox Written in 2017 by
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

//! # Error Handling

use std::{error, fmt, io, string};
use hid;
use secp256k1;

/// Ice Box error
#[derive(Debug)]
pub enum Error {
    /// Error from hidapi
    Hid(hid::Error),
    /// std io error
    Io(io::Error),
    /// Error from libsecp
    Secp(secp256k1::Error),
    /// Error parsing text
    Utf8(string::FromUtf8Error),
    /// Less than one device was plugged in
    DongleNotFound,
    /// More than one device was plugged in
    DongleNotUnique,
    /// APDU reply had bad status word
    ApduBadStatus(u16),
    /// APDU reply had wrong channel
    ApduWrongChannel,
    /// APDU reply had wrong tag
    ApduWrongTag,
    /// APDU reply had out of order sequence numbers
    ApduWrongSequence,
    /// Received message with invalid length (message, received length)
    ResponseWrongLength(u8, usize),
    /// An wallet cannot produce anymore addresses
    WalletFull,
    /// An encrypted wallet had a bad filesize
    WalletWrongSize(usize),
    /// An encrypted wallet had a bad magic (probably not a wallet)
    WalletWrongMagic(u64),
    /// Attempted to use a user ID that exceeds the field length of the wallet (used, max)
    UserIdTooLong(usize, usize),
    /// Attempted to use a note that exceeds the field length of the wallet (used, max)
    NoteTooLong(usize, usize),
    /// Tried to access entry not in the wallet
    EntryOutOfRange(usize),
    /// Received an unparseable signature
    BadSignature,
    /// The dongle requested we do something unsupported
    Unsupported,
    /// Received APDU frame of shorter than expected length
    UnexpectedEof
}

impl From<hid::Error> for Error {
    fn from(e: hid::Error) -> Error {
        Error::Hid(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Error {
        Error::Utf8(e)
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Hid(ref e) => Some(e),
            Error::Io(ref e) => Some(e),
            Error::Secp(ref e) => Some(e),
            Error::Utf8(ref e) => Some(e),
            _ => None
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Hid(ref e) => error::Error::description(e),
            Error::Io(ref e) => error::Error::description(e),
            Error::Secp(ref e) => error::Error::description(e),
            Error::Utf8(ref e) => error::Error::description(e),
            Error::DongleNotFound => "Ledger device not found",
            Error::DongleNotUnique => "multiple Ledger devices found",
            Error::ApduBadStatus(_) => "bad APDU status word (is device unlocked?)",
            Error::ApduWrongChannel => "wrong APDU channel (is device running the right app?)",
            Error::ApduWrongTag => "wrong APDU tag (is device running the right app?)",
            Error::ApduWrongSequence => "bad APDU sequence no",
            Error::ResponseWrongLength(_,_) => "bad message length",
            Error::WalletFull => "wallet is full, it has no more available addresses",
            Error::WalletWrongSize(_) => "wallet had invalid length",
            Error::WalletWrongMagic(_) => "wallet had wrong magic",
            Error::UserIdTooLong(_, _) => "user ID too long",
            Error::NoteTooLong(_, _) => "note too long",
            Error::EntryOutOfRange(_) => "tried to access entry outside of wallet",
            Error::BadSignature => "unparseable signature",
            Error::Unsupported => "we were asked to do something unsupported",
            Error::UnexpectedEof => "unexpected end of data"
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Hid(ref e) => fmt::Display::fmt(e, f),
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::Secp(ref e) => fmt::Display::fmt(e, f),
            Error::Utf8(ref e) => fmt::Display::fmt(e, f),
            Error::ApduBadStatus(sw) => write!(f, "bad APDU status word {}", sw),
            Error::ResponseWrongLength(msg, len) => write!(f, "bad APDU response length {} for message 0x{:02x}", len, msg),
            Error::WalletWrongSize(len) => write!(f, "bad wallet size {}", len),
            Error::WalletWrongMagic(magic) => write!(f, "bad wallet magic {:08x}", magic),
            Error::UserIdTooLong(used, max) => write!(f, "user ID length {} exceeds max {}", used, max),
            Error::NoteTooLong(used, max) => write!(f, "user ID length {} exceeds max {}", used, max),
            Error::EntryOutOfRange(entry) => write!(f, "entry {} not in wallet", entry),
            _ => f.write_str(error::Error::description(self))
        }
    }
}


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

//! # Error Handling

use std::{error, fmt};
use hid;

/// Ice Box error
#[derive(Debug, Clone)]
pub enum Error {
    /// Error from hidapi
    Hid(hid::Error),
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
    /// Received APDU frame of shorter than expected length
    UnexpectedEof
}

impl From<hid::Error> for Error {
    fn from(e: hid::Error) -> Error {
        Error::Hid(e)
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Hid(ref e) => Some(e),
            _ => None
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Hid(ref e) => error::Error::description(e),
            Error::DongleNotFound => "Ledger device not found",
            Error::DongleNotUnique => "multiple Ledger devices found",
            Error::ApduBadStatus(_) => "bad APDU status word (is device unlocked?)",
            Error::ApduWrongChannel => "wrong APDU channel (is device running the right app?)",
            Error::ApduWrongTag => "wrong APDU tag (is device running the right app?)",
            Error::ApduWrongSequence => "bad APDU sequence no",
            Error::ResponseWrongLength(_,_) => "bad message length",
            Error::UnexpectedEof => "unexpected end of data"
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Hid(ref e) => fmt::Display::fmt(e, f),
            Error::ApduBadStatus(sw) => write!(f, "bad APDU status word {}", sw),
            Error::ResponseWrongLength(msg, len) => write!(f, "bad APDU response length {} for message 0x{:02x}", len, msg),
            _ => f.write_str(error::Error::description(self))
        }
    }
}


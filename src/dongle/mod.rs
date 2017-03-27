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

//! # Dongle
//!
//! Abstract API for communicating with the device
//!

use constants;
use error::Error;
use self::message::{Command, Response};

pub mod ledger;
pub mod message;

/// Trait representing an abstroct hardware wallet
pub trait Dongle {
    /// Sends raw data to the device and returns its response, which is a pair
    /// (status word, raw bytes). Generally this function is never used directly.
    fn exchange(&mut self, data: &[u8]) -> Result<(u16, Vec<u8>), Error>;

    /// Returns the type of the device
    fn product(&self) -> Product;

    /// Queries the device for its firmware version
    fn get_firmware_version(&mut self) -> Result<message::FirmwareVersion, Error> {
        let command = message::GetFirmwareVersion;
        let (sw, rev) = try!(self.exchange(&command.encode()));
        if sw == constants::apdu::ledger::sw::OK {
            message::FirmwareVersion::decode(&rev)
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }
}

/// Enum representing the different devices we support
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Product {
    /// Used in unit tests
    TestJig,
    /// Ledger Nano S
    NanoS
}


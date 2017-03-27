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

//! # Messages
//!
//! Structured versions of various APDU messages
//! These are documented in the [btchip documentation](https://ledgerhq.github.io/btchip-doc/bitcoin-technical-beta.html)
//!

use constants::apdu;
use error::Error;

/// A message that can be received from the dongle
pub trait Response: Sized {
    /// Decode the message from a byte string
    fn decode(data: &[u8]) -> Result<Self, Error>;
}

/// A message that can be sent to the dongle
pub trait Command {
    /// Encode a message as a byte string
    fn encode(&self) -> Vec<u8>;
}

/// GET FIRMWARE VERSION message
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GetFirmwareVersion;

impl Command for GetFirmwareVersion {
    fn encode(&self) -> Vec<u8> {
        vec![apdu::ledger::BTCHIP_CLA, apdu::ledger::ins::GET_FIRMWARE_VERSION, 0, 0, 0]
    }
}

/// Response to the GET FIRMWARE VERSION message
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FirmwareVersion {
    /// Whether or not the device uses compressed keys
    pub compressed: bool,
    /// Whether or not the device has its own user input
    pub has_screen_and_buttons: bool,
    /// Whether or not the device takes user input externally
    pub external_screen_and_buttons: bool,
    /// Whether or not the device supports NFC and payment extensions
    pub nfc_payment_ext: bool,
    /// Whether or not the device supports BLE and low power extensions
    pub ble_low_power_ext: bool,
    /// Whether the implementation is running on a Trusted Execution Environment
    pub tee: bool,
    /// Architecture ("special version")
    pub architecture: u8,
    /// Major version
    pub major_version: u8,
    /// Minor version
    pub minor_version: u8,
    /// Patch version
    pub patch_version: u8,
    /// Loader major version, if applicable
    pub loader_major_version: Option<u8>,
    /// Loader minor version, if applicable
    pub loader_minor_version: Option<u8>
}

impl Response for FirmwareVersion {
    fn decode(data: &[u8]) -> Result<FirmwareVersion, Error> {
        // The full documented version of this message has 7 bytes, but in fact the
        // Nano S and Blue will return 8; the extra byte is to signal something that
        // ultimately never became real, and is just vestigial, according to Nicolas
        // on Slack.
        if data.len() < 5 || data.len() > 8 {
            return Err(Error::ResponseWrongLength(apdu::ledger::ins::GET_FIRMWARE_VERSION, data.len()));
        }

        let loader_major;
        let loader_minor;
        if data.len() >= 7 {
            loader_major = Some(data[5]);
            loader_minor = Some(data[6]);
        } else {
            loader_major = None;
            loader_minor = None;
        }

        Ok(FirmwareVersion {
            compressed: data[0] & 0x01 != 0,
            has_screen_and_buttons: data[0] & 0x02 != 0,
            external_screen_and_buttons: data[0] & 0x04 != 0,
            nfc_payment_ext: data[0] & 0x08 != 0,
            ble_low_power_ext: data[0] & 0x10 != 0,
            tee: data[0] & 0x20 != 0,
            architecture: data[1],
            major_version: data[2],
            minor_version: data[3],
            patch_version: data[4],
            loader_major_version: loader_major,
            loader_minor_version: loader_minor
        })
    }
}


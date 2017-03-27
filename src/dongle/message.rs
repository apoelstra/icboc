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

use secp256k1::{Secp256k1, ContextFlag};
use secp256k1::key::PublicKey;
use byteorder::{WriteBytesExt, BigEndian};

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

/// GET WALLET PUBLIC KEY  message
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GetWalletPublicKey<'a>(pub &'a [u32]);

impl<'a> Command for GetWalletPublicKey<'a> {
    fn encode(&self) -> Vec<u8> {
        assert!(self.0.len() > 0);
        assert!(self.0.len() < 11);  // limitation of the Nano S

        let mut ret = Vec::with_capacity(5 + 4 * self.0.len());
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::GET_WALLET_PUBLIC_KEY);
        ret.push(0);
        ret.push(0);
        ret.push((1 + 4 * self.0.len()) as u8);
        ret.push(self.0.len() as u8);
        for childnum in self.0 {
            let _ = ret.write_u32::<BigEndian>(*childnum);
        }
        ret
    }
}

/// Response to the GET WALLET PUBLIC KEY message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPublicKey {
    /// The EC public key
    pub public_key: PublicKey,
    /// The base58-encoded address corresponding to the public key
    pub b58_address: String,
    /// The BIP32 chaincode associated to this key
    pub chaincode: [u8; 32]
}

impl Response for WalletPublicKey {
    fn decode(data: &[u8]) -> Result<WalletPublicKey, Error> {
        let secp = Secp256k1::with_caps(ContextFlag::None);

        let pk_len = data[0] as usize;
        if 2 + pk_len > data.len() {
            return Err(Error::UnexpectedEof);
        }
        let pk = try!(PublicKey::from_slice(&secp, &data[1..1+pk_len]));

        let addr_len = data[1 + pk_len] as usize;
        if 2 + pk_len + addr_len + 32 != data.len() {
            return Err(Error::ResponseWrongLength(apdu::ledger::ins::GET_WALLET_PUBLIC_KEY, data.len()));
        }
        let addr = try!(String::from_utf8(data[2 + pk_len..2 + pk_len + addr_len].to_owned()));

        let mut ret = WalletPublicKey {
            public_key: pk,
            b58_address: addr,
            chaincode: [0; 32]
        };
        ret.chaincode.clone_from_slice(&data[2 + pk_len + addr_len..]);
        Ok(ret)
    }
}

/// SIGN MESSAGE prepare message
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SignMessagePrepare<'a>(pub &'a [u32], pub &'a [u8]);

impl<'a> Command for SignMessagePrepare<'a> {
    fn encode(&self) -> Vec<u8> {
        assert!(self.0.len() > 0);
        assert!(self.0.len() < 11);  // limitation of the Nano S
        assert!(self.1.len() < 213); // limitation of this sw, lets us fit prepare into a single message

        let mut ret = Vec::with_capacity(5 + 4 * self.0.len());
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::SIGN_MESSAGE);
        ret.push(0x00);  // preparing...
        ret.push(0x01);  // ...the first (and only, for us) part of the message
        ret.push((1 + 4 * self.0.len() + 2 + self.1.len()) as u8);
        ret.push(self.0.len() as u8);
        for childnum in self.0 {
            let _ = ret.write_u32::<BigEndian>(*childnum);
        }
        ret.push(0);
        ret.push(self.1.len() as u8);
        ret.extend(self.1);
        ret
    }
}

/// SIGN MESSAGE sign message
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SignMessageSign;

impl Command for SignMessageSign {
    fn encode(&self) -> Vec<u8> {
        vec![
            apdu::ledger::BTCHIP_CLA,
            apdu::ledger::ins::SIGN_MESSAGE,
            0x80, // signing
            0x00, // irrelevant
            0x01, // no user authentication needed
            0x00
        ]
    }
}

/// GET RANDOM message
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GetRandom(pub u8);

impl Command for GetRandom {
    fn encode(&self) -> Vec<u8> {
        vec![
            apdu::ledger::BTCHIP_CLA,
            apdu::ledger::ins::GET_RANDOM,
            0x00, 0x00, self.0
        ]
    }
}






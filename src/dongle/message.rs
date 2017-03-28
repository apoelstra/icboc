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
use std::cmp;

use constants::apdu;
use error::Error;

/// A message that can be received from the dongle
pub trait Response: Sized {
    /// Decode the message from a byte string
    fn decode(data: &[u8]) -> Result<Self, Error>;
}

/// A message that can be sent to the dongle
pub trait Command {
    /// Encodes the next APDU as a byte string, or None if there are no remaining
    /// APDUs to send
    fn encode_next(&mut self) -> Option<Vec<u8>>;

    /// Used to update a (potentially multipart) reply
    fn decode_reply(&mut self, data: Vec<u8>) -> Result<(), Error>;

    /// Pull the command apart into a full assembled reply and status word
    fn into_reply(self) -> (u16, Vec<u8>);
}

/// GET FIRMWARE VERSION message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFirmwareVersion {
    sent: bool,
    reply: Vec<u8>,
    sw: u16
}

impl GetFirmwareVersion {
    /// Constructor
    pub fn new() -> GetFirmwareVersion {
        GetFirmwareVersion {
            sent: false,
            reply: vec![],
            sw: 0
        }
    }
}

impl Command for GetFirmwareVersion {
    fn encode_next(&mut self) -> Option<Vec<u8>> {
        if self.sent {
            None
        } else {
            self.sent = true;
            Some(vec![apdu::ledger::BTCHIP_CLA, apdu::ledger::ins::GET_FIRMWARE_VERSION, 0, 0, 0])
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        if data.len() < 2 {
            return Err(Error::UnexpectedEof);
        }
        let sw2 = data.pop().unwrap();
        let sw1 = data.pop().unwrap();
        self.reply = data;
        self.sw = ((sw1 as u16) << 8) + sw2 as u16;
        Ok(())
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}

/// Response to the GET FIRMWARE VERSION message
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetWalletPublicKey<'a> {
    sent: bool,
    reply: Vec<u8>,
    sw: u16,
    bip32_path: &'a [u32],
}

impl<'a> GetWalletPublicKey<'a> {
    /// Constructor
    pub fn new(bip32_path: &'a [u32]) -> GetWalletPublicKey {
        assert!(bip32_path.len() < 11);  // limitation of the Nano S

        GetWalletPublicKey {
            sent: false,
            reply: vec![],
            sw: 0,
            bip32_path: bip32_path
        }
    }
}

impl<'a> Command for GetWalletPublicKey<'a> {
    fn encode_next(&mut self) -> Option<Vec<u8>> {
        if self.sent {
            return None;
        }
        self.sent = true;

        let mut ret = Vec::with_capacity(5 + 4 * self.bip32_path.len());
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::GET_WALLET_PUBLIC_KEY);
        ret.push(0);
        ret.push(0);
        ret.push((1 + 4 * self.bip32_path.len()) as u8);
        ret.push(self.bip32_path.len() as u8);
        for childnum in self.bip32_path {
            let _ = ret.write_u32::<BigEndian>(*childnum);
        }
        Some(ret)
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        if data.len() < 2 {
            return Err(Error::UnexpectedEof);
        }
        let sw2 = data.pop().unwrap();
        let sw1 = data.pop().unwrap();
        self.reply = data;
        self.sw = ((sw1 as u16) << 8) + sw2 as u16;
        Ok(())
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessagePrepare<'a> {
    sent_length: usize,
    reply: Vec<u8>,
    sw: u16,
    bip32_path: &'a [u32],
    message: &'a [u8]
}

impl<'a> SignMessagePrepare<'a> {
    /// Constructor
    pub fn new(bip32_path: &'a [u32], message: &'a [u8]) -> SignMessagePrepare<'a> {
        assert!(bip32_path.len() < 11);   // limitation of the Nano S
        assert!(message.len() < 0x10000); // limitation of the Nano S

        SignMessagePrepare {
            sent_length: 0,
            reply: vec![],
            sw: 0,
            bip32_path: bip32_path,
            message: message
        }
    }
}

impl<'a> Command for SignMessagePrepare<'a> {
    fn encode_next(&mut self) -> Option<Vec<u8>> {
        if self.sent_length > self.message.len() {
            unreachable!();  // sanity check
        }
        if self.sent_length == self.message.len() {
            return None;
        }

        // First message
        if self.sent_length == 0 {
            let (packet_len, message_len) = {
                let header_len = 5;
                let init_data_len = 1 + 4 * self.bip32_path.len() + 2;
                let space = apdu::ledger::PACKET_SIZE - init_data_len - header_len;
                let message_len = cmp::min(space, self.message.len());
                (init_data_len + message_len, message_len)
            };
            let mut ret = Vec::with_capacity(5 + packet_len);
            ret.push(apdu::ledger::BTCHIP_CLA);
            ret.push(apdu::ledger::ins::SIGN_MESSAGE);
            ret.push(0x00);  // preparing...
            ret.push(0x01);  // ...the first part of the message
            ret.push(packet_len as u8);
            ret.push(self.bip32_path.len() as u8);
            for childnum in self.bip32_path {
                let _ = ret.write_u32::<BigEndian>(*childnum);
            }
            let _ = ret.write_u16::<BigEndian>(self.message.len() as u16);
            ret.extend(&self.message[0..message_len]);
            self.sent_length += message_len;
            Some(ret)
        // Subsequent messages, much simpler
        } else {
            let remaining_len = self.message.len() - self.sent_length;
            let packet_len = cmp::min(apdu::ledger::PACKET_SIZE - 5, remaining_len);

            let mut ret = Vec::with_capacity(5 + packet_len);
            ret.push(apdu::ledger::BTCHIP_CLA);
            ret.push(apdu::ledger::ins::SIGN_MESSAGE);
            ret.push(0x00);  // preparing...
            ret.push(0x80);  // ...the next part of the message
            ret.push(packet_len as u8);
            ret.extend(&self.message[self.sent_length..self.sent_length + packet_len]);
            self.sent_length += packet_len;
            Some(ret)
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        if data.len() < 2 {
            return Err(Error::UnexpectedEof);
        }
        let sw2 = data.pop().unwrap();
        let sw1 = data.pop().unwrap();
        if data.len() > 2 {
            return Err(Error::Unsupported);
        }
        self.reply = data;
        self.sw = ((sw1 as u16) << 8) + sw2 as u16;
        if self.sw != apdu::ledger::sw::OK {
            Err(Error::ApduBadStatus(self.sw))
        } else {
            Ok(())
        }
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}

/// SIGN MESSAGE sign message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessageSign {
    sent: bool,
    reply: Vec<u8>,
    sw: u16
}

impl SignMessageSign {
    /// Constructor
    pub fn new() -> SignMessageSign {
        SignMessageSign {
            sent: false,
            reply: vec![],
            sw: 0
        }
    }
}

impl Command for SignMessageSign {
    fn encode_next(&mut self) -> Option<Vec<u8>> {
        if self.sent {
            None
        } else {
            self.sent = true;
            Some(vec![
                apdu::ledger::BTCHIP_CLA,
                apdu::ledger::ins::SIGN_MESSAGE,
                0x80, // signing
                0x00, // irrelevant
                0x01, // no user authentication needed
                0x00
            ])
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        if data.len() < 2 {
            return Err(Error::UnexpectedEof);
        }
        let sw2 = data.pop().unwrap();
        let sw1 = data.pop().unwrap();
        self.reply = data;
        self.sw = ((sw1 as u16) << 8) + sw2 as u16;
        Ok(())
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}

/// GET RANDOM message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRandom {
    sent: bool,
    reply: Vec<u8>,
    sw: u16,
    count: u8
}

impl GetRandom {
    /// Constructor
    pub fn new(count: u8) -> GetRandom {
        GetRandom {
            sent: false,
            reply: vec![],
            sw: 0,
            count: count
        }
    }
}

impl Command for GetRandom {
    fn encode_next(&mut self) -> Option<Vec<u8>> {
        if self.sent {
            None
        } else {
            self.sent = true;
            Some(vec![
                apdu::ledger::BTCHIP_CLA,
                apdu::ledger::ins::GET_RANDOM,
                0x00, 0x00, self.count
            ])
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        if data.len() < 2 {
            return Err(Error::UnexpectedEof);
        }
        let sw2 = data.pop().unwrap();
        let sw1 = data.pop().unwrap();
        self.reply = data;
        self.sw = ((sw1 as u16) << 8) + sw2 as u16;
        Ok(())
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}






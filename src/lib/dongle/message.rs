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

//! # Messages
//!
//! Structured versions of various APDU messages
//! These are documented in the [btchip documentation](https://ledgerhq.github.io/btchip-doc/bitcoin-technical-beta.html)
//!

use core::cmp;
use core::convert::{TryFrom as _, TryInto as _};

use miniscript::bitcoin;
use miniscript::bitcoin::bip32;

use crate::constants::apdu::ledger::{self, Instruction};
use crate::wallet;
use crate::Error;

/// A message that can be received from the dongle
pub trait Response: Sized {
    /// Decode the message from a byte string
    fn decode(data: &[u8]) -> Result<Self, Error>;
}

/// A message that can be sent to the dongle
pub trait Command {
    /// Encodes the next APDU as a byte string, or None if there are no remaining
    /// APDUs to send
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>>;

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
    sw: u16,
}

impl GetFirmwareVersion {
    /// Constructor
    pub fn new() -> Self {
        GetFirmwareVersion {
            sent: false,
            reply: vec![],
            sw: 0,
        }
    }
}

impl Command for GetFirmwareVersion {
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent {
            None
        } else {
            self.sent = true;
            Some(vec![
                ledger::BTCHIP_CLA,
                Instruction::GetFirmwareVersion.into_u8(),
                0,
                0,
                0,
            ])
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        match (data.pop(), data.pop()) {
            (Some(sw2), Some(sw1)) => {
                self.reply = data;
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
        }
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}

/// Response to the GET FIRMWARE VERSION message
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
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
    pub loader_minor_version: Option<u8>,
}

impl Response for FirmwareVersion {
    fn decode(data: &[u8]) -> Result<FirmwareVersion, Error> {
        // The full documented version of this message has 7 bytes, but in fact the
        // Nano S and Blue will return 8; the extra byte is to signal something that
        // ultimately never became real, and is just vestigial, according to Nicolas
        // on Slack.
        if data.len() < 5 || data.len() > 8 {
            return Err(Error::ResponseWrongLength {
                apdu: Instruction::GetFirmwareVersion,
                expected: 5..9,
                found: data.len(),
            });
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
            loader_minor_version: loader_minor,
        })
    }
}

/// GET WALLET PUBLIC KEY  message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetWalletPublicKey<'a> {
    sent: bool,
    reply: Vec<u8>,
    sw: u16,
    bip32_path: &'a [bip32::ChildNumber],
    display: bool,
}

impl<'a> GetWalletPublicKey<'a> {
    /// Constructor
    pub fn new<P: AsRef<[bip32::ChildNumber]>>(bip32_path: &'a P, display: bool) -> Self {
        assert!(bip32_path.as_ref().len() < 11); // limitation of the Nano S

        GetWalletPublicKey {
            sent: false,
            reply: vec![],
            sw: 0,
            bip32_path: bip32_path.as_ref(),
            display,
        }
    }
}

impl Command for GetWalletPublicKey<'_> {
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent {
            return None;
        }
        self.sent = true;

        let mut ret = Vec::with_capacity(5 + 4 * self.bip32_path.len());
        ret.push(ledger::BTCHIP_CLA);
        ret.push(Instruction::GetWalletPublicKey.into_u8());
        ret.push(self.display.into());
        ret.push(0);
        ret.push((1 + 4 * self.bip32_path.len()) as u8);
        ret.push(self.bip32_path.len() as u8);
        for &childnum in self.bip32_path {
            ret.extend(u32::from(childnum).to_be_bytes());
        }
        Some(ret)
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        match (data.pop(), data.pop()) {
            (Some(sw2), Some(sw1)) => {
                self.reply = data;
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
        }
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}

/// Response to the GET WALLET PUBLIC KEY message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPublicKey {
    /// The EC public key
    pub public_key: bitcoin::secp256k1::PublicKey,
    /// The base58-encoded address corresponding to the public key
    pub b58_address: String,
    /// The BIP32 chain code associated to this key
    pub chain_code: bip32::ChainCode,
}

impl Response for WalletPublicKey {
    #[allow(clippy::range_plus_one)] // false positive on 1..1 + pk_len
    fn decode(data: &[u8]) -> Result<WalletPublicKey, Error> {
        let pk_len = data[0] as usize;
        if 2 + pk_len > data.len() {
            return Err(Error::UnexpectedEof);
        }
        // The ledger will return an uncompressed public key, but actually
        // derives addresses using compressed keys. This is fine; we just
        // parse as a secp pubkey, and rust-bitcoin will do the right thing
        // (since it understands the bip32 spec as just using "keys" and
        // always encoding them compressedly).
        let pk = bitcoin::secp256k1::PublicKey::from_slice(&data[1..1 + pk_len])?;

        let addr_len = data[1 + pk_len] as usize;
        let expected_len = 2 + pk_len + addr_len + 32;
        if expected_len != data.len() {
            return Err(Error::ResponseWrongLength {
                apdu: Instruction::GetWalletPublicKey,
                expected: expected_len..expected_len,
                found: data.len(),
            });
        }
        let addr = String::from_utf8(data[2 + pk_len..2 + pk_len + addr_len].to_owned())?;
        let cc_bytes: [u8; 32] = match data[2 + pk_len + addr_len..].try_into() {
            Ok(cc) => cc,
            Err(_) => return Err(Error::UnexpectedEof),
        };

        Ok(WalletPublicKey {
            public_key: pk,
            b58_address: addr,
            chain_code: bip32::ChainCode::from(cc_bytes),
        })
    }
}

/// SIGN MESSAGE prepare message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessagePrepare<'path, 'msg> {
    sent_length: usize,
    reply: Vec<u8>,
    sw: u16,
    bip32_path: &'path [bip32::ChildNumber],
    message: &'msg [u8],
}

impl<'path, 'msg> SignMessagePrepare<'path, 'msg> {
    /// Constructor
    pub fn new<P: AsRef<[bip32::ChildNumber]>>(bip32_path: &'path P, message: &'msg [u8]) -> Self {
        assert!(bip32_path.as_ref().len() < 11); // limitation of the Nano S
        assert!(message.len() < 0x10000); // limitation of the Nano S

        SignMessagePrepare {
            sent_length: 0,
            reply: vec![],
            sw: 0,
            bip32_path: bip32_path.as_ref(),
            message,
        }
    }
}

impl Command for SignMessagePrepare<'_, '_> {
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent_length > self.message.len() {
            unreachable!(); // sanity check
        }
        if self.sent_length == self.message.len() {
            return None;
        }

        // First message
        if self.sent_length == 0 {
            let (packet_len, message_len) = {
                let header_len = 5;
                let init_data_len = 1 + 4 * self.bip32_path.len() + 2;
                let space = apdu_size - init_data_len - header_len;
                let message_len = cmp::min(space, self.message.len());
                (init_data_len + message_len, message_len)
            };
            let mut ret = Vec::with_capacity(5 + packet_len);
            ret.push(ledger::BTCHIP_CLA);
            ret.push(Instruction::SignMessage.into_u8());
            ret.push(0x00); // preparing...
            ret.push(0x01); // ...the first part of the message
            ret.push(packet_len as u8);
            ret.push(self.bip32_path.len() as u8);
            for &childnum in self.bip32_path {
                ret.extend(u32::from(childnum).to_be_bytes());
            }
            ret.extend(
                u16::try_from(self.message.len())
                    .expect("message len < 2^16")
                    .to_be_bytes(),
            );
            ret.extend(&self.message[0..message_len]);
            self.sent_length += message_len;
            Some(ret)
        // Subsequent messages, much simpler
        } else {
            let remaining_len = self.message.len() - self.sent_length;
            let packet_len = cmp::min(apdu_size - 5, remaining_len);

            let mut ret = Vec::with_capacity(5 + packet_len);
            ret.push(ledger::BTCHIP_CLA);
            ret.push(Instruction::SignMessage.into_u8());
            ret.push(0x00); // preparing...
            ret.push(0x80); // ...the next part of the message
            ret.push(packet_len as u8);
            ret.extend(&self.message[self.sent_length..self.sent_length + packet_len]);
            self.sent_length += packet_len;
            Some(ret)
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        match (data.pop(), data.pop()) {
            (Some(sw2), Some(sw1)) => {
                self.reply = data;
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
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
    sw: u16,
}

impl SignMessageSign {
    /// Constructor
    pub fn new() -> SignMessageSign {
        SignMessageSign {
            sent: false,
            reply: vec![],
            sw: 0,
        }
    }
}

impl Command for SignMessageSign {
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent {
            None
        } else {
            self.sent = true;
            Some(vec![
                ledger::BTCHIP_CLA,
                Instruction::SignMessage.into_u8(),
                0x80, // signing
                0x00, // irrelevant
                0x01, // no user authentication needed
                0x00,
            ])
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        match (data.pop(), data.pop()) {
            (Some(sw2), Some(sw1)) => {
                self.reply = data;
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
        }
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
    count: u8,
}

impl GetRandom {
    /// Constructor
    pub fn new(count: u8) -> GetRandom {
        GetRandom {
            sent: false,
            reply: vec![],
            sw: 0,
            count,
        }
    }
}

impl Command for GetRandom {
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent {
            None
        } else {
            self.sent = true;
            Some(vec![
                ledger::BTCHIP_CLA,
                Instruction::GetRandom.into_u8(),
                0,
                0,
                self.count,
            ])
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        match (data.pop(), data.pop()) {
            (Some(sw2), Some(sw1)) => {
                self.reply = data;
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
        }
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}

/// GET TRUSTED INPUT message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetTrustedInput {
    reply: Vec<u8>,
    sw: u16,
    ser_tx: Vec<Vec<u8>>,
    // On the first call to `encode_next` we send the vout index. We
    // use an Option to keep track of whether we've already done this.
    vout: Option<u32>,
}

impl GetTrustedInput {
    /// Constructor
    pub fn new(tx: &bitcoin::Transaction, vout: u32) -> GetTrustedInput {
        let mut ser_tx = super::tx::encode_tx(tx, ledger::MAX_APDU_SIZE - 9);
        ser_tx.reverse(); // Reverse the order of the cuts so we can send them by popping
        GetTrustedInput {
            reply: vec![],
            sw: 0,
            ser_tx,
            vout: Some(vout),
        }
    }
}

impl Command for GetTrustedInput {
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>> {
        // If `self.ser_tx` is empty we are done sending entire transaction
        let tx = self.ser_tx.pop()?;

        let mut ret = Vec::with_capacity(apdu_size);
        ret.push(ledger::BTCHIP_CLA);
        ret.push(Instruction::GetTrustedInput.into_u8());
        ret.push(if self.vout.is_some() { 0x00 } else { 0x80 });
        ret.push(0x00);
        ret.push(0x00); // Will overwrite this with final length
        if let Some(vout) = self.vout.take() {
            ret.extend(vout.to_be_bytes());
        }
        ret.extend(tx);

        // Mark size and return
        assert!(ret.len() < apdu_size);
        ret[4] = (ret.len() - 5) as u8;
        Some(ret)
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        // Note that only the last reply is nonempty for this one
        match (data.pop(), data.pop()) {
            (Some(sw2), Some(sw1)) => {
                self.reply = data;
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
        }
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}

/// UNTRUSTED HASH TRANSACTION INPUT START message
pub struct UntrustedHashTransactionInputStart {
    ser_inputs: Vec<Vec<u8>>,
    sent_first: bool,
    first_input: bool,
    sw: u16,
}

impl UntrustedHashTransactionInputStart {
    /// Constructor: `spend` is a prepared `Spend` object describing what to do,
    /// `index` is the input that we're signing for now. `continuing` should
    /// be set if there are multiple inputs to be signed and this is not the
    /// first
    pub fn new(
        tx: &bitcoin::Transaction,
        index: usize,
        trusted_inputs: &[super::TrustedInput],
        first_input: bool,
    ) -> UntrustedHashTransactionInputStart {
        let mut ser_inputs =
            super::tx::encode_input(tx, index, trusted_inputs, ledger::MAX_APDU_SIZE);
        ser_inputs.reverse(); // Reverse the order of the cuts so we can send them by popping
        UntrustedHashTransactionInputStart {
            ser_inputs,
            sent_first: false,
            first_input,
            sw: 0,
        }
    }
}

impl Command for UntrustedHashTransactionInputStart {
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>> {
        // If `self.ser_inputs` is empty we are done sending entire transaction
        let input = self.ser_inputs.pop()?;

        let mut ret = Vec::with_capacity(apdu_size);
        ret.push(ledger::BTCHIP_CLA);
        ret.push(Instruction::UntrustedHashTransactionInputStart.into_u8());
        ret.push(if self.sent_first { 0x80 } else { 0x00 });
        ret.push(if self.first_input { 0x00 } else { 0x80 });
        ret.push(0x00); // Will overwrite this with final length
        ret.extend(input);

        self.sent_first = true;

        // Mark size and return
        assert!(ret.len() < apdu_size);
        ret[4] = (ret.len() - 5) as u8;
        Some(ret)
    }

    fn decode_reply(&mut self, data: Vec<u8>) -> Result<(), Error> {
        // In this case the reply length should be exactly 2 (0-length message, status word)
        match data[..] {
            [] | [_] => Err(Error::UnexpectedEof),
            [sw1, sw2] => {
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::Unsupported),
        }
    }

    // no reply to this message
    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, vec![])
    }
}

/// UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL message
pub struct UntrustedHashTransactionInputFinalize {
    ser_outputs: Vec<Vec<u8>>,
    change_path: Option<bip32::DerivationPath>,
    sw: u16,
}

impl UntrustedHashTransactionInputFinalize {
    /// Constructor
    pub fn new(
        tx: &bitcoin::Transaction,
        change_address: Option<&wallet::Address>,
    ) -> UntrustedHashTransactionInputFinalize {
        let mut ser_outputs = super::tx::encode_outputs(tx, ledger::MAX_APDU_SIZE);
        ser_outputs.reverse(); // Reverse the order of the cuts so we can send them by popping
        UntrustedHashTransactionInputFinalize {
            ser_outputs,
            change_path: change_address.and_then(wallet::Address::change_path),
            sw: 0,
        }
    }
}

impl Command for UntrustedHashTransactionInputFinalize {
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>> {
        // If `self.ser_outputs` is empty we are done sending entire transaction
        let output = self.ser_outputs.pop()?;

        let mut ret = Vec::with_capacity(apdu_size);
        ret.push(ledger::BTCHIP_CLA);
        ret.push(Instruction::UntrustedHashTransactionInputFinalize.into_u8());

        if let Some(path) = self.change_path.take() {
            let cnums: &[bip32::ChildNumber] = path.as_ref();

            ret.push(0xff);
            ret.push(0x00);
            ret.push((1 + 4 * cnums.len()) as u8);
            ret.push(cnums.len() as u8);
            for &childnum in cnums {
                ret.extend(u32::from(childnum).to_be_bytes());
            }
            Some(ret)
        } else {
            ret.push(0x00); // Will overwrite this with 0x80 on final message
            ret.push(0x00);
            ret.push(0x00); // Will overwrite this with length
            ret.extend(output);

            if self.ser_outputs.is_empty() {
                ret[2] = 0x80;
            }
            assert!(ret.len() < apdu_size);
            ret[4] = (ret.len() - 5) as u8;
            Some(ret)
        }
    }

    fn decode_reply(&mut self, data: Vec<u8>) -> Result<(), Error> {
        // On the Nano S we only ever receive some variable number of zeros, at most
        // 2 of them, so check the length as a simple sanity check
        match data[..] {
            [] | [_] => Err(Error::UnexpectedEof),
            [0, 0, sw1, sw2] | [0, sw1, sw2] | [sw1, sw2] => {
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::Unsupported),
        }
    }

    // no reply to this message
    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, vec![])
    }
}

/// UNTRUSTED HASH SIGN  message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedHashSign<'a> {
    sent: bool,
    reply: Vec<u8>,
    sw: u16,
    bip32_path: &'a [bip32::ChildNumber],
    sighash: bitcoin::sighash::EcdsaSighashType,
    tx_locktime: u32,
}

impl<'a> UntrustedHashSign<'a> {
    /// Constructor
    pub fn new<P: AsRef<[bip32::ChildNumber]>>(
        bip32_path: &'a P,
        sighash: bitcoin::sighash::EcdsaSighashType,
        tx_locktime: u32,
    ) -> Self {
        UntrustedHashSign {
            sent: false,
            reply: vec![],
            sw: 0,
            bip32_path: bip32_path.as_ref(),
            sighash,
            tx_locktime,
        }
    }
}

impl Command for UntrustedHashSign<'_> {
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent {
            return None;
        }
        self.sent = true;

        let mut ret = Vec::with_capacity(5 + 4 * self.bip32_path.len());
        ret.push(ledger::BTCHIP_CLA);
        ret.push(Instruction::UntrustedHashSign.into_u8());
        ret.push(0x00);
        ret.push(0x00);
        ret.push((1 + 4 * self.bip32_path.len() + 6) as u8);
        ret.push(self.bip32_path.len() as u8);
        for &childnum in self.bip32_path {
            ret.extend(u32::from(childnum).to_be_bytes());
        }
        ret.push(0x00); // user validation code
        ret.extend(self.tx_locktime.to_be_bytes());
        ret.push(self.sighash.to_u32() as u8);
        Some(ret)
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        match (data.pop(), data.pop()) {
            (Some(sw2), Some(sw1)) => {
                self.reply = data;
                self.sw = u16::from_be_bytes([sw1, sw2]);
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
        }
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, self.reply)
    }
}

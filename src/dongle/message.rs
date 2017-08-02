// ICBOC
// Written in 2017 by
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

use bitcoin::blockdata::transaction::{Transaction, SigHashType};
use bitcoin::network::constants::Network;
use byteorder::{WriteBytesExt, BigEndian};
use secp256k1::{Secp256k1, ContextFlag};
use secp256k1::key::PublicKey;
use std::cmp;

use constants::apdu;
use error::Error;
use spend;
use util::{encode_transaction_with_cutpoints, encode_spend_outputs_with_cutpoints, encode_spend_inputs_with_cutpoints_segwit_input, encode_spend_inputs_with_cutpoints_segwit_init};

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
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
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
    display: bool
}

impl<'a> GetWalletPublicKey<'a> {
    /// Constructor
    pub fn new(bip32_path: &'a [u32], display: bool) -> GetWalletPublicKey {
        assert!(bip32_path.len() < 11);  // limitation of the Nano S

        GetWalletPublicKey {
            sent: false,
            reply: vec![],
            sw: 0,
            bip32_path: bip32_path,
            display: display
        }
    }
}

impl<'a> Command for GetWalletPublicKey<'a> {
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent {
            return None;
        }
        self.sent = true;

        let mut ret = Vec::with_capacity(5 + 4 * self.bip32_path.len());
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::GET_WALLET_PUBLIC_KEY);
        ret.push(if self.display {1} else {0});
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
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>> {
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
                let space = apdu_size - init_data_len - header_len;
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
            let packet_len = cmp::min(apdu_size - 5, remaining_len);

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
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
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
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
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


/// GET RANDOM message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetTrustedInput {
    sent_cuts: usize,
    reply: Vec<u8>,
    sw: u16,
    ser_tx: Vec<u8>,
    cuts: Vec<usize>,
    vout: u32
}

impl GetTrustedInput {
    /// Constructor: ser_tx is the full transaction, vout is the index of the output we care about
    pub fn new(tx: &Transaction, vout: u32, apdu_size: usize) -> GetTrustedInput {
        let (ser_tx, cuts) = encode_transaction_with_cutpoints(tx, apdu_size - 9);
        GetTrustedInput {
            sent_cuts: 0,
            reply: vec![],
            sw: 0,
            ser_tx: ser_tx,
            cuts: cuts,
            vout: vout
        }
    }
}

impl Command for GetTrustedInput {
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent_cuts >= self.cuts.len() {
            unreachable!();  // sanity check
        }
        // We are always looking one cut ahead (and have an extra
        // "cut" at self.ser_tx.len() for this reason).
        if self.sent_cuts == self.cuts.len() - 1 {
            return None;
        }

        let mut ret = Vec::with_capacity(apdu_size);
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::GET_TRUSTED_INPUT);
        if self.sent_cuts == 0 {
            ret.push(0x00);
            ret.push(0x00);
            ret.push(0x00);  // Will overwrite this with final length
            let _ = ret.write_u32::<BigEndian>(self.vout);
        } else {
            ret.push(0x80);
            ret.push(0x00);
            ret.push(0x00);  // Will overwrite this with final length
        }

        // Put as many transaction cuts as we can into the message
        let mut next_cut_len = self.cuts[self.sent_cuts + 1] - self.cuts[self.sent_cuts];
        while ret.len() + next_cut_len < apdu_size {
            ret.extend(&self.ser_tx[self.cuts[self.sent_cuts]..self.cuts[self.sent_cuts + 1]]);
            self.sent_cuts += 1;
            if self.sent_cuts < self.cuts.len() - 1 {
                next_cut_len = self.cuts[self.sent_cuts + 1] - self.cuts[self.sent_cuts];
            } else {
                break;
            }
        }

        // Mark size and return
        assert!(ret.len() < apdu_size);
        ret[4] = (ret.len() - 5) as u8;
        Some(ret)
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        // Note that only the last reply is nonempty for this one
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

/// UNTRUSTED HASH TRANSACTION INPUT START message
pub struct UntrustedHashTransactionInputStart {
    continuing: bool,
    ser_inputs: Vec<u8>,
    cuts: Vec<usize>,
    sent_cuts: usize,
    sw: u16
}

impl UntrustedHashTransactionInputStart {
    /// Constructor: `spend` is a prepared `Spend` object describing what to do,
    /// `index` is the input that we're signing for now. `continuing` should
    /// be set if there are multiple inputs to be signed and this is not the
    /// first
    pub fn new(spend: &spend::Spend, index: usize, continuing: bool, apdu_size: usize) -> UntrustedHashTransactionInputStart {
        let (ser_inputs, cuts) = if continuing {
            encode_spend_inputs_with_cutpoints_segwit_input(spend, index, apdu_size)
        } else {
            encode_spend_inputs_with_cutpoints_segwit_init(spend, apdu_size)
        };
        UntrustedHashTransactionInputStart {
            continuing: continuing,
            ser_inputs: ser_inputs,
            cuts: cuts,
            sent_cuts: 0,
            sw: 0
        }
    }
}

impl Command for UntrustedHashTransactionInputStart {
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>> {
        let mut ret = Vec::with_capacity(apdu_size);
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::UNTRUSTED_HASH_TRANSACTION_INPUT_START);
        ret.push(if self.sent_cuts != 0 { 0x80 } else { 0x00 });
        ret.push(if self.continuing { 0x80 } else { 0x02 });
        ret.push(0x00);  // Will overwrite this with final length

        // Rest same as for `GetTrustedInput`
        if self.sent_cuts >= self.cuts.len() {
            unreachable!();  // sanity check
        }
        // We are always looking one cut ahead (and have an extra
        // "cut" at self.ser_tx.len() for this reason).
        if self.sent_cuts == self.cuts.len() - 1 {
            return None;
        }

        let mut next_cut_len = self.cuts[self.sent_cuts + 1] - self.cuts[self.sent_cuts];
        while ret.len() + next_cut_len < apdu_size {
            ret.extend(&self.ser_inputs[self.cuts[self.sent_cuts]..self.cuts[self.sent_cuts + 1]]);
            self.sent_cuts += 1;
            if self.sent_cuts < self.cuts.len() - 1 {
                next_cut_len = self.cuts[self.sent_cuts + 1] - self.cuts[self.sent_cuts];
            } else {
                break;
            }
        }

        // Mark size and return
        assert!(ret.len() < apdu_size);
        ret[4] = (ret.len() - 5) as u8;
        Some(ret)
    }

    fn decode_reply(&mut self, data: Vec<u8>) -> Result<(), Error> {
        if data.len() != 2 {
            return Err(Error::Unsupported);
        }
        self.sw = ((data[0] as u16) << 8) + data[1] as u16;
        Ok(())
    }

    // no reply to this message
    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, vec![])
    }
}

/// UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL message
pub struct UntrustedHashTransactionInputFinalize {
    need_to_send_change_path: bool,
    change_path: [u32; 5],
    ser_outputs: Vec<u8>,
    cuts: Vec<usize>,
    sent_cuts: usize,
    sw: u16
}

impl UntrustedHashTransactionInputFinalize {
    /// Constructor: `spend` is a prepared `Spend` object describing what to do.
    pub fn new(spend: &spend::Spend, apdu_size: usize) -> UntrustedHashTransactionInputFinalize {
        let (ser_outputs, cuts) = encode_spend_outputs_with_cutpoints(spend, apdu_size);
        UntrustedHashTransactionInputFinalize {
            need_to_send_change_path: spend.change_amount > 0,
            change_path: spend.change_path,
            ser_outputs: ser_outputs,
            cuts: cuts,
            sent_cuts: 0,
            sw: 0
        }
    }
}

impl Command for UntrustedHashTransactionInputFinalize {
    fn encode_next(&mut self, apdu_size: usize) -> Option<Vec<u8>> {
        let mut ret = Vec::with_capacity(apdu_size);
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE);

        if self.need_to_send_change_path {
            self.need_to_send_change_path = false;
            ret.push(0xff);
            ret.push(0x00);
            ret.push((1 + 4 * self.change_path.len()) as u8);
            ret.push(self.change_path.len() as u8);
            for childnum in &self.change_path[..] {
                let _ = ret.write_u32::<BigEndian>(*childnum);
            }
            Some(ret)
        } else {
            ret.push(0x00);  // Will overwrite this with 0x80 on final message
            ret.push(0x00);
            ret.push(0x00);  // Will overwrite this with length

            // Rest same as for `GetTrustedInput`
            if self.sent_cuts >= self.cuts.len() {
                unreachable!();  // sanity check
            }
            // We are always looking one cut ahead (and have an extra
            // "cut" at self.ser_tx.len() for this reason).
            if self.sent_cuts == self.cuts.len() - 1 {
                return None;
            }

            let mut next_cut_len = self.cuts[self.sent_cuts + 1] - self.cuts[self.sent_cuts];
            while ret.len() + next_cut_len < apdu_size {
                ret.extend(&self.ser_outputs[self.cuts[self.sent_cuts]..self.cuts[self.sent_cuts + 1]]);
                self.sent_cuts += 1;
                if self.sent_cuts < self.cuts.len() - 1 {
                    next_cut_len = self.cuts[self.sent_cuts + 1] - self.cuts[self.sent_cuts];
                } else {
                    break;
                }
            }

            // Mark size and return
            if self.sent_cuts == self.cuts.len() - 1 {
                ret[2] = 0x80;
            }
            assert!(ret.len() < apdu_size);
            ret[4] = (ret.len() - 5) as u8;
            Some(ret)
        }
    }

    fn decode_reply(&mut self, mut data: Vec<u8>) -> Result<(), Error> {
        // On the Nano S we only ever receive some variable number of zeros, at most
        // 2 of them, so check the length as a simple sanity check
        if data.len() > 4 || data.len() < 2 {
            return Err(Error::Unsupported);
        }
        let sw2 = data.pop().unwrap();
        let sw1 = data.pop().unwrap();
        self.sw = ((sw1 as u16) << 8) + sw2 as u16;
        Ok(())
    }

    // no reply to this message
    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, vec![])
    }
}

/// UNTRUSTED HASH SIGN  message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedHashSign {
    sent: bool,
    reply: Vec<u8>,
    sw: u16,
    bip32_path: [u32; 5],
    sighash: SigHashType,
    locktime: u32
}

impl UntrustedHashSign {
    /// Constructor
    pub fn new(bip32_path: [u32; 5], sighash: SigHashType, locktime: u32) -> UntrustedHashSign {
        assert!(bip32_path.len() < 11);  // limitation of the Nano S

        UntrustedHashSign {
            sent: false,
            reply: vec![],
            sw: 0,
            bip32_path: bip32_path,
            sighash: sighash,
            locktime: locktime
        }
    }
}

impl Command for UntrustedHashSign {
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent {
            return None;
        }
        self.sent = true;

        let mut ret = Vec::with_capacity(5 + 4 * self.bip32_path.len());
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::UNTRUSTED_HASH_SIGN);
        ret.push(0x00);
        ret.push(0x00);
        ret.push((1 + 4 * self.bip32_path.len() + 6) as u8);
        ret.push(self.bip32_path.len() as u8);
        for childnum in &self.bip32_path {
            let _ = ret.write_u32::<BigEndian>(*childnum);
        }
        ret.push(0x00); // user validation code
        let _ = ret.write_u32::<BigEndian>(self.locktime);
        ret.push(self.sighash.as_u32() as u8 | 0x40);
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

/// SET ALTERNATE COIN VERSIONS message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAlternateCoinVersions {
    sent: bool,
    sw: u16,
    pubkey_version: u16,
    script_version: u16
}

impl SetAlternateCoinVersions {
    /// Constructor
    pub fn new(network: Network) -> SetAlternateCoinVersions {
        match network {
            Network::Bitcoin => {
                SetAlternateCoinVersions {
                    sent: false,
                    sw: 0,
                    pubkey_version: 0,
                    script_version: 5
                }
            }
            Network::Testnet => {
                SetAlternateCoinVersions {
                    sent: false,
                    sw: 0,
                    pubkey_version: 111,
                    script_version: 196
                }
            }
        }
    }
}

impl Command for SetAlternateCoinVersions {
    fn encode_next(&mut self, _apdu_size: usize) -> Option<Vec<u8>> {
        if self.sent {
            return None;
        }
        self.sent = true;

        let mut ret = Vec::with_capacity(7);
        ret.push(apdu::ledger::BTCHIP_CLA);
        ret.push(apdu::ledger::ins::SET_ALTERNATE_COIN_VERSION);
        ret.push(0x00);
        ret.push(0x00);
        ret.push(0x05);
        let _ = ret.write_u16::<BigEndian>(self.pubkey_version);
        let _ = ret.write_u16::<BigEndian>(self.script_version);
        ret.push(0x01);  // "Bitcoin family"
        Some(ret)
    }

    fn decode_reply(&mut self, data: Vec<u8>) -> Result<(), Error> {
        if data.len() != 2 {
            return Err(Error::UnexpectedEof);
        }
        self.sw = ((data[0] as u16) << 8) + data[1] as u16;
        Ok(())
    }

    fn into_reply(self) -> (u16, Vec<u8>) {
        (self.sw, vec![])
    }
}


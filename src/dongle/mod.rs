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

use bitcoin::blockdata::transaction::{Transaction, SigHashType};
use bitcoin::network::constants::Network;

use constants;
use error::Error;
use self::message::{Command, Response};
use spend::Spend;
use util::convert_ledger_der_to_compact;

pub mod ledger;
pub mod message;

/// Trait representing an abstroct hardware wallet
pub trait Dongle {
    /// Sends raw data to the device and returns its response, which is a pair
    /// (status word, raw bytes). Generally this function is never used directly.
    fn exchange<C: Command>(&mut self, cmd: C) -> Result<(u16, Vec<u8>), Error>;

    /// Returns the type of the device
    fn product(&self) -> Product;

    /// Queries the device for its firmware version
    fn get_firmware_version(&mut self) -> Result<message::FirmwareVersion, Error> {
        let command = message::GetFirmwareVersion::new();
        let (sw, rev) = try!(self.exchange(command));
        if sw == constants::apdu::ledger::sw::OK {
            message::FirmwareVersion::decode(&rev)
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Queries the device for a BIP32 extended pubkey
    fn get_public_key(&mut self, bip32_path: &[u32]) -> Result<message::WalletPublicKey, Error> {
        let command = message::GetWalletPublicKey::new(bip32_path);;
        let (sw, rev) = try!(self.exchange(command));
        if sw == constants::apdu::ledger::sw::OK {
            message::WalletPublicKey::decode(&rev)
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Query the device to sign an arbitrary message
    fn sign_message(&mut self, message: &[u8], bip32_path: &[u32]) -> Result<[u8; 64], Error> {
        let command = message::SignMessagePrepare::new(bip32_path, message);
        let (sw, rev) = try!(self.exchange(command));
        if sw != constants::apdu::ledger::sw::OK {
            return Err(Error::ApduBadStatus(sw));
        }

        if rev != &[0, 0] {
            panic!("Ledger requested user authentication but we don't know how to handle that");
        }

        let command = message::SignMessageSign::new();
        let (sw, rev) = try!(self.exchange(command));
        if sw == constants::apdu::ledger::sw::OK {
            convert_ledger_der_to_compact(&rev)
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Query the device for up to 255 random bytes
    fn get_random(&mut self, n: u8) -> Result<Vec<u8>, Error> {
        let command = message::GetRandom::new(n);
        let (sw, rev) = try!(self.exchange(command));
        if sw == constants::apdu::ledger::sw::OK {
            Ok(rev)
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Query the device for a trusted input
    fn get_trusted_input(&mut self, tx: &Transaction, vout: u32) -> Result<Vec<u8>, Error> {
        let command = message::GetTrustedInput::new(tx, vout, constants::apdu::ledger::MAX_APDU_SIZE);
        let (sw, rev) = try!(self.exchange(command));
        if rev.len() != 56 {
            return Err(Error::ResponseWrongLength(constants::apdu::ledger::ins::GET_TRUSTED_INPUT, rev.len()));
        }
        if sw == constants::apdu::ledger::sw::OK {
            Ok(rev)
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Send the device a `UNTRUSTED HASH TRANSACTION INPUT START` command
    fn transaction_input_start(&mut self, spend: &Spend, index: usize, continuing: bool) -> Result<(), Error> {
        let command = message::UntrustedHashTransactionInputStart::new(spend, index, continuing, constants::apdu::ledger::MAX_APDU_SIZE);
        let (sw, _) = try!(self.exchange(command));
        if sw == constants::apdu::ledger::sw::OK {
            Ok(())
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Send the device a `UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL` command
    fn transaction_input_finalize(&mut self, spend: &Spend) -> Result<(), Error> {
        let command = message::UntrustedHashTransactionInputFinalize::new(spend, constants::apdu::ledger::MAX_APDU_SIZE);
        let (sw, _) = try!(self.exchange(command));
        if sw == constants::apdu::ledger::sw::OK {
            Ok(())
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Sends the device a `UNTRUSTED HASH SIGN` command
    fn transaction_sign(&mut self, bip32_path: [u32; 5], sighash: SigHashType, locktime: u32) -> Result<Vec<u8>, Error> {
        let command = message::UntrustedHashSign::new(bip32_path, sighash, locktime);
        let (sw, rev) = try!(self.exchange(command));
        if sw == constants::apdu::ledger::sw::OK {
            Ok(rev)
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Sends the device a `SET ALTERNATE COIN VERSIONS` command
    fn set_network(&mut self, network: Network) -> Result<(), Error> {
        let command = message::SetAlternateCoinVersions::new(network);
        let (sw, _) = try!(self.exchange(command));
        if sw == constants::apdu::ledger::sw::OK {
            Ok(())
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


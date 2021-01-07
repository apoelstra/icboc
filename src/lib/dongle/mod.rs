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

//! # Dongle
//!
//! Abstract API for communicating with the device
//!

use miniscript::{self, bitcoin};
use miniscript::bitcoin::secp256k1;
use miniscript::bitcoin::util::bip32;

use crate::{constants, Error, KeyCache};
use crate::util::parse_ledger_signature;
use self::message::{Command, Response};
//use spend::Spend;

pub mod ledger;
pub mod message;

/// Trait representing an abstroct hardware wallet
pub trait Dongle {
    /// Sends raw data to the device and returns its response, which is a pair
    /// (status word, raw bytes). Generally this function is never used directly.
    fn exchange<C: Command>(&mut self, cmd: C) -> Result<(u16, Vec<u8>), Error>;

    /// Queries the device for its firmware version
    fn get_firmware_version(&mut self) -> Result<message::FirmwareVersion, Error> {
        let command = message::GetFirmwareVersion::new();
        let (sw, rev) = self.exchange(command)?;
        if sw == constants::apdu::ledger::sw::OK {
            message::FirmwareVersion::decode(&rev)
        } else {
            Err(Error::ResponseBadStatus {
                apdu: constants::apdu::ledger::Instruction::GetFirmwareVersion,
                status: sw,
            })
        }
    }

    /// Queries the device for a BIP32 extended pubkey
    fn get_public_key<P: AsRef<[bip32::ChildNumber]>>(
        &mut self,
        bip32_path: &P,
        display: bool,
    ) -> Result<message::WalletPublicKey, Error> {
        let command = message::GetWalletPublicKey::new(bip32_path, display);
        let (sw, rev) = self.exchange(command)?;
        if sw == constants::apdu::ledger::sw::OK {
            message::WalletPublicKey::decode(&rev)
        } else {
            Err(Error::ResponseBadStatus {
                apdu: constants::apdu::ledger::Instruction::GetWalletPublicKey,
                status: sw,
            })
        }
    }

    /// Queries the device for 12 random bytes
    fn get_random_nonce(&mut self) -> Result<[u8; 12], Error> {
        let command = message::GetRandom::new(12);
        let (sw, rev) = self.exchange(command)?;
        if sw == constants::apdu::ledger::sw::OK {
            let mut res = [0; 12];
            res.copy_from_slice(&rev[..]);
            Ok(res)
        } else {
            Err(Error::ResponseBadStatus {
                apdu: constants::apdu::ledger::Instruction::GetRandom,
                status: sw,
            })
        }
    }

    /// Obtains a bitcoin pubkey by querying the Ledger for a given BIP32 path
    fn get_wallet_public_key(
        &mut self,
        key: &miniscript::DescriptorPublicKey,
        key_cache: &mut KeyCache,
    ) -> Result<bitcoin::PublicKey, Error> {
        match *key {
            miniscript::DescriptorPublicKey::SinglePub(ref single) => Ok(single.key),
            miniscript::DescriptorPublicKey::XPub(ref xkey) => {
                if let Some(entry) = key_cache.lookup(xkey.xkey, &xkey.derivation_path) {
                    return Ok(entry);
                }

                let fingerprint = key.master_fingerprint();
                let key_full_path = key.full_derivation_path();
        
                // Check for fingerprint mismatch
                let master_xpub = self.get_master_xpub()?;
                if fingerprint != master_xpub.fingerprint() {
                    return Err(Error::NotOurKey {
                        key_fingerprint: fingerprint,
                        our_fingerprint: master_xpub.fingerprint(),
                    });
                // Check for keyorigin mismatch
                } else if let miniscript::DescriptorPublicKey::XPub(ref xkey) = *key {
                    if let Some((_, ref originpath)) = xkey.origin {
                        let dongle_xpub = self.get_public_key(originpath, false)?;
                        if dongle_xpub.public_key != xkey.xkey.public_key {
                            // This will be a confusing error message because the two
                            // fingerprints are the same, but given that it is very
                            // unlikely this will ever happen (absent malicious or
                            // trollish behaviour) it didn't seem worth the effort to
                            // produce a better error message
                            return Err(Error::NotOurKey {
                                key_fingerprint: fingerprint,
                                our_fingerprint: fingerprint,
                            });
                        }
                    }
                }
                // The fingerprint/origin match the dongle. Look up the key and cache it.
                let dongle_xpub = self.get_public_key(&key_full_path, false)?;
                key_cache.insert(xkey.xkey, xkey.derivation_path.clone(), dongle_xpub.public_key);
                Ok(dongle_xpub.public_key)
            }
        }
    }

    /// Gets the BIP32 fingerprint of the device's master key
    fn get_master_xpub(&mut self) -> Result<bip32::ExtendedPubKey, Error> {
        let master_wpk = self.get_public_key(&[], false)?;
        let master_xpub = bip32::ExtendedPubKey {
            network: bitcoin::Network::Bitcoin,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: bip32::ChildNumber::Normal { index: 0 },
            public_key: master_wpk.public_key,
            chain_code: master_wpk.chain_code[..].into(),
        };
        Ok(master_xpub)
    }

    /// Query the device to sign an arbitrary message
    fn sign_message<P: AsRef<[bip32::ChildNumber]>>(
        &mut self,
        message: &[u8],
        bip32_path: &P,
    ) -> Result<secp256k1::Signature, Error> {
        let command = message::SignMessagePrepare::new(bip32_path, message);
        let (sw, rev) = self.exchange(command)?;
        // This should never happen unless we exceed Ledger limits
        if sw != constants::apdu::ledger::sw::OK {
            return Err(Error::ResponseBadStatus {
                apdu: constants::apdu::ledger::Instruction::SignMessage,
                status: sw,
            });
        }

        if rev != &[0, 0] {
            panic!("Ledger requested user authentication but we don't know how to handle that");
        }

        let command = message::SignMessageSign::new();
        let (sw, mut rev) = self.exchange(command)?;
        match sw {
            constants::apdu::ledger::sw::OK => Ok(parse_ledger_signature(&mut rev)?),
            constants::apdu::ledger::sw::SIGN_REFUSED => Err(Error::UserRefusedSignMessage),
            sw => Err(Error::ResponseBadStatus {
                apdu: constants::apdu::ledger::Instruction::SignMessage,
                status: sw,
            }),
        }
    }

/*
    /// Query the device for a trusted input
    fn get_trusted_input(&mut self, tx: &Transaction, vout: u32) -> Result<Vec<u8>, Error> {
        let command = message::GetTrustedInput::new(tx, vout, constants::apdu::ledger::MAX_APDU_SIZE);
        let (sw, rev) = self.exchange(command)?;
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
        let (sw, _) = self.exchange(command)?;
        if sw == constants::apdu::ledger::sw::OK {
            Ok(())
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Send the device a `UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL` command
    fn transaction_input_finalize(&mut self, spend: &Spend) -> Result<(), Error> {
        let command = message::UntrustedHashTransactionInputFinalize::new(spend, constants::apdu::ledger::MAX_APDU_SIZE);
        let (sw, _) = self.exchange(command)?;
        if sw == constants::apdu::ledger::sw::OK {
            Ok(())
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Sends the device a `UNTRUSTED HASH SIGN` command
    fn transaction_sign(&mut self, bip32_path: [u32; 5], sighash: SigHashType, locktime: u32) -> Result<Vec<u8>, Error> {
        let command = message::UntrustedHashSign::new(bip32_path, sighash, locktime);
        let (sw, rev) = self.exchange(command)?;
        if sw == constants::apdu::ledger::sw::OK {
            Ok(rev)
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }

    /// Sends the device a `SET ALTERNATE COIN VERSIONS` command
    fn set_network(&mut self, network: Network) -> Result<(), Error> {
        let command = message::SetAlternateCoinVersions::new(network);
        let (sw, _) = self.exchange(command)?;
        if sw == constants::apdu::ledger::sw::OK {
            Ok(())
        } else {
            Err(Error::ApduBadStatus(sw))
        }
    }
*/
}


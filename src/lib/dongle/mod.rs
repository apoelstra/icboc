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

use miniscript::bitcoin::bip32;
use miniscript::bitcoin::secp256k1::{self, ecdsa};
use miniscript::{self, bitcoin};

use self::message::{Command, Response};
use crate::constants::apdu::ledger as ledger_const;
use crate::util::parse_ledger_signature;
use crate::wallet;
use crate::{Error, KeyCache};

pub mod ledger;
pub mod message;
mod tx;

/// Data that needs to be provided to the Ledger when
/// signing for a legacy input
#[derive(Debug)]
pub struct TrustedInput {
    /// Opaque blob provided by the ledger in response to the
    /// `get_trusted_input` call
    blob: [u8; 56],
    /// `ScriptPubKey` of the output being spent
    script_pubkey: bitcoin::ScriptBuf,
}

impl Default for TrustedInput {
    fn default() -> Self {
        TrustedInput {
            blob: [0; 56],
            script_pubkey: bitcoin::ScriptBuf::new(),
        }
    }
}

/// Trait representing an abstroct hardware wallet
pub trait Dongle {
    /// Sends raw data to the device and returns its response, which is a pair
    /// (status word, raw bytes). Generally this function is never used directly.
    fn exchange<C: Command>(&mut self, cmd: C) -> Result<(u16, Vec<u8>), Error>;

    /// Queries the device for its firmware version
    fn get_firmware_version(&mut self) -> Result<message::FirmwareVersion, Error> {
        let command = message::GetFirmwareVersion::new();
        let (sw, rev) = self.exchange(command)?;
        if sw == ledger_const::sw::OK {
            message::FirmwareVersion::decode(&rev)
        } else {
            Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::GetFirmwareVersion,
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
        if sw == ledger_const::sw::OK {
            message::WalletPublicKey::decode(&rev)
        } else {
            Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::GetWalletPublicKey,
                status: sw,
            })
        }
    }

    /// Queries the device for 12 random bytes
    fn get_random_nonce(&mut self) -> Result<[u8; 12], Error> {
        let command = message::GetRandom::new(12);
        let (sw, rev) = self.exchange(command)?;
        if sw == ledger_const::sw::OK {
            let mut res = [0; 12];
            res.copy_from_slice(&rev);
            Ok(res)
        } else {
            Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::GetRandom,
                status: sw,
            })
        }
    }

    /// Obtains a bitcoin pubkey by querying the Ledger for a given BIP32 path
    fn get_wallet_public_key(
        &mut self,
        key: &miniscript::DefiniteDescriptorKey,
        key_cache: &mut KeyCache,
    ) -> Result<secp256k1::PublicKey, Error> {
        // FIXME once https://github.com/rust-bitcoin/rust-miniscript/pull/492 is in we can just convert
        // the reference without cloning. with as_descriptor_public_key.
        let key: miniscript::DescriptorPublicKey = key.clone().into();
        match key {
            miniscript::DescriptorPublicKey::Single(ref single) => match single.key {
                miniscript::descriptor::SinglePubKey::FullKey(key) => Ok(key.inner),
                miniscript::descriptor::SinglePubKey::XOnly(_) => Err(Error::NoTaprootSupport),
            },
            miniscript::DescriptorPublicKey::XPub(ref xkey) => {
                if let Some(entry) = key_cache.lookup(xkey.xkey, &xkey.derivation_path) {
                    return Ok(entry);
                }

                let fingerprint = key.master_fingerprint();
                let key_full_path = key.full_derivation_path().expect("no multipath keys");
                assert!(key_full_path.len() < 11); // limitation of the Nano S

                // Check for fingerprint mismatch
                let master_xpub = self.get_master_xpub()?;
                if fingerprint != master_xpub.fingerprint() {
                    return Err(Error::NotOurKey {
                        key_fingerprint: fingerprint,
                        our_fingerprint: master_xpub.fingerprint(),
                    });
                // Check for keyorigin mismatch
                } else if let miniscript::DescriptorPublicKey::XPub(ref xkey) = key {
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
                key_cache.insert(
                    xkey.xkey,
                    xkey.derivation_path.clone(),
                    dongle_xpub.public_key,
                );
                Ok(dongle_xpub.public_key)
            }
            miniscript::DescriptorPublicKey::MultiXPub(..) => {
                panic!("multipath keys (BIP 389) not supported")
            }
        }
    }

    /// Gets the BIP32 fingerprint of the device's master key
    fn get_master_xpub(&mut self) -> Result<bip32::Xpub, Error> {
        let master_wpk = self.get_public_key(&[], false)?;
        let master_xpub = bip32::Xpub {
            network: bitcoin::NetworkKind::Main,
            depth: 0,
            parent_fingerprint: bip32::Fingerprint::default(),
            child_number: bip32::ChildNumber::Normal { index: 0 },
            public_key: master_wpk.public_key,
            chain_code: master_wpk.chain_code.into(),
        };
        Ok(master_xpub)
    }

    /// Query the device to sign an arbitrary message
    fn sign_message<P: AsRef<[bip32::ChildNumber]>>(
        &mut self,
        message: &[u8],
        bip32_path: &P,
    ) -> Result<ecdsa::Signature, Error> {
        let command = message::SignMessagePrepare::new(bip32_path, message);
        let (sw, rev) = self.exchange(command)?;
        // This should never happen unless we exceed Ledger limits
        if sw != ledger_const::sw::OK {
            return Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::SignMessage,
                status: sw,
            });
        }

        assert_eq!(
            rev,
            [0, 0],
            "Ledger requested user authentication but we don't know how to handle that",
        );

        let command = message::SignMessageSign::new();
        let (sw, mut rev) = self.exchange(command)?;
        match sw {
            ledger_const::sw::OK => Ok(parse_ledger_signature(&mut rev)?),
            ledger_const::sw::SIGN_REFUSED => Err(Error::UserRefusedSignMessage),
            sw => Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::SignMessage,
                status: sw,
            }),
        }
    }

    /// Query the device for a "trusted input", i.e. a self-signed blob
    /// attesting to the information related to a txout that we intent
    /// to spend
    ///
    /// We have to send the entire transaction to the device along with
    /// its vout.
    fn get_trusted_input(
        &mut self,
        tx: &bitcoin::Transaction,
        vout: u32,
    ) -> Result<TrustedInput, Error> {
        let command = message::GetTrustedInput::new(tx, vout);
        let (sw, rev) = self.exchange(command)?;
        if sw == ledger_const::sw::OK {
            if rev.len() == 56 {
                let mut ret = TrustedInput::default();
                ret.blob.copy_from_slice(&rev);
                ret.script_pubkey = tx.output[vout as usize].script_pubkey.clone();
                Ok(ret)
            } else {
                Err(Error::ResponseWrongLength {
                    apdu: ledger_const::Instruction::GetTrustedInput,
                    expected: 56..57,
                    found: rev.len(),
                })
            }
        } else {
            Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::GetTrustedInput,
                status: sw,
            })
        }
    }

    /// Send the device a `UNTRUSTED HASH TRANSACTION INPUT START` command
    ///
    /// When signing a transaction, for each input you send this message,
    /// followed by `INPUT FINALIZE FULL`, followed by `SIGN`. For the
    /// the first input you set `continuing` to `false`, after that you
    /// set it to `true`.
    ///
    /// It is best not to call this directly, instead calling the wrapper
    /// function TODO
    fn transaction_input_start(
        &mut self,
        tx: &bitcoin::Transaction,
        index: usize,
        trusted_inputs: &[TrustedInput],
        first_input: bool,
    ) -> Result<(), Error> {
        let command = message::UntrustedHashTransactionInputStart::new(
            tx,
            index,
            trusted_inputs,
            first_input,
        );
        let (sw, _) = self.exchange(command)?;
        if sw == ledger_const::sw::OK {
            Ok(())
        } else {
            Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::UntrustedHashTransactionInputStart,
                status: sw,
            })
        }
    }

    /// Send the device a `UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL` command
    fn transaction_input_finalize(
        &mut self,
        tx: &bitcoin::Transaction,
        change_address: Option<&wallet::Address>,
    ) -> Result<(), Error> {
        let command = message::UntrustedHashTransactionInputFinalize::new(tx, change_address);
        let (sw, _) = self.exchange(command)?;
        if sw == ledger_const::sw::OK {
            Ok(())
        } else {
            Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::UntrustedHashTransactionInputFinalize,
                status: sw,
            })
        }
    }

    /// Sends the device a `UNTRUSTED HASH SIGN` command
    fn transaction_sign<P: AsRef<[bip32::ChildNumber]>>(
        &mut self,
        bip32_path: &P,
        sighash: bitcoin::sighash::EcdsaSighashType,
        tx_locktime: u32,
    ) -> Result<ecdsa::Signature, Error> {
        let command = message::UntrustedHashSign::new(bip32_path, sighash, tx_locktime);
        let (sw, mut rev) = self.exchange(command)?;
        if sw == ledger_const::sw::OK {
            rev[0] = 0x30;
            ecdsa::Signature::from_der_lax(&rev).map_err(Error::from)
        } else {
            Err(Error::ResponseBadStatus {
                apdu: ledger_const::Instruction::UntrustedHashSign,
                status: sw,
            })
        }
    }
}

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

//! # Error Handling

use crate::constants;
use miniscript::bitcoin;
use std::{io, ops, string};
use thiserror::Error;

/// Ice Box error
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum Error {
    #[error("incorrect channel for APDU (expected {expected:?}, found {found:?})")]
    ApduWrongChannel { expected: u16, found: u16 },
    #[error("incorrect tag for APDU (expected {expected:?}, found {found:?})")]
    ApduWrongTag { expected: u8, found: u8 },
    #[error("incorrect sequence no for APDU (expected {expected:?}, found {found:?})")]
    ApduWrongSequence { expected: u16, found: u16 },
    #[error("bitcoin")]
    Bitcoin(#[from] bitcoin::key::ParsePublicKeyError),
    #[error("no dongle detected")]
    DongleNotFound,
    #[error("more than one dongle detected")]
    DongleNotUnique,
    #[error("tried to import the same descriptor twice")]
    DuplicateDescriptor,
    #[error("utf8")]
    FromUtf8(#[from] string::FromUtf8Error),
    #[error("io")]
    Io(#[from] io::Error),
    #[error("could not compute public key for {0}")]
    KeyNotFound(miniscript::DescriptorPublicKey),
    #[error("miniscript")]
    Miniscript(#[from] miniscript::Error),
    #[error("not our key (fingerprint {key_fingerprint} vs our fingerprint {our_fingerprint})")]
    NotOurKey {
        our_fingerprint: bitcoin::bip32::Fingerprint,
        key_fingerprint: bitcoin::bip32::Fingerprint,
    },
    #[error("hidapi")]
    Hid(#[from] hidapi::HidError),
    #[error("device replied to {apdu:?} with bad status code {status:04X}")]
    ResponseBadStatus {
        apdu: constants::apdu::ledger::Instruction,
        status: u16,
    },
    #[error("incorrect length for {apdu:?} response (expected {expected:?}, found {found:?})")]
    ResponseWrongLength {
        apdu: constants::apdu::ledger::Instruction,
        expected: ops::Range<usize>,
        found: usize,
    },
    #[error("tx {0} not cached in wallet")]
    TxNotFound(bitcoin::Txid),
    #[error("txo {0} not found in wallet")]
    TxoNotFound(bitcoin::OutPoint),
    #[error("secp256k1")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error("user refused to sign message")]
    UserRefusedSignMessage,
    #[error("unexpected end-of-data")]
    UnexpectedEof,
    #[error("device did something we do not support")]
    Unsupported,
    #[error("we do not yet have taproot support")]
    NoTaprootSupport,
}

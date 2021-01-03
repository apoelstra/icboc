// ICBOC 3D
// Written in 2020 by
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

use miniscript::bitcoin;
use std::{ops, string};
use thiserror::Error;
use crate::constants;

/// Ice Box error
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum Error {
    #[error("incorrect channel for APDU (expected {expected:?}, found {found:?})")]
    ApduWrongChannel {
        expected: u16,
        found: u16,
    },
    #[error("incorrect tag for APDU (expected {expected:?}, found {found:?})")]
    ApduWrongTag {
        expected: u8,
        found: u8,
    },
    #[error("incorrect sequence no for APDU (expected {expected:?}, found {found:?})")]
    ApduWrongSequence {
        expected: u16,
        found: u16,
    },
    #[error("bitcoin")]
    Bitcoin(#[from] bitcoin::util::key::Error),
    #[error("no dongle detected")]
    DongleNotFound,
    #[error("more than one dongle detected")]
    DongleNotUnique,
    #[error("utf8")]
    FromUtf8(#[from] string::FromUtf8Error),
    #[error("miniscript")]
    Miniscript(#[from] miniscript::Error),
    #[error("not our key (fingerprint {key_fingerprint} vs our fingerprint {our_fingerprint})")]
    NotOurKey {
        our_fingerprint: bitcoin::util::bip32::Fingerprint,
        key_fingerprint: bitcoin::util::bip32::Fingerprint,
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
    #[error("secp256k1")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error("user refused to sign message")]
    UserRefusedSignMessage,
    #[error("unexpected end-of-data")]
    UnexpectedEof,
}


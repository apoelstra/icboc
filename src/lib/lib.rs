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

//! # Ice Box Library
//!
//! Ice Box is an library designed to use the Ledger Nano S (and possibly
//! other Ledger products) in a cold-wallet fashion. It is the library
//! providing the functionality for the Ice Box application, which can be
//! used directly to interact with the Ledger.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]

pub mod constants;
mod dongle;
mod error;
mod wallet;
mod util;

pub use dongle::Dongle;
pub use dongle::ledger;
pub use error::Error;
pub use util::{parse_ledger_signature, parse_ledger_signature_recoverable};
pub use wallet::{Descriptor, Wallet, Txo};

// Re-export all the hidapi types because the double `hidapi::HidDevice`
// naming bugs me
/// Re-exports of types from `hidapi` with nicer names
pub mod hid {
    pub use hidapi::HidApi as Api;
    pub use hidapi::HidDevice as Device;
    pub use hidapi::HidError as Error;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
